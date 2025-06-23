#include "mce.h"
#include "mce_lib.h"
#include "mce_irq.h"

static void __mce_update_dim(u16 total_events, u64 packets,
			     u64 bytes, struct dim *dim)
{
	struct dim_sample dim_sample = {};

	dim_update_sample(total_events, packets, bytes, &dim_sample);
	dim_sample.comp_ctr = 0;

	/* if dim settings get stale, like when not updated for 1
	 * second or longer, force it to start again. This addresses the
	 * frequent case of an idle queue being switched to by the
	 * scheduler. The 1,000 here means 1,000 milliseconds.
	 */
	if (ktime_ms_delta(dim_sample.time, dim->start_sample.time) >=
	    1000)
		dim->state = DIM_START_MEASURE;

	net_dim(dim, dim_sample);
}

/**
 * mce_net_dim - Update net DIM algorithm
 * @q_vector: the vector associated with the interrupt
 *
 * Create a DIM sample and notify net_dim() so that it can possibly decide
 * a new ITR value based on incoming packets, bytes, and interrupts.
 *
 * This function is a no-op if the ring is not configured to dynamic ITR.
 */
static void mce_net_dim(struct mce_q_vector* q_vector)
{
	struct mce_ring_container *tx = &q_vector->tx;
	struct mce_ring_container *rx = &q_vector->rx;

	if (ITR_IS_SW_DYNAMIC(tx)) {
		u64 packets = 0, bytes = 0;
		struct mce_ring *tx_ring;

		mce_rc_for_each_ring(tx_ring, q_vector->tx) {
			packets += tx_ring->ring_stats->stats.pkts;
			bytes += tx_ring->ring_stats->stats.bytes;
		}

		__mce_update_dim(q_vector->total_events, packets, bytes,
				 &tx->dim);
	}

	if (ITR_IS_SW_DYNAMIC(rx)) {
		u64 packets = 0, bytes = 0;
		struct mce_ring *rx_ring;

		mce_rc_for_each_ring(rx_ring, q_vector->rx) {
			packets += rx_ring->ring_stats->stats.pkts;
			bytes += rx_ring->ring_stats->stats.bytes;
		}
		__mce_update_dim(q_vector->total_events, packets, bytes,
				 &rx->dim);
	}
}

/**
 * mce_napi_poll - NAPI polling Rx/Tx cleanup routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean all queues associated with a q_vector.
 *
 * Returns the amount of work done
 */
int mce_napi_poll(struct napi_struct *napi, int budget)
{
	struct mce_q_vector *q_vector = NULL;
	struct mce_ring *ring =NULL;
	bool clean_complete = true;
	int budget_per_ring = 0;
	int work_done = 0;

	q_vector = container_of(napi, struct mce_q_vector, napi);

	/* Since the actual Tx work is minimal, we can give the Tx a larger
	 * budget and be more aggressive about cleaning up the Tx descriptors.
	 */
	mce_rc_for_each_ring(ring, q_vector->tx) {
		clean_complete = mce_clean_tx_irq(ring, budget);
	}

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (unlikely(budget <= 0))
		return budget;

	/* normally we have 1 Rx ring per q_vector */
	if (unlikely(q_vector->num_ring_rx > 1))
		/* We attempt to distribute budget to each Rx queue fairly, but
		 * don't allow the budget to go below 1 because that would exit
		 * polling early.
		 */
		budget_per_ring =
			max_t(int, budget / q_vector->num_ring_rx, 1);
	else
		/* Max of 1 Rx ring in this q_vector so give it the budget */
		budget_per_ring = budget;

	mce_rc_for_each_ring(ring, q_vector->rx) {
		int cleaned;

		cleaned = mce_clean_rx_irq(ring, budget_per_ring);
		work_done += cleaned;
		if (cleaned >= budget_per_ring)
			clean_complete = false;
	}

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
		int cpu_id = smp_processor_id();

		if (!cpumask_test_cpu(cpu_id, &q_vector->affinity_mask)) {
			/* Tell napi that we are done polling */
			napi_complete_done(napi, work_done);
			/* Force an interrupt */
			mce_rc_for_each_ring(ring, q_vector->tx) {
				struct mce_vsi *vsi = ring->vsi;
				struct mce_hw *hw = &vsi->back->hw;

				hw->ops->set_txring_trig_intr(ring);
				printk("cpuid:%d change irq affinity\n",
				       cpu_id);
			}

			/* Return budget-1 so that polling stops */
			return budget - 1;
		}
		return budget;
	}

	/* Work is done so exit the polling mode and re-enable the interrupt */
	if (likely(napi_complete_done(napi, work_done))) {
		mce_net_dim(q_vector);
		/* napi_ret : false (means vector is still in POLLING mode
		 *            true (means out of POLLING)
		 * NOTE: Generally if napi_ret is TRUE, enable device interrupt
		 * but there are condition/optimization, where it can be
		 * optimized. Basically, if napi_complete_done returns true.
		 * But if it is last time Rx packets were cleaned,
		 * then most likely, consumer thread will come back to do
		 * busy_polling where cleaning of  Tx/Rx queue will happen
		 * normally. Hence no reason to arm the interrupt.
		 *
		 * If for some reason, consumer thread/context doesn't comeback
		 * to busy_poll:napi_poll, there is bail-out mechanism to kick
		 * start the state machine thru' SW triggered interrupt from
		 * service task.
		 */
		/* write tx rx once togater */
#ifndef THREAD_POLL
		mce_enable_vec_txrxs_irq(q_vector);
#endif
	}

	return min_t(int, work_done, budget - 1);
}

/**
 * mce_get_irq_num - get system irq number based on index from driver
 * @pf: board private structure
 * @idx: driver irq index
 */
int mce_get_irq_num(struct mce_pf *pf, int idx)
{
	if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSIX) {
#ifdef HAVE_PCI_ALLOC_IRQ
		return pci_irq_vector(pf->pdev, idx);
#else
		if (!pf->msix_entries)
			return -EINVAL;

		return pf->msix_entries[idx].vector;
#endif /* HAVE_PCI_ALLOC_IRQ */
	}
	return pf->pdev->irq;
}

#ifdef HAVE_PCI_ALLOC_IRQ
static int mce_alloc_and_fill_msix_entries(struct mce_pf *pf, int nvec)
{
	int i;

	pf->msix_entries =
		kcalloc(nvec, sizeof(*pf->msix_entries), GFP_KERNEL);
	if (!pf->msix_entries)
		return -ENOMEM;

	for (i = 0; i < nvec; i++) {
		pf->msix_entries[i].entry = i;
		pf->msix_entries[i].vector = mce_get_irq_num(pf, i);
	}

	return 0;
}
#endif /* HAVE_PCI_ALLOC_IRQ */

#ifndef HAVE_PCI_ALLOC_IRQ
static int mce_alloc_msix_entries(struct mce_pf *pf, u16 num_entries)
{
	u16 i;

	pf->msix_entries = devm_kcalloc(mce_pf_to_dev(pf), num_entries,
					sizeof(*pf->msix_entries),
					GFP_KERNEL);
	if (!pf->msix_entries)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++)
		pf->msix_entries[i].entry = i;

	return 0;
}

static void mce_free_msix_entries(struct mce_pf *pf)
{
	devm_kfree(mce_pf_to_dev(pf), pf->msix_entries);
	pf->msix_entries = NULL;
}
#endif /* HAVE_PCI_ALLOC_IRQ */

static int mce_ena_msix(struct mce_pf *pf, int nvec)
{
#ifdef HAVE_PCI_ALLOC_IRQ
	return pci_alloc_irq_vectors(pf->pdev, MCE_MIN_MSIX, nvec,
				     PCI_IRQ_MSIX);
#else
	int vectors;
	int err;

	err = mce_alloc_msix_entries(pf, nvec);
	if (err)
		return err;

	vectors = pci_enable_msix_range(pf->pdev, pf->msix_entries,
					MCE_MIN_MSIX, nvec);
	if (vectors < 0)
		mce_free_msix_entries(pf);

	return vectors;
#endif /* HAVE_PCI_ALLOC_IRQ */
}

static void mce_dis_msix(struct mce_pf *pf)
{
#ifdef HAVE_PCI_ALLOC_IRQ
	pci_free_irq_vectors(pf->pdev);
#else
	mce_free_msix_entries(pf);
	pci_disable_msix(pf->pdev);
#endif /* HAVE_PCI_ALLOC_IRQ */
}

static void mce_dis_msi(struct mce_pf *pf)
{
	pci_disable_msi(pf->pdev);
}

/**
 * mce_ena_msix_range - 获取msix的数量
 *
 * msix的数量按当前可用的cpu数量获取
 */
static int mce_ena_msix_range(struct mce_pf *pf)
{
	struct device *dev = mce_pf_to_dev(pf);
	int num_local_cpus = mce_get_num_local_cpus(dev);
	int needed = mce_normalize_cpu_count(num_local_cpus);
	int v_actual = 0;
	int err = -ENOSPC;

	needed = min_t(int, needed,
		       pf->max_pf_txqs + pf->num_mbox_irqs +
			       pf->num_rdma_irqs);
	needed = min_t(int, needed, pf->num_msix_cnt);

	v_actual = mce_ena_msix(pf, needed);
	if (v_actual < 0) {
		err = v_actual;
		goto err;
	} else if (v_actual < needed) {
		mce_dis_msix(pf);
		goto err;
	}

	return v_actual;
err:
	dev_err(mce_pf_to_dev(pf), "Failed to enable MSI-X vectors\n");
	return  err;
}

struct mce_res_tracker *mce_alloc_res_tracker(struct mce_pf *pf, u16 size)
{
	struct mce_res_tracker *result;

	result = devm_kzalloc(mce_pf_to_dev(pf),
			      struct_size(pf->irq_tracker, list, size),
			      GFP_KERNEL);
	if (!result)
		return NULL;

	return result;
}

/**
 * mce_init_interrupt_scheme - Determine proper interrupt scheme
 * @pf: board private structure to initialize
 */
int mce_init_interrupt_scheme(struct mce_pf *pf)
{
	int vectors = 0, err = 0;

	if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSIX) {
		if (!test_bit(MCE_FLAG_IRQ_MSIX_CAPABLE, pf->flags)) {
			err = -EPERM;
			pf->pcie_irq_mode = MCE_PCIE_IRQ_MODE_MSI;
			dev_warn(mce_pf_to_dev(pf),
				 "no msix capable, try msi mode\n");
			goto msi_mode;
		}

		vectors = mce_ena_msix_range(pf);
		if (vectors < 0) {
			err = vectors;
			pf->pcie_irq_mode = MCE_PCIE_IRQ_MODE_MSI;
			dev_warn(
				mce_pf_to_dev(pf),
				"Failed to enable MSI-X vectors, try msi mode\n");
			goto msi_mode;
		}

#ifdef HAVE_PCI_ALLOC_IRQ
		/* pf->msix_entries is used in idc and needs to be filled
			* on kernel with new irq alloc API.
			*/
		if (mce_alloc_and_fill_msix_entries(pf, vectors)) {
			mce_dis_msix(pf);
			return -ENOMEM;
		}
#endif /* HAVE_PCI_ALLOC_IRQ */
		pf->irq_tracker = mce_alloc_res_tracker(pf, vectors);
		if (!pf->irq_tracker) {
			mce_dis_msix(pf);
			return -ENOMEM;
		}
		set_bit(MCE_FLAG_IRQ_MSIX_ENA, pf->flags);
		goto out;
	}

msi_mode:
	if (!test_bit(MCE_FLAG_IRQ_MSI_CAPABLE, pf->flags)) {
		dev_warn(mce_pf_to_dev(pf), "no msi capable, exit\n");
		goto out;
	}

	if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSI) {
		err = pci_enable_msi(pf->pdev);
		if (err) {
			dev_warn(
				mce_pf_to_dev(pf),
				"Failed to enable MSI interrupt, falling back to legacy\n");
			set_bit(MCE_FLAG_IRQ_LEGENCY_ENA, pf->flags);
			pf->pcie_irq_mode = MCE_PCIE_IRQ_MODE_LEGENCY;
		} else {
			vectors = MCE_PCIE_IRQ_MODE_NO_MSIX_MAX_VECTORS;
			pf->irq_tracker =
				mce_alloc_res_tracker(pf, vectors);
			if (!pf->irq_tracker) {
				mce_dis_msi(pf);
				return -ENOMEM;
			}
			set_bit(MCE_FLAG_IRQ_MSI_ENA, pf->flags);
		}
	}

out:
	if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_LEGENCY) {
		vectors = MCE_PCIE_IRQ_MODE_NO_MSIX_MAX_VECTORS;
		pf->irq_tracker = mce_alloc_res_tracker(pf, vectors);
		if (!pf->irq_tracker)
			return -ENOMEM;
		set_bit(MCE_FLAG_IRQ_LEGENCY_ENA, pf->flags);
	}

	pf->num_msix_cnt = vectors;
	pf->num_avail_msix = vectors;
	pf->irq_tracker->num_entries = vectors;
	pf->irq_tracker->end = pf->irq_tracker->num_entries;
	return err;
}

/**
 * mce_clear_interrupt_scheme - Undo things done by mce_init_interrupt_scheme
 * @pf: board private structure
 */
void mce_clear_interrupt_scheme(struct mce_pf *pf)
{
#ifdef HAVE_PCI_ALLOC_IRQ
	kfree(pf->msix_entries);
	pf->msix_entries = NULL;

#endif /* PEER_SUPPORT */
	if (test_bit(MCE_FLAG_IRQ_MSIX_ENA, pf->flags))
		mce_dis_msix(pf);
	else if (test_bit(MCE_FLAG_IRQ_MSI_ENA, pf->flags))
		mce_dis_msi(pf);

	if (pf->irq_tracker) {
		devm_kfree(mce_pf_to_dev(pf), pf->irq_tracker);
		pf->irq_tracker = NULL;
	}
}

/**
 * mce_napi_add - register NAPI handler for the VSI
 * @vsi: VSI for which NAPI handler is to be registered
 *
 * This function is only called in the driver's load path. Registering the NAPI
 * handler is done in mce_vsi_alloc_q_vector() for all other cases (i.e. resume,
 * reset/rebuild, etc.)
 */
void mce_napi_add(struct mce_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	mce_for_each_q_vector(vsi, v_idx)
		netif_napi_add(vsi->netdev, &vsi->q_vectors[v_idx]->napi,
			       mce_napi_poll);
}

/**
 * mce_irq_affinity_notify - Callback for affinity changes
 * @notify: context as to what irq was changed
 * @mask: the new affinity mask
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * so that we may register to receive changes to the irq affinity masks.
 */
static void
mce_irq_affinity_notify(struct irq_affinity_notify *notify,
			const cpumask_t *mask)
{
	struct mce_q_vector *q_vector = NULL;

	q_vector = container_of(notify, struct mce_q_vector,
				affinity_notify);

	cpumask_copy(&q_vector->affinity_mask, mask);
}

/**
 * mce_irq_affinity_release - Callback for affinity notifier release
 * @ref: internal core kernel usage
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * to inform the current notification subscriber that they will no longer
 * receive notifications.
 */
static void mce_irq_affinity_release(struct kref __always_unused *ref) {}

/**
 * mce_vsi_req_single_irq_msix - get a single MSI-X vector from the OS for VSI
 * @vsi: the VSI being configured
 * @basename: name for the vector
 * @vector_id: index of the vector in VSI
 */
static
int mce_vsi_req_single_irq_msix(struct mce_vsi *vsi,
				  char *basename,
				  u16 vector_id)
{
	struct mce_q_vector *q_vector = vsi->q_vectors[vector_id];
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	int base = vsi->base_vector;
	u16 rx_irq_idx, tx_irq_idx;
	struct device *dev;
	int irq_num, err;
	unsigned long irq_flags = 0;

	mce_vsi_get_q_vector_q_base(vsi, vector_id,
				    &tx_irq_idx, &rx_irq_idx);

	if (q_vector->tx.ring && q_vector->rx.ring) {
		if (q_vector->num_ring_rx == 1) {
			snprintf(q_vector->name, sizeof(q_vector->name),
				 "%s-%s-%u", basename, "TxRx", rx_irq_idx);
		} else {
			u32 num_rx = q_vector->num_ring_rx;

			snprintf(q_vector->name, sizeof(q_vector->name),
				 "%s-%s-%u-%u", basename, "TxRx",
				 rx_irq_idx, rx_irq_idx + num_rx - 1);
		}
	} else if (q_vector->rx.ring) {
		snprintf(q_vector->name, sizeof(q_vector->name),
			 "%s-%s-%u", basename, "rx", rx_irq_idx);
	} else if (q_vector->tx.ring) {
		snprintf(q_vector->name, sizeof(q_vector->name),
			 "%s-%s-%u", basename, "tx", tx_irq_idx);
	} else {
		/* skip this unused q_vector */
		return 0;
	}
	dev = mce_pf_to_dev(pf);
	irq_num = mce_get_irq_num(pf, base + vector_id);
	if (test_bit(MCE_FLAG_IRQ_LEGENCY_ENA, pf->flags))
		irq_flags = IRQF_SHARED;
	else
		irq_flags = 0;

	err = devm_request_irq(dev, irq_num, vsi->irq_handler, irq_flags,
			       q_vector->name, q_vector);
	if (err) {
		netdev_err(vsi->netdev, "request irq failed, error: %d\n",
			   err);
		return err;
	}

	if (test_bit(MCE_FLAG_IRQ_LEGENCY_ENA, pf->flags))
		hw->ops->set_irq_legency_en(hw, true, 0x200);
	else
		hw->ops->set_irq_legency_en(hw, false, 0x0);
	/* register for affinity change notifications */
	if (1 || !IS_ENABLED(CONFIG_RFS_ACCEL)) {
		struct irq_affinity_notify *affinity_notify;

		affinity_notify = &q_vector->affinity_notify;
		affinity_notify->notify = mce_irq_affinity_notify;
		affinity_notify->release = mce_irq_affinity_release;
		irq_set_affinity_notifier(irq_num, affinity_notify);
	}

	return 0;
}

/**
 * mce_vsi_req_irq_msix - get MSI-X vectors from the OS for the VSI
 * @vsi: the VSI being configured
 * @basename: name for the vector
 */
int mce_vsi_req_irq_msix(struct mce_vsi *vsi, char *basename)
{
	struct mce_pf *pf = vsi->back;
	int base = vsi->base_vector;
	struct device *dev;
	int vector, err;
	int irq_num;

#ifdef THREAD_POLL
	struct cpumask *mask;

	mask = kmalloc(sizeof(struct cpumask), GFP_KERNEL);
	if (!mask) {
		return -ENOMEM;
	}
	vsi->mce_poll_thread = kthread_run(mce_poll_thread_handler, vsi,
					   "mce_threadpoll");
	cpumask_clear(mask);
	cpumask_set_cpu(2, mask);
	set_cpus_allowed_ptr(vsi->mce_poll_thread, mask);
	if (!vsi->mce_poll_thread) {
		netdev_err(vsi->netdev, "mce threadpoll run failed\n");
		kfree(mask);
		return -EIO;
	}
	kfree(mask);
	return 0;
#endif

	dev = mce_pf_to_dev(pf);
	mce_for_each_q_vector(vsi, vector) {
		err = mce_vsi_req_single_irq_msix(vsi, basename, vector);
		if (err)
			goto free_q_irqs;
	}

	// err = mce_set_cpu_rx_rmap(vsi);
	// if (err) {
	// 	netdev_err(vsi->netdev, "Failed to setup CPU RMAP on VSI %u: %pe\n",
	// 		   vsi->idx, ERR_PTR(err));
	// 	goto free_q_irqs;
	// }

	vsi->irqs_ready = true;
	return 0;

free_q_irqs:
	while (vector) {
		vector--;
		irq_num = mce_get_irq_num(pf, base + vector);
		if (1 || !IS_ENABLED(CONFIG_RFS_ACCEL))
			irq_set_affinity_notifier(irq_num, NULL);
		devm_free_irq(dev, irq_num, &vsi->q_vectors[vector]);
	}
	return err;
}
