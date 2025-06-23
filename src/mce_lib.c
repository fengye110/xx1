#include "mce.h"
#include "mce_base.h"
#include "mce_irq.h"
#include "mce_lib.h"
#include "mce_dcb.h"
#include "mce_dcbnl.h"
#include "mce_fdir.h"

//static void mce_vsi_close_hw_transmit(struct mce_vsi *vsi)
//{
//	struct mce_hw *hw = &(vsi->back->hw);
//
//	hw->ops->enable_proc(hw);
//}

static void mce_vsi_start_hw_transmit(struct mce_vsi *vsi)
{
	struct mce_hw *hw = &(vsi->back->hw);

	hw->ops->disable_proc(hw);
}

void mce_vsi_cfg_netdev_tc(struct mce_vsi *vsi, struct mce_dcb *dcb)
{
	struct net_device *netdev = vsi->netdev;
	//struct mce_tc_cfg *tccfg = &(dcb->cur_tccfg);
	//int i = 0;

	if (netdev == NULL)
		return;

	netdev_reset_tc(netdev);

	// never setup this, driver do mapping pro to tc
	/*
	if (tccfg->ntc_cnt) {
		netdev_set_num_tc(netdev, tccfg->ntc_cnt);

		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			netdev_set_prio_tc_map(netdev, i, tccfg->prio_tc[i]);
		}

		for (i = 0; i < tccfg->ntc_cnt; i++) {
			netdev_set_tc_queue(netdev, i, tccfg->ntc_txq_cunt[i],
					tccfg->ntc_txq_base[i]);
		}
	} */
}

static void mce_vsi_dcb_all_default(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	mce_dcb_tc_default(&(dcb->cur_tccfg));
	mce_dcb_tc_default(&(dcb->new_tccfg));
	mce_dcb_ets_default(&(dcb->cur_etscfg));
	mce_dcb_ets_default(&(dcb->new_etscfg));
	mce_dcb_pfc_default(&(dcb->cur_pfccfg));
	mce_dcb_pfc_default(&(dcb->new_pfccfg));
}

void mce_vsi_dcb_default(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	u8 i = 0;

	mutex_lock(&(dcb->dcb_mutex));

	/* setup default dscp_map */
	for (i = 0; i < MCE_MAX_DSCP; i++)
		dcb->dscp_map[i] = (i / 8);

	dcb->dcbx_cap = DCB_CAP_DCBX_VER_IEEE | DCB_CAP_DCBX_VER_CEE |
			DCB_CAP_DCBX_HOST;
	//dcb->dcbx_cap = DCB_CAP_DCBX_VER_IEEE |
	//		DCB_CAP_DCBX_HOST;

	mce_vsi_dcb_all_default(vsi);

	// for test
	//set_bit(MCE_DCB_EN, dcb->flags);
	/*
	 * never setup dcb state accroding to queues count ? */
	 /*
	if (vsi->num_txq >= MCE_MAX_PRIORITY) {
		set_bit(MCE_DCB_EN, dcb->flags);
		mce_dcbnl_set_app(dcb, vsi->netdev);
	} else {
		clear_bit(MCE_DCB_EN, dcb->flags);
	} */

	mutex_unlock(&(dcb->dcb_mutex));
}

static void mce_vsi_dcb_check(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	//struct mce_hw *hw = &(pf->hw);
	struct mce_dcb *dcb = pf->dcb;

	mutex_lock(&(dcb->dcb_mutex));

//	if (vsi->num_txq >= MCE_MAX_PRIORITY) {
//	//	if (!test_bit(MCE_DCB_EN, dcb->flags)) {
//	//		mce_dcbnl_set_app(dcb, vsi->netdev);
//	//		set_bit(MCE_DCB_EN, dcb->flags);
//	//	}
//
//		if (!test_bit(MCE_PFC_EN, dcb->flags) &&
//		    !test_bit(MCE_ETS_EN, dcb->flags))
//			mce_vsi_dcb_all_default(vsi);
//
//		if (test_bit(MCE_PFC_EN, dcb->flags)) {
//			u16 tmp_cnt = 0;
//
//			tmp_cnt = (u16)DIV_ROUND_UP(vsi->num_txq,
//						    MCE_MAX_QCNT_IN_QG);
//
//			if (tmp_cnt >= MCE_MAX_TC_CNT)
//				dcb->cur_etscfg.ets_cap = MCE_MAX_TC_CNT;
//			else
//				dcb->cur_etscfg.ets_cap = tmp_cnt;
//		}
//
//	} else {
//		if (test_bit(MCE_DCB_EN, dcb->flags))
//			mce_dcbnl_del_app(dcb, vsi->netdev);

	/* default close all */
		// don't change dcb
		//clear_bit(MCE_DCB_EN, dcb->flags);
		clear_bit(MCE_ETS_EN, dcb->flags);
		clear_bit(MCE_PFC_EN, dcb->flags);
		//clear_bit(MCE_DSCP_EN, dcb->flags);

		mce_vsi_dcb_all_default(vsi);

		//hw->ops->disable_tc(hw);
		//hw->ops->set_q_to_tc(hw, dcb);
	//}

	mutex_unlock(&(dcb->dcb_mutex));
}

/**
 * mce_vsi_recfg_qs - Change the number of queues on a VSI
 * @vsi: VSI being changed
 * @new_rx: new number of Rx queues
 * @new_tx: new number of Tx queues
 *
 * Only change the number of queues if new_tx, or new_rx is non-0.
 *
 * Returns 0 on success.
 */
int mce_vsi_recfg_qs(struct mce_vsi *vsi, int new_rx, int new_tx)
{
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	int err = 0, timeout = 50;

	if (!new_rx && !new_tx)
		return -EINVAL;

	while (test_and_set_bit(MCE_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	if (new_tx)
		vsi->req_txq = (u16)new_tx;
	if (new_rx) {
		vsi->req_rxq = (u16)new_rx;
		// reset rss table if new rx set
		hw->hw_flags &= (~MCE_F_RSS_TABLE_INITED);
	}

	/* set for the next time the netdev is started */
	if (!netif_running(vsi->netdev)) {
		mce_vsi_rebuild(vsi);
		dev_dbg(mce_pf_to_dev(pf),
			"Link is down, queue count change happens "
			"when link is brought up\n");
		goto done;
	}

	mce_vsi_close(vsi);
	mce_vsi_rebuild(vsi);
	mce_vsi_open(vsi);
done:
	clear_bit(MCE_CFG_BUSY, pf->state);
	return err;
}

/**
 * mce_vsi_type_str - maps VSI type enum to string equivalents
 * @vsi_type: VSI type enum
 */
const char *mce_vsi_type_str(enum mce_vsi_type vsi_type)
{
	switch (vsi_type) {
	case MCE_VSI_PF:
		return "MCE_VSI_PF";
	case MCE_VSI_VF:
		return "MCE_VSI_VF";
	default:
		return "unknown";
	}
}

/**
 * mce_get_num_local_cpus - Get number of local cpus
 * @dev: pointer to device
 *
 * Return number of local cpus
 */
int mce_get_num_local_cpus(struct device *dev)
{
	int node = dev_to_node(dev);

	if (node == NUMA_NO_NODE)
		return cpumask_weight(cpu_online_mask);
	else
		return cpumask_weight(cpumask_of_node(node));
}

/*
 * mce_normalize_cpu_count - normalize the cpu count.
 * @num_cpus: number of cpu cores
 *
 * Returns the cpu count limited to a predefined
 * range of [MIN_DEFAULT_VECTORS, MAX_DEFAULT_VECTORS].
 */
int mce_normalize_cpu_count(int num_cpus)
{
	if (num_cpus > MAX_DEFAULT_VECTORS)
		num_cpus = MAX_DEFAULT_VECTORS;
	else if (num_cpus < MIN_DEFAULT_VECTORS)
		num_cpus = MIN_DEFAULT_VECTORS;
	return num_cpus;
}

/**
 * mce_vsi_set_num_desc - Set number of descriptors for queues on this VSI
 * @vsi: the VSI being configured
 */
static void mce_vsi_set_num_desc(struct mce_vsi *vsi)
{
	if (!vsi->num_rx_desc)
		vsi->num_rx_desc = MCE_MAX_NUM_DESC_DEFAULT;
	if (!vsi->num_tx_desc)
		vsi->num_tx_desc = MCE_MAX_NUM_DESC_DEFAULT;
}

/**
 * mce_vsi_set_num_qs - 确定需要的队列数量，使用的队列数量，qvec的数量
 *
 * 需要的队列数量：支持的最大队列数量
 * 使用的队列数量：qvec的数量，或者是指定数量（指定数量来自用户，或者根据tc数量算出）
 * qvec的数量：总中断数量 - mobx中断数量 - rdma中断数量
 */
static void mce_vsi_set_num_qs(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	u16 q_irq_cnt = 0;
	struct mce_dcb *dcb = pf->dcb;

	vsi->base_vector = pf->qvec_irq_base;

	if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSIX) {
		/* TODO: vector 0-3: ring 0-3, vector 4/5: rdma
		 * vector 6: reserved, vector 7: mbx
		 */
#ifdef MCE_DEBUG_XINSI_PCIE
		q_irq_cnt = pf->num_msix_cnt - pf->num_mbox_irqs -
			    pf->num_rdma_irqs;
#else
		q_irq_cnt = pf->num_msix_cnt - pf->num_mbox_irqs -
			    pf->num_rdma_irqs - 1;
#endif
	} else if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSI) {
		/* in msi mode, vector 0: ring0 and mbx */
		q_irq_cnt = MCE_PCIE_IRQ_MODE_NO_MSIX_MAX_VECTORS;
	} else {
		/* in legency mode, vector 0: ring0 and mbx */
		q_irq_cnt = MCE_PCIE_IRQ_MODE_NO_MSIX_MAX_VECTORS;
	}
	vsi->num_q_vectors = q_irq_cnt;

	/* we always alloc for all queues */
	// should update if in soc, should relative with cpus?
	vsi->alloc_txq = pf->max_pf_txqs;
	vsi->alloc_rxq = pf->max_pf_rxqs;
	vsi->num_tc_offset = pf->max_pf_txqs / pf->num_max_tc;

	if (vsi->req_txq)
		vsi->num_txq_real = vsi->req_txq;
	else
		vsi->num_txq_real = min_t(u16, q_irq_cnt, vsi->alloc_txq / pf->num_max_tc);
	

	// if dcb on
	if (test_bit(MCE_DCB_EN, dcb->flags)) {
		/* maybe reset by tc num todo */
		vsi->num_txq = vsi->num_txq_real * pf->num_max_tc;
	} else {
		vsi->num_txq = vsi->num_txq_real;
	}
	// consider q_vector is more ?
	if (pf->max_pf_rxqs == 8)
		vsi->num_q_vectors = min_t(u16, q_irq_cnt, vsi->num_txq_real);
	else
		vsi->num_q_vectors = min_t(u16, q_irq_cnt, vsi->num_txq);

	// some q_vector has only tx 
	// since tx >= rx
	/* only 1 Rx queue unless RSS is enabled */
	if (!test_bit(MCE_FLAG_RSS_ENA, pf->flags)) {
		vsi->num_rxq = 1;
	} else {
		if (vsi->req_rxq)
			vsi->num_rxq = vsi->req_rxq;
		else
			vsi->num_rxq = min_t(u16, q_irq_cnt, vsi->alloc_rxq / pf->num_max_tc);
		// if dcb on
		// only chengjian
		if (pf->max_pf_rxqs == 8) {
			if (test_bit(MCE_DCB_EN, dcb->flags)) {
				/* maybe reset by tc num todo */
				vsi->num_rxq = vsi->num_rxq * pf->num_max_tc;
			} else {
				vsi->num_rxq = vsi->num_rxq;
			}
		}
	}
}

/**
 * mce_vsi_alloc_arrays - Allocate queue and vector pointer arrays for the VSI
 * @vsi: VSI pointer
 *
 * On error: returns error code (negative)
 * On success: returns 0
 */
static int mce_vsi_alloc_arrays(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	struct device *dev = mce_pf_to_dev(pf);

	/* allocate memory for both Tx and Rx ring pointers */
	vsi->tx_rings = devm_kcalloc(dev, vsi->alloc_txq,
				     sizeof(*vsi->tx_rings), GFP_KERNEL);
	if (!vsi->tx_rings) {
		dev_err(dev, "vsi devm_kcalloc tx_rings failed\n");
		return -ENOMEM;
	}

	vsi->rx_rings = devm_kcalloc(dev, vsi->alloc_rxq,
				     sizeof(*vsi->rx_rings), GFP_KERNEL);
	if (!vsi->rx_rings) {
		dev_err(dev, "vsi devm_kcalloc rx_rings failed\n");
		goto err_rings;
	}

	/* allocate memory for q_vector pointers */
	vsi->q_vectors = devm_kcalloc(dev, vsi->num_q_vectors,
				      sizeof(*vsi->q_vectors), GFP_KERNEL);
	if (!vsi->q_vectors) {
		dev_err(dev, "vsi devm_kcalloc q_vectors failed\n");
		goto err_vectors;
	}

	return 0;

err_vectors:
	devm_kfree(dev, vsi->rx_rings);
err_rings:
	devm_kfree(dev, vsi->tx_rings);
	return -ENOMEM;
}

/**
 * mce_msix_clean_rings - MSIX mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
#ifdef HAVE_NETPOLL_CONTROLLER
irqreturn_t mce_msix_clean_rings(int __always_unused irq, void *data)
#else
static irqreturn_t mce_msix_clean_rings(int __always_unused irq,
					void *data)
#endif /* HAVE_NETPOLL_CONTROLLER */
{
	struct mce_q_vector *q_vector = data;

#ifndef THREAD_POLL
	if (!q_vector->tx.ring && !q_vector->rx.ring)
		return IRQ_HANDLED;
	q_vector->total_events++;
	mce_disable_vec_txrxs_irq(q_vector);
#endif
	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * mce_intr_clean_rings - MSI/LEGENCY mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
#ifdef HAVE_NETPOLL_CONTROLLER
irqreturn_t mce_intr_clean_rings(int __always_unused irq, void *data)
#else
static irqreturn_t mce_intr_clean_rings(int __always_unused irq,
					void *data)
#endif /* HAVE_NETPOLL_CONTROLLER */
{
	struct mce_q_vector *q_vector = data;
#ifdef MCE_DEBUG_VF
	struct mce_pf *pf = q_vector->vsi->back;
#endif

#ifndef THREAD_POLL
	if (!q_vector->tx.ring && !q_vector->rx.ring)
		return IRQ_HANDLED;
	q_vector->total_events++;
	mce_disable_vec_txrxs_irq(q_vector);
#endif
	napi_schedule(&q_vector->napi);
#ifdef MCE_DEBUG_VF
	mce_clean_mailboxq_subtask(pf);
#endif
	return IRQ_HANDLED;
}

/**
 * mce_vsi_alloc_stat_arrays - Allocate statistics arrays
 * @vsi: VSI pointer
 */
static int mce_vsi_alloc_stat_arrays(struct mce_vsi *vsi)
{
	struct mce_vsi_stats *vsi_stat;
	struct mce_pf *pf = vsi->back;
	struct device *dev;
	u16 alloc_qps;

	dev = mce_pf_to_dev(pf);

	if (!pf->vsi_stats)
		return -ENOENT;

	vsi_stat = devm_kzalloc(dev, sizeof(*vsi_stat), GFP_KERNEL);

	if (!vsi_stat)
		return -ENOMEM;

	alloc_qps = vsi->alloc_txq;

	vsi_stat->tx_ring_stats =
		devm_kcalloc(dev, alloc_qps,
			     sizeof(*vsi_stat->tx_ring_stats), GFP_KERNEL);

	vsi_stat->rx_ring_stats =
		devm_kcalloc(dev, alloc_qps,
			     sizeof(*vsi_stat->rx_ring_stats), GFP_KERNEL);

	if (!vsi_stat->tx_ring_stats || !vsi_stat->rx_ring_stats)
		goto err_alloc;

	pf->vsi_stats[vsi->idx] = vsi_stat;

	return 0;

err_alloc:
	devm_kfree(mce_pf_to_dev(pf), vsi_stat->tx_ring_stats);
	devm_kfree(mce_pf_to_dev(pf), vsi_stat->rx_ring_stats);
	devm_kfree(mce_pf_to_dev(pf), vsi_stat);
	return -ENOMEM;
}

/**
 * mce_get_free_slot - get the next available free slot in array
 * @array: array to search
 * @size: size of the array
 * @curr: last known occupied index to be used as a search hint
 *
 * void * is being used to keep the functionality generic. This lets us use this
 * function on any array of pointers.
 */
static int mce_get_free_slot(void *array, int size, int curr)
{
	int **tmp_array = array;
	int next;

	if (curr < (size - 1) && !tmp_array[curr + 1]) {
		next = curr + 1;
	} else {
		int i = 0;

		while ((i < size) && (tmp_array[i]))
			i++;
		if (i == size)
			next = MCE_NO_VSI;
		else
			next = i;
	}
	return next;
}

static struct mce_vsi *mce_vsi_alloc(struct mce_pf *pf,
				     enum mce_vsi_type vsi_type)
{
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_vsi *vsi = NULL;

	mutex_lock(&pf->sw_mutex);

	if (pf->next_vsi == MCE_NO_VSI) {
		dev_err(dev, "out of VSI slots!\n");
		goto unlock_pf;
	}

	if (pf->vsi[pf->next_vsi]) {
		dev_err(dev, "VSI slot %u already in use!\n",
			pf->next_vsi);
		goto unlock_pf;
	}

	vsi = devm_kzalloc(dev, sizeof(*vsi), GFP_KERNEL);
	if (!vsi) {
		dev_err(dev, "vsi devm_kzalloc failed!\n");
		goto unlock_pf;
	}

	vsi->type = vsi_type;
	vsi->back = pf;
	vsi->idx = pf->next_vsi;

	mce_vsi_set_num_qs(vsi);
	mce_vsi_set_num_desc(vsi);

	if (mce_vsi_alloc_arrays(vsi))
		goto err_rings;

	/* Setup default MSIX irq handler for VSI */
	if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSIX)
		vsi->irq_handler = mce_msix_clean_rings;
	else
		vsi->irq_handler = mce_intr_clean_rings;

	/* allocate memory for Tx/Rx ring stat pointers */
	if (mce_vsi_alloc_stat_arrays(vsi))
		goto err_rings;

	pf->vsi[vsi->idx] = vsi;

	pf->next_vsi = mce_get_free_slot(pf->vsi, pf->num_alloc_vsi,
					 pf->next_vsi);

	goto unlock_pf;

err_rings:
	devm_kfree(dev, vsi);
	vsi = NULL;
unlock_pf:
	mutex_unlock(&pf->sw_mutex);
	return vsi;
}

/**
 * mce_vsi_free_arrays - De-allocate queue and vector pointer arrays for the VSI
 * @vsi: pointer to VSI being cleared
 */
static void mce_vsi_free_arrays(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	struct device *dev;

	dev = mce_pf_to_dev(pf);

	/* free the ring and vector containers */
	if (vsi->q_vectors) {
		devm_kfree(dev, vsi->q_vectors);
		vsi->q_vectors = NULL;
	}
	if (vsi->tx_rings) {
		devm_kfree(dev, vsi->tx_rings);
		vsi->tx_rings = NULL;
	}
	if (vsi->rx_rings) {
		devm_kfree(dev, vsi->rx_rings);
		vsi->rx_rings = NULL;
	}
}

/**
 * mce_free_irq_res -  释放从start开始,needed个连续的中断资源
 *
 * 成功返回0
 */
int mce_free_irq_res(struct mce_res_tracker *res, u16 needed, u16 start)
{
	u16 i = start;

	if (!res || needed > res->end || start > res->end ||
	    start + needed > res->end)
		return -EINVAL;

	while (needed--) {
		res->list[i++] = 0;
	}

	return 0;
}

/**
 * mce_get_irq_res: 从start开始,使用needed个连续的中断资源
 *
 * 成功返回0
 */
int mce_get_irq_res(struct mce_pf *pf, struct mce_res_tracker *res,
		    u16 needed, u16 start)
{
	u16 end = 0;

	if (!res || !pf)
		return -EINVAL;
	/* no msix mode, only one vector for ring */
	if (pf->pcie_irq_mode != MCE_PCIE_IRQ_MODE_MSIX)
		return 0;
	if (!needed || needed > res->num_entries) {
		dev_err(mce_pf_to_dev(pf),
			"param err: needed=%d, num_entries = %d\n", needed,
			res->num_entries);
		return -EINVAL;
	}
	if (needed > res->end || start > res->end ||
	    start + needed > res->end)
		return -ENOMEM;
	do {
		/* skip already allocated entries */
		if (res->list[end++] & MCE_RES_VALID_BIT) {
			start = end;
			if ((start + needed) > res->end)
				break;
		}

		if (end == (start + needed)) {
			int i = start;

			/* there was enough, so assign it to the requestor */
			while (i != end)
				res->list[i++] = MCE_RES_VALID_BIT;

			return 0;
		}
	} while (end < res->end);
	return -ENOMEM;
}

/**
 * 功能: 为队列向量申请可用的中断资源
 *
 * 成功返回0
 */
static int mce_vsi_alloc_q_irq_res(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	u16 need_cnt = vsi->num_q_vectors;
	u16 start_id = vsi->base_vector;
	int ret = 0;

	ret = mce_get_irq_res(pf, pf->irq_tracker, need_cnt, start_id);
	if (ret == 0)
		pf->num_avail_msix -= need_cnt;

	return ret;
}

static void mce_vsi_free_q_irq_res(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	u16 need_cnt = vsi->num_q_vectors;
	u16 start_id = vsi->base_vector;
	int ret = 0;

	ret = mce_free_irq_res(pf->irq_tracker, need_cnt, start_id);
	if (ret)
		dev_err(mce_pf_to_dev(pf), "free_q_irq_res err\n");
	else
		pf->num_avail_msix += need_cnt;
}

/**
 * mce_vsi_clear_rings - Deallocates the Tx and Rx rings for VSI
 * @vsi: the VSI having rings deallocated
 */
static void mce_vsi_clear_rings(struct mce_vsi *vsi)
{
	int i;

	/* Avoid stale references by clearing map from vector to ring */
	if (vsi->q_vectors) {
		mce_for_each_q_vector(vsi, i)
		{
			struct mce_q_vector *q_vector = vsi->q_vectors[i];

			if (q_vector) {
				q_vector->tx.ring = NULL;
				q_vector->rx.ring = NULL;
			}
		}
	}

	if (vsi->tx_rings) {
		for (i = 0; i < vsi->alloc_txq; i++) {
			mce_destroy_txring(vsi, i);
		}
	}
	if (vsi->rx_rings) {
		for (i = 0; i < vsi->alloc_rxq; i++) {
			mce_destroy_rxring(vsi, i);
		}
	}
}

/**
 * mce_vsi_alloc_rings - Allocates Tx and Rx rings for the VSI
 * @vsi: VSI which is having rings allocated
 */
static int mce_vsi_alloc_rings(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	struct device *dev;
	u16 i;

	dev = mce_pf_to_dev(pf);
	/* Allocate Tx rings */
	for (i = 0; i < vsi->alloc_txq; i++) {
		if (mce_create_txring(vsi, i))
			goto err_out;
	}

	/* Allocate Rx rings */
	for (i = 0; i < vsi->alloc_rxq; i++) {
		if (mce_create_rxring(vsi, i))
			goto err_out;
	}

	return 0;

err_out:
	mce_vsi_clear_rings(vsi);
	return -ENOMEM;
}

/**
 * mce_vsi_free_stats - Free the ring statistics structures
 * @vsi: VSI pointer
 */
static void mce_vsi_free_stats(struct mce_vsi *vsi)
{
	struct mce_vsi_stats *vsi_stat;
	struct mce_pf *pf = vsi->back;
	int i;

	if (!pf->vsi_stats)
		return;

	vsi_stat = pf->vsi_stats[vsi->idx];

	if (!vsi_stat)
		return;

	for (i = 0; i < vsi->alloc_txq; i++) {
		if (vsi_stat->tx_ring_stats[i]) {
			kfree_rcu(vsi_stat->tx_ring_stats[i], rcu);
			WRITE_ONCE(vsi_stat->tx_ring_stats[i], NULL);
		}
	}

	for (i = 0; i < vsi->alloc_rxq; i++) {
		if (vsi_stat->rx_ring_stats[i]) {
			kfree_rcu(vsi_stat->rx_ring_stats[i], rcu);
			WRITE_ONCE(vsi_stat->rx_ring_stats[i], NULL);
		}
	}

	devm_kfree(mce_pf_to_dev(pf), vsi_stat->tx_ring_stats);
	vsi_stat->tx_ring_stats = NULL;
	devm_kfree(mce_pf_to_dev(pf), vsi_stat->rx_ring_stats);
	vsi_stat->rx_ring_stats = NULL;
	devm_kfree(mce_pf_to_dev(pf), vsi_stat);
	pf->vsi_stats[vsi->idx] = NULL;
}

/**
 * mce_vsi_map_rings_to_vectors - Map VSI rings to interrupt vectors
 * @vsi: the VSI being configured
 *
 * This function maps descriptor rings to the queue-specific vectors allotted
 * through the MSI-X enabling code. On a constrained vector budget, we map Tx
 * and Rx rings to the vector as "efficiently" as possible.
 */
static void mce_vsi_map_rings_to_vectors(struct mce_vsi *vsi)
{
	int q_vectors = vsi->num_q_vectors;
	u16 tx_rings_rem, rx_rings_rem;
	int v_id;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	u16 q_base = 0, q_id = 0, q_base_dcb_t = 0, q_id_tx = 0;
	u16 q_id_rx = 0;
	u16 q_base_dcb_r = 0;

	/* initially assigning remaining rings count to VSIs num queue value */
	tx_rings_rem = vsi->num_txq;
	rx_rings_rem = vsi->num_rxq;

	for (v_id = 0; v_id < q_vectors; v_id++) {
		struct mce_q_vector *q_vector = vsi->q_vectors[v_id];
		u8 tx_rings_per_v, rx_rings_per_v;
		int step = 1, j = 0;

		/* Tx rings mapping to vector */
		tx_rings_per_v =
			(u8)DIV_ROUND_UP(tx_rings_rem, q_vectors - v_id);
		q_vector->num_ring_tx = tx_rings_per_v;
		q_vector->tx.ring = NULL;
		// if dcb on, consider num_txq_real, to valid idx ring
		if (test_bit(MCE_DCB_EN, dcb->flags)) {
			step = pf->max_pf_txqs / pf->num_max_tc;

			for (j = 0; j < tx_rings_per_v; j++) {
				struct mce_ring *tx_ring = vsi->tx_rings[q_id_tx];

				//printk("dcb remap %d to vector %d\n", q_id_tx, v_id);
				if (tx_ring) {
					tx_ring->q_vector = q_vector;
					tx_ring->next = q_vector->tx.ring;
					q_vector->tx.ring = tx_ring;
				} else {
					dev_err(mce_pf_to_dev(vsi->back),
							"NULL Tx ring found\n");
					break;
				}
				q_id_tx = q_id_tx + step;

				/* if more than num_txq, add q_base and reset q_id_tx */
				if (q_id_tx >= vsi->alloc_txq) {
					q_base_dcb_t++; 
					q_id_tx = q_base_dcb_t;
				}
			}
		} else {
			step = 1;
			q_base = vsi->num_txq - tx_rings_rem;
			for (q_id = q_base, j = 0; j < tx_rings_per_v;
					q_id = q_id + step, j++) {
				struct mce_ring *tx_ring = vsi->tx_rings[q_id];

				//printk("remap %d to vector %d\n", q_id, v_id);
				if (tx_ring) {
					tx_ring->q_vector = q_vector;
					tx_ring->next = q_vector->tx.ring;
					q_vector->tx.ring = tx_ring;
				} else {
					dev_err(mce_pf_to_dev(vsi->back),
							"NULL Tx ring found\n");
					break;
				}
			}
		}

		tx_rings_rem -= tx_rings_per_v;

		/* Rx rings mapping to vector */
		rx_rings_per_v =
			(u8)DIV_ROUND_UP(rx_rings_rem, q_vectors - v_id);
		q_vector->num_ring_rx = rx_rings_per_v;
		q_vector->rx.ring = NULL;
		// only for chengjian 
		if ((pf->max_pf_rxqs == 8) && (test_bit(MCE_DCB_EN, dcb->flags))) {
			step = pf->max_pf_rxqs / pf->num_max_tc;

			for (j = 0; j < rx_rings_per_v; j++) {
				struct mce_ring *rx_ring = vsi->rx_rings[q_id_rx];

				//printk("dcb remap rx %d to vector %d\n", q_id_rx, v_id);
				if (rx_ring) {
					rx_ring->q_vector = q_vector;
					rx_ring->next = q_vector->rx.ring;
					q_vector->rx.ring = rx_ring;
				} else {
					dev_err(mce_pf_to_dev(vsi->back),
							"NULL Rx ring found\n");
					break;
				}
				q_id_rx = q_id_rx + step;

				/* if more than num_rxq, add q_base and reset q_id_rx */
				if (q_id_rx >= vsi->alloc_rxq) {
					q_base_dcb_r++; 
					q_id_rx = q_base_dcb_r;
				}
			}
		} else {
			step = 1;
			q_base = vsi->num_rxq - rx_rings_rem;
			for (q_id = q_base, j = 0; j < rx_rings_per_v;
					q_id = q_id + step, j++) {
				struct mce_ring *rx_ring = vsi->rx_rings[q_id];

				//printk("remap rx %d to vector %d\n", q_id, v_id);
				if (rx_ring) {
					rx_ring->q_vector = q_vector;
					rx_ring->next = q_vector->rx.ring;
					q_vector->rx.ring = rx_ring;
				} else {
					dev_err(mce_pf_to_dev(vsi->back),
							"NULL Rx ring found\n");
					break;
				}
			}
		}
		rx_rings_rem -= rx_rings_per_v;
	}
}

/**
 * mce_vsi_alloc_ring_stats - Allocates Tx and Rx ring stats for the VSI
 * @vsi: VSI which is having stats allocated
 */
static int mce_vsi_alloc_ring_stats(struct mce_vsi *vsi)
{
	struct mce_ring_stats **tx_ring_stats;
	struct mce_ring_stats **rx_ring_stats;
	struct mce_vsi_stats *vsi_stats;
	struct mce_pf *pf = vsi->back;
	u16 i;

	if (!pf->vsi_stats)
		return -ENOENT;

	vsi_stats = pf->vsi_stats[vsi->idx];

	if (!vsi_stats) {
		dev_err(&(pf->pdev->dev), "vsi_stats is NULL\n");
		return -ENOENT;
	}

	tx_ring_stats = vsi_stats->tx_ring_stats;

	if (!tx_ring_stats) {
		dev_err(&(pf->pdev->dev), "tx_ring_stats is NULL\n");
		return -ENOENT;
	}

	rx_ring_stats = vsi_stats->rx_ring_stats;

	if (!rx_ring_stats) {
		dev_err(&(pf->pdev->dev), "rx_ring_stats is NULL\n");
		return -ENOENT;
	}

	/* Allocate Tx ring stats */
	for (i = 0; i < vsi->alloc_txq; i++) {
		struct mce_ring_stats *ring_stats;
		struct mce_ring *ring;

		ring = vsi->tx_rings[i];
		ring_stats = tx_ring_stats[i];

		if (!ring_stats) {
			ring_stats =
				kzalloc(sizeof(*ring_stats), GFP_KERNEL);
			if (!ring_stats)
				goto err_out;

			WRITE_ONCE(tx_ring_stats[i], ring_stats);
		}

		ring->ring_stats = ring_stats;
	}

	/* Allocate Rx ring stats */
	for (i = 0; i < vsi->alloc_rxq; i++) {
		struct mce_ring_stats *ring_stats;
		struct mce_ring *ring;

		ring = vsi->rx_rings[i];
		ring_stats = rx_ring_stats[i];

		if (!ring_stats) {
			ring_stats =
				kzalloc(sizeof(*ring_stats), GFP_KERNEL);
			if (!ring_stats)
				goto err_out;

			WRITE_ONCE(rx_ring_stats[i], ring_stats);
		}

		ring->ring_stats = ring_stats;
	}

	return 0;

err_out:
	mce_vsi_free_stats(vsi);
	return -ENOMEM;
}

/**
 * mce_vsi_clear - clean up and deallocate the provided VSI
 * @vsi: pointer to VSI being cleared
 *
 * This deallocates the VSI's queue resources, removes it from the PF's
 * VSI array if necessary, and deallocates the VSI
 *
 * Returns 0 on success, negative on failure
 */
static int mce_vsi_clear(struct mce_vsi *vsi)
{
	struct mce_pf *pf = NULL;
	struct device *dev;

	if (!vsi)
		return 0;

	if (!vsi->back)
		return -EINVAL;

	pf = vsi->back;
	dev = mce_pf_to_dev(pf);

	if (!pf->vsi[vsi->idx] || pf->vsi[vsi->idx] != vsi) {
		dev_dbg(dev, "vsi does not exist at pf->vsi[%d]\n",
			vsi->idx);
		return -EINVAL;
	}

	mutex_lock(&pf->sw_mutex);
	/* updates the PF for this cleared VSI */

	pf->vsi[vsi->idx] = NULL;
	if (vsi->idx < pf->next_vsi)
		pf->next_vsi = vsi->idx;

	mce_vsi_free_arrays(vsi);
	mutex_unlock(&pf->sw_mutex);
	devm_kfree(dev, vsi);

	return 0;
}

/**
 * mce_vsi_cfg_qvec_irq - 设置硬件irq_vector和队列中断的映射关系
 */
static void mce_vsi_cfg_qvec_irq(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	struct mce_q_vector *q_vector = NULL;
	struct mce_ring *tx_ring = NULL;
	struct mce_ring *rx_ring = NULL;
	u16 qvec_base = vsi->base_vector;
	int i = 0, j = 0;

	/* 先全部清0 */
	for (i = 0; i < pf->max_pf_txqs; i++)
		hw->ops->cfg_vec2tqirq(hw, i, 0);

	for (i = 0; i < pf->max_pf_rxqs; i++)
		hw->ops->cfg_vec2rqirq(hw, i, 0);
#ifdef MCE_13P_DEBUG_MSIX
       wr32(hw, 0x28000, 0);
       wr32(hw, 0x28008, 0);
       wr32(hw, 0x28018, 1);
       wr32(hw, 0x28028, 2);
       wr32(hw, 0x28038, 3);
       wr32(hw, 0x28048, 4);
       wr32(hw, 0x28058, 5);
       wr32(hw, 0x28068, 6);
       wr32(hw, 0x28078, 7);
#endif

	mce_for_each_q_vector(vsi, i)
	{
		q_vector = vsi->q_vectors[i];
		j = q_vector->v_idx;

		/* 告诉硬件txq使用的队列中断 */
		mce_rc_for_each_ring(tx_ring, q_vector->tx) {
			if (tx_ring == NULL)
				continue;

			hw->ops->cfg_vec2tqirq(
				hw, tx_ring->q_index + hw->ring_base_addr,
				(j + qvec_base));
		}

		/* 告诉硬件rxq使用的队列中断 */
		mce_rc_for_each_ring(rx_ring, q_vector->tx) {
			if (rx_ring == NULL)
				continue;

			hw->ops->cfg_vec2rqirq(
				hw, rx_ring->q_index + hw->ring_base_addr,
				(j + qvec_base));
		}
	}
}

struct mce_vsi *mce_vsi_setup(struct mce_pf *pf,
			      enum mce_vsi_type vsi_type)
{
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_vsi *vsi = NULL;
	struct mce_hw *hw = &(pf->hw);
	int ret = 0;

	vsi = mce_vsi_alloc(pf, vsi_type);
	if (!vsi) {
		dev_err(dev, "could not allocate VSI\n");
		return NULL;
	}

	// we start from down state
	set_bit(MCE_VSI_DOWN, vsi->state);
	vsi->port_info = hw->port_info;
	// in default prio 7 is for rdma
	if (pf->m_status == MRDMA_INSMOD) {
		vsi->valid_prio = 0x7f;
	} else {
		vsi->valid_prio = 0xff;
	}

	ret = mce_vsi_alloc_q_vectors(vsi);
	if (ret) {
		dev_err(dev, "VSI failed to alloc q_vectors\n");
		goto unroll_vsi_alloc;
	}

	ret = mce_vsi_alloc_q_irq_res(vsi);
	if (ret) {
		dev_err(dev, "VSI failed to alloc vector irq res\n");
		goto unroll_alloc_q_vector;
	}

	ret = mce_vsi_alloc_rings(vsi);
	if (ret) {
		dev_err(dev, "VSI failed to alloc rings\n");
		goto unroll_vector_base;
	}
	// should update me later
	mce_vsi_map_rings_to_vectors(vsi);
	mce_vsi_cfg_qvec_irq(vsi);

	ret = mce_vsi_alloc_ring_stats(vsi);
	if (ret) {
		dev_err(dev, "VSI failed to alloc rings stats\n");
		goto unroll_clear_rings;
	}

	return vsi;

unroll_clear_rings:
	mce_vsi_clear_rings(vsi);
unroll_vector_base:
	/* reclaim SW interrupts back to the common pool */
	mce_vsi_free_q_irq_res(vsi);
unroll_alloc_q_vector:
	mce_vsi_free_q_vectors(vsi);
	mce_vsi_free_stats(vsi);
unroll_vsi_alloc:
	mce_vsi_clear(vsi);

	return NULL;
}

/**
 * mce_vsi_cfg_frame_size - setup max frame size and Rx buffer length
 * @vsi: VSI
 */
void mce_vsi_cfg_frame_size(struct mce_vsi *vsi)
{
	if (!vsi->netdev ||
	    test_bit(MCE_FLAG_LEGACY_RX, vsi->back->flags)) {
		vsi->max_frame = MCE_AQ_SET_MAC_FRAME_SIZE_MAX;
		vsi->rx_buf_len = MCE_RXBUF_2048;
#if (PAGE_SIZE < 8192)
	} else if (!MCE_2K_TOO_SMALL_WITH_PADDING &&
		   (vsi->netdev->mtu <= ETH_DATA_LEN)) {
		vsi->max_frame = MCE_RXBUF_1536 - NET_IP_ALIGN;
		vsi->rx_buf_len = MCE_RXBUF_1536 - NET_IP_ALIGN;
#endif
	} else {
		vsi->max_frame = MCE_AQ_SET_MAC_FRAME_SIZE_MAX;
#if (PAGE_SIZE < 8192)
		vsi->rx_buf_len = MCE_RXBUF_3072;
#else
		vsi->rx_buf_len = MCE_RXBUF_2048;
#endif
	}
}

/**
 * mce_vsi_free_irq - Free the IRQ association with the OS
 * @vsi: the VSI being configured
 */
static void mce_vsi_free_irq(struct mce_vsi *vsi)
{
	struct mce_pf *pf = vsi->back;
	int base = vsi->base_vector;
	int i;

	if (!vsi->q_vectors || !vsi->irqs_ready)
		return;

	vsi->irqs_ready = false;

	mce_for_each_q_vector(vsi, i)
	{
		u16 vector = i + base;
		int irq_num;

		irq_num = mce_get_irq_num(pf, vector);

		/* free only the irqs that were actually requested */
		if (!vsi->q_vectors[i] ||
		    !(vsi->q_vectors[i]->num_ring_tx ||
		      vsi->q_vectors[i]->num_ring_rx))
			continue;

		/* clear the affinity notifier in the IRQ descriptor */
		if (1 || !IS_ENABLED(CONFIG_RFS_ACCEL))
			irq_set_affinity_notifier(irq_num, NULL);

		/* clear the affinity_mask in the IRQ descriptor */
		synchronize_irq(irq_num);
		devm_free_irq(mce_pf_to_dev(pf), irq_num,
			      vsi->q_vectors[i]);
	}
}

/**
 * mce_vsi_dis_irq - Mask off queue interrupt generation on the VSI
 * @vsi: the VSI being un-configured
 */
static void mce_vsi_dis_irq(struct mce_vsi *vsi)
{
	int base = vsi->base_vector;
	int i;

	/* disable each interrupt */
	mce_for_each_q_vector(vsi, i)
	{
		if (!vsi->q_vectors[i])
			continue;

		mce_disable_vec_txs_irq(vsi->q_vectors[i]);
		mce_disable_vec_rxs_irq(vsi->q_vectors[i]);
	}

	/* don't call synchronize_irq() for VF's from the host */
	if (vsi->type == MCE_VSI_VF)
		return;

	mce_for_each_q_vector(vsi, i)
		synchronize_irq(mce_get_irq_num(vsi->back, i + base));
}

/**
 * mce_vsi_stop_lan_tx_rings - Disable Tx rings
 * @vsi: the VSI being configured
 */
static int mce_vsi_stop_lan_tx_rings(struct mce_vsi *vsi)
{
	u16 q_idx;

	mce_for_each_txq_new(vsi, q_idx) {

		if (!vsi->tx_rings[q_idx]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, q_idx);
			continue;
		}
		mce_stop_tx_ring(vsi->tx_rings[q_idx]);
	}

	return 0;
}

/**
 * mce_vsi_stop_all_rx_rings - stop/disable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be disabled
 *
 * Returns 0 on success and a negative value on error
 */
static int mce_vsi_stop_all_rx_rings(struct mce_vsi *vsi)
{
	u16 q_idx;

	mce_for_each_rxq_new(vsi, q_idx) {
		if (!vsi->rx_rings[q_idx]->q_vector)
			continue;
		mce_stop_rx_ring(vsi->rx_rings[q_idx]);
	}

	return 0;
}

/**
 * mce_vsi_napi_disable_all - Disable NAPI for all q_vectors in the VSI
 * @vsi: VSI having NAPI disabled
 */
static void mce_vsi_napi_disable_all(struct mce_vsi *vsi)
{
	int q_idx;

	if (!vsi->netdev)
		return;

	mce_for_each_q_vector(vsi, q_idx)
	{
		struct mce_q_vector *q_vector = vsi->q_vectors[q_idx];

		if (q_vector->rx.ring || q_vector->tx.ring)
			napi_disable(&q_vector->napi);

		cancel_work_sync(&q_vector->tx.dim.work);
		cancel_work_sync(&q_vector->rx.dim.work);
	}
}

/**
 * mce_down - Shutdown the connection
 * @vsi: The VSI being stopped
 *
 * Caller of this function is expected to set the vsi->state MCE_DOWN bit
 */
int mce_down(struct mce_vsi *vsi)
{
	int link_err = 0, vlan_err = 0;
	int i, tx_err, rx_err;
	struct mce_hw *hw = &(vsi->back->hw);

	WARN_ON(!test_bit(MCE_VSI_DOWN, vsi->state));

	if (vsi->netdev && vsi->type == MCE_VSI_PF) {
		netif_tx_disable(vsi->netdev);
		netif_carrier_off(vsi->netdev);
		vsi->link = 0;
	}
	mce_fdir_del_all_fltrs(hw);
	// don't stop since rdma may using tx
	//mce_vsi_close_hw_transmit(vsi);
	
	mce_vsi_dis_irq(vsi);
	mce_vsi_napi_disable_all(vsi);

	tx_err = mce_vsi_stop_lan_tx_rings(vsi);
	if (tx_err)
		netdev_err(vsi->netdev,
			   "Failed stop Tx rings, VSI %d error %d\n",
			   vsi->idx, tx_err);

	rx_err = mce_vsi_stop_all_rx_rings(vsi);
	if (rx_err)
		netdev_err(vsi->netdev,
			   "Failed stop Rx rings, VSI %d error %d\n",
			   vsi->idx, rx_err);

	mce_for_each_txq_new(vsi, i) {
		if (!vsi->tx_rings[i]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, i);
			continue;
		}
		mce_clean_tx_ring(vsi->tx_rings[i]);
	}

	mce_for_each_rxq_new(vsi, i) {
		if (!vsi->rx_rings[i]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, i);
			continue;
		}
		mce_clean_rx_ring(vsi->rx_rings[i]);
	}


	if (tx_err || rx_err || link_err || vlan_err) {
		netdev_err(vsi->netdev, "Failed to close VSI 0x%04X\n",
			   vsi->idx);
		return -EIO;
	}

	return 0;
}

/**
 * mce_vsi_close - Shut down a VSI
 * @vsi: the VSI being shut down
 */
void mce_vsi_close(struct mce_vsi *vsi)
{
#ifdef THREAD_POLL
	vsi->quit_poll_thread = true;
	usleep_range(20000, 30000);
	kthread_stop(vsi->mce_poll_thread);
#endif

	if (!test_and_set_bit(MCE_VSI_DOWN, vsi->state))
		mce_down(vsi);
	mce_vsi_free_irq(vsi);
	mce_vsi_free_tx_rings(vsi);
	mce_vsi_free_rx_rings(vsi);
}

/**
 * mce_vsi_release - Delete a VSI and free its resources
 * @vsi: the VSI being removed
 *
 * Returns 0 on success or < 0 on error
 */
int mce_vsi_release(struct mce_vsi *vsi)
{
	struct mce_pf *pf;

	if (!vsi->back)
		return -ENODEV;
	pf = vsi->back;

	/* Disable VSI and free resources */
	//mce_vsi_close(vsi);


	if (vsi->netdev) {
		if (test_bit(MCE_VSI_NETDEV_REGISTERED, vsi->state)) {
			unregister_netdev(vsi->netdev);
			clear_bit(MCE_VSI_NETDEV_REGISTERED, vsi->state);
		}
		if (test_bit(MCE_VSI_NETDEV_ALLOCD, vsi->state)) {
			free_netdev(vsi->netdev);
			vsi->netdev = NULL;
			clear_bit(MCE_VSI_NETDEV_ALLOCD, vsi->state);
		}
	}

	/* reclaim SW interrupts back to the common pool */
	mce_free_irq_res(pf->irq_tracker, vsi->num_q_vectors,
			 vsi->base_vector);
	pf->num_avail_msix += vsi->num_q_vectors;
	mce_vsi_free_q_vectors(vsi);
	mce_vsi_clear_rings(vsi);
	mce_vsi_free_stats(vsi);

	mce_vsi_clear(vsi);

	return 0;
}

/**
 * mce_vsi_release_all - Delete all VSIs
 * @pf: PF from which all VSIs are being removed
 */
void mce_vsi_release_all(struct mce_pf *pf)
{
	int err, i;

	if (!pf->vsi)
		return;

	mce_for_each_vsi(pf, i)
	{
		if (!pf->vsi[i])
			continue;

		err = mce_vsi_release(pf->vsi[i]);
		if (err) {
			dev_dbg(mce_pf_to_dev(pf),
				"Failed to release pf->vsi[%d], err %d, idx = %d\n",
				i, err, pf->vsi[i]->idx);
		} else {
			pf->vsi[i] = NULL;
		}
	}
}

/**
 * mce_vsi_free_tx_rings - Free Tx resources for VSI queues
 * @vsi: the VSI having resources freed
 */
void mce_vsi_free_tx_rings(struct mce_vsi *vsi)
{
	int i;

	if (!vsi->tx_rings)
		return;

	mce_for_each_txq_new(vsi, i) {
		if (!vsi->tx_rings[i]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, i);
			continue;
		}
		if (vsi->tx_rings[i] && vsi->tx_rings[i]->desc)
		mce_free_tx_ring(vsi->tx_rings[i]);
	}
}

/**
 * mce_vsi_free_rx_rings - Free Rx resources for VSI queues
 * @vsi: the VSI having resources freed
 */
void mce_vsi_free_rx_rings(struct mce_vsi *vsi)
{
	int i;

	if (!vsi->rx_rings)
		return;

	mce_for_each_rxq_new(vsi,i) {
		if (!vsi->rx_rings[i]->q_vector)
			continue;
		if (vsi->rx_rings[i] && vsi->rx_rings[i]->desc)
			mce_free_rx_ring(vsi->rx_rings[i]);
	}
}

/**
 * mce_vsi_ena_irq - Enable IRQ for the given VSI
 * @vsi: the VSI being configured
 */
static void mce_vsi_ena_irq(struct mce_vsi *vsi)
{
	struct mce_q_vector *q_vector = NULL;
	int i = 0;

	mce_for_each_q_vector(vsi, i)
	{
		q_vector = vsi->q_vectors[i];

		mce_enable_vec_txs_irq(q_vector);
		mce_enable_vec_rxs_irq(q_vector);
	}
}

static void mce_tx_dim_work(struct work_struct *work)
{
	struct mce_ring_container *rc;
	struct dim *dim;
	struct mce_hw *hw = NULL;
	struct mce_ring *tx_ring;
	struct dim_cq_moder cur_moder;

	dim = container_of(work, struct dim, work);
	rc = (struct mce_ring_container *)dim->priv;
	hw = &(rc->ring->vsi->back->hw);

	cur_moder = net_dim_get_tx_moderation(dim->mode, dim->profile_ix);

	mce_rc_for_each_ring(tx_ring,(*rc)) {
		tx_ring->q_vector->tx.dim_params.usecs = cur_moder.usec;
		tx_ring->q_vector->tx.dim_params.frames = cur_moder.pkts;
		hw->ops->set_txring_intr_coal(tx_ring);
	}

	dim->state = DIM_START_MEASURE;
}

static void mce_rx_dim_work(struct work_struct *work)
{
	struct mce_ring_container *rc;
	struct dim *dim;
	struct mce_hw *hw = NULL;
	struct mce_ring *rx_ring;
	struct dim_cq_moder cur_moder;

	dim = container_of(work, struct dim, work);
	rc = (struct mce_ring_container *)dim->priv;
	hw = &(rc->ring->vsi->back->hw);

	cur_moder = net_dim_get_rx_moderation(dim->mode, dim->profile_ix);

	mce_rc_for_each_ring(rx_ring,(*rc)) {
		rx_ring->q_vector->rx.dim_params.frames = cur_moder.pkts;
#ifdef MCE_RX_WB_COAL
	// if open rx aggregate, rx delay should never more than aggregat time
	// 1024 / 100M ~ 10.24us
	// soc can remove this 
		if (cur_moder.usec < 11)	
			cur_moder.usec = 11;
#endif
		rx_ring->q_vector->rx.dim_params.usecs = cur_moder.usec;
		hw->ops->set_rxring_intr_coal(rx_ring);
	}

	dim->state = DIM_START_MEASURE;
}

static void mce_init_moderation(struct mce_q_vector *q_vector)
{
	struct mce_ring_container *rc;

	rc = &q_vector->tx;
	rc->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	rc->dim.profile_ix = 0;
	rc->dim.priv = rc;
	INIT_WORK(&rc->dim.work, mce_tx_dim_work);

	rc = &q_vector->rx;
	rc->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_CQE;
	rc->dim.profile_ix = 0;
	rc->dim.priv = rc;
	INIT_WORK(&rc->dim.work, mce_rx_dim_work);
}

/**
 * mce_qvec_napi_enable - Enable NAPI for a single q_vector of a VSI
 * @q_vector: a queue interrupt vector being configured
 */
static void mce_qvec_napi_enable(struct mce_q_vector *q_vector)
{
	mce_init_moderation(q_vector);

	if (q_vector->rx.ring || q_vector->tx.ring)
		napi_enable(&q_vector->napi);
}

/**
 * mce_vsi_napi_enable_all - Enable NAPI for all q_vectors in the VSI
 * @vsi: the VSI being configured
 */
static void mce_vsi_napi_enable_all(struct mce_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	mce_for_each_q_vector(vsi, v_idx)
		mce_qvec_napi_enable(vsi->q_vectors[v_idx]);
}

static int mce_vsi_update_hw(struct mce_vsi *vsi)
{
	struct mce_hw *hw = &(vsi->back->hw);
	struct net_device *netdev = vsi->netdev;
	netdev_features_t features = netdev->features;
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int err = 0;

	hw->ops->enable_axi_tx(hw);
	hw->ops->enable_axi_rx(hw);
	ether_addr_copy(vf->t_info.macaddr, vsi->port_info->addr);
	err = mce_vf_set_veb_misc_rule(hw, PFINFO_IDX,
				       __VEB_POLICY_TYPE_UC_ADD_MACADDR);
	if (err) {
		netdev_err(netdev, "Failed to update mac addr");
		return err;
	}

	hw->ops->set_rx_csumofld(hw, features);

	hw->ops->set_vlan_strip(hw, features);
	hw->ops->set_vlan_filter(hw, features);

	hw->ops->set_rss_key(hw);
	mce_set_rss_table(hw, PFINFO_IDX, vsi->num_rxq);
	hw->ops->set_rss_hash_type(hw);
	hw->ops->set_rss_hash(hw, features);

	hw->ops->set_max_pktlen(hw, netdev->mtu);

	if (!test_bit(MCE_PFC_EN, vsi->back->dcb->flags))
		hw->ops->set_pause(hw, netdev->mtu);
	return err;
}

/**
 * mce_up_complete - Finish the last steps of bringing up a connection
 * @vsi: The VSI being configured
 *
 * Return 0 on success and negative value on error
 */
static int mce_up_complete(struct mce_vsi *vsi)
{
	mce_vsi_start_all_tx_rings(vsi);
	mce_vsi_start_all_rx_rings(vsi);

	mce_vsi_napi_enable_all(vsi);
	mce_vsi_ena_irq(vsi);

	mce_vsi_update_hw(vsi);
	mce_vsi_start_hw_transmit(vsi);

	clear_bit(MCE_VSI_DOWN, vsi->state);

	return 0;
}

/**
 * mce_vsi_open - Called when a network interface is made active
 * @vsi: the VSI to open
 *
 * Initialization of the VSI
 *
 * Returns 0 on success, negative value on error
 */
int mce_vsi_open(struct mce_vsi *vsi)
{
	char int_name[MCE_INT_NAME_STR_LEN];
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_hw *hw = &pf->hw;
	int err;

	/* allocate descriptors */
	err = mce_vsi_setup_tx_rings(vsi);
	if (err)
		goto err_setup_tx;

	err = mce_vsi_setup_rx_rings(vsi);
	if (err)
		goto err_setup_rx;

	err = mce_vsi_cfg(vsi);
	if (err)
		goto err_setup_rx;

	snprintf(int_name, sizeof(int_name) - 1, "%s-%s",
		 dev_driver_string(mce_pf_to_dev(pf)), vsi->netdev->name);
	err = mce_vsi_req_irq_msix(vsi, int_name);
	if (err)
		goto err_setup_rx;

	/* Notify the stack of the actual queue counts. */
	if (test_bit(MCE_DCB_EN, dcb->flags))
		err = netif_set_real_num_tx_queues(vsi->netdev, vsi->num_txq);
	else
		err = netif_set_real_num_tx_queues(vsi->netdev, vsi->num_txq_real);

	if (err)
		goto err_set_qs;

	err = netif_set_real_num_rx_queues(vsi->netdev, vsi->num_rxq);
	if (err)
		goto err_set_qs;

	mce_vsi_dcb_check(vsi);

	err = mce_up_complete(vsi);
	if (err)
		goto err_up_complete;

	mce_vsi_cfg_netdev_tc(vsi, pf->dcb);
#if MCE_SELECT_QUEUE_DEBUG
	pf->d_txqueue.permit = true;
#endif
	netif_tx_start_all_queues(vsi->netdev);
	/* force up */
	if (hw->func_caps.common_cap.num_txq != 8)
		netif_carrier_on(vsi->netdev);

	return 0;

err_up_complete:
	mce_down(vsi);
err_set_qs:
	mce_vsi_free_irq(vsi);
err_setup_rx:
	mce_vsi_free_rx_rings(vsi);
err_setup_tx:
	mce_vsi_free_tx_rings(vsi);

	return err;
}

/**
 * mce_up - Bring the connection back up after being down
 * @vsi: VSI being configured
 */
int mce_up(struct mce_vsi *vsi)
{
	int err;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;

	err = mce_vsi_cfg(vsi);
	if (!err)
		err = mce_up_complete(vsi);

	if (err)
		return err;

	netif_tx_start_all_queues(vsi->netdev);
	if (hw->func_caps.common_cap.num_txq != 8)
		netif_carrier_on(vsi->netdev);

	return err;
}

/**
 * mce_vsi_get_q_vector_q_base - get vector's base numbers of Tx and Rx queues
 * @vsi: related VSI
 * @vector_id: index of the vector in VSI
 * @txq: pointer to a return value of Tx base queue number
 * @rxq: pointer to a return value of Rx base queue number
 */
void mce_vsi_get_q_vector_q_base(struct mce_vsi *vsi, u16 vector_id,
				 u16 *txq, u16 *rxq)
{
	int i;

	*txq = 0;
	*rxq = 0;

	for (i = 0; i < vector_id; i++) {
		struct mce_q_vector *q_vector = vsi->q_vectors[i];

		*txq += q_vector->num_ring_tx;
		*rxq += q_vector->num_ring_rx;
	}
}

/**
 * mce_update_ring_stats - Update ring statistics
 * @ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 *
 * This function assumes that caller has acquired a u64_stats_sync lock.
 */
static void mce_update_ring_stats(struct mce_ring *ring, u64 pkts,
				  u64 bytes)
{
	ring->ring_stats->stats.bytes += bytes;
	ring->ring_stats->stats.pkts += pkts;
}

/**
 * mce_update_tx_ring_stats - Update Tx ring specific counters
 * @tx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void mce_update_tx_ring_stats(struct mce_ring *tx_ring, u64 pkts,
			      u64 bytes)
{
	u64_stats_update_begin(&tx_ring->ring_stats->syncp);
	mce_update_ring_stats(tx_ring, pkts, bytes);
	u64_stats_update_end(&tx_ring->ring_stats->syncp);
}

/**
 * mce_update_rx_ring_stats - Update Rx ring specific counters
 * @rx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void mce_update_rx_ring_stats(struct mce_ring *rx_ring, u64 pkts,
			      u64 bytes)
{
	u64_stats_update_begin(&rx_ring->ring_stats->syncp);
	mce_update_ring_stats(rx_ring, pkts, bytes);
	u64_stats_update_end(&rx_ring->ring_stats->syncp);
}

/**
 * mce_vsi_rebuild - Rebuild VSI after reset
 * @vsi: VSI to be rebuild
 * @init_vsi: is this an initialization or a reconfigure of the VSI
 *
 * Returns 0 on success and negative value on failure
 */
int mce_vsi_rebuild(struct mce_vsi *vsi)
{
	enum mce_vsi_type vtype;
	struct mce_pf *pf;
	int ret;

	if (!vsi)
		return -EINVAL;

	pf = vsi->back;
	vtype = vsi->type;

	mce_vsi_free_q_vectors(vsi);
	mce_vsi_free_q_irq_res(vsi);

	mce_vsi_clear_rings(vsi);
	mce_vsi_free_arrays(vsi);
	mce_vsi_set_num_qs(vsi);
	mce_vsi_set_num_desc(vsi);

	ret = mce_vsi_alloc_arrays(vsi);
	if (ret < 0)
		goto err_vsi_alloc_arrays;

	ret = mce_vsi_alloc_q_vectors(vsi);
	if (ret)
		goto err_vsi_alloc_q_vectors;

	ret = mce_vsi_alloc_q_irq_res(vsi);
	if (ret)
		goto err_vsi_alloc_q_irq_res;

	ret = mce_vsi_alloc_rings(vsi);
	if (ret)
		goto err_vsi_alloc_rings;

	mce_vsi_map_rings_to_vectors(vsi);
	mce_vsi_cfg_qvec_irq(vsi);

	ret = mce_vsi_alloc_ring_stats(vsi);
	if (ret)
		goto err_vsi_alloc_ring_stats;

	return 0;

err_vsi_alloc_ring_stats:
	mce_vsi_clear_rings(vsi);
err_vsi_alloc_rings:
	mce_vsi_free_q_irq_res(vsi);
err_vsi_alloc_q_irq_res:
	mce_vsi_free_q_vectors(vsi);
err_vsi_alloc_q_vectors:
	mce_vsi_free_arrays(vsi);
err_vsi_alloc_arrays:
	set_bit(MCE_RESET_FAILED, pf->state);
	return ret;
}

/**
 * mce_update_pf_stats - Update PF port stats counters
 * @pf: PF whose stats needs to be updated
 */
void mce_update_pf_stats(struct mce_pf *pf)
{
	struct mce_hw *hw = &(pf->hw);

	hw->ops->get_hw_stats(hw, &(pf->prev_stats), &(pf->stats));
}

void mce_setup_L2_filter(struct mce_pf *pf)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	netdev_features_t features = netdev->features;
	struct mce_hw *hw = &(pf->hw);
	bool uc_enable;
	bool mc_enable;

	if (netdev->flags & IFF_PROMISC) {
		features &= (~NETIF_F_HW_VLAN_CTAG_FILTER);
		features &= (~NETIF_F_HW_VLAN_STAG_FILTER);
		uc_enable = false;
	} else {
		uc_enable = true;
	}

	if (netdev->flags & IFF_ALLMULTI)
		mc_enable = false;
	else
		mc_enable = true;

	hw->ops->set_vlan_filter(hw, features);
	hw->ops->set_uc_filter(hw, uc_enable);
	hw->ops->set_mc_filter(hw, mc_enable);
}

int mce_set_bw_limit_init(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;

	set_bit(MCE_VF_BW_INITED, pf->state);
	hw->vf.ops->set_vf_bw_limit_init(pf);
	return 0;
}

int mce_set_max_bw_limit(struct mce_pf *pf, int vf_id, u64 max_tx_rate,
			 u16 ring_cnt)
{
	struct mce_hw *hw = &pf->hw;

	hw->vf.ops->set_vf_bw_limit_rate(pf, vf_id, max_tx_rate, ring_cnt);
	return 0;
}

int mce_set_rss_table(struct mce_hw *hw, u16 vf_id, u16 q_cnt)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		hw->vf.ops->set_vf_rss_table(hw, PFINFO_IDX, q_cnt);
	else
		hw->ops->set_rss_table(hw, q_cnt);
	return 0;
}

struct vf_data_storage *
mce_realloc_and_fill_pfinfo(struct mce_pf *pf, bool to_pfvf, bool copied)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_data_storage *p = NULL, *p1;

	p1 = p = vf->vfinfo;
	if (!to_pfvf) {
		vf->vfinfo = &pf->pfinfo[1];
		if (copied)
			memcpy(&vf->vfinfo[PFINFO_IDX], &p[PFINFO_IDX],
			       sizeof(struct vf_data_storage));
	} else {
		if (!p) {
			dev_err(mce_pf_to_dev(pf),
				"vfinfo is null, cannot fill pfinfo\n");
			return NULL;
		}
		p = &pf->pfinfo[1];
		if (copied)
			memcpy(&vf->vfinfo[PFINFO_IDX], &p[PFINFO_IDX],
			       sizeof(*p));
	}

	return p1;
}

/**
 * int_pow - computes the exponentiation of the given base and exponent
 * @base: base which will be raised to the given power
 * @exp: power to be raised to
 *
 * Computes: pow(base, exp), i.e. @base raised to the @exp power
 */
u64 mce_int_pow(u64 base, unsigned int exp)
{
	u64 result = 1;

	while (exp) {
		if (exp & 1)
			result *= base;
		exp >>= 1;
		base *= base;
	}

	return result;
}

#ifdef THREAD_POLL
int mce_poll_thread_handler(void *data)
{
	int i;
	struct mce_vsi *vsi = data;
	mce_vsi_dis_irq(vsi);
	do {
		for (i = 0; i < vsi->num_q_vectors; i++)
			mce_msix_clean_rings(0, vsi->q_vectors[i]);

		usleep_range(1, 4);
	} while (!kthread_should_stop() && vsi->quit_poll_thread != true);

	return 0;
}
#endif

bool mce_get_misc_irq_evt(struct mce_hw *hw, enum mce_misc_irq_type type)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	bool ret = false;

	if (!(pf->mac_misc_irq & BIT(type)))
		return ret;
	ret = hw->ops->get_misc_irq_evt(hw, type);
	return ret;
}

int mce_setup_misc_irq(struct mce_hw *hw, bool en, int nr_vec)
{
	int ret = 0;

	ret = hw->ops->set_misc_irq(hw, en, nr_vec);
	return ret;
}

int mce_pre_handle_misc_irq(struct mce_hw *hw, enum mce_misc_irq_type type)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		set_bit(MCE_FLAG_MISC_IRQ_PCS_LINK_PENDING, pf->flags);
		// hw->ops->clear_misc_irq_evt(hw, MCE_MAC_MISC_IRQ_PCS_LINK, MCE_MISC_IRQ_CLEAR_ALL);
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		set_bit(MCE_FLAG_MISC_IRQ_PTP_PENDING, pf->flags);
		// hw->ops->clear_misc_irq_evt(hw, MCE_MAC_MISC_IRQ_PTP, MCE_MISC_IRQ_CLEAR_ALL);
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		set_bit(MCE_FLAG_MISC_IRQ_FLR_PENDING, pf->flags);
		break;
	default:
		break;
	}

	return 0;
}

