#include "mce_lib.h"
#include "mce_txrx_lib.h"

#ifdef HAVE_XDP_SUPPORT

#include <linux/bpf_trace.h>
#ifdef HAVE_XDP_BUFF_IN_XDP_H
#include <net/xdp.h>
#else
#include <linux/filter.h>
#endif /* HAVE_XDP_BUFF_IN_XDP_H */
#endif /* HAVE_XDP_SUPPORT */

int mce_create_txring(struct mce_vsi *vsi, int index)
{
	struct mce_ring *ring;

	/* allocate with kzalloc(), free with kfree_rcu() */
	ring = kzalloc(sizeof(*ring), GFP_KERNEL);
	if (ring == NULL)
		return -ENOMEM;

	ring->q_index = index;
	ring->vsi = vsi;
	ring->dev = &(vsi->back->pdev->dev);
	ring->count = vsi->num_tx_desc;
	WRITE_ONCE(vsi->tx_rings[index], ring);

	return 0;
}

void mce_destroy_txring(struct mce_vsi *vsi, int index)
{
	if (vsi->tx_rings[index]) {
		kfree_rcu(vsi->tx_rings[index], rcu);
		WRITE_ONCE(vsi->tx_rings[index], NULL);
	}
}

static void mce_set_tx_ctx(struct mce_ring *tx_ring)
{
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (tx_ring == NULL)
		return;

	hw->ops->set_txring_ctx(tx_ring, hw);
}
static void mce_cfg_xps_tx_ring(struct mce_ring *ring)
{
#ifdef THREAD_POLL
	int i = 0;
	struct mce_vsi *vsi = ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	struct cpumask *mask;

	mask = kmalloc(sizeof(struct cpumask), GFP_KERNEL);
	if (!mask) {
		return;
	}
	cpumask_clear(mask);
	cpumask_set_cpu(2, mask); // 将 CPU 2 设置到 mask 中
	for (i = 0; i < hw->func_caps.common_cap.num_txq; i++) {
		netif_set_xps_queue(ring->netdev, mask, i);
	}
	kfree(mask);
#else
#ifndef HAVE_XPS_QOS_SUPPORT
	struct mce_vsi *vsi = ring->vsi;

#endif /* !HAVE_XPS_QOS_SUPPORT */
	if (!ring->q_vector || !ring->netdev)
		return;

#ifndef HAVE_XPS_QOS_SUPPORT
	/* Single TC mode enable XPS
	 * If there is more than 1 TC, netdev_set_num_tc() resets XPS settings
	 */
	if (vsi->back->dcb->cur_tccfg.tc_cnt > 1)
		return;
#endif /* !HAVE_XPS_QOS_SUPPORT */

	/* We only initialize XPS once, so as not to overwrite user settings */
	if (test_and_set_bit(MCE_TX_XPS_INIT_DONE, ring->xps_state))
		return;

	netif_set_xps_queue(ring->netdev, &ring->q_vector->affinity_mask,
			    ring->q_index);
#endif
}

/**
 * mce_vsi_cfg_txq - Configure single Tx queue
 * @vsi: the VSI that queue belongs to
 * @tx_ring: Tx ring to be configured
 */
static int mce_vsi_cfg_txq(struct mce_ring *tx_ring)
{
	if (tx_ring == NULL)
		return -EFAULT;
	mce_cfg_xps_tx_ring(tx_ring);
	mce_set_tx_ctx(tx_ring);

	return 0;
}

/**
 * mce_vsi_cfg_txqs - Configure the VSI for Tx
 * @vsi: the VSI being configured
 * @tx_rings: Tx ring array to be configured
 * @count: number of Tx ring array elements
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx VSI for operation.
 */
static int mce_vsi_cfg_txqs(struct mce_vsi *vsi,
			    struct mce_ring **tx_rings, u16 count)
{
	u16 q_idx = 0;
	int err = 0;

	for (q_idx = 0; q_idx < count; q_idx++) {
		if (!tx_rings[q_idx]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, q_idx);
			continue;
		}
		err = mce_vsi_cfg_txq(tx_rings[q_idx]);
		if (err)
			goto err_cfg_txqs;
	}

err_cfg_txqs:
	return err;
}

/**
 * mce_vsi_cfg_lan_txqs - Configure the VSI for Tx
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx VSI for operation.
 */
static int mce_vsi_cfg_lan_txqs(struct mce_vsi *vsi)
{
	return mce_vsi_cfg_txqs(vsi, vsi->tx_rings, vsi->alloc_txq);
}

/**
 * mce_setup_tx_ring - Allocate the Tx descriptors
 * @tx_ring: the Tx ring to set up
 *
 * Return 0 on success, negative on error
 */
int mce_setup_tx_ring(struct mce_ring *tx_ring)
{
	struct device *dev = tx_ring->dev;

	if (!dev)
		return -ENOMEM;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(tx_ring->tx_buf);
	tx_ring->tx_buf = devm_kcalloc(dev, sizeof(*tx_ring->tx_buf),
				       tx_ring->count, GFP_KERNEL);
	if (!tx_ring->tx_buf)
		return -ENOMEM;

#ifdef MCE_TX_WB_COAL
	tx_ring->size = (tx_ring->count + 1) * sizeof(struct mce_desc);
#else
	/* round up to nearest page */
	tx_ring->size =
		ALIGN(tx_ring->count * sizeof(struct mce_desc), PAGE_SIZE);
#endif
	tx_ring->desc = dmam_alloc_coherent(dev, tx_ring->size,
					    &tx_ring->dma, GFP_KERNEL);
	if (!tx_ring->desc) {
		dev_err(dev,
			"Unable to allocate memory for the "
			"Tx descriptor ring, size=%d\n",
			tx_ring->size);
		goto err;
	}

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
	tx_ring->ring_stats->tx_stats.prev_pkt = -1;
	tx_ring->flags = 0;
	return 0;

err:
	devm_kfree(dev, tx_ring->tx_buf);
	tx_ring->tx_buf = NULL;
	return -ENOMEM;
}

/**
 * mce_vsi_setup_tx_rings - Allocate VSI Tx queue resources
 * @vsi: VSI having resources allocated
 *
 * Return 0 on success, negative on failure
 */
int mce_vsi_setup_tx_rings(struct mce_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->num_txq) {
		dev_err(mce_pf_to_dev(vsi->back),
			"VSI %d has 0 Tx queues\n", vsi->idx);
		return -EINVAL;
	}

	mce_for_each_txq_new(vsi, i) {
		struct mce_ring *tx_ring = vsi->tx_rings[i];

		if (!tx_ring->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, i);
			continue;
		}

		if (!tx_ring)
			return -EINVAL;

		if (vsi->netdev)
			tx_ring->netdev = vsi->netdev;

		err = mce_setup_tx_ring(tx_ring);
		if (err)
			break;
	}

	return err;
}

static inline void enable_txring_irq(struct mce_ring *tx_ring)
{
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (tx_ring == NULL)
		return;

	hw->ops->enable_txring_irq(tx_ring);
}

static inline void disable_txring_irq(struct mce_ring *tx_ring)
{
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (tx_ring == NULL)
		return;

	hw->ops->disable_txring_irq(tx_ring);
}

static inline void mce_start_tx_ring(struct mce_ring *tx_ring)
{
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (tx_ring == NULL)
		return;

	hw->ops->start_txring(tx_ring);
}

void mce_stop_tx_ring(struct mce_ring *tx_ring)
{
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (tx_ring == NULL)
		return;

	hw->ops->stop_txring(tx_ring);
}

void mce_update_tx_dim(struct mce_ring *tx_ring)
{
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	struct mce_pf *pf = vsi->back;
	bool on = !!test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);

	if (tx_ring == NULL)
		return;

	hw->ops->set_txring_hw_dim(tx_ring, on);
}

void mce_update_rx_dim(struct mce_ring *rx_ring)
{
	struct mce_vsi *vsi = rx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	struct mce_pf *pf = vsi->back;
	bool on = !!test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);

	if (rx_ring == NULL)
		return;

	hw->ops->set_rxring_hw_dim(rx_ring, on);
}

static inline void enable_txrxring_irq(struct mce_ring *tx_ring)
{
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (tx_ring == NULL)
		return;

	hw->ops->enable_txrxring_irq(tx_ring);
}

static inline void disable_txrxring_irq(struct mce_ring *tx_ring)
{
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (tx_ring == NULL)
		return;

	hw->ops->disable_txrxring_irq(tx_ring);
}

/**
 * mce_unmap_and_free_tx_buf - Release a Tx buffer
 * @ring: the ring that owns the buffer
 * @tx_buf: the buffer to free
 */
static void mce_unmap_and_free_tx_buf(struct mce_ring *ring,
				      struct mce_tx_buf *tx_buf)
{
	if (tx_buf->skb) {
		dev_kfree_skb_any(tx_buf->skb);

		if (dma_unmap_len(tx_buf, len))
			dma_unmap_single(ring->dev,
					 dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buf, len)) {
		dma_unmap_page(ring->dev, dma_unmap_addr(tx_buf, dma),
			       dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	}
#ifndef MCE_TX_WB_COAL
	tx_buf->next_to_watch = NULL;
#endif
	tx_buf->skb = NULL;
	dma_unmap_len_set(tx_buf, len, 0);
	/* tx_buf must be completely set up in the transmit path */
}

static struct netdev_queue *txring_txq(const struct mce_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->q_index);
}

/**
 * mce_clean_tx_ring - Free any empty Tx buffers
 * @tx_ring: ring to be cleaned
 */
void mce_clean_tx_ring(struct mce_ring *tx_ring)
{
	u16 i = tx_ring->next_to_clean;
	struct mce_tx_buf *tx_buf = &tx_ring->tx_buf[i];

	/* ring already cleared, nothing to do */
	if (!tx_ring->tx_buf)
		return;
	while (i != tx_ring->next_to_use) {
		struct mce_tx_desc *eop_desc, *tx_desc;

		dev_kfree_skb_any(tx_buf->skb);
		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev, dma_unmap_addr(tx_buf, dma),
				dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);

		eop_desc = tx_buf->next_to_watch;
		tx_desc = MCE_TX_DESC(tx_ring, i);
		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buf++;
			tx_desc++;
			i++;
			if (unlikely(i == tx_ring->count)) {
				i = 0;
				tx_buf = tx_ring->tx_buf;
				tx_desc = MCE_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buf, len))
				dma_unmap_page(tx_ring->dev,
						dma_unmap_addr(tx_buf, dma),
						dma_unmap_len(tx_buf, len),
						DMA_TO_DEVICE);
		}
		/* move us one more past the eop_desc for start of next pkt */
		tx_buf++;
		i++;
		if (unlikely(i == tx_ring->count)) {
			i = 0;
			tx_buf = tx_ring->tx_buf;
		}
	}

	/* Free all the Tx ring sk_buffs */
	for (i = 0; i < tx_ring->count; i++)
		mce_unmap_and_free_tx_buf(tx_ring, &tx_ring->tx_buf[i]);

	memset(tx_ring->tx_buf, 0,
	       sizeof(*tx_ring->tx_buf) * tx_ring->count);

	/* Zero out the descriptor ring */
	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	if (!tx_ring->netdev)
		return;

	/* cleanup Tx queue statistics */
	netdev_tx_reset_queue(txring_txq(tx_ring));
}

/**
 * mce_free_tx_ring - Free Tx resources per queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 */
void mce_free_tx_ring(struct mce_ring *tx_ring)
{
	mce_clean_tx_ring(tx_ring);
	devm_kfree(tx_ring->dev, tx_ring->tx_buf);
	tx_ring->tx_buf = NULL;

	if (tx_ring->desc) {
		dmam_free_coherent(tx_ring->dev, tx_ring->size,
				   tx_ring->desc, tx_ring->dma);
		tx_ring->desc = NULL;
	}
}

void mce_disable_vec_txs_irq(struct mce_q_vector *vector)
{
	struct mce_ring *ring;
#ifdef MCE_13P_DEBUG_MSIX
	return;
#endif
	mce_rc_for_each_ring(ring, vector->tx) {
		disable_txring_irq(ring);
	}
}

void mce_enable_vec_txs_irq(struct mce_q_vector *vector)
{
	struct mce_ring *ring;

	mce_rc_for_each_ring(ring, vector->tx) {
		enable_txring_irq(ring);
	}
}

void mce_disable_vec_txrxs_irq(struct mce_q_vector *vector)
{
	struct mce_ring *ring;

	mce_rc_for_each_ring(ring, vector->tx) {
		disable_txrxring_irq(ring);
	}
}

void mce_enable_vec_txrxs_irq(struct mce_q_vector *vector)
{
	struct mce_ring *ring;

	mce_rc_for_each_ring(ring, vector->tx) {
		enable_txrxring_irq(ring);
	}
}

/**
 * mce_xmit_desc_count - calculate number of Tx descriptors needed
 * @skb: send buffer
 *
 * Returns number of data descriptors needed for this skb.
 */
static u32 mce_xmit_desc_count(struct sk_buff *skb)
{
	u32 nr_frags = skb_shinfo(skb)->nr_frags;

	return (nr_frags + 1);
}

/**
 * __mce_maybe_stop_tx - 2nd level check for Tx stop conditions
 * @tx_ring: the ring to be checked
 * @size: the size buffer we want to assure is available
 *
 * Returns -EBUSY if a stop is needed, else 0
 */
static int __mce_maybe_stop_tx(struct mce_ring *tx_ring, unsigned int size)
{
	netif_tx_stop_queue(txring_txq(tx_ring));
	/* Memory barrier before checking head and tail */
	smp_mb();

	/* Check again in a case another CPU has just made room available. */
	if (likely(MCE_DESC_UNUSED(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_tx_start_queue(txring_txq(tx_ring));
	++(tx_ring->ring_stats->tx_stats.restart_q);
	return 0;
}

/**
 * mce_maybe_stop_tx - 1st level check for Tx stop conditions
 * @tx_ring: the ring to be checked
 * @size:    the size buffer we want to assure is available
 *
 * Returns 0 if stop is not needed
 */
static int mce_maybe_stop_tx(struct mce_ring *tx_ring, u32 size)
{
	if (likely(MCE_DESC_UNUSED(tx_ring) >= size))
		return 0;

	return __mce_maybe_stop_tx(tx_ring, size);
}

/* only support 3 vlan */
static int __get_vlan_headers_nums(struct mce_pf *pf, struct sk_buff *skb,
				   struct mce_tx_desc *tmp_desc,
				   bool vtag_present, __be16 protocol)
{
	struct vlan_hdr *vhdr, _vhdr;
	struct vlan_ethhdr *vethhdr, _vethhdr;

	__be16 v_protocol;
	u16 vlan0 = 0, vlan1 = 0;
	int num = 0, i;

	if (vtag_present) {
		if (pf->vlan_strip_cnt <= 1)
			goto out_drop;
		num = 0;
		i = 0;
		vethhdr = skb_header_pointer(skb, VLAN_HLEN * i,
					     sizeof(_vethhdr), &_vethhdr);
		if (!vethhdr)
			goto out_drop;
		v_protocol = vethhdr->h_vlan_proto;
		if (__VLAN_ALLOWED(v_protocol)) {
			num++;
			i++;
			vlan1 = ntohs(vethhdr->h_vlan_TCI);
			tmp_desc->vlan1 = vlan1;
			if (v_protocol == __constant_htons(ETH_P_8021Q))
				SET_MAC_VLAN_CTRL_INNER_TYPE(
					tmp_desc->mac_vlan_ctl, 0);
			else
				SET_MAC_VLAN_CTRL_INNER_TYPE(
					tmp_desc->mac_vlan_ctl, 1);
		} else
			goto out_drop;
	} else {
		num = 0;
		i = 0;
		vhdr = skb_header_pointer(skb, ETH_HLEN + VLAN_HLEN * i,
					  sizeof(_vhdr), &_vhdr);
		if (!vhdr)
			goto out_drop;
		num++;
		i++;
		vlan0 = ntohs(vhdr->h_vlan_TCI);
		tmp_desc->vlan0 = vlan0;
		if (protocol == __constant_htons(ETH_P_8021Q))
			SET_CMD_VLAN_OUTER_TYPE(tmp_desc->cmd, 0);
		else
			SET_CMD_VLAN_OUTER_TYPE(tmp_desc->cmd, 1);
		if (pf->vlan_strip_cnt <= 1)
			goto out_drop;
		/* next protocol */
		v_protocol = vhdr->h_vlan_encapsulated_proto;
		if (__VLAN_ALLOWED(v_protocol)) {
			vhdr = skb_header_pointer(skb,
						  ETH_HLEN + VLAN_HLEN * i,
						  sizeof(_vhdr), &_vhdr);
			if (!vhdr)
				goto out_drop;
		} else
			goto out_drop;
		num++;
		i++;
		vlan1 = ntohs(vhdr->h_vlan_TCI);
		tmp_desc->vlan1 = vlan1;
		if (v_protocol == __constant_htons(ETH_P_8021Q))
			SET_MAC_VLAN_CTRL_INNER_TYPE(
				tmp_desc->mac_vlan_ctl, 0);
		else
			SET_MAC_VLAN_CTRL_INNER_TYPE(
				tmp_desc->mac_vlan_ctl, 1);
	}

out_drop:
	SET_MAC_VLAN_CTRL_CNT(tmp_desc->mac_vlan_ctl, num);

#if 0
	pr_info("DEBUG: mce tx vtag_present=%d, num=%d vlan0=%d, vlan1=%d\n",
		vtag_present, num, vlan0, vlan1);
#endif
	return num;
}

static void mce_tx_prepare_vlan(struct mce_ring *tx_ring,
				struct mce_tx_buf *first,
				struct mce_tx_desc *tmp_desc,
				struct mce_pf *pf)
{
	struct sk_buff *skb = first->skb;
	__be16 protocol = skb->protocol;

	if (MCE_INSERT_VLAN_CNT(pf)) {
		/* outer vlan */
		tmp_desc->vlan0 = pf->dvlan_ctrl.outer_hdr.vid;
		SET_CMD_VLAN_OUTER_TYPE(tmp_desc->cmd,
					pf->dvlan_ctrl.outer_hdr.type);
		/* inner vlan */
		tmp_desc->vlan1 = pf->dvlan_ctrl.inner_hdr.vid;
		SET_MAC_VLAN_CTRL_INNER_TYPE(
			tmp_desc->mac_vlan_ctl,
			pf->dvlan_ctrl.inner_hdr.type);

		first->vlan_size += 8;
		SET_MAC_VLAN_CTRL_CNT(tmp_desc->mac_vlan_ctl, 0);
		SET_CMD_VLAN_VALID(tmp_desc->cmd);
		SET_CMD_VLAN_OFLD(tmp_desc->cmd, MCE_INSERT_VLAN_CNT(pf));

		u64_stats_update_begin(&tx_ring->ring_stats->syncp);
		(tx_ring->ring_stats->tx_stats.inserted_vlan)++;
		u64_stats_update_end(&tx_ring->ring_stats->syncp);
		return;
	}

	if (skb_vlan_tag_present(skb)) {
		tmp_desc->vlan0 = skb_vlan_tag_get(skb);
		protocol = skb->vlan_proto;
		// protocol = vlan_get_protocol(skb);
		switch (protocol) {
		case htons(ETH_P_8021Q):
			SET_CMD_VLAN_OUTER_TYPE(tmp_desc->cmd, 0);
			break;
		case htons(ETH_P_8021AD):
			SET_CMD_VLAN_OUTER_TYPE(tmp_desc->cmd, 1);
			break;
		default:
			return;
		}
		/* vlan insert by hw */
		first->vlan_size += 4;
		SET_MAC_VLAN_CTRL_CNT(tmp_desc->mac_vlan_ctl, 0);
		SET_CMD_VLAN_VALID(tmp_desc->cmd);
		SET_CMD_VLAN_OFLD(tmp_desc->cmd, 1);
		/* when pf had setup one vlan for this vf, then no other vlan
		 * are allowed to be configured
		 */
		__get_vlan_headers_nums(pf, skb, tmp_desc, true, protocol);
		u64_stats_update_begin(&tx_ring->ring_stats->syncp);
		(tx_ring->ring_stats->tx_stats.inserted_vlan)++;
		u64_stats_update_end(&tx_ring->ring_stats->syncp);
	} else {
		if (__VLAN_ALLOWED(protocol)) {
			__get_vlan_headers_nums(pf, skb, tmp_desc, false,
						protocol);
			SET_CMD_VLAN_VALID(tmp_desc->cmd);
			SET_CMD_VLAN_OFLD(tmp_desc->cmd, 0);
		}
	}
}

static u16 cal_pseudo_2(u16 *data, int len)
{
	int i;
	u32 sum = 0;

	for (i = 0; i < len / 2; i++)
                 sum += *(data + i);

         if ((len % 2) != 0)
		 sum += ((u16)(data[len / 2] & 0xFF) << 8);

         while (sum >> 16)
                 sum = (sum & 0xFFFF) + (sum >> 16);

	return (u16)sum;
}

/**
 * mce_tso - computes mss and TSO length to prepare for TSO
 * @first: pointer to struct mce_tx_buf
 * @tmp_desc: current descriptor information
 *
 * Returns 0 or error (negative) if TSO can't happen, 1 otherwise.
 */
static int mce_tso(struct mce_tx_buf *first, struct mce_tx_desc *tmp_desc,
		   struct mce_pf *pf)
{
	struct sk_buff *skb = first->skb;
	u32 paylen = 0;
	u8 l4_start = 0;
	u8 header_len = 0;
	struct per_head header;
	struct per_head_v6 header_v6;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	if (skb_cow_head(skb, 0) < 0)
		return -1;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	if (ip.v4->version == 4) {
		ip.v4->tot_len = 0;
		ip.v4->check = 0;
		header.sip = ip.v4->saddr;
		header.dip = ip.v4->daddr;
	} else {
		ip.v6->payload_len = 0;
		header_v6.sip = ip.v6->saddr;
		header_v6.dip = ip.v6->daddr;
	}

	if (skb_shinfo(skb)->gso_type &
	    (SKB_GSO_GRE |
#ifdef NETIF_F_GSO_PARTIAL
	     SKB_GSO_GRE_CSUM |
#endif
#ifdef NETIF_F_GSO_IPXIP4
	     SKB_GSO_IPXIP4 | SKB_GSO_IPXIP6 |
#else
#ifdef NETIF_F_GSO_IPIP
	     SKB_GSO_IPIP | SKB_GSO_SIT |
#endif
#endif /* NETIF_F_GSO_IPXIP4 */
	     SKB_GSO_UDP_TUNNEL | SKB_GSO_UDP_TUNNEL_CSUM)) {

#ifndef NETIF_F_GSO_PARTIAL
		if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM) {
#else
		if (!(skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL) &&
		    (skb_shinfo(skb)->gso_type &
		     SKB_GSO_UDP_TUNNEL_CSUM)) {
#endif
			l4.udp->len = 0;
			/* determine offset of outer transport header */
			l4_start = (u8)(l4.hdr - skb->data);
			/* remove payload length from outer checksum */
			paylen = skb->len - l4_start;
			csum_replace_by_diff(
				&l4.udp->check,
				(__force __wsum)htonl(paylen));

			SET_CMD_L4_CHK_OFLD(tmp_desc->cmd);
		} else if (skb_shinfo(skb)->gso_type & 
			   (SKB_GSO_UDP_TUNNEL | SKB_GSO_UDP_TUNNEL_CSUM)) {

			l4.udp->len = 0;
			if (ip.v4->version == 4) {
				header.proto = 0x1100;
				header.resv = 0;
				l4.udp->check = cal_pseudo_2((u16 *)&header, sizeof(struct per_head));
			} else {
				header_v6.proto = 0x1100;
				header_v6.resv = 0;
				l4.udp->check = cal_pseudo_2((u16 *)&header_v6, sizeof(struct per_head_v6));
			}
			SET_CMD_L4_CHK_OFLD(tmp_desc->cmd);
		}

		/* reset pointers to inner headers */
		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);

		/* initialize inner IP header fields */
		if (ip.v4->version == 4) {
			ip.v4->tot_len = 0;
			ip.v4->check = 0;
		} else {
			ip.v6->payload_len = 0;
		}
	}

	/* determine offset of transport header */
	l4_start = (u8)(l4.hdr - skb->data);

	/* remove payload length from checksum */
	paylen = skb->len - l4_start;

#ifdef NETIF_F_GSO_UDP_L4
	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
		csum_replace_by_diff(&l4.udp->check,
				     (__force __wsum)htonl(paylen));
		/* compute length of UDP segmentation header */
		header_len = (u8)sizeof(l4.udp) + l4_start;

	} else {
		csum_replace_by_diff(&l4.tcp->check,
				     (__force __wsum)htonl(paylen));
		/* compute length of TCP segmentation header */
		header_len = (u8)((l4.tcp->doff * 4) + l4_start);
	}
#else
	csum_replace_by_diff(&l4.tcp->check,
			     (__force __wsum)htonl(paylen));
	header_len = (u8)((l4.tcp->doff * 4) + l4_start);
#endif

	tmp_desc->mss = skb_shinfo(skb)->gso_size;
	/* update tso seg to hw */
	if (pf->priv_h.en) {
		header_len -= pf->priv_h.en;
		SET_MAC_VLAN_CTRL_PRIV_HDR(tmp_desc->mac_vlan_ctl, 1);
		SET_TSO_SEG_NUM(tmp_desc->priv_inner_type, pf->priv_h.len);
	} else {
		SET_TSO_SEG_NUM(tmp_desc->priv_inner_type,
				skb_shinfo(skb)->gso_segs);
	}

	/* update gso_segs and bytecount */
	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * header_len;
	first->bytecount_fifo += (first->gso_segs - 1) * header_len;
	first->head_size = header_len;
	pf->is_checksumed = true;

	SET_CMD_TSO(tmp_desc->cmd);

	return 0;
}

/**
 * mce_tx_csum - Enable Tx checksum offloads
 * @skb: send buffer
 * @tmp_desc: current descriptor information
 */
static int mce_tx_csum(struct sk_buff *skb, struct mce_tx_desc *tmp_desc,
		       struct mce_pf *pf)
{
	u8 l4_proto = 0;
	u8 *exthdr = NULL;
	u32 tunnel = OUTTER_TYPE;
	int ret = 0;
	__be16 frag_off;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	if (pf->priv_h.en)
		SET_L2_HDR_LEN(tmp_desc->outer_hdr_len,
			       (ip.hdr - skb->data) - pf->priv_h.len);
	else
		SET_L2_HDR_LEN(tmp_desc->outer_hdr_len,
			       (ip.hdr - skb->data)); // outer l2 hdr len
	SET_L3_HDR_LEN(tmp_desc->outer_hdr_len,
		       (l4.hdr - ip.hdr)); // outer l3 hdr len

	if (ip.v4->version == 4) {
		SET_CMD_L3_TYPE(tmp_desc->cmd, L3TYPE_IPv4);
		l4_proto = ip.v4->protocol;
	} else {
		SET_CMD_L3_TYPE(tmp_desc->cmd, L3TYPE_IPv6);
		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		ret = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto,
				       &frag_off);
		if (ret < 0)
			return ret;
	}

	if (skb->encapsulation) {
		u8 *inner_mac = skb_inner_mac_header(skb);

		SET_TUNNEL_HDR_LEN(tmp_desc->l4_hdr_len,
				   ((inner_mac - skb->data) >> 1));

		/* define outer transport */
		switch (l4_proto) {
		case IPPROTO_UDP:
			SET_CMD_L4_TYPE(tmp_desc->cmd,
					L4TYPE_UDP); // outer l4 type

			switch (l4.udp->dest) {
#if defined(HAVE_VXLAN_RX_OFFLOAD) || defined(HAVE_VXLAN_TYPE)
#if IS_ENABLED(CONFIG_VXLAN)
#ifndef IANA_VXLAN_UDP_PORT
#define IANA_VXLAN_UDP_PORT 4789
#endif
#ifndef IANA_VXLAN_GPE_UDP_PORT
#define IANA_VXLAN_GPE_UDP_PORT 4790
#endif
#define VXLAN_GPE_UDP_PORT (8472)

			case htons(IANA_VXLAN_UDP_PORT):
			case htons(IANA_VXLAN_GPE_UDP_PORT):
			case htons(VXLAN_GPE_UDP_PORT):
				tunnel = INNER_VXLAN;
				break;
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD || HAVE_VXLAN_TYPE */
#ifdef HAVE_GTP_SUPPORT
#ifndef GTP1U_PORT
#define GTP1U_PORT 2152
#endif
			case htons(GTP1U_PORT):
				tunnel = INNER_GTP_U;
				break;
#endif /* HAVE_GTP_SUPPORT */
#if defined(HAVE_GENEVE_RX_OFFLOAD) || defined(HAVE_GENEVE_TYPE)
#if IS_ENABLED(CONFIG_GENEVE)
			case htons(GENEVE_UDP_PORT):
				tunnel = INNER_GENEVE;
				break;
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD || HAVE_GENEVE_TYPE */
			default:
				/* others try to use software */
				skb_checksum_help(skb);
				return 0;
			}
			SET_CMD_TUNNEL_TYPE(tmp_desc->cmd, tunnel);
			break;
		case IPPROTO_GRE:
			tunnel = INNER_GRE;
			SET_CMD_TUNNEL_TYPE(tmp_desc->cmd, INNER_GRE);
			break;
		default:
			if (CMD_TSO_STATUS(tmp_desc->cmd) == 1)
				return -1;

			goto unknow_type;
		}

		/* reset pointers to inner headers */
		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);

		/* initialize inner IP header fields */
		if (ip.v4->version == 4) {
			l4_proto = ip.v4->protocol;
			SET_INNER_L3_TYPE(tmp_desc->priv_inner_type,
					  L3TYPE_IPv4);
		} else {
			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			if (l4.hdr != exthdr)
				ipv6_skip_exthdr(skb, exthdr - skb->data,
						 &l4_proto, &frag_off);
			SET_INNER_L3_TYPE(tmp_desc->priv_inner_type,
					  L3TYPE_IPv6);
		}

		if (CMD_TSO_STATUS(tmp_desc->cmd) == 1) {
			SET_CMD_INNER_L3_CHK_OFLD(
				tmp_desc->cmd); //内3层校验和卸载
		}

		SET_L2_HDR_LEN(tmp_desc->inner_hdr_len,
			       (ip.hdr - inner_mac)); //inner l2 hdr len
		SET_L3_HDR_LEN(tmp_desc->inner_hdr_len,
			       (l4.hdr - ip.hdr)); //inner l3 hdr len
	}

	if (CMD_TSO_STATUS(tmp_desc->cmd) == 1)
		SET_CMD_L3_CHK_OFLD(tmp_desc->cmd); //外3层校验和卸载

	/* Enable L4 checksum offloads */
	switch (l4_proto) {
	case IPPROTO_TCP:
		if (tunnel == OUTTER_TYPE)
			SET_CMD_L4_TYPE(tmp_desc->cmd, L4TYPE_TCP);
		else
			SET_INNER_L4_TYPE(tmp_desc->priv_inner_type,
					  L4TYPE_TCP);

		SET_L4_HDR_LEN(tmp_desc->l4_hdr_len, (l4.tcp->doff * 4));
		break;
	case IPPROTO_UDP:
		if (tunnel == OUTTER_TYPE)
			SET_CMD_L4_TYPE(tmp_desc->cmd, L4TYPE_UDP);
		else
			SET_INNER_L4_TYPE(tmp_desc->priv_inner_type,
					  L4TYPE_UDP);

		SET_L4_HDR_LEN(tmp_desc->l4_hdr_len, 8);
		break;
	case IPPROTO_SCTP:
		if (tunnel == OUTTER_TYPE)
			SET_CMD_L4_TYPE(tmp_desc->cmd, L4TYPE_SCTP);
		else
			SET_INNER_L4_TYPE(tmp_desc->priv_inner_type,
					  L4TYPE_SCTP);

		SET_L4_HDR_LEN(tmp_desc->l4_hdr_len, 12);
		break;
	default:
		goto unknow_type;
	}

	if (tunnel != OUTTER_TYPE)
		SET_CMD_INNER_L4_CHK_OFLD(tmp_desc->cmd); //内4层校验和卸载
	else
		SET_CMD_L4_CHK_OFLD(tmp_desc->cmd); //外4层校验和卸载
	pf->is_checksumed = true;
	return 0;

unknow_type:
	SET_L2_HDR_LEN(tmp_desc->inner_hdr_len, 0);
	SET_L3_HDR_LEN(tmp_desc->inner_hdr_len, 0);
	SET_L4_HDR_LEN(tmp_desc->l4_hdr_len, 0);
	SET_CMD_L3_TYPE(tmp_desc->cmd, L3TYPE_RES);
	SET_CMD_L4_TYPE(tmp_desc->cmd, L4TYPE_RES);
	SET_TUNNEL_HDR_LEN(tmp_desc->l4_hdr_len, 0);
	SET_INNER_L3_TYPE(tmp_desc->priv_inner_type, L3TYPE_RES);
	SET_INNER_L4_TYPE(tmp_desc->priv_inner_type, L4TYPE_RES);
	skb_checksum_help(skb);
	return 0;
}

static u16 cal_fifo_depth(struct mce_tx_buf *first)
{
	u16 depth = 0;
	int packet_len;
#define ALIGN_SIZE (64)

	if (first->gso_size) {
		packet_len = first->head_size + first->gso_size +
			     first->vlan_size;
		depth = ((packet_len + ALIGN_SIZE - 1) / ALIGN_SIZE) *
			(first->gso_segs - 1);
		/* the last packet */
		packet_len = first->bytecount_fifo %
			     (packet_len - first->vlan_size);
		if (!packet_len)
			packet_len = first->head_size + first->gso_size +
				     first->vlan_size;
		else
			packet_len += first->vlan_size;
	} else {
		/* up to align */
		packet_len = first->bytecount_fifo + first->vlan_size;
	}

	/* it must tso we only need the last packet */
	depth += (packet_len + ALIGN_SIZE - 1) / ALIGN_SIZE;
#if 0
	printk("gso_size is %d, total_bytes %d head_size %d vlan_size %d gso_segs %d depth %d\n",
		first->gso_size, first->bytecount_fifo, first->head_size, first->vlan_size, first->gso_segs,
		depth);
#endif
	return depth;
}

/*
static void pirnt_desc(u8 *buf, int size)
{
	int i;

	for (i = 0; i < size; i = i + 16) {
		printk("%02x: "
		       "%02x %02x %02x %02x "
		       "%02x %02x %02x %02x "
		       "%02x %02x %02x %02x "
		       "%02x %02x %02x %02x\n",
		       i, *(buf + i), *(buf + i + 1), *(buf + i + 2),
		       *(buf + i + 3), *(buf + i + 4), *(buf + i + 5),
		       *(buf + i + 6), *(buf + i + 7), *(buf + i + 8),
		       *(buf + i + 9), *(buf + i + 10), *(buf + i + 11),
		       *(buf + i + 12), *(buf + i + 13), *(buf + i + 14),
		       *(buf + i + 15));
	}
}*/

/**
 * mce_tx_map - Build the Tx descriptor
 * @first: first buffer info buffer to use
 * @tx_ring: ring to send buffer on
 * @tmp_desc: current descriptor information
 *
 * This function loops over the skb data pointed to by *first
 * and gets a physical address for each memory location and programs
 * it and the length into the transmit descriptor.
 */
static void mce_tx_map(struct mce_tx_buf *first, struct mce_ring *tx_ring,
		       struct mce_tx_desc *tmp_desc)
{
	struct sk_buff *skb = first->skb;
	struct mce_tx_buf *tx_buf = NULL;
	struct mce_tx_desc *tx_desc = NULL;
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_pf *pf = vsi->back;
	skb_frag_t *frag = NULL;
	dma_addr_t dma = 0;
	u32 data_len = 0;
	u32 size = 0;
	u16 i = tx_ring->next_to_use;
	bool kick;
	/* calculate tx whole_depth for hw */

	data_len = skb->data_len;
	size = skb_headlen(skb);
	tx_desc = MCE_TX_DESC(tx_ring, i);
	tx_buf = first;
	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);
	first->fifo_depth = cal_fifo_depth(first);
	if (test_bit(MCE_PFC_EN, pf->dcb->flags)) {
		tx_ring->ring_stats->tx_stats.tx_pfc_count +=
			first->fifo_depth;
	}
	if (first->gso_size)
		tx_ring->ring_stats->tx_stats.tx_tso_count++;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		if (dma_mapping_error(tx_ring->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);
		tx_desc->addr = cpu_to_le64(dma);
		/* set eth fifo len to hw */

		while (unlikely(size > MCE_MAX_DATA_PER_TXD)) {
			tx_desc->data_len =
				cpu_to_le16(MCE_MAX_DATA_PER_TXD & 0xffff);
			mce_buid_ctob(tx_desc, tmp_desc);
			tx_desc->vlan2 = first->fifo_depth;
			tx_desc++;
			i++;
			if (i == tx_ring->count) {
				tx_desc = MCE_TX_DESC(tx_ring, 0);
				i = 0;
			}

			dma += MCE_MAX_DATA_PER_TXD;
			size -= MCE_MAX_DATA_PER_TXD;

			tx_desc->addr = cpu_to_le64(dma);
		}

		tx_desc->data_len = cpu_to_le16(size & 0xffff);
		mce_buid_ctob(tx_desc, tmp_desc);
		tx_desc->vlan2 = first->fifo_depth;
		if (pf->priv_h.en && pf->is_checksumed) {
			SET_MAC_VLAN_CTRL_PRIV_HDR(tx_desc->mac_vlan_ctl,
						   1);
			SET_TSO_SEG_NUM(tx_desc->priv_inner_type,
					pf->priv_h.len);
		}

		if (likely(!data_len))
			break;

		//printk("222\n");
		//pirnt_desc((u8 *)tx_desc, sizeof(struct mce_tx_desc));
		tx_desc++;
		i++;
		if (i == tx_ring->count) {
			tx_desc = MCE_TX_DESC(tx_ring, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;
		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_buf = &tx_ring->tx_buf[i];
	}

	if (test_bit(MCE_FLAG_MBX_CTRL_ENA, pf->flags)) {
		SET_CMD_MBX_CTRL(tmp_desc->cmd);
		SET_CMD_MBX_RING_IDX(tx_desc->mss, pf->mbx_ring_id);
		SET_CMD_RPU(tmp_desc->cmd);
	}

	if (test_bit(MCE_FLAG_MBX_DATA_ENA, pf->flags)) {
		SET_CMD_MBX_DATA(tmp_desc->cmd);
		SET_CMD_MBX_RING_IDX(tx_desc->mss, pf->mbx_ring_id);
		SET_CMD_RPU(tmp_desc->cmd);
	}

	/* only for test ptp tx intr */
	if (pf->mac_misc_irq & BIT(MCE_MAC_MISC_IRQ_PTP))
		SET_CMD_PTP(tmp_desc->cmd);
	SET_CMD_EOP(tmp_desc->cmd);
	SET_CMD_RS(tmp_desc->cmd);
	tx_desc->cmd = cpu_to_le32(tmp_desc->cmd);
	i++;
	if (i == tx_ring->count)
		i = 0;

	//printk("333\n");
	//pirnt_desc((u8 *)tx_desc, sizeof(struct mce_tx_desc));
	//printk("[debug] Tx: ring-%u, next_to_clean-%03u next_to_use-%03u, "
	//	 "queue_state %lx\n",
	//	 tx_ring->q_index,
	//	 tx_ring->next_to_clean,
	//	 i,
	//	 txring_txq(tx_ring)->state);
	//pirnt_desc((u8 *)tx_desc, sizeof(struct mce_tx_desc));
#ifdef MCE_DEBUG
	pr_info("[debug] Tx: ring-%u, next_to_clean-%03u next_to_use-%03u, "
		"queue_state %lx\n",
		tx_ring->q_index, tx_ring->next_to_clean, i,
		txring_txq(tx_ring)->state);
	print_hex_dump(KERN_CONT, "tx desc: ", DUMP_PREFIX_OFFSET, 16, 1,
		       tx_desc, 32, true);
#endif

	/* Force memory writes to complete before letting h/w know there
	 * are new descriptors to fetch.
	 *
	 * We also use this memory barrier to make certain all of the
	 * status bits have been updated before next_to_watch is written.
	 */
	wmb();
#ifndef MCE_TX_WB_COAL
	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;
#endif
	tx_ring->next_to_use = i;

	mce_maybe_stop_tx(tx_ring, DESC_NEEDED);
	if (pf->priv_h.en)
		first->bytecount -= pf->priv_h.len;
	/* notify HW of packet */
	kick = __netdev_tx_sent_queue(
		txring_txq(tx_ring), first->bytecount, netdev_xmit_more());
	if (kick) {
		/* notify HW of packet */
		writel(tx_ring->next_to_use, tx_ring->tail);
#ifndef SPIN_UNLOCK_IMPLIES_MMIOWB

		/* we need this if more than one processor can write to our tail
		 * at a time, it synchronizes IO on IA64/Altix systems
		 */
		mmiowb();
#endif /* SPIN_UNLOCK_IMPLIES_MMIOWB */
	}

	return;

dma_error:
	dev_err(tx_ring->dev, "TX DMA map failed");
	/* clear DMA mappings for failed tx_buf map */
	for (;;) {
		tx_buf = &tx_ring->tx_buf[i];
		mce_unmap_and_free_tx_buf(tx_ring, tx_buf);
		if (tx_buf == first)
			break;
		if (i == 0)
			i = tx_ring->count;
		i--;
	}

	tx_ring->next_to_use = i;
}

/**
 * mce_start_xmit - Selects the correct VSI and Tx queue to send buffer
 * @skb: send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
netdev_tx_t mce_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_ring *tx_ring = NULL;
	struct mce_tx_buf *first = NULL;
	struct mce_tx_desc tmp_desc = { 0 };
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = &(dcb->cur_etscfg);
	u32 count = 0;
	int q_base = vsi->num_tc_offset;
	int tc = 0;
	struct sk_buff *priv_h_skb;
	u8 *priv_data;

	if (!netif_carrier_ok(netdev)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* drop all */
	if (pf->tx_drop_en) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (test_bit(MCE_VSI_DROP_TX, vsi->state)) {
		/* if we should drop all tx */
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (pf->priv_h.en) {
		if (skb_headroom(skb) < pf->priv_h.len) {
			priv_h_skb =
				skb_realloc_headroom(skb, pf->priv_h.len);
			if (!priv_h_skb) {
				dev_kfree_skb_any(skb);
				netdev_err(netdev,
					   "priv realloc skb failed\n");
				return NETDEV_TX_OK;
			}
			dev_kfree_skb(skb);
			skb = priv_h_skb;
		}
		priv_data = (u8 *)skb_push(skb, pf->priv_h.len);
		strncpy(priv_data, pf->priv_h.priv_header, pf->priv_h.len);
	}

	if (skb_put_padto(skb, MCE_MIN_PKT_LEN))
		return NETDEV_TX_OK;

	if (test_bit(MCE_ETS_EN, dcb->flags))
		tc = etscfg->prio_table[skb->priority & TC_BITMASK];

	//printk("queue_mapping is %d, priority is %d tc %d\n", skb->queue_mapping, skb->priority, tc);
	// should add tc base
	tx_ring = vsi->tx_rings[skb->queue_mapping % vsi->num_txq_real +
				tc * q_base];
	if (!tx_ring) {
		netdev_err(netdev, "no tx_ring[%u]\n", skb->queue_mapping);
		return NETDEV_TX_BUSY;
	}
#if __DEBUG_SKB_DUMP
	mce_tx_skb_dump(skb, true);
#endif
	count = mce_xmit_desc_count(skb);
	if (mce_maybe_stop_tx(tx_ring, count)) {
		netdev_err(netdev, "tx_ring[%u] full\n",
			   skb->queue_mapping);
		++(tx_ring->ring_stats->tx_stats.tx_busy);
		return NETDEV_TX_BUSY;
	}

	/* prefetch for bql data which is infrequently used */
	netdev_txq_bql_enqueue_prefetchw(txring_txq(tx_ring));

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_buf[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = max_t(unsigned int, skb->len, ETH_ZLEN);
	/* the true data len */
	first->bytecount_fifo = skb->len;
	first->gso_size = skb_shinfo(skb)->gso_size;
	first->vlan_size = 0;
	first->gso_segs = 1;
	//first->prio = skb->priority & 0x7;

	/* if vlan offload priority is ? */

	mce_tx_prepare_vlan(tx_ring, first, &tmp_desc, pf);

	if (test_bit(MCE_PFC_EN, pf->dcb->flags)) {
		/* if not dscp mode, we should check vlan prio */
		/* if not vlan, we use prio 0 */
		//if (!(test_bit(MCE_DSCP_EN, pf->dcb->flags))) {
		//	if (tmp_desc.vlan0)
		//		first->prio = (tmp_desc.vlan0 >> 13) & 0x7;
		//	else
		//		first->prio = 0;
		//}
		//printk("set prio %d\n", first->prio);
		SET_CMD_PRIO_ID(tmp_desc.cmd, skb->priority & 0x7);
		SET_CMD_ENABLE_PRIO(tmp_desc.cmd);
	}

#ifdef HAVE_PTP_1588_CLOCK
#ifdef SKB_SHARED_TX_IS_UNION
	if (unlikely(skb_tx(skb)->hardware) &&
	    pf->flags2 & MCE_FLAG2_PTP_ENABLED && pf->ptp_tx_en) {
		if (!test_and_set_bit_lock(MCE_PTP_TX_IN_PROGRESS,
					   pf->state)) {
			skb_tx(skb)->in_progress = 1;

#else
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) &&
	    pf->flags2 & MCE_FLAG2_PTP_ENABLED && pf->ptp_tx_en) {
		if (!test_and_set_bit_lock(MCE_PTP_TX_IN_PROGRESS,
					   pf->state)) {
			skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
#endif
			SET_CMD_PTP(tmp_desc.cmd);
			// fix me later
			//tx_flags |= RNP_TXD_FLAG_PTP;
			pf->ptp_tx_skb = skb_get(skb);
			pf->tx_hwtstamp_start = jiffies;
			schedule_work(&pf->tx_hwtstamp_work);
			//printk("it is ptp packet\n");
		} else {
			netdev_dbg(tx_ring->netdev, "ptp_tx_skb miss\n");
		}
	}
#endif
	/* set up TSO offload */
	if (mce_tso(first, &tmp_desc, pf) < 0)
		goto tx_drop;

	if (mce_tx_csum(skb, &tmp_desc, pf) < 0)
		goto tx_drop;

	mce_tx_map(first, tx_ring, &tmp_desc);

	return NETDEV_TX_OK;

tx_drop:
	dev_kfree_skb_any(skb);
	tx_ring->ring_stats->tx_stats.tx_drop++;
	return NETDEV_TX_OK;
}

#ifdef MCE_TX_WB_COAL
/**
 * mce_clean_tx_irq - Reclaim resources after transmit completes
 * @tx_ring: Tx ring to clean
 * @napi_budget: Used to determine if we are in netpoll
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 */
bool mce_clean_tx_irq(struct mce_ring *tx_ring, int napi_budget)
{
	unsigned int total_bytes = 0, total_pkts = 0;
	unsigned int clean_cnt = 0;
	struct mce_vsi *vsi = tx_ring->vsi;
	struct mce_tx_desc *tx_desc = NULL;
	struct mce_desc *head_desc = NULL;
	struct mce_tx_buf *tx_buf = NULL;
	u32 head_val = 0;
	u16 i = tx_ring->next_to_clean;

	netdev_txq_bql_complete_prefetchw(txring_txq(tx_ring));

	tx_buf = &tx_ring->tx_buf[i];
	tx_desc = MCE_TX_DESC(tx_ring, i);
	head_desc = MCE_DESC(tx_ring, tx_ring->count);
	head_val = (le32_to_cpu(head_desc->desc0) & 0x7fff);

	while (i != head_val) {
		if (tx_buf->skb) {
			/* update the statistics for this packet */
			total_bytes += tx_buf->bytecount;
			total_pkts += tx_buf->gso_segs;
			prefetchw(&tx_buf->skb->users);
			/* free the skb */
			napi_consume_skb(tx_buf->skb, napi_budget);
			/* clear tx_buf data */
			tx_buf->skb = NULL;
		}

		if (dma_unmap_len(tx_buf, len)) {
			dma_unmap_single(tx_ring->dev,
					 dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len),
					 DMA_TO_DEVICE);
			dma_unmap_len_set(tx_buf, len, 0);
			dma_unmap_addr_set(tx_buf, dma, 0);
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(i == tx_ring->count)) {
			i = 0;
			tx_buf = tx_ring->tx_buf;
			tx_desc = MCE_TX_DESC(tx_ring, 0);
		}

		prefetch(tx_desc);
		clean_cnt++;
	}

	tx_ring->next_to_clean = i;

	mce_update_tx_ring_stats(tx_ring, total_pkts, total_bytes);

	netdev_tx_completed_queue(txring_txq(tx_ring), total_pkts,
				  total_bytes);

#define TX_WAKE_THRESHOLD ((s16)(MAX_SKB_FRAGS * 2))
	if (unlikely(total_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     (MCE_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
		prefetch(&vsi->state);
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (netif_tx_queue_stopped(txring_txq(tx_ring)) &&
		    !test_bit(MCE_VSI_DOWN, vsi->state)) {
			netif_tx_wake_queue(txring_txq(tx_ring));
			++tx_ring->ring_stats->tx_stats.restart_q;
		}
	}

	return clean_cnt >= napi_budget ? false : true;
}
#else
/**
 * mce_clean_tx_irq - Reclaim resources after transmit completes
 * @tx_ring: Tx ring to clean
 * @napi_budget: Used to determine if we are in netpoll
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 */
bool mce_clean_tx_irq(struct mce_ring *tx_ring, int napi_budget)
{
	unsigned int total_bytes = 0, total_pkts = 0;
	unsigned int budget = MCE_DFLT_IRQ_WORK;
	struct mce_vsi *vsi = tx_ring->vsi;
	s16 i = tx_ring->next_to_clean;
	struct mce_tx_desc *tx_desc = NULL;
	struct mce_tx_buf *tx_buf = NULL;
	//struct mce_pf *pf = vsi->back;

	netdev_txq_bql_complete_prefetchw(txring_txq(tx_ring));

	tx_buf = &tx_ring->tx_buf[i];
	tx_desc = MCE_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	prefetch(&vsi->state);

	do {
		struct mce_tx_desc *eop_desc = tx_buf->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* follow the guidelines of other drivers */
		prefetchw(&tx_buf->skb->users);

		smp_rmb(); /* prevent any other reads prior to eop_desc */

		if (!(eop_desc->cmd & cpu_to_le32(MCE_TXD_CMD_DD))) {
			break;
		}

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buf->bytecount;
		total_pkts += tx_buf->gso_segs;

		/* free the skb */
		napi_consume_skb(tx_buf->skb, napi_budget);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev, dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len),
				 DMA_TO_DEVICE);
		/* clear tx_buf data */
		tx_buf->skb = NULL;
		dma_unmap_len_set(tx_buf, len, 0);
		dma_unmap_addr_set(tx_buf, dma, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buf++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buf = tx_ring->tx_buf;
				tx_desc = MCE_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buf, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buf, dma),
					       dma_unmap_len(tx_buf, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buf, len, 0);
				dma_unmap_addr_set(tx_buf, dma, 0);
			}
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buf = tx_ring->tx_buf;
			tx_desc = MCE_TX_DESC(tx_ring, 0);
		}

		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;

	mce_update_tx_ring_stats(tx_ring, total_pkts, total_bytes);
	netdev_tx_completed_queue(txring_txq(tx_ring), total_pkts,
				  total_bytes);
#define TX_WAKE_THRESHOLD ((s16)(MAX_SKB_FRAGS * 2))
	if (unlikely(total_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     (MCE_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (netif_tx_queue_stopped(txring_txq(tx_ring)) &&
		    !test_bit(MCE_VSI_DOWN, vsi->state)) {
			netif_tx_wake_queue(txring_txq(tx_ring));
			++tx_ring->ring_stats->tx_stats.restart_q;
		}
	}

	return !!budget;
}
#endif /* MCE_TX_WB_COAL */

/**
 * mce_vsi_start_all_tx_rings - start/enable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be enabled
 *
 * Returns 0 on success and a negative value on error
 */
int mce_vsi_start_all_tx_rings(struct mce_vsi *vsi)
{
	u16 q_idx;

	mce_for_each_txq_new(vsi, q_idx) {
		if (!vsi->tx_rings[q_idx]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, q_idx);
			continue;
		}
		mce_start_tx_ring(vsi->tx_rings[q_idx]);
		mce_update_tx_dim(vsi->tx_rings[q_idx]);
	}

	return 0;
}

int mce_create_rxring(struct mce_vsi *vsi, int index)
{
	struct mce_ring *ring;

	/* allocate with kzalloc(), free with kfree_rcu() */
	ring = kzalloc(sizeof(*ring), GFP_KERNEL);
	if (ring == NULL)
		return -ENOMEM;

	ring->q_index = index;
	ring->vsi = vsi;
	ring->dev = &(vsi->back->pdev->dev);
	ring->count = vsi->num_rx_desc;
	WRITE_ONCE(vsi->rx_rings[index], ring);

	return 0;
}

void mce_destroy_rxring(struct mce_vsi *vsi, int index)
{
	if (vsi->rx_rings[index]) {
		kfree_rcu(vsi->rx_rings[index], rcu);
		WRITE_ONCE(vsi->rx_rings[index], NULL);
	}
}

static void mce_set_rx_ctx(struct mce_ring *rx_ring)
{
	struct mce_vsi *vsi = rx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (rx_ring == NULL) {
		return;
	}

	hw->ops->set_rxring_ctx(rx_ring, hw);

	/* configure Rx buffer alignment */
	if (!vsi->netdev || test_bit(MCE_FLAG_LEGACY_RX, vsi->back->flags))
		mce_clear_ring_build_skb_ena(rx_ring);
	else
		mce_set_ring_build_skb_ena(rx_ring);
}

/**
 * mce_rx_offset - Return expected offset into page to access data
 * @rx_ring: Ring we are requesting offset of
 *
 * Returns the offset value for ring into the data buffer.
 */
static unsigned int mce_rx_offset(struct mce_ring *rx_ring)
{
	if (mce_ring_uses_build_skb(rx_ring))
		return MCE_SKB_PAD;
	return 0;
}

/**
 * mce_alloc_mapped_page - recycle or make a new page
 * @rx_ring: ring to use
 * @bi: rx_buf struct to modify
 *
 * Returns true if the page was successfully allocated or
 * reused.
 */
static bool mce_alloc_mapped_page(struct mce_ring *rx_ring,
				  struct mce_rx_buf *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma;

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(page))
		return true;

	/* alloc new page for storage */
	page = dev_alloc_pages(mce_rx_pg_order(rx_ring));
	if (unlikely(!page)) {
		dev_err(rx_ring->dev,
			"%s: failed to allocate rx desc memory on ring %u",
			__func__, rx_ring->q_index);
		rx_ring->ring_stats->rx_stats.alloc_page_failed++;
		return false;
	}

	/* map page for use */
#ifndef HAVE_STRUCT_DMA_ATTRS
	dma = dma_map_page_attrs(rx_ring->dev, page, 0,
				 mce_rx_pg_size(rx_ring), DMA_FROM_DEVICE,
				 MCE_RX_DMA_ATTR);
#else
	dma = dma_map_page(rx_ring->dev, page, 0, mce_rx_pg_size(rx_ring),
			   DMA_FROM_DEVICE);
#endif

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		dev_err(rx_ring->dev,
			"%s: DMA mapping failed on rx ring %u", __func__,
			rx_ring->q_index);
		__free_pages(page, mce_rx_pg_order(rx_ring));
		rx_ring->ring_stats->rx_stats.alloc_page_failed++;
		return false;
	}

	bi->dma = dma;
	bi->page = page;
	bi->page_offset = mce_rx_offset(rx_ring);
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	page_ref_add(page, USHRT_MAX - 1);
	bi->pagecnt_bias = USHRT_MAX;
#else
	bi->pagecnt_bias = 1;
#endif

	return true;
}

/**
 * mce_alloc_rx_bufs - Replace used receive buffers
 * @rx_ring: ring to place buffers on
 * @cleaned_count: number of buffers to replace
 *
 * Returns false if all allocations were successful, true if any fail. Returning
 * true signals to the caller that we didn't replace cleaned_count buffers and
 * there is more work to do.
 *
 * First, try to clean "cleaned_count" Rx buffers. Then refill the cleaned Rx
 * buffers. Then bump tail at most one time. Grouping like this lets us avoid
 * multiple tail writes per call.
 */
static void mce_alloc_rx_bufs(struct mce_ring *rx_ring, u16 cleaned_count)
{
	struct mce_rx_desc_down *rx_desc = NULL;
	struct mce_rx_buf *bi = NULL;
	u16 ntu = rx_ring->next_to_use;
	/* do nothing if no valid netdev defined */
	if ((!rx_ring->netdev) || !cleaned_count)
		return;

	/* get the Rx descriptor and buffer based on next_to_use */
	rx_desc = MCE_RXDESC_DOWN(rx_ring, ntu);
	bi = &(rx_ring->rx_buf[ntu]);

	do {
		/* if we fail here, we have work remaining */
		if (!mce_alloc_mapped_page(rx_ring, bi))
			break;

		/* sync the buffer for use by the device */
		dma_sync_single_range_for_device(rx_ring->dev, bi->dma,
						 bi->page_offset,
						 rx_ring->rx_buf_len,
						 DMA_FROM_DEVICE);

		/* Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
		rx_desc->addr = cpu_to_le64(bi->dma + bi->page_offset);
		rx_desc->cmd0 = 0;
		rx_desc++;
		bi++;
		ntu++;
		if (unlikely(ntu == rx_ring->count)) {
			rx_desc = MCE_RXDESC_DOWN(rx_ring, 0);
			bi = rx_ring->rx_buf;
			ntu = 0;
		}

		cleaned_count--;
	} while (cleaned_count);

	if (rx_ring->next_to_use != ntu) {
		WRITE_ONCE(rx_ring->next_to_use, ntu);
		WRITE_ONCE(rx_ring->next_to_alloc, ntu);
		wmb();
		writel(rx_ring->next_to_use, rx_ring->tail);
	}
}

/**
 * mce_vsi_cfg_rxq - Configure an Rx queue
 * @ring: the ring being configured
 *
 * Return 0 on success and a negative value on error.
 */
static int mce_vsi_cfg_rxq(struct mce_ring *ring)
{
	u16 num_bufs = MCE_DESC_UNUSED(ring);

	if (ring == NULL)
		return -EFAULT;

	ring->rx_buf_len = ring->vsi->rx_buf_len;

	mce_set_rx_ctx(ring);

	mce_alloc_rx_bufs(ring, num_bufs);

	return 0;
}

/**
 * mce_vsi_cfg_rxqs - Configure the VSI for Rx
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Rx VSI for operation.
 */
static int mce_vsi_cfg_rxqs(struct mce_vsi *vsi)
{
	u16 i;

	mce_vsi_cfg_frame_size(vsi);

	/* set up individual rings */
	mce_for_each_rxq_new(vsi, i) {
		int err;

		if (!vsi->rx_rings[i]->q_vector)
			continue;
		err = mce_vsi_cfg_rxq(vsi->rx_rings[i]);
		if (err)
			return err;
	}

	return 0;
}

/**
 * mce_setup_rx_ring - Allocate the Rx descriptors
 * @rx_ring: the Rx ring to set up
 *
 * Return 0 on success, negative on error
 */
int mce_setup_rx_ring(struct mce_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;

	if (!dev)
		return -ENOMEM;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(rx_ring->rx_buf);
	rx_ring->rx_buf = devm_kcalloc(dev, sizeof(*rx_ring->rx_buf),
				       rx_ring->count, GFP_KERNEL);
	if (!rx_ring->rx_buf)
		return -ENOMEM;
	/* round up to nearest page */
	rx_ring->size =
		ALIGN(rx_ring->count * sizeof(struct mce_desc), PAGE_SIZE);
	rx_ring->desc = dmam_alloc_coherent(dev, rx_ring->size,
					    &rx_ring->dma, GFP_KERNEL);
	if (!rx_ring->desc) {
		dev_err(dev,
			"Unable to allocate memory for the Rx "
			"descriptor ring, size=%d\n",
			rx_ring->size);
		goto err;
	}

	rx_ring->next_to_use = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->flags = 0;

	return 0;
err:
	devm_kfree(dev, rx_ring->rx_buf);
	rx_ring->rx_buf = NULL;
	return -ENOMEM;
}

/**
 * mce_vsi_setup_rx_rings - Allocate VSI Rx queue resources
 * @vsi: VSI having resources allocated
 *
 * Return 0 on success, negative on failure
 */
int mce_vsi_setup_rx_rings(struct mce_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->num_rxq) {
		dev_err(mce_pf_to_dev(vsi->back),
			"VSI %d has 0 Rx queues\n", vsi->idx);
		return -EINVAL;
	}

	mce_for_each_rxq_new(vsi, i) {
		struct mce_ring *ring = vsi->rx_rings[i];

		if (!ring)
			return -EINVAL;
		if (!ring->q_vector)
			continue;
		if (vsi->netdev)
			ring->netdev = vsi->netdev;
		err = mce_setup_rx_ring(ring);
		if (err)
			break;
	}

	return err;
}

static inline void enable_rxring_irq(struct mce_ring *rx_ring)
{
	struct mce_vsi *vsi = rx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (rx_ring == NULL)
		return;

	hw->ops->enable_rxring_irq(rx_ring);
}

static inline void disable_rxring_irq(struct mce_ring *rx_ring)
{
	struct mce_vsi *vsi = rx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (rx_ring == NULL)
		return;

	hw->ops->disable_rxring_irq(rx_ring);
}

static inline void mce_start_rx_ring(struct mce_ring *rx_ring)
{
	struct mce_vsi *vsi = rx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (rx_ring == NULL)
		return;

	hw->ops->start_rxring(rx_ring);
}

void mce_stop_rx_ring(struct mce_ring *rx_ring)
{
	struct mce_vsi *vsi = rx_ring->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	if (rx_ring == NULL)
		return;

	hw->ops->stop_rxring(rx_ring);
}

/**
 * mce_clean_rx_ring - Free Rx buffers
 * @rx_ring: ring to be cleaned
 */
void mce_clean_rx_ring(struct mce_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!rx_ring->rx_buf)
		return;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		struct mce_rx_buf *rx_buf = &rx_ring->rx_buf[i];

		if (rx_buf->skb) {
			dev_kfree_skb(rx_buf->skb);
			rx_buf->skb = NULL;
		}
		if (!rx_buf->page)
			continue;

		/* Invalidate cache lines that may have been written to by
		 * device so that we avoid corrupting memory.
		 */
		dma_sync_single_range_for_cpu(dev, rx_buf->dma,
					      rx_buf->page_offset,
					      rx_ring->rx_buf_len,
					      DMA_FROM_DEVICE);

#ifndef HAVE_STRUCT_DMA_ATTRS
		/* free resources associated with mapping */
		dma_unmap_page_attrs(dev, rx_buf->dma,
				     mce_rx_pg_size(rx_ring),
				     DMA_FROM_DEVICE, MCE_RX_DMA_ATTR);
#else
		dma_unmap_page(dev, rx_buf->dma, mce_rx_pg_size(rx_ring),
			       DMA_FROM_DEVICE);
#endif
		__page_frag_cache_drain(rx_buf->page,
					rx_buf->pagecnt_bias);

		rx_buf->page = NULL;
		rx_buf->page_offset = 0;
	}

	memset(rx_ring->rx_buf, 0,
	       sizeof(*rx_ring->rx_buf) * rx_ring->count);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
}

/**
 * mce_free_rx_ring - Free Rx resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 */
void mce_free_rx_ring(struct mce_ring *rx_ring)
{
	mce_clean_rx_ring(rx_ring);
	devm_kfree(rx_ring->dev, rx_ring->rx_buf);
	rx_ring->rx_buf = NULL;

	if (rx_ring->desc) {
		dmam_free_coherent(rx_ring->dev, rx_ring->size,
				   rx_ring->desc, rx_ring->dma);
		rx_ring->desc = NULL;
	}
}

void mce_disable_vec_rxs_irq(struct mce_q_vector *vector)
{
	struct mce_ring *ring;

	mce_rc_for_each_ring(ring, vector->rx) {
		disable_rxring_irq(ring);
	}
}

void mce_enable_vec_rxs_irq(struct mce_q_vector *vector)
{
	struct mce_ring *ring;

	mce_rc_for_each_ring(ring, vector->rx) {
		enable_rxring_irq(ring);
	}
}

static inline struct mce_rx_buf *mce_rx_buf(struct mce_ring *rx_ring,
					    u32 idx)
{
	return &rx_ring->rx_buf[idx];
}

/**
 * mce_get_rx_buf - Fetch Rx buffer and synchronize data for use
 * @rx_ring: Rx descriptor ring to transact packets on
 * @skb: skb to be used
 * @size: size of buffer to add to skb
 * @rx_buf_pgcnt: rx_buf page refcount
 *
 * This function will pull an Rx buffer from the ring and synchronize it
 * for use by the CPU.
 */
static struct mce_rx_buf *mce_get_rx_buf(struct mce_ring *rx_ring,
					 struct sk_buff **skb,
					 const unsigned int size,
					 int *rx_buf_pgcnt)
{
	struct mce_rx_buf *rx_buf;

	rx_buf = mce_rx_buf(rx_ring, rx_ring->next_to_clean);
	*rx_buf_pgcnt =
#if (PAGE_SIZE < 8192)
		page_count(rx_buf->page);
#else
		0;
#endif
	prefetchw(rx_buf->page);
	*skb = rx_buf->skb;

	if (!size)
		return rx_buf;
	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev, rx_buf->dma,
				      rx_buf->page_offset, size,
				      DMA_FROM_DEVICE);

	/* We have pulled a buffer for use, so decrement pagecnt_bias */
	rx_buf->pagecnt_bias--;

	return rx_buf;
}

/**
 * mce_rx_buf_adjust_pg_offset - Prepare Rx buffer for reuse
 * @rx_buf: Rx buffer to adjust
 * @size: Size of adjustment
 *
 * Update the offset within page so that Rx buf will be ready to be reused.
 * For systems with PAGE_SIZE < 8192 this function will flip the page offset
 * so the second half of page assigned to Rx buffer will be used, otherwise
 * the offset is moved by "size" bytes
 */
static void mce_rx_buf_adjust_pg_offset(struct mce_rx_buf *rx_buf,
					unsigned int size)
{
#if (PAGE_SIZE < 8192)
	/* flip page offset to other buffer */
	rx_buf->page_offset ^= size;
#else
	/* move offset up to the next cache line */
	rx_buf->page_offset += size;
#endif
}

/**
 * mce_add_rx_frag - Add contents of Rx buffer to sk_buff as a frag
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: buffer containing page to add
 * @skb: sk_buff to place the data into
 * @size: packet length from rx_desc
 *
 * This function will add the data contained in rx_buf->page to the skb.
 * It will just attach the page as a frag to the skb.
 * The function will then update the page offset.
 */
static void mce_add_rx_frag(struct mce_ring *rx_ring,
			    struct mce_rx_buf *rx_buf, struct sk_buff *skb,
			    unsigned int size)
{
#if (PAGE_SIZE >= 8192)
	unsigned int truesize =
		SKB_DATA_ALIGN(size + mce_rx_offset(rx_ring));
#else
	unsigned int truesize = mce_rx_pg_size(rx_ring) / 2;
#endif

	if (!size)
		return;
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buf->page,
			rx_buf->page_offset, size, truesize);

	/* page is being used so we must update the page offset */
	mce_rx_buf_adjust_pg_offset(rx_buf, truesize);
}

/**
 * mce_build_skb - Build skb around an existing buffer
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: Rx buffer to pull data from
 * @xdp: xdp_buff pointing to the data
 *
 * This function builds an skb around an existing Rx buffer, taking care
 * to set up the skb correctly and avoid any memcpy overhead.
 */
static struct sk_buff *mce_build_skb(struct mce_ring *rx_ring,
				     struct mce_rx_buf *rx_buf,
				     struct xdp_buff *xdp)
{
	struct mce_netdev_priv *np = netdev_priv(rx_ring->netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
#ifdef HAVE_XDP_BUFF_DATA_META
	u8 metasize = xdp->data - xdp->data_meta;
#endif /* HAVE_XDP_BUFF_DATA_META */
#if (PAGE_SIZE < 8192)
	unsigned int truesize = mce_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize =
		SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
		SKB_DATA_ALIGN(xdp->data_end - xdp->data_hard_start);
#endif
	struct sk_buff *skb;
#ifdef HAVE_XDP_BUFF_DATA_META
	/* Prefetch first cache line of first page. If xdp->data_meta
		 * is unused, this points exactly as xdp->data, otherwise we
		 * likely have a consumer accessing first few bytes of meta
		 * data, and then actual data.
		 */
	net_prefetch(xdp->data_meta);
#else
	net_prefetch(xdp->data);
#endif /* HAVE_XDP_BUFF_DATA_META */

	/* build an skb around the page buffer */
	skb = build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb))
		return NULL;

	/* must to record Rx queue, otherwise OS features such as
	 * symmetric queue won't work
	 */
	skb_record_rx_queue(skb, rx_ring->q_index);

	/* update pointers within the skb to store the data */
	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	__skb_put(skb, xdp->data_end - xdp->data);
#ifdef HAVE_XDP_BUFF_DATA_META
	if (metasize)
		skb_metadata_set(skb, metasize);
#endif /* HAVE_XDP_BUFF_DATA_META */
	if (pf->priv_h.en)
		skb_pull(skb, pf->priv_h.len);
	/* buffer is used by skb, update page_offset */
	mce_rx_buf_adjust_pg_offset(rx_buf, truesize);

	return skb;
}

/**
 * mce_get_headlen - determine size of header for RSC/LRO/GRO/FCOE
 * @data: pointer to the start of the headers
 * @max_len: total length of section to find headers in
 *
 * This function is meant to determine the length of headers that will
 * be recognized by hardware for LRO, GRO, and RSC offloads.  The main
 * motivation of doing this is to only perform one pull for IPv4 TCP
 * packets so that we can do basic things like calculating the gso_size
 * based on the average data per packet.
 **/
static unsigned int mce_get_headlen(unsigned char *data,
				    unsigned int max_len)
{
	union {
		unsigned char *network;
		/* l2 headers */
		struct ethhdr *eth;
		struct vlan_hdr *vlan;
		/* l3 headers */
		struct iphdr *ipv4;
		struct ipv6hdr *ipv6;
	} hdr;
	__be16 protocol;
	u8 nexthdr = 0; /* default to not TCP */
	u8 hlen;

	/* this should never happen, but better safe than sorry */
	if (max_len < ETH_HLEN)
		return max_len;

	/* initialize network frame pointer */
	hdr.network = data;

	/* set first protocol and move network header forward */
	protocol = hdr.eth->h_proto;
	hdr.network += ETH_HLEN;

	/* handle any vlan tag if present */
	if (protocol == htons(ETH_P_8021Q)) {
		if ((hdr.network - data) > (max_len - VLAN_HLEN))
			return max_len;

		protocol = hdr.vlan->h_vlan_encapsulated_proto;
		hdr.network += VLAN_HLEN;
	}

	/* handle L3 protocols */
	if (protocol == htons(ETH_P_IP)) {
		if ((hdr.network - data) >
		    (max_len - sizeof(struct iphdr)))
			return max_len;

		/* access ihl as a u8 to avoid unaligned access on ia64 */
		hlen = (hdr.network[0] & 0x0F) << 2;

		/* verify hlen meets minimum size requirements */
		if (hlen < sizeof(struct iphdr))
			return hdr.network - data;

		/* record next protocol if header is present */
		if (!(hdr.ipv4->frag_off & htons(IP_OFFSET)))
			nexthdr = hdr.ipv4->protocol;
	} else if (protocol == htons(ETH_P_IPV6)) {
		if ((hdr.network - data) >
		    (max_len - sizeof(struct ipv6hdr)))
			return max_len;

		/* record next protocol */
		nexthdr = hdr.ipv6->nexthdr;
		hlen = sizeof(struct ipv6hdr);
	} else {
		return hdr.network - data;
	}

	/* relocate pointer to start of L4 header */
	hdr.network += hlen;

	/* finally sort out TCP/UDP */
	if (nexthdr == IPPROTO_TCP) {
		if ((hdr.network - data) >
		    (max_len - sizeof(struct tcphdr)))
			return max_len;

		/* access doff as a u8 to avoid unaligned access on ia64 */
		hlen = (hdr.network[12] & 0xF0) >> 2;

		/* verify hlen meets minimum size requirements */
		if (hlen < sizeof(struct tcphdr))
			return hdr.network - data;

		hdr.network += hlen;
	} else if (nexthdr == IPPROTO_UDP) {
		if ((hdr.network - data) >
		    (max_len - sizeof(struct udphdr)))
			return max_len;

		hdr.network += sizeof(struct udphdr);
	}

	/*
	 * If everything has gone correctly hdr.network should be the
	 * data section of the packet and will be the end of the header.
	 * If not then it probably represents the end of the last recognized
	 * header.
	 */
	if ((hdr.network - data) < max_len)
		return hdr.network - data;
	else
		return max_len;
}

/**
 * mce_construct_skb - Allocate skb and populate it
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: Rx buffer to pull data from
 * @xdp: xdp_buff pointing to the data
 *
 * This function allocates an skb. It then populates it with the page
 * data from the current receive descriptor, taking care to set up the
 * skb correctly.
 */
static struct sk_buff *mce_construct_skb(struct mce_ring *rx_ring,
					 struct mce_rx_buf *rx_buf,
					 struct xdp_buff *xdp)
{
	unsigned int size = xdp->data_end - xdp->data;
	unsigned int headlen;
	struct sk_buff *skb;

	/* prefetch first cache line of first page */
	net_prefetch(xdp->data);

	/* allocate a skb to store the frags */
	skb = napi_alloc_skb(&rx_ring->q_vector->napi, MCE_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	skb_record_rx_queue(skb, rx_ring->q_index);
	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > MCE_RX_HDR_SIZE)
		headlen = mce_get_headlen(xdp->data, MCE_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), xdp->data,
	       ALIGN(headlen, sizeof(long)));

	/* if we exhaust the linear part then add what is left as a frag */
	size -= headlen;
	if (size) {
#if (PAGE_SIZE >= 8192)
		unsigned int truesize = SKB_DATA_ALIGN(size);
#else
		unsigned int truesize = mce_rx_pg_size(rx_ring) / 2;
#endif
		skb_add_rx_frag(skb, 0, rx_buf->page,
				rx_buf->page_offset + headlen, size,
				truesize);
		/* buffer is used by skb, update page_offset */
		mce_rx_buf_adjust_pg_offset(rx_buf, truesize);
	} else {
		/* buffer is unused, reset bias back to rx_buf; data was copied
		 * onto skb's linear part so there's no need for adjusting
		 * page offset and we can reuse this buffer as-is
		 */
		rx_buf->pagecnt_bias++;
	}

	return skb;
}

/**
 * mce_inc_ntc: Advance the next_to_clean index
 * @rx_ring: Rx ring
 **/
static void mce_inc_ntc(struct mce_ring *rx_ring)
{
	u16 ntc = rx_ring->next_to_clean + 1;

	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;
	prefetch(MCE_RXDESC_UP(rx_ring, ntc));
}

/**
 * mce_page_is_reserved - check if reuse is possible
 * @page: page struct to check
 */
static bool mce_page_is_reserved(struct page *page)
{
	return (page_to_nid(page) != numa_mem_id()) ||
	       page_is_pfmemalloc(page);
}

/**
 * mce_can_reuse_rx_page - Determine if page can be reused for another Rx
 * @rx_buf: buffer containing the page
 * @rx_buf_pgcnt: rx_buf page refcount pre xdp_do_redirect() call
 *
 * If page is reusable, we have a green light for calling mce_reuse_rx_page,
 * which will assign the current buffer to the buffer that next_to_alloc is
 * pointing to; otherwise, the DMA mapping needs to be destroyed and
 * page freed
 */
static bool mce_can_reuse_rx_page(struct mce_rx_buf *rx_buf,
				  int rx_buf_pgcnt)
{
	unsigned int pagecnt_bias = rx_buf->pagecnt_bias;
	struct page *page = rx_buf->page;

	/* avoid re-using remote pages */
	if (unlikely(mce_page_is_reserved(page)))
		return false;

#if (PAGE_SIZE < 8192)
	/* if we are only owner of page we can reuse it */
	if (unlikely((rx_buf_pgcnt - pagecnt_bias) > 1))
		return false;
#else
#define MCE_LAST_OFFSET (SKB_WITH_OVERHEAD(PAGE_SIZE) - MCE_RXBUF_2048)
	if (rx_buf->page_offset > MCE_LAST_OFFSET)
		return false;
#endif /* PAGE_SIZE < 8192) */

	/* If we have drained the page fragment pool we need to update
	 * the pagecnt_bias and page count so that we fully restock the
	 * number of references the driver holds.
	 */
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	if (unlikely(pagecnt_bias == 1)) {
		page_ref_add(page, USHRT_MAX - 1);
		rx_buf->pagecnt_bias = USHRT_MAX;
	}
#else
	if (likely(!pagecnt_bias)) {
		get_page(page);
		rx_buf->pagecnt_bias = 1;
	}
#endif

	return true;
}

/**
 * mce_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: Rx descriptor ring to store buffers on
 * @old_buf: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 */
static void mce_reuse_rx_page(struct mce_ring *rx_ring,
			      struct mce_rx_buf *old_buf)
{
	u16 nta = rx_ring->next_to_alloc;
	struct mce_rx_buf *new_buf;

	new_buf = &rx_ring->rx_buf[nta];

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* Transfer page from old buffer to new buffer.
	 * Move each member individually to avoid possible store
	 * forwarding stalls and unnecessary copy of skb.
	 */
	new_buf->dma = old_buf->dma;
	new_buf->page = old_buf->page;
	new_buf->page_offset = old_buf->page_offset;
	new_buf->pagecnt_bias = old_buf->pagecnt_bias;
}

/**
 * mce_put_rx_buf - Clean up used buffer and either recycle or free
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: Rx buffer to pull data from
 * @rx_buf_pgcnt: Rx buffer page count pre xdp_do_redirect()
 *
 * This function will update next_to_clean and then clean up the contents
 * of the rx_buf. It will either recycle the buffer or unmap it and free
 * the associated resources.
 */
static void mce_put_rx_buf(struct mce_ring *rx_ring,
			   struct mce_rx_buf *rx_buf, int rx_buf_pgcnt)
{
	mce_inc_ntc(rx_ring);

	if (!rx_buf)
		return;

	if (mce_can_reuse_rx_page(rx_buf, rx_buf_pgcnt)) {
		/* hand second half of page back to the ring */
		mce_reuse_rx_page(rx_ring, rx_buf);
	} else {
		/* we are not reusing the buffer so unmap it */
#ifndef HAVE_STRUCT_DMA_ATTRS
		dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma,
				     mce_rx_pg_size(rx_ring),
				     DMA_FROM_DEVICE, MCE_RX_DMA_ATTR);
#else
		dma_unmap_page(rx_ring->dev, rx_buf->dma,
			       mce_rx_pg_size(rx_ring), DMA_FROM_DEVICE);
#endif
		__page_frag_cache_drain(rx_buf->page,
					rx_buf->pagecnt_bias);
	}

	/* clear contents of buffer_info */
	rx_buf->page = NULL;
	rx_buf->skb = NULL;
}

/**
 * mce_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 *
 * If the buffer is an EOP buffer, this function exits returning false,
 * otherwise return true indicating that this is in fact a non-EOP buffer.
 */
static bool mce_is_non_eop(struct mce_ring *rx_ring,
			   struct mce_rx_desc_up *rx_desc,
			   struct sk_buff *skb)
{
	if ((rx_desc->cmd & cpu_to_le32(MCE_RXD_CMD_EOP)))
		return false;

	/* place skb in next buffer to be received */
	rx_ring->rx_buf[rx_ring->next_to_clean].skb = skb;
	rx_ring->ring_stats->rx_stats.non_eop_descs++;

	return true;
}

/**
 * mce_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @rx_ring: Rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing. The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed
 */
int mce_clean_rx_irq(struct mce_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
	u16 cleaned_count = MCE_DESC_UNUSED(rx_ring);
	struct xdp_buff xdp;
#ifdef HAVE_PTP_1588_CLOCK
	struct mce_netdev_priv *np = netdev_priv(rx_ring->netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
#endif

	/* start the loop to process Rx packets bounded by 'budget' */
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		struct mce_rx_desc_up *rx_desc = NULL;
		struct mce_rx_buf *rx_buf = NULL;
		struct sk_buff *skb = NULL;
		unsigned int size;
		int rx_buf_pgcnt;

		if (cleaned_count >= MCE_RX_BUFFER_WRITE) {
			mce_alloc_rx_bufs(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		/* get the Rx desc from Rx ring based on 'next_to_clean' */
		rx_desc = MCE_RXDESC_UP(rx_ring, rx_ring->next_to_clean);

		/* DD bit will always be zero for unused descriptors
		 * because it's cleared in cleanup, and overlaps with hdr_addr
		 * which is always zero because packet split isn't used, if the
		 * hardware wrote DD then it will be non-zero
		 */
		if (!(rx_desc->cmd & cpu_to_le32(MCE_RXD_CMD_DD)))
			break;

#ifdef MCE_DEBUG
		pr_info("[debug] Rx: ring-%u, next_to_clean-%03u "
			"next_to_use-%03u\n",
			rx_ring->q_index, rx_ring->next_to_clean,
			rx_ring->next_to_use);
		print_hex_dump(KERN_CONT, "rx desc: ", DUMP_PREFIX_OFFSET,
			       16, 1, rx_desc, 32, true);
#endif

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * DD bit is set.
		 */
		dma_rmb();

		size = le16_to_cpu(rx_desc->data_len);
		rx_buf =
			mce_get_rx_buf(rx_ring, &skb, size, &rx_buf_pgcnt);
		if (!size) {
			xdp.data = NULL;
			xdp.data_end = NULL;
			xdp.data_hard_start = NULL;
#ifdef HAVE_XDP_BUFF_DATA_META
			xdp.data_meta = NULL;
#endif /* HAVE_XDP_BUFF_DATA_META */
		} else {
			xdp.data = page_address(rx_buf->page) +
				   rx_buf->page_offset;
			xdp.data_hard_start =
				xdp.data - mce_rx_offset(rx_ring);
#ifdef HAVE_XDP_BUFF_DATA_META
			xdp.data_meta = xdp.data;
#endif /* HAVE_XDP_BUFF_DATA_META */
			xdp.data_end = xdp.data + size;
		}

		if (skb) {
			mce_add_rx_frag(rx_ring, rx_buf, skb, size);
		} else if (likely(xdp.data)) {
			if (mce_ring_uses_build_skb(rx_ring)) {
				skb = mce_build_skb(rx_ring, rx_buf, &xdp);
			} else {
				skb = mce_construct_skb(rx_ring, rx_buf,
							&xdp);
			}
		}
		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_ring->ring_stats->rx_stats.alloc_buf_failed++;
			if (rx_buf)
				rx_buf->pagecnt_bias++;
			break;
		}
#ifdef HAVE_PTP_1588_CLOCK
		if (pf->ptp_rx_en && (pf->flags2 & MCE_FLAG2_PTP_ENABLED))
			mce_ptp_get_rx_hwstamp(pf, rx_desc, skb);
#endif

		mce_put_rx_buf(rx_ring, rx_buf, rx_buf_pgcnt);
		cleaned_count++;

		if (mce_is_non_eop(rx_ring, rx_desc, skb))
			continue;

		/* pad the skb if needed, to make a valid ethernet frame */
		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		mce_process_skb_fields(rx_ring, rx_desc, skb);

		/* send completed skb up the stack */
		napi_gro_receive(&(rx_ring->q_vector->napi), skb);

		total_rx_pkts++;
	}

	if (rx_ring->ring_stats)
		mce_update_rx_ring_stats(rx_ring, total_rx_pkts,
					 total_rx_bytes);

	/* guarantee a trip back through this routine if there was a failure */
	return (int)total_rx_pkts;
}

/**
 * mce_vsi_start_all_rx_rings - start/enable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be enabled
 *
 * Returns 0 on success and a negative value on error
 */
int mce_vsi_start_all_rx_rings(struct mce_vsi *vsi)
{
	u16 q_idx;

	mce_for_each_rxq_new(vsi, q_idx) {

		if (!vsi->rx_rings[q_idx]->q_vector)
			continue;
		mce_start_rx_ring(vsi->rx_rings[q_idx]);
		mce_update_rx_dim(vsi->rx_rings[q_idx]);
	}

	return 0;
}

/**
 * mce_vsi_cfg - Setup the VSI
 * @vsi: the VSI being configured
 *
 * Return 0 on success and negative value on error
 */
int mce_vsi_cfg(struct mce_vsi *vsi)
{
	int err;

	err = mce_vsi_cfg_lan_txqs(vsi);
	if (!err)
		err = mce_vsi_cfg_rxqs(vsi);

	return err;
}
