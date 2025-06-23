#include "mce_lib.h"
#include "mce_netdev.h"
#include "mce_txrx.h"
#include "mce_irq.h"
#include "mce_dcbnl.h"
#include "mce_tc_lib.h"
#include "mce_fdir.h"
#include "mce_netdev.h"
#include "mce_dcb.h"
#include "mce_n20/mce_hw_n20.h"

/**
 * mce_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP). At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns 0 on success, negative value on failure
 */
int mce_open(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	int err = 0;

	if (test_bit(MCE_NEEDS_RESTART, pf->state)) {
		netdev_err(netdev,
			   "driver needs to be unloaded and reloaded\n");
		return -EIO;
	}

	netif_carrier_off(netdev);
	vsi->link = 0;

	err = mce_vsi_open(vsi);
	if (err)
		netdev_err(netdev, "Failed to open VSI 0x%04X\n",
			   vsi->idx);
#ifdef HAVE_PTP_1588_CLOCK
	mce_ptp_register(pf);
#endif
	/* Update existing tunnels information */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
	udp_tunnel_get_rx_info(netdev);
#else /* HAVE_UDP_ENC_RX_OFFLOAD */
#ifdef HAVE_VXLAN_RX_OFFLOAD
#if IS_ENABLED(CONFIG_VXLAN)
	vxlan_get_rx_port(netdev);
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD */
#ifdef HAVE_GENEVE_RX_OFFLOAD
#if IS_ENABLED(CONFIG_GENEVE)
	geneve_get_rx_port(netdev);
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD */
#endif /* HAVE_UDP_ENC_RX_OFFLOAD */

	netdev_info(netdev, "open");

	return err;
}

/**
 * mce_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state. The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns success only - not allowed to fail
 */
static int mce_stop(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
#ifdef HAVE_PTP_1588_CLOCK
	struct mce_pf *pf = vsi->back;

	mce_ptp_unregister(pf);
#endif
	mce_vsi_close(vsi);

	netdev_info(netdev, "close");

	return 0;
}

/**
 * mce_fetch_u64_stats_per_ring - get packets and bytes stats per ring
 * @ring_stat: Tx or Rx stats to read from
 * @pkts: packets stats counter
 * @bytes: bytes stats counter
 *
 * This function fetches stats from the ring considering the atomic operations
 * that needs to be performed to read u64 values in 32 bit machine.
 */
static void mce_fetch_u64_stats_per_ring(struct mce_ring_stats *ring_stat,
					 u64 *pkts, u64 *bytes)
{
	unsigned int start;
	*pkts = 0;
	*bytes = 0;

	if (!ring_stat)
		return;
	do {
		start = u64_stats_fetch_begin(&ring_stat->syncp);
		*pkts = ring_stat->stats.pkts;
		*bytes = ring_stat->stats.bytes;
	} while (u64_stats_fetch_retry(&ring_stat->syncp, start));
}

/**
 * mce_update_vsi_tx_ring_stats - Update VSI Tx ring stats counters
 * @vsi: the VSI to be updated
 * @vsi_stats: the stats struct to be updated
 * @rings: rings to work on
 * @count: number of rings
 */
static void
mce_update_vsi_tx_ring_stats(struct mce_vsi *vsi,
			       struct rtnl_link_stats64 *vsi_stats,
			       struct mce_ring **rings, u16 count)
{
	u16 i;

	for (i = 0; i < count; i++) {
		struct mce_ring *ring;
		u64 pkts, bytes;

		ring = READ_ONCE(rings[i]);
		mce_fetch_u64_stats_per_ring(ring->ring_stats, &pkts,
					       &bytes);
		vsi_stats->tx_packets += pkts;
		vsi_stats->tx_bytes += bytes;
		vsi_stats->tx_dropped +=
			READ_ONCE(ring->ring_stats->tx_stats.tx_drop);
		vsi->tx_restart += ring->ring_stats->tx_stats.restart_q;
		vsi->tx_busy += ring->ring_stats->tx_stats.tx_busy;
		vsi->tx_linearize +=
			ring->ring_stats->tx_stats.tx_linearize;
		vsi->ofld_stats.tx_inserted_vlan +=
			ring->ring_stats->tx_stats.inserted_vlan;
	}
}

/**
 * mce_update_vsi_ring_stats - Update VSI stats counters
 * @vsi: the VSI to be updated
 */
void mce_update_vsi_ring_stats(struct mce_vsi *vsi)
{
	struct rtnl_link_stats64 *net_stats, *stats_prev;
	struct rtnl_link_stats64 *vsi_stats;
	int i;

	vsi_stats = kzalloc(sizeof(*vsi_stats), GFP_ATOMIC);
	if (!vsi_stats)
		return;

	/* reset non-netdev (extended) stats */
	vsi->tx_restart = 0;
	vsi->tx_busy = 0;
	vsi->tx_linearize = 0;
	vsi->rx_buf_failed = 0;
	vsi->rx_page_failed = 0;

	/* reset vlan csum offload stats */
	vsi->ofld_stats.tx_inserted_vlan = 0;
	vsi->ofld_stats.rx_stripped_vlan = 0;
	vsi->ofld_stats.rx_csum_err = 0;
	vsi->ofld_stats.rx_csum_unnecessary = 0;
	vsi->ofld_stats.rx_csum_none = 0;

	rcu_read_lock();

	/* update Tx rings counters */
	mce_update_vsi_tx_ring_stats(vsi, vsi_stats, vsi->tx_rings,
				       vsi->num_txq);

	/* update Rx rings counters */
	mce_for_each_rxq_new(vsi, i) {
		struct mce_ring *ring = READ_ONCE(vsi->rx_rings[i]);
		struct mce_ring_stats *ring_stats;
		u64 pkts, bytes;

		if (!ring->q_vector)
			continue;

		ring_stats = ring->ring_stats;
		mce_fetch_u64_stats_per_ring(ring_stats, &pkts, &bytes);
		vsi_stats->rx_packets += pkts;
		vsi_stats->rx_bytes += bytes;
		vsi->rx_buf_failed +=
			ring_stats->rx_stats.alloc_buf_failed;
		vsi->rx_page_failed +=
			ring_stats->rx_stats.alloc_page_failed;
		vsi->ofld_stats.rx_stripped_vlan +=
			ring_stats->rx_stats.stripped_vlan;
		vsi->ofld_stats.rx_csum_err +=
			ring_stats->rx_stats.csum_err;
		vsi->ofld_stats.rx_csum_unnecessary +=
			ring_stats->rx_stats.csum_unnecessary;
		vsi->ofld_stats.rx_csum_none +=
			ring_stats->rx_stats.csum_none;
	}

	rcu_read_unlock();

	net_stats = &vsi->net_stats;
	stats_prev = &vsi->net_stats_prev;

	/* clear prev counters after reset */
	if (vsi_stats->tx_packets < stats_prev->tx_packets ||
	    vsi_stats->rx_packets < stats_prev->rx_packets) {
		stats_prev->tx_packets = 0;
		stats_prev->tx_bytes = 0;
		stats_prev->rx_packets = 0;
		stats_prev->rx_bytes = 0;
		stats_prev->tx_dropped = 0;
	}

	/* update netdev counters */
	net_stats->tx_packets +=
		vsi_stats->tx_packets - stats_prev->tx_packets;
	net_stats->tx_bytes += vsi_stats->tx_bytes - stats_prev->tx_bytes;
	net_stats->rx_packets +=
		vsi_stats->rx_packets - stats_prev->rx_packets;
	net_stats->rx_bytes += vsi_stats->rx_bytes - stats_prev->rx_bytes;
	net_stats->tx_dropped +=
		vsi_stats->tx_dropped - stats_prev->tx_dropped;

	stats_prev->tx_packets = vsi_stats->tx_packets;
	stats_prev->tx_bytes = vsi_stats->tx_bytes;
	stats_prev->rx_packets = vsi_stats->rx_packets;
	stats_prev->rx_bytes = vsi_stats->rx_bytes;
	stats_prev->tx_dropped = vsi_stats->tx_dropped;

	kfree(vsi_stats);
}

/**
 * mce_get_stats64 - get statistics for network device structure
 * @netdev: network interface device structure
 * @stats: main device statistics structure
 */
static
#ifdef HAVE_VOID_NDO_GET_STATS64
	void
	mce_get_stats64(struct net_device *netdev,
			  struct rtnl_link_stats64 *stats)
#else /* HAVE_VOID_NDO_GET_STATS64 */
	struct rtnl_link_stats64 *
	mce_get_stats64(struct net_device *netdev,
			  struct rtnl_link_stats64 *stats)
#endif /* !HAVE_VOID_NDO_GET_STATS64 */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct rtnl_link_stats64 *vsi_stats;
	struct mce_vsi *vsi = np->vsi;

	vsi_stats = &(vsi->net_stats);

	if (!vsi->num_txq || !vsi->num_rxq)
#ifdef HAVE_VOID_NDO_GET_STATS64
		return;
#else
		return stats;
#endif

	/* netdev packet/byte stats come from ring counter. These are obtained
	 * by summing up ring counters (done by mce_update_vsi_ring_stats).
	 * But, only call the update routine and read the registers if VSI is
	 * not down.
	 */
	if (!test_bit(MCE_VSI_DOWN, vsi->state))
		mce_update_vsi_ring_stats(vsi);

	stats->tx_packets = vsi_stats->tx_packets;
	stats->tx_bytes = vsi_stats->tx_bytes;
	stats->rx_packets = vsi_stats->rx_packets;
	stats->rx_bytes = vsi_stats->rx_bytes;

	/* The rest of the stats can be read from the hardware but instead we
	 * just return values that the watchdog task has already obtained from
	 * the hardware.
	 */
	stats->multicast = vsi_stats->multicast;
	stats->tx_errors = vsi_stats->tx_errors;
	stats->tx_dropped = vsi_stats->tx_dropped;
	stats->rx_errors = vsi_stats->rx_errors;
	stats->rx_dropped = vsi_stats->rx_dropped;
	stats->rx_crc_errors = vsi_stats->rx_crc_errors;
	stats->rx_length_errors = vsi_stats->rx_length_errors;
#ifndef HAVE_VOID_NDO_GET_STATS64

	return stats;
#endif
}

/**
 * mce_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 */
static int mce_set_features(struct net_device *netdev,
			      netdev_features_t features)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	netdev_features_t changed = netdev->features ^ features;

	if ((changed & NETIF_F_RXCSUM) && !(netdev->flags & IFF_PROMISC) &&
	    !(netdev->features & NETIF_F_RXALL)) {
		hw->ops->set_rx_csumofld(hw, features);
	}

	if ((changed & NETIF_F_HW_VLAN_CTAG_RX) ||
	    (changed & NETIF_F_HW_VLAN_STAG_RX)) {
		hw->ops->set_vlan_strip(hw, features);
	}

	if (((changed & NETIF_F_HW_VLAN_CTAG_FILTER) ||
	     (changed & NETIF_F_HW_VLAN_STAG_FILTER)) &&
	    !(netdev->flags & IFF_PROMISC) &&
	    !(netdev->features & NETIF_F_RXALL)) {
		hw->ops->set_vlan_filter(hw, features);
	}

	if (changed & NETIF_F_RXHASH) {
		hw->ops->set_rss_hash(hw, features);
	}

	if (changed & NETIF_F_NTUPLE) {
		mce_fdir_del_all_fltrs(hw);
	}

	netdev->features = features;

	return 0;
}

/**
 * mce_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 */
static void mce_set_rx_mode(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;

	if (!vsi)
		return;
	mce_setup_L2_filter(pf);
	/* Set the flags to synchronize filters
	 * ndo_set_rx_mode may be triggered even without a change in netdev
	 * flags
	 */
	set_bit(MCE_VSI_UMAC_FLTR_CHANGED, vsi->state);
	set_bit(MCE_VSI_MMAC_FLTR_CHANGED, vsi->state);
	set_bit(MCE_FLAG_FLTR_SYNC, vsi->back->flags);
	/* schedule our worker thread which will take care of
	 * applying the new filter changes
	 */
	mce_service_task_schedule(vsi->back);
}

static int mce_ioctl(struct net_device *netdev, struct ifreq *req, int cmd)
{
#ifdef HAVE_PTP_1588_CLOCK
        struct mce_netdev_priv *np = netdev_priv(netdev);
        struct mce_vsi *vsi = np->vsi;
        struct mce_pf *pf = vsi->back;
#endif
        /* ptp 1588 used this */
        switch (cmd) {
#ifdef HAVE_PTP_1588_CLOCK
#ifdef SIOCGHWTSTAMP
        case SIOCGHWTSTAMP:
                return mce_ptp_get_ts_config(pf, req);
                break;
#endif
        case SIOCSHWTSTAMP:
                return mce_ptp_set_ts_config(pf, req);
                break;
#endif
        case SIOCGMIIPHY:
                return 0;
        case SIOCGMIIREG:
                /*fall through */
        case SIOCSMIIREG:
		// addme later
                //return mce_mii_ioctl(netdev, req, cmd);
                break;
        }
        return -EINVAL;
}

/**
 * mce_vlan_rx_add_vid - Add a VLAN ID filter to HW offload
 * @netdev: network interface to be adjusted
 * @proto: VLAN TPID
 * @vid: VLAN ID to be added
 *
 * net_device_ops implementation for adding VLAN IDs
 */
static int mce_vlan_rx_add_vid(struct net_device *netdev, __be16 proto,
				 u16 vid)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = NULL;
	struct mce_vlan_list_entry *vlan_entry = NULL;
	int ret = 0;

	if (!vid)
		return ret;

	while (test_and_set_bit(MCE_CFG_BUSY, vsi->state))
		usleep_range(1000, 2000);

	/* record vlan */
	vlan_entry = devm_kzalloc(mce_hw_to_dev(hw), sizeof(*vlan_entry),
				  GFP_KERNEL);
	if (!vlan_entry)
		return -ENOMEM;

	vlan_entry->vid = vid;
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		hw->ops->add_vlan_filter(hw, vid);
		hw->ops->set_vlan_strip(hw, netdev->features);
		ret = 0;
		goto exit;
	}
	/* enable sriov */
	vf = mce_pf_to_vf(pf);
	if (!vf || !vf->vfinfo) {
		ret = -EFAULT;
		goto free_entry;
	}
	/* pf take as vf 0, when turn on sriov */
	mutex_lock(&vf->cfg_lock);
	mce_vf_setup_vlan(pf, PFINFO_IDX, vid);
	mutex_unlock(&vf->cfg_lock);
exit:
	list_add_tail(&vlan_entry->vlan_node, &hw->vlan_list_head);
free_entry:
	clear_bit(MCE_CFG_BUSY, vsi->state);
	if (ret)
		devm_kfree(mce_hw_to_dev(hw), vlan_entry);
	return ret;
}

static struct mce_vlan_list_entry *
mce_vlan_find_entry_by_vid(struct mce_hw *hw, u16 vid)
{
	struct mce_vlan_list_entry *vlan_entry = NULL;

	list_for_each_entry(vlan_entry, &hw->vlan_list_head, vlan_node) {
		if (vid == vlan_entry->vid)
			return vlan_entry;
	}
	return NULL;
}

/**
 * mce_vlan_rx_kill_vid - Remove a VLAN ID filter from HW offload
 * @netdev: network interface to be adjusted
 * @proto: VLAN TPID
 * @vid: VLAN ID to be removed
 *
 * net_device_ops implementation for removing VLAN IDs
 */
static int mce_vlan_rx_kill_vid(struct net_device *netdev, __be16 proto,
				  u16 vid)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = NULL;
	struct mce_vlan_list_entry *vlan_entry = NULL;
	int ret = 0;

	if (!vid)
		return 0;

	while (test_and_set_bit(MCE_CFG_BUSY, vsi->state))
		usleep_range(1000, 2000);

	vlan_entry = mce_vlan_find_entry_by_vid(hw, vid);
	if (!vlan_entry) {
		ret = -EIO;
		goto err;
	}

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		hw->ops->del_vlan_filter(hw, vid);
		ret = 0;
		goto exit;
	}

	vf = mce_pf_to_vf(pf);
	if (!vf || !vf->vfinfo) {
		ret = -EIO;
		goto err;
	}
	mutex_lock(&vf->cfg_lock);
	mce_vf_del_vlan(pf, PFINFO_IDX, vid);
	mutex_unlock(&vf->cfg_lock);
exit:
	/* del vlan node */
	list_del(&vlan_entry->vlan_node);
	devm_kfree(hw->dev, vlan_entry);
err:
	clear_bit(MCE_CFG_BUSY, vsi->state);
	return ret;
}

/**
 * mce_set_mac_address - NDO callback to set MAC address
 * @netdev: network interface device structure
 * @pi: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 */
static int mce_set_mac_address(struct net_device *netdev, void *pi)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct sockaddr *addr = pi;
	int err = 0;
	u8 *mac = NULL;

	mac = (u8 *)addr->sa_data;

	if (!is_valid_ether_addr(mac))
		return -EADDRNOTAVAIL;

	if (ether_addr_equal(netdev->dev_addr, mac)) {
		netdev_dbg(netdev, "already using mac %pM\n", mac);
		return 0;
	}

	if (test_bit(MCE_DOWN, pf->state)) {
		netdev_err(netdev, "can't set mac %pM. device not ready\n",
			   mac);
		return -EBUSY;
	}
	ether_addr_copy(vf->t_info.macaddr, mac);

	err = mce_vf_set_veb_misc_rule(hw, PFINFO_IDX,
					 __VEB_POLICY_TYPE_UC_ADD_MACADDR);
	if (err) {
		netdev_err(netdev,
			   "can't set mac %pM. something error at hw\n",
			   mac);
		return -EIO;
	}

	netif_addr_lock_bh(netdev);
	/* change the netdev's MAC address */
	eth_hw_addr_set(netdev, mac);
	ether_addr_copy(vsi->port_info->addr, mac);
	netif_addr_unlock_bh(netdev);

	return 0;
}

#ifndef HAVE_NETDEV_MIN_MAX_MTU
/**
 * mce_check_mtu_valid - check if specified MTU can be set for a netdev
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 if MTU is valid, negative otherwise
 */
static int mce_check_mtu_valid(struct net_device *netdev, int new_mtu)
{
#ifdef HAVE_NETDEV_EXTENDED_MIN_MAX_MTU
	if (new_mtu < netdev->extended->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->extended->min_mtu);
		return -EINVAL;
	} else if (new_mtu > netdev->extended->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->extended->max_mtu);
		return -EINVAL;
	}
#else /* HAVE_NETDEV_EXTENDED_MIN_MAX_MTU */
	if (new_mtu < ETH_MIN_MTU) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   ETH_MIN_MTU);
		return -EINVAL;
	} else if (new_mtu > MCE_FPGA_MAX_MTU) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   MCE_FPGA_MAX_MTU);
		return -EINVAL;
	}
#endif /* HAVE_NETDEV_EXTENDED_MIN_MAX_MTU */

	return 0;
}
#endif /* !HAVE_NETDEV_MIN_MAX_MTU */

/**
 * mce_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int mce_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	int err = 0;

	if (new_mtu == (int)netdev->mtu) {
		netdev_warn(netdev, "MTU is already %u\n", netdev->mtu);
		return 0;
	}

#ifndef HAVE_NETDEV_MIN_MAX_MTU
	err = mce_check_mtu_valid(netdev, new_mtu);
	if (err)
		return err;
#endif /* !HAVE_NETDEV_MIN_MAX_MTU */

	netdev->mtu = (unsigned int)new_mtu;

	/* if VSI is up, bring it down and then back up */
	if (!test_and_set_bit(MCE_VSI_DOWN, vsi->state)) {
		err = mce_down(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_down err %d\n",
				   err);
			return err;
		}

		err = mce_up(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_up err %d\n",
				   err);
			return err;
		}
	}

	netdev_dbg(netdev, "changed MTU to %d\n", new_mtu);
	set_bit(MCE_FLAG_MTU_CHANGED, pf->flags);

	return 0;
}

#ifdef HAVE_NDO_SET_TX_MAXRATE

static int map_to_real_queue(struct mce_pf *pf, int q)
{
	u16 q_base_dcb_r = 0;
	int q_id_rx = 0;
	int i;
	int q_cnt = pf->max_pf_rxqs;
	int step = pf->max_pf_rxqs / pf->num_max_tc;
	int ret;

	for (i = 0; i <= q; i++) {
		ret = q_id_rx;

		q_id_rx = q_id_rx + step;	
		if (q_id_rx >= q_cnt) {
			q_base_dcb_r++; 
			q_id_rx = q_base_dcb_r;
		}
	}

	return ret;
}
/**
 * mce_set_tx_maxrate - NDO callback to set the maximum per-queue bitrate
 * @netdev: network interface device structure
 * @queue_index: Queue ID
 * @maxrate: maximum bandwidth in Mbps
 */
static int mce_set_tx_maxrate(struct net_device *netdev, int queue_index,
				u32 maxrate)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	struct mce_ring *tx_ring = vsi->tx_rings[queue_index];
	int status = 0;
	struct mce_dcb *dcb = pf->dcb;
	int real_queue = 0;

	// if dcb on should skip tc
	if (test_bit(MCE_DCB_EN, dcb->flags)) {
		real_queue = map_to_real_queue(pf, queue_index);
		//printk("map to real queue %d\n", queue_offset);
		tx_ring = vsi->tx_rings[real_queue];
		//return 0;
	}

	/* Validate maxrate requested is within permitted range */
	if (maxrate && (maxrate > (MCE_SCHED_MAX_BW / 1000))) {
		netdev_err(
			netdev,
			"Invalid max rate %d specified for the queue %d\n",
			maxrate, queue_index);
		return -EINVAL;
	}

	if (maxrate && (maxrate < 10)) {
		netdev_err(
			netdev,
			"Invalid max rate %d specified for the queue %d\n",
			maxrate, queue_index);
		return -EINVAL;
	}

	if (netif_msg_drv(pf))
		netdev_info(netdev, "tx queue %u set maxrate %uMb\n",
			    queue_index, maxrate);

	/* Set BW back to default, when user set maxrate to 0 */
	if (!maxrate)
		status = hw->ops->cfg_txring_bw_lmt(tx_ring, 0);
	else
		status = hw->ops->cfg_txring_bw_lmt(tx_ring, maxrate);
	if (status)
		netdev_err(netdev, "Unable to set Tx max rate, error %d\n",
			   status);

	return status;
}
#endif /* HAVE_NDO_SET_TX_MAXRATE */

/**
 * mce_find_tnl - return -1 mean not match ; return 0 ~ 7 mean matched
 * @hw: pointer to PF struct
 * @tnl_type: tunnel type
 * @port: tunnel port
 */
static int mce_find_tnl(struct mce_hw *hw,
			  enum mce_tunnel_type tnl_type, u16 port)
{
	struct mce_tunnel_entry *tnl_entry;
	int ret = -1;
	u16 i = 0;

	if (tnl_type >= TNL_LAST) {
		dev_err(hw->dev, "Unknown  tunnel type\n");
		return ret;
	}

	for (i = 0; i < MCE_TUNNEL_MAX_ENTRIES; i++) {
		tnl_entry = &(hw->tnl[tnl_type].tbl[i]);
		if (tnl_entry->in_use == false)
			continue;

		if (tnl_entry->port == port) {
			ret = i;
			break;
		}
	}

	return ret;
}

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
static int mce_udp_tunnel_add(struct net_device *netdev,
				unsigned int table, unsigned int idx,
				struct udp_tunnel_info *ti);
static int mce_udp_tunnel_del(struct net_device *netdev,
				unsigned int table, unsigned int idx,
				struct udp_tunnel_info *ti);

void mce_udp_tunnel_prepare(struct mce_pf *pf)
{
	int i = 0;

	pf->udp_tunnel_nic.set_port = mce_udp_tunnel_add;
	pf->udp_tunnel_nic.unset_port = mce_udp_tunnel_del;
	pf->udp_tunnel_nic.flags = UDP_TUNNEL_NIC_INFO_MAY_SLEEP;
#ifdef HAVE_UDP_TUNNEL_NIC_SHARED
	pf->udp_tunnel_nic.shared = &pf->udp_tunnel_shared;
#endif /* HAVE_UDP_TUNNEL_NIC_SHARED */

	pf->udp_tunnel_nic.tables[i].n_entries = MCE_TUNNEL_MAX_ENTRIES;
	pf->udp_tunnel_nic.tables[i].tunnel_types = UDP_TUNNEL_TYPE_VXLAN;
	i++;
	pf->udp_tunnel_nic.tables[i].n_entries = MCE_TUNNEL_MAX_ENTRIES;
	pf->udp_tunnel_nic.tables[i].tunnel_types = UDP_TUNNEL_TYPE_GENEVE;
	i++;
	pf->udp_tunnel_nic.tables[i].n_entries = MCE_TUNNEL_MAX_ENTRIES;
	pf->udp_tunnel_nic.tables[i].tunnel_types = UDP_TUNNEL_TYPE_VXLAN_GPE;
}
#endif /* HAVE_UDP_TUNNEL_NIC_INFO */

#ifdef HAVE_TX_TIMEOUT_TXQUEUE
/**
 * ice_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: Tx queue
 */
static void mce_tx_timeout(struct net_device *netdev, unsigned int txqueue)
#else
static void mce_tx_timeout(struct net_device *netdev)
#endif
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);

// this should more than pfc dead lock(10s)
#define TX_TIMEO_LIMIT 16000
	printk("juest delay watchdog_timeo now %d\n", netdev->watchdog_timeo);
	if (netdev->watchdog_timeo < TX_TIMEO_LIMIT)
		netdev->watchdog_timeo *= 2;
	if (test_bit(MCE_FLAG_PF_RESET_ENA, pf->flags))
		return;
	set_bit(MCE_FLAG_PF_RESET_ENA, pf->flags);
}

#ifndef HAVE_UDP_TUNNEL_NIC_INFO
/**
 * mce_udp_tunnel_add - Get notifications about UDP tunnel ports that come up
 * @netdev: This physical port's netdev
 * @ti: Tunnel endpoint information
 */
static void __maybe_unused mce_udp_tunnel_add(struct net_device *netdev,
						struct udp_tunnel_info *ti)
#else /* !HAVE_UDP_TUNNEL_NIC_INFO */
static int mce_udp_tunnel_add(struct net_device *netdev,
				unsigned int table, unsigned int idx,
				struct udp_tunnel_info *ti)
#endif /* !HAVE_UDP_TUNNEL_NIC_INFO */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	enum mce_tunnel_type tnl_type;
	u16 port = ntohs(ti->port);
	int index = -1;

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		tnl_type = TNL_VXLAN;
		break;
	case UDP_TUNNEL_TYPE_GENEVE:
		tnl_type = TNL_GENEVE;
		break;
	case UDP_TUNNEL_TYPE_VXLAN_GPE:
		tnl_type = TNL_VXLAN_GPE;
		break;
	default:
		netdev_err(netdev, "Unknown tunnel type\n");
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
		return -EINVAL;
#else
		return;
#endif
	}

	mutex_lock(&hw->tnl_lock);
	index = mce_find_tnl(hw, tnl_type, port);
	if (index >= 0) {
		++(hw->tnl[tnl_type].tbl[index].ref_cnt);
	} else {
		if ((hw->tnl[tnl_type].tnl_cnt + 1) >
		    MCE_TUNNEL_MAX_ENTRIES) {
			netdev_err(netdev, "The number of tunnel has reached the limit\n");
			mutex_unlock(&hw->tnl_lock);
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
			return -EPERM;
#else
			return;
#endif
		} else {
			hw->ops->add_tnl(hw, tnl_type, port);
		}
	}
	mutex_unlock(&hw->tnl_lock);

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	return 0;
#endif
}

#ifndef HAVE_UDP_TUNNEL_NIC_INFO
/**
 * mce_udp_tunnel_del - Get notifications about UDP tunnel ports that go away
 * @netdev: This physical port's netdev
 * @ti: Tunnel endpoint information
 */
static void __maybe_unused mce_udp_tunnel_del(struct net_device *netdev,
						struct udp_tunnel_info *ti)
#else /* !HAVE_UDP_TUNNEL_NIC_INFO */
static int mce_udp_tunnel_del(struct net_device *netdev,
				unsigned int table, unsigned int idx,
				struct udp_tunnel_info *ti)
#endif /* HAVE_UDP_TUNNEL_NIC_INFO */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	enum mce_tunnel_type tnl_type;
	int index = -1;
	u16 port = ntohs(ti->port);
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	int ret = 0;
#endif

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		tnl_type = TNL_VXLAN;
		break;
	case UDP_TUNNEL_TYPE_GENEVE:
		tnl_type = TNL_GENEVE;
		break;
	case UDP_TUNNEL_TYPE_VXLAN_GPE:
		tnl_type = TNL_VXLAN_GPE;
		break;
	default:
		netdev_err(netdev, "Unknown tunnel type\n");
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
		return -EINVAL;
#else
		return;
#endif
	}

	mutex_lock(&hw->tnl_lock);
	index = mce_find_tnl(hw, tnl_type, port);
	if (index >= 0) {
		if ((hw->tnl[tnl_type].tbl[index].ref_cnt) > 1) {
			(hw->tnl[tnl_type].tbl[index].ref_cnt)--;
		} else {
			hw->ops->del_tnl(hw, tnl_type, port);
		}
	} else {
		netdev_err(netdev,
			   "Unable to find Tunnel, port %u, tnl_type %u\n",
			   port, tnl_type);
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
		ret = -EINVAL;
#endif
	}
	mutex_unlock(&hw->tnl_lock);

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	return ret;
#endif
}

#if defined(HAVE_VXLAN_RX_OFFLOAD) && !defined(HAVE_UDP_ENC_RX_OFFLOAD)
#if IS_ENABLED(CONFIG_VXLAN)
/**
 * mce_add_vxlan_port - Get notifications about VxLAN ports that come up
 * @netdev: This physical port's netdev
 * @sa_family: Socket Family that VxLAN is notifying us about
 * @port: New UDP port number that VxLAN started listening to
 */
static void mce_add_vxlan_port(struct net_device *netdev,
				 sa_family_t sa_family, __be16 port)
{
	struct udp_tunnel_info ti = {
		.type = UDP_TUNNEL_TYPE_VXLAN,
		.sa_family = sa_family,
		.port = port,
	};

	mce_udp_tunnel_add(netdev, &ti);
}

/**
 * mce_del_vxlan_port - Get notifications about VxLAN ports that go away
 * @netdev: This physical port's netdev
 * @sa_family: Socket Family that VxLAN is notifying us about
 * @port: UDP port number that VxLAN stopped listening to
 */
static void mce_del_vxlan_port(struct net_device *netdev,
				 sa_family_t sa_family, __be16 port)
{
	struct udp_tunnel_info ti = {
		.type = UDP_TUNNEL_TYPE_VXLAN,
		.sa_family = sa_family,
		.port = port,
	};

	mce_udp_tunnel_del(netdev, &ti);
}
#endif /* CONFIG_VXLAN */
#endif /* HAVE_VXLAN_RX_OFFLOAD && !HAVE_UDP_ENC_RX_OFFLOAD */

#if defined(HAVE_GENEVE_RX_OFFLOAD) && !defined(HAVE_UDP_ENC_RX_OFFLOAD)
#if IS_ENABLED(CONFIG_GENEVE)
/**
 * mce_add_geneve_port - Get notifications about GENEVE ports that come up
 * @netdev: This physical port's netdev
 * @sa_family: Socket Family that GENEVE is notifying us about
 * @port: New UDP port number that GENEVE started listening to
 */
static void mce_add_geneve_port(struct net_device *netdev,
				  sa_family_t sa_family, __be16 port)
{
	struct udp_tunnel_info ti = {
		.type = UDP_TUNNEL_TYPE_GENEVE,
		.sa_family = sa_family,
		.port = port,
	};

	mce_udp_tunnel_add(netdev, &ti);
}

/**
 * mce_del_geneve_port - Get notifications about GENEVE ports that go away
 * @netdev: This physical port's netdev
 * @sa_family: Socket Family that GENEVE is notifying us about
 * @port: UDP port number that GENEVE stopped listening to
 */
static void mce_del_geneve_port(struct net_device *netdev,
				  sa_family_t sa_family, __be16 port)
{
	struct udp_tunnel_info ti = {
		.type = UDP_TUNNEL_TYPE_GENEVE,
		.sa_family = sa_family,
		.port = port,
	};

	mce_udp_tunnel_del(netdev, &ti);
}

#endif /* CONFIG_GENEVE */
#endif /* HAVE_GENEVE_RX_OFFLOAD  && !HAVE_UDP_ENC_RX_OFFLOAD */

#ifdef HAVE_TC_SETUP_CLSFLOWER

/**
 * mce_setup_tc_cls_flower - flower classifier offloads
 * @np: net device to configure
 * @filter_dev: device on which filter is added
 * @cls_flower: offload data
 */
#ifdef HAVE_TC_INDIR_BLOCK
static int
mce_setup_tc_cls_flower(struct mce_netdev_priv *np,
			struct net_device *filter_dev,
			struct flow_cls_offload *cls_flower)
#else
static int
mce_setup_tc_cls_flower(struct mce_netdev_priv *np,
			struct net_device __always_unused *filter_dev,
			struct tc_cls_flower_offload *cls_flower)
#endif /* HAVE_TC_INDIR_BLOCK */
{
	struct mce_vsi *vsi = np->vsi;

#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
	if (cls_flower->common.chain_index)
		return -EOPNOTSUPP;
#endif /* HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV */

	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return mce_add_cls_flower(filter_dev, vsi, cls_flower);
	case FLOW_CLS_DESTROY:
		return mce_del_cls_flower(vsi, cls_flower);
	default:
		return -EINVAL;
	}
}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/**
 * mce_setup_tc_block_cb - callback handler registered for TC block
 * @type: TC SETUP type
 * @type_data: TC flower offload data that contains user input
 * @cb_priv: netdev private data
 */
static int mce_setup_tc_block_cb(enum tc_setup_type type,
				 void *type_data, void *cb_priv)
{
	struct mce_netdev_priv *np = cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return mce_setup_tc_cls_flower(np, np->vsi->netdev,
					       type_data);
	default:
		return -EOPNOTSUPP;
	}
}
#endif

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
static int mce_setup_tc_mqprio_dcb(struct mce_vsi *vsi,
				     void *type_data)
{
	// struct tc_mqprio_qopt_offload *mqprio = type_data;
	// struct tc_mqprio_qopt *mqopt = &mqprio->qopt;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_tc_cfg *new_tccfg = NULL;
	struct mce_tc_cfg *cur_tccfg = NULL;

	mutex_lock(&(dcb->dcb_mutex));

	new_tccfg = &(dcb->new_tccfg);
	cur_tccfg = &(dcb->cur_tccfg);

	mce_dcb_tc_default(new_tccfg);

	memcpy(cur_tccfg, new_tccfg, sizeof(dcb->cur_tccfg));

	clear_bit(MCE_MQPRIO_CHANNEL, dcb->flags);

	hw->ops->disable_tc(hw);
	hw->ops->clr_q_to_tc(hw);

	mce_vsi_cfg_netdev_tc(vsi, dcb);

	mutex_unlock(&(dcb->dcb_mutex));

	return 0;
}

static int mce_setup_tc_mqprio_channel(struct mce_vsi *vsi,
				       void *type_data)
{
	struct tc_mqprio_qopt_offload *mqprio = type_data;
	struct tc_mqprio_qopt *mqopt = &mqprio->qopt;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_tc_cfg *new_tccfg = NULL;
	struct mce_tc_cfg *cur_tccfg = NULL;
	u16 need_tcs = 0;
	u16 qcnt_rem = 0;
	u16 qcnt_tal = 0;
	u8 i = 0, j = 0, k = 0;

	if (!test_bit(MCE_DCB_EN, dcb->flags)) {
		netdev_err(vsi->netdev,
			   "TC_MQPRIO_MODE_DCB not supported, "
			   "hw dcb is not enable, Ensure that "
			   "the number of tx queues is sufficient.\n");
		return -EOPNOTSUPP;
	}

	if (test_bit(MCE_ETS_EN, dcb->flags)) {
		netdev_err(vsi->netdev,
			   "TC_MQPRIO_MODE_DCB not supported, "
			   "ETS has been enabled by netlink.\n");
		return -EOPNOTSUPP;
	}

	if (mqopt->num_tc > MCE_MAX_TC_CNT) {
		netdev_err(vsi->netdev,
			   "TC_MQPRIO_MODE_DCB not supported, "
			   "the number of tcs out of range.\n");
		return -EOPNOTSUPP;
	}

	if (vsi->num_txq < MCE_MAX_PRIORITY) {
		netdev_err(vsi->netdev,
			   "TC_MQPRIO_MODE_DCB not supported, "
			   "The number of tx queues must be "
			   "greater than or equal to 8.\n");
		return -EOPNOTSUPP;
	}

	mutex_lock(&(dcb->dcb_mutex));

	new_tccfg = &(dcb->new_tccfg);
	cur_tccfg = &(dcb->cur_tccfg);

	mce_dcb_tc_default(new_tccfg);
	new_tccfg->tc_cnt = mqopt->num_tc;
	new_tccfg->qg_cnt = mqopt->num_tc;

	for (i = 0; i < mqopt->num_tc; i++)
		new_tccfg->tc_qgs[i] = 1;

	for (i = 0; i < mqopt->num_tc; i++)
		qcnt_rem += mqopt->count[i];
	need_tcs = (u16)DIV_ROUND_UP(qcnt_rem, MCE_MAX_QCNT_IN_QG);
	if (need_tcs != mqopt->num_tc) {
		netdev_err(vsi->netdev,
			   "TC_MQPRIO_MODE_DCB not supported, "
			   "The number of tx queues must be four "
			   "times the number of TCS.\n");
		return -EINVAL;
	}

	qcnt_tal = qcnt_rem;

	for (i = 0; i < mqopt->num_tc; i++) {
		u16 qcnt_per_qg = 0;
		qcnt_per_qg =
			(u16)DIV_ROUND_UP(qcnt_rem, (mqopt->num_tc - i));

		new_tccfg->qg_qs[i] = qcnt_per_qg;
		qcnt_rem -= qcnt_per_qg;
	}
	if (qcnt_rem > 0) {
		netdev_err(vsi->netdev,
			   "TC_MQPRIO_MODE_DCB not supported, "
			   "The number of tx queues is incorrect.\n");
		return -EINVAL;
	}

	for (i = 0; i < mqopt->num_tc; i++) {
		u32 min_rate = (mqprio->min_rate[i] * 8 / 1000000);
		u32 max_rate = (mqprio->max_rate[i] * 8 / 1000000);

		if (min_rate > max_rate) {
			netdev_err(
				vsi->netdev,
				"min rate cannot be greater than max rate\n");
			return -EINVAL;
		}

		new_tccfg->min_rate[i] = min_rate;
		new_tccfg->max_rate[i] = max_rate;
	}

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		u8 t = mqopt->prio_tc_map[i];

		new_tccfg->prio_tc[i] = t;
		new_tccfg->tc_prios_cnt[t]++;
		if (new_tccfg->tc_prios_cnt[t] > 4) {
			netdev_err(
				vsi->netdev,
				"A tc cannot have more than four priorities\n");
			return -EINVAL;
		}
	}

	qcnt_rem = qcnt_tal;
	k = 0;
	for (i = 0; i < mqopt->num_tc; i++) {
		u16 qcnt_per_prio = 0;
		u16 qcnt_in_qg = new_tccfg->qg_qs[i];
		u16 pcnt_in_tc = new_tccfg->tc_prios_cnt[i];

		for (j = 0; j < pcnt_in_tc; j++) {
			qcnt_per_prio = (u16)DIV_ROUND_UP(
				qcnt_in_qg, (pcnt_in_tc - j));

			new_tccfg->ntc_txq_base[k] = qcnt_tal - qcnt_rem;
			new_tccfg->ntc_txq_cunt[k] = qcnt_per_prio;
			qcnt_rem -= qcnt_per_prio;
			qcnt_in_qg -= qcnt_per_prio;

			new_tccfg->prio_ntc[k] = k;
			k++;
		}
	}
	new_tccfg->ntc_cnt = k;

	memcpy(cur_tccfg, new_tccfg, sizeof(dcb->cur_tccfg));

	mqopt->hw = TC_MQPRIO_HW_OFFLOAD_TCS;

	hw->ops->set_qg_rate(hw, dcb);
	hw->ops->set_qg_ctrl(hw, dcb);
	hw->ops->set_q_to_tc(hw, dcb);
	hw->ops->enable_tc(hw, dcb);

	mce_vsi_cfg_netdev_tc(vsi, dcb);

	set_bit(MCE_MQPRIO_CHANNEL, dcb->flags);

	mutex_unlock(&(dcb->dcb_mutex));
	return 0;
}

static int mce_setup_tc_mqprio(struct mce_netdev_priv *np,
			       void *type_data)
{
	struct tc_mqprio_qopt_offload *mqprio = type_data;
	struct mce_vsi *vsi = np->vsi;

	if (vsi->num_txq % MCE_MAX_TC_CNT != 0) {
		netdev_err(vsi->netdev,
			   "tx ring count is not "
			   " a multiple of %u\n",
			   MCE_MAX_TC_CNT);
		return -EOPNOTSUPP;
	}

	switch (mqprio->mode) {
	case TC_MQPRIO_MODE_DCB:
		return mce_setup_tc_mqprio_dcb(vsi, type_data);
	case TC_MQPRIO_MODE_CHANNEL:
		return mce_setup_tc_mqprio_channel(vsi, type_data);
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
static LIST_HEAD(mce_block_cb_list);
#endif

static int
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
mce_setup_tc(struct net_device *netdev, enum tc_setup_type type,
	       void *type_data)
#elif defined(HAVE_NDO_SETUP_TC_CHAIN_INDEX)
mce_setup_tc(struct net_device *netdev, u32 __always_unused handle,
	       u32 __always_unused chain_index, __be16 proto,
	       struct tc_to_netdev *tc)
#else
mce_setup_tc(struct net_device *netdev, u32 __always_unused handle,
	       __be16 __always_unused proto, struct tc_to_netdev *tc)
#endif
{
#ifndef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
	struct tc_cls_flower_offload *cls_flower = tc->cls_flower;
	unsigned int type = tc->type;
#elif !defined(HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO)
	struct tc_cls_flower_offload *cls_flower = type_data;
#endif /* HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV */
	struct mce_netdev_priv *np = netdev_priv(netdev);
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	int err = 0;

	switch (type) {
	case TC_SETUP_QDISC_MQPRIO:
		err = mce_setup_tc_mqprio(np, type_data);
		return err;
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple(type_data,
						  &mce_block_cb_list,
						  mce_setup_tc_block_cb,
						  np, np, true);
	default:
		return -EOPNOTSUPP;
	}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
	return -EOPNOTSUPP;
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

/**
 * mce_get_dscp_up - return the UP/TC value for a SKB
 * @dcbcfg: DCB config that contains DSCP to UP/TC mapping
 * @skb: SKB to query for info to determine UP/TC
 *
 * This function is to only be called when the PF is in L3 DSCP PFC mode
 */
static u8 mce_get_dscp_up(struct mce_dcb *dcb, struct sk_buff *skb)
{
	u8 dscp = 0;

	if (skb->protocol == htons(ETH_P_IP))
		dscp = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	return dcb->dscp_map[dscp];
}

#ifndef HAVE_NDO_SELECT_QUEUE_SB_DEV
#if defined(HAVE_NDO_SELECT_QUEUE_ACCEL) || \
	defined(HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK)
#ifndef HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED
static u16
mce_select_queue(struct net_device *netdev, struct sk_buff *skb,
		   void __always_unused *accel_priv,
		   select_queue_fallback_t fallback)
#else /* HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED */
static u16
mce_select_queue(struct net_device *netdev, struct sk_buff *skb,
		   void __always_unused *accel_priv);
#endif /* HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED */
#else /* HAVE_NDO_SELECT_QUEUE_ACCEL || HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK */
static u16 mce_select_queue(struct net_device *netdev, struct sk_buff *skb)
#endif /*HAVE_NDO_SELECT_QUEUE_ACCEL || HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK */
#else /* HAVE_NDO_SELECT_QUEUE_SB_DEV */
#ifdef HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED
static u16
mce_select_queue(struct net_device *netdev, struct sk_buff *skb,
		 struct net_device *sb_dev)
#else /* HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED */
static u16
mce_select_queue(struct net_device *netdev, struct sk_buff *skb,
		   struct net_device *sb_dev,  select_queue_fallback_t fallback)
#endif /* HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED */
#endif /* HAVE_NDO_SELECT_QUEUE_SB_DEV */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = &(dcb->cur_etscfg);
	u16 queue;
	int tc = 0;
	u16 queue_offset = 0;
	struct mce_tc_cfg *tccfg = &(dcb->cur_tccfg);
#if MCE_SELECT_QUEUE_DEBUG
	static int e_id = 0, s_id = 0, step, q_id;

	if (pf->d_txqueue.en && pf->d_txqueue.permit) {
		s_id = pf->d_txqueue.s_id;
		e_id = pf->d_txqueue.e_id;
		step = e_id - s_id + 1;
#if defined(HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED)
		q_id = netdev_pick_tx(netdev, skb, sb_dev);
#elif defined(HAVE_NDO_SELECT_QUEUE_SB_DEV)
		q_id = fallback(netdev, skb, sb_dev);
#elif defined(HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK)
		q_id = fallback(netdev, skb);
#else
		q_id = __netdev_pick_tx(netdev, skb);
#endif
		q_id = q_id % step + s_id;
		pf->d_txqueue.r_id = q_id;
		return q_id;
	}
#endif
	if (test_bit(MCE_DSCP_EN, dcb->flags)) {
		skb->priority = mce_get_dscp_up(dcb, skb);
	} else {
		if (skb_vlan_tag_present(skb)) {
			skb->priority = (skb_vlan_tag_get(skb) >> 13 ) & 0x7;
		} else if (__VLAN_ALLOWED(skb->protocol)) {
			struct vlan_hdr *vhdr, _vhdr;

			vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr),
					&_vhdr);
			if (!vhdr)
				goto skip_prio;

			skb->priority = (ntohs(vhdr->h_vlan_TCI) >> 13 ) & 0x7;
		}
		// no vlan packet use stack prio
	}
skip_prio:
	/* if prio is not valid for this nic, use a valid one */
	// only do this if ets or pfc on
	if (test_bit(MCE_ETS_EN, dcb->flags) || test_bit(MCE_PFC_EN, dcb->flags)) {
		if (!(vsi->valid_prio & (1 << skb->priority))) {
			//printk("prio %d is not valid for nic\n", skb->priority);
			skb->priority = ffs(vsi->valid_prio) - 1;
			//printk("use new priority %d\n", skb->priority);
		}
	}
	/* should check nic valid prio */
#if defined(HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED)
	queue = netdev_pick_tx(netdev, skb, sb_dev);
#elif defined(HAVE_NDO_SELECT_QUEUE_SB_DEV)
	queue = fallback(netdev, skb, sb_dev);
#elif defined(HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK)
	queue = fallback(netdev, skb);
#else
	queue = __netdev_pick_tx(netdev, skb);
#endif
	

	// if ets on, we change tc, and queue_offset
	if (test_bit(MCE_ETS_EN, dcb->flags)) {
		tc = etscfg->prio_table[skb->priority & TC_BITMASK];
		/* if ets on, we should offset queue */
		queue_offset = tc * vsi->num_txq_real;
	}

	// if pfc on, we use pfx_txq_base and pfc_txq_count
	if (test_bit(MCE_PFC_EN, dcb->flags)) {
		if (tccfg->pfc_txq_count[tc][skb->priority])
			queue = (tccfg->pfc_txq_base[tc][skb->priority] + (queue % tccfg->pfc_txq_count[tc][skb->priority]));
		else {
			printk("%d txq_count error %d\n", tc, tccfg->pfc_txq_count[tc][skb->priority]);

			queue = 0;
		}
	}

	// if dcb on, queue should only in tc range
	if (test_bit(MCE_DCB_EN, dcb->flags)) {
		queue = queue % vsi->num_txq_real;
	}
	// try to offset queue
	queue = queue_offset + queue;
	
	return queue;
}

#ifdef HAVE_NDO_FEATURES_CHECK
#define MCE_TXD_CTX_MIN_MSS (64)
#define MCE_MAX_TUNNEL_HDR_LEN 80
#define MCE_MAX_MAC_HDR_LEN (127)
#define MCE_MAX_NETWORK_HDR_LEN (511)
/**
 * mce_features_check - Validate encapsulated packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t
mce_features_check(struct sk_buff *skb,
		     struct net_device __always_unused *netdev,
		     netdev_features_t features)
{
	bool gso = skb_is_gso(skb);
	size_t len;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame. We can rule out both by just
	 * checking for CHECKSUM_PARTIAL
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 64 bytes. If it is then we need to drop support for GSO.
	 */
	if (gso && (skb_shinfo(skb)->gso_size < MCE_TXD_CTX_MIN_MSS))
		features &= ~NETIF_F_GSO_MASK;

	len = skb_network_offset(skb);
	if (len > MCE_MAX_MAC_HDR_LEN)
		goto out_rm_features;

	len = skb_network_header_len(skb);
	if (len > MCE_MAX_NETWORK_HDR_LEN)
		goto out_rm_features;

	if (skb->encapsulation) {
		/* this must work for VXLAN frames AND IPIP/SIT frames, and in
		 * the case of IPIP frames, the transport header pointer is
		 * after the inner header! So check to make sure that this
		 * is a GRE or UDP_TUNNEL frame before doing that math.
		 */
		if (gso && (skb_shinfo(skb)->gso_type &
			    (SKB_GSO_GRE | SKB_GSO_UDP_TUNNEL))) {
			len = skb_inner_mac_header(skb) -
			      skb_transport_header(skb);
			if (len > MCE_MAX_TUNNEL_HDR_LEN)
				goto out_rm_features;
		}

		len = skb_inner_network_header_len(skb);
		if (len > MCE_MAX_NETWORK_HDR_LEN)
			goto out_rm_features;
	}

	return features;
out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}
#endif /* HAVE_NDO_FEATURES_CHECK */

static const struct net_device_ops mce_netdev_ops = {
	.ndo_open = mce_open,
	.ndo_stop = mce_stop,
	.ndo_start_xmit = mce_start_xmit,
	.ndo_get_stats64 = mce_get_stats64,
	.ndo_set_features = mce_set_features,
	.ndo_set_rx_mode = mce_set_rx_mode,
#ifdef HAVE_NDO_ETH_IOCTL
        .ndo_eth_ioctl = mce_ioctl,
#else
        .ndo_do_ioctl = mce_ioctl,
#endif /* HAVE_NDO_ETH_IOCTL */
	.ndo_vlan_rx_add_vid = mce_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = mce_vlan_rx_kill_vid,
#ifdef HAVE_NDO_FEATURES_CHECK
	.ndo_features_check = mce_features_check,
#endif
#ifdef HAVE_NETDEV_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = mce_change_mtu,
#else
	.ndo_change_mtu = mce_change_mtu,
#endif /* HAVE_NETDEV_EXTENDED_MIN_MAX_MTU */
#ifdef HAVE_NDO_SET_TX_MAXRATE
#ifdef HAVE_NDO_EXTENDED_SET_TX_MAXRATE
	.extended.ndo_set_tx_maxrate = mce_set_tx_maxrate,
#else
	.ndo_set_tx_maxrate = mce_set_tx_maxrate,
#endif /* HAVE_NDO_EXTENDED_SET_TX_MAXRATE */
#endif /* HAVE_NDO_SET_TX_MAXRATE */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_UDP_TUNNEL
	.extended.ndo_udp_tunnel_add = mce_udp_tunnel_add,
	.extended.ndo_udp_tunnel_del = mce_udp_tunnel_del,
#else
#ifndef HAVE_UDP_TUNNEL_NIC_INFO
	.ndo_udp_tunnel_add = mce_udp_tunnel_add,
	.ndo_udp_tunnel_del = mce_udp_tunnel_del,
#else
#ifdef HAVE_NDO_UDP_TUNNEL_CALLBACK
	.ndo_udp_tunnel_add = udp_tunnel_nic_add_port,
	.ndo_udp_tunnel_del = udp_tunnel_nic_del_port,
#endif /* HAVE_NDO_UDP_TUNNEL_CALLBACK */
#endif /* !HAVE_UDP_TUNNEL_NIC_INFO */
#endif
#else /* !HAVE_UDP_ENC_RX_OFFLOAD */
#ifdef HAVE_VXLAN_RX_OFFLOAD
#if IS_ENABLED(CONFIG_VXLAN)
	.ndo_add_vxlan_port = mce_add_vxlan_port,
	.ndo_del_vxlan_port = mce_del_vxlan_port,
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD */
#ifdef HAVE_GENEVE_RX_OFFLOAD
#if IS_ENABLED(CONFIG_GENEVE)
	.ndo_add_geneve_port = mce_add_geneve_port,
	.ndo_del_geneve_port = mce_del_geneve_port,
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD */
#endif /* HAVE_UDP_ENC_RX_OFFLOAD */
	.ndo_set_mac_address = mce_set_mac_address,
	.ndo_set_vf_spoofchk = mce_set_vf_spoofchk,
#ifdef HAVE_NDO_SET_VF_TRUST
	.ndo_set_vf_mac = mce_set_vf_mac,
	.ndo_get_vf_config = mce_get_vf_cfg,
#ifdef HAVE_RHEL7_NET_DEVICE_OPS_EXT
	/* RHEL7 requires ndo_size to be defined to enable extended ops */
	.ndo_size = sizeof(const struct net_device_ops),
	.extended.ndo_set_vf_trust = mce_set_vf_trust,
#else
	.ndo_set_vf_trust = mce_set_vf_trust,
#endif /* HAVE_RHEL7_NET_DEVICE_OPS_EXT */
#endif /* HAVE_NDO_SET_VF_TRUST */

#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SET_VF_VLAN
	.extended.ndo_set_vf_vlan = mce_set_vf_port_vlan,
#else
	.ndo_set_vf_vlan = mce_set_vf_port_vlan,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SET_VF_VLAN */
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	.ndo_set_vf_rate = mce_set_vf_bw,
#else
	.ndo_set_vf_tx_rate = mce_set_vf_bw,
#endif
#ifdef HAVE_TC_SETUP_CLSFLOWER
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC
	.extended.ndo_setup_tc_rh = mce_setup_tc,
#else
	.ndo_setup_tc = mce_setup_tc,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC */
#endif /* HAVE_TC_SETUP_CLSFLOWER */
	.ndo_tx_timeout = mce_tx_timeout,
	.ndo_select_queue = mce_select_queue,
};

/**
 * mce_set_netdev_features - set features for the given netdev
 * @netdev: netdev instance
 */
static void mce_set_netdev_features(struct net_device *netdev)
{
	netdev_features_t csumo_features = 0;
	netdev_features_t vlano_features = 0;
	netdev_features_t dflt_features = 0;
	netdev_features_t tso_features = 0;
	netdev_features_t fixed_features = 0;

	dflt_features |= NETIF_F_SG;
	dflt_features |= NETIF_F_HIGHDMA;
	dflt_features |= NETIF_F_NTUPLE;
	dflt_features |= NETIF_F_RXHASH;
#ifdef NETIF_F_HW_TC
	netdev->hw_features |= NETIF_F_HW_TC;
#endif /* NETIF_F_HW_TC */

#ifdef NETIF_F_HW_CSUM
	csumo_features |= NETIF_F_HW_CSUM;
#else
	csumo_features |= NETIF_F_IP_CSUM;
	csumo_features |= NETIF_F_IPV6_CSUM;
#endif
	csumo_features |= NETIF_F_SCTP_CRC;
	csumo_features |= NETIF_F_RXCSUM;

	vlano_features |= NETIF_F_HW_VLAN_CTAG_TX;
	vlano_features |= NETIF_F_HW_VLAN_CTAG_RX;
	vlano_features |= NETIF_F_HW_VLAN_STAG_TX;
	vlano_features |= NETIF_F_HW_VLAN_STAG_RX;

	fixed_features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	fixed_features |= NETIF_F_HW_VLAN_STAG_FILTER;

	tso_features |= NETIF_F_TSO;
	tso_features |= NETIF_F_TSO_ECN;
	tso_features |= NETIF_F_TSO6;
	tso_features |= NETIF_F_GSO_GRE;
	tso_features |= NETIF_F_GSO_UDP_TUNNEL;
#ifdef NETIF_F_GSO_GRE_CSUM
	tso_features |= NETIF_F_GSO_GRE_CSUM;
	tso_features |= NETIF_F_GSO_UDP_TUNNEL_CSUM;
#endif
#ifdef NETIF_F_GSO_PARTIAL
	tso_features |= NETIF_F_GSO_PARTIAL;
#endif
#ifdef NETIF_F_GSO_IPXIP4
	tso_features |= NETIF_F_GSO_IPXIP4;
	tso_features |= NETIF_F_GSO_IPXIP6;
#else
#ifdef NETIF_F_GSO_IPIP
	tso_features |= NETIF_F_GSO_IPIP;
	tso_features |= NETIF_F_GSO_SIT;
#endif
#endif /* NETIF_F_GSO_IPXIP4 */
#ifdef NETIF_F_GSO_UDP_L4
	tso_features |= NETIF_F_GSO_UDP_L4;
#endif /* NETIF_F_GSO_UDP_L4 */

#ifndef NETIF_F_GSO_PARTIAL
	tso_features ^= NETIF_F_GSO_UDP_TUNNEL_CSUM;
#else
	netdev->gso_partial_features |= NETIF_F_GSO_UDP_TUNNEL_CSUM;
	netdev->gso_partial_features |= NETIF_F_GSO_GRE_CSUM;
	netdev->gso_partial_features |= NETIF_F_GSO_UDP_TUNNEL;
	netdev->gso_partial_features |= NETIF_F_GSO_GRE;

#endif
	/* set features that user can change */
	netdev->hw_features |= dflt_features;
	netdev->hw_features |= csumo_features;
	netdev->hw_features |= vlano_features;
	netdev->hw_features |= tso_features;

	/* enable features */
	netdev->features |= netdev->hw_features;
	netdev->features |= fixed_features;

	/* encap and VLAN devices inherit default, csumo and tso features */
	netdev->hw_enc_features |= dflt_features;
	netdev->hw_enc_features |= csumo_features;
	netdev->hw_enc_features |= tso_features;

	netdev->vlan_features |= dflt_features;
	netdev->vlan_features |= csumo_features;
	netdev->vlan_features |= tso_features;

#ifdef NETIF_F_HW_TC
	// netdev->hw_features |= NETIF_F_HW_TC;
#endif /* NETIF_F_HW_TC */
}

/**
 * mce_cfg_netdev - Allocate, configure and register a netdev
 * @vsi: the VSI associated with the new netdev
 *
 * Returns 0 on success, negative value on failure
 */
int mce_cfg_netdev(struct mce_vsi *vsi)
{
	int alloc_txq = vsi->alloc_txq;
	int alloc_rxq = vsi->alloc_rxq;
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	struct mce_pf *pf = vsi->back;
#endif
	struct mce_netdev_priv *np = NULL;
	struct net_device *netdev = NULL;

	netdev = alloc_etherdev_mqs(sizeof(*np), alloc_txq, alloc_rxq);
	if (!netdev)
		return -ENOMEM;

	set_bit(MCE_VSI_NETDEV_ALLOCD, vsi->state);
	vsi->netdev = netdev;
	np = netdev_priv(netdev);
	np->vsi = vsi;

	mce_set_netdev_features(netdev);

	netdev->netdev_ops = &mce_netdev_ops;
	mce_set_ethtool_ops(netdev);

	mce_set_dcbnl_ops(netdev);

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	netdev->udp_tunnel_nic_info = &pf->udp_tunnel_nic;
#endif

	netdev->priv_flags |= IFF_UNICAST_FLT;

	if (vsi->type == MCE_VSI_PF) {
		SET_NETDEV_DEV(netdev, mce_pf_to_dev(vsi->back));
		if (is_valid_ether_addr(vsi->port_info->perm_addr)) {
			ether_addr_copy(vsi->port_info->addr,
					vsi->port_info->perm_addr);
			eth_hw_addr_set(netdev, vsi->port_info->perm_addr);
			ether_addr_copy(netdev->perm_addr,
					vsi->port_info->perm_addr);
		} else {
			netdev_warn(netdev, "Invalid MAC address in list; "
					    "using random MAC");
			eth_hw_addr_random(netdev);
			ether_addr_copy(vsi->port_info->addr,
					netdev->dev_addr);
		}
	}

	netdev->priv_flags |= IFF_UNICAST_FLT;

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 2 * HZ;

#ifdef HAVE_NETDEV_MIN_MAX_MTU
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = MCE_FPGA_MAX_MTU;
#endif /* HAVE_NETDEV_MIN_MAX_MTU */
#ifdef HAVE_NETDEV_EXTENDED_MIN_MAX_MTU
	netdev->extended->min_mtu = ETH_MIN_MTU;
	netdev->extended->max_mtu = MCE_FPGA_MAX_MTU;
#endif /* HAVE_NETDEV_EXTENDED_MIN_MAX_MTU */

	return 0;
}

/**
 * mce_register_netdev - register netdev and devlink port
 * @pf: pointer to the PF struct
 */
int mce_register_netdev(struct mce_pf *pf)
{
	struct mce_vsi *vsi;
	int err = 0;
	vsi = mce_get_main_vsi(pf);
	if (!vsi || !vsi->netdev)
		return -EIO;

	err = register_netdev(vsi->netdev);
	if (err)
		goto err_register_netdev;

	set_bit(MCE_VSI_NETDEV_REGISTERED, vsi->state);
	netif_carrier_off(vsi->netdev);
	netif_tx_stop_all_queues(vsi->netdev);
	mce_vsi_dcb_default(vsi);

	return 0;
err_register_netdev:
	free_netdev(vsi->netdev);
	vsi->netdev = NULL;
	clear_bit(MCE_VSI_NETDEV_ALLOCD, vsi->state);
	return err;
}
