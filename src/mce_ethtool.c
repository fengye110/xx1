#include "mce.h"
#include "mce_lib.h"
#include "mce_netdev.h"
#include "mce_ethtool.h"
#include "mce_ethtool_fdir.h"
#include "mce_vf_lib.h"
#include "mce_version.h"
#include "mce_dcb.h"

static const struct mce_stats mce_gstrings_net_stats[] = {
	MCE_NETDEV_STAT("rx_packets", net_stats.rx_packets),
	MCE_NETDEV_STAT("rx_bytes", net_stats.rx_bytes),
	MCE_NETDEV_STAT("tx_packets", net_stats.tx_packets),
	MCE_NETDEV_STAT("tx_bytes", net_stats.tx_bytes),
};

#define MCE_NET_STATS_LEN ARRAY_SIZE(mce_gstrings_net_stats)

static const struct mce_stats mce_gstrings_ofld_stats[] = {
	MCE_OFLD_STAT("tx_inserted_vlan", ofld_stats.tx_inserted_vlan),
	MCE_OFLD_STAT("rx_stripped_vlan", ofld_stats.rx_stripped_vlan),
	MCE_OFLD_STAT("rx_csum_err", ofld_stats.rx_csum_err),
	MCE_OFLD_STAT("rx_csum_unnecessary",
			ofld_stats.rx_csum_unnecessary),
	MCE_OFLD_STAT("rx_csum_none", ofld_stats.rx_csum_none),
};

#define MCE_OFLD_STATS_LEN ARRAY_SIZE(mce_gstrings_ofld_stats)

static const struct mce_stats mce_gstrings_hw_stats[] = {
	MCE_HW_STAT("pause_tx",
		      stats.pause_tx),
	MCE_HW_STAT("pause_rx",
		      stats.pause_rx),
	MCE_HW_STAT("tx_vport_rdma_unicast_packets",
		      stats.tx_vport_rdma_unicast_packets),
	MCE_HW_STAT("tx_vport_rdma_unicast_bytes",
		      stats.tx_vport_rdma_unicast_bytes),
	MCE_HW_STAT("rx_vport_rdma_unicast_packets",
		      stats.rx_vport_rdma_unicast_packets),
	MCE_HW_STAT("rx_vport_rdma_unicast_bytes",
		      stats.rx_vport_rdma_unicast_bytes),
	MCE_HW_STAT("np_cnp_sent", stats.np_cnp_sent),
	MCE_HW_STAT("rp_cnp_handled", stats.rn_cnp_handled),
	MCE_HW_STAT("np_ecn_marked_roce_packets",
		      stats.np_ecn_marked_roce_packets),
	MCE_HW_STAT("rp_cnp_ignored", stats.rp_cnp_ignored),
	MCE_HW_STAT("out_of_sequence", stats.out_of_sequence),
	MCE_HW_STAT("packet_seq_err", stats.packet_seq_err),
	MCE_HW_STAT("ack_timeout_err", stats.ack_timeout_err),
};

#define MCE_HW_STATS_LEN ARRAY_SIZE(mce_gstrings_hw_stats)

static const struct mce_stats mce_gstrings_txq_stats[] = {
	MCE_QUEUE_STAT("packets", stats.pkts),
	MCE_QUEUE_STAT("bytes", stats.bytes),
	MCE_QUEUE_STAT("inserted_vlan", tx_stats.inserted_vlan),
	MCE_QUEUE_STAT("drop", tx_stats.tx_drop),
	MCE_QUEUE_STAT("pfc_count", tx_stats.tx_pfc_count),
};

#define MCE_TXQ_STATS_LEN ARRAY_SIZE(mce_gstrings_txq_stats)

static const struct mce_stats mce_gstrings_rxq_stats[] = {
	MCE_QUEUE_STAT("packets", stats.pkts),
	MCE_QUEUE_STAT("bytes", stats.bytes),
	MCE_QUEUE_STAT("stripped_vlan", rx_stats.stripped_vlan),
	MCE_QUEUE_STAT("csum_err", rx_stats.csum_err),
	MCE_QUEUE_STAT("csum_unnecessary", rx_stats.csum_unnecessary),
	MCE_QUEUE_STAT("csum_none", rx_stats.csum_none),
};

static const struct mce_ring_reg mce_gstrings_rxq_stats_1[] = {
	MCE_QUEUE_REG("rx_multicast", 0xd0, 1),
	MCE_QUEUE_REG("rx_broadcast", 0xd8, 1),
};

#define MCE_RXQ_STATS_LEN_1 ARRAY_SIZE(mce_gstrings_rxq_stats)
#define MCE_RXQ_STATS_LEN_2 ARRAY_SIZE(mce_gstrings_rxq_stats_1)
#define MCE_RXQ_STATS_LEN (ARRAY_SIZE(mce_gstrings_rxq_stats) + ARRAY_SIZE(mce_gstrings_rxq_stats_1))

static int mce_q_stats_len(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	int total_slen = 0;

	total_slen += np->vsi->num_txq * (MCE_TXQ_STATS_LEN);
	total_slen += np->vsi->num_rxq * (MCE_RXQ_STATS_LEN);

	return total_slen;
}

#define MCE_ALL_STATS_LEN(n)                        \
	(MCE_NET_STATS_LEN + MCE_OFLD_STATS_LEN + \
	 MCE_HW_STATS_LEN + mce_q_stats_len(n))

struct mce_priv_flag {
	char name[ETH_GSTRING_LEN];
	u32 bitno; /* bit position in pf->flags */
};

#define MCE_PRIV_FLAG(_name, _bitno)          \
	{                                       \
		.name = _name, .bitno = _bitno, \
	}

static const struct mce_priv_flag mce_gstrings_priv_flags[] = {
	/* allow VF can receive packets which be xmited by its self */
	MCE_PRIV_FLAG("vf_recv_xmit_by_self",
		      MCE_FLAG_VF_RECV_XMIT_BY_SELF),
	MCE_PRIV_FLAG("vf-true-promisc-support",
		      MCE_FLAG_VF_TRUE_PROMISC_ENA),
	MCE_PRIV_FLAG("vf-rqa-tcpsync-support",
		      MCE_FLAG_VF_RQA_TCPSYNC_ENA),
	MCE_PRIV_FLAG("hw_dim", MCE_FLAG_HW_DIM_ENA),
	MCE_PRIV_FLAG("sw_dim", MCE_FLAG_SW_DIM_ENA),
	MCE_PRIV_FLAG("dscp", MCE_FLAG_DSCP_ENA),
	MCE_PRIV_FLAG("ddp_extra_en", MCE_FLAG_DDP_EXTRA_ENA),
	MCE_PRIV_FLAG("evb_vepa", MCE_FLAG_EVB_VEPA_ENA),
	MCE_PRIV_FLAG("tun_out", MCE_FLAG_TUN_OUT_ENA),
	MCE_PRIV_FLAG("tx_debug", MCE_FLAG_TX_DEBUG_ENA),
	MCE_PRIV_FLAG("rx_buffer_manually", MCE_FLAG_RX_BUFFER_MANUALLY)

};
#define MCE_PRIV_FLAG_ARRAY_SIZE ARRAY_SIZE(mce_gstrings_priv_flags)


#if defined(ETHTOOL_GLINKSETTINGS) && !defined(KYLIN_V4_ETHTOOL_FIX_BOND)
static int mce_get_link_ksettings(struct net_device *netdev,
                                     struct ethtool_link_ksettings *cmd)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;

        ethtool_link_ksettings_zero_link_mode(cmd, supported);
        ethtool_link_ksettings_zero_link_mode(cmd, advertising);

#ifdef HAVE_ETHTOOL_25G_BITS
	ethtool_link_ksettings_add_link_mode(cmd, supported, 25000baseKR_Full);
	ethtool_link_ksettings_add_link_mode(cmd, supported, 25000baseSR_Full);
	ethtool_link_ksettings_add_link_mode(cmd, supported, 25000baseCR_Full);

	ethtool_link_ksettings_add_link_mode(cmd, advertising, 25000baseKR_Full);
	ethtool_link_ksettings_add_link_mode(cmd, advertising, 25000baseSR_Full);
	ethtool_link_ksettings_add_link_mode(cmd, advertising, 25000baseCR_Full);

#endif
	ethtool_link_ksettings_add_link_mode(cmd, supported, FIBRE);
	ethtool_link_ksettings_add_link_mode(cmd, advertising, FIBRE);
	cmd->base.port = PORT_FIBRE;

	if (vsi->link) {
		cmd->base.speed = SPEED_25000;
		cmd->base.duplex = DUPLEX_FULL;
	} else {
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
	}

	return 0;
}
#else
static int mce_get_settings(struct net_device *netdev,
                               struct ethtool_cmd *ecmd)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
        u32 supported_link;
        u32 advertised_link;
	
#ifdef HAVE_ETHTOOL_25G_BITS
	ecmd->supported |= ADVERTISED_2500baseX_Full;
	ecmd->advertising |= ADVERTISED_2500baseX_Full;

#endif
	ecmd->supported |= SUPPORTED_FIBRE;
	ecmd->advertising |= ADVERTISED_FIBRE;
	ecmd->port = PORT_FIBRE;

	if (vsi->link) {
		ethtool_cmd_speed_set(ecmd, SPEED_25000);	
		ecmd->duplex = DUPLEX_FULL;
	} else {
		ethtool_cmd_speed_set(ecmd, SPEED_UNKNOWN);
		ecmd->duplex = DUPLEX_UNKNOWN;
	}


	return 0;
}

#endif

static void mce_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	strscpy(drvinfo->driver, DRIVER_NAME, sizeof(drvinfo->driver));

	strscpy(drvinfo->version, DRV_VERSION, sizeof(drvinfo->version));

	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		 "dma:0x%x nic:0x%x", hw->dma_version, hw->nic_version);

	strscpy(drvinfo->bus_info, pci_name(vsi->back->pdev),
		sizeof(drvinfo->bus_info));

	drvinfo->n_stats = MCE_ALL_STATS_LEN(netdev);
}

static int mce_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return MCE_ALL_STATS_LEN(netdev);
	case ETH_SS_PRIV_FLAGS:
		return MCE_PRIV_FLAG_ARRAY_SIZE;
	default:
		return -EOPNOTSUPP;
	}
}

static void mce_get_strings(struct net_device *netdev, u32 stringset,
			      u8 *data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	u32 i = 0;
	u32 j = 0;
	u8 *p = data;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < MCE_NET_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mce_gstrings_net_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}

		for (i = 0; i < MCE_OFLD_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mce_gstrings_ofld_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}

		for (i = 0; i < MCE_HW_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 mce_gstrings_hw_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}

		mce_for_each_txq_new(vsi, i) {
			if (!vsi->tx_rings[i]->q_vector) {
				//printk("%s skip tx queue %d\n", __func__, i);
				continue;
			}

			for (j = 0; j < MCE_TXQ_STATS_LEN; j++) {
				snprintf(p, ETH_GSTRING_LEN,
					 "txq_%u_%s", i,
					 mce_gstrings_txq_stats[j]
						 .stat_string);
				p += ETH_GSTRING_LEN;
			}
		}

		mce_for_each_rxq_new(vsi, i) {
			if (!vsi->rx_rings[i]->q_vector) {
				//printk("%s skip tx queue %d\n", __func__, i);
				continue;
			}
			for (j = 0; j < MCE_RXQ_STATS_LEN_1; j++) {
				snprintf(p, ETH_GSTRING_LEN,
					 "rxq_%u_%s", i,
					 mce_gstrings_rxq_stats[j]
						 .stat_string);
				p += ETH_GSTRING_LEN;
			}
			for (j = 0; j < MCE_RXQ_STATS_LEN_2; j++) {
				snprintf(p, ETH_GSTRING_LEN,
					 "rxq_%u_%s", i,
					 mce_gstrings_rxq_stats_1[j]
						 .stat_string);
				p += ETH_GSTRING_LEN;
			}
		}
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < MCE_PRIV_FLAG_ARRAY_SIZE; i++)
			ethtool_sprintf(&p, "%s",
					mce_gstrings_priv_flags[i].name);
		break;
		break;

	default:
		break;
	}
}

static void
mce_get_ethtool_stats(struct net_device *netdev,
			struct ethtool_stats __always_unused *stats,
			u64 *data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_ring *tx_ring;
	struct mce_ring *rx_ring;
	u32 j = 0;
	u32 k = 0;
	int i = 0;
	char *p;
	u32 offset = 0;

	mce_update_vsi_ring_stats(vsi);
	mce_update_pf_stats(pf);

	for (j = 0; j < MCE_NET_STATS_LEN; j++) {
		p = (char *)vsi + mce_gstrings_net_stats[j].stat_offset;
		data[i++] = (mce_gstrings_net_stats[j].sizeof_stat ==
			     sizeof(u64)) ?
				    *(u64 *)p :
				    *(u32 *)p;
	}

	for (j = 0; j < MCE_OFLD_STATS_LEN; j++) {
		p = (char *)vsi + mce_gstrings_ofld_stats[j].stat_offset;
		data[i++] = (mce_gstrings_ofld_stats[j].sizeof_stat ==
			     sizeof(u64)) ?
				    *(u64 *)p :
				    *(u32 *)p;
	}

	for (j = 0; j < MCE_HW_STATS_LEN; j++) {
		p = (char *)pf + mce_gstrings_hw_stats[j].stat_offset;
		data[i++] = (mce_gstrings_hw_stats[j].sizeof_stat ==
			     sizeof(u64)) ?
				    *(u64 *)p :
				    *(u32 *)p;
	}

	/* populate per queue stats */
	rcu_read_lock();

	mce_for_each_txq_new(vsi, j) {
		if (!vsi->tx_rings[j]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, i);
			continue;
		}
		tx_ring = READ_ONCE(vsi->tx_rings[j]);
		if (tx_ring && tx_ring->ring_stats) {
			for (k = 0; k < MCE_TXQ_STATS_LEN; k++) {
				p = (char *)(tx_ring->ring_stats) +
				    mce_gstrings_txq_stats[k].stat_offset;
				data[i++] = (mce_gstrings_txq_stats[k]
						     .sizeof_stat ==
					     sizeof(u64)) ?
						    *(u64 *)p :
						    *(u32 *)p;
			}
		} else {
			for (k = 0; k < MCE_TXQ_STATS_LEN; k++) {
				data[i++] = 0;
			}
		}
	}

	mce_for_each_rxq_new(vsi, j) {
		if (!vsi->rx_rings[j]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, i);
			continue;
		}
		rx_ring = READ_ONCE(vsi->rx_rings[j]);
		if (rx_ring && rx_ring->ring_stats) {
			for (k = 0; k < MCE_RXQ_STATS_LEN_1; k++) {
				p = (char *)(rx_ring->ring_stats) +
				    mce_gstrings_rxq_stats[k].stat_offset;
				data[i++] = (mce_gstrings_rxq_stats[k]
						     .sizeof_stat ==
					     sizeof(u64)) ?
						    *(u64 *)p :
						    *(u32 *)p;
			}
			for (k = 0; k < MCE_RXQ_STATS_LEN_2; k++) {
				offset = mce_gstrings_rxq_stats_1[k].reg;
				if (mce_gstrings_rxq_stats_1[k].isu64)
					data[i++] = ring_rd64(rx_ring, offset);	
				else
					data[i++] = ring_rd32(rx_ring, offset);	
			}
			// add for hw stats per ring
		} else {
			for (k = 0; k < MCE_RXQ_STATS_LEN; k++) {
				data[i++] = 0;
			}
		}
	}

	rcu_read_unlock();
}

/**
 * mce_get_priv_flags - report device private flags
 * @netdev: network interface device structure
 *
 * The get string set count and the string set should be matched for each
 * flag returned. Add new strings for each flag to the mce_gstrings_priv_flags
 * array.
 *
 * Returns a u32 bitmap of flags.
 */
static u32 mce_get_priv_flags(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	u32 i, ret_flags = 0;

	for (i = 0; i < MCE_PRIV_FLAG_ARRAY_SIZE; i++) {
		const struct mce_priv_flag *priv_flag;

		priv_flag = &mce_gstrings_priv_flags[i];

		if (test_bit(priv_flag->bitno, pf->flags))
			ret_flags |= BIT(i);
	}

	return ret_flags;
}

/**
 * mce_set_priv_flags - set private flags
 * @netdev: network interface device structure
 * @flags: bit flags to be set
 */
static int mce_set_priv_flags(struct net_device *netdev, u32 flags)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	DECLARE_BITMAP(orig_flags, MCE_PF_FLAGS_NBITS);
	DECLARE_BITMAP(change_flags, MCE_PF_FLAGS_NBITS);
	u32 i;
	bool on;

	if (flags > BIT(MCE_PRIV_FLAG_ARRAY_SIZE))
		return -EINVAL;

	bitmap_copy(orig_flags, pf->flags, MCE_PF_FLAGS_NBITS);

	// set new priv to pf->flags
	for (i = 0; i < MCE_PRIV_FLAG_ARRAY_SIZE; i++) {
		const struct mce_priv_flag *priv_flag;

		priv_flag = &mce_gstrings_priv_flags[i];

		if (flags & BIT(i))
			set_bit(priv_flag->bitno, pf->flags);
		else
			clear_bit(priv_flag->bitno, pf->flags);
	}
	bitmap_xor(change_flags, pf->flags, orig_flags,
		   MCE_PF_FLAGS_NBITS);

	if (test_bit(MCE_FLAG_VF_RECV_XMIT_BY_SELF, change_flags)) {
		on = !!test_bit(MCE_FLAG_VF_RECV_XMIT_BY_SELF,
				pf->flags);
		hw->vf.ops->set_vf_recv_ximit_by_self(hw, on);
	}

	if (test_bit(MCE_FLAG_VF_TRUE_PROMISC_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags);
		if (on)
			mce_vf_setup_true_promisc(pf);
		else
			mce_vf_del_true_promisc(pf);
	}

	if (test_bit(MCE_FLAG_VF_RQA_TCPSYNC_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_VF_RQA_TCPSYNC_ENA, pf->flags);
		mce_vf_setup_rqa_tcp_sync_en(pf, on);
	}

	if (test_bit(MCE_FLAG_HW_DIM_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);
		// if hw on, must close sw_dim
		if (on)
			clear_bit(MCE_FLAG_SW_DIM_ENA, pf->flags);
			
		mce_for_each_txq_new(vsi, i) {
			struct mce_ring *txring = vsi->tx_rings[i];
			if (!txring->q_vector) {
				//printk("%s skip tx queue %d\n", __func__, i);
				continue;
			}
			hw->ops->set_txring_hw_dim(txring, on);
			if (on)
				txring->q_vector->tx.dim_params.mode = ITR_HW_DYNAMIC;
			else {
				if (test_bit(MCE_FLAG_SW_DIM_ENA, pf->flags))
					txring->q_vector->tx.dim_params.mode = ITR_SW_DYNAMIC;
				else
					txring->q_vector->tx.dim_params.mode = ITR_STATIC;
			}
		}
		mce_for_each_rxq_new(vsi, i) {
			struct mce_ring *rxring = vsi->rx_rings[i];
			if (!rxring->q_vector)
				continue;
			hw->ops->set_rxring_hw_dim(rxring, on);
			if (on)
				rxring->q_vector->rx.dim_params.mode = ITR_HW_DYNAMIC;
			else {
				if (test_bit(MCE_FLAG_SW_DIM_ENA, pf->flags))
					rxring->q_vector->rx.dim_params.mode = ITR_SW_DYNAMIC;
				else
					rxring->q_vector->rx.dim_params.mode = ITR_STATIC;
			}
		}
		
	}

	if (test_bit(MCE_FLAG_SW_DIM_ENA, change_flags)) {
		bool on_hw;

		on = !!test_bit(MCE_FLAG_SW_DIM_ENA, pf->flags);

		// if sw_dim on, force close hw_dim
		if (on)
			clear_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);

		on_hw = !!test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags);

		mce_for_each_txq_new(vsi, i) {
			struct mce_ring *txring = vsi->tx_rings[i];

			if (!txring->q_vector) {
				//printk("%s skip tx queue %d\n", __func__, i);
				continue;
			}

			hw->ops->set_txring_hw_dim(txring, on_hw);

			if (on) 
				txring->q_vector->tx.dim_params.mode = ITR_SW_DYNAMIC;
			else
				txring->q_vector->tx.dim_params.mode = ITR_STATIC;

		}

		mce_for_each_rxq_new(vsi, i) {
			struct mce_ring *rxring = vsi->rx_rings[i];

			if (!rxring->q_vector) {
				//printk("%s skip tx queue %d\n", __func__, i);
				continue;
			}
			hw->ops->set_rxring_hw_dim(rxring, on_hw);
			if (on)
				rxring->q_vector->rx.dim_params.mode = ITR_SW_DYNAMIC;
			else
				rxring->q_vector->rx.dim_params.mode = ITR_STATIC;
		}
	}


	if (test_bit(MCE_FLAG_DSCP_ENA, change_flags)) {
		//struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
		//struct iidc_qos_params *qos_info = &cdev_info->qos_info;
		struct iidc_event *event;

		on = !!test_bit(MCE_FLAG_DSCP_ENA, pf->flags);
		if (on) {
			set_bit(MCE_DSCP_EN, pf->dcb->flags);
			//qos_info->map_mode = IIDC_DSCP_PFC_MODE;
		} else {
			clear_bit(MCE_DSCP_EN, pf->dcb->flags);
			//qos_info->map_mode = IIDC_VLAN_PFC_MODE;
		}
		// if change mode should echo to mrdma?

		hw->ops->set_dscp(hw, pf->dcb);
		event = kzalloc(sizeof(*event), GFP_KERNEL);
		set_bit(IIDC_EVENT_PRIO_MODE_CHNG, event->type);
		mce_send_event_to_auxs(pf, event);
		kfree(event);
	}

	if (test_bit(MCE_FLAG_DDP_EXTRA_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_DDP_EXTRA_ENA, pf->flags);
		hw->ops->set_ddp_extra_en(hw, on);
	}

	if (test_bit(MCE_FLAG_EVB_VEPA_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags);
		if (on)
			hw->ops->set_evb_mode(hw, MCE_EVB_VEPA);
		else
			hw->ops->set_evb_mode(hw, MCE_EVB_VEB);
	}

	if (test_bit(MCE_FLAG_TUN_OUT_ENA, change_flags)) {
		on = !!test_bit(MCE_FLAG_TUN_OUT_ENA, pf->flags);
		if (on)
			clear_bit(TNL_INNER_EN, hw->l2_fltr_flags);
		else
			set_bit(TNL_INNER_EN, hw->l2_fltr_flags);

		hw->ops->set_tun_select_inner(hw, !on);
	}

	return 0;
}

/**
 * mce_get_rss_hash_opt - Retrieve hash fields for a given flow-type
 * @hw: the VSI being configured
 * @nfc: ethtool rxnfc command
 */
static void mce_get_rss_hash_opt(struct mce_hw *hw,
				   struct ethtool_rxnfc *nfc)
{
	u32 hdrs = hw->rss_hash_type;
	u32 hash_flds = 0;

	nfc->data = 0;

	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
		if (hdrs & MCE_F_HASH_IPV4_TCP) {
			hash_flds |= MCE_F_HASH_IPV4_TCP;
		}
		if (hdrs & MCE_F_HASH_IPV4) {
			hash_flds |= MCE_F_HASH_IPV4;
		}
		break;
	case UDP_V4_FLOW:
		if (hdrs & MCE_F_HASH_IPV4_UDP) {
			hash_flds |= MCE_F_HASH_IPV4_UDP;
		}
		if (hdrs & MCE_F_HASH_IPV4) {
			hash_flds |= MCE_F_HASH_IPV4;
		}
		break;
	case SCTP_V4_FLOW:
		if (hdrs & MCE_F_HASH_IPV4_SCTP) {
			hash_flds |= MCE_F_HASH_IPV4_SCTP;
		}
		if (hdrs & MCE_F_HASH_IPV4) {
			hash_flds |= MCE_F_HASH_IPV4;
		}
		break;
	case TCP_V6_FLOW:
		if (hdrs & MCE_F_HASH_IPV6_TCP) {
			hash_flds |= MCE_F_HASH_IPV6_TCP;
		}
		if (hdrs & MCE_F_HASH_IPV6) {
			hash_flds |= MCE_F_HASH_IPV6;
		}
		break;
	case UDP_V6_FLOW:
		if (hdrs & MCE_F_HASH_IPV6_UDP) {
			hash_flds |= MCE_F_HASH_IPV6_UDP;
		}
		if (hdrs & MCE_F_HASH_IPV6) {
			hash_flds |= MCE_F_HASH_IPV6;
		}
		break;
	case SCTP_V6_FLOW:
		if (hdrs & MCE_F_HASH_IPV6_SCTP) {
			hash_flds |= MCE_F_HASH_IPV6_SCTP;
		}
		if (hdrs & MCE_F_HASH_IPV6) {
			hash_flds |= MCE_F_HASH_IPV6;
		}
		break;
	default:
		break;
	}

	if ((hash_flds & MCE_F_HASH_IPV4_TCP) ||
	    (hash_flds & MCE_F_HASH_IPV4_UDP) ||
	    (hash_flds & MCE_F_HASH_IPV4_SCTP) ||
	    (hash_flds & MCE_F_HASH_IPV6_TCP) ||
	    (hash_flds & MCE_F_HASH_IPV6_UDP) ||
	    (hash_flds & MCE_F_HASH_IPV6_SCTP)) {
		nfc->data |= (u64)RXH_L4_B_0_1;
		nfc->data |= (u64)RXH_L4_B_2_3;
	}

	if ((hash_flds & MCE_F_HASH_IPV4) ||
	    (hash_flds & MCE_F_HASH_IPV6)) {
		nfc->data |= (u64)RXH_IP_SRC;
		nfc->data |= (u64)RXH_IP_DST;
	}
}

/**
 * mce_get_rxnfc - command to get Rx flow classification rules
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 * @rule_locs: buffer to rturn Rx flow classification rules
 *
 * Returns Success if the command is supported.
 */
static int mce_get_rxnfc(struct net_device *netdev,
			   struct ethtool_rxnfc *cmd,
			   u32 __always_unused *rule_locs)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = vsi->num_rxq;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = hw->fdir_active_fltr;
		cmd->data = hw->func_caps.fd_fltr_guar;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = mce_get_ethtool_fdir_entry(hw, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
		ret = mce_get_fdir_fltr_ids(hw, cmd, (u32 *)rule_locs);
		break;
	case ETHTOOL_GRXFH:
		mce_get_rss_hash_opt(hw, cmd);
		ret = 0;
		break;
	default:
		break;
	}

	return ret;
}

/**
 * mce_set_rss_hash_opt - Enable/Disable flow types for RSS hash
 * @vsi: the VSI being configured
 * @nfc: ethtool rxnfc command
 *
 * Returns Success if the flow input set is supported.
 */
static int mce_set_rss_hash_opt(struct mce_vsi *vsi,
				  struct ethtool_rxnfc *nfc)
{
	struct mce_hw *hw = &(vsi->back->hw);
	u32 hash_type = 0;

	if (nfc->data & RXH_IP_SRC || nfc->data & RXH_IP_DST) {
		switch (nfc->flow_type) {
		case TCP_V4_FLOW:
		case UDP_V4_FLOW:
		case SCTP_V4_FLOW:
			hash_type |= MCE_F_HASH_IPV4;
			break;
		case TCP_V6_FLOW:
		case UDP_V6_FLOW:
		case SCTP_V6_FLOW:
			hash_type |= MCE_F_HASH_IPV6;
			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	if (nfc->data & RXH_L4_B_0_1 || nfc->data & RXH_L4_B_2_3) {
		switch (nfc->flow_type) {
		case TCP_V4_FLOW:
			hash_type |= MCE_F_HASH_IPV4_TCP;
			hash_type |= MCE_F_HASH_IPV4;
			break;
		case UDP_V4_FLOW:
			hash_type |= MCE_F_HASH_IPV4_UDP;
			hash_type |= MCE_F_HASH_IPV4;
			break;
		case SCTP_V4_FLOW:
			hash_type |= MCE_F_HASH_IPV4_SCTP;
			hash_type |= MCE_F_HASH_IPV4;
			break;
		case TCP_V6_FLOW:
			hash_type |= MCE_F_HASH_IPV6_TCP;
			hash_type |= MCE_F_HASH_IPV6;
			break;
		case UDP_V6_FLOW:
			hash_type |= MCE_F_HASH_IPV6_UDP;
			hash_type |= MCE_F_HASH_IPV6;
			break;
		case SCTP_V6_FLOW:
			hash_type |= MCE_F_HASH_IPV6_SCTP;
			hash_type |= MCE_F_HASH_IPV6;
			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	if (nfc->data & RXH_L2DA || nfc->data & RXH_VLAN ||
	    nfc->data & RXH_DISCARD || nfc->data & RXH_L3_PROTO) {
		return -EOPNOTSUPP;
	}

	hw->rss_hash_type = hash_type;
	hw->ops->set_rss_hash_type(hw);

	return 0;
}

/**
 * mce_set_rxnfc - command to set Rx flow rules.
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 *
 * Returns 0 for success and negative values for errors
 */
static int mce_set_rxnfc(struct net_device *netdev,
			   struct ethtool_rxnfc *cmd)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		return mce_add_ntuple_ethtool(vsi, cmd);
	case ETHTOOL_SRXCLSRLDEL:
		return mce_del_ntuple_ethtool(vsi, cmd);
	case ETHTOOL_SRXFH:
		return mce_set_rss_hash_opt(vsi, cmd);
	default:
		break;
	}
	return -EOPNOTSUPP;
}

#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
/**
 * mce_get_rxfh_key_size - get the RSS hash key size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 */
static u32
mce_get_rxfh_key_size(struct net_device __always_unused *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	return (hw->func_caps.common_cap.rss_key_size);
}

/**
 * mce_get_rxfh_indir_size - get the Rx flow hash indirection table size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 */
static u32 mce_get_rxfh_indir_size(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	return (hw->func_caps.common_cap.rss_table_size);
}

#ifdef HAVE_RXFH_HASHFUNC
#if defined(HAVE_ETHTOOL_RXFH_PARAM)
/**
 * mce_get_rxfh - get the Rx flow hash indirection table
 * @netdev: network interface device structure
 * @rxfh: pointer to param struct (indir, key, hfunc)
 *
 * Reads the indirection table directly from the hardware.
 */
static int
mce_get_rxfh(struct net_device *netdev, struct ethtool_rxfh_param *rxfh)
#else
static int
mce_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc)
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
#else
static int mce_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key)
#endif
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	int i = 0;
	u8 *lut;

#ifdef HAVE_RXFH_HASHFUNC
#if defined(HAVE_ETHTOOL_RXFH_PARAM)
	rxfh->hfunc = hw->rss_hfunc;
#else
	if (hfunc)
		*hfunc = hw->rss_hfunc;
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
#endif
#if defined(HAVE_ETHTOOL_RXFH_PARAM)
	if (!rxfh->indir)
#else
	if (!indir)
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
		return 0;

	lut = kzalloc(hw->func_caps.common_cap.rss_table_size, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;

	for (i = 0; i < hw->func_caps.common_cap.rss_table_size; i++) {
#if defined(HAVE_ETHTOOL_RXFH_PARAM)
		rxfh->indir[i] = (u32)(hw->rss_table[i]);
#else
		indir[i] = (u32)(hw->rss_table[i]);
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
	}

#if defined(HAVE_ETHTOOL_RXFH_PARAM)
	if (rxfh->key) {
		memcpy(rxfh->key, hw->rss_key,
		       (hw->func_caps.common_cap.rss_key_size));
	}
#else
	if (key) {
		memcpy(key, hw->rss_key,
		       (hw->func_caps.common_cap.rss_key_size));
	}
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
	kfree(lut);
	return 0;
}

#ifdef HAVE_RXFH_HASHFUNC
/**
 * mce_set_rxfh - set the Rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 * @hfunc: hash function
 *
 * Returns -EINVAL if the table specifies an invalid queue ID, otherwise
 * returns 0 after programming the table.
 */
#if defined(HAVE_ETHTOOL_RXFH_PARAM)
static int
mce_set_rxfh(struct net_device *netdev, struct ethtool_rxfh_param *rxfh,
		 struct netlink_ext_ack *extack)
#else
static int
mce_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key,
		 const u8 hfunc)
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
#elif defined(HAVE_RXFH_NONCONST)
static int mce_set_rxfh(struct net_device *netdev, u32 *indir, u8 *key)
#else
static int mce_set_rxfh(struct net_device *netdev, const u32 *indir,
			  const u8 *key)
#endif /* HAVE_RXFH_HASHFUNC */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &(pf->hw);

	if (!test_bit(MCE_FLAG_RSS_ENA, pf->flags)) {
		/* RSS not supported return error here */
		netdev_warn(netdev,
			    "RSS is not configured on this VSI!\n");
		return -EIO;
	}

#ifdef HAVE_RXFH_HASHFUNC
#if defined(HAVE_ETHTOOL_RXFH_PARAM)
	if (rxfh->hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    (rxfh->hfunc != ETH_RSS_HASH_TOP &&
	     rxfh->hfunc != ETH_RSS_HASH_XOR))
		return -EOPNOTSUPP;

	if (rxfh->hfunc && rxfh->hfunc != hw->rss_hfunc) {
		hw->rss_hfunc = rxfh->hfunc;
		hw->ops->set_rss_hash(hw, netdev->features);
	}
#else
	if (hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    (hfunc != ETH_RSS_HASH_TOP && hfunc != ETH_RSS_HASH_XOR)) {
		return -EOPNOTSUPP;
	}

	if (hfunc && hfunc != hw->rss_hfunc) {
		hw->rss_hfunc = hfunc;
		hw->ops->set_rss_hash(hw, netdev->features);
	}
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
#endif /* HAVE_RXFH_HASHFUNC */

#if defined(HAVE_ETHTOOL_RXFH_PARAM)
	if (rxfh->key) {
		memcpy(hw->rss_key, rxfh->key,
		       (hw->func_caps.common_cap.rss_key_size));
#else
	if (key) {
		memcpy(hw->rss_key, key,
		       (hw->func_caps.common_cap.rss_key_size));
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
		hw->ops->set_rss_key(hw);
	}

#if defined(HAVE_ETHTOOL_RXFH_PARAM)
	if (rxfh->indir) {
#else
	if (indir) {
#endif /* HAVE_ETHTOOL_RXFH_PARAM */
		int i;
		for (i = 0; i < (hw->func_caps.common_cap.rss_table_size);
		     i++) {
#if defined(HAVE_ETHTOOL_RXFH_PARAM)
			hw->rss_table[i] = (u8)(rxfh->indir[i]);
#else
			hw->rss_table[i] = (u16)(indir[i]);
#endif
		}
		mce_set_rss_table(hw, PFINFO_IDX, vsi->num_rxq);
	}

	return 0;
}
#endif /* ETHTOOL_GRSSH && ETHTOOL_SRSSH */

/**
 * mce_get_combined_cnt - return the current number of combined channels
 * @vsi: PF VSI pointer
 *
 * Go through all queue vectors and count ones that have both Rx and Tx ring
 * attached
 */
static u32 mce_get_combined_cnt(struct mce_vsi *vsi)
{
//	struct mce_q_vector *q_vector = NULL;
//	u32 combined = 0;
//	int q_idx;

	/*
	mce_for_each_q_vector(vsi, q_idx) {
		q_vector = vsi->q_vectors[q_idx];

		combined += min_t(u32, q_vector->num_ring_rx,
				  q_vector->num_ring_tx);
	} */

	//return combined;
	return vsi->num_txq_real;
}

/**
 * mce_get_channels - get the current and max supported channels
 * @dev: network interface device structure
 * @ch: ethtool channel data structure
 */
static void mce_get_channels(struct net_device *dev,
			       struct ethtool_channels *ch)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;

	/* report maximum channels */
	ch->max_rx = pf->max_pf_rxqs / pf->num_max_tc;
	ch->max_tx = pf->max_pf_txqs / pf->num_max_tc;
	ch->max_combined = min_t(int, ch->max_rx, ch->max_tx);

	ch->max_rx = 0;
	ch->max_tx = 0;

	/* report current channels */
	ch->combined_count = mce_get_combined_cnt(vsi);
	//ch->rx_count = vsi->num_rxq - ch->combined_count;
	//ch->tx_count = vsi->num_txq - ch->combined_count;
	ch->rx_count = 0;
	ch->tx_count = 0;

	/* report other queues */
	ch->other_count = pf->num_mbox_irqs;
	ch->max_other = ch->other_count;
}

/**
 * mce_set_channels - set the number channels
 * @dev: network interface device structure
 * @ch: ethtool channel data structure
 */
static int mce_set_channels(struct net_device *dev,
			      struct ethtool_channels *ch)
{
	struct mce_netdev_priv *np = netdev_priv(dev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	int new_rx = 0, new_tx = 0;
	u32 curr_combined;
	struct mce_dcb *dcb = pf->dcb;
	bool old_ets = false;
	bool old_pfc = false;

	if (pf->hw.fdir_active_fltr) {
		netdev_err(dev, "Cannot set channels "
				"when Flow Director filters are active\n");
		return -EOPNOTSUPP;
	}


	//if (test_bit(MCE_ETS_EN, pf->dcb->flags) ||
	//    test_bit(MCE_PFC_EN, pf->dcb->flags)) {
	//	netdev_err(dev, "Cannot set channels "
	//			"when ETS or PFC is active\n");
	//	return -EOPNOTSUPP;
	//}

	if (test_and_clear_bit(MCE_MQPRIO_CHANNEL, pf->dcb->flags)) {
		pf->hw.ops->disable_tc(&(pf->hw));
		pf->hw.ops->clr_q_to_tc(&(pf->hw));
	} 

	curr_combined = mce_get_combined_cnt(vsi);

	/* these checks are for cases where user didn't specify a particular
	 * value on cmd line but we get non-zero value anyway via
	 * get_channels(); look at ethtool.c in ethtool repository (the user
	 * space part), particularly, do_schannels() routine
	 */
	if (ch->rx_count == vsi->num_rxq - curr_combined)
		ch->rx_count = 0;
	if (ch->tx_count == vsi->num_txq - curr_combined)
		ch->tx_count = 0;
	if (ch->combined_count == curr_combined)
		ch->combined_count = 0;

	if (!(ch->combined_count || (ch->rx_count && ch->tx_count))) {
		netdev_err(
			dev,
			"Please specify at least 1 Rx and 1 Tx channel\n");
		return -EINVAL;
	}

	new_rx = ch->combined_count + ch->rx_count;
	new_tx = ch->combined_count + ch->tx_count;

	// fixme later
	if (new_rx > pf->max_pf_rxqs) {
		netdev_err(dev, "Maximum allowed Rx channels is %d\n",
			   pf->max_pf_rxqs);
		return -EINVAL;
	}
	if (new_tx > pf->max_pf_txqs) {
		netdev_err(dev, "Maximum allowed Tx channels is %d\n",
			   pf->max_pf_txqs);
		return -EINVAL;
	}

	// if channels change, we should close ets and pfc in default
	if (test_bit(MCE_ETS_EN, pf->dcb->flags))
		old_ets = true;

	if (test_bit(MCE_PFC_EN, pf->dcb->flags))
		old_pfc = true;

	clear_bit(MCE_ETS_EN, pf->dcb->flags);
	clear_bit(MCE_PFC_EN, pf->dcb->flags);
	//clean it
	// todo 
	mce_dcb_tc_default(&(dcb->cur_tccfg));
	mce_dcb_tc_default(&(dcb->new_tccfg));
	mce_dcb_ets_default(&(dcb->cur_etscfg));
	mce_dcb_ets_default(&(dcb->new_etscfg));
	mce_dcb_pfc_default(&(dcb->cur_pfccfg));
	mce_dcb_pfc_default(&(dcb->new_pfccfg));
	// set default
	//dcb->dcbx_cap = DCB_CAP_DCBX_VER_IEEE | DCB_CAP_DCBX_VER_CEE |
	//		DCB_CAP_DCBX_HOST;
	// clean hw setup	
	mce_dcb_update_hwpfccfg(pf->dcb);
	mce_dcb_update_hwetscfg(pf->dcb);

	mce_vsi_recfg_qs(vsi, new_rx, new_tx);

	// restore ets and pfc setup
	if (old_ets) {
		dev->dcbnl_ops->ieee_setets(dev, &(dcb->ets_os));
	} 


	if (old_pfc) {
		dev->dcbnl_ops->ieee_setpfc(dev, &(dcb->pfc_os));
	}

	return 0;
}

#ifdef HAVE_ETHTOOL_EXTENDED_RINGPARAMS
static void mce_get_ringparam(
	struct net_device *netdev, struct ethtool_ringparam *ring,
	struct kernel_ethtool_ringparam __always_unused *kernel_rp,
	struct netlink_ext_ack __always_unused *extack)
#else /* HAVE_ETHTOOL_EXTENDED_RINGPARAMS */
static void mce_get_ringparam(struct net_device *netdev,
				struct ethtool_ringparam *ring)
#endif /* HAVE_ETHTOOL_EXTENDED_RINGPARAMS */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;

	ring->rx_max_pending = MCE_MAX_NUM_DESC;
	ring->tx_max_pending = MCE_MAX_NUM_DESC;
	ring->rx_pending = vsi->rx_rings[0]->count;
	ring->tx_pending = vsi->tx_rings[0]->count;

	/* Rx mini and jumbo rings are not supported */
	ring->rx_mini_max_pending = 0;
	ring->rx_jumbo_max_pending = 0;
	ring->rx_mini_pending = 0;
	ring->rx_jumbo_pending = 0;
}

#ifdef HAVE_ETHTOOL_EXTENDED_RINGPARAMS
static int mce_set_ringparam(
	struct net_device *netdev, struct ethtool_ringparam *ring,
	struct kernel_ethtool_ringparam __always_unused *kernel_rp,
	struct netlink_ext_ack __always_unused *extack)
#else /* HAVE_ETHTOOL_EXTENDED_RINGPARAMS */
static int mce_set_ringparam(struct net_device *netdev,
			       struct ethtool_ringparam *ring)
#endif /* HAVE_ETHTOOL_EXTENDED_RINGPARAMS */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_ring *tx_rings = NULL;
	struct mce_ring *rx_rings = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	int i, timeout = 50, err = 0;
	u16 new_rx_cnt, new_tx_cnt;

	if (ring->tx_pending > MCE_MAX_NUM_DESC ||
	    ring->tx_pending < MCE_MIN_NUM_DESC ||
	    ring->rx_pending > MCE_MAX_NUM_DESC ||
	    ring->rx_pending < MCE_MIN_NUM_DESC) {
		netdev_err(
			netdev,
			"Descriptors requested (Tx: %d / Rx: %d) out of range [%d-%d] (increment %d)\n",
			ring->tx_pending, ring->rx_pending,
			MCE_MIN_NUM_DESC, MCE_MAX_NUM_DESC,
			MCE_REQ_DESC_MULTIPLE);
		return -EINVAL;
	}

	new_tx_cnt = ALIGN(ring->tx_pending, MCE_REQ_DESC_MULTIPLE);
	if (new_tx_cnt != ring->tx_pending)
		netdev_info(
			netdev,
			"Requested Tx descriptor count rounded up to %d\n",
			new_tx_cnt);
	new_rx_cnt = ALIGN(ring->rx_pending, MCE_REQ_DESC_MULTIPLE);
	if (new_rx_cnt != ring->rx_pending)
		netdev_info(
			netdev,
			"Requested Rx descriptor count rounded up to %d\n",
			new_rx_cnt);

	/* if nothing to do return success */
	if (new_tx_cnt == vsi->tx_rings[0]->count &&
	    new_rx_cnt == vsi->rx_rings[0]->count) {
		netdev_dbg(
			netdev,
			"Nothing to change, descriptor count is same as requested\n");
		return 0;
	}

	while (test_and_set_bit(MCE_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	/* set for the next time the netdev is started */
	if (!netif_running(vsi->netdev)) {
		mce_for_each_txq_new(vsi, i) {
			if (!vsi->tx_rings[i]->q_vector) {
				//printk("%s skip tx queue %d\n", __func__, i);
				continue;
			}
			vsi->tx_rings[i]->count = new_tx_cnt;
		}
		mce_for_each_rxq_new(vsi, i) {
			if (!vsi->rx_rings[i]->q_vector)
				continue;
			vsi->rx_rings[i]->count = new_rx_cnt;
		}

		vsi->num_tx_desc = (u16)new_tx_cnt;
		vsi->num_rx_desc = (u16)new_rx_cnt;
		netdev_dbg(
			netdev,
			"Link is down, descriptor count change happens when link is brought up\n");
		goto done;
	}

	if (new_tx_cnt == vsi->tx_rings[0]->count)
		goto process_rx;

	/* alloc updated Tx resources */
	netdev_info(netdev, "Changing Tx descriptor count from %d to %d\n",
		    vsi->tx_rings[0]->count, new_tx_cnt);

	tx_rings = kcalloc(vsi->num_txq, sizeof(*tx_rings), GFP_KERNEL);
	if (!tx_rings) {
		err = -ENOMEM;
		goto done;
	}

	mce_for_each_txq_new(vsi, i) {
		if (!vsi->tx_rings[i]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, i);
			continue;
		}
		/* clone ring and setup updated count */
		tx_rings[i] = *vsi->tx_rings[i];
		tx_rings[i].count = new_tx_cnt;
		tx_rings[i].desc = NULL;
		tx_rings[i].tx_buf = NULL;
		err = mce_setup_tx_ring(&tx_rings[i]);
		if (err) {
			while (i--)
				mce_clean_tx_ring(&tx_rings[i]);
			kfree(tx_rings);
			tx_rings = NULL;
			goto done;
		}
	}

process_rx:
	if (new_rx_cnt == vsi->rx_rings[0]->count)
		goto process_link;

	/* alloc updated Rx resources */
	netdev_info(netdev, "Changing Rx descriptor count from %d to %d\n",
		    vsi->rx_rings[0]->count, new_rx_cnt);

	rx_rings = kcalloc(vsi->num_rxq, sizeof(*rx_rings), GFP_KERNEL);
	if (!rx_rings) {
		err = -ENOMEM;
		goto done;
	}

	mce_for_each_rxq_new(vsi, i) {
		if (!vsi->rx_rings[i]->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, i);
			continue;
		}
		/* clone ring and setup updated count */
		rx_rings[i] = *vsi->rx_rings[i];
		rx_rings[i].count = new_rx_cnt;
		rx_rings[i].desc = NULL;
		rx_rings[i].rx_buf = NULL;
		err = mce_setup_rx_ring(&rx_rings[i]);
		if (err) {
			while (i) {
				i--;
				mce_free_rx_ring(&rx_rings[i]);
			}
			kfree(rx_rings);
			rx_rings = NULL;
			err = -ENOMEM;
			goto free_tx;
		}
	}

process_link:
	/* Bring interface down, copy in the new ring info, then restore the
	 * interface. if VSI is up, bring it down and then back up
	 */
	if (!test_and_set_bit(MCE_VSI_DOWN, vsi->state)) {
		mce_down(vsi);

		if (tx_rings) {
			mce_for_each_txq_new(vsi, i) {
				if (!vsi->tx_rings[i]->q_vector) {
					//printk("%s skip tx queue %d\n", __func__, i);
					continue;
				}
				mce_free_tx_ring(vsi->tx_rings[i]);
				*vsi->tx_rings[i] = tx_rings[i];
			}
			kfree(tx_rings);
			tx_rings = NULL;
		}

		if (rx_rings) {
			mce_for_each_rxq_new(vsi, i) {
				if (!vsi->rx_rings[i]->q_vector) {
					//printk("%s skip tx queue %d\n", __func__, i);
					continue;
				}
				mce_free_rx_ring(vsi->rx_rings[i]);
				*vsi->rx_rings[i] = rx_rings[i];
			}
			kfree(rx_rings);
			rx_rings = NULL;
		}

		vsi->num_tx_desc = new_tx_cnt;
		vsi->num_rx_desc = new_rx_cnt;
		mce_up(vsi);
	}
	goto done;

free_tx:
	/* error cleanup if the Rx allocations failed after getting Tx */
	if (tx_rings) {
		mce_for_each_txq_new(vsi, i) {
			if (!vsi->tx_rings[i]->q_vector) {
				//printk("%s skip tx queue %d\n", __func__, i);
				continue;
			}
			mce_free_tx_ring(&tx_rings[i]);
		}
	}

done:
	kfree(rx_rings);
	kfree(tx_rings);
	clear_bit(MCE_CFG_BUSY, pf->state);
	return err;
}

static u32 mce_get_msglevel(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pf *pf = np->vsi->back;

	return pf->msg_enable;
}

static void mce_set_msglevel(struct net_device *netdev, u32 data)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pf *pf = np->vsi->back;

	pf->msg_enable = data;
}

/**
 * mce_get_pauseparam - Get Flow Control status
 * @netdev: network interface device structure
 * @pause: ethernet pause (flow control) parameters
 *
 * Get autonegotiated flow control status from link status.
 */
static void mce_get_pauseparam(struct net_device *netdev,
				 struct ethtool_pauseparam *pause)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = (struct mce_pf *)(vsi->back);
	struct mce_flow_control *fc = &(pf->fc);

	pause->rx_pause = 0;
	pause->tx_pause = 0;

	pause->autoneg = ((fc->auto_pause == MCE_PAUSE_EN) ?
				  AUTONEG_ENABLE :
				  AUTONEG_DISABLE);

	/* PFC enabled so report LFC as off */

	/* Get flow control status based on autonegotiation */
	switch (fc->current_mode) {
	case MCE_FC_TX_PAUSE:
		pause->tx_pause = 1;
		break;
	case MCE_FC_RX_PAUSE:
		pause->rx_pause = 1;
		break;
	case MCE_FC_FULL:
		pause->tx_pause = 1;
		pause->rx_pause = 1;
		break;
	default:
		break;
	}
}

/**
 * mce_set_pauseparam - Set Flow Control parameter
 * @netdev: network interface device structure
 * @pause: return Tx/Rx flow control status
 */
static int mce_set_pauseparam(struct net_device *netdev,
				struct ethtool_pauseparam *pause)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = (struct mce_pf *)(vsi->back);
	struct mce_hw *hw = &(pf->hw);
	struct mce_flow_control *fc = &(pf->fc);
	u32 is_an;

	/* Changing the port's flow control is not supported
	 * if this isn't thePF VSI
	 */
	if (vsi->type != MCE_VSI_PF) {
		netdev_info(netdev, "Changing flow control parameters "
				    "only supported for PF VSI\n");
		return -EOPNOTSUPP;
	}

	if (test_bit(MCE_PFC_EN, pf->dcb->flags)) {
		netdev_info(netdev, "The NIC is currently in PFC mode. "
			    "The pause change cannot take effect\n");
		return -EOPNOTSUPP;
	}

	is_an = ((fc->auto_pause == MCE_PAUSE_EN) ? AUTONEG_ENABLE :
						      AUTONEG_DISABLE);

	if (pause->autoneg != is_an) {
		netdev_info(netdev,
			    "Sorry, We do not yet support autoneg\n");
		return -EOPNOTSUPP;
	}

	/* If we have link and don't have autoneg */
	if (!test_bit(MCE_DOWN, pf->state)) {
		/* Send message that it might not necessarily work*/
		netdev_info(netdev, "Autoneg did not complete so changing "
				    "settings may not result in an actual "
				    "change.\n");
	}

	/* PFC enabled so report LFC as off */

	if (pause->rx_pause && pause->tx_pause)
		fc->req_mode = MCE_FC_FULL;
	else if (pause->rx_pause && !pause->tx_pause)
		fc->req_mode = MCE_FC_RX_PAUSE;
	else if (!pause->rx_pause && pause->tx_pause)
		fc->req_mode = MCE_FC_TX_PAUSE;
	else if (!pause->rx_pause && !pause->tx_pause)
		fc->req_mode = MCE_FC_NONE;
	else
		return -EINVAL;

	if (fc->current_mode != fc->req_mode)
		hw->ops->set_pause_en_only(hw);

	return 0;
}

#ifdef HAVE_ETHTOOL_COALESCE_EXTACK
static int
mce_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		   struct kernel_ethtool_coalesce __maybe_unused *kec,
		   struct netlink_ext_ack __maybe_unused *extack)
#else
static int
mce_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec)
#endif /* HAVE_ETHTOOL_COALESCE_EXTACK */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_ring_container *rx = &(vsi->q_vectors[0]->rx);
	struct mce_ring_container *tx = &(vsi->q_vectors[0]->tx);

	if (rx->dim_params.mode == ITR_STATIC) {
		ec->use_adaptive_rx_coalesce = ITR_STATIC;
	} else {
		ec->use_adaptive_rx_coalesce = ITR_DYNAMIC;
	}

	ec->rx_coalesce_usecs = rx->dim_params.usecs;
	ec->rx_max_coalesced_frames = rx->dim_params.frames;

	if (tx->dim_params.mode == ITR_STATIC) {
		ec->use_adaptive_tx_coalesce = ITR_STATIC;
	} else {
		ec->use_adaptive_tx_coalesce = ITR_DYNAMIC;
	}

	ec->tx_coalesce_usecs = tx->dim_params.usecs;
	ec->tx_max_coalesced_frames = tx->dim_params.frames;

	return 0;
}

#ifdef HAVE_ETHTOOL_COALESCE_EXTACK
/**
 * mce_set_coalesce - set coalesce settings for all queues
 * @netdev: pointer to the netdev associated with this query
 * @ec: ethtool structure to read the requested coalesce settings
 * @kec: kernel coalesce parameter
 * @extack: kernel extack parameter
 *
 * Return 0 on success, negative otherwise.
 */
static int
mce_set_coalesce(struct net_device *netdev,
		   struct ethtool_coalesce *ec,
		   struct kernel_ethtool_coalesce __maybe_unused *kec,
		   struct netlink_ext_ack __maybe_unused *extack)
#else
static int
mce_set_coalesce(struct net_device *netdev,
		   struct ethtool_coalesce *ec)
#endif /* HAVE_ETHTOOL_COALESCE_EXTACK */
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = (struct mce_pf *)(vsi->back);
	struct mce_hw_operations *hw_ops = pf->hw.ops;
	u32 tx_usecs = 0, tx_frames = 0;
	u32 rx_usecs = 0, rx_frames = 0;
	int i = 0;

	if (test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags)) {
		netdev_info(netdev, "Invalid value, because hw dim is enabled\n");
		return -EINVAL;
	}

#ifndef ETHTOOL_COALESCE_USECS
	if (ec->rx_coalesce_usecs_irq || ec->rx_max_coalesced_frames_irq ||
	    ec->tx_coalesce_usecs_irq || ec->tx_max_coalesced_frames_irq ||
	    ec->stats_block_coalesce_usecs ||
	    ec->pkt_rate_low || ec->rx_coalesce_usecs_low ||
	    ec->rx_max_coalesced_frames_low || ec->tx_coalesce_usecs_low ||
	    ec->tx_max_coalesced_frames_low || ec->pkt_rate_high ||
	    ec->rx_max_coalesced_frames_high ||
	    ec->tx_coalesce_usecs_high ||
	    ec->tx_max_coalesced_frames_high || ec->rate_sample_interval)
		return -EOPNOTSUPP;
#endif

	if (ec->tx_coalesce_usecs < MCE_MAX_INTR_TIME &&
	    ec->tx_coalesce_usecs > 0) {
		tx_usecs = ec->tx_coalesce_usecs;
	} else {
		netdev_info(netdev,
			    "Invalid value, tx_coalesce_usecs valid values are 1 - %d\n",
			    MCE_MAX_INTR_TIME);
		return -EINVAL;
	}

	if (ec->tx_max_coalesced_frames < MCE_MAX_INTR_PKTS &&
	    ec->tx_max_coalesced_frames > 0) {
		tx_frames = ec->tx_max_coalesced_frames;
	} else {
		netdev_info(netdev,
			    "Invalid value, tx_coalesce_frames valid values are 1 - %d\n",
			    MCE_MAX_INTR_PKTS);
		return -EINVAL;
	}

	if (ec->rx_coalesce_usecs < MCE_MAX_INTR_TIME &&
	    ec->rx_coalesce_usecs > 0) {
		rx_usecs = ec->rx_coalesce_usecs;
	} else {
		netdev_info(netdev,
			    "Invalid value, rx_coalesce_usecs valid values are 1 - %d\n",
			    MCE_MAX_INTR_TIME);
		return -EINVAL;
	}

	if (ec->rx_max_coalesced_frames < MCE_MAX_INTR_PKTS &&
	    ec->rx_max_coalesced_frames > 0) {
		rx_frames = ec->rx_max_coalesced_frames;
	} else {
		netdev_info(netdev,
			    "Invalid value, rx_coalesce_frames valid values are 1 - %d\n",
			    MCE_MAX_INTR_PKTS);
		return -EINVAL;
	}

	mce_for_each_q_vector(vsi, i) {
		struct mce_q_vector *q_vector = vsi->q_vectors[i];
		struct mce_ring *ring;

		if (ec->use_adaptive_rx_coalesce) {
			q_vector->rx.dim_params.mode = ITR_SW_DYNAMIC;
		} else {
			q_vector->rx.dim_params.mode = ITR_STATIC;
			q_vector->rx.dim_params.frames = rx_frames;
			q_vector->rx.dim_params.usecs = rx_usecs;
			mce_rc_for_each_ring(ring, q_vector->rx) {
				hw_ops->set_rxring_intr_coal(ring);
			}
		}

		if (ec->use_adaptive_tx_coalesce) {
			q_vector->tx.dim_params.mode = ITR_SW_DYNAMIC;
		} else {
			q_vector->tx.dim_params.mode = ITR_STATIC;
			q_vector->tx.dim_params.frames = tx_frames;
			q_vector->tx.dim_params.usecs = tx_usecs;
			mce_rc_for_each_ring(ring, q_vector->tx) {
				hw_ops->set_txring_intr_coal(ring);
			}
		}
	}

	return 0;
}

#ifdef HAVE_ETHTOOL_KERNEL_TS_INFO
int mce_get_ts_info(struct net_device *dev, struct kernel_ethtool_ts_info *info)
#else
int mce_get_ts_info(struct net_device *dev, struct ethtool_ts_info *info)
#endif
{
        struct mce_netdev_priv *np = netdev_priv(dev);
        struct mce_vsi *vsi = np->vsi;
        struct mce_pf *pf = vsi->back;

        /*For we juse set it as pf0 */
        if (!(pf->flags2 & MCE_FLAG2_PTP_ENABLED))
                return ethtool_op_get_ts_info(dev, info);
#ifdef HAVE_PTP_1588_CLOCK
        if (pf->ptp_clock)
                info->phc_index = ptp_clock_index(pf->ptp_clock);
        else
                info->phc_index = -1;

        info->so_timestamping =
                SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE |
                SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE |
                SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE;

        info->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);

        info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
                           BIT(HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
                           BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
                           /* 802.AS1 */
                           BIT(HWTSTAMP_FILTER_PTP_V2_L2_EVENT) |
                           BIT(HWTSTAMP_FILTER_PTP_V2_L2_SYNC) |
                           BIT(HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ) |
                           BIT(HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ) |
                           BIT(HWTSTAMP_FILTER_ALL);
#endif
        return 0;
}

static const struct ethtool_ops mce_ethtool_ops = {
#if defined(ETHTOOL_GLINKSETTINGS) && !defined(KYLIN_V4_ETHTOOL_FIX_BOND)
        .get_link_ksettings = mce_get_link_ksettings,
        //.set_link_ksettings = mce_set_link_ksettings,
#else
        .get_settings = mce_get_settings,
        //.set_settings = mce_set_settings,
#endif

	.get_drvinfo = mce_get_drvinfo,
	.get_sset_count = mce_get_sset_count,
	.get_strings = mce_get_strings,
	.get_link = ethtool_op_get_link,
	.get_ethtool_stats = mce_get_ethtool_stats,
	.get_priv_flags = mce_get_priv_flags,
	.set_priv_flags = mce_set_priv_flags,
	.get_rxnfc = mce_get_rxnfc,
	.set_rxnfc = mce_set_rxnfc,
#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
	.get_rxfh_key_size = mce_get_rxfh_key_size,
	.get_rxfh_indir_size = mce_get_rxfh_indir_size,
	.get_rxfh = mce_get_rxfh,
	.set_rxfh = mce_set_rxfh,
#endif /* ETHTOOL_GRSSH && ETHTOOL_SRSSH */
	.get_channels = mce_get_channels,
	.set_channels = mce_set_channels,
	.get_ringparam = mce_get_ringparam,
	.set_ringparam = mce_set_ringparam,
	.get_msglevel = mce_get_msglevel,
	.set_msglevel = mce_set_msglevel,
	.get_pauseparam = mce_get_pauseparam,
	.set_pauseparam = mce_set_pauseparam,
#ifdef ETHTOOL_COALESCE_USECS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_MAX_FRAMES |
				     ETHTOOL_COALESCE_USE_ADAPTIVE,
#endif /* ETHTOOL_COALESCE_USECS */
	.get_coalesce = mce_get_coalesce,
	.set_coalesce = mce_set_coalesce,
	.get_ts_info = mce_get_ts_info,
};

void mce_set_ethtool_ops(struct net_device *netdev)
{
#ifndef ETHTOOL_OPS_COMPAT
	netdev->ethtool_ops = &mce_ethtool_ops;
#else
	SET_ETHTOOL_OPS(netdev, &rnp_ethtool_ops);
#endif
}
