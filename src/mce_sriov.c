#include "mce.h"
#include "mce_base.h"
#include "mce_lib.h"
#include "mce_sriov.h"
#include "mce_virtchnl.h"
#include "mce_n20/mce_hw_n20.h"

#ifdef CONFIG_PCI_IOV
static int mce_sriov_reinit(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int timeout = 50;

	while (test_and_set_bit(MCE_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	vsi->req_txq = 0;
	vsi->req_rxq = 0;

	/* set for the next time the netdev is started */
	if (!netif_running(vsi->netdev)) {
		mce_vsi_rebuild(vsi);
		dev_dbg(mce_pf_to_dev(pf),
			"Link is down, queue count change happens "
			"when link is brought up\n");
		goto done;
	}

	rtnl_lock();
	mce_vsi_close(vsi);
	mce_vsi_rebuild(vsi);
	mce_vf_resync_mc_list(pf,
			      !!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags));
	mce_vf_resync_vlan_list(pf,
				!!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags));
	mce_vsi_open(vsi);
	rtnl_unlock();
done:
	clear_bit(MCE_CFG_BUSY, pf->state);
	return 0;
}
#endif

/**
 * mce_set_vf_mac
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @mac: MAC address
 *
 * program VF MAC address
 */
int mce_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	if (is_multicast_ether_addr(mac)) {
		netdev_err(netdev, "%pM not a valid unicast address\n",
			   mac);
		return -EINVAL;
	}

	if (!vf)
		return -EINVAL;

	mutex_lock(&vf->cfg_lock);

	if (is_zero_ether_addr(mac)) {
		/* VF will send VIRTCHNL_OP_ADD_ETH_ADDR message with its MAC */
		vf->vfinfo[vf_id].pf_set_mac = false;
		netdev_info(
			netdev,
			"Removing MAC on VF %d. VF driver will be reinitialized\n",
			vf_id);
	} else {
		/* PF will add MAC rule for the VF */
		vf->vfinfo[vf_id].pf_set_mac = true;
		netdev_info(
			netdev,
			"Setting MAC %pM on VF %d. VF driver will be reinitialized\n",
			mac, vf_id);
	}
	memcpy(vf->vfinfo[vf_id].vf_mac_addresses, mac, ETH_ALEN);
	/* update T4 mac entry */
	mce_msg_post_status_signle(pf, PF_SET_RESET_STATUS, vf_id);
	mutex_unlock(&vf->cfg_lock);

	return 0;
}

/**
 * mce_get_vf_cfg
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ivi: VF configuration structure
 *
 * return VF configuration
 */
int mce_get_vf_cfg(struct net_device *netdev, int vf_id,
		   struct ifla_vf_info *ivi)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	if (vf_id >= pf->num_vfs || !vf)
		return -EINVAL;

	ivi->vf = vf_id;
	ether_addr_copy(ivi->mac, vf->vfinfo[vf_id].vf_mac_addresses);
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	ivi->max_tx_rate = vf->vfinfo[vf_id].tx_rate;
	ivi->min_tx_rate = 0;
#else
	ivi->tx_rate = vf->vfinfo[vf_id].tx_rate;
#endif /* HAVE_NDO_SET_VF_MIN_MAX_TX_RATE */
	ivi->vlan = vf->vfinfo[vf_id].pf_vlan;
	ivi->qos = vf->vfinfo[vf_id].pf_qos;

#ifdef HAVE_NDO_SET_VF_LINK_STATE
	ivi->linkstate = vf->vfinfo[vf_id].link_state = true;
#endif
	ivi->spoofchk = vf->vfinfo[vf_id].spoofchk_enabled;
#ifdef HAVE_NDO_SET_VF_TRUST
	ivi->trusted = vf->vfinfo[vf_id].trusted;
#endif

	return 0;
}

/**
 * mce_is_supported_port_vlan_proto - make sure the vlan_proto is supported
 * @hw: hardware structure used to check the VLAN mode
 * @vlan_proto: VLAN TPID being checked
 *
 * If the device is configured in Double VLAN Mode (DVM), then both ETH_P_8021Q
 * and ETH_P_8021AD are supported. If the device is configured in Single VLAN
 * Mode (SVM), then only ETH_P_8021Q is supported.
 */
static bool mce_is_supported_port_vlan_proto(struct mce_hw *hw,
					     u16 vlan_proto)
{
	bool is_supported = false;

	switch (vlan_proto) {
	case ETH_P_8021Q:
		is_supported = true;
		break;
	case ETH_P_8021AD:
		is_supported = false;
		break;
	}

	return is_supported;
}

#ifdef IFLA_VF_VLAN_INFO_MAX
/**
 * mce_set_vf_port_vlan
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @vlan_id: VLAN ID being set
 * @qos: priority setting
 * @vlan_proto: VLAN protocol
 *
 * program VF Port VLAN ID and/or QoS
 */
int mce_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id,
			 u8 qos, __be16 vlan_proto)
#else
int mce_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id,
			 u8 qos)
#endif /* IFLA_VF_VLAN_INFO_MAX */
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &pf->hw;
#ifdef IFLA_VF_VLAN_INFO_MAX
	u16 local_vlan_proto = ntohs(vlan_proto);
#else
	u16 local_vlan_proto = ETH_P_8021Q;
#endif
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	if (vf_id >= pf->num_vfs || !vf)
		return -EINVAL;

	if (vlan_id >= VLAN_N_VID || qos > 7) {
		dev_err(dev,
			"Invalid Port VLAN parameters for VF %d, ID %d, QoS %d\n",
			vf_id, vlan_id, qos);
		return -EINVAL;
	}

	if (!mce_is_supported_port_vlan_proto(&pf->hw, local_vlan_proto)) {
		dev_err(dev, "VF VLAN protocol 0x%04x is not supported\n",
			local_vlan_proto);
		return -EPROTONOSUPPORT;
	}

	mutex_lock(&vf->cfg_lock);
	/* TODO: need to handle vlan_id and qos */
	if (vlan_id)
		mce_vf_setup_vlan(pf, vf_id, vlan_id);
	else
		mce_vf_del_vlan(pf, vf_id, vf->vfinfo[vf_id].pf_vlan);

	vf->vfinfo[vf_id].pf_qos = qos;
	vf->vfinfo[vf_id].pf_vlan = vlan_id;
	/* update spoofchk vlan */
	if (vf->vfinfo[vf_id].trusted) {
		hw->vf.ops->set_vf_spoofchk_vlan(hw, vf_id, true,
						 MCE_VF_ANTI_VLAN_SET);

	} else {
		hw->vf.ops->set_vf_spoofchk_vlan(hw, vf_id, false,
						 MCE_VF_ANTI_VLAN_SET);
	}

	/* TODO: need judge vf is actived? */
	mce_msg_post_status_signle(pf, PF_SET_VLAN_STATUS, vf_id);
	mutex_unlock(&vf->cfg_lock);

	return 0;
}

/**
 * mce_set_vf_bw - set min/max VF bandwidth
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @min_tx_rate: Minimum Tx rate in Mbps
 * @max_tx_rate: Maximum Tx rate in Mbps
 */
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
int mce_set_vf_bw(struct net_device *netdev, int vf_id, int min_tx_rate,
		  int max_tx_rate)
#else
int mce_set_vf_bw(struct net_device *netdev, int vf_id, int max_tx_rate)
#endif
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_dcb *dcb = pf->dcb;
	int ret = 0;

	if (vf_id >= pf->num_vfs || !vf)
		return -EINVAL;

	if (test_bit(MCE_DCB_EN, dcb->flags)) {
		dev_err(dev,
			"DCB on PF is currently enabled. VF MAX Tx rate limiting"
			" not allowed on this PF.\n");
		return -EOPNOTSUPP;
	}
	if (vf->vfinfo[vf_id].tx_rate != (unsigned int)max_tx_rate) {
		if (!test_bit(MCE_VF_BW_INITED, pf->state))
			mce_set_bw_limit_init(pf);
		ret = mce_set_max_bw_limit(
			pf, vf_id, (u64)max_tx_rate * 1000 * 1000, 4);
		if (ret) {
			dev_err(dev,
				"Unable to set max-tx-rate for VF %d\n",
				vf_id);
			goto err;
		}
		vf->vfinfo[vf_id].tx_rate = max_tx_rate;
	}
err:
	return ret;
}

#ifdef HAVE_NDO_SET_VF_TRUST
/**
 * mce_set_vf_trust
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @trusted: Boolean value to enable/disable trusted VF
 *
 * Enable or disable a given VF as trusted
 */
int mce_set_vf_trust(struct net_device *netdev, int vf_id, bool trusted)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &(pf->hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	if (!vf)
		return -EINVAL;

	mutex_lock(&vf->cfg_lock);
	if (vf->vfinfo[vf_id].trusted != trusted) {
		vf->vfinfo[vf_id].trusted = trusted;
		mce_vf_set_trusted(pf, vf_id, trusted);
		if (test_bit(MCE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags))
			hw->vf.ops->set_vf_true_promisc(hw, vf_id,
							trusted);
		pf->vf_trust_num = trusted ? pf->vf_trust_num + 1 :
					     pf->vf_trust_num - 1;
		if (pf->vf_trust_num <= 0)
			hw->vf.ops->set_vf_trust_vport_en(hw, false);
		else
			hw->vf.ops->set_vf_trust_vport_en(hw, true);
	}
	mutex_unlock(&vf->cfg_lock);

	return 0;
}
#endif

/**
 * mce_set_vf_spoofchk
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ena: flag to enable or disable feature
 *
 * Enable or disable VF spoof checking
 */
int mce_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int ret;

	if (!vf)
		return -EINVAL;

	if (ena == vf->vfinfo[vf_id].spoofchk_enabled) {
		dev_dbg(mce_pf_to_dev(pf), "VF:%d spoofchk already %s\n",
			vf_id, ena ? "ON" : "OFF");
		ret = 0;
		goto out;
	}

	mutex_lock(&vf->cfg_lock);
	vf->vfinfo[vf_id].spoofchk_enabled = ena;
	ret = mce_vf_apply_spoofchk(pf, vf_id, ena);
	mutex_unlock(&vf->cfg_lock);

out:
	return ret;
}

#ifdef CONFIG_PCI_IOV

static int __mce_enable_sriov(struct mce_pf *pf, unsigned int num_vfs)
{
	struct mce_hw *hw = &(pf->hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	/* Allocate memory for per VF control structures */
	vf->vfinfo = kcalloc(num_vfs + PFINFO_OFF,
			     sizeof(struct vf_data_storage), GFP_KERNEL);

	if (!vf->vfinfo)
		return -ENOMEM;
	/* reserve one for pf */
	vf->vfinfo = &vf->vfinfo[PFINFO_OFF];
	mce_realloc_and_fill_pfinfo(pf, true, true);
	mutex_init(&vf->cfg_lock);
	hw->vf.ops->set_vf_rebase_ring_base(hw);
	hw->vf.ops->set_vf_virtual_config(hw, true);
	hw->vf.ops->set_vf_dma_qs(hw, MCE_USER_CONFIG_VF_DMA_QS);
	hw->vf.ops->set_vf_emac_post_ctrl(hw, MCE_VF_VEB_VLAN_OUTER1, true,
					  MCE_VF_POST_CTRL_FILTER_TX_TO_RX,
					  true);
	hw->vf.ops->set_vf_trust_vport_en(hw, false);
	hw->vf.ops->set_vf_trusted(hw, PFINFO_IDX, true);
	hw->vf.ops->set_vf_default_vport(hw, PFINFO_IDX);

	/* when turn on sriov, pf take as vf, so we need close uc/mc L2 filter.
	 * used vf vlan filter table.
	 */
	hw->promisc_no_permit = false;
	hw->ops->set_uc_filter(hw, true);
	hw->ops->set_mc_filter(hw, true);
	hw->ops->set_vlan_filter(hw, false);
	hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX, false);
	hw->vf.ops->set_vf_set_vtag_vport_en(hw, PFINFO_IDX, true);
	hw->promisc_no_permit = true;
	return 0;
}

static int mce_vf_configuration(struct mce_pf *pf, int event_mask)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	unsigned char vf_mac_addr[ETH_ALEN];
	struct mce_hw *hw = &pf->hw;
	int vfn = event_mask;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);

	if (vfn != PFINFO_IDX) {
#ifdef MCE_DEBUG_VF
		vf_mac_addr[0] = 0xde;
		vf_mac_addr[1] = 0xa9;
		vf_mac_addr[2] = 0x5f;
		vf_mac_addr[3] = 0xd2;
		vf_mac_addr[4] = 0xd0;
		vf_mac_addr[5] = 0x40;
#else
		memcpy(vf_mac_addr, vsi->port_info->perm_addr, ETH_ALEN);
#endif
		vf_mac_addr[5] += 0x80 | vfn;
		vf_mac_addr[4] += pf->pdev->devfn;
		memcpy(vf->vfinfo[vfn].vf_mac_addresses, vf_mac_addr,
		       ETH_ALEN);
		vf->vfinfo[vfn].pf_vlan_entry = MCE_VF_UNUSED;
		vf->vfinfo[vfn].spoofchk_enabled = true;
		vf->vfinfo[vfn].trusted = false;
		hw->vf.ops->set_vf_spoofchk_mac(hw, vfn, true, true);
		hw->vf.ops->set_vf_spoofchk_vlan(hw, vfn, false,
						 MCE_VF_ANTI_VLAN_CLEAR);
	} else {
		memcpy(vf->vfinfo[PFINFO_IDX].vf_mac_addresses,
		       vsi->port_info->addr, ETH_ALEN);
		vf->vfinfo[PFINFO_IDX].pf_vlan_entry = MCE_VF_UNUSED;
		vf->vfinfo[PFINFO_IDX].spoofchk_enabled = true;
		vf->vfinfo[PFINFO_IDX].trusted = false;
		/* update pf anti mac */
		hw->vf.ops->set_vf_spoofchk_mac(hw, PFINFO_IDX, true,
						true);
		hw->vf.ops->set_vf_spoofchk_vlan(hw, PFINFO_IDX, false,
						 MCE_VF_ANTI_VLAN_CLEAR);
	}

	return 0;
}

int mce_disable_sriov(struct mce_pf *pf)
{
	struct mce_hw_func_caps *func_caps = &(pf->hw.func_caps);
	struct mce_hw *hw = &(pf->hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct device *dev = mce_pf_to_dev(pf);
	struct vf_data_storage *t_vfinfo = NULL;
	struct iidc_event *event;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EINVAL;
	clear_bit(MCE_FLAG_SRIOV_ENA, pf->flags);
	pf->num_vfs = hw->max_vfs = 0;
	hw->ops->set_fd_fltr_guar(hw);
	rdma_wr32(hw, N20_RDMA_REG_FUNC_SIZE, 0);
	hw->vf.ops->set_vf_rebase_ring_base(hw);
	hw->vf.ops->set_vf_virtual_config(hw, false);
	hw->vf.ops->set_vf_dma_qs(hw, MCE_VF_DMA_QS_UNDEFINED);
	hw->vf.ops->set_vf_emac_post_ctrl(hw, MCE_VF_VEB_VLAN_OUTER1, true,
					  MCE_VF_POST_CTRL_NORMAL, true);
	/* when turn on sriov, pf take as vf, so we need close uc/mc L2 filter */
	hw->promisc_no_permit = false;
	/* when turn off sriov, need restore promic to real setup*/
	mce_setup_L2_filter(pf);
	hw->vf.ops->set_vf_trusted(hw, PFINFO_IDX, false);
	hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX, true);
	hw->vf.ops->set_vf_set_vtag_vport_en(hw, PFINFO_IDX, false);

	/* realloc vfinfo and free vfinfo*/
	t_vfinfo = mce_realloc_and_fill_pfinfo(pf, false, true);
	if (t_vfinfo)
		t_vfinfo = &t_vfinfo[PFINFO_IDX];
	if (t_vfinfo != NULL) {
		kfree(t_vfinfo);
		t_vfinfo = NULL;
	}
	mutex_destroy(&vf->cfg_lock);

	pf->max_pf_txqs = hw->func_caps.common_cap.num_txq;
	pf->max_pf_rxqs = hw->func_caps.common_cap.num_rxq;
	func_caps->common_cap.rss_table_size = N20_RSS_PF_TABLE_SIZE;
#ifdef CONFIG_PCI_IOV
	/*
	 * If our VFs are assigned we cannot shut down SR-IOV
	 * without causing issues, so just leave the hardware
	 * available but disabled
	 */
	if (pci_vfs_assigned(pf->pdev)) {
		dev_err(dev,
			"Unloading driver while VFs are assigned - VFs will not be deallocated\n");
		return -EPERM;
	}
	/* disable iov and allow time for transactions to clear */
	pci_disable_sriov(pf->pdev);
#endif
	/* first disable sriov, then reinit mrdma */
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	set_bit(IIDC_EVENT_FUNC_SIZE_CHNG, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

	/* take a breather then clean up driver data */
	msleep(100);
	return 0;
}
#endif

static int mce_pci_sriov_enable(struct mce_pf *pf, int num_vfs)
{
#ifdef CONFIG_PCI_IOV
	int pre_existing_vfs = pci_num_vf(pf->pdev);
	int err = 0, i;
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_hw_func_caps *func_caps = &(pf->hw.func_caps);
	struct mce_hw *hw = &pf->hw;
	int val;
	struct iidc_event *event;

	if (pf->num_vfs == num_vfs)
		return -EINVAL;

	if (pre_existing_vfs && pre_existing_vfs != num_vfs)
		err = mce_disable_sriov(pf);
	else if (pre_existing_vfs && pre_existing_vfs == num_vfs)
		goto out;
	if (err)
		goto err_out;
	set_bit(MCE_FLAG_SRIOV_ENA, pf->flags);
	pf->num_vfs = hw->max_vfs = num_vfs;
	hw->ops->set_fd_fltr_guar(hw);
	val = 0;
	while ((1 << val) < (num_vfs + 1))
		val++;
	rdma_wr32(hw, N20_RDMA_REG_FUNC_SIZE, val);
	err = __mce_enable_sriov(pf, num_vfs);
	if (err)
		goto err_out;
	for (i = PFINFO_IDX; i < pf->num_vfs; i++)
		mce_vf_configuration(pf, i);

	pf->max_pf_txqs = func_caps->common_cap.vf_num_txq;
	pf->max_pf_rxqs = func_caps->common_cap.vf_num_rxq;
	func_caps->common_cap.rss_table_size = N20_RSS_VF_TABLE_SIZE;

	err = mce_sriov_reinit(pf);
	if (err)
		goto err_out;
	/* first reinit mrdma, then sriov */
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	set_bit(IIDC_EVENT_FUNC_SIZE_CHNG, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

	err = pci_enable_sriov(pf->pdev, num_vfs);
	if (err) {
		dev_err(dev, "Failed to enable PCI sriov: %d num %d\n",
			err, num_vfs);
		mce_disable_sriov(pf);
		mce_sriov_reinit(pf);
		goto err_out;
	}

out:
	return num_vfs;

err_out:
	clear_bit(MCE_FLAG_SRIOV_ENA, pf->flags);
	return err;

#endif /* CONFIG_PCI_IOV */
	return 0;
}

static int mce_pci_sriov_disable(struct mce_pf *pf)
{
	int err;
	struct mce_hw_func_caps *func_caps = &(pf->hw.func_caps);

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EINVAL;

	err = mce_disable_sriov(pf);
#ifdef CONFIG_PCI_IOV
	if (!err) {
		func_caps->common_cap.rss_table_size =
			N20_RSS_PF_TABLE_SIZE;
		mce_sriov_reinit(pf);
	}
#endif

	return err;
}

/**
 * mce_check_sriov_allowed - check if SR-IOV is allowed based on various checks
 * @pf: PF to enabled SR-IOV on
 */
static int mce_check_sriov_allowed(struct mce_pf *pf)
{
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev = vsi->netdev;
	struct mce_hw *hw = &pf->hw;
	struct mce_vlan_list_entry *vlan_entry = NULL;
	int vlan_cnt = 0;

	if (!test_bit(MCE_FLAG_SRIOV_CAPABLE, pf->flags)) {
		dev_err(dev, "This device is not capable of SR-IOV\n");
		return -EOPNOTSUPP;
	}

	if (netdev_mc_count(netdev) > MCE_MAX_MC_WHITE_LISTS) {
		dev_err(dev,
			"The multicast nums cannot exceeds maximum allowed: %d"
			" before turn on sriov\n",
			MCE_MAX_MC_WHITE_LISTS);
		return -EOPNOTSUPP;
	}

	list_for_each_entry(vlan_entry, &hw->vlan_list_head, vlan_node) {
		vlan_cnt++;
		if (vlan_cnt > MCE_MAX_VF_VLAN_WHITE_LISTS) {
			dev_err(dev,
				"The vlan nums cannot exceeds maximum allowed: %d"
				" before turn on sriov\n",
				MCE_MAX_VF_VLAN_WHITE_LISTS);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

/**
 * mce_sriov_configure - Enable or change number of VFs via sysfs
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of VFs to allocate or 0 to free VFs
 *
 * This function is called when the user updates the number of VFs in sysfs. On
 * success return whatever num_vfs was set to by the caller. Return negative on
 * failure.
 */
int mce_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct mce_pf *pf = pci_get_drvdata(pdev);
	int err;

	err = mce_check_sriov_allowed(pf);
	if (err)
		return err;
	if (num_vfs == 0)
		return mce_pci_sriov_disable(pf);
	else
		return mce_pci_sriov_enable(pf, num_vfs);
}
