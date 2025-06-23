#include "mce.h"
#include "mce_type.h"
#include "mce_base.h"
#include "mce_lib.h"
#include "mce_sriov.h"
#include "mce_virtchnl.h"
#include "mce_vf_lib.h"

int N20_FPGA_VFNUM(struct mce_hw *hw, int vfid)
{
	int vfnum = 0;
#ifdef MCE_DEBUG_XINSI_PCIE
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		vfnum = (vfid == PFINFO_IDX) ? pf->max_vfs : (vfid);
#else
	vfnum = (vfid == PFINFO_IDX) ? 0 : vfid + 1;
#endif
	return vfnum;
}

static int mce_vf_find_vlan_loc(struct mce_pf *pf, int vf_id,
				  u16 vlan_id)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int i = 0;

	for (i = 0; i < MCE_MAX_VF_VLAN_WHITE_LISTS; i++) {
		if (vf->vfinfo[vf_id].vf_vlan[i].vid == vlan_id)
			return i;
	}
	return -1;
}

int mce_vf_setup_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int loc, avail_id;

	loc = mce_vf_find_vlan_loc(pf, vf_id, vlan_id);
	if (loc >= 0) {
		dev_info(mce_hw_to_dev(hw),
			 "%s vf:%d vlan id:%d had beed setuped, exit!\n",
			 __func__, N20_FPGA_VFNUM(hw, vf_id), vlan_id);
		return -1;
	}

	avail_id = find_first_zero_bit(vf->vfinfo[vf_id].avail_vlan,
				       MCE_MAX_VF_VLAN_WHITE_LISTS);
	if (avail_id >= MCE_MAX_VF_VLAN_WHITE_LISTS) {
		dev_info(
			mce_hw_to_dev(hw),
			"%s vf:%d the vlan nums exceeds maximum allowed:%d\n",
			__func__, N20_FPGA_VFNUM(hw, vf_id),
			MCE_MAX_VF_VLAN_WHITE_LISTS);
		return -1;
	}
	set_bit(avail_id, vf->vfinfo[vf_id].avail_vlan);
	vf->vfinfo[vf_id].vf_vlan[avail_id].vid = vlan_id;
	vf->t_info.entry = avail_id;
	vf->t_info.vlanid = vlan_id;
	//dev_info(mce_hw_to_dev(hw), "add vlan: vf:%d vid:%d loc:%d\n",
	//	 vf_id, vlan_id, avail_id);
	mce_vf_set_veb_misc_rule(hw, vf_id,
				   __VEB_POLICY_TYPE_UC_ADD_VLAN);

	return 0;
}

int mce_vf_del_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int loc;

	loc = mce_vf_find_vlan_loc(pf, vf_id, vlan_id);
	if (loc < 0) {
		dev_info(mce_hw_to_dev(hw),
			 "%s vf:%d vlan id:%d not exist, exit!\n",
			 __func__, N20_FPGA_VFNUM(hw, vf_id), vlan_id);
		return -1;
	}

	// dev_info(mce_hw_to_dev(hw), "del vlan: vf:%d vid:%d loc:%d\n",
	// 	 vf_id, vlan_id, loc);
	clear_bit(loc, vf->vfinfo[vf_id].avail_vlan);
	vf->t_info.entry = loc;
	mce_vf_set_veb_misc_rule(hw, vf_id,
				   __VEB_POLICY_TYPE_UC_DEL_VLAN);
	vf->vfinfo[vf_id].vf_vlan[loc].vid = 0;
	vf->vfinfo[vf_id].vf_vlan[loc].qos = 0;

	return 0;
}

int mce_vf_setup_true_promisc(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int i;

	/* turn on pf true promisc */
	hw->vf.ops->set_vf_true_promisc(hw, PFINFO_IDX, true);

	if (!vf || !vf->vfinfo)
		return 0;

	for (i = 0; i < pf->num_vfs; i++) {
		if (vf->vfinfo[i].trusted)
			hw->vf.ops->set_vf_true_promisc(hw, i, true);
		else
			hw->vf.ops->set_vf_true_promisc(hw, i, false);
	}

	return 0;
}

int mce_vf_del_true_promisc(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int i;

	/* turn on pf true promisc */
	hw->vf.ops->set_vf_true_promisc(hw, PFINFO_IDX, false);

	if (!vf || !vf->vfinfo)
		return 0;

	for (i = 0; i < pf->num_vfs; i++)
		hw->vf.ops->set_vf_true_promisc(hw, i, false);

	return 0;
}

int mce_vf_setup_rqa_tcp_sync_en(struct mce_pf *pf, bool on)
{
	struct mce_hw *hw = &pf->hw;

	/* turn on tcp sync enable */
	hw->vf.ops->set_vf_rqa_tcp_sync_en(hw, on);
	return 0;
}

static int mce_vf_ena_spoofchk(struct mce_pf *pf, int vfid)
{
	struct mce_hw *hw = &pf->hw;

	hw->vf.ops->set_vf_spoofchk_mac(hw, vfid, true, false);
	hw->vf.ops->set_vf_spoofchk_vlan(hw, vfid, true,
					 MCE_VF_ANTI_VLAN_HOLD);

	return 0;
}

static int mce_vf_dis_spoofchk(struct mce_pf *pf, int vfid)
{
	struct mce_hw *hw = &pf->hw;

	hw->vf.ops->set_vf_spoofchk_mac(hw, vfid, false, false);
	hw->vf.ops->set_vf_spoofchk_vlan(hw, vfid, false,
					 MCE_VF_ANTI_VLAN_HOLD);
	return 0;
}

/**
 * mce_vf_apply_spoofchk - Apply Tx spoof checking setting
 * @pf: associated to the pf
 * @vfid: config vf number
 * @enable: whether to enable or disable the spoof checking
 */
int mce_vf_apply_spoofchk(struct mce_pf *pf, int vfid, bool enable)
{
	int err;

	if (enable)
		err = mce_vf_ena_spoofchk(pf, vfid);
	else
		err = mce_vf_dis_spoofchk(pf, vfid);
	return err;
}

/**
 * mce_vf_set_trusted - set vf trusted
 * @pf: associated to the pf
 * @vfid: config vf number
 * @enable: whether to enable or disable the spoof checking
 */
int mce_vf_set_trusted(struct mce_pf *pf, int vfid, bool enable)
{
	struct mce_hw *hw = &pf->hw;
	int err = 0;

	hw->vf.ops->set_vf_trusted(hw, vfid, enable);
	/* TODO: when trust on, the spoof mac/van enble bit should clear */
	return err;
}

int mce_vf_resync_mc_list(struct mce_pf *pf, bool to_pfvf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev = vsi->netdev;
	struct netdev_hw_addr *ha;
	struct mce_hw *hw = &pf->hw;

	if (netdev_mc_empty(netdev))
		return 0;

	if (to_pfvf) {
		/* clear pfvf multicast addr filter table */
		hw->vf.ops->set_vf_clear_mc_filter(hw, true);
		/* copy pf multicast filter table to pfvf */
		netdev_for_each_mc_addr(ha, netdev)
			hw->vf.ops->set_vf_add_mc_fliter(hw, ha->addr);
	} else {
		/* clear pf multicast filter table*/
		hw->ops->clr_mc_filter(hw);
		netdev_for_each_mc_addr(ha, netdev) {
			/* clear pfvf multicast filter table */
			hw->vf.ops->set_vf_del_mc_filter(hw, ha->addr);
			hw->ops->add_mc_filter(hw, ha->addr);
		}
	}
	return 0;
}

int mce_vf_resync_vlan_list(struct mce_pf *pf, bool to_pfvf)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_vlan_list_entry *vlan_entry = NULL;
	u16 vid;

	list_for_each_entry(vlan_entry, &hw->vlan_list_head, vlan_node) {
		vid = vlan_entry->vid;
		if (to_pfvf) {
			/* del pf vlan and add pfvf vlan*/
			hw->ops->del_vlan_filter(hw, vid);
			mce_vf_setup_vlan(pf, PFINFO_IDX, vid);
		} else {
			/* del vfpf vlan and add pf vlan */
			mce_vf_del_vlan(pf, PFINFO_IDX, vid);
			hw->ops->add_vlan_filter(hw, vid);
		}
	}

	return 0;
}

static int __set_veb_vm_add_uc_macaddr_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_uc_addr_offset + vfid;
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, true);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);

	return 0;
}

static int __set_veb_vm_add_uc_macaddr_with_act_rule(struct mce_hw *hw,
						     int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_uc_addr_offset + vfid;
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, true);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);
	hw->vf.ops->set_vf_set_veb_act(hw, vfid, entry, true,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int
__set_veb_vm_add_macvlan_macaddr_with_act_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_macvlan_addr_offset + vfid +
		vf->t_info.index * MCE_VM_MAX_VF_MACVLAN_NUMS;
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, true);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);
	hw->vf.ops->set_vf_set_veb_act(hw, vfid, entry, true,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int __set_veb_vm_add_bcmc_macaddr_rule(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	memset(vf->t_info.macaddr, 0xff, ETH_ALEN);
	entry = hw->vf_bcmc_addr_offset;
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);

	return 0;
}

static int __set_veb_vm_add_bcmc_macaddr_with_act_rule(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	memset(vf->t_info.macaddr, 0xff, ETH_ALEN);
	entry = hw->vf_bcmc_addr_offset;
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);
	hw->vf.ops->set_vf_set_veb_act(hw, PFINFO_BCMC, entry, true,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int __set_veb_vm_del_uc_macaddr_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_uc_addr_offset + vfid;
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, false);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	return 0;
}

static int __set_veb_vm_del_uc_macaddr_with_act_rule(struct mce_hw *hw,
						     int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_uc_addr_offset + vfid;
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, false);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	hw->vf.ops->set_vf_set_veb_act(hw, vfid, entry, false,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int
__set_veb_vm_del_macvlan_macaddr_with_act_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_macvlan_addr_offset + vfid +
		vf->t_info.index * MCE_VM_MAX_VF_MACVLAN_NUMS;
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, false);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	hw->vf.ops->set_vf_set_veb_act(hw, vfid, entry, false,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int __set_veb_vm_del_bcmc_macaddr_rule(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_bcmc_addr_offset;
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	return 0;
}

static int __set_veb_vm_del_bcmc_macaddr_with_act_rule(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_bcmc_addr_offset;
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	hw->vf.ops->set_vf_set_veb_act(hw, PFINFO_BCMC, entry, false,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int __set_veb_vm_add_uc_vlan_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry = vf->t_info.entry;

	hw->vf.ops->set_vf_add_vlan_filter(hw, vfid, entry);
	return 0;
}

static int __set_veb_vm_del_uc_vlan_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry = vf->t_info.entry;

	hw->vf.ops->set_vf_del_vlan_filter(hw, vfid, entry);
	return 0;
}

int mce_vf_set_veb_misc_rule(struct mce_hw *hw, int vfid,
			       enum veb_policy_type ptype)
{
	if (ptype == __VEB_POLICY_TYPE_NONE ||
	    ptype >= __VEB_POLICY_TYPE_MAX)
		return 0;

	switch (ptype) {
	case __VEB_POLICY_TYPE_UC_ADD_MACADDR:
		__set_veb_vm_add_uc_macaddr_rule(hw, vfid);
		break;
	case __VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT:
		__set_veb_vm_add_uc_macaddr_with_act_rule(hw, vfid);
		break;
	case __VEB_POLICY_TYPE_MACVLAN_ADD_MACADDR_WITH_ACT:
		__set_veb_vm_add_macvlan_macaddr_with_act_rule(hw, vfid);
		break;
	case __VEB_POLICY_TYPE_UC_DEL_MACADDR:
		__set_veb_vm_del_uc_macaddr_rule(hw, vfid);
		break;
	case __VEB_POLICY_TYPE_UC_DEL_MACADDR_WITH_ACT:
		__set_veb_vm_del_uc_macaddr_with_act_rule(hw, vfid);
		break;
	case __VEB_POLICY_TYPE_MACVLAN_DEL_MACADDR_WITH_ACT:
		__set_veb_vm_del_macvlan_macaddr_with_act_rule(hw, vfid);
		break;
	case __VEB_POLICY_TYPE_BCMC_ADD_MACADDR:
		__set_veb_vm_add_bcmc_macaddr_rule(hw);
		break;
	case __VEB_POLICY_TYPE_BCMC_ADD_MACADDR_WITH_ACT:
		__set_veb_vm_add_bcmc_macaddr_with_act_rule(hw);
		break;
	case __VEB_POLICY_TYPE_BCMC_DEL_MACADDR:
		__set_veb_vm_del_bcmc_macaddr_rule(hw);
		break;
	case __VEB_POLICY_TYPE_BCMC_DEL_MACADDR_WITH_ACT:
		__set_veb_vm_del_bcmc_macaddr_with_act_rule(hw);
		break;
	case __VEB_POLICY_TYPE_UC_ADD_VLAN:
		__set_veb_vm_add_uc_vlan_rule(hw, vfid);
		break;
	case __VEB_POLICY_TYPE_UC_DEL_VLAN:
		__set_veb_vm_del_uc_vlan_rule(hw, vfid);
		break;
	default:
		break;
	}

	return 0;
}
