#include "mce.h"
#include "mce_virtchnl.h"

int mce_msg_post_status_signle(struct mce_pf *pf, enum PF_STATUS status,
			       int vfid)
{
	u32 msgbuf[MCE_VFMAILBOX_SIZE];
	struct mce_hw *hw = &(pf->hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	switch (status) {
	case PF_SET_VLAN_STATUS:
		msgbuf[0] = MCE_PF_SET_VLAN | (vfid << MCE_VNUM_OFFSET);
		msgbuf[1] = vf->vfinfo[vfid].pf_vlan;
		break;
	case PF_SET_RESET_STATUS:
		msgbuf[0] = MCE_PF_SET_RESET | (vfid << MCE_VNUM_OFFSET);
		msgbuf[1] = 0;
		break;
	default:
		return 0;
	}

	return mce_write_mbx(hw, msgbuf, 2, vfid);
}

static int mce_vf_reset_msg(struct mce_hw *hw, u32 vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 msgbuf[MCE_VF_RESET_MSG_LEN];
	unsigned char *vf_mac = vf->vfinfo[vfid].vf_mac_addresses;
	u8 *addr = (u8 *)(&msgbuf[1]);

	msgbuf[0] = MCE_VF_RESET;
	if (!is_zero_ether_addr(vf_mac)) {
		msgbuf[0] |= MCE_VT_MSGTYPE_ACK;
		memcpy(addr, vf_mac, ETH_ALEN);
	} else {
		dev_warn(
			mce_hw_to_dev(hw),
			"VF %d has no MAC address assigned, you may have to assign "
			"one manually\n",
			vfid);
	}

	//if (!vf->vfinfo[vfid].clear_to_send)
	//	vf->vfinfo[vfid].intr_enabled = false;
	/* enable VF mailbox for further messages */
	vf->vfinfo[vfid].clear_to_send = true;
	msgbuf[F_VF_RESET_RING_MAX_CNT] = hw->ring_max_cnt;
	msgbuf[F_VF_RESET_VLAN] = vf->vfinfo[vfid].pf_vlan;
	/* first vf mbx command with no intrrupt */
	mce_write_mbx(hw, msgbuf, MCE_VF_RESET_MSG_LEN, vfid);
	mutex_lock(&vf->cfg_lock);
	ether_addr_copy(vf->t_info.macaddr, vf_mac);
	vf->t_info.bcmc_bitmap = MCE_F_SET;
	mce_vf_set_veb_misc_rule(
		hw, vfid, __VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT);
	mutex_unlock(&vf->cfg_lock);
	return 0;
}

static int mce_vf_set_intr_en(struct mce_hw *hw, u32 *msgbuf, u32 vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	vf->vfinfo[vfid].intr_enabled = !!msgbuf[1];
	return 0;
}

static int mce_vf_set_vlan_msg(struct mce_hw *hw, u32 *msgbuf, u32 vf_id)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int add = ((msgbuf[0] & MCE_VT_MSGINFO_MASK) >>
		   MCE_VT_MSGINFO_SHIFT);
	int vid = (msgbuf[1] & MCE_VLVF_VLANID_MASK);

	/* vlan 0 has no work to do */
	if (!vid)
		return 0;

	mutex_lock(&vf->cfg_lock);
	if (add)
		mce_vf_setup_vlan(pf, vf_id, vid);
	else
		mce_vf_del_vlan(pf, vf_id, vid);
	mutex_unlock(&vf->cfg_lock);
	return 0;
}

static int mce_vf_set_vlan_strip_msg(struct mce_hw *hw, u32 *msgbuf,
				     u32 vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	// bool vlan_strip_on = !!(msgbuf[1] >> 31);
	// int queue_cnt = msgbuf[1] & 0xffff;

	mutex_lock(&vf->cfg_lock);
	// hw->vf.ops->set_vf_vlan_strip(hw, vfid, vlan_strip_on);
	mutex_unlock(&vf->cfg_lock);

	return 0;
}

static int mce_vf_set_mac_addr(struct mce_hw *hw, u32 *msgbuf, u32 vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u8 *new_mac = ((u8 *)(&msgbuf[1]));

	if (!is_valid_ether_addr(new_mac)) {
		dev_err(mce_hw_to_dev(hw),
			"VF %d attempted to set invalid mac addr\n", vfid);
		return -1;
	}

	ether_addr_copy(vf->vfinfo[vfid].vf_mac_addresses, new_mac);
	ether_addr_copy(vf->t_info.macaddr, new_mac);
	vf->t_info.bcmc_bitmap = MCE_F_HOLD;
	mutex_lock(&vf->cfg_lock);
	mce_vf_set_veb_misc_rule(
		hw, vfid, __VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT);
	/* Update antispoof mac addr */
	hw->vf.ops->set_vf_spoofchk_mac(
		hw, vfid, vf->vfinfo[vfid].spoofchk_enabled, true);
	mutex_unlock(&vf->cfg_lock);

	return 0;
}

static int mce_vf_set_macvlan_addr(struct mce_hw *hw, u32 *msgbuf,
				   u32 vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u8 *new_mac = ((u8 *)(&msgbuf[2]));

	if (!is_valid_ether_addr(new_mac)) {
		dev_err(mce_hw_to_dev(hw),
			"VF %d attempted to set invalid mac addr\n", vfid);
		return -1;
	}

	ether_addr_copy(vf->t_info.macaddr, new_mac);
	vf->t_info.index = msgbuf[1];
	vf->t_info.bcmc_bitmap = MCE_F_HOLD;
	mutex_lock(&vf->cfg_lock);
	mce_vf_set_veb_misc_rule(
		hw, vfid, __VEB_POLICY_TYPE_MACVLAN_ADD_MACADDR_WITH_ACT);
	mutex_unlock(&vf->cfg_lock);

	return 0;
}

static int mce_vf_del_macvlan_addr(struct mce_hw *hw, u32 *msgbuf,
				   u32 vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u8 *new_mac = ((u8 *)(&msgbuf[2]));

	if (!is_valid_ether_addr(new_mac)) {
		dev_err(mce_hw_to_dev(hw),
			"VF %d attempted to set invalid mac addr\n", vfid);
		return -1;
	}

	ether_addr_copy(vf->t_info.macaddr, new_mac);
	vf->t_info.index = msgbuf[1];
	vf->t_info.bcmc_bitmap = MCE_F_HOLD;
	mutex_lock(&vf->cfg_lock);
	mce_vf_set_veb_misc_rule(
		hw, vfid, __VEB_POLICY_TYPE_MACVLAN_DEL_MACADDR_WITH_ACT);
	mutex_unlock(&vf->cfg_lock);

	return 0;
}

static int mce_vf_set_promisc_mode(struct mce_hw *hw, u32 *msgbuf,
				   u32 vfid)
{
	u32 flags = msgbuf[1];

	switch (flags) {
	case FLAG_VF_NONE_PROMISC:
		break;
	case FLAG_VF_MULTICAST_PROMISC:
		break;
	case FLAG_VF_UNICAST_PROMISC | FLAG_VF_MULTICAST_PROMISC:
		break;

	default:
		break;
	}

	return 0;
}

static int mce_rcv_msg_from_vf(struct mce_hw *hw, u32 vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 mbx_size = MCE_VFMAILBOX_SIZE;
	u32 msgbuf[MCE_VFMAILBOX_SIZE];
	s32 retval;

	retval = mce_read_mbx(hw, msgbuf, mbx_size, vfid);
	if (retval) {
		dev_err(mce_hw_to_dev(hw),
			"Error receiving message from VF:%d\n", vfid);
		return retval;
	}

	/* this is a message we already processed, do nothing */
	if (msgbuf[0] & (MCE_VT_MSGTYPE_ACK | MCE_VT_MSGTYPE_NACK))
		return retval;

	/* clear vf num */
	msgbuf[0] &= (~MCE_VF_MASK);
	/* this is a vf reset request */
	if ((msgbuf[0] & MCE_MAIL_CMD_MASK) == MCE_VF_RESET) {
		return mce_vf_reset_msg(hw, vfid);
	}

	if (!vf->vfinfo[vfid].clear_to_send) {
		msgbuf[0] |= MCE_VT_MSGTYPE_NACK;
		mce_write_mbx(hw, msgbuf, 1, vfid);
		return retval;
	}

	switch ((msgbuf[0] & MCE_MAIL_CMD_MASK)) {
	case MCE_VF_SET_MBX_INTR_EN:
		retval = mce_vf_set_intr_en(hw, msgbuf, vfid);
		break;
	case MCE_VF_SET_VLAN:
		retval = mce_vf_set_vlan_msg(hw, msgbuf, vfid);
		break;
	case MCE_VF_SET_VLAN_STRIP:
		retval = mce_vf_set_vlan_strip_msg(hw, msgbuf, vfid);
		break;
	case MCE_VF_SET_MAC_ADDR:
		retval = mce_vf_set_mac_addr(hw, msgbuf, vfid);
		break;
	case MCE_VF_SET_PROMISC_MODE:
		retval = mce_vf_set_promisc_mode(hw, msgbuf, vfid);
		break;
	case MCE_VF_SET_MACVLAN_ADDR:
		retval = mce_vf_set_macvlan_addr(hw, msgbuf, vfid);
		break;
	case MCE_VF_DEL_MACVLAN_ADDR:
		retval = mce_vf_del_macvlan_addr(hw, msgbuf, vfid);
		break;
	default:
		dev_err(mce_hw_to_dev(hw),
			"recv vf unknown cmd, vfnum:%d msg0:%8.8x\n", vfid,
			msgbuf[0]);
		retval = MCE_ERR_MBX;
		break;
	}
	/* notify the VF of the results of what it sent us */
	if (retval)
		msgbuf[0] |= MCE_VT_MSGTYPE_NACK;
	else
		msgbuf[0] |= MCE_VT_MSGTYPE_ACK;
	msgbuf[0] |= (vfid << 21);
	msgbuf[0] |= MCE_VT_MSGTYPE_CTS;
	if ((msgbuf[0] & MCE_MAIL_CMD_MASK) != MCE_VF_REMOVED)
		mce_write_mbx(hw, msgbuf, mbx_size, vfid);

	return 0;
}

static void mce_rcv_ack_from_vf(struct mce_hw *hw, u32 vfid)
{
	u32 msg = MCE_VT_MSGTYPE_NACK;
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	if (!vf->vfinfo[vfid].clear_to_send)
		mce_write_mbx(hw, &msg, 1, vfid);
}

int mce_vc_process_mailbox_msg(struct mce_pf *pf, enum MBX_ID mbx_id)
{
	struct mce_hw *hw = &(pf->hw);
	int ret = -1;

	if ((mbx_id == MBX_FW))
		return -1;

	ret = mce_check_for_msg(hw, mbx_id);
	if (ret == MBX_RET_SUCCESS)
		mce_rcv_msg_from_vf(hw, mbx_id);

	ret = mce_check_for_ack(hw, mbx_id);
	if (ret == MBX_RET_SUCCESS)
		mce_rcv_ack_from_vf(hw, mbx_id);

	return ret;
}
