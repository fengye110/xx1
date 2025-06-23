/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022 - 2024 Mucse Corporation */
#include "mce.h"
#include "mce_base.h"
#include "mce_netdev.h"
#include "mce_txrx_lib.h"
#ifdef MCE_SYSFS
#include <linux/module.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/time.h>
#include "mce_vf_lib.h"
#include "mce_fwchnl.h"
#include "mucse_auxiliary/mce_idc.h"
#include "mce_n20/mce_hw_n20.h"

#define to_net_device(n) container_of(n, struct net_device, dev)

static ssize_t test_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	int ret = 0;
	struct net_device *netdev = mce_device_to_netdev(dev);
	if (!netif_carrier_ok(netdev)) {
		netif_carrier_on(netdev);
		printk("set link on\n");
	} else if (netif_carrier_ok(netdev)) {
		netif_carrier_off(netdev);
		printk("set link off\n");
	}

	return ret;
}

static ssize_t test_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	return count;
}

static ssize_t default_vport_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	int ret = 0;

	ret = sprintf(buf, "default vport:%d\n", pf->default_vport);
	return ret;
}

static ssize_t default_vport_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &(pf->hw);
	s32 d_vport = 0;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EPERM;

	if (kstrtos32(buf, 10, &d_vport))
		return -EINVAL;

	/* if d_vport less than zero, restore default config,
	 * other setup the default vport.
	 */
	if (d_vport < 0)
		d_vport = PFINFO_IDX;
	if (d_vport >= pf->num_vfs)
		return -EINVAL;
	pf->default_vport = d_vport;
	hw->vf.ops->set_vf_default_vport(hw, d_vport);
	return count;
}

static void to_binary(u16 num, char *binary_str, int bits) {
	int i;
	for (i = bits - 1; i >= 0; i--) {
		binary_str[bits - 1 - i] = (num & (1 << i)) ? '1' : '0';
	}

	binary_str[bits] = '\0';
}

static ssize_t nic_prio_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int ret = 0;
	char string[30];

	to_binary(vsi->valid_prio, string, 8);


	ret = sprintf(buf, " nic prio %s\n", string);
	return ret;
}

static ssize_t nic_prio_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	u16 valid = 0;
	struct iidc_event *event;

	if (kstrtos16(buf, 2, &valid))
		return -EINVAL;
	/* should never 0 */
	if (valid == 0)
		return -EINVAL;
	// if all zero, should return 
	if ((valid & 0xff) == 0)
		return -EINVAL;
	// if mrdma driver on, we must reseve prio7
	if (pf->m_status == MRDMA_INSMOD) {
		if (valid & 0x80) {
			printk("never use prio 7 if MRDMA_INSMOD\n");
			return -EINVAL;
		}
	}

	vsi->valid_prio = valid & 0xff;
	// nic valid prio, should mask rdma
	cdev_info->valid_prio = (~vsi->valid_prio);

	event = kzalloc(sizeof(*event), GFP_KERNEL);

	set_bit(IIDC_EVENT_PRIO_CHNG, event->type);
	//set_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

	return count;
}

static ssize_t rdma_prio_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	int ret = 0;
	char string[30];

	to_binary(cdev_info->valid_prio, string, 8);

	ret = sprintf(buf, "rdma prio %s\n", string);
	return ret;
}

static ssize_t rdma_prio_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	u16 valid = 0;
	struct iidc_event *event;

	if (kstrtos16(buf, 2, &valid))
		return -EINVAL;
	if (valid == 0xff)
		return -EINVAL;

	cdev_info->valid_prio = valid & 0xff;

	vsi->valid_prio = (~cdev_info->valid_prio);

	// if mrdma insmod, should never use prio7
	if (pf->m_status == MRDMA_INSMOD)
		vsi->valid_prio &= 0x7f;

	event = kzalloc(sizeof(*event), GFP_KERNEL);

	set_bit(IIDC_EVENT_PRIO_CHNG, event->type);
	//set_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

	return count;
}

static ssize_t tx_debug_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	int ret = 0;

	ret = sprintf(buf, "debug tx queue:%d\n", pf->debug_tx);
	return ret;
}

static ssize_t tx_debug_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	s32 debug_tx = 0;

	if (kstrtos32(buf, 10, &debug_tx))
		return -EINVAL;

	pf->debug_tx = debug_tx;
	return count;
}

static ssize_t tx_drop_en_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	s32 debug_tx = 0;

	if (kstrtos32(buf, 10, &debug_tx))
		return -EINVAL;

	pf->tx_drop_en = debug_tx;
	return count;
}

static int __mce_check_dvlan(u32 proto, u32 id, enum mce_dvlan_type *type)
{
	if (proto == 0x8100)
		*type = MCE_VLAN_TYPE_8100;
	else if (proto == 0x88a8)
		*type = MCE_VLAN_TYPE_88a8;
	else
		return -EINVAL;
	if (id <= 0 || id >= 4095)
		return -EINVAL;

	return 0;
}

static ssize_t set_dvlan_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_dvlan_ctrl *dvc = &pf->dvlan_ctrl;
	int ret = 0;

	ret = sprintf(buf,
		      "double vlan: enable:%d \n"
		      "outer_vlan_type:0x%s outer_vlan_vid:%d\n"
		      "inner_vlan_type:0x%s inner_vlan_vid:%d\n",
		      dvc->en,
		      dvc->outer_hdr.type == MCE_VLAN_TYPE_8100 ? "8100" :
								  "88a8",
		      dvc->outer_hdr.vid,
		      dvc->inner_hdr.type == MCE_VLAN_TYPE_8100 ? "8100" :
								  "88a8",
		      dvc->inner_hdr.vid);
	return ret;
}

static ssize_t set_dvlan_store(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &pf->hw;
	struct mce_vf *vf = NULL;
	int cnt = 0;
	struct mce_dvlan_ctrl *dvc = &pf->dvlan_ctrl;
	int o_proto, i_proto;

	memset(dvc, 0, sizeof(struct mce_dvlan_ctrl));
	/* enable(1/0) + outer_vlan_type(8100/88a8) + outer_vlan_vla(vid) + 
	 * inner_vlan_type(8100/88a8) + inner_vlan_val(vid) */
	cnt = sscanf(buf, "%d %x %hd %x %hd", &dvc->en, &o_proto,
		     &dvc->outer_hdr.vid, &i_proto, &dvc->inner_hdr.vid);
	if (cnt != 5)
		return -EINVAL;

	if (__mce_check_dvlan(o_proto, dvc->outer_hdr.vid,
			      &dvc->outer_hdr.type))
		return -EINVAL;
	if (__mce_check_dvlan(i_proto, dvc->inner_hdr.vid,
			      &dvc->inner_hdr.type))
		return -EINVAL;

	if (dvc->en) {
		set_bit(MCE_FLAG_VF_INSERT_VLAN, pf->flags);
		pf->vlan_strip_cnt = 2;
		dvc->cnt = 2;
		hw->ops->set_vlan_strip(hw, netdev->features);

#ifdef NETIF_F_HW_VLAN_CTAG_RX
		netdev->features &= ~NETIF_F_HW_VLAN_CTAG_RX;
#endif
#ifdef NETIF_F_HW_VLAN_CTAG_TX
		netdev->features &= ~NETIF_F_HW_VLAN_CTAG_TX;
#endif

#ifdef NETIF_F_HW_VLAN_STAG_RX
		netdev->features &= ~NETIF_F_HW_VLAN_STAG_RX;
#endif
#ifdef NETIF_F_HW_VLAN_STAG_TX
		netdev->features &= ~NETIF_F_HW_VLAN_STAG_TX;
#endif
		/* enable vlan filter */
		hw->ops->add_vlan_filter(hw, dvc->outer_hdr.vid);
		if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
			return count;
		vf = mce_pf_to_vf(pf);
		if (!vf || !vf->vfinfo)
			return count;
		/* pf take as vf 0, when turn on sriov */
		mutex_lock(&vf->cfg_lock);
		mce_vf_setup_vlan(pf, PFINFO_IDX, dvc->outer_hdr.vid);
		mutex_unlock(&vf->cfg_lock);
	} else {
		/* disable vlan filter */
		hw->ops->del_vlan_filter(hw, pf->dvlan_ctrl.outer_hdr.vid);
		if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
			vf = mce_pf_to_vf(pf);
			if (vf && vf->vfinfo) {
				mutex_lock(&vf->cfg_lock);
				mce_vf_del_vlan(
					pf, PFINFO_IDX,
					pf->dvlan_ctrl.outer_hdr.vid);
				mutex_unlock(&vf->cfg_lock);
			}
		}
		memset(&pf->dvlan_ctrl, 0, sizeof(struct mce_dvlan_ctrl));
		clear_bit(MCE_FLAG_VF_INSERT_VLAN, pf->flags);
#ifdef NETIF_F_HW_VLAN_CTAG_RX
		netdev->features |= NETIF_F_HW_VLAN_CTAG_RX;
#endif
#ifdef NETIF_F_HW_VLAN_CTAG_TX
		netdev->features |= NETIF_F_HW_VLAN_CTAG_TX;
#endif

#ifdef NETIF_F_HW_VLAN_STAG_RX
		netdev->features |= NETIF_F_HW_VLAN_STAG_RX;
#endif
#ifdef NETIF_F_HW_VLAN_STAG_TX
		netdev->features |= NETIF_F_HW_VLAN_STAG_TX;
#endif
		pf->vlan_strip_cnt = 1;
		hw->ops->set_vlan_strip(hw, netdev->features);
	}

	return count;
}

struct mce_reg_info {
	u8 log_info[32];
	u32 cond;
	bool verbose_en;
	u16 offset;
};

struct mce_reg_info mce_fd_profileid_debug[] = {
	{ "fsm_cnt", GENMASK(1, 0), true, 0 },
	{ "fsm_nt", GENMASK(3, 2), true, 2 },
	{ "entry_match", GENMASK(4, 4), true, 4 },
	{ "entry_end", GENMASK(5, 5), true, 5 },
	{ "entry_timeout", GENMASK(6, 6), true, 6 },
	{ "pkt_port_ena_r", GENMASK(7, 7), true, 7 },
	{ "pkt_ipv6_ena_r", GENMASK(8, 8), true, 8 },
	{ "pkt_port_r", GENMASK(15, 9), true, 9 },
	{ "pkt_profile_r", GENMASK(21, 16), true, 16 },
};

static int mce_dump_logs(struct mce_hw *hw, struct mce_reg_info *data_base,
			 u16 item_num, u32 dump_reg, char *buf, int ret)
{
	u32 value = 0;
	u16 i = 0;

	value = rd32(hw, dump_reg);
	for (i = 0; i < item_num; i++) {
		if (data_base[i].cond & value) {
			if (data_base[i].verbose_en) {
				ret += sprintf(
					buf + ret, "%s 0x%x\n",
					data_base[i].log_info,
					(value & data_base[i].cond) >>
						data_base[i].offset);
			} else {
				ret += sprintf(buf + ret, "%s\n",
					       data_base[i].log_info);
			}
		}
	}

	return ret;
}

static u32 mce_fd_debug_cmd(struct mce_hw *hw, u32 cmd)
{
	u32 ctrl = 0;

	ctrl = rd32(hw, 0xf0000);
	ctrl &= ~GENMASK(31, 27);
	ctrl |= cmd << 27;
	wr32(hw, 0xf0000, ctrl);

	return 0;
}

static ssize_t fd_rx_debug_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &pf->hw;
	int ret = 0;

	mce_fd_debug_cmd(hw, 0 << 1);
	ret = mce_dump_logs(hw, mce_fd_profileid_debug,
			    ARRAY_SIZE(mce_fd_profileid_debug), 0xf0004,
			    buf, ret);
	mce_fd_debug_cmd(hw, 1 << 1);
	ret += sprintf(buf + ret, "status hash 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 2 << 1);
	ret += sprintf(buf + ret, "status sign_hash 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 3 << 1);
	ret += sprintf(buf + ret, "status match 0x%.2x\n",
		       rd32(hw, 0xf0004));
	ret += sprintf(buf + ret, "-------- input --------\n");
	mce_fd_debug_cmd(hw, 6 << 1);
	ret += sprintf(buf + ret, "inpt_data0 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 7 << 1);
	ret += sprintf(buf + ret, "inpt_data1 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 8 << 1);
	ret += sprintf(buf + ret, "inpt_data2 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 9 << 1);
	ret += sprintf(buf + ret, "inpt_data3 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 10 << 1);
	ret += sprintf(buf + ret, "inpt_data4 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 11 << 1);
	ret += sprintf(buf + ret, "inpt_data5 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 12 << 1);
	ret += sprintf(buf + ret, "inpt_data6 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 13 << 1);
	ret += sprintf(buf + ret, "inpt_data7 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 14 << 1);
	ret += sprintf(buf + ret, "inpt_data8 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 15 << 1);
	ret += sprintf(buf + ret, "inpt_data9 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 16 << 1);
	ret += sprintf(buf + ret, "inpt_dataa 0x%.2x\n",
		       rd32(hw, 0xf0004));
	ret += sprintf(buf + ret, "-------- mask ---------\n");
	mce_fd_debug_cmd(hw, 6 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data0 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 7 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data1 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 8 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data2 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 9 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data3 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 10 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data4 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 11 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data5 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 12 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data6 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 13 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data7 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 14 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data8 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 15 << 1 | 1);
	ret += sprintf(buf + ret, "mask_data9 0x%.2x\n",
		       rd32(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 16 << 1 | 1);
	ret += sprintf(buf + ret, "mask_dataa 0x%.2x\n",
		       rd32(hw, 0xf0004));
	return ret;
}

static ssize_t rqa_tcpsync_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = NULL;
	int vfidx = 0, ret = 0;

	vf = mce_pf_to_vf(pf);
	if (!vf || !vf->vfinfo) {
		ret += sprintf(buf + ret, "error: vfinfo is NULL\n");
		return ret;
	}

	for (vfidx = PFINFO_IDX; vfidx < pf->num_vfs; vfidx++) {
		if (!vf->vfinfo[vfidx].tcpsync.valid)
			continue;
		ret += sprintf(
			buf + ret,
			"vfnum: %d ring num: %d sync_tuple_pri:%d drop: %d \n",
			vfidx, vf->vfinfo[vfidx].tcpsync.pri.bits.ring_num,
			vf->vfinfo[vfidx].tcpsync.acl.bits.sync_tuple_pri,
			vf->vfinfo[vfidx].tcpsync.pri.bits.drop);
	}

	return ret;
}

static ssize_t rqa_tcpsync_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &(pf->hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int cnt, set, vfnum, ring_num, sync_tuple_pri, drop;

	/**
	 * set|clear + vfnum + ring_num + sync_tuple_pri + drop
	 * vfnum: in this command, the vfnum of pf is -1,
	 * the vfnum of vf need plus 1.
	 * sync_tuple_pri: 1 tcpsync prio large then tuple
	 */
	cnt = sscanf(buf, "%d %d %d %d %d", &set, &vfnum, &ring_num,
		     &sync_tuple_pri, &drop);
	if (cnt != 5)
		return -EINVAL;

	if (vfnum >= pf->num_vfs || vfnum < -1)
		return -EINVAL;

	if (!vf || !vf->vfinfo)
		return -EINVAL;

	memset(&vf->vfinfo[vfnum].tcpsync, 0, sizeof(struct mce_tcpsync));
	if (!!set) {
		vf->vfinfo[vfnum].tcpsync.acl.bits.enum_en = !!set;
		vf->vfinfo[vfnum].tcpsync.acl.bits.sync_tuple_pri =
			!!sync_tuple_pri;
		vf->vfinfo[vfnum].tcpsync.pri.bits.ring_num = ring_num;
		vf->vfinfo[vfnum].tcpsync.pri.bits.ring_valid = 1;
		vf->vfinfo[vfnum].tcpsync.pri.bits.drop = !!drop;
	}
	vf->vfinfo[vfnum].tcpsync.valid = !!set;

	hw->vf.ops->set_vf_rqa_tcp_sync_remapping(
		hw, vfnum, &vf->vfinfo[vfnum].tcpsync);
	return count;
}

static ssize_t vf_true_promisc_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = NULL;
	int vfidx = 0, ret = 0;

	vf = mce_pf_to_vf(pf);
	if (!vf || !vf->vfinfo) {
		ret += sprintf(buf + ret, "error: vfinfo is NULL\n");
		return ret;
	}

	for (vfidx = PFINFO_IDX; vfidx < pf->num_vfs; vfidx++)
		ret += sprintf(buf + ret, "vfnum: %d enable: %d \n", vfidx,
			       vf->vfinfo[vfidx].vf_true_promsic_en);

	return ret;
}

static ssize_t vf_true_promisc_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &(pf->hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int cnt, set, vfnum;

	/* set|clear + vfnum */
	cnt = sscanf(buf, "%d %d", &set, &vfnum);
	if (cnt != 2)
		return -EINVAL;

	if (vfnum >= pf->num_vfs || vfnum < -1)
		return -EINVAL;

	if (!vf || !vf->vfinfo)
		return -EINVAL;

	vf->vfinfo[vfnum].vf_true_promsic_en = !!set;
	hw->vf.ops->set_vf_true_promisc(
		hw, vfnum, vf->vfinfo[vfnum].vf_true_promsic_en);
	return count;
}

static ssize_t rx_wrr_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &(pf->hw);
	int i, ret = 0;

	ret += sprintf(buf + ret, "rx wrr %s:\n", hw->rx_wrr_en ? "enable" : "disable");
	for (i = 0; i < 8; i++)
	ret += sprintf(buf + ret, "vmark[%d] %d\n", i, hw->vmark[i]);

	return ret;
}

static ssize_t rx_wrr_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct net_device *netdev = mce_device_to_netdev(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &(pf->hw);
	int cnt, en, vmark[8];

	/* set|clear + vfnum */
	cnt = sscanf(buf, "%d %d %d %d %d %d %d %d %d", &en, &vmark[0],
			   &vmark[1], &vmark[2], &vmark[3], &vmark[4],
			   &vmark[5], &vmark[6], &vmark[7]);
	if (cnt != 9)
		return -EINVAL;
	if (en)
		hw->rx_wrr_en = true;
	else 
		hw->rx_wrr_en = false;

	memcpy(hw->vmark, vmark, sizeof(vmark));

	return count;
}

static int __print_desc(char *buf, void *data, int len)
{
	u8 *ptr = (u8 *)data;
	int ret = 0;
	int i = 0;

	for (i = 0; i < len; i++)
		ret += sprintf(buf + ret, "%02x ", *(ptr + i));

	return ret;
}

static struct netdev_queue *__mce_txring_txq(const struct mce_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->q_index);
}

static ssize_t txring_info_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_ring *tx_ring = NULL;
	struct mce_tx_buf *tx_buf = NULL;
	struct mce_tx_desc *eop_desc;
	int s_id, e_id;
	int ret = 0, i;
#define __DMA_REG_TX_DESC_HEAD (0x6c)
#define __DMA_REG_TX_DESC_TAIL (0x70)

	if (!pf->d_ringinfo.txring_vaild) {
		ret = sprintf(
			buf,
			"error: need setup debug tx ring num range first\n");
		return ret;
	}

	s_id = pf->d_ringinfo.txring_start;
	e_id = pf->d_ringinfo.txring_end;
	for (i = s_id; i <= e_id; i++) {
		struct netdev_queue *q;
		struct dql *dql;

		if (i >= vsi->num_txq) {
			ret = sprintf(
				buf,
				"error: tx queue id:%d larger than num_txq:%d, exit!\n",
				i, vsi->num_txq);
			return ret;
		}

		tx_ring = vsi->tx_rings[i];
		q = __mce_txring_txq(tx_ring);
		dql = &q->dql;
		// tx_ring->tx_buf
		ret += sprintf(buf + ret,
			       "====== tx ring num %d info: ======\n", i);
		ret += sprintf(buf + ret, "BQL queue state:0x%lx: \n",
			       q->state);
		ret += sprintf(buf + ret,
			       "1: num_queued:%d adj_limit:%d limit:%d \n",
			       dql->num_queued, dql->adj_limit,
			       dql->limit);
		ret += sprintf(
			buf + ret,
			"2: num_completed:%d p_ovlimit:%d p_num_queued:%d \n",
			dql->num_completed, dql->prev_ovlimit,
			dql->prev_num_queued);
		ret += sprintf(buf + ret, "3: max_limit:%d min_limit:%d\n",
			       dql->max_limit, dql->min_limit);
		ret += sprintf(buf + ret, "next_to_use: %d\n",
			       tx_ring->next_to_use);
		ret += sprintf(buf + ret, "next_to_clean: %d\n",
			       tx_ring->next_to_clean);
		ret += sprintf(buf + ret, "hw_head: %d   hw_tail: %d\n",
			       ring_rd32(tx_ring, __DMA_REG_TX_DESC_HEAD),
			       ring_rd32(tx_ring, __DMA_REG_TX_DESC_TAIL));
		tx_buf = &tx_ring->tx_buf[tx_ring->next_to_clean];
		eop_desc = tx_buf->next_to_watch;
		if (eop_desc) {
			ret += sprintf(buf + ret, "next_to_watch:\n");
			ret += __print_desc(buf + ret, eop_desc,
					    sizeof(*eop_desc));
			ret += sprintf(buf + ret, "\n");
		} else {
			ret += sprintf(buf + ret, "next_to_watch: no\n");
		}
	}

	return ret;
}

static ssize_t txring_info_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int s_id, e_id, cnt;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d", &s_id, &e_id);
	if (cnt != 2 || s_id > e_id)
		return -EINVAL;
	if (e_id >= vsi->num_txq)
		return -EINVAL;
	pf->d_ringinfo.txring_start = s_id;
	pf->d_ringinfo.txring_end = e_id;
	pf->d_ringinfo.txring_vaild = true;
	return count;
}

static ssize_t rxring_info_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_ring *rx_ring = NULL;
	struct mce_rx_desc_up *rx_desc = NULL;
	int s_id, e_id;
	int ret = 0, i;
#define __DMA_REG_RX_DESC_HEAD (0x3c)
#define __DMA_REG_RX_DESC_TAIL (0x40)

	if (!pf->d_ringinfo.rxring_vaild) {
		ret = sprintf(
			buf,
			"error: need setup debug rx ring num range first\n");
		return ret;
	}

	s_id = pf->d_ringinfo.rxring_start;
	e_id = pf->d_ringinfo.rxring_end;
	for (i = s_id; i <= e_id; i++) {
		rx_ring = vsi->rx_rings[i];
		// tx_ring->tx_buf
		ret += sprintf(buf + ret,
			       "====== rx ring num %d info: ======\n", i);
		ret += sprintf(buf + ret, "next_to_use: %d\n",
			       rx_ring->next_to_use);
		ret += sprintf(buf + ret, "next_to_clean: %d\n",
			       rx_ring->next_to_clean);
		ret += sprintf(buf + ret, "hw_head: %d   hw_tail: %d\n",
			       ring_rd32(rx_ring, __DMA_REG_RX_DESC_HEAD),
			       ring_rd32(rx_ring, __DMA_REG_RX_DESC_TAIL));
		rx_desc = MCE_RXDESC_UP(rx_ring, rx_ring->next_to_clean);
		if (rx_desc) {
			ret += sprintf(buf + ret, "next_to_clean desc:\n");
			ret += __print_desc(buf + ret, rx_desc,
					    sizeof(*rx_desc));
			ret += sprintf(buf + ret, "\n");
			rx_desc = MCE_RXDESC_UP(rx_ring,
						rx_ring->next_to_clean);
		} else {
			ret += sprintf(buf + ret,
				       "next_to_clean desc: no\n");
		}
	}
	return ret;
}

static ssize_t rxring_info_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int s_id, e_id, cnt;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d", &s_id, &e_id);
	if (cnt != 2 || s_id > e_id)
		return -EINVAL;
	if (e_id >= vsi->num_rxq)
		return -EINVAL;
	pf->d_ringinfo.rxring_start = s_id;
	pf->d_ringinfo.rxring_end = e_id;
	pf->d_ringinfo.rxring_vaild = true;
	return count;
}

static ssize_t select_queue_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	int ret = 0;
#if MCE_SELECT_QUEUE_DEBUG
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);

	ret += sprintf(buf + ret, "enable:%d s_id:%d e_id:%d r_id:%d\n",
		       pf->d_txqueue.en, pf->d_txqueue.s_id,
		       pf->d_txqueue.e_id, pf->d_txqueue.r_id);
#else
	ret += sprintf(buf + ret,
		       "MCE_SELECT_QUEUE_DEBUG donnot turn on\n");
#endif
	return ret;
}

static ssize_t select_queue_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
#if MCE_SELECT_QUEUE_DEBUG
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int en, s_id, e_id, cnt;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d %d", &en, &s_id, &e_id);
	if (cnt != 3 || s_id > e_id)
		return -EINVAL;
	if (e_id >= vsi->num_txq)
		return -EINVAL;
	pf->d_txqueue.s_id = s_id;
	pf->d_txqueue.e_id = e_id;
	pf->d_txqueue.en = !!en;
	return count;
#else
	return count;
#endif
}

static ssize_t debug_fw_mbx_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &(pf->hw);
	int ret = 0, err;

	err = mce_mbx_get_lane_stat(hw);

	if (!err)
		ret += sprintf(buf + ret, "debug fw mbx: ret ok\n");
	else
		ret += sprintf(buf + ret, "debug fw mbx: ret err\n");
	return ret;
}

static ssize_t ring_mbx_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	int ret = 0;
	bool en = false;

	en = !!test_bit(MCE_FLAG_MBX_CTRL_ENA, pf->flags);
	ret += sprintf(buf + ret, "ring mbx ctrl enable: %s\n",
		       en ? "yes" : "no");
	en = !!test_bit(MCE_FLAG_MBX_DATA_ENA, pf->flags);
	ret += sprintf(buf + ret, "ring mbx data enable: %s\n",
		       en ? "yes" : "no");
	return ret;
}

static ssize_t ring_mbx_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	int cmd, ring_num, cnt;

	/* cmd + ring num
	 * cmd: 
	 *    0: clear mbx flags
	 *    1: set mbx ctrl 
	 *    2: set mbx data 
	 * ring num: 0~15
	 **/
	cnt = sscanf(buf, "%d %d", &cmd, &ring_num);
	if (cnt != 2)
		return -EINVAL;
	if (cmd == 0) {
		clear_bit(MCE_FLAG_MBX_CTRL_ENA, pf->flags);
		clear_bit(MCE_FLAG_MBX_DATA_ENA, pf->flags);
		pf->mbx_ring_id = 0xffff;
	} else if (cmd == 1) {
		pf->mbx_ring_id = ring_num;
		set_bit(MCE_FLAG_MBX_CTRL_ENA, pf->flags);
	} else {
		pf->mbx_ring_id = ring_num;
		set_bit(MCE_FLAG_MBX_DATA_ENA, pf->flags);
	}

	return count;
}

static ssize_t priv_header_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	int ret = 0;

	ret += sprintf(buf + ret, "private header enabled: %s\n",
		       pf->priv_h.en ? "yes" : "no");
	if (pf->priv_h.len &&
	    (pf->priv_h.len < MCE_PRIV_HEADER_LEN_LINIT)) {
		ret += sprintf(buf + ret, "data: %s\n",
			       pf->priv_h.priv_header);
		ret += sprintf(buf + ret, "len: %d\n", pf->priv_h.len);
	}
	return ret;
}

static ssize_t priv_header_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &pf->hw;
	int cnt;
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

	memset(&pf->priv_h, 0, sizeof(pf->priv_h));
	/* enable + strings */
	cnt = sscanf(buf, "%d %" TOSTRING(MCE_PRIV_HEADER_LEN) "s",
		     &pf->priv_h.en, pf->priv_h.priv_header);
	if (cnt != 2)
		return -EINVAL;

	pf->priv_h.len = pf->priv_h.en ? strlen(pf->priv_h.priv_header) :
					 0;
	if (pf->priv_h.en) {
		hw->ops->set_dma_tso_cnts_en(hw, pf->priv_h.en);
		hw->ops->set_max_pktlen(hw, netdev->mtu);
	}
	return count;
}

static ssize_t vf_dma_qs_store(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &pf->hw;
	int dma_qs, cnt;

	cnt = sscanf(buf, "%d", &dma_qs);
	if (cnt != 1)
		return -EINVAL;
	//if (dma_qs < MCE_VF_DMA_QS_START || dma_qs > MCE_VF_DMA_QS_8)
	//	return -EINVAL;
	mce_mbx_set_vf_qs(hw, dma_qs);
	return count;
}

static ssize_t own_vpd_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
#ifdef MCE_DEBUG_CM3
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &pf->hw;
	char pn[33] = { 0 }, sn[33] = { 0 };
#endif
	int ret = 0;

#ifdef MCE_DEBUG_CM3
	mce_mbx_get_pn_sn(hw, pn, sn);
	ret += sprintf(
		buf + ret, "Product Name: %s\n",
		"Ethernet Controller N20 Series for 10/25/100 GbE (Dual-port)");
	ret += sprintf(buf + ret, "[PN] Part number: %s\n", pn);
	ret += sprintf(buf + ret, "[SN] Serial number: %s\n", sn);
#else
	ret += sprintf(buf + ret, "Get vpd failed, donnot support CM3!\n");
#endif
	return ret;
}

static ssize_t pf_reset_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);

	set_bit(MCE_FLAG_PF_RESET_ENA, pf->flags);
	return count;
}

static ssize_t pri2buf_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &(dcb->cur_pfccfg);
	int ret = 0; 

	ret += sprintf(buf + ret, "Priority Buffer: %d %d %d %d %d %d %d %d\n",
		       pfccfg->rx_pri2buf[0],
		       pfccfg->rx_pri2buf[1],
		       pfccfg->rx_pri2buf[2],
		       pfccfg->rx_pri2buf[3],
		       pfccfg->rx_pri2buf[4],
		       pfccfg->rx_pri2buf[5],
		       pfccfg->rx_pri2buf[6],
		       pfccfg->rx_pri2buf[7]);
	return ret;
}

static ssize_t pri2buf_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &(dcb->cur_pfccfg);
	int cnt, i;
	int pri2buf[MCE_MAX_PRIORITY];

	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
		return -EINVAL;

	cnt = sscanf(buf, "%d %d %d %d %d %d %d %d", &pri2buf[0],
			   &pri2buf[1], &pri2buf[2], &pri2buf[3], &pri2buf[4],
			   &pri2buf[5], &pri2buf[6], &pri2buf[7]);
	if (cnt != 8)
		return -EINVAL;

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (pri2buf[i] >= MCE_MAX_PRIORITY)
			return -EINVAL;
		pfccfg->rx_pri2buf[i] = pri2buf[i];
	}

	return count;
}

static DEVICE_ATTR(pri2buf, 0644, pri2buf_show, pri2buf_store);

static ssize_t buffer_size_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &(dcb->cur_pfccfg);
	int ret = 0; 
	//struct mce_hw *hw = &pf->hw;

	if (test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
		ret += sprintf(buf + ret, "Manually on\n");
	else
		ret += sprintf(buf + ret, "Manually off\n");

	ret += sprintf(buf + ret, "Buffer size(bytes): %d %d %d %d %d %d %d %d\n",
		       pfccfg->fifo_depth[0] * 64,
		       pfccfg->fifo_depth[1] * 64,
		       pfccfg->fifo_depth[2] * 64,
		       pfccfg->fifo_depth[3] * 64,
		       pfccfg->fifo_depth[4] * 64,
		       pfccfg->fifo_depth[5] * 64,
		       pfccfg->fifo_depth[6] * 64,
		       pfccfg->fifo_depth[7] * 64);
	// setup the new rx setup
	//hw->ops.setup_rx_buffer(hw);
	return ret;
}

static int check_pri2buf(struct mce_pfc_cfg *pfccfg, int fifo)
{
	int i;
	int ret = 0;

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (pfccfg->rx_pri2buf[i] == fifo)
			ret = 1;
	}
	
	return ret;
}

static ssize_t buffer_size_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &(dcb->cur_pfccfg);
	int fifo[MCE_MAX_PRIORITY];
	int sum = 0, i;
	int tmp = 0, cnt;
	struct mce_hw *hw = &pf->hw;
	// at least 1024
	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
		return -EINVAL;

	cnt = sscanf(buf, "%d %d %d %d %d %d %d %d", &fifo[0],
			   &fifo[1], &fifo[2], &fifo[3], &fifo[4],
			   &fifo[5], &fifo[6], &fifo[7]);
	if (cnt != 8)
		return -EINVAL;
	
	// check total 
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		// low-assign to 16
		fifo[i] = fifo[i] / 64;
		// if this fifo is used, min 0x400
		if (check_pri2buf(pfccfg, i) && (fifo[i] < 0x400))
			return -EINVAL;
		sum += fifo[i];
	}

	if (sum > N20_FIFO_TAL_DEEP)
		return -EINVAL;
	// store it to hw
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		pfccfg->fifo_head[i] = tmp;
		pfccfg->fifo_tail[i] = tmp + fifo[i] - 1;
		pfccfg->fifo_depth[i] = fifo[i];
		tmp += fifo[i];
	}

	hw->ops->setup_rx_buffer(hw);

	return count;
}


static DEVICE_ATTR(buffer_size, 0644, buffer_size_show, buffer_size_store);
static DEVICE_ATTR(default_vport, 0644, default_vport_show,
		   default_vport_store);
static DEVICE_ATTR(test, 0644, test_show,
		   test_store);
static DEVICE_ATTR(set_dvlan, 0644, set_dvlan_show, set_dvlan_store);
static DEVICE_ATTR(fd_rx_debug, 0644, fd_rx_debug_show, NULL);
static DEVICE_ATTR(rqa_tcpsync, 0644, rqa_tcpsync_show, rqa_tcpsync_store);
static DEVICE_ATTR(vf_true_promisc, 0644, vf_true_promisc_show,
		   vf_true_promisc_store);
static DEVICE_ATTR(rx_wrr, 0644, rx_wrr_show,
		   rx_wrr_store);
static DEVICE_ATTR(txring_info, 0644, txring_info_show, txring_info_store);
static DEVICE_ATTR(rxring_info, 0644, rxring_info_show, rxring_info_store);
// static DEVICE_ATTR(txdesc_info, 0644, txdesc_info_show, txdesc_info_store);
// static DEVICE_ATTR(rxdesc_info, 0644, rxdesc_info_show, rxdesc_info_store);
static DEVICE_ATTR(select_queue, 0644, select_queue_show,
		   select_queue_store);
static DEVICE_ATTR(tx_debug, 0644, tx_debug_show, tx_debug_store);
static DEVICE_ATTR(nic_prio, 0644, nic_prio_show, nic_prio_store);
static DEVICE_ATTR(rdma_prio, 0644, rdma_prio_show, rdma_prio_store);
static DEVICE_ATTR(tx_drop_en, 0644, NULL, tx_drop_en_store);

static DEVICE_ATTR(debug_fw_mbx, 0644, debug_fw_mbx_show, NULL);
static DEVICE_ATTR(ring_mbx, 0644, ring_mbx_show, ring_mbx_store);
static DEVICE_ATTR(priv_header, 0644, priv_header_show, priv_header_store);
static DEVICE_ATTR(vf_dma_qs, 0644, NULL, vf_dma_qs_store);
static DEVICE_ATTR(own_vpd, 0644, own_vpd_show, NULL);
static DEVICE_ATTR(pf_reset, 0644, NULL, pf_reset_store);

static struct attribute *dev_attrs[] = {
	&dev_attr_test.attr,
	&dev_attr_default_vport.attr,
	&dev_attr_set_dvlan.attr,
	&dev_attr_rqa_tcpsync.attr,
	&dev_attr_vf_true_promisc.attr,
	&dev_attr_txring_info.attr,
	&dev_attr_rxring_info.attr,
	//	&dev_attr_txdesc_info.attr,
	//	&dev_attr_rxdesc_info.attr,
	&dev_attr_select_queue.attr,
	&dev_attr_ring_mbx.attr,
	&dev_attr_priv_header.attr,
	&dev_attr_vf_dma_qs.attr,
	&dev_attr_pf_reset.attr,
	NULL,
};

static struct attribute *qos_dev_attrs[] = {
	&dev_attr_pri2buf.attr,
	&dev_attr_buffer_size.attr,
	NULL,
};

const static struct attribute_group qos_attr_grp = {
	.name = "qos",
	.attrs = qos_dev_attrs,
};

static struct attribute *vendor_dev_attrs[] = {
	&dev_attr_tx_debug.attr,     &dev_attr_nic_prio.attr,
	&dev_attr_rdma_prio.attr,    &dev_attr_tx_drop_en.attr,
	&dev_attr_debug_fw_mbx.attr, &dev_attr_fd_rx_debug.attr,
	&dev_attr_own_vpd.attr,	     
	&dev_attr_rx_wrr.attr,
	NULL,
};

const static struct attribute_group vendor_attr_grp = {
	.name = "vendor",
	.attrs = vendor_dev_attrs,
};

static struct attribute_group dev_attr_grp = {
	.attrs = dev_attrs,
};

const static struct attribute_group *attr_grps[] = {
	&dev_attr_grp,
	&vendor_attr_grp,
	&qos_attr_grp,
	NULL,
};

void mce_sysfs_exit(struct mce_pf *pf)
{
	struct net_device *netdev = pf->vsi[0]->netdev;

	//sysfs_remove_group(&netdev->dev.kobj, &dev_attr_grp);
	sysfs_remove_groups(&netdev->dev.kobj, &attr_grps[0]);
}

int mce_sysfs_init(struct mce_pf *pf)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	int err = 0;

	//err = sysfs_create_group(&netdev->dev.kobj, &dev_attr_grp);
	err = sysfs_create_groups(&netdev->dev.kobj, &attr_grps[0]);
	if (err)
		dev_err(mce_pf_to_dev(pf),
			"Failed to create sysfs group\n");
	return err;
}

#endif
