/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2024 Mucse Corporation */

#ifndef _MCE_VF_LIB_H_
#define _MCE_VF_LIB_H_
#include <linux/netdevice.h>

#define PFINFO_IDX (-1)
#define PFINFO_OFF (0 - PFINFO_IDX)
#define PFINFO_NONE (0xff)
#define PFINFO_BCMC (0xfff)
#define PFINFO_DEFAULT_VLAN (0xfff)

#define MCE_MBOX_IRQ_NO_MSIX_BASE (0)
#define MCE_VF_NOT_FOUND (-100)
#define MCE_VF_INVALID (-101)
#define MCE_VF_UNUSED (-102)

#define MCE_LIMIT_VFS (128)
/* TODO: should get max vfs from pcie capbility */
#define MCE_TOTAL_VFS (pf->num_vfs + 1) /* pf take as vf */

struct mce_hw;

/* VM RULE */
enum veb_policy_type {
	__VEB_POLICY_TYPE_NONE,
	__VEB_POLICY_TYPE_UC_ADD_MACADDR,
	__VEB_POLICY_TYPE_UC_DEL_MACADDR,
	__VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT,
	__VEB_POLICY_TYPE_UC_DEL_MACADDR_WITH_ACT,
	__VEB_POLICY_TYPE_MACVLAN_ADD_MACADDR_WITH_ACT,
	__VEB_POLICY_TYPE_MACVLAN_DEL_MACADDR_WITH_ACT,
	__VEB_POLICY_TYPE_BCMC_ADD_MACADDR,
	__VEB_POLICY_TYPE_BCMC_DEL_MACADDR,
	__VEB_POLICY_TYPE_BCMC_ADD_MACADDR_WITH_ACT,
	__VEB_POLICY_TYPE_BCMC_DEL_MACADDR_WITH_ACT,
	__VEB_POLICY_TYPE_UC_ADD_VLAN,
	__VEB_POLICY_TYPE_UC_DEL_VLAN,
	__VEB_POLICY_TYPE_MAX,
};

enum mce_vf_dma_qs {
	MCE_VF_DMA_QS_START,
	MCE_VF_DMA_QS_4 = MCE_VF_DMA_QS_START,
	MCE_VF_DMA_QS_8,
	MCE_VF_DMA_QS_16,
	MCE_VF_DMA_QS_32,
	MCE_VF_DMA_QS_64,
	MCE_VF_DMA_QS_128,
	MCE_VF_DMA_QS_UNDEFINED,
};
/* exanple:
 * 11: isolate + MCE_VF_DMA_QS_4
 * 12: isolate + MCE_VF_DMA_QS_8 */
#define MCE_VF_DMA_QS_PCIE_ISOLATE_BASE (2)

enum mce_vf_veb_vlan_type {
	MCE_VF_VEB_VLAN_INVALID = 0,
	MCE_VF_VEB_VLAN_OUTER1,
	MCE_VF_VEB_VLAN_OUTER2,
	MCE_VF_VEB_VLAN_OUTER3,
};

enum mce_vf_post_ctrl {
	MCE_VF_POST_CTRL_NORMAL = 0,
	MCE_VF_POST_CTRL_FILTER_TX_TO_RX,
	MCE_VF_POST_CTRL_ALLIN_TO_RX,
	MCE_VF_POST_CTRL_ALLIN_TO_TXTRANS_AND_RX,
};

enum mce_vf_antivlan_ctrl {
	MCE_VF_ANTI_VLAN_CLEAR = 0,
	MCE_VF_ANTI_VLAN_SET,
	MCE_VF_ANTI_VLAN_HOLD,
};

#define MCE_USER_CONFIG_VF_DMA_QS (hw->dma_qs)

struct vf_vlan {
	u16 vid;
	u16 qos;
};

struct mce_tcpsync {
	union {
		struct {
			u32 sync_tuple_pri : 1;
			u32 rsv0 : 19;
			u32 act_pri : 3;
			u32 rsv1 : 8;
			u32 enum_en : 1;
		} bits;
		u32 data;
	} acl;

	union {
		struct {
			u32 mark : 16;
			u32 rm_vlan_type : 2;
			u32 ring_num : 9;
			u32 pri_valid : 1;
			u32 mark_valid : 1;
			u32 vlan_valid : 1;
			u32 ring_valid : 1;
			u32 drop : 1;
		} bits;
		u32 data;
	} pri;
	bool valid;
};

struct vf_data_storage {
	unsigned char vf_mac_addresses[ETH_ALEN];
	bool pf_set_mac;
	u16 pf_vlan; /* When set, guest VLAN config not allowed. */
#define MCE_MAX_VF_VLAN_WHITE_LISTS (16)
	struct vf_vlan vf_vlan[MCE_MAX_VF_VLAN_WHITE_LISTS];
	DECLARE_BITMAP(avail_vlan, MCE_MAX_VF_VLAN_WHITE_LISTS);
	int pf_vlan_entry; /* When set, guest VLAN config not allowed. */
	u16 pf_qos;
	u16 tx_rate;
	int link_enable;
#ifdef HAVE_NDO_SET_VF_LINK_STATE
	int link_state;
#endif
	u8 spoofchk_enabled;
	u8 trusted;
	int xcast_mode;
	bool intr_enabled;
	bool clear_to_send;
	struct mce_tcpsync tcpsync;
	bool vf_true_promsic_en;
#define MCE_MAX_ETYPE_CNT (16)
	DECLARE_BITMAP(avail_etype, MCE_MAX_ETYPE_CNT);
};

/* Software flag types. */
enum mce_flag_type {
	MCE_F_HOLD = 0,
	MCE_F_SET,
	MCE_F_CLEAR,
};

struct vf_tmp_info {
	u16 vlanid;
	int entry;
	u8 macaddr[ETH_ALEN];
	int cnt;
	u32 index;
	enum mce_flag_type bcmc_bitmap;
};

struct mce_vf {
	struct mce_pf *pf;
	struct vf_tmp_info t_info;
	struct vf_data_storage *vfinfo;
	struct mutex cfg_lock;
	DECLARE_BITMAP(avail_tunnel_bcmc, MCE_LIMIT_VFS);
};
struct mce_hw;
int N20_FPGA_VFNUM(struct mce_hw *hw, int vfid);
int mce_vf_apply_spoofchk(struct mce_pf *pf, int vfid, bool enable);
int mce_vf_set_trusted(struct mce_pf *pf, int vfid, bool enable);
int mce_vf_resync_mc_list(struct mce_pf *pf, bool to_pfvf);
int mce_vf_resync_vlan_list(struct mce_pf *pf, bool to_pfvf);
int mce_vf_setup_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id);
int mce_vf_del_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id);
int mce_vf_setup_true_promisc(struct mce_pf *pf);
int mce_vf_del_true_promisc(struct mce_pf *pf);
int mce_vf_setup_rqa_tcp_sync_en(struct mce_pf *pf, bool on);
// int mce_vf_set_veb_misc_rule(struct mce_hw *hw, int vfid,
// 			       enum veb_policy_type ptype);
#endif /* _MCE_VF_LIB_H_ */