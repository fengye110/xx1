/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023-2024 Mucse Corporation */

#ifndef _MCE_SWITCH_H_
#define _MCE_SWITCH_H_

enum mce_tc_tunnel_type {
	TNL_TC_VXLAN = 0,
	TNL_TC_GENEVE,
	TNL_TC_GRETAP,
	TNL_TC_GTP,
	TNL_TC_GTPC,
	TNL_TC_GTPU,
	TNL_TC_ECPRI,
	TNL_TC_LAST = 0xFF,
	TNL_TC_ALL = 0xFF,
};

struct mce_sw_act_ctrl {
	/* Source VSI for LOOKUP_TX or source port for LOOKUP_RX */
	u16 src;
	u16 flag;
	enum mce_sw_fwd_act_type fltr_act;
	/* Depending on filter action */
	union {
		/* This is a queue ID in case of ICE_FWD_TO_Q and starting
		 * queue ID in case of ICE_FWD_TO_QGRP.
		 */
		u16 q_id : 11;
		u16 vsi_id : 10;
		u16 hw_vsi_id : 10;
		u16 vsi_list_id : 10;
	} fwd_id;
	/* software VSI handle */
	u16 vsi_handle;
	u8 qgrp_size;
};

struct mce_rule_query_data {
	/* Recipe ID for which the requested rule was added */
	u16 rid;
	/* Rule ID that was added or is supposed to be removed */
	u16 rule_id;
	/* vsi_handle for which Rule was added or is supposed to be removed */
	u16 vsi_handle;
};

/*
 * This structure allows to pass info about lb_en and lan_en
 * flags to mce_add_adv_rule. Values in act would be used
 * only if act_valid was set to true, otherwise dflt
 * values would be used.
 */
struct mce_adv_rule_flags_info {
	u32 act;
	u8 act_valid; /* indicate if flags in act are valid */
};

enum mce_protocol_type {
	MCE_MAC_OFOS = 0,
	MCE_MAC_IL,
	MCE_ETYPE_OL,
	MCE_ETYPE_IL,
	MCE_VLAN_OFOS,
	MCE_IPV4_OFOS,
	MCE_IPV4_IL,
	MCE_IPV6_OFOS,
	MCE_IPV6_IL,
	MCE_TCP_IL,
	MCE_UDP_OF,
	MCE_UDP_ILOS,
	MCE_SCTP_IL,
	MCE_VXLAN,
	MCE_GENEVE,
	MCE_VXLAN_GPE,
	MCE_NVGRE,
	MCE_GTP,
	MCE_GTP_NO_PAY,
	MCE_PPPOE,
	MCE_PFCP,
	MCE_L2TPV3,
	MCE_ESP,
	MCE_AH,
	MCE_NAT_T,
	MCE_VLAN_EX,
	MCE_VLAN_IN,
	MCE_HW_METADATA,
	MCE_PROTOCOL_LAST
};

#if 0
enum mce_sw_tun_type {
	MCE_NON_TUN = 0,
	MCE_SW_TUN_AND_NON_TUN,
	MCE_SW_TUN_VXLAN_GPE,
	MCE_SW_TUN_GENEVE, /* GENEVE matches only non-VLAN pkts */
	MCE_SW_TUN_GENEVE_VLAN, /* GENEVE matches both VLAN and non-VLAN pkts */
	MCE_SW_TUN_VXLAN, /* VXLAN matches only non-VLAN pkts */
	MCE_SW_TUN_VXLAN_VLAN, /* VXLAN matches both VLAN and non-VLAN pkts */
	MCE_SW_TUN_NVGRE,
	MCE_SW_TUN_UDP, /* This means all "UDP" tunnel types: VXLAN-GPE, VXLAN
			 * and GENEVE
			 */
	MCE_SW_IPV4_TCP,
	MCE_SW_IPV4_UDP,
	MCE_SW_IPV6_TCP,
	MCE_SW_IPV6_UDP,
	MCE_SW_TUN_GTPU,
	MCE_SW_TUN_GTPC,
	MCE_ALL_TUNNELS /* All tunnel types including NVGRE */
};
#endif
enum mce_sw_tun_type {
	MCE_SW_NON_TUN = 0,
	MCE_SW_TUN_VXLAN = 1,
	MCE_SW_TUN_GRE,
	MCE_SW_TUN_GENEVE,
	MCE_SW_TUN_GTP_U,
	MCE_SW_TUN_GTP_C,
	MCE_SW_TUN_IPINIP,
	MCE_SW_TUN_MPLS_UDP,
};

struct mce_adv_rule_info {
	/* Store metadata values in rule info */
	enum mce_sw_tun_type tun_type;
	u16 vlan_type;
	u16 fltr_rule_id;
	u32 priority;
	u16 src_vsi;
	struct mce_sw_act_ctrl sw_act;
	u8 add_dir_lkup;
	u16 lg_id;
	struct mce_adv_rule_flags_info flags_info;
};
#endif /* _MCE_SWITCH_H_ */
