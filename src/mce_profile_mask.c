/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2024 Mucse Corporation */
#include "mce.h"
#include "mce_tc_lib.h"
#include "mce_lib.h"
#include "mce_fltr.h"
#include "mce_pattern.h"
#include "mce_parse.h"
#include "mce_switch.h"
#include "mce_fdir_flow.h"
#include "mce_profile_mask.h"

struct mce_profile_options_mask {
	u64 options;

	u32 field_mask;
};

#define MCE_FIELD_M_IP4_SIP BIT(0)
#define MCE_FIELD_M_IP4_DIP BIT(1)
#define MCE_FIELD_M_IP6_SIP (BIT(0) | BIT(5))
#define MCE_FIELD_M_IP6_DIP (BIT(1) | BIT(6))
#define MCE_FIELD_M_L4_PROTO BIT(2)
#define MCE_FIELD_M_L4_SPORT BIT(2)
#define MCE_FIELD_M_L4_DPORT BIT(3)
#define MCE_FIELD_M_TEID BIT(4)
#define MCE_FIELD_M_DSCP BIT(4)
#define MCE_FIELD_M_VNI BIT(4)
#define MCE_FIELD_M_NVGRE_TNI BIT(4)
#define MCE_FIELD_M_ESP_SPI (BIT(2) | BIT(3))

#define MCE_FIELD_M_ETH_VLAN BIT(0)
#define MCE_FIELD_M_ETH_SMAC (BIT(1) | BIT(2))
#define MCE_FIELD_M_ETH_DMAC (BIT(3) | BIT(4))
#define MCE_FIELD_M_ETH_TYPE BIT(0)

static struct mce_profile_options_mask mce_dummy_todo[] = {
	{ 0, 0 },
};

static struct mce_profile_options_mask mce_ipv4_tcp_sync[] = {
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv4_tcp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_TCP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_udp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_UDP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_UDP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_sctp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_SCTP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_SCTP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_esp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_ESP_SPI, MCE_FIELD_M_ESP_SPI },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_pay[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_L4_PROTO, MCE_FIELD_M_L4_PROTO },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_frag[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_IPV4_FRAG, 0 },
};

static struct mce_profile_options_mask mce_ipv4_vxlan[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_VXLAN_VNI, MCE_FIELD_M_VNI },
};

static struct mce_profile_options_mask mce_ipv4_geneve[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GENEVE_VNI, MCE_FIELD_M_VNI },
};

static struct mce_profile_options_mask mce_ipv4_nvgre[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_NVGRE_TNI, MCE_FIELD_M_NVGRE_TNI },
};

static struct mce_profile_options_mask mce_ipv4_gtpu[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_U_TEID, MCE_FIELD_M_TEID },
};

static struct mce_profile_options_mask mce_ipv4_gtpc[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_C_TEID, MCE_FIELD_M_TEID },
};

static struct mce_profile_options_mask mce_ipv6_tcp_sync[] = {
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv6_tcp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_TCP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv6_udp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_UDP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_UDP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv6_sctp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_SCTP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_SCTP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv6_esp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_ESP_SPI, MCE_FIELD_M_ESP_SPI },
};

static struct mce_profile_options_mask mce_ipv6_pay[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_L4_PROTO, MCE_FIELD_M_L4_PROTO },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv6_frag[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_IPV6_FRAG, 0 },
};

static struct mce_profile_options_mask mce_ipv6_vxlan[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_VXLAN_VNI, MCE_FIELD_M_VNI },
};

static struct mce_profile_options_mask mce_ipv6_geneve[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GENEVE_VNI, MCE_FIELD_M_VNI },
};

static struct mce_profile_options_mask mce_ipv6_nvgre[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_NVGRE_TNI, MCE_FIELD_M_NVGRE_TNI },
};

static struct mce_profile_options_mask mce_ipv6_gtpu[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_U_TEID, MCE_FIELD_M_TEID },
};

static struct mce_profile_options_mask mce_ipv6_gtpc[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_C_TEID, MCE_FIELD_M_TEID },
};

static struct mce_profile_options_mask mce_l2_eth[] = {
	{ MCE_OPT_VLAN_VID, MCE_FIELD_M_ETH_VLAN },
	{ MCE_OPT_SMAC, MCE_FIELD_M_ETH_SMAC },
	{ MCE_OPT_DMAC, MCE_FIELD_M_ETH_DMAC },
};

static struct mce_profile_options_mask mce_l2_ethtype[] = {
	{ MCE_OPT_ETHTYPE, MCE_FIELD_M_ETH_TYPE },
};

struct mce_profile_select_db {
	u64 profile_id;
	struct mce_profile_options_mask *options_list;
	u16 sup_options_num;
};

static struct mce_profile_select_db mce_profile_bitmask[] = {
	{ MCE_PTYPE_UNKNOW, mce_dummy_todo,
	  ARRAY_SIZE(mce_dummy_todo) }, /* 0 */
	{ MCE_PTYPE_L2_ONLY, mce_l2_eth, ARRAY_SIZE(mce_l2_eth) }, /* 1 */
	{ MCE_PTYPE_TUN_INNER_L2_ONLY, mce_l2_eth,
	  ARRAY_SIZE(mce_l2_eth) }, /* 2 */
	{ MCE_PTYPE_TUN_OUTER_L2_ONLY, mce_l2_eth,
	  ARRAY_SIZE(mce_l2_eth) }, /* 3 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_FRAG, mce_ipv4_frag,
	  ARRAY_SIZE(mce_ipv4_frag) }, /* 4 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_FRAG, mce_ipv6_frag,
	  ARRAY_SIZE(mce_ipv6_frag) }, /* 5 */
	{ MCE_PTYPE_L2_ETHTYPE, mce_l2_ethtype,
	  ARRAY_SIZE(mce_l2_ethtype) }, /* 6 */
	{ MCE_PTYPE_TUN_INNER_L2_ETHTYPE, mce_l2_ethtype,
	  ARRAY_SIZE(mce_l2_ethtype) }, /* 7 */
	{ MCE_PTYPE_IPV4_FRAG, mce_ipv4_frag,
	  ARRAY_SIZE(mce_ipv4_frag) }, /* 8*/
	{ MCE_PTYPE_IPV4_TCP_SYNC, mce_ipv4_tcp_sync,
	  ARRAY_SIZE(mce_ipv4_tcp_sync) }, /* 9 */
	{ MCE_PTYPE_IPV4_TCP, mce_ipv4_tcp,
	  ARRAY_SIZE(mce_ipv4_tcp) }, /* 10 */
	{ MCE_PTYPE_IPV4_UDP, mce_ipv4_udp,
	  ARRAY_SIZE(mce_ipv4_udp) }, /* 11 */
	{ MCE_PTYPE_IPV4_SCTP, mce_ipv4_sctp,
	  ARRAY_SIZE(mce_ipv4_sctp) }, /* 12 */
	{ MCE_PTYPE_IPV4_ESP, mce_ipv4_esp,
	  ARRAY_SIZE(mce_ipv4_esp) }, /* 13 */
	{ MCE_PTYPE_IPV4_PAY, mce_ipv4_pay,
	  ARRAY_SIZE(mce_ipv4_pay) }, /* 14 */
	{ 0, 0 }, /* 15 */
	{ MCE_PTYPE_IPV6_FRAG, mce_ipv6_frag,
	  ARRAY_SIZE(mce_ipv6_frag) }, /* 16 */
	{ MCE_PTYPE_IPV6_TCP_SYNC, mce_ipv6_tcp_sync,
	  ARRAY_SIZE(mce_ipv6_tcp_sync) }, /* 17 */
	{ MCE_PTYPE_IPV6_TCP, mce_ipv6_tcp,
	  ARRAY_SIZE(mce_ipv6_tcp) }, /* 18 */
	{ MCE_PTYPE_IPV6_UDP, mce_ipv6_udp,
	  ARRAY_SIZE(mce_ipv6_udp) }, /* 19 */
	{ MCE_PTYPE_IPV6_SCTP, mce_ipv6_sctp,
	  ARRAY_SIZE(mce_ipv6_sctp) }, /* 20 */
	{ MCE_PTYPE_IPV6_ESP, mce_ipv6_esp,
	  ARRAY_SIZE(mce_ipv6_esp) }, /* 21 */
	{ MCE_PTYPE_IPV6_PAY, mce_ipv6_pay,
	  ARRAY_SIZE(mce_ipv6_pay) }, /* 22 */
	{ 0, 0 }, /* 23 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_PAY, mce_ipv4_pay,
	  ARRAY_SIZE(mce_ipv4_pay) }, /* 24 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_TCP, mce_ipv4_tcp,
	  ARRAY_SIZE(mce_ipv4_tcp) }, /* 25 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_UDP, mce_ipv4_udp,
	  ARRAY_SIZE(mce_ipv4_udp) }, /* 26 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_SCTP, mce_ipv4_sctp,
	  ARRAY_SIZE(mce_ipv4_sctp) }, /* 27 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_PAY, mce_ipv6_pay,
	  ARRAY_SIZE(mce_ipv6_pay) }, /* 28 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_TCP, mce_ipv6_tcp,
	  ARRAY_SIZE(mce_ipv6_tcp) }, /* 29 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_UDP, mce_ipv6_udp,
	  ARRAY_SIZE(mce_ipv6_udp) }, /* 30 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_SCTP, mce_ipv6_sctp,
	  ARRAY_SIZE(mce_ipv6_sctp) }, /* 31 */
	{ MCE_PTYPE_GTP_U_GPDU_IPV4, mce_ipv4_gtpu,
	  ARRAY_SIZE(mce_ipv4_gtpu) }, /* 32 */
	{ MCE_PTYPE_GTP_U_IPV4, mce_ipv4_gtpu,
	  ARRAY_SIZE(mce_ipv4_gtpu) }, /* 33 */
	{ MCE_PTYPE_GTP_C_TEID_IPV4, mce_ipv4_gtpc,
	  ARRAY_SIZE(mce_ipv4_gtpc) }, /* 34 */
	{ MCE_PTYPE_GTP_C_IPV4, mce_ipv4_udp,
	  ARRAY_SIZE(mce_ipv4_udp) }, /* 35 */
	{ MCE_PTYPE_GTP_U_GPDU_IPV6, mce_ipv6_gtpu,
	  ARRAY_SIZE(mce_ipv6_gtpu) }, /* 36 */
	{ MCE_PTYPE_GTP_U_IPV6, mce_ipv6_gtpu,
	  ARRAY_SIZE(mce_ipv6_gtpu) }, /* 37 */
	{ MCE_PTYPE_GTP_C_TEID_IPV6, mce_ipv6_gtpc,
	  ARRAY_SIZE(mce_ipv6_gtpc) }, /* 38 */
	{ MCE_PTYPE_GTP_C_IPV6, mce_ipv6_udp,
	  ARRAY_SIZE(mce_ipv6_udp) }, /* 39 */
	{ MCE_PTYPE_TUN_INNER_IPV4_FRAG, mce_ipv4_frag,
	  ARRAY_SIZE(mce_ipv4_frag) }, /* 40 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP_SYNC, mce_ipv4_tcp_sync,
	  ARRAY_SIZE(mce_ipv4_tcp_sync) }, /* 41 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP, mce_ipv4_tcp,
	  ARRAY_SIZE(mce_ipv4_tcp) }, /* 42 */
	{ MCE_PTYPE_TUN_INNER_IPV4_UDP, mce_ipv4_udp,
	  ARRAY_SIZE(mce_ipv4_udp) }, /* 43 */
	{ MCE_PTYPE_TUN_INNER_IPV4_SCTP, mce_ipv4_sctp,
	  ARRAY_SIZE(mce_ipv4_sctp) }, /* 44 */
	{ MCE_PTYPE_TUN_INNER_IPV4_ESP, mce_ipv4_esp,
	  ARRAY_SIZE(mce_ipv4_esp) }, /* 45 */
	{ MCE_PTYPE_TUN_INNER_IPV4_PAY, mce_ipv4_pay,
	  ARRAY_SIZE(mce_ipv4_pay) }, /* 46 */
	{ 0, 0 }, /* 47 */
	{ MCE_PTYPE_TUN_INNER_IPV6_FRAG, mce_ipv6_frag,
	  ARRAY_SIZE(mce_ipv6_frag) }, /* 48 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP_SYNC, mce_ipv6_tcp_sync,
	  ARRAY_SIZE(mce_ipv6_tcp_sync) }, /* 49 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP, mce_ipv6_tcp,
	  ARRAY_SIZE(mce_ipv6_tcp) }, /* 50 */
	{ MCE_PTYPE_TUN_INNER_IPV6_UDP, mce_ipv6_udp,
	  ARRAY_SIZE(mce_ipv6_udp) }, /* 51 */
	{ MCE_PTYPE_TUN_INNER_IPV6_SCTP, mce_ipv6_sctp,
	  ARRAY_SIZE(mce_ipv6_sctp) }, /* 52 */
	{ MCE_PTYPE_TUN_INNER_IPV6_ESP, mce_ipv6_esp,
	  ARRAY_SIZE(mce_ipv6_esp) }, /* 53 */
	{ MCE_PTYPE_TUN_INNER_IPV6_PAY, mce_ipv6_pay,
	  ARRAY_SIZE(mce_ipv6_pay) }, /* 54 */
	{ 0, 0 }, /* 55 */
	{ MCE_PTYPE_TUN_IPV4_VXLAN, mce_ipv4_vxlan,
	  ARRAY_SIZE(mce_ipv4_vxlan) }, /* 56 */
	{ MCE_PTYPE_TUN_IPV4_GENEVE, mce_ipv4_geneve,
	  ARRAY_SIZE(mce_ipv4_geneve) }, /* 57 */
	{ MCE_PTYPE_TUN_IPV4_GRE, mce_ipv4_nvgre,
	  ARRAY_SIZE(mce_ipv4_nvgre) }, /* 58 */
	{ 0, 0 }, /* 59 */
	{ MCE_PTYPE_TUN_IPV6_VXLAN, mce_ipv6_vxlan,
	  ARRAY_SIZE(mce_ipv6_vxlan) }, /* 60 */
	{ MCE_PTYPE_TUN_IPV6_GENEVE, mce_ipv6_geneve,
	  ARRAY_SIZE(mce_ipv6_geneve) }, /* 61 */
	{ MCE_PTYPE_TUN_IPV6_GRE, mce_ipv6_nvgre,
	  ARRAY_SIZE(mce_ipv6_nvgre) }, /* 62 */
};

struct mce_profile_field_mask {
	u64 options;
	u16 bit_val;
};

struct mce_field_mask {
	u16 offset;
	u16 key_off;
	u8 mask_block[8];
	u16 mask_wide;
	u64 mask_options;
};

static const struct mce_field_mask mce_eth_mask[] = {
	{
		__builtin_offsetof(struct mce_ether_meta, dst_addr),
		4,
		"\xff\xff\xff\xff\xff\xff",
		6,
		MCE_OPT_SMAC,
	},
	{
		__builtin_offsetof(struct mce_ether_meta, src_addr),
		10,
		"\xff\xff\xff\xff\xff\xff",
		6,
		MCE_OPT_DMAC,
	},
	{
		__builtin_offsetof(struct mce_ether_meta, ethtype_id),
		0,
		"\xff\xff",
		2,
		MCE_OPT_ETHTYPE,
	},
};

static const struct mce_field_mask mce_ipv4_mask[] = {
	{ __builtin_offsetof(struct mce_ipv4_meta, src_addr),
	  0,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_IPV4_SIP },
	{ __builtin_offsetof(struct mce_ipv4_meta, dst_addr),
	  4,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_IPV4_DIP },
	{ __builtin_offsetof(struct mce_ipv4_meta, protocol),
	  8,
	  { "\xff" },
	  1,
	  MCE_OPT_L4_PROTO },
	{
		__builtin_offsetof(struct mce_ipv4_meta, dscp),
		12,
		{ "\xfc" },
		1,
		MCE_OPT_IPV4_DSCP,
	},
	{
		__builtin_offsetof(struct mce_ipv4_meta, is_frag),
		0,
		{ "\x00" },
		1,
		MCE_OPT_IPV4_FRAG,
	},
};

static const struct mce_field_mask mce_tcp_mask[] = {
	{ __builtin_offsetof(struct mce_tcp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_TCP_SPORT },
	{ __builtin_offsetof(struct mce_tcp_meta, dst_port),
	  10,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_TCP_DPORT },
};

static const struct mce_field_mask mce_udp_mask[] = {
	{ __builtin_offsetof(struct mce_udp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_UDP_SPORT },
	{ __builtin_offsetof(struct mce_udp_meta, dst_port),
	  10,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_UDP_DPORT },
};

static const struct mce_field_mask mce_sctp_mask[] = {
	{ __builtin_offsetof(struct mce_sctp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_SCTP_SPORT },
	{ __builtin_offsetof(struct mce_sctp_meta, dst_port),
	  10,
	  { "\xff\xff\xff\xff" },
	  2,
	  MCE_OPT_SCTP_DPORT },
};

static const struct mce_field_mask mce_ipv6_mask[] = {
	{ __builtin_offsetof(struct mce_ipv6_meta, src_addr),
	  0,
	  { "\xff\xff\xff\xff\xff\xff\xff\xff" },
	  16,
	  MCE_OPT_IPV6_SIP },
	{ __builtin_offsetof(struct mce_ipv6_meta, dst_addr),
	  4,
	  { "\xff\xff\xff\xff\xff\xff\xff\xff" },
	  16,
	  MCE_OPT_IPV6_DIP },
	{ __builtin_offsetof(struct mce_ipv6_meta, protocol),
	  8,
	  { "\xff" },
	  1,
	  MCE_OPT_L4_PROTO },
	{ __builtin_offsetof(struct mce_ipv6_meta, dscp),
	  12,
	  { "\xfc" },
	  1,
	  MCE_OPT_IPV6_DSCP },
	{
		__builtin_offsetof(struct mce_ipv6_meta, is_frag),
		0,
		{ "\x00" },
		1,
		MCE_OPT_IPV6_FRAG,
	},
};

static const struct mce_field_mask mce_esp_mask[] = {
	{ __builtin_offsetof(struct mce_esp_meta, spi),
	  8,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_ESP_SPI },
};

static const struct mce_field_mask mce_vxlan_mask[] = {
	{ __builtin_offsetof(struct mce_vxlan_meta, vni),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_VXLAN_VNI },
};

static const struct mce_field_mask mce_geneve_mask[] = {
	{ __builtin_offsetof(struct mce_geneve_meta, vni),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_GENEVE_VNI },
};

static const struct mce_field_mask mce_nvgre_mask[] = {
	{ __builtin_offsetof(struct mce_nvgre_meta, key),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_NVGRE_TNI },
};

static const struct mce_field_mask mce_gtp_mask[] = {
	{ __builtin_offsetof(struct mce_gtp_meta, teid),
	  12,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_GTP_U_TEID },
};

struct mce_field_mask_select_db {
	u16 type;
	const struct mce_field_mask *options_list;
	u16 sup_options_num;
};

static struct mce_field_mask_select_db mce_field_mask_db[] = {
	{ MCE_ETH_META, mce_eth_mask, ARRAY_SIZE(mce_eth_mask) },
	{ 0, 0, 0 },
	{ MCE_IPV4_META, mce_ipv4_mask, ARRAY_SIZE(mce_ipv4_mask) },
	{ MCE_IPV6_META, mce_ipv6_mask, ARRAY_SIZE(mce_ipv6_mask) },
	{ 0, 0, 0 },
	{ MCE_UDP_META, mce_udp_mask, ARRAY_SIZE(mce_udp_mask) },
	{ MCE_TCP_META, mce_tcp_mask, ARRAY_SIZE(mce_tcp_mask) },
	{ MCE_SCTP_META, mce_sctp_mask, ARRAY_SIZE(mce_sctp_mask) },
	{ MCE_ESP_META, mce_esp_mask, ARRAY_SIZE(mce_esp_mask) },
	{ MCE_VXLAN_META, mce_vxlan_mask, ARRAY_SIZE(mce_vxlan_mask) },
	{ MCE_GENEVE_META, mce_geneve_mask, ARRAY_SIZE(mce_geneve_mask) },
	{ MCE_NVGRE_META, mce_nvgre_mask, ARRAY_SIZE(mce_nvgre_mask) },
	{ MCE_GTPU_META, mce_gtp_mask, ARRAY_SIZE(mce_gtp_mask) },
	{ MCE_GTPC_META, mce_gtp_mask, ARRAY_SIZE(mce_gtp_mask) },
};

int mce_check_conflct_filed_bitmask(
	struct mce_hw_profile *profile,
	struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *src, *dst;
	bool new_mask = false;
	int i = 0;

	if (mask_info->used_block != profile->mask_info->used_block)
		return -EINVAL;
	for (i = 0; i < mask_info->used_block; i++) {
		dst = &profile->mask_info->field_bitmask[i];
		src = &mask_info->field_bitmask[i];
		if (src->key_off != dst->key_off ||
		    src->mask != dst->mask ||
		    src->options != dst->options) {
			new_mask = true;
		}
	}
	if (new_mask)
		return -EINVAL;

	return 0;
}

int mce_prof_bitmask_alloc(struct mce_hw *hw,
			   struct mce_fdir_handle *handle,
			   struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *block;
	u64 field_bitmask_opt = 0;
	int i = 0, j = 0;

	for (i = 0; i < mask_info->used_block; i++) {
		block = &mask_info->field_bitmask[i];
		for (j = 0; j < 32; j++) {
			if (handle->field_mask[j].used) {
				if (handle->field_mask[j].key_off ==
					    block->key_off &&
				    handle->field_mask[j].mask ==
					    block->mask) {
					field_bitmask_opt |= BIT(j);
					handle->field_mask[j].ref_count++;
					break;
				}
			} else {
				handle->field_mask[j].key_off =
					block->key_off;
				handle->field_mask[j].mask = block->mask;
				handle->field_mask[j].used = 1;
				handle->field_mask[j].ref_count++;
				field_bitmask_opt |= BIT(j);
				hw->ops->fd_field_bitmask_setup(
					hw, &handle->field_mask[j], j);
				break;
			}
		}
	}

	return field_bitmask_opt;
}

int mce_conflct_profile_check(struct mce_fdir_handle *handle,
			      struct mce_fdir_filter *filter)
{
	u64 profile_id = filter->profile_id;
	struct mce_hw_profile *profile = handle->profiles[profile_id];

	if (profile == NULL)
		return 0;
	if (profile->ref_cnt && profile->options == filter->options)
		return -EBUSY;
	if (profile->ref_cnt == 0) {
		kfree(profile);
		handle->profiles[profile_id] = NULL;
	}
	return 0;
}

int mce_check_field_bitmask_valid(struct mce_lkup_meta *meta)
{
	union mce_flow_hdr *mask = &meta->mask;
	const struct mce_field_mask *field_opt;
	enum flow_meta_type type = meta->type;
	union mce_flow_hdr zero_mask = { 0 };
	const char all_zero[256] = { 0 };
	int i = 0, j = 0;
	u8 *ptr = NULL;
	u16 block = 0;

	if (meta->type >= MCE_META_TYPE_MAX)
		return 0;

	field_opt = mce_field_mask_db[type].options_list;
	if (!memcmp(&zero_mask, mask, sizeof(*mask)))
		return 0;
	ptr = (u8 *)mask;
	for (i = 0; i < mce_field_mask_db[type].sup_options_num;
	     i++, field_opt++) {
		if (!memcmp(all_zero, (ptr + field_opt->offset),
			    field_opt->mask_wide))
			continue;
		if (!memcmp((void const *)field_opt->mask_block,
			    (ptr + field_opt->offset),
			    field_opt->mask_wide))
			continue;
		if (field_opt->mask_wide > 1) {
			u16 *fv =
				(u16 *)(((u8 *)mask) + field_opt->offset);
			for (j = 0; j < field_opt->mask_wide / 2; j++) {
				if (fv[j] != 0xffff)
					block++;
			}
		} else {
			if (!memcmp((u8 *)mask + field_opt->offset,
				    &field_opt->mask_block, 1))
				continue;
			block++;
		}
	}

	return block;
}

int mce_fdir_field_mask_init(struct mce_lkup_meta *meta, u16 meta_num,
			     struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *block_mask = NULL;
	const struct mce_field_mask *field_opt;
	const char all_zero[256] = { 0 };
	union mce_flow_hdr *mask;
	int i = 0, j = 0, k = 0;
	u16 field_size = 0, *fv, block = 0, type = 0;
	u8 *ptr = NULL;

	/* ipv6-[3] ipv6[2] ipv6[1]--- ipv6-sip[0] */
	/*                        |< 96 >|  32     */
	/*             		  |   6   |   2    */
	/*                        | 128          | */
	/* 13 12 11 10 | 9 8 |765 432  | 1	0 |*/
	block_mask = mask_info->field_bitmask;
	for (i = 0; i < meta_num; i++) {
		type = meta[i].type;
		mask = &meta[i].mask;
		if (type == MCE_META_TYPE_MAX)
			continue;
		ptr = (u8 *)mask;
		field_size = mce_field_mask_db[type].sup_options_num;
		field_size *= sizeof(struct mce_field_mask);
		field_opt = mce_field_mask_db[type].options_list;
		for (j = 0; j < mce_field_mask_db[type].sup_options_num;
		     j++, field_opt++) {
			if (!memcmp(all_zero, (ptr + field_opt->offset),
				    field_opt->mask_wide))
				continue;
			fv = (u16 *)(((u8 *)mask) + field_opt->offset);
			if (field_opt->mask_wide == 1) {
				if (fv[0] != 0xff) {
					block_mask->options =
						field_opt->mask_options;
					block_mask->key_off =
						field_opt->key_off + k * 2;
					block_mask->mask = fv[0];
					block_mask++;
					block++;
				}
			} else {
				for (k = 0; k < field_opt->mask_wide / 2;
				     k++) {
					if (fv[k] != 0xffff) {
						fd_print(
							"type:%d field_opt->mask_wide %d fv 0x%.2x\n",
							type,
							field_opt->mask_wide,
							fv[k]);
						block_mask->options =
							field_opt
								->mask_options;
						block_mask->key_off =
							field_opt->key_off +
							k * 2;
						fd_print(
							"type:%d base_key_off %d k %d\n",
							type,
							block_mask->key_off,
							k);
						if (k > 1) {
							if (field_opt->mask_options ==
							    MCE_OPT_IPV6_SIP) {
								block_mask
									->key_off +=
									12;
							}
							if (field_opt->mask_options ==
							    MCE_OPT_IPV6_DIP)
								block_mask
									->key_off +=
									20;
						}
						fd_print(
							"type:%d block_mask->key_off 0x%.2x\n",
							type,
							block_mask
								->key_off);
						block_mask->mask = fv[k];
						block_mask++;
						block++;
					} else {
						fd_print(
							"type:%d mask=0xffff\n",
							type);
					}
				}
			}
		}
	}
	mask_info->used_block = block;

	return block;
}

struct mce_hw_profile *
mce_fdir_alloc_profile(struct mce_fdir_handle *handle,
		       struct mce_fdir_filter *filter)
{
	struct mce_profile_select_db *profile_db = NULL;
	struct mce_hw_profile *profile = NULL;
	u32 profile_id = filter->profile_id;
	int i, j, bit = -1, bit_num = 0;
	u64 options = filter->options;
	bool mask_match = false;

	if (mce_conflct_profile_check(handle, filter))
		return NULL;
	profile = kzalloc(sizeof(*profile), GFP_KERNEL);
	if (profile == NULL)
		return NULL;
	profile->profile_id = profile_id;
	profile_db = &mce_profile_bitmask[profile_id];
	bit_num = __user_popcount(options);
#if 0
	fd_print("profile_id:0x%x options:0x%llx bit_num:%d\n", profile_id,
		 options, bit_num);
#endif
	for (i = 0; i < bit_num; i++) {
		bit = __builtin_ffsll(options) - 1;
		if (bit < 0)
			break;
		for (j = 0; j < profile_db->sup_options_num; j++) {
#if 0
			fd_print(
				"profile_id:0x%x i:%d bit:%d j:%d db:0x%llx\n",
				profile_id, i, bit, j,
				profile_db->options_list[j].options);
#endif
			if (BIT_ULL(bit) ==
			    profile_db->options_list[j].options) {
				profile->fied_mask |=
					profile_db->options_list[j]
						.field_mask;
				mask_match = true;
			}
		}
		options &= ~BIT_ULL(bit);
	}
#define MCE_PROFILE_NO_OPT MCE_OPT_TCP_SYNC
	if (!mask_match && !(filter->options & MCE_PROFILE_NO_OPT)) {
		kfree(profile);
		return NULL;
	}
	profile->options = filter->options;

	return profile;
}

int mce_fdir_remove_profile(struct mce_hw *hw,
			    struct mce_fdir_handle *handle,
			    struct mce_fdir_filter *filter)
{
	struct mce_hw_profile *profile = NULL;
	u16 profile_id = filter->profile_id;

	profile = handle->profiles[profile_id];
	if (profile == NULL) {
		dev_err(mce_hw_to_dev(hw),
			"%s: profile ptr is null, profile id:0x%x\n",
			__func__, profile_id);
		return -1;
	}
	if (profile->mask_info) {
		profile->mask_info->ref_cnt--;
		if (profile->mask_info->ref_cnt == 0) {
			hw->ops->fd_profile_field_bitmask_update(
				hw, profile_id, 0);
			kfree(profile->mask_info);
			profile->mask_info = NULL;
		}
	}
	profile->ref_cnt--;
	if (profile->ref_cnt == 0) {
		hw->ops->fd_profile_update(hw, profile, false);
		kfree(profile);
		handle->profiles[profile_id] = NULL;
	}
	return 0;
}