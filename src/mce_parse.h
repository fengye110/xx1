#ifndef _MCE_PARSE_H_
#define _MCE_PARSE_H_

#define __MCE_IPV4_HDR_DSCP_MASK (0xfc)
#define __MCE_IPV6_HDR_DSCP_MASK (0xfc)

enum mce_flow_params_error_type {
	MCE_FLOW_PARAMS_ERROR_ETH = 100,
	MCE_FLOW_PARAMS_ERROR_MAX,
};

enum mce_flow_item_type {
	MCE_FLOW_ITEM_TYPE_END,
	MCE_FLOW_ITEM_TYPE_VOID,
	MCE_FLOW_ITEM_TYPE_INVERT,
	MCE_FLOW_ITEM_TYPE_ANY,
	MCE_FLOW_ITEM_TYPE_PORT_ID,
	MCE_FLOW_ITEM_TYPE_RAW,
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_VLAN,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_ICMP,
	MCE_FLOW_ITEM_TYPE_UDP,
	MCE_FLOW_ITEM_TYPE_TCP,
	MCE_FLOW_ITEM_TYPE_SCTP,
	MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_E_TAG,
	MCE_FLOW_ITEM_TYPE_NVGRE,
	MCE_FLOW_ITEM_TYPE_MPLS,
	MCE_FLOW_ITEM_TYPE_GRE,
	MCE_FLOW_ITEM_TYPE_FUZZY,
	MCE_FLOW_ITEM_TYPE_GTP,
	MCE_FLOW_ITEM_TYPE_GTPC,
	MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_VXLAN_GPE,
	MCE_FLOW_ITEM_TYPE_ARP_ETH_IPV4,
	MCE_FLOW_ITEM_TYPE_IPV6_EXT,
	MCE_FLOW_ITEM_TYPE_ICMP6,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_NS,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_NA,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_OPT,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH,
	MCE_FLOW_ITEM_TYPE_MARK,
	MCE_FLOW_ITEM_TYPE_META,
	MCE_FLOW_ITEM_TYPE_GRE_KEY,
	MCE_FLOW_ITEM_TYPE_GTP_PSC,
	MCE_FLOW_ITEM_TYPE_PPPOES,
	MCE_FLOW_ITEM_TYPE_PPPOED,
	MCE_FLOW_ITEM_TYPE_PPPOE_PROTO_ID,
	MCE_FLOW_ITEM_TYPE_NSH,
	MCE_FLOW_ITEM_TYPE_IGMP,
	MCE_FLOW_ITEM_TYPE_AH,
	MCE_FLOW_ITEM_TYPE_HIGIG2,
	MCE_FLOW_ITEM_TYPE_TAG,
	MCE_FLOW_ITEM_TYPE_L2TPV3OIP,
	MCE_FLOW_ITEM_TYPE_PFCP,
	MCE_FLOW_ITEM_TYPE_ECPRI,
	MCE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
	MCE_FLOW_ITEM_TYPE_GENEVE_OPT,
	MCE_FLOW_ITEM_TYPE_INTEGRITY,
	MCE_FLOW_ITEM_TYPE_CONNTRACK,
	MCE_FLOW_ITEM_TYPE_PORT_REPRESENTOR,
	MCE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
	MCE_FLOW_ITEM_TYPE_FLEX,
	MCE_FLOW_ITEM_TYPE_L2TPV2,
	MCE_FLOW_ITEM_TYPE_PPP,
	MCE_FLOW_ITEM_TYPE_GRE_OPTION,
	MCE_FLOW_ITEM_TYPE_MACSEC,
	MCE_FLOW_ITEM_TYPE_METER_COLOR,
	MCE_FLOW_ITEM_TYPE_MAX_NUM, /* 61 */
};

#define MCE_PARSE_FLOW_ITERM_LOOKUP_LISTS   \
	(BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH) |  \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_VLAN) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP) |  \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP) |  \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_SCTP) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_ESP))
#define MCE_PARSE_ENC_OUTER_FLOW_ITERM_LOOKUP_LISTS \
	(BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH) |          \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4) |         \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6) |         \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP) |          \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_VXLAN) |        \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GENEVE) |       \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_NVGRE) |        \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPC) |         \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPU))
#define MCE_PARSE_ENC_INNER_FLOW_ITERM_LOOKUP_LISTS \
	(BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH) |          \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4) |         \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6) |         \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP) |          \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP) |          \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_SCTP) |         \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_VXLAN) |        \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GENEVE) |       \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_NVGRE) |        \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPC) |         \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPU))

struct mce_fdir_handle;
struct mce_tc_flower_fltr;
struct mce_lkup_meta *
mce_parse_get_next_meta(struct mce_fdir_handle *handle, u32 *meta_num,
			  bool is_tunnel);
int mce_fd_check_params_valid(struct mce_tc_flower_fltr *tc_fltr,
			      struct mce_lkup_meta *meta, int meta_num,
			      bool is_tunnel);
int mce_parse_eth(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_enc_eth(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
			struct mce_lkup_meta *meta, u64 *inset,
			u8 *fd_compose, bool is_tunnel);
int mce_parse_vlan(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		   struct mce_lkup_meta *meta, u64 *inset, u8 *fd_compose,
		   bool is_tunnel);
int mce_parse_ip4(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_enc_ip4(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
			struct mce_lkup_meta *meta, u64 *inset,
			u8 *fd_compose, bool is_tunnel);
int mce_parse_ip6(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_enc_ip6(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
			struct mce_lkup_meta *meta, u64 *inset,
			u8 *fd_compose, bool is_tunnel);
int mce_parse_udp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_enc_udp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
			struct mce_lkup_meta *meta, u64 *inset,
			u8 *fd_compose, bool is_tunnel);
int mce_parse_tcp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_sctp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		     struct mce_lkup_meta *meta, u64 *inset,
		     u8 *fd_compose, bool is_tunnel);
int mce_parse_vxlan(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		      struct mce_lkup_meta *meta, u64 *inset,
		      u8 *compose, bool is_tunnel);
int mce_parse_geneve(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		       struct mce_lkup_meta *meta, u64 *inset,
		       u8 *compose, bool is_tunnel);
int mce_parse_nvgre(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		      struct mce_lkup_meta *meta, u64 *inset,
		      u8 *compose, bool is_tunnel);
int mce_parse_gtpc(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		     struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		     bool is_tunnel);
int mce_parse_gtpu(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		     struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		     bool is_tunnel);
int mce_parse_esp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		  struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		  bool is_tunnel);
#endif