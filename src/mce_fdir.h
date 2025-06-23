#ifndef _MCE_FDIR_H_
#define _MCE_FDIR_H_

#define __SUPPORT_FD__
#ifdef __SUPPORT_FD__
#include "mce_fdir_flow.h"

struct mce_fdir_filter;
typedef int (*flow_engine_init_t)(struct mce_pf *pf, void **handle);
typedef int (*flow_engine_create_t)(struct mce_pf *pf,
				    struct mce_fdir_filter *filter,
				    struct mce_tc_flower_fltr *fltr);
typedef int (*flow_engine_destroy_t)(struct mce_pf *pf,
				     struct mce_fdir_filter *filter,
				     struct mce_tc_flower_fltr *fltr);
struct mce_flow_engine_module {
	flow_engine_init_t init; /* Init module manage resource info */
	//flow_engine_uinit_t uinit; /* release all manage flow rule */
	// flow_engine_parse_t parse; /* check pattern hw can support */
	flow_engine_create_t create; /* create redit flow action */
	flow_engine_destroy_t destroy; /* destroy the rule by add before */
	//flow_engine_query_t query;
	enum mce_flow_module type;
	void *handle;
};

#endif /* __SUPPORT_FD__ */

enum mce_fltr_ptype {
	MCE_FLTR_PTYPE_NONE = 0,
	MCE_FLTR_PTYPE_NONF_ETH,
	MCE_FLTR_PTYPE_IPV4_TCP,
	MCE_FLTR_PTYPE_IPV4_UDP,
	MCE_FLTR_PTYPE_IPV4_SCTP,
	MCE_FLTR_PTYPE_IPV4_OTHER,
	MCE_FLTR_PTYPE_IPV6_TCP,
	MCE_FLTR_PTYPE_IPV6_UDP,
	MCE_FLTR_PTYPE_IPV6_SCTP,
	MCE_FLTR_PTYPE_IPV6_OTHER,
};

struct mce_fdir_v4 {
	__be32 dst_ip;
	__be32 src_ip;
	__be16 dst_port;
	__be16 src_port;
	__be32 l4_header;
	__be32 sec_parm_idx;	/* security parameter index */
	u8 tos;
	u8 ip_ver;
	u8 proto;
	u8 ttl;
};

#define MCE_IPV6_ADDR_LEN_AS_U32		4
#define N20_MAX_ETYPE_FDIR_CNT (15)

struct mce_fdir_v6 {
	__be32 dst_ip[MCE_IPV6_ADDR_LEN_AS_U32];
	__be32 src_ip[MCE_IPV6_ADDR_LEN_AS_U32];
	__be16 dst_port;
	__be16 src_port;
	__be32 l4_header; /* next header */
	__be32 sec_parm_idx; /* security parameter index */
	u8 tc;
	u8 proto;
	u8 hlim;
};
struct mce_fdir_eth {
	u8 dst[ETH_ALEN];
	u8 src[ETH_ALEN];
	__be16 type;
};

struct mce_fdir_fltr {
	struct list_head fltr_node;
	struct mce_fdir_eth eth, eth_mask;
	union {
		struct mce_fdir_v4 v4;
		struct mce_fdir_v6 v6;
	}ip, mask;
	enum mce_fltr_ptype flow_type;
	u32 fltr_id;
	u32 q_id;
	u32 fltr_config;
	u32 fltr_action;
	int vfid;
	int etype_loc;
	int tuple5_loc;
#define F_FLTR_ACTION_DROP BIT(31)
};

struct mce_fdir_fltr *mce_fdir_find_fltr_by_idx(struct mce_hw *hw, u32 fltr_idx);
bool mce_fdir_is_dup_fltr(struct mce_hw *hw, struct mce_fdir_fltr *input);
void mce_fdir_del_all_fltrs(struct mce_hw *hw);

extern struct mce_flow_engine_module mce_fdir_engine;

#endif /* _MCE_FDIR_H_ */
