#ifndef _MCE_FDIR_FLOW_H_
#define _MCE_FDIR_FLOW_H_

#define MCE_FD_DEBUG (0)
#if MCE_FD_DEBUG
#define fd_debug(hw, fmt, args...) \
	dev_info(mce_hw_to_dev(hw), "%s fd:" fmt, __func__, ##args)
#define fd_print(fmt, args...) printk("%s fd:" fmt, __func__, ##args)
#else
#define fd_debug(hw, fmt, args...) \
	do {                       \
	} while (0)
#define fd_print(fmt, args...) \
	do {                   \
	} while (0)
#endif

#include "mce_parse.h"
#include "mce_profile_mask.h"

#define MCE_ATR_BUCKET_HASH_KEY 0x3DAD14E2
#define MCE_ATR_SIGNATURE_HASH_KEY 0x174D3614

#define MCE_HASH_VALID_BIT GENMASK(12, 0)
#define MCE_SIGN_HASH_VALID_BIT GENMASK(15, 0)

#define MCE_FDIR_EXACT_ENTRAYS_BITS (13)
#define MCE_MAX_FDIR_EXACT_ENTRY (1 << MCE_FDIR_EXACT_ENTRAYS_BITS)
#define MCE_FDIR_SIGN_ENTRAYS_BITS (14)
#define MCE_MAX_FDIR_SIGN_ENTRY (1 << MCE_FDIR_SIGN_ENTRAYS_BITS)
#define MCE_NODE_MAX_ENTRY (4)
#define MCE_SIGN_NODE_MAX_ENTRY (4)
#define MCE_EXACT_NODE_MAX_ENTRY (2)

/* common all rule action bit define */
#define MCE_RULE_ACTION_DROP BIT(31)
#define MCE_RULE_ACTION_PASS (0)
#define MCE_RULE_ACTION_Q_EN BIT(30)
#define MCE_RULE_ACTION_VLAN_EN BIT(29)
#define MCE_RULE_ACTION_MARK_EN BIT(28)
#define MCE_RULE_ACTION_PRIO_EN BIT(27)
#define MCE_RULE_ACTION_Q_S (18)
#define MCE_RULE_ACTION_Q_MASK GENMASK(28, 18)
#define MCE_RULE_ACTION_POP_VLAN_MASK GENMASK(17, 16)
#define MCE_RULE_ACTION_POP_VLAN_S (16)
#define MCE_RULE_ACTION_MARK_MASK GENMASK(15, 0)

enum mce_pop_vlan_tag {
	MCE_POP_1VLAN = 1,
	MCE_POP_2VLAN,
	MCE_POP_3VLAN,
};

struct mce_inset_key {
	u64 inset_key0;
	u64 inset_key1;
} __packed __aligned(1);

struct mce_inset_key_extend {
	u32 dword_key[6];
} __packed __aligned(1);

struct mce_hw_inset_key {
	struct mce_inset_key inset;
	struct mce_inset_key_extend inset_ex;
	u32 dscp_vtag;
	u16 tun_type;
} __packed __aligned(1);

union mce_hash_data {
	struct {
		u32 hash_inset[10];
		u16 rev;
	};
	u16 word_stream[21];
} __packed __aligned(1);

union mce_ext_seg {
	struct {
		u16 first_seg : 15;
		u16 pad : 1;

		u16 data_1[21];
		u16 end_seg;
		/* 366 bit */
	};
	u16 word_stream[23];
} __packed __aligned(1);

struct mce_hash_key {
	u32 key[11];
} __packed __aligned(1);

/* Flow Director ATR input struct. */
union mce_exact_atr_input {
	struct {
		u16 next_fd_ptr : 13;
		u16 end : 1;
		u16 resv1 : 2;
		/* 16 bit */
		union {
			struct {
				u32 action;
				u16 priority : 3;
				u16 resv2 : 1;
				u16 e_vld : 1;
				u16 profile_id : 6;
				u16 resv3 : 5;
				u8 port : 7;
				u8 resv4 : 1;
				/* 56 bit */
				struct mce_inset_key inset;
				/* 184 bit */
			} __packed __aligned(1);
		} entry[MCE_EXACT_NODE_MAX_ENTRY];
		/* 384 bit */
	} v4;
	struct {
		u64 next_fd_ptr : 13;
		u64 end : 1;
		u64 action : 32;
		u64 priority : 3;
		u64 resv1 : 1;
		u64 e_vld : 1;
		u64 profile_id : 6;
		u64 port : 7;
		/* 64 bit */
		struct mce_inset_key inset;
		/* 192 bit */
		struct mce_inset_key_extend inset_ex;
		/* 384 bit */
	} v6;
	u32 dword_stream[12];
} __packed __aligned(1);

union mce_sign_atr_input {
	struct {
		u16 next_fd_ptr : 13;
		u16 end : 1;
		u16 resv1 : 2;
		/* 16 bit */
		struct {
			u32 actions;
			/* 32 bit */
			u32 priority : 3;
			u32 resv2 : 1;
			u32 resv3 : 4;
			u32 e_vld : 1;
			u32 profile_id : 6;
			u32 port : 7;
			u32 resv4 : 2;
			u32 sign_p1 : 8;
			/* 64 bit */
			u8 sign[3];
			/* 88 bit */
		} __packed __aligned(1) entry[MCE_SIGN_NODE_MAX_ENTRY];
		/* 192 bit */
	} __packed __aligned(1);
	u32 dword_stream[12];
} __packed __aligned(1);

enum mce_fdir_hash_mode {
	MCE_MODE_HASH_INSET,
	MCE_MODE_HASH_EX_PORT,
};

struct mce_node_key {
	union {
		/* exact_key */
		struct mce_hw_inset_key hw_inset;
		/* sign_key */
		u32 sign_hash;
	};
	bool used;
};

struct mce_node_info {
	struct mce_node_key key[MCE_NODE_MAX_ENTRY];

	u8 bit_used;
};

enum mce_fdir_mode_type {
	MCE_FDIR_EXACT_M_MODE,
	MCE_FDIR_SIGN_M_MODE,
	MCE_FDIR_MACVLAN_MODE,
};

struct mce_fdir_node {
	struct list_head entry;
	enum mce_fdir_mode_type type;
	union mce_exact_atr_input exact_meta;
	union mce_sign_atr_input sign_meta;
	struct mce_node_info node_info;
	bool is_ipv6;
	u16 loc;
};

/* Flow Director ATR input struct. */
union mce_fdir_pattern {
	struct {
		union {
			struct {
				u8 src_mac[ETH_ALEN];
				u8 dst_mac[ETH_ALEN];
				u16 vlan_id;
			};
			struct {
				u16 ether_type;
				u32 dst_addr[4];
				u32 src_addr[4];
				u8 ip_tos;
				u8 protocol;
				u16 l4_sport;
				u16 l4_dport;
				union {
					u32 vni;
					u32 key;
					u32 esp_spi;
					u32 teid;
					u32 vtag; /* sctp vtag */
				};
				u16 tun_type;
			};
		};
	} __packed __aligned(1) formatted;
} __packed __aligned(1);

struct mce_hw_rule_inset {
	struct mce_hw_inset_key keys;

	u32 action;
	u8 profile_id;
	u8 port;
	u8 priority;
};

struct mce_rule_date {
	u32 dword_stream[12];
};

enum mce_filter_action {
	MCE_FILTER_PASS,
	MCE_FILTER_DROP,
};

struct mce_flow_action {
	u8 redirect_en;
	u8 mark_en;
	u8 pop_vlan;
	u8 rss_cfg;
	u8 priority;
	enum mce_filter_action rule_action;
};

struct mce_fdir_filter {
	struct mce_rule_date data;
	struct mce_hw_rule_inset hw_inset;
	union mce_fdir_pattern lkup_pattern;
	struct hlist_node hl_node;
	u64 key;
	bool is_ipv6;

	struct mce_flow_action actions;
	u32 fdirhash; /* hash value for fdir */
	u32 signhash;
	bool hash_child;
	bool clear_node;
	u16 profile_id;
	struct mce_lkup_meta *meta;
	struct mce_field_bitmask_info *mask_info;
	u64 options;
	u16 meta_num;
	u16 loc;
	int rule_engine;
};

struct mce_fdir_hash_entry {
	u32 fdir_hash;
	u16 nb_child;
	bool is_ipv6;
	struct list_head entry;
	struct list_head node_entrys;
};

enum flow_meta_type {
	MCE_ETH_META = 0,
	MCE_VLAN_META,
	MCE_IPV4_META,
	MCE_IPV6_META,
	MCE_IP_FRAG,
	MCE_UDP_META,
	MCE_TCP_META,
	MCE_SCTP_META,
	MCE_ESP_META,
	MCE_VXLAN_META,
	MCE_GENEVE_META,
	MCE_NVGRE_META,
	MCE_GTPU_META,
	MCE_GTPC_META,
	MCE_VPORT_ID,
	MCE_META_TYPE_MAX,
};

struct mce_ether_meta {
	u8 dst_addr[ETH_ALEN];
	u8 src_addr[ETH_ALEN];

	u16 ethtype_id;
};

struct mce_vlan_meta {
	u16 vlan_id;
};

struct mce_ipv4_meta {
	u32 src_addr;
	u32 dst_addr;
	u8 protocol;
	u8 is_frag;
	u8 dscp;
};

struct mce_ipv6_meta {
	u32 src_addr[4];
	u32 dst_addr[4];
	u8 protocol;
	u8 dscp;
	u8 is_frag;
};

struct mce_ip_frag_meta {
	u8 is_frag;
};

struct mce_tcp_meta {
	u16 src_port;
	u16 dst_port;
};

struct mce_udp_meta {
	u16 src_port;
	u16 dst_port;
};

struct mce_sctp_meta {
	u16 src_port;
	u16 dst_port;
	u32 vtag;
};

struct mce_esp_meta {
	u32 spi;
};

struct mce_vxlan_meta {
	u32 vni;
};

struct mce_geneve_meta {
	u32 vni;
};

struct mce_nvgre_meta {
	u32 key;
};

struct mce_gtp_meta {
	u32 teid; /**< Tunnel endpoint identifier. */
};

struct mce_vport_meta {
	u16 vport_id;
};

enum mce_flow_module {
	MCE_FLOW_GENERIC = 1,
	MCE_FLOW_RSS,
	MCE_FLOW_FDIR,
};

union mce_flow_hdr {
	struct mce_ether_meta eth_meta;
	struct mce_vlan_meta vlan_meta;
	struct mce_ipv4_meta ipv4_meta;
	struct mce_ipv6_meta ipv6_meta;
	struct mce_ip_frag_meta frag_meta;
	struct mce_tcp_meta tcp_meta;
	struct mce_udp_meta udp_meta;
	struct mce_sctp_meta sctp_meta;
	struct mce_esp_meta esp_meta;
	struct mce_vxlan_meta vxlan_meta;
	struct mce_geneve_meta geneve_meta;
	struct mce_nvgre_meta nvgre_meta;
	struct mce_gtp_meta gtp_meta;
	struct mce_vport_meta vport_meta;
};

struct mce_lkup_meta {
	enum flow_meta_type type;
	union mce_flow_hdr hdr;
	union mce_flow_hdr mask;
};

struct mce_fdir_field_mask {
	u16 key_off;
	u16 mask;
	u16 loc;
	bool used;
	u64 ref_count;
};

struct mce_fdir_handle {
	DECLARE_HASHTABLE(fdir_exact_tb, MCE_FDIR_EXACT_ENTRAYS_BITS);
	DECLARE_HASHTABLE(fdir_sign_tb, MCE_FDIR_SIGN_ENTRAYS_BITS);
	struct list_head hash_node_v4_list;
	struct list_head hash_node_v6_list;
	enum mce_fdir_mode_type mode;
	enum mce_fdir_hash_mode hash_mode;
	struct mce_fdir_field_mask field_mask[32];
	struct mce_lkup_meta meta_db[2][MCE_META_TYPE_MAX];
	struct mce_hw_profile *profiles[64];
	u32 entry_bitmap[128];
	bool fdir_flush_en;
};

static inline unsigned int __user_popcount(u64 x)
{
	unsigned int count = 0;
	while (x) {
		count += x & 1;
		x >>= 1;
	}
	return count;
}

typedef int (*mce_fdir_profile_key_encode)(struct mce_fdir_filter *filter);
struct mce_fdir_key_encode {
	u64 profile_id;
	mce_fdir_profile_key_encode key_encode;
};

struct mce_flow_ptype_match;
int mce_compose_init_item_type(u8 **compose);
int mce_compose_find_prof_id(struct mce_pf *pf, u8 *compose, u16 *prof_id,
			     struct mce_tc_flower_fltr *tc_fltr);
int mce_compose_deinit_item_type(u8 *compose);
int mce_compose_set_item_type(u8 *compose,
				enum mce_flow_item_type type);
void mce_init_flow_engine(struct mce_pf *pf, int mode);
void *mce_get_engine_handle(struct mce_pf *pf,
			      enum mce_flow_module type);
struct mce_fdir_filter *
mce_meta_to_fdir_rule(struct mce_hw *hw,
			struct mce_fdir_handle *handle, u16 meta_num,
			bool is_ipv6, bool is_tunnel);
struct mce_fdir_filter *
mce_meta_to_fdir_rule_l2(struct mce_hw *hw, struct mce_fdir_handle *handle,
			 u16 meta_num, bool is_ipv6, bool is_tunnel);
int mce_fdir_key_setup(struct mce_fdir_filter *filter);
#endif /* _MCE_FDIR_FLOW__H_ */
