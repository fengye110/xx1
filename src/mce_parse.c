#include "mce.h"
#include "mce_tc_lib.h"
#include "mce_parse.h"
#include "mce_pattern.h"

struct mce_lkup_meta *
mce_parse_get_next_meta(struct mce_fdir_handle *handle, u32 *meta_num,
			  bool is_tunnel)
{
	struct mce_lkup_meta *meta = NULL;

	meta = &handle->meta_db[is_tunnel][*meta_num];
	memset(meta, 0, sizeof(*meta));
	meta->type = MCE_META_TYPE_MAX;
	++*meta_num;
	return meta;
}

static bool
mce_enc_udp_is_support_proto(struct mce_tc_flower_fltr *tc_fltr)
{
	if (tc_fltr->tunnel_type == TNL_GRETAP)
		return false;
	return true;
}

static bool
mce_enc_inner_eth_type_is_support_proto(struct mce_tc_flower_fltr *tc_fltr,
					bool is_tunnel)
{
	if (!is_tunnel)
		return true;

	if (tc_fltr->tunnel_type == TNL_VXLAN ||
	    tc_fltr->tunnel_type == TNL_GENEVE ||
	    tc_fltr->tunnel_type == TNL_GRETAP)
		return true;
	return false;
}

static bool
mce_enc_inner_eth_is_support_proto(struct mce_tc_flower_fltr *tc_fltr,
				   bool is_tunnel)
{
	if (!is_tunnel)
		return true;
	if (tc_fltr->tunnel_type == TNL_VXLAN ||
	    tc_fltr->tunnel_type == TNL_GENEVE)
		return true;
	return false;
}

static int __mce_fd_check_eth_valid(struct mce_tc_flower_fltr *tc_fltr,
				    struct mce_lkup_meta *meta,
				    int meta_num, bool is_tunnel)
{
	u16 etype_id;

	if (meta_num < 1)
		return 0;
	if (meta[meta_num - 1].type == MCE_ETH_META) {
		etype_id = meta->hdr.eth_meta.ethtype_id;
		if (etype_id == ETH_P_IP || etype_id == ETH_P_IPV6 ||
		    etype_id == ETH_P_8021Q || etype_id == ETH_P_8021AD)
			return -MCE_FLOW_PARAMS_ERROR_ETH;
	}
	return 0;
}

int mce_fd_check_params_valid(struct mce_tc_flower_fltr *tc_fltr,
			      struct mce_lkup_meta *meta, int meta_num,
			      bool is_tunnel)
{
	int ret = 0;

	/* check eth mode */
	ret = __mce_fd_check_eth_valid(tc_fltr, meta, meta_num, is_tunnel);
	if (ret)
		return ret;
	return ret;
}

int mce_parse_eth(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		    bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	u64 options = 0;

	headers = is_tunnel ? &tc_fltr->inner_headers :
			      &tc_fltr->outer_headers;
	if (!(flags & MCE_TC_FLWR_FIELD_ETH_TYPE_ID))
		return -EINVAL;

	meta->hdr.eth_meta.ethtype_id = htons(headers->l2_key.n_proto);
	meta->mask.eth_meta.ethtype_id = htons(headers->l2_mask.n_proto);
	fd_print("outer start n_proto:0x%x mask:0x%x\n",
		 headers->l2_key.n_proto, headers->l2_mask.n_proto);
	if (meta->hdr.eth_meta.ethtype_id == ETH_P_IP ||
	    meta->hdr.eth_meta.ethtype_id == ETH_P_IPV6) {
		if (!mce_enc_inner_eth_is_support_proto(tc_fltr,
							is_tunnel))
			return -1;
	} else {
		if (!mce_enc_inner_eth_type_is_support_proto(tc_fltr,
							     is_tunnel))
			return -1;
	}

	options |= MCE_OPT_ETHTYPE;
	fd_print("outer end n_proto:0x%x mask:0x%x\n",
		 headers->l2_key.n_proto, headers->l2_mask.n_proto);
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_ETH);

	if (flags &
	    (MCE_TC_FLWR_FIELD_DST_MAC | MCE_TC_FLWR_FIELD_SRC_MAC)) {
		struct mce_tc_l2_hdr *l2_key, *l2_mask;

		l2_key = &headers->l2_key;
		l2_mask = &headers->l2_mask;

		if (flags & MCE_TC_FLWR_FIELD_DST_MAC) {
			ether_addr_copy(meta->hdr.eth_meta.dst_addr,
					l2_key->dst_mac);
			ether_addr_copy(meta->mask.eth_meta.dst_addr,
					l2_mask->dst_mac);
			options |= MCE_OPT_DMAC;
		}
		if (flags & MCE_TC_FLWR_FIELD_SRC_MAC) {
			ether_addr_copy(meta->hdr.eth_meta.src_addr,
					l2_key->src_mac);
			ether_addr_copy(meta->mask.eth_meta.src_addr,
					l2_mask->src_mac);
			options |= MCE_OPT_SMAC;
		}
	}

	if (options) {
		meta->type = MCE_ETH_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_vlan(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		   struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		   bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	u64 options = 0;

	headers = is_tunnel ? &tc_fltr->inner_headers :
			      &tc_fltr->outer_headers;
	if (!(flags & MCE_TC_FLWR_FIELD_VLAN))
		return -EINVAL;

	meta->hdr.vlan_meta.vlan_id =
		cpu_to_be16(headers->vlan_hdr.vlan_id);
	meta->mask.vlan_meta.vlan_id = cpu_to_be16(VLAN_VID_MASK);

	options |= MCE_OPT_VLAN_VID;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_VLAN);
	fd_print("vlan_id:0x%x mask:0x%x\n", meta->hdr.vlan_meta.vlan_id,
		 meta->mask.vlan_meta.vlan_id);
	if (options) {
		meta->type = MCE_VLAN_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_enc_eth(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
			struct mce_lkup_meta *meta, u64 *inset,
			u8 *compose, bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	u64 options = 0;

	headers = &tc_fltr->inner_headers;
	meta->hdr.eth_meta.ethtype_id = headers->l2_key.n_proto;
	meta->mask.eth_meta.ethtype_id = headers->l2_mask.n_proto;

	/* tunnel packets, outer eth must existed, may ignore eth type */
	fd_print("n_proto:0x%x mask:0x%x\n", headers->l2_key.n_proto,
		 headers->l2_mask.n_proto);
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_ETH);

	/* in tunnel inner mode, no need analyze eth type, return directly*/
	if (tc_fltr->parsed_inner)
		return 0;
	options |= MCE_OPT_ETHTYPE;
	if (flags & MCE_TC_FLWR_FIELD_ENC_DST_MAC) {
		struct mce_tc_l2_hdr *l2_key, *l2_mask;

		l2_key = &headers->l2_key;
		l2_mask = &headers->l2_mask;

		if (flags & MCE_TC_FLWR_FIELD_ENC_DST_MAC) {
			ether_addr_copy(meta->hdr.eth_meta.dst_addr,
					l2_key->dst_mac);
			ether_addr_copy(meta->mask.eth_meta.dst_addr,
					l2_mask->dst_mac);
			options |= MCE_OPT_DMAC;
		}
	}

	if (options) {
		meta->type = MCE_ETH_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_ip4(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		    bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	struct mce_tc_l3_hdr *l3_key, *l3_mask;
	u64 options = 0;
	bool is_set = false;

	headers = is_tunnel ? &tc_fltr->inner_headers :
			      &tc_fltr->outer_headers;
	l3_key = &headers->l3_key;
	l3_mask = &headers->l3_mask;

	fd_print("n_proto:0x%x mask:0x%x\n", headers->l2_key.n_proto,
		 headers->l2_mask.n_proto);
	if ((headers->l2_key.n_proto & headers->l2_mask.n_proto) !=
	    htons(ETH_P_IP))
		return -1;

	/* copy L3 (IPv[4|6]: src, dest) address */
	if (flags &
	    (MCE_TC_FLWR_FIELD_DEST_IPV4 | MCE_TC_FLWR_FIELD_SRC_IPV4)) {
		if (flags & MCE_TC_FLWR_FIELD_DEST_IPV4) {
			meta->hdr.ipv4_meta.dst_addr =
				cpu_to_be32(l3_key->dst_ipv4);
			meta->mask.ipv4_meta.dst_addr =
				cpu_to_be32(l3_mask->dst_ipv4);
			options |= MCE_OPT_IPV4_DIP;
			fd_print("dstaddr:0x%x maskaddr:0x%x\n",
				 meta->hdr.ipv4_meta.dst_addr,
				 meta->mask.ipv4_meta.dst_addr);
		}
		if (flags & MCE_TC_FLWR_FIELD_SRC_IPV4) {
			options |= MCE_OPT_IPV4_SIP;
			meta->hdr.ipv4_meta.src_addr =
				cpu_to_be32(l3_key->src_ipv4);
			meta->mask.ipv4_meta.src_addr =
				cpu_to_be32(l3_mask->src_ipv4);
			fd_print("srcaddr:0x%x maskaddr:0x%x\n",
				 meta->hdr.ipv4_meta.src_addr,
				 meta->mask.ipv4_meta.src_addr);
		}
		is_set = true;
	}

	if (flags & MCE_TC_FLWR_FIELD_IP_TOS) {
		if (l3_mask->tos & __MCE_IPV4_HDR_DSCP_MASK) {
			options |= MCE_OPT_IPV4_DSCP;
			meta->hdr.ipv4_meta.dscp =
				l3_key->tos & __MCE_IPV4_HDR_DSCP_MASK;
			meta->mask.ipv4_meta.dscp =
				l3_mask->tos & __MCE_IPV4_HDR_DSCP_MASK;
			fd_print("dscp:0x%x mask:0x%x\n",
				 meta->hdr.ipv4_meta.dscp,
				 meta->mask.ipv4_meta.dscp);
		}
		is_set = true;
	}

	if (l3_mask->ip_proto) {
		meta->hdr.ipv4_meta.protocol = l3_key->ip_proto;
		meta->mask.ipv4_meta.protocol = l3_mask->ip_proto;
		options |= MCE_OPT_L4_PROTO;
		is_set = true;
		fd_print("ip_proto:0x%x mask:0x%x\n",
			 meta->hdr.ipv4_meta.protocol,
			 meta->mask.ipv4_meta.protocol);
	}

	if (flags & MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT) {
		options |= MCE_OPT_IPV4_FRAG;
		meta->hdr.ipv4_meta.is_frag = 1;
		is_set = true;
		fd_print("is_fragment:0x%d\n",
			 meta->hdr.ipv4_meta.is_frag);
	}

	if (is_set)
		mce_compose_set_item_type(compose,
					  MCE_FLOW_ITEM_TYPE_IPV4);

	if (options) {
		meta->type = MCE_IPV4_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_enc_ip4(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
			struct mce_lkup_meta *meta, u64 *inset,
			u8 *compose, bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	struct mce_tc_l3_hdr *l3_key, *l3_mask;
	u64 options = 0;
	bool is_set = false;

	headers = &tc_fltr->outer_headers;
	l3_key = &headers->l3_key;
	l3_mask = &headers->l3_mask;
	/* copy L3 (IPv[4|6]: src, dest) address */
	if (flags & (MCE_TC_FLWR_FIELD_ENC_SRC_IPV4 |
		     MCE_TC_FLWR_FIELD_ENC_DEST_IPV4)) {
		if (flags & MCE_TC_FLWR_FIELD_ENC_DEST_IPV4) {
			meta->hdr.ipv4_meta.dst_addr =
				cpu_to_be32(l3_key->dst_ipv4);
			meta->mask.ipv4_meta.dst_addr =
				cpu_to_be32(l3_mask->dst_ipv4);
			options |= (is_tunnel ? MCE_OPT_OUT_IPV4_DIP :
						MCE_OPT_IPV4_DIP);
			fd_print("dstaddr:0x%x maskaddr:0x%x\n",
				 meta->hdr.ipv4_meta.dst_addr,
				 meta->mask.ipv4_meta.dst_addr);
		}
		if (flags & MCE_TC_FLWR_FIELD_ENC_SRC_IPV4) {
			options |= (is_tunnel ? MCE_OPT_OUT_IPV4_SIP :
						MCE_OPT_IPV4_SIP);
			meta->hdr.ipv4_meta.src_addr =
				cpu_to_be32(l3_key->src_ipv4);
			meta->mask.ipv4_meta.src_addr =
				cpu_to_be32(l3_mask->src_ipv4);
			fd_print("srcaddr:0x%x maskaddr:0x%x\n",
				 meta->hdr.ipv4_meta.src_addr,
				 meta->mask.ipv4_meta.src_addr);
		}
		is_set = true;
	}

	if (flags & MCE_TC_FLWR_FIELD_ENC_IP_TOS) {
		if (l3_mask->tos & __MCE_IPV4_HDR_DSCP_MASK) {
			options |= MCE_OPT_IPV4_DSCP;
			meta->hdr.ipv4_meta.dscp =
				l3_key->tos & __MCE_IPV4_HDR_DSCP_MASK;
			meta->mask.ipv4_meta.dscp =
				l3_mask->tos & __MCE_IPV4_HDR_DSCP_MASK;
			fd_print("dscp:0x%x mask:0x%x\n",
				 meta->hdr.ipv4_meta.dscp,
				 meta->mask.ipv4_meta.dscp);
		}
		is_set = true;
	}

	if (l3_mask->ip_proto) {
		meta->hdr.ipv4_meta.protocol = l3_key->ip_proto;
		meta->mask.ipv4_meta.protocol = l3_mask->ip_proto;
		options |= MCE_OPT_L4_PROTO;
		is_set = true;
		fd_print("ip_proto:0x%x mask:0x%x\n",
			 meta->hdr.ipv4_meta.protocol,
			 meta->mask.ipv4_meta.protocol);
	}

	if (!tc_fltr->parsed_inner &&
	    (flags & MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT)) {
		options |= MCE_OPT_IPV4_FRAG;
		meta->hdr.ipv4_meta.is_frag = 1;
		is_set = true;
		fd_print("is_fragment:0x%d\n",
			 meta->hdr.ipv4_meta.is_frag);
	}

	headers = &tc_fltr->inner_headers;
	if (headers->l2_key.n_proto == htons(ETH_P_IP)) {
		fd_print("l2 type is ip4: force setup ipv4\n");
		is_set = true;
	}

	if (is_set)
		mce_compose_set_item_type(compose,
					  MCE_FLOW_ITEM_TYPE_IPV4);

	if (options && !tc_fltr->parsed_inner) {
		meta->type = MCE_IPV4_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_ip6(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		    bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	struct mce_ipv6_meta *ipv6_meta = &meta->hdr.ipv6_meta;
	struct mce_ipv6_meta *ipv6_mask = &meta->mask.ipv6_meta;
	struct mce_tc_l3_hdr *l3_key, *l3_mask;
	const __be32 *ip_hdr = NULL, *ip_mask = NULL;
	u64 options = 0;
	bool is_set = false;
	int i = 0;

	headers = is_tunnel ? &tc_fltr->inner_headers :
			      &tc_fltr->outer_headers;
	l3_key = &headers->l3_key;
	l3_mask = &headers->l3_mask;

	if ((headers->l2_key.n_proto & headers->l2_mask.n_proto) !=
	    htons(ETH_P_IPV6))
		return -1;

	/* copy L3 (IPv[4|6]: src, dest) address */
	if (flags & (MCE_TC_FLWR_FIELD_DEST_IPV6 |
		     MCE_TC_FLWR_FIELD_SRC_IPV6)) {
		if (flags & MCE_TC_FLWR_FIELD_SRC_IPV6) {
			ip_hdr = (const __be32 *)l3_key->src_ipv6_addr;
			ip_mask = (const __be32 *)l3_mask->src_ipv6_addr;
			for (i = 0; i < 4; i++) {
				ipv6_meta->src_addr[i] =
					cpu_to_be32(ip_hdr[3 - i]);
				ipv6_mask->src_addr[i] =
					cpu_to_be32(ip_mask[3 - i]);
				fd_print(
					"i:%d srcaddr:0x%x maskaddr:0x%x\n",
					i, ipv6_meta->src_addr[i],
					ipv6_mask->src_addr[i]);
			}

			options |= MCE_OPT_IPV6_SIP;
		}
		if (flags & MCE_TC_FLWR_FIELD_DEST_IPV6) {
			ip_hdr = (const __be32 *)l3_key->dst_ipv6_addr;
			ip_mask = (const __be32 *)l3_mask->dst_ipv6_addr;
			for (i = 0; i < 4; i++) {
				ipv6_meta->dst_addr[i] =
					cpu_to_be32(ip_hdr[3 - i]);
				ipv6_mask->dst_addr[i] =
					cpu_to_be32(ip_mask[3 - i]);
				fd_print(
					"i:%d dstaddr:0x%x maskaddr:0x%x\n",
					i, ipv6_meta->dst_addr[i],
					ipv6_mask->dst_addr[i]);
			}
			options |= MCE_OPT_IPV6_DIP;
		}
		is_set = true;
	}

	if (flags & MCE_TC_FLWR_FIELD_IP_TOS) {
		if (l3_mask->tos & __MCE_IPV6_HDR_DSCP_MASK) {
			options |= MCE_OPT_IPV6_DSCP;
			ipv6_meta->dscp = l3_key->tos &
					  __MCE_IPV6_HDR_DSCP_MASK;
			/* tos donnot support mask */
			ipv6_mask->dscp = 0xff;
			fd_print("dscp:0x%x mask:0x%x\n", ipv6_meta->dscp,
				 ipv6_mask->dscp);
			is_set = true;
		}
	}

	if (l3_mask->ip_proto) {
		ipv6_meta->protocol = l3_key->ip_proto;
		ipv6_mask->protocol = l3_mask->ip_proto;
		options |= MCE_OPT_L4_PROTO;
		is_set = true;
		fd_print("ip_proto:0x%x mask:0x%x\n", ipv6_meta->protocol,
			 ipv6_mask->protocol);
	}

	if (flags & MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT) {
		options |= MCE_OPT_IPV6_FRAG;
		ipv6_meta->is_frag = 1;
		is_set = true;
		fd_print("is_fragment:0x%d\n", ipv6_meta->is_frag);
	}

	if (is_set)
		mce_compose_set_item_type(compose,
					  MCE_FLOW_ITEM_TYPE_IPV6);

	if (options) {
		meta->type = MCE_IPV6_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_enc_ip6(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
			struct mce_lkup_meta *meta, u64 *inset,
			u8 *compose, bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	struct mce_ipv6_meta *ipv6_meta = &meta->hdr.ipv6_meta;
	struct mce_ipv6_meta *ipv6_mask = &meta->mask.ipv6_meta;
	struct mce_tc_l3_hdr *l3_key, *l3_mask;
	const __be32 *ip_hdr = NULL, *ip_mask = NULL;
	u64 options = 0;
	bool is_set = false;
	int i = 0;

	headers = &tc_fltr->outer_headers;
	l3_key = &headers->l3_key;
	l3_mask = &headers->l3_mask;
	/* copy L3 (IPv[4|6]: src, dest) address */
	if (flags & (MCE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
		     MCE_TC_FLWR_FIELD_ENC_DEST_IPV6)) {
		if (flags & MCE_TC_FLWR_FIELD_ENC_SRC_IPV6) {
			ip_hdr = (const __be32 *)l3_key->src_ipv6_addr;
			ip_mask = (const __be32 *)l3_mask->src_ipv6_addr;
			for (i = 0; i < 4; i++) {
				ipv6_meta->src_addr[i] =
					cpu_to_be32(ip_hdr[3 - i]);
				ipv6_mask->src_addr[i] =
					cpu_to_be32(ip_mask[3 - i]);
				fd_print(
					"i:%d srcaddr:0x%x maskaddr:0x%x\n",
					i, ipv6_meta->src_addr[i],
					ipv6_mask->src_addr[i]);
			}

			options |= (is_tunnel ? MCE_OPT_OUT_IPV6_SIP :
						MCE_OPT_IPV6_SIP);
		}
		if (flags & MCE_TC_FLWR_FIELD_ENC_DEST_IPV6) {
			ip_hdr = (const __be32 *)l3_key->dst_ipv6_addr;
			ip_mask = (const __be32 *)l3_mask->dst_ipv6_addr;
			for (i = 0; i < 4; i++) {
				ipv6_meta->dst_addr[i] =
					cpu_to_be32(ip_hdr[3 - i]);
				ipv6_mask->dst_addr[i] =
					cpu_to_be32(ip_mask[3 - i]);
				fd_print(
					"i:%d dstaddr:0x%x maskaddr:0x%x\n",
					i, ipv6_meta->dst_addr[i],
					ipv6_mask->dst_addr[i]);
			}
			options |= (is_tunnel ? MCE_OPT_OUT_IPV6_DIP :
						MCE_OPT_IPV6_DIP);
		}
		is_set = true;
	}

	if (flags & MCE_TC_FLWR_FIELD_ENC_IP_TOS) {
		if (l3_mask->tos & __MCE_IPV6_HDR_DSCP_MASK) {
			options |= MCE_OPT_IPV6_DSCP;
			ipv6_meta->dscp = l3_key->tos &
					  __MCE_IPV6_HDR_DSCP_MASK;
			/* tos donnot support mask */
			ipv6_mask->dscp = 0xff;
			fd_print("dscp:0x%x mask:0x%x\n", ipv6_meta->dscp,
				 ipv6_mask->dscp);
			is_set = true;
		}
	}

	if (l3_mask->ip_proto) {
		ipv6_meta->protocol = l3_key->ip_proto;
		ipv6_mask->protocol = l3_mask->ip_proto;
		options |= MCE_OPT_L4_PROTO;
		is_set = true;
		fd_print("ip_proto:0x%x mask:0x%x\n", ipv6_meta->protocol,
			 ipv6_mask->protocol);
	}

	if (!tc_fltr->parsed_inner &&
	    (flags & MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT)) {
		options |= MCE_OPT_IPV6_FRAG;
		ipv6_meta->is_frag = 1;
		is_set = true;
		fd_print("is_fragment:0x%d\n", ipv6_meta->is_frag);
	}

#if 0
	headers = &tc_fltr->inner_headers;
	if (headers->l2_key.n_proto == htons(ETH_P_IPV6)) {
		fd_print("l2 type is ip6: force setup ipv6\n");
		is_set = true;
	}
#endif
	if (is_set)
		mce_compose_set_item_type(compose,
					  MCE_FLOW_ITEM_TYPE_IPV6);
	if (options && !tc_fltr->parsed_inner) {
		meta->type = MCE_IPV6_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_udp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		    bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	u64 options = 0;

	headers = is_tunnel ? &tc_fltr->inner_headers :
			      &tc_fltr->outer_headers;

	if (headers->l3_key.ip_proto != IPPROTO_UDP)
		return -EINVAL;

	meta->type = MCE_UDP_META;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_UDP);

	if (flags & (MCE_TC_FLWR_FIELD_DEST_L4_PORT |
		     MCE_TC_FLWR_FIELD_SRC_L4_PORT)) {
		struct mce_tc_l4_hdr *l4_key, *l4_mask;

		l4_key = &headers->l4_key;
		l4_mask = &headers->l4_mask;

		if (flags & MCE_TC_FLWR_FIELD_DEST_L4_PORT) {
			meta->hdr.udp_meta.dst_port =
				cpu_to_be16(l4_key->dst_port);
			meta->mask.udp_meta.dst_port =
				cpu_to_be16(l4_mask->dst_port);
			options |= MCE_OPT_UDP_DPORT;
			fd_print("dstport:0x%x maskport:0x%x\n",
				 meta->hdr.udp_meta.dst_port,
				 meta->mask.udp_meta.dst_port);
		}
		if (flags & MCE_TC_FLWR_FIELD_SRC_L4_PORT) {
			meta->hdr.udp_meta.src_port =
				cpu_to_be16(l4_key->src_port);
			meta->mask.udp_meta.src_port =
				cpu_to_be16(l4_mask->src_port);
			options |= MCE_OPT_UDP_SPORT;
			fd_print("srcport:0x%x maskport:0x%x\n",
				 meta->hdr.udp_meta.src_port,
				 meta->mask.udp_meta.src_port);
		}
	}

	if (options)
		*inset |= options;

	return options ? 0 : -1;
}

int mce_parse_enc_udp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
			struct mce_lkup_meta *meta, u64 *inset,
			u8 *compose, bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	u64 options = 0;

	headers = &tc_fltr->outer_headers;

	fd_print("ip_proto:0x%x 0x%x tun type:0x%x\n",
		 headers->l3_key.ip_proto,
		 tc_fltr->outer_headers.l3_key.ip_proto,
		 tc_fltr->tunnel_type);
	/* tunnrl default over udp , but nvgre outer ip_proto cannot be udp */
	if (!mce_enc_udp_is_support_proto(tc_fltr))
		return -EINVAL;

	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_UDP);
	if (flags & (MCE_TC_FLWR_FIELD_ENC_DEST_L4_PORT |
		     MCE_TC_FLWR_FIELD_ENC_SRC_L4_PORT)) {
		struct mce_tc_l4_hdr *l4_key, *l4_mask;

		l4_key = &headers->l4_key;
		l4_mask = &headers->l4_mask;

		if (flags & MCE_TC_FLWR_FIELD_ENC_DEST_L4_PORT) {
			meta->hdr.udp_meta.dst_port =
				cpu_to_be16(l4_key->dst_port);
			meta->mask.udp_meta.dst_port =
				cpu_to_be16(l4_mask->dst_port);
			options |= (is_tunnel ? MCE_OPT_OUT_L4_DPORT :
						MCE_OPT_UDP_DPORT);
			fd_print("dstport:0x%x maskport:0x%x\n",
				 meta->hdr.udp_meta.dst_port,
				 meta->mask.udp_meta.dst_port);
		}
		if (flags & MCE_TC_FLWR_FIELD_ENC_SRC_L4_PORT) {
			meta->hdr.udp_meta.src_port =
				cpu_to_be16(l4_key->src_port);
			meta->mask.udp_meta.src_port =
				cpu_to_be16(l4_mask->src_port);
			options |= (is_tunnel ? MCE_OPT_OUT_L4_SPORT :
						MCE_OPT_UDP_SPORT);
			fd_print("srcport:0x%x maskport:0x%x\n",
				 meta->hdr.udp_meta.src_port,
				 meta->mask.udp_meta.src_port);
		}
	}

	if (options && !tc_fltr->parsed_inner) {
		*inset |= options;
		meta->type = MCE_UDP_META;
	}
	return options ? 0 : -1;
}

int mce_parse_tcp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		    bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	u64 options = 0;

	headers = is_tunnel ? &tc_fltr->inner_headers :
			      &tc_fltr->outer_headers;
	if (headers->l3_key.ip_proto != IPPROTO_TCP)
		return -EINVAL;
	meta->type = MCE_TCP_META;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_TCP);

	if (flags & (MCE_TC_FLWR_FIELD_DEST_L4_PORT |
		     MCE_TC_FLWR_FIELD_SRC_L4_PORT)) {
		struct mce_tc_l4_hdr *l4_key, *l4_mask;

		l4_key = &headers->l4_key;
		l4_mask = &headers->l4_mask;

		if (flags & MCE_TC_FLWR_FIELD_DEST_L4_PORT) {
			meta->hdr.tcp_meta.dst_port =
				cpu_to_be16(l4_key->dst_port);
			meta->mask.tcp_meta.dst_port =
				cpu_to_be16(l4_mask->dst_port);
			options |= MCE_OPT_TCP_DPORT;
			fd_print("dstport:0x%x maskport:0x%x\n",
				 meta->hdr.tcp_meta.dst_port,
				 meta->mask.tcp_meta.dst_port);
		}
		if (flags & MCE_TC_FLWR_FIELD_SRC_L4_PORT) {
			meta->hdr.tcp_meta.src_port =
				cpu_to_be16(l4_key->src_port);
			meta->mask.tcp_meta.src_port =
				cpu_to_be16(l4_mask->src_port);
			options |= MCE_OPT_TCP_SPORT;
			fd_print("srcport:0x%x maskport:0x%x\n",
				 meta->hdr.tcp_meta.src_port,
				 meta->mask.tcp_meta.src_port);
		}
	}

	if (options)
		*inset |= options;
	return options ? 0 : -1;
}

int mce_parse_sctp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		     struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		     bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	u64 options = 0;

	headers = is_tunnel ? &tc_fltr->inner_headers :
			      &tc_fltr->outer_headers;

	if (headers->l3_key.ip_proto != IPPROTO_SCTP)
		return -EINVAL;

	meta->type = MCE_SCTP_META;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_SCTP);

	if (flags & (MCE_TC_FLWR_FIELD_DEST_L4_PORT |
		     MCE_TC_FLWR_FIELD_SRC_L4_PORT)) {
		struct mce_tc_l4_hdr *l4_key, *l4_mask;

		l4_key = &headers->l4_key;
		l4_mask = &headers->l4_mask;

		if (flags & MCE_TC_FLWR_FIELD_DEST_L4_PORT) {
			meta->hdr.sctp_meta.dst_port =
				cpu_to_be16(l4_key->dst_port);
			meta->mask.sctp_meta.dst_port =
				cpu_to_be16(l4_mask->dst_port);
			options |= MCE_OPT_SCTP_DPORT;
			fd_print("dstport:0x%x maskport:0x%x\n",
				 meta->hdr.sctp_meta.dst_port,
				 meta->mask.sctp_meta.dst_port);
		}
		if (flags & MCE_TC_FLWR_FIELD_SRC_L4_PORT) {
			meta->hdr.sctp_meta.src_port =
				cpu_to_be16(l4_key->src_port);
			meta->mask.sctp_meta.src_port =
				cpu_to_be16(l4_mask->src_port);
			options |= MCE_OPT_SCTP_SPORT;
			fd_print("srcport:0x%x maskport:0x%x\n",
				 meta->hdr.sctp_meta.src_port,
				 meta->mask.sctp_meta.src_port);
		}
	}

	if (options)
		*inset |= options;
	return options ? 0 : -1;
}

int mce_parse_vxlan(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		      struct mce_lkup_meta *meta, u64 *inset,
		      u8 *compose, bool is_tunnel)
{
	u64 options = 0;
	u32 tenant_id;

	tenant_id = be32_to_cpu(tc_fltr->tenant_id & 0xffffff00);
	meta->hdr.vxlan_meta.vni = tenant_id;
	meta->mask.vxlan_meta.vni = be32_to_cpu(0xffffff00);
	fd_print("vni:0x%x mask:0x%x\n", meta->hdr.vxlan_meta.vni,
		 meta->mask.vxlan_meta.vni);
	options |= MCE_OPT_VXLAN_VNI;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_VXLAN);

	if (options && !tc_fltr->parsed_inner) {
		meta->type = MCE_NVGRE_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_geneve(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		       struct mce_lkup_meta *meta, u64 *inset,
		       u8 *compose, bool is_tunnel)
{
	u64 options = 0;
	u32 tenant_id;

	tenant_id = be32_to_cpu(tc_fltr->tenant_id & 0xffffff00);
	meta->hdr.geneve_meta.vni = tenant_id;
	meta->mask.geneve_meta.vni = be32_to_cpu(0xffffff00);
	fd_print("vni:0x%x mask:0x%x\n", meta->hdr.geneve_meta.vni,
		 meta->mask.geneve_meta.vni);
	options |= MCE_OPT_GENEVE_VNI;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_GENEVE);

	if (options && !tc_fltr->parsed_inner) {
		meta->type = MCE_NVGRE_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_nvgre(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		    bool is_tunnel)
{
	u64 options = 0;

	meta->hdr.nvgre_meta.key =
		be32_to_cpu(tc_fltr->tenant_id & 0xffffff00);
	meta->mask.nvgre_meta.key = be32_to_cpu(0xffffff00);
	fd_print("vni:0x%x mask:0x%x\n", meta->hdr.nvgre_meta.key,
		 meta->mask.nvgre_meta.key);
	options |= MCE_OPT_NVGRE_TNI;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_NVGRE);

	if (options && !tc_fltr->parsed_inner) {
		meta->type = MCE_NVGRE_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_gtpc(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		   struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		   bool is_tunnel)
{
	u64 options = 0;

	meta->hdr.gtp_meta.teid = be32_to_cpu(tc_fltr->tenant_id);
	meta->mask.gtp_meta.teid = be32_to_cpu(0xffffffff);
	fd_print("vni:0x%x mask:0x%x\n", meta->hdr.gtp_meta.teid,
		 meta->mask.gtp_meta.teid);
	options |= MCE_OPT_GTP_C_TEID;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_GTPC);

	if (options && !tc_fltr->parsed_inner) {
		meta->type = MCE_GTPC_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_gtpu(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		     struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		     bool is_tunnel)
{
	u64 options = 0;

	meta->hdr.gtp_meta.teid = be32_to_cpu(tc_fltr->tenant_id);
	meta->mask.gtp_meta.teid = be32_to_cpu(0xffffffff);
	fd_print("vni:0x%x mask:0x%x\n", meta->hdr.gtp_meta.teid,
		 meta->mask.gtp_meta.teid);
	options |= MCE_OPT_GTP_U_TEID;
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_GTPU);

	if (options && !tc_fltr->parsed_inner) {
		meta->type = MCE_GTPU_META;
		*inset |= options;
	}
	return options ? 0 : -1;
}

int mce_parse_esp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		  struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		  bool is_tunnel)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;
	u64 options = 0;

	if (!(tc_fltr->flags & MCE_TC_FLWR_FIELD_IPSEC_SPI))
		return -1;

	headers = is_tunnel ? &tc_fltr->inner_headers :
			      &tc_fltr->outer_headers;
	meta->hdr.esp_meta.spi = be32_to_cpu(headers->ipsec_hdr.spi);
	meta->mask.esp_meta.spi = be32_to_cpu(0xffffffff);
	fd_print("spi:0x%x mask:0x%x\n", meta->hdr.esp_meta.spi,
		 meta->mask.esp_meta.spi);
	mce_compose_set_item_type(compose, MCE_FLOW_ITEM_TYPE_ESP);
	/* esp in tunnel, need ignore esp spi */
	if (!is_tunnel)
		options |= MCE_OPT_ESP_SPI;
	meta->type = MCE_ESP_META;
	*inset |= options;
	return 0;
}