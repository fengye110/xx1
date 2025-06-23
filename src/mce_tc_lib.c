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
#ifdef HAVE_GRETAP_TYPE
#include <net/gre.h>
#endif /* HAVE_GRETAP_TYPE */
#ifdef HAVE_TCF_MIRRED_DEV
#include <net/gtp.h>
#endif /* HAVE_TCF_MIRRED_DEV */
#include "mce_profile_mask.h"

#ifdef HAVE_TC_SETUP_CLSFLOWER
#define MCE_TC_METADATA_LKUP_IDX 0

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/**
 * mce_is_tunnel_fltr - is this a tunnel filter
 * @f: Pointer to tc-flower filter
 *
 * This function should be called only after tunnel_type
 * of the filter is set by calling mce_tc_tun_parse()
 */
static bool mce_is_tunnel_fltr(struct mce_tc_flower_fltr *f)
{
	return (f->tunnel_type == TNL_VXLAN ||
		f->tunnel_type == TNL_GENEVE ||
		f->tunnel_type == TNL_GRETAP ||
		f->tunnel_type == TNL_GTPU || f->tunnel_type == TNL_GTPC);
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

struct mce_vsi *mce_locate_vsi_using_queue(struct mce_vsi *vsi,
					       int queue)
{
	return vsi;
}

/**
 * mce_tc_forward_action - Determine destination VSI and queue for the action
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 * @rx_ring: Pointer to ring ptr
 * @dest_vsi: Pointer to VSI ptr
 *
 * Validates the tc forward action and determines the destination VSI and queue
 * for the forward action.
 */
static int __always_unused mce_tc_forward_action(
	struct mce_vsi *vsi, struct mce_tc_flower_fltr *tc_fltr,
	struct mce_vsi **dest_vsi)
{
	struct mce_vsi *ch_vsi = NULL;
	struct mce_pf *pf = vsi->back;
	struct device *dev;

	dev = mce_pf_to_dev(pf);
	*dest_vsi = NULL;

	if (tc_fltr->action.fltr_act == MCE_FWD_TO_Q) {
		int q = tc_fltr->action.fwd.q.queue;

		ch_vsi = mce_locate_vsi_using_queue(vsi, q);
	} else if (tc_fltr->action.fltr_act == MCE_DROP_PACKET) {
		/* support drop packets */
		ch_vsi = mce_locate_vsi_using_queue(vsi, 0);
	} else {
		dev_err(dev,
			"Unable to add filter because of unsupported action %u (supported actions: drop or fwd to queue)\n",
			tc_fltr->action.fltr_act);
		return -EINVAL;
	}

	/* Must have valid "ch_vsi" (it could be main VSI or ADQ VSI */
	if (!ch_vsi) {
		dev_err(dev,
			"Unable to add filter because specified destination VSI doesn't exist\n");
		return -EINVAL;
	}

	*dest_vsi = ch_vsi;
	return 0;
}

static enum mce_protocol_type __maybe_unused
mce_proto_type_from_tunnel(enum mce_tunnel_type type)
{
	switch (type) {
	case TNL_VXLAN:
		return MCE_VXLAN;
	case TNL_GENEVE:
		return MCE_GENEVE;
	case TNL_GRETAP:
		return MCE_NVGRE;
	case TNL_GTPU:
		/* NO_PAY profiles will not work with GTP-U */
		return MCE_GTP;
	case TNL_GTPC:
		return MCE_GTP_NO_PAY;
	default:
		return 0;
	}
}

static enum mce_sw_tun_type
mce_sw_type_from_tunnel(enum mce_tunnel_type type)
{
	switch (type) {
	case TNL_VXLAN:
		return MCE_SW_TUN_VXLAN;
	case TNL_GENEVE:
		return MCE_SW_TUN_GENEVE;
	case TNL_GRETAP:
		return MCE_SW_TUN_GRE;
	case TNL_GTPU:
		return MCE_SW_TUN_GTP_U;
	case TNL_GTPC:
		return MCE_SW_TUN_GTP_C;
	case TNL_IPSEC:
		/* ipsec take as non tunnel */
		return MCE_SW_NON_TUN;
	default:
		return MCE_SW_NON_TUN;
	}
}

static int mce_tc_fill_tunnel_outer(struct mce_tc_flower_fltr *tc_fltr,
				    u32 flags, struct mce_lkup_meta *meta,
				    u64 *inset, u8 *compose,
				    bool is_tunnel,
				    struct mce_fdir_handle *handle,
				    u8 *fd_compose, int *field_bitmask_num)
{
	u32 meta_num = 0;
	u64 lk_lists = 0;
	int ret = 0, i;

	if (!is_tunnel)
		return -1;
	/* parse tunnel */
	if (tc_fltr->parsed_inner)
		lk_lists = MCE_PARSE_ENC_INNER_FLOW_ITERM_LOOKUP_LISTS;
	else
		lk_lists = MCE_PARSE_ENC_OUTER_FLOW_ITERM_LOOKUP_LISTS;
	for (i = 0; i < MCE_FLOW_ITEM_TYPE_MAX_NUM; i++) {
		/* if ok, get next meta form database */
		if (!ret)
			meta = mce_parse_get_next_meta(handle, &meta_num,
						       is_tunnel);
		switch (lk_lists & BIT_ULL(i)) {
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH):
			ret = mce_parse_enc_eth(tc_fltr, flags, meta,
						inset, fd_compose,
						is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4):
			ret = mce_parse_enc_ip4(tc_fltr, flags, meta,
						inset, fd_compose,
						is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6):
			ret = mce_parse_enc_ip6(tc_fltr, flags, meta,
						inset, fd_compose,
						is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP):
			ret = mce_parse_enc_udp(tc_fltr, flags, meta,
						inset, fd_compose,
						is_tunnel);
			break;
#if 0
		/* tunnrl outer not support tcp or sctp */
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP):
			ret = mce_parse_tcp(tc_fltr, flags, meta, inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_SCTP):
			ret = mce_parse_sctp(tc_fltr, flags, meta, inset,
					     fd_compose, is_tunnel);
			break;
#endif
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_VXLAN):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_VXLAN)
				ret = mce_parse_vxlan(tc_fltr, flags, meta,
						      inset, fd_compose,
						      is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_GENEVE):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_GENEVE)
				ret = mce_parse_geneve(tc_fltr, flags,
						       meta, inset,
						       fd_compose,
						       is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_NVGRE):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_GRETAP)
				ret = mce_parse_nvgre(tc_fltr, flags, meta,
						      inset, fd_compose,
						      is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPC):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_GTPC)
				ret = mce_parse_gtpc(tc_fltr, flags, meta,
						     inset, fd_compose,
						     is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPU):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_GTPU)
				ret = mce_parse_gtpu(tc_fltr, flags, meta,
						     inset, fd_compose,
						     is_tunnel);
			break;
#ifdef HAVE_FLOW_DISSECTOR_KEY_IPSEC
#if 0
		/* ipsec maybe take as non-tunnel packet? */
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ESP):
			ret = -1;
			if (tc_fltr->tunnel_type == TNL_IPSEC)
				ret = mce_parse_esp(tc_fltr, flags, meta,
						    inset, fd_compose,
						    is_tunnel);
			break;
#endif
#endif
		default:
			ret = -1;
			break;
		}
#if 0
		if (lk_lists & BIT_ULL(i))
			fd_print(
				"lk_lists:0x%llx flags:0x%x i:%d inset:0x%llx\n",
				lk_lists, flags, i, inset);
#endif
		if (!ret && !tc_fltr->parsed_inner)
			*field_bitmask_num +=
				mce_check_field_bitmask_valid(meta);
	}

	if (ret)
		meta_num--;
	return meta_num;
}

/**
 * mce_tc_fill_rules - fill filter rules based on TC fltr
 * @hw: pointer to HW structure
 * @flags: TC flower field flags
 * @tc_fltr: pointer to TC flower filter
 * @list: list of advance rule elements
 * @rule_info: pointer to information about rule
 * @l4_proto: pointer to information such as L4 proto type
 *
 * Fill mce_adv_lkup_elem list based on TC flower flags and
 * TC flower headers. This list should be used to add
 * advance filter in hardware.
 */
static int mce_tc_fill_rules(struct mce_hw *hw, u32 flags,
			       struct mce_fdir_filter **filter,
			       struct mce_tc_flower_fltr *tc_fltr,
			       struct mce_fdir_handle *handle,
			       struct mce_adv_rule_info *rule_info,
			       u8 *fd_compose)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_lkup_meta *meta = NULL;
	bool is_tunnel = false, is_ipv6 = false;
	int ret = 0, i, j, field_bitmask_num = 0;
	struct mce_field_bitmask_info *mask_info = NULL;
	u16 block_size = 0;
	u64 inset = 0, lk_lists;
	u32 meta_num = 0;

#ifdef HAVE_TCF_VLAN_TPID
	u16 vlan_tpid = 0;
#endif /* HAVE_TCF_VLAN_TPID */

#ifdef HAVE_TCF_VLAN_TPID
	rule_info->vlan_type = vlan_tpid;
#endif /* HAVE_TCF_VLAN_TPID */

	if (test_bit(TNL_INNER_EN, hw->l2_fltr_flags))
		tc_fltr->parsed_inner = true;

	rule_info->tun_type =
		mce_sw_type_from_tunnel(tc_fltr->tunnel_type);
	if (tc_fltr->tunnel_type != TNL_TC_LAST) {
		is_tunnel = true;
		meta_num = mce_tc_fill_tunnel_outer(
			tc_fltr, flags, meta, &inset, fd_compose,
			is_tunnel, handle, fd_compose, &field_bitmask_num);
		if (!tc_fltr->parsed_inner && !!meta_num)
			goto only_parse_outer;
	}

	/* parse non-tunnel */
	ret = 0;
	lk_lists = MCE_PARSE_FLOW_ITERM_LOOKUP_LISTS;
	for (i = 0; i < MCE_FLOW_ITEM_TYPE_MAX_NUM; i++) {
		/* if ok, get next meta form database */
		if (!ret)
			meta = mce_parse_get_next_meta(handle, &meta_num,
						       is_tunnel);
		switch (lk_lists & BIT_ULL(i)) {
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH):
			ret = mce_parse_eth(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_VLAN):
			ret = mce_parse_vlan(tc_fltr, flags, meta, &inset,
					     fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4):
			ret = mce_parse_ip4(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6):
			ret = mce_parse_ip6(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP):
			ret = mce_parse_udp(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP):
			ret = mce_parse_tcp(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_SCTP):
			ret = mce_parse_sctp(tc_fltr, flags, meta, &inset,
					     fd_compose, is_tunnel);
			break;
		case BIT_ULL(MCE_FLOW_ITEM_TYPE_ESP):
			ret = mce_parse_esp(tc_fltr, flags, meta, &inset,
					    fd_compose, is_tunnel);
			break;
		default:
			ret = -1;
			break;
		}
#if 0
		if (lk_lists & BIT_ULL(i))
			fd_print(
				"lk_lists:0x%llx flags:0x%x i:%d inset:0x%llx\n",
				lk_lists, flags, i, inset);
#endif
		if (!ret)
			field_bitmask_num +=
				mce_check_field_bitmask_valid(meta);
	}

only_parse_outer:
	meta = &handle->meta_db[is_tunnel][0];
	for (i = 0, j = 0; i < meta_num; i++) {
		if (fd_compose[i]) {
			if (fd_compose[i] == MCE_FLOW_ITEM_TYPE_IPV6)
				is_ipv6 = true;
			fd_debug(
				hw,
				"i:%d fd_compose:0x%02x meta_type:0x%02x\n",
				i, fd_compose[i], meta[i].type);
			j++;
		} else {
			break;
		}
	}
	meta_num = j;
	ret = mce_fd_check_params_valid(tc_fltr, meta, meta_num,
					is_tunnel);
	if (ret) {
		switch (ret) {
		case -MCE_FLOW_PARAMS_ERROR_ETH:
			NL_SET_ERR_MSG_MOD(
				tc_fltr->extack,
				"ethertype unsupport ipv4/ipv6 or cvlan/svlan");
			break;
		default:
			NL_SET_ERR_MSG_MOD(tc_fltr->extack,
					   "input params invalid");
			break;
		}
		return -1;
	}

	if (field_bitmask_num) {
		fd_print("prifile field bitmap en\n");
		fd_print("meta_num:%d field_bitmask_num:%d\n", meta_num,
			 field_bitmask_num);
		mask_info = kzalloc(sizeof(struct mce_field_bitmask_info),
				    GFP_KERNEL);
		block_size = sizeof(struct mce_field_bitmask_block) *
			     field_bitmask_num;
		mask_info->field_bitmask = kzalloc(block_size, GFP_KERNEL);
		meta = &handle->meta_db[is_tunnel][0];
		mce_fdir_field_mask_init(meta, meta_num, mask_info);
	}
	if (pf->fdir_mode == MCE_FDIR_MACVLAN_MODE)
		*filter = mce_meta_to_fdir_rule_l2(hw, handle, meta_num,
						   false, is_tunnel);
	else
		*filter = mce_meta_to_fdir_rule(hw, handle, meta_num,
						false, is_tunnel);
	(*filter)->mask_info = mask_info;
	(*filter)->options = inset;
	tc_fltr->tunnel_sw_type = rule_info->tun_type;
	tc_fltr->filter = *filter;

	return 0;
}

/**
 * mce_add_tc_flower_adv_fltr - add appropriate filter rules
 * @vsi: Pointer to VSI
 * @tc_fltr: Pointer to TC flower filter structure
 *
 * based on filter parameters using Advance recipes supported
 * by OS package.
 */
int mce_add_tc_flower_adv_fltr(struct mce_vsi *vsi,
				 struct mce_tc_flower_fltr *tc_fltr)
{
	struct mce_adv_rule_info rule_info = { 0 };
	struct mce_fdir_handle *handle = NULL;
	struct mce_pf *pf = vsi->back;
	struct mce_fdir_filter *filter = NULL;
	struct mce_hw *hw = &pf->hw;
	u32 flags = tc_fltr->flags;
	struct mce_vsi *ch_vsi;
	int ret = 0;
	u8 *fd_compose = NULL;
	u16 prof_id = 0;

	handle = (struct mce_fdir_handle *)mce_get_engine_handle(
		pf, MCE_FLOW_FDIR);
	if (handle == NULL)
		return -EINVAL;
	if (mce_compose_init_item_type(&fd_compose))
		return -EINVAL;

	/* validate forwarding action VSI and queue */
	ret = mce_tc_forward_action(vsi, tc_fltr, &ch_vsi);
	if (ret)
		goto err_exit;

	ret = mce_tc_fill_rules(hw, flags, &filter, tc_fltr, handle,
				&rule_info, fd_compose);
	if (ret)
		goto err_exit;
	if (!mce_compose_find_prof_id(pf, fd_compose, &prof_id, tc_fltr)) {
		dev_err(hw->dev, "cannot find profile id\n");
		goto err_exit;
	}

	filter->profile_id = prof_id;
	dev_info(mce_hw_to_dev(hw), "%s: profile id:0x%x\n", __func__,
		 filter->profile_id);
	ret = pf->flow_engine->create(pf, filter, tc_fltr);
err_exit:
	mce_compose_deinit_item_type(fd_compose);
	return ret;
}

/**
 * mce_tc_set_port - Parse ports from TC flower filter
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel port
 */
static int mce_tc_set_port(struct flow_match_ports match,
			     struct mce_tc_flower_fltr *fltr,
			     struct mce_tc_flower_lyr_2_4_hdrs *headers,
			     bool is_encap)
{
	if (match.key->dst) {
		fltr->flags |= MCE_TC_FLWR_FIELD_DEST_L4_PORT;
		headers->l4_key.dst_port = (match.key->dst);
		headers->l4_mask.dst_port = (match.mask->dst);
	}
	if (match.key->src) {
		fltr->flags |= MCE_TC_FLWR_FIELD_SRC_L4_PORT;
		headers->l4_key.src_port = (match.key->src);
		headers->l4_mask.src_port = (match.mask->src);
	}

	return 0;
}

/**
 * mce_tc_set_ipv4 - Parse IPv4 addresses from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv4 address
 */
static int mce_tc_set_ipv4(struct flow_match_ipv4_addrs *match,
			     struct mce_tc_flower_fltr *fltr,
			     struct mce_tc_flower_lyr_2_4_hdrs *headers,
			     bool is_encap)
{
	if (match->key->dst) {
		if (is_encap)
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_DEST_IPV4;
		else
			fltr->flags |= MCE_TC_FLWR_FIELD_DEST_IPV4;
		headers->l3_key.dst_ipv4 = match->key->dst;
		headers->l3_mask.dst_ipv4 = match->mask->dst;
	}
	if (match->key->src) {
		if (is_encap)
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_SRC_IPV4;
		else
			fltr->flags |= MCE_TC_FLWR_FIELD_SRC_IPV4;
		headers->l3_key.src_ipv4 = match->key->src;
		headers->l3_mask.src_ipv4 = match->mask->src;
	}
	return 0;
}

/**
 * mce_tc_set_ipv6 - Parse IPv6 addresses from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 * @is_encap: set true for tunnel IPv6 address
 */
static int mce_tc_set_ipv6(struct flow_match_ipv6_addrs *match,
			     struct mce_tc_flower_fltr *fltr,
			     struct mce_tc_flower_lyr_2_4_hdrs *headers,
			     bool is_encap)
{
	struct mce_tc_l3_hdr *l3_key, *l3_mask;

	/* src and dest IPV6 address should not be LOOPBACK
	 * (0:0:0:0:0:0:0:1), which can be represented as ::1
	 */
	if (ipv6_addr_loopback(&match->key->dst) ||
	    ipv6_addr_loopback(&match->key->src)) {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Bad IPv6, addr is LOOPBACK");
		return -EINVAL;
	}
	/* if src/dest IPv6 address is *,* error */
	if (ipv6_addr_any(&match->mask->dst) &&
	    ipv6_addr_any(&match->mask->src)) {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Bad src/dest IPv6, addr is any");
		return -EINVAL;
	}
	if (!ipv6_addr_any(&match->mask->dst)) {
		if (is_encap)
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_DEST_IPV6;
		else
			fltr->flags |= MCE_TC_FLWR_FIELD_DEST_IPV6;
	}
	if (!ipv6_addr_any(&match->mask->src)) {
		if (is_encap)
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_SRC_IPV6;
		else
			fltr->flags |= MCE_TC_FLWR_FIELD_SRC_IPV6;
	}

	l3_key = &headers->l3_key;
	l3_mask = &headers->l3_mask;

	if (fltr->flags & (MCE_TC_FLWR_FIELD_ENC_SRC_IPV6 |
			   MCE_TC_FLWR_FIELD_SRC_IPV6)) {
		memcpy(&l3_key->src_ipv6_addr, &match->key->src.s6_addr,
		       sizeof(match->key->src.s6_addr));
		memcpy(&l3_mask->src_ipv6_addr, &match->mask->src.s6_addr,
		       sizeof(match->mask->src.s6_addr));
	}
	if (fltr->flags & (MCE_TC_FLWR_FIELD_ENC_DEST_IPV6 |
			   MCE_TC_FLWR_FIELD_DEST_IPV6)) {
		memcpy(&l3_key->dst_ipv6_addr, &match->key->dst.s6_addr,
		       sizeof(match->key->dst.s6_addr));
		memcpy(&l3_mask->dst_ipv6_addr, &match->mask->dst.s6_addr,
		       sizeof(match->mask->dst.s6_addr));
	}

	return 0;
}

#if defined(HAVE_TCF_MIRRED_DEV) || \
	defined(HAVE_TC_FLOW_RULE_INFRASTRUCTURE)
/**
 * mce_is_tnl_gtp - detect if tunnel type is GTP or not
 * @tunnel_dev: ptr to tunnel device
 * @rule: ptr to flow_rule
 *
 * If curr_tnl_type is TNL_LAST and "flow_rule" is non-NULL, then
 * check if enc_dst_port is well known GTP port (2152)
 * if so - return true (indicating that tunnel type is GTP), otherwise false.
 */
static bool mce_is_tnl_gtp(struct net_device *tunnel_dev,
			     struct flow_rule *rule)
{
	/* if flow_rule is non-NULL, proceed with detecting possibility
	 * of GTP tunnel. Unlike VXLAN and GENEVE, there is no such API
	 * like  netif_is_gtp since GTP is not natively supported in kernel
	 */
	if (rule && (!is_vlan_dev(tunnel_dev))) {
		struct flow_match_ports match;
		u16 enc_dst_port;

		if (!flow_rule_match_key(rule,
					 FLOW_DISSECTOR_KEY_ENC_PORTS))
			return false;

		/* get ENC_PORTS info */
		flow_rule_match_enc_ports(rule, &match);
		enc_dst_port = be16_to_cpu(match.key->dst);

		/* Outer UDP port is GTP well known port,
		 * if 'enc_dst_port' matched with GTP well known port,
		 * return true from this function.
		 */
		return enc_dst_port == GTP1U_PORT;
	}
	return false;
}

#ifdef HAVE_FLOW_DISSECTOR_KEY_IPSEC
static bool __maybe_unused mce_is_tnl_ipsec(struct net_device *tunnel_dev,
					    struct flow_rule *rule,
					    struct mce_tc_flower_fltr *fltr)
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		headers = &fltr->outer_headers;
		flow_rule_match_basic(rule, &match);
		headers->l3_key.ip_proto = match.key->ip_proto;
		fd_print("ipsec_en:%d ip_proto:%d\n", fltr->ipsec_en,
			 headers->l3_key.ip_proto);
		if (headers->l3_key.ip_proto == IPPROTO_ESP)
			return true;
	}

	if (rule && (!is_vlan_dev(tunnel_dev))) {
		struct flow_match_ports match;
		u16 enc_dst_port;

		if (!flow_rule_match_key(rule,
					 FLOW_DISSECTOR_KEY_ENC_PORTS))
			return false;

		/* get ENC_PORTS info */
		flow_rule_match_enc_ports(rule, &match);
		enc_dst_port = be16_to_cpu(match.key->dst);

		/* Outer UDP port is ESP well known port,
		 * if 'enc_dst_port' matched with ESP well known port,
		 * return true from this function.
		 */
		fd_print("ipsec_en:%d enc_dst_port:%d\n", fltr->ipsec_en,
			 enc_dst_port);
		if (enc_dst_port == MCE_TC_FLWR_IPSEC_NAT_T_PORT0 ||
		    enc_dst_port == MCE_TC_FLWR_IPSEC_NAT_T_PORT1)
			return true;
	}
	return false;
}
#endif /* HAVE_FLOW_DISSECTOR_KEY_IPSEC */

#ifdef HAVE_FLOW_DISSECTOR_KEY_PPPOE
/**
 * mce_tc_set_pppoe - Parse PPPoE fields from TC flower filter
 * @match: Pointer to flow match structure
 * @fltr: Pointer to filter structure
 * @headers: Pointer to outer header fields
 * @returns PPP protocol used in filter (ppp_ses or ppp_disc)
 */
static u16 __maybe_unused mce_tc_set_pppoe(
	struct flow_match_pppoe *match, struct mce_tc_flower_fltr *fltr,
	struct mce_tc_flower_lyr_2_4_hdrs *headers)
{
	if (match->mask->session_id) {
		fltr->flags |= MCE_TC_FLWR_FIELD_PPPOE_SESSID;
		headers->pppoe_hdr.session_id = match->key->session_id;
	}

	if (match->mask->ppp_proto) {
		fltr->flags |= MCE_TC_FLWR_FIELD_PPP_PROTO;
		headers->pppoe_hdr.ppp_proto = match->key->ppp_proto;
	}

	return be16_to_cpu(match->key->type);
}
#endif /* HAVE_FLOW_DISSECTOR_KEY_PPPOE */

/**
 * mce_tc_tun_get_type - get the tunnel type
 * @tunnel_dev: ptr to tunnel device
 * @rule: ptr to flow_rule
 *
 * This function detects appropriate tunnel_type if specified device is
 * tunnel device such as vxlan/geneve othertwise it tries to detect
 * tunnel type based on outer GTP port (2152)
 */
int mce_tc_tun_get_type(struct net_device *tunnel_dev,
			struct flow_rule *rule,
			struct mce_tc_flower_fltr *fltr)
{
#ifdef HAVE_VXLAN_TYPE
#if IS_ENABLED(CONFIG_VXLAN)
	if (netif_is_vxlan(tunnel_dev))
		return TNL_VXLAN;
#endif
#endif /* HAVE_VXLAN_TYPE */
#ifdef HAVE_GENEVE_TYPE
#if IS_ENABLED(CONFIG_GENEVE)
	if (netif_is_geneve(tunnel_dev))
		return TNL_GENEVE;
#endif
#endif /* HAVE_GENEVE_TYPE */
#ifdef HAVE_GRETAP_TYPE
	if (netif_is_gretap(tunnel_dev) || netif_is_ip6gretap(tunnel_dev))
		return TNL_GRETAP;
#endif /* HAVE_GRETAP_TYPE */

#ifdef HAVE_GTP_SUPPORT
	/* Assume GTP-U by default in case of GTP netdev.
	 * GTP-C may be selected later, based on enc_dst_port.
	 */
	if (netif_is_gtp(tunnel_dev))
		return TNL_GTPU;
#endif /* HAVE_GTP_SUPPORT */
#ifdef HAVE_FLOW_DISSECTOR_KEY_IPSEC
#if 0
	/* TODO: ipsec maybe take as non-tunnel packet? */
	if (mce_is_tnl_ipsec(tunnel_dev, rule, fltr))
		return TNL_IPSEC;
#endif
#endif
	/* detect possibility of GTP tunnel type based on input */
	if (mce_is_tnl_gtp(tunnel_dev, rule))
		return TNL_GTPU;

	return TNL_LAST;
}

static bool mce_is_tunnel_supported(struct net_device *dev,
				    struct flow_rule *rule,
				    struct mce_tc_flower_fltr *fltr)
{
	int ret = 0;

	ret = mce_tc_tun_get_type(dev, rule, fltr);
	return ret != TNL_LAST;
}
#endif /* HAVE_TCF_MIRRED_DEC || HAVE_TC_FLOW_RULE_INFRASTRUCTURE */

#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
static bool mce_is_tunnel_supported_rule(struct flow_rule *rule)
{
	return (flow_rule_match_key(rule,
				    FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) ||
		flow_rule_match_key(rule,
				    FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) ||
		flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID) ||
		flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS));
}

static struct net_device *
mce_get_tunnel_device(struct net_device *dev, struct flow_rule *rule,
		      struct mce_tc_flower_fltr *fltr)
{
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	struct flow_action_entry *act;
	int i;

	if (mce_is_tunnel_supported(dev, rule, fltr))
		return dev;

	flow_action_for_each(i, act, &rule->action) {
		if (act->id == FLOW_ACTION_REDIRECT &&
		    mce_is_tunnel_supported(act->dev, rule, fltr))
			return act->dev;
	}
#endif /* HAVE_TC_FLOW_RULE_INFRASTRUCTURE */

	if (mce_is_tunnel_supported_rule(rule))
		return dev;

	return NULL;
}

/**
 * mce_tc_tun_info - Parse and store tunnel info
 * @pf: ptr to PF device
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @tunnel: type of tunnel (e.g. VxLAN, Geneve, GTP)
 *
 * Parse tunnel attributes such as tunnel_id and store them.
 */
static int mce_tc_tun_info(struct mce_pf *pf,
			     struct flow_cls_offload *f,
			     struct mce_tc_flower_fltr *fltr,
			     enum mce_tunnel_type tunnel)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);

	/* match on VNI */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID)) {
		struct device *dev = mce_pf_to_dev(pf);
		struct flow_match_enc_keyid enc_keyid;
		u32 key_id;

		flow_rule_match_enc_keyid(rule, &enc_keyid);
		if (!enc_keyid.mask->keyid) {
			dev_err(dev,
				"Bad mask for encap key_id 0x%04x, it must be non-zero\n",
				be32_to_cpu(enc_keyid.mask->keyid));
			return -EINVAL;
		}

		if (enc_keyid.mask->keyid !=
		    cpu_to_be32(MCE_TC_FLOWER_MASK_32)) {
			dev_err(dev,
				"Bad mask value for encap key_id 0x%04x\n",
				be32_to_cpu(enc_keyid.mask->keyid));
			return -EINVAL;
		}

		key_id = be32_to_cpu(enc_keyid.key->keyid);
		if (tunnel == TNL_VXLAN || tunnel == TNL_GENEVE) {
			/* VNI is only 3 bytes, applicable for VXLAN/GENEVE */
			if (key_id > MCE_TC_FLOWER_VNI_MAX) {
				dev_err(dev, "VNI out of range : 0x%x\n",
					key_id);
				return -EINVAL;
			}
		}
		fltr->flags |= MCE_TC_FLWR_FIELD_TENANT_ID;
		fltr->tenant_id = enc_keyid.key->keyid;
	}

	return 0;
}

/**
 * mce_tc_tun_parse - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int mce_tc_tun_parse(struct net_device *filter_dev,
			      struct mce_vsi *vsi,
			      struct flow_cls_offload *f,
			      struct mce_tc_flower_fltr *fltr,
			      struct mce_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	enum mce_tunnel_type tunnel_type;
	struct mce_pf *pf = vsi->back;
	struct device *dev;
	int err = 0;

	dev = mce_pf_to_dev(pf);
	tunnel_type = mce_tc_tun_get_type(filter_dev, rule, fltr);

	if (tunnel_type == TNL_VXLAN || tunnel_type == TNL_GTPU ||
	    tunnel_type == TNL_GTPC || tunnel_type == TNL_GENEVE ||
	    tunnel_type == TNL_GRETAP || tunnel_type == TNL_IPSEC) {
		err = mce_tc_tun_info(pf, f, fltr, tunnel_type);
		if (err) {
			dev_err(dev,
				"Failed to parse tunnel (tunnel_type %u) attributes\n",
				tunnel_type);
			return err;
		}
	} else {
		dev_err(dev,
			"Tunnel HW offload is not supported for the tunnel type: %d\n",
			tunnel_type);
		return -EOPNOTSUPP;
	}
	fltr->tunnel_type = tunnel_type;
	if (headers->l3_key.ip_proto != IPPROTO_ESP)
		headers->l3_key.ip_proto = IPPROTO_UDP;
	return err;
}

/**
 * mce_parse_gtp_type - Sets GTP tunnel type to GTP-U or GTP-C
 * @match: Flow match structure
 * @fltr: Pointer to filter structure
 *
 * GTP-C/GTP-U is selected based on destination port number (enc_dst_port).
 * Before calling this funtcion, fltr->tunnel_type should be set to TNL_GTPU,
 * therefore making GTP-U the default choice (when destination port number is
 * not specified).
 */
static int mce_parse_gtp_type(struct flow_match_ports match,
				struct mce_tc_flower_fltr *fltr)
{
	u16 dst_port;

	if (match.key->dst) {
		dst_port = be16_to_cpu(match.key->dst);

		switch (dst_port) {
		case GTP1U_PORT:
			break;
		case MCE_GTPC_PORT:
			fltr->tunnel_type = TNL_GTPC;
			break;
		default:
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Unsupported GTP port number");
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * mce_parse_tunnel_attr - Parse tunnel attributes from TC flower filter
 * @filter_dev: Pointer to device on which filter is being added
 * @vsi: Pointer to VSI structure
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 * @headers: inner or outer header fields
 */
static int
mce_parse_tunnel_attr(struct net_device *filter_dev,
			struct mce_vsi *vsi, struct flow_cls_offload *f,
			struct mce_tc_flower_fltr *fltr,
			struct mce_tc_flower_lyr_2_4_hdrs *headers)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_control enc_control;
	int err;

	err = mce_tc_tun_parse(filter_dev, vsi, f, fltr, headers);
	if (err) {
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "failed to parse tunnel attributes");
		return err;
	}

	flow_rule_match_enc_control(rule, &enc_control);
	if (enc_control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_enc_ipv4_addrs(rule, &match);
		if (mce_tc_set_ipv4(&match, fltr, headers, true))
			return -EINVAL;
	} else if (enc_control.key->addr_type ==
		   FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_enc_ipv6_addrs(rule, &match);
		if (mce_tc_set_ipv6(&match, fltr, headers, true))
			return -EINVAL;
	}

#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_IP
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP)) {
		struct flow_match_ip match;

		flow_rule_match_enc_ip(rule, &match);

		if (match.mask->tos) {
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_IP_TOS;
			headers->l3_key.tos = match.key->tos;
			headers->l3_mask.tos = match.mask->tos;
		}

		if (match.mask->ttl) {
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_IP_TTL;
			headers->l3_key.ttl = match.key->ttl;
			headers->l3_mask.ttl = match.mask->ttl;
		}
	}
#endif /* HAVE_FLOW_DISSECTOR_KEY_ENC_IP */

	if ((fltr->tunnel_type == TNL_VXLAN ||
	     fltr->tunnel_type == TNL_GENEVE) &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_enc_ports(rule, &match);
		if (match.key->dst) {
			fltr->flags |=
				MCE_TC_FLWR_FIELD_ENC_DEST_L4_PORT;
			/* tunnel packets unsupport src_port */
			headers->l4_key.dst_port = match.key->dst;
			headers->l4_mask.dst_port = match.mask->dst;
		}
	}

	if ((fltr->tunnel_type == TNL_GTPU ||
	     fltr->tunnel_type == TNL_GTPC) &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_enc_ports(rule, &match);

		if (mce_parse_gtp_type(match, fltr))
			return -EINVAL;
		if (match.key->dst) {
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_DEST_L4_PORT;
			/* tunnel packets unsupport src_port */
			headers->l4_key.dst_port = match.key->dst;
			headers->l4_mask.dst_port = match.mask->dst;
		}
	}

#ifdef HAVE_GTP_SUPPORT
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_OPTS)) {
		struct flow_match_enc_opts match;

		flow_rule_match_enc_opts(rule, &match);

		memcpy(&fltr->gtp_pdu_info_keys, &match.key->data[0],
		       sizeof(struct gtp_pdu_session_info));

		memcpy(&fltr->gtp_pdu_info_masks, &match.mask->data[0],
		       sizeof(struct gtp_pdu_session_info));

		fltr->flags |= MCE_TC_FLWR_FIELD_ENC_OPTS;
	}
#endif /* HAVE_GTP_SUPPORT */

	return 0;
}
#endif /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */

/**
 * mce_parse_cls_flower - Parse TC flower filters provided by kernel
 * @vsi: Pointer to the VSI
 * @filter_dev: Pointer to device on which filter is being added
 * @f: Pointer to struct flow_cls_offload
 * @fltr: Pointer to filter structure
 */
#ifdef HAVE_TC_INDIR_BLOCK
static int mce_parse_cls_flower(struct net_device *filter_dev,
				  struct mce_vsi *vsi,
				  struct flow_cls_offload *f,
				  struct mce_tc_flower_fltr *fltr)
#else
static int
mce_parse_cls_flower(struct net_device __always_unused *filter_dev,
		       struct mce_vsi __always_unused *vsi,
		       struct tc_cls_flower_offload *f,
		       struct mce_tc_flower_fltr *fltr)
#endif /* HAVE_TC_INDIR_BLOCK */
{
	struct mce_tc_flower_lyr_2_4_hdrs *headers =
		&fltr->outer_headers;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	u16 n_proto_mask = 0, n_proto_key = 0, addr_type = 0;
	struct flow_dissector *dissector;
#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
	struct net_device *tunnel_dev;
#endif /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */

	dissector = rule->match.dissector;
	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
#ifdef HAVE_TC_FLOWER_VLAN_IN_TAGS
	      BIT(FLOW_DISSECTOR_KEY_VLANID) |
#endif
#ifndef HAVE_TC_FLOWER_VLAN_IN_TAGS
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
#endif
#ifdef HAVE_FLOW_DISSECTOR_KEY_CVLAN
	      BIT(FLOW_DISSECTOR_KEY_CVLAN) |
#endif /* HAVE_FLOW_DISSECTOR_KEY_CVLAN */
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
#ifdef HAVE_TC_FLOWER_ENC
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_PORTS) |
#ifdef HAVE_GTP_SUPPORT
	      BIT(FLOW_DISSECTOR_KEY_ENC_OPTS) |
#endif /* HAVE_GTP_SUPPORT */
	      BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
	      BIT(FLOW_DISSECTOR_KEY_IP) |
#endif /* HAVE_FLOW_DISSECTOR_KEY_IP */
#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_IP
	      BIT(FLOW_DISSECTOR_KEY_ENC_IP) |
#endif /* HAVE_FLOW_DISSECTOR_KEY_ENC_IP */
#ifdef HAVE_FLOW_DISSECTOR_KEY_IPSEC
	      BIT(FLOW_DISSECTOR_KEY_IPSEC) |
#endif /* HAVE_FLOW_DISSECTOR_KEY_IPSEC */
#endif /* HAVE_TC_FLOWER_ENC */
	      BIT(FLOW_DISSECTOR_KEY_META) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS))) {
		fd_print("dissector used_keys:0x%llx\n",
			 dissector->used_keys);
		NL_SET_ERR_MSG_MOD(fltr->extack, "Unsupported key used");
		return -EOPNOTSUPP;
	}
#if defined(HAVE_TC_FLOWER_ENC) && defined(HAVE_TC_INDIR_BLOCK)
#ifdef HAVE_FLOW_DISSECTOR_KEY_IPSEC
	if (dissector->used_keys & BIT(FLOW_DISSECTOR_KEY_IPSEC))
		fltr->ipsec_en = true;
	fd_print("dissector used_keys:0x%llx\n", dissector->used_keys);
#endif /* HAVE_FLOW_DISSECTOR_KEY_IPSEC */

	tunnel_dev = mce_get_tunnel_device(filter_dev, rule, fltr);
	if (tunnel_dev) {
		int err;

		filter_dev = tunnel_dev;
		err = mce_parse_tunnel_attr(filter_dev, vsi, f, fltr,
					      headers);
		if (err) {
			NL_SET_ERR_MSG_MOD(
				fltr->extack,
				"Failed to parse TC flower tunnel attributes");
			return err;
		}

		/* header pointers should point to the inner headers, outer
		 * header were already set by mce_parse_tunnel_attr
		 */
		headers = &fltr->inner_headers;
	} else {
		fltr->tunnel_type = TNL_LAST;
	}

#else /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */
	fltr->tunnel_type = TNL_TC_LAST;
#endif /* HAVE_TC_FLOWER_ENC && HAVE_TC_INDIR_BLOCK */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);

		n_proto_key = ntohs(match.key->n_proto);
		n_proto_mask = ntohs(match.mask->n_proto);

		fltr->flags |= MCE_TC_FLWR_FIELD_ETH_TYPE_ID;
		headers->l2_key.n_proto = cpu_to_be16(n_proto_key);
		headers->l2_mask.n_proto = cpu_to_be16(n_proto_mask);
		headers->l3_key.ip_proto = match.key->ip_proto;
		headers->l3_mask.ip_proto = match.mask->ip_proto;
		fd_print(
			"parse n_proto:0x%x nmask:0x%x ip_proto:0x%x ipmask:0x%x\n",
			headers->l2_key.n_proto, headers->l2_mask.n_proto,
			match.key->ip_proto, match.mask->ip_proto);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);

		if (!is_zero_ether_addr(match.key->dst)) {
			ether_addr_copy(headers->l2_key.dst_mac,
					match.key->dst);
			ether_addr_copy(headers->l2_mask.dst_mac,
					match.mask->dst);
			fltr->flags |= MCE_TC_FLWR_FIELD_DST_MAC;
		}

		if (!is_zero_ether_addr(match.key->src)) {
			ether_addr_copy(headers->l2_key.src_mac,
					match.key->src);
			ether_addr_copy(headers->l2_mask.src_mac,
					match.mask->src);
			fltr->flags |= MCE_TC_FLWR_FIELD_SRC_MAC;
		}
	}

#ifdef HAVE_TC_FLOWER_VLAN_IN_TAGS
	if (dissector_uses_key(dissector, FLOW_DISSECTOR_KEY_VLANID)) {
		struct flow_dissector_key_tags *key =
			(struct flow_dissector_key_tags *)
				skb_flow_dissector_target(
					f->dissector,
					FLOW_DISSECTOR_KEY_VLANID, f->key);
		struct flow_dissector_key_tags *mask =
			(struct flow_dissector_key_tags *)
				skb_flow_dissector_target(
					f->dissector,
					FLOW_DISSECTOR_KEY_VLANID,
					f->mask);

		if (mask->vlan_id) {
			if (mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= MCE_TC_FLWR_FIELD_VLAN;
				headers->vlan_hdr.vlan_id = cpu_to_be16(
					key->vlan_id & VLAN_VID_MASK);
			} else {
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "Bad VLAN mask");
				return -EINVAL;
			}
		}

		if (match.mask->vlan_priority) {
			fltr->flags |= MCE_TC_FLWR_FIELD_VLAN_PRIO;
			headers->vlan_hdr.vlan_prio = be16_encode_bits(
				match.key->vlan_priority, VLAN_PRIO_MASK);
		}
#ifdef HAVE_TCF_VLAN_TPID
		if (mask->vlan_tpid) {
			headers->vlan_hdr.vlan_tpid = key->vlan_tpid;
			fltr->flags |= MCE_TC_FLWR_FIELD_VLAN_TPID;
		}
#endif /* HAVE_TCF_VLAN_TPID */
	}
#else /* !HAVE_TC_FLOWER_VLAN_IN_TAGS */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN) ||
	    is_vlan_dev(filter_dev)) {
		struct flow_dissector_key_vlan mask;
		struct flow_dissector_key_vlan key;
		struct flow_match_vlan match;

		if (is_vlan_dev(filter_dev)) {
			match.key = &key;
			match.key->vlan_id = vlan_dev_vlan_id(filter_dev);
#ifdef HAVE_TCF_VLAN_TPID
			match.key->vlan_tpid =
				vlan_dev_vlan_proto(filter_dev);
#endif /* HAVE_TCF_VLAN_TPID */
			match.key->vlan_priority = 0;
			match.mask = &mask;
			memset(match.mask, 0xff, sizeof(*match.mask));
			match.mask->vlan_priority = 0;
		} else {
			flow_rule_match_vlan(rule, &match);
		}

		if (match.mask->vlan_id) {
			if (match.mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= MCE_TC_FLWR_FIELD_VLAN;
				headers->vlan_hdr.vlan_id =
					cpu_to_be16(match.key->vlan_id &
						    VLAN_VID_MASK);
			} else {
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "Bad VLAN mask");
				return -EINVAL;
			}
		}

		if (match.mask->vlan_priority) {
			fltr->flags |= MCE_TC_FLWR_FIELD_VLAN_PRIO;
			headers->vlan_hdr.vlan_prio = be16_encode_bits(
				match.key->vlan_priority, VLAN_PRIO_MASK);
		}
#ifdef HAVE_TCF_VLAN_TPID
		if (match.mask->vlan_tpid)
			headers->vlan_hdr.vlan_tpid = match.key->vlan_tpid;
#endif /* HAVE_TCF_VLAN_TPID */
	}
#endif /* HAVE_TC_FLOWER_VLAN_IN_TAGS */

#ifdef HAVE_FLOW_DISSECTOR_KEY_CVLAN
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_cvlan(rule, &match);
		if (match.mask->vlan_id) {
			if (match.mask->vlan_id == VLAN_VID_MASK) {
				fltr->flags |= MCE_TC_FLWR_FIELD_CVLAN;
				headers->cvlan_hdr.vlan_id =
					cpu_to_be16(match.key->vlan_id &
						    VLAN_VID_MASK);
			} else {
				NL_SET_ERR_MSG_MOD(fltr->extack,
						   "Bad CVLAN mask");
				return -EINVAL;
			}
		}

		if (match.mask->vlan_priority) {
			fltr->flags |= MCE_TC_FLWR_FIELD_CVLAN_PRIO;
			headers->cvlan_hdr.vlan_prio = be16_encode_bits(
				match.key->vlan_priority, VLAN_PRIO_MASK);
		}
	}
#endif /* HAVE_FLOW_DISSECTOR_KEY_CVLAN */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
		/* ip flags, first frag take as normal frag*/
		if (match.key->flags & FLOW_DIS_IS_FRAGMENT)
			fltr->flags |= MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT;
		if (match.key->flags & FLOW_DIS_FIRST_FRAG)
			fltr->flags |= MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT;
		addr_type = match.key->addr_type;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		if (mce_tc_set_ipv4(&match, fltr, headers, false))
			return -EINVAL;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		if (mce_tc_set_ipv6(&match, fltr, headers, false))
			return -EINVAL;
	}

#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);

		if (match.mask->tos) {
			if (match.mask->tos != 0xff) {
				NL_SET_ERR_MSG_MOD(
					fltr->extack,
					"unsupported ipv4/v6 tos mask");
				return -EOPNOTSUPP;
			}
			fltr->flags |= MCE_TC_FLWR_FIELD_IP_TOS;
			headers->l3_key.tos = match.key->tos;
			headers->l3_mask.tos = match.mask->tos;
			fd_print("parse tos:0x%x mask:0x%x\n",
				 match.key->tos, match.mask->tos);
		}

		if (match.mask->ttl) {
			fltr->flags |= MCE_TC_FLWR_FIELD_IP_TTL;
			headers->l3_key.ttl = match.key->ttl;
			headers->l3_mask.ttl = match.mask->ttl;
		}
	}
#endif /* HAVE_FLOW_DISSECTOR_KEY_IP */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		if (mce_tc_set_port(match, fltr, headers, false))
			return -EINVAL;
		switch (headers->l3_key.ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_SCTP:
			break;
		default:
			NL_SET_ERR_MSG_MOD(
				fltr->extack,
				"Only UDP TCP and SCTP transport are supported");
			return -EINVAL;
		}
	}

#ifdef HAVE_FLOW_DISSECTOR_KEY_IPSEC
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPSEC)) {
		struct flow_match_ipsec match;

		flow_rule_match_ipsec(rule, &match);
		fd_print("dissector ipsec: spi:0x%x mask:0x%x\n",
			 match.key->spi, match.mask->spi);
		headers->ipsec_hdr.spi = match.key->spi;
		headers->ipsec_mask.spi = match.mask->spi;
		fltr->flags |= MCE_TC_FLWR_FIELD_IPSEC_SPI;
	}
#endif /* HAVE_FLOW_DISSECTOR_KEY_IPSEC */
	return 0;
}

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/**
 * mce_handle_tclass_action - Support directing to a traffic class or queue
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Support directing traffic to a traffic class or queue
 */
static int mce_handle_tclass_action(struct mce_vsi *vsi,
				      struct flow_cls_offload *cls_flower,
				      struct mce_tc_flower_fltr *fltr)
{
	unsigned int nrx = TC_H_MIN(cls_flower->classid);
	u32 num_tc;
	u32 queue;

	num_tc = (u32)netdev_get_num_tc(vsi->netdev);

	if (nrx < TC_H_MIN_PRIORITY) {
		/* user specified queue, hence action is forward to queue */
		if (nrx > vsi->num_rxq) {
			NL_SET_ERR_MSG_MOD(
				fltr->extack,
				"Unable to add filter because specified queue is invalid");
			return -ENXIO;
		}

		queue = nrx;
		/* forward to queue */
		if (fltr->action.fltr_act != MCE_DROP_PACKET)
			fltr->action.fltr_act = MCE_FWD_TO_Q;
		fltr->action.fwd.q.queue = queue;
	} else if ((nrx - TC_H_MIN_PRIORITY) < num_tc) {
		NL_SET_ERR_MSG_MOD(
			fltr->extack,
			"Unable to add filter because user specified not support hw_tc as forward action");
		return -EINVAL;
	} else {
		NL_SET_ERR_MSG_MOD(
			fltr->extack,
			"Unable to add filter because user specified neither queue nor hw_tc as forward action");
		return -EINVAL;
	}

	if (mce_is_tunnel_fltr(fltr)) {
		if (!(fltr->flags & MCE_TC_FLWR_FIELD_ENC_DST_MAC)) {
			ether_addr_copy(fltr->outer_headers.l2_key.dst_mac,
					vsi->netdev->dev_addr);
			eth_broadcast_addr(
				fltr->outer_headers.l2_mask.dst_mac);
			fltr->flags |= MCE_TC_FLWR_FIELD_ENC_DST_MAC;
		}
	} else if (!(fltr->flags & MCE_TC_FLWR_FIELD_DST_MAC)) {
		ether_addr_copy(fltr->outer_headers.l2_key.dst_mac,
				vsi->netdev->dev_addr);
		eth_broadcast_addr(fltr->outer_headers.l2_mask.dst_mac);
		fltr->flags |= MCE_TC_FLWR_FIELD_DST_MAC;
	}
	return 0;
}

#endif

/**
 * mce_parse_tc_flower_actions - Parse the actions for a TC filter
 * @filter_dev: Ingress netdev
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to TC flower offload structure
 * @fltr: Pointer to TC flower filter structure
 *
 * Parse the actions for a TC filter
 */
static int
mce_parse_tc_flower_actions(struct net_device *filter_dev,
			      struct mce_vsi *vsi,
			      struct flow_cls_offload *cls_flower,
			      struct mce_tc_flower_fltr *fltr)
{
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls_flower);
	struct flow_action *flow_action = &rule->action;
	struct flow_action_entry *act;
	int i;
#else
	struct tcf_exts *exts = cls_flower->exts;
	struct tc_action *tc_act;
#if defined(HAVE_TCF_EXTS_FOR_EACH_ACTION)
	int i;
#else
	struct tc_action *temp;
	LIST_HEAD(tc_actions);
#endif
#endif /* HAVE_TC_FLOW_RULE_INFRASTRUCTURE */

#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	if (!flow_action_has_entries(flow_action))
#elif defined(HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV)
	if (!tcf_exts_has_actions(exts))
#else
	if (tc_no_actions(exts))
#endif
		goto no_action;

#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
	flow_action_for_each(i, act, flow_action) {
#elif defined(HAVE_TCF_EXTS_FOR_EACH_ACTION)
	tcf_exts_for_each_action(i, tc_act, exts)
	{
#elif defined(HAVE_TCF_EXTS_TO_LIST)
	tcf_exts_to_list(exts, &tc_actions);

	list_for_each_entry_safe(tc_act, temp, &tc_actions, list) {
#else
	list_for_each_entry_safe(tc_act, temp, &(exts)->actions, list) {
#endif /* HAVE_TCF_EXTS_TO_LIST */
		/* Drop action */
#ifdef HAVE_TC_FLOW_RULE_INFRASTRUCTURE
		if (act->id == FLOW_ACTION_DROP) {
#else
		if (is_tcf_gact_shot(tc_act)) {
#endif
			/* only support drop or pass */
			fltr->action.fltr_act = MCE_DROP_PACKET;
		}

		if (act->id == FLOW_ACTION_VLAN_POP) {
			/* only support pop 1 vlan， this need setup by netdev
			 * vlan status. */
			fltr->action.pop_vlan = true;
		}
	}

no_action:
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (cls_flower->classid)
		return mce_handle_tclass_action(vsi, cls_flower, fltr);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	return 0;
}

/**
 * mce_add_switch_fltr - Add TC flower filters
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct mce_tc_flower_fltr
 *
 * Add filter in HW switch block
 */
static int mce_add_switch_fltr(struct mce_vsi *vsi,
				 struct mce_tc_flower_fltr *fltr)
{
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	if (fltr->action.fltr_act == MCE_FWD_TO_QGRP)
		return -EOPNOTSUPP;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
#ifdef HAVE_TC_SETUP_CLSFLOWER
	return mce_add_tc_flower_adv_fltr(vsi, fltr);
#else
	return -EOPNOTSUPP;
#endif /* HAVE_TC_SETUP_CLSFLOWER */
}

/**
 * mce_add_tc_fltr - adds a TC flower filter
 * @netdev: Pointer to netdev
 * @vsi: Pointer to VSI
 * @f: Pointer to flower offload structure
 * @__fltr: Pointer to struct mce_tc_flower_fltr
 *
 * This function parses TC-flower input fields, parses action,
 * and adds a filter.
 */
#ifdef HAVE_TC_INDIR_BLOCK
static int mce_add_tc_fltr(struct net_device *netdev,
			     struct mce_vsi *vsi,
			     struct flow_cls_offload *f,
			     struct mce_tc_flower_fltr **__fltr)
#else
static int mce_add_tc_fltr(struct net_device *netdev,
			     struct mce_vsi *vsi,
			     struct tc_cls_flower_offload *f,
			     struct mce_tc_flower_fltr **__fltr)
#endif /* HAVE_TC_INDIR_BLOCK */
{
	struct mce_tc_flower_fltr *fltr;
	int err;

	/* by default, set output to be INVALID */
	*__fltr = NULL;

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	fltr->cookie = f->cookie;
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
	fltr->extack = f->common.extack;
#endif
	fltr->src_vsi = vsi;
	INIT_HLIST_NODE(&fltr->tc_flower_node);

	err = mce_parse_cls_flower(netdev, vsi, f, fltr);
	if (err < 0)
		goto err;

	err = mce_parse_tc_flower_actions(netdev, vsi, f, fltr);
	if (err < 0)
		goto err;

	err = mce_add_switch_fltr(vsi, fltr);
	if (err < 0)
		goto err;

	/* return the newly created filter */
	*__fltr = fltr;

	return 0;
err:
	kfree(fltr);
	return err;
}

/**
 * mce_find_tc_flower_fltr - Find the TC flower filter in the list
 * @pf: Pointer to PF
 * @cookie: filter specific cookie
 */
static struct mce_tc_flower_fltr *
mce_find_tc_flower_fltr(struct mce_pf *pf, unsigned long cookie)
{
	struct mce_tc_flower_fltr *fltr;

	hlist_for_each_entry(fltr, &pf->tc_flower_fltr_list,
			     tc_flower_node)
		if (cookie == fltr->cookie)
			return fltr;

	return NULL;
}

/**
 * mce_add_cls_flower - add TC flower filters
 * @netdev: Pointer to filter device
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to flower offload structure
 */
int
#ifdef HAVE_TC_INDIR_BLOCK
mce_add_cls_flower(struct net_device *netdev, struct mce_vsi *vsi,
		   struct flow_cls_offload *cls_flower)
#else
mce_add_cls_flower(struct net_device __always_unused *netdev,
		   struct mce_vsi *vsi,
		   struct tc_cls_flower_offload *cls_flower)
#endif /* HAVE_TC_INDIR_BLOCK */
{
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
	struct netlink_ext_ack *extack = cls_flower->common.extack;
#endif /* HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK */
	struct net_device *vsi_netdev = vsi->netdev;
	struct mce_tc_flower_fltr *fltr;
	struct mce_pf *pf = vsi->back;
	int err;

	if (!(vsi_netdev->features & NETIF_F_HW_TC)) {
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
#ifdef HAVE_TC_INDIR_BLOCK
		/* Based on TC indirect notifications from kernel, all ice
		 * devices get an instance of rule from higher level device.
		 * Avoid triggering explicit error in this case.
		 */
		if (netdev == vsi_netdev)
			NL_SET_ERR_MSG_MOD(
				extack,
				"can't apply TC flower filters, turn ON hw-tc-offload and try again");
#else
		NL_SET_ERR_MSG_MOD(
			extack,
			"can't apply TC flower filters, turn ON hw-tc-offload and try again");
#endif /* HAVE_TC_INDIR_BLOCK */
#else /* !HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK */
		netdev_err(
			vsi_netdev,
			"can't apply TC flower filters, turn ON hw-tc-offload and try again\n");
#endif /* HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK */
		return -EINVAL;
	}

	/* avoid duplicate entries, if exists - return error */
	fltr = mce_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (fltr) {
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
		NL_SET_ERR_MSG_MOD(
			extack, "filter cookie already exists, ignoring");
#else
		netdev_warn(vsi_netdev,
			    "filter cookie %lx already exists, ignoring\n",
			    fltr->cookie);
#endif /* HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK */
		return -EEXIST;
	}
	/* prep and add TC-flower filter in HW */
	err = mce_add_tc_fltr(netdev, vsi, cls_flower, &fltr);
	if (err)
		return err;

	/* add filter into an ordered list */
	hlist_add_head(&fltr->tc_flower_node, &pf->tc_flower_fltr_list);
	return 0;
}

/**
 * mce_del_tc_fltr - deletes a filter from HW table
 * @vsi: Pointer to VSI
 * @fltr: Pointer to struct mce_tc_flower_fltr
 *
 * This function deletes a filter from HW table and manages book-keeping
 */
static int mce_del_tc_fltr(struct mce_vsi *vsi,
			     struct mce_tc_flower_fltr *fltr)
{
	struct mce_fdir_filter *filter;
	struct mce_pf *pf = vsi->back;
	union mce_fdir_pattern *lkup_pattern;
	int err = 0;

	filter = fltr->filter;
	lkup_pattern = &filter->lkup_pattern;

	pf->flow_engine->destroy(pf, filter, fltr);

	if (err) {
		if (err == -ENOENT) {
			NL_SET_ERR_MSG_MOD(fltr->extack,
					   "Filter does not exist");
			return -ENOENT;
		}
		NL_SET_ERR_MSG_MOD(fltr->extack,
				   "Failed to delete TC flower filter");
		return -EIO;
	}

	return 0;
}

/**
 * mce_del_cls_flower - delete TC flower filters
 * @vsi: Pointer to VSI
 * @cls_flower: Pointer to struct flow_cls_offload
 */
int mce_del_cls_flower(struct mce_vsi *vsi,
			 struct flow_cls_offload *cls_flower)
{
	struct mce_tc_flower_fltr *fltr;
	struct mce_pf *pf = vsi->back;
	int err;

	fltr = mce_find_tc_flower_fltr(pf, cls_flower->cookie);
	if (!fltr) {
		if (hlist_empty(&pf->tc_flower_fltr_list))
			return 0;
#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
		NL_SET_ERR_MSG_MOD(
			cls_flower->common.extack,
			"failed to delete TC flower filter because unable to find it");
#else
		dev_err(mce_pf_to_dev(pf),
			"failed to delete TC flower filter because unable to find it\n");
#endif
		return -EINVAL;
	}

#ifdef HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
	fltr->extack = cls_flower->common.extack;
#endif
	err = mce_del_tc_fltr(vsi, fltr);
	if (err)
		return err;

	/* delete filter from an ordered list */
	hlist_del(&fltr->tc_flower_node);

	/* free the filter node */
	kfree(fltr);

	return 0;
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */
