#ifndef _MCE_LIB_H_
#define _MCE_LIB_H_

#include "mce.h"

#define __VLAN_ALLOWED(protocol)                          \
	!!((protocol) == __constant_htons(ETH_P_8021Q) || \
	   (protocol) == __constant_htons(ETH_P_8021AD))

#define MCE_INSERT_VLAN_CNT(pf) ((pf)->dvlan_ctrl.cnt)

#define __DEBUG_SKB_DUMP (0)
#if __DEBUG_SKB_DUMP
#include <linux/highmem.h>

static inline void __mce_tx_skb_dump(const struct sk_buff *skb,
				     bool full_pkt)
{
	static atomic_t can_dump_full = ATOMIC_INIT(5);
	struct skb_shared_info *sh = skb_shinfo(skb);
	struct net_device *dev = skb->dev;
	struct sock *sk = skb->sk;
	struct sk_buff *list_skb;
	bool has_mac, has_trans;
	int headroom, tailroom;
	int i, len, seg_len;
	const char *level = KERN_WARNING;

	if (full_pkt)
		full_pkt = atomic_dec_if_positive(&can_dump_full) >= 0;

	if (full_pkt)
		len = skb->len;
	else
		len = min_t(int, skb->len, MAX_HEADER + 128);

	headroom = skb_headroom(skb);
	tailroom = skb_tailroom(skb);

	has_mac = skb_mac_header_was_set(skb);
	has_trans = skb_transport_header_was_set(skb);

	printk(KERN_DEBUG
	       "queue_mapping=%u skbaddr=%p vlan_tagged=%d vlan_proto=0x%04x\n"
	       "vlan_tci=0x%04x protocol=0x%04x\n"
	       "skb->head=%u skb->data=%u skb->tail=%u skb->end=%u\n"
	       "skb->datalen=%u skb_len=%u skb->truesize=%u headroom=%u headlen=%u tailroom=%u\n"
	       "mac=(%d,%d) net=(%d,%d) trans=%d\n"
	       "shinfo(txflags=%u nr_frags=%u gso(size=%hu type=%u segs=%hu))\n"
	       "csum(0x%x ip_summed=%u complete_sw=%u valid=%u level=%u)\n"
	       "hash(0x%x sw=%u l4=%u) proto=0x%04x pkttype=%u iif=%d\n",
	       skb->queue_mapping, skb, skb_vlan_tag_present(skb),
	       ntohs(skb->vlan_proto), skb_vlan_tag_get(skb),
	       ntohs(skb->protocol), skb->head, skb->data, skb->tail,
	       skb->end, skb->data_len, skb->len, skb->truesize, headroom,
	       skb_headlen(skb), tailroom, has_mac ? skb->mac_header : -1,
	       has_mac ? (skb->network_header - skb->mac_header) : -1,
	       skb->network_header,
	       has_trans ? skb_network_header_len(skb) : -1,
	       has_trans ? skb->transport_header : -1, sh->tx_flags,
	       sh->nr_frags, sh->gso_size, sh->gso_type, sh->gso_segs,
	       skb->csum, skb->ip_summed, skb->csum_complete_sw,
	       skb->csum_valid, skb->csum_level, skb->hash, skb->sw_hash,
	       skb->l4_hash, ntohs(skb->protocol), skb->pkt_type,
	       skb->skb_iif);
	if (dev)
		printk(KERN_DEBUG "%sdev name=%s feat=0x%pNF\n", level,
		       dev->name, &dev->features);

	seg_len = min_t(int, skb_headlen(skb), len);
	if (seg_len)
		print_hex_dump(level, "skb linear:   ", DUMP_PREFIX_OFFSET,
			       16, 1, skb->data, seg_len, false);
	len -= seg_len;

	for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 p_off, p_len, copied;
		struct page *p;
		u8 *vaddr;

		p = skb_frag_address(frag);
		p_len = skb_frag_size(frag);
		seg_len = min_t(int, p_len, len);
		vaddr = kmap_atomic(p);
		print_hex_dump(level, "skb frag:     ", DUMP_PREFIX_OFFSET,
			       16, 1, vaddr, seg_len, false);
		kunmap_atomic(vaddr);
		len -= seg_len;
		if (!len)
			break;
	}

	if (full_pkt && skb_has_frag_list(skb)) {
		printk(KERN_DEBUG "skb fraglist:\n");
		skb_walk_frags(skb, list_skb)
			__mce_tx_skb_dump(list_skb, true);
	}
}

static inline void mce_print_skb_data(struct sk_buff *skb)
{
	unsigned int i;
	unsigned char *data;
	struct skb_shared_info *shinfo;
	unsigned int j;

	if (skb_headlen(skb) > 0) {
		printk(KERN_INFO "Linear data (%u bytes): ",
		       skb_headlen(skb));
		data = skb->data;
		for (i = 0; i < skb_headlen(skb); i++) {
			printk(KERN_CONT "%02x ", data[i]);
		}
		printk(KERN_CONT "\n");
	}

	shinfo = skb_shinfo(skb);
	for (i = 0; i < shinfo->nr_frags; i++) {
		skb_frag_t *frag = &shinfo->frags[i];
		unsigned int frag_size = skb_frag_size(frag);
		void *frag_data = skb_frag_address(frag);

		printk(KERN_INFO "Fragment %u (%u bytes): ", i, frag_size);
		for (j = 0; j < frag_size; j++) {
			printk(KERN_CONT "%02x ",
			       ((unsigned char *)frag_data)[j]);
		}
		printk(KERN_CONT "\n");
	}

	if (shinfo->frag_list) {
		struct sk_buff *frag_skb;
		printk(KERN_INFO "Printing frag_list:\n");
		skb_walk_frags(skb, frag_skb)
		{
			mce_print_skb_data(frag_skb);
		}
	}
}

#define mce_tx_skb_dump __mce_tx_skb_dump
#endif

/* VM RULE */
enum mce_misc_irq_act_type {
	__MISC_IRQ_TYPE_REGISTER_INTR_VEC,
	__MISC_IRQ_TYPE_SET_INTR_MASK,
	__MISC_IRQ_TYPE_GET_INTR_STAT,
	__MISC_IRQ_TYPE_CLR_INTR_STAT,
};

void mce_vsi_cfg_netdev_tc(struct mce_vsi *vsi, struct mce_dcb *dcb);
void mce_vsi_dcb_default(struct mce_vsi *vsi);
int mce_vsi_recfg_qs(struct mce_vsi *vsi, int new_rx, int new_tx);
struct mce_vsi *mce_vsi_setup(struct mce_pf *pf,
			      enum mce_vsi_type vsi_type);
int mce_get_num_local_cpus(struct device *dev);
int mce_normalize_cpu_count(int num_cpus);
const char *mce_vsi_type_str(enum mce_vsi_type vsi_type);
int mce_get_irq_res(struct mce_pf *pf, struct mce_res_tracker *res,
		    u16 needed, u16 start);
int mce_free_irq_res(struct mce_res_tracker *res, u16 needed, u16 start);
void mce_vsi_cfg_frame_size(struct mce_vsi *vsi);
int mce_vsi_release(struct mce_vsi *vsi);
void mce_vsi_release_all(struct mce_pf *pf);
void mce_vsi_get_q_vector_q_base(struct mce_vsi *vsi, u16 vector_id,
				 u16 *txq, u16 *rxq);
int mce_vsi_open(struct mce_vsi *vsi);
void mce_vsi_close(struct mce_vsi *vsi);
int mce_down(struct mce_vsi *vsi);
int mce_up(struct mce_vsi *vsi);
void mce_update_tx_ring_stats(struct mce_ring *tx_ring, u64 pkts,
			      u64 bytes);
void mce_update_rx_ring_stats(struct mce_ring *rx_ring, u64 pkts,
			      u64 bytes);
void mce_vsi_free_tx_rings(struct mce_vsi *vsi);
void mce_vsi_free_rx_rings(struct mce_vsi *vsi);
int mce_vsi_rebuild(struct mce_vsi *vsi);
void mce_update_pf_stats(struct mce_pf *pf);
void mce_setup_L2_filter(struct mce_pf *pf);
int mce_set_bw_limit_init(struct mce_pf *pf);
int mce_set_max_bw_limit(struct mce_pf *pf, int vf_id, u64 max_tx_rate,
			 u16 ring_cnt);
int mce_set_rss_table(struct mce_hw *hw, u16 vf_id, u16 q_cnt);
struct vf_data_storage *
mce_realloc_and_fill_pfinfo(struct mce_pf *pf, bool to_pfvf, bool copied);
u64 mce_int_pow(u64 base, unsigned int exp);
#ifdef THREAD_POLL
int mce_poll_thread_handler(void *data);
#endif
bool mce_get_misc_irq_evt(struct mce_hw *hw, enum mce_misc_irq_type type);
int mce_setup_misc_irq(struct mce_hw *hw, bool en, int nr_vec);
int mce_pre_handle_misc_irq(struct mce_hw *hw,
			    enum mce_misc_irq_type type);
#endif /* _MCE_LIB_H_ */
