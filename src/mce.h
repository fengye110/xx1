#ifndef _MCE_H_
#define _MCE_H_

#include "compat/kcompat.h"
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/netdevice.h>
#include <linux/compiler.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/cpumask.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>
#ifdef HAVE_NDO_DFWD_OPS
#include <linux/if_macvlan.h>
#endif /* HAVE_NDO_DFWD_OPS */
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/aer.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/bitmap.h>
#ifdef HAVE_INCLUDE_BITFIELD
#include <linux/bitfield.h>
#endif /* HAVE_INCLUDE_BITFIELD */
#include <linux/hashtable.h>
#include <linux/log2.h>
#include <linux/ip.h>
#include <linux/sctp.h>
#include <linux/ipv6.h>
#include <linux/pkt_sched.h>
#include <linux/if_bridge.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/sizes.h>
#ifdef HAVE_LINKMODE
#include <linux/linkmode.h>
#endif /* HAVE_LINKMODE */
#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf.h>
#include <linux/filter.h>
#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#include <net/xdp_sock.h>
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#include <net/ipv6.h>
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include <net/devlink.h>
#endif /* CONFIG_NET_DEVLINK */
#ifdef HAVE_CONFIG_DIMLIB
#include <linux/dim.h>
#else
#include "compat/kcompat_dim.h"
#endif
#if defined(HAVE_GNSS_MODULE) && IS_ENABLED(CONFIG_GNSS)
#include <linux/gnss.h>
#else /* !HAVE_GNSS_MODULE || !IS_ENABLED(CONFIG_GNSS) */
#include "compat/kcompat_gnss.h"
#endif /* HAVE_GNSS_MODULE && IS_ENABLED(CONFIG_GNSS) */
#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf.h>
#include <linux/filter.h>
#ifdef HAVE_XDP_BUFF_RXQ
#include <net/xdp.h>
#endif /* HAVE_XDP_BUFF_RXQ */
#endif /* HAVE_XDP_SUPPORT */
#include "mce_type.h"
#include "mce_txrx.h"
#include "mucse_auxiliary/linux/mucse_auxiliary_bus.h"
#include "mce_ptp.h"

#if defined(HAVE_VXLAN_RX_OFFLOAD) || defined(HAVE_VXLAN_TYPE)
#if IS_ENABLED(CONFIG_VXLAN)
#include <net/vxlan.h>
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD || HAVE_VXLAN_TYPE */
#ifdef HAVE_GRE_ENCAP_OFFLOAD
#include <net/gre.h>
#endif /* HAVE_GRE_ENCAP_OFFLOAD */
#if defined(HAVE_GENEVE_RX_OFFLOAD) || defined(HAVE_GENEVE_TYPE)
#if IS_ENABLED(CONFIG_GENEVE)
#include <net/geneve.h>
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD || HAVE_GENEVE_TYPE */
#ifdef HAVE_GTP_SUPPORT
#include <net/gtp.h>
#endif /* HAVE_GTP_SUPPORT */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
#include <net/udp_tunnel.h>
#endif
#ifdef NETIF_F_HW_TC
#include <net/pkt_cls.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_gact.h>
#endif /* NETIF_F_HW_TC */
#include <net/ip.h>
#include <linux/cpu_rmap.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include "mce_fdir.h"
#include "mce_sriov.h"
#include "./mucse_auxiliary/mce_idc.h"

#define DRIVER_NAME "mcepf"

#define MCE_GTPC_PORT 2123
#define mce_pf_to_dev(pf) (&((pf)->pdev->dev))
#define mce_hw_to_dev(hw) ((hw)->dev)

#define mce_for_each_q_vector(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_q_vectors; (i)++)

/* iterator for handling rings in ring container */
#define mce_rc_for_each_ring(pos, head) \
	for (pos = (head).ring; pos != NULL; pos = pos->next)

/* Macros for each Tx/Rx ring in a VSI */
#define mce_for_each_txq(vsi, i) for ((i) = 0; (i) < (vsi)->num_txq; (i)++)

// scan all alloc_txq
#define mce_for_each_txq_new(vsi, i) for ((i) = 0; (i) < (vsi)->alloc_txq; (i)++)

//#define mce_for_each_rxq(vsi, i) for ((i) = 0; (i) < (vsi)->num_rxq; (i)++)
#define mce_for_each_rxq_new(vsi, i) for ((i) = 0; (i) < (vsi)->alloc_rxq; (i)++)

/* Macro for each VSI in a PF */
#define mce_for_each_vsi(pf, i) \
	for ((i) = 0; (i) < (pf)->num_alloc_vsi; (i)++)

/* Macros for each misc irq */
#define mce_for_each_misc_irq(i)                                      \
	for ((i) = MCE_MAC_MISC_IRQ_NONE; (i) < MCE_MAC_MISC_IRQ_MAX; \
	     (i)++)

#define MCE_RXBUF_3072 (3072)
#define MCE_RXBUF_2048 (2048)
#define MCE_RXBUF_1536 (1536)
#define MCE_AQ_SET_MAC_FRAME_SIZE_MAX (9728)
#define MCE_ETH_PKT_HDR_PAD (ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))
#define MCE_MAX_MTU (MCE_AQ_SET_MAC_FRAME_SIZE_MAX - MCE_ETH_PKT_HDR_PAD)
#define MCE_FPGA_MAX_MTU (9732 - MCE_ETH_PKT_HDR_PAD)
#define MCE_INT_NAME_STR_LEN (IFNAMSIZ + 16)

#define MCE_DFLT_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

#define MCE_SCHED_MAX_BW (100000000) /* in Kbps */

/* MSIX */
#define MCE_MIN_MSIX (1)

/* VSI */
#define MCE_NO_VSI (1)
#ifndef MAX_DEFAULT_VECTORS
#define MAX_DEFAULT_VECTORS (64)
#endif /* MAX_DEFAULT_VECTORS */
#define MIN_DEFAULT_VECTORS (8)

#define MCE_RES_VALID_BIT (0x8000)
#define MCE_INVAL_Q_INDEX (0xffff)
struct per_head {
	u32 sip;
	u32 dip;
	u16 proto;
	u16 resv;
};

struct per_head_v6 {
	struct in6_addr sip;
	struct in6_addr dip;
	u16 proto;
	u16 resv;
};

/* ring info */
#define MCE_MAX_NUM_DESC (8192)
#define MCE_MAX_NUM_DESC_DEFAULT (1024)
#define MCE_MIN_NUM_DESC (64)
#define MCE_REQ_DESC_MULTIPLE (32)
#define MAX_RING_CNT (512)
#define MAX_Q_VECTORS (MAX_RING_CNT + 1)
#define MCE_MIN_PKT_LEN (60)

/* DCB fpga 4 tc max; 4 queue for each tc*/
#ifndef MCE_MAX_TC_CNT
#define MCE_MAX_TC_CNT (4)
#endif
#define MCE_QUEUE_FOR_TC (4)

// MCE_MAX_TC_CNT * MCE_QUEUE_FOR_TC = max_queue
#define MCE_MAX_TC_CNT_RDMA (8)
#define MCE_MAX_TC_CNT_NIC (8)
#define MCE_MAX_PRIORITY (8)
#define MAX_PFC_NO_TSO_MAX_SET (6)
#define MCE_MAX_DSCP (64)
#define MCE_MAX_QGS (128)
/* each qg has 4 queues fixed */
#define MCE_MAX_QCNT_IN_QG (4)

/* read or write reg*/
#if 0
#define rd32(rdev, off) readl((rdev)->eth_bar_base + (off))
#define wr32(rdev, off, val) writel((val), (rdev)->eth_bar_base + (off))
#else
#define rd32(rdev, off) mce_rd32(rdev, off)
#define wr32(rdev, off, val) mce_wr32(rdev, off, val)
#endif
#if 0
#define wr32(rdev, off, val) \
do {\
if (off == 0x41200) {\
printk("in %s\n", __func__);\
}\
writel((val), (rdev)->eth_bar_base + (off));\
}while(0)
#endif
#define rd64(rdev, off) readq((rdev)->eth_bar_base + (off))
#define wr64(rdev, off, val) writeq((val), (rdev)->eth_bar_base + (off))
#define ring_rd32(ring, off) readl((ring)->ring_addr + (off))
#define ring_wr32(ring, off, val) writel((val), (ring)->ring_addr + (off))
#define ring_rd64(ring, off) readq((ring)->ring_addr + (off))
#define ring_wr64(ring, off, val) writeq((val), (ring)->ring_addr + (off))
//#ifndef MCE_DEBUG_XINSI_PCIE
#if 0
#define rdma_rd32(rdev, off) readl((rdev)->rdma_bar_base + (off))
#define rdma_wr32(rdev, off, val) \
	writel((val), (rdev)->rdma_bar_base + (off))
#define rdma_rd64(rdev, off) readq((rdev)->rdma_bar_base + (off))
#else
#define rdma_rd32(rdev, off) mce_rdma_rd32(rdev, off)
#define rdma_wr32(rdev, off, val) \
	mce_rdma_wr32(rdev, off, val)
#define rdma_rd64(rdev, off) mce_rdma_rd64(rdev, off)
#endif
/*
#else
#define rdma_rd32(rdev, off) 0
#define rdma_wr32(rdev, off, val) \
	do {                      \
	} while (0)
#define rdma_rd64(rdev, off) 0
#endif
*/
#define npu_wr(hw, off, val) iowrite32(val, (hw)->npu_bar_base + (off))
#define npu_rd(hw, off) ioread32((hw)->npu_bar_base + (off))
#define vector_wr(hw, off, val) iowrite32(val, (hw)->vector_bar_base + (off))
#define vector_rd(hw, off) ioread32((hw)->vector_bar_base + (off))

#define SET_BIT(n, var) (var = (var | (1 << n)))
#define CLR_BIT(n, var) (var = (var & (~(1 << n))))
#define CHK_BIT(n, var) (var & (1 << n))

enum mce_boards {
	board_n20 = 0,
};

enum mce_pf_state {
	MCE_TESTING,
	MCE_DOWN,
	MCE_SERVICE_DIS,
	MCE_NEEDS_RESTART,
	MCE_SHUTTING_DOWN,
	MCE_SERVICE_SCHED,
	MCE_RESET_FAILED,
	MCE_MAILBOXQ_EVENT_PENDING,
	MCE_VF_BW_INITED,
	MCE_PTP_TX_IN_PROGRESS,
	MCE_STATE_NBITS /* must be last */
};

enum mce_pf_flags {
	MCE_FLAG_FLTR_SYNC,
	MCE_FLAG_RSS_ENA,
	MCE_FLAG_SRIOV_ENA,
	MCE_FLAG_SRIOV_CAPABLE,
	MCE_FLAG_LEGACY_RX,
	MCE_FLAG_MTU_CHANGED,
	MCE_FLAG_VF_RECV_XMIT_BY_SELF,
	MCE_FLAG_VF_TRUE_PROMISC_ENA,
	MCE_FLAG_VF_RQA_TCPSYNC_ENA,
	MCE_FLAG_VF_INSERT_VLAN,
	MCE_FLAG_HW_DIM_ENA,
	MCE_FLAG_SW_DIM_ENA,
	MCE_FLAG_DSCP_ENA,
	MCE_FLAG_DDP_EXTRA_ENA,
	MCE_FLAG_EVB_VEPA_ENA,
	MCE_FLAG_ESWITCH_CAPABLE,
	MCE_FLAG_TUN_OUT_ENA,
	MCE_FLAG_TX_DEBUG_ENA,
	MCE_FLAG_RX_BUFFER_MANUALLY,
	MCE_FLAG_IRQ_MSIX_CAPABLE,
	MCE_FLAG_IRQ_MSIX_ENA,
	MCE_FLAG_IRQ_MSI_CAPABLE,
	MCE_FLAG_IRQ_MSI_ENA,
	MCE_FLAG_IRQ_LEGENCY_CAPABLE,
	MCE_FLAG_IRQ_LEGENCY_ENA,
	/* misc irq flags */
	MCE_FLAG_MISC_IRQ_PCS_LINK_PENDING,
	MCE_FLAG_MISC_IRQ_PTP_PENDING,
	MCE_FLAG_MISC_IRQ_FLR_PENDING,
	MCE_FLAG_MBX_CTRL_ENA,
	MCE_FLAG_MBX_DATA_ENA,
	MCE_FLAG_MRDMA_CHANGED,
	MCE_FLAG_PF_RESET_ENA,
	MCE_PF_FLAGS_NBITS /* must be last */
};

enum mce_vsi_state {
	MCE_VSI_DOWN,
	MCE_VSI_NEEDS_RESTART,
	MCE_VSI_NETDEV_ALLOCD,
	MCE_VSI_NETDEV_REGISTERED,
	MCE_VSI_UMAC_FLTR_CHANGED,
	MCE_VSI_MMAC_FLTR_CHANGED,
	MCE_VSI_PROMISC_CHANGED,
	MCE_CFG_BUSY,
	MCE_VSI_DROP_TX,
	MCE_VSI_STATE_NBITS /* must be last */
};

enum pma_type {
	PHY_TYPE_NONE = 0,
	PHY_TYPE_1G_BASE_KX,
	PHY_TYPE_SGMII,
	PHY_TYPE_10G_BASE_KR,
	PHY_TYPE_25G_BASE_KR,
	PHY_TYPE_40G_BASE_KR4,
	PHY_TYPE_10G_BASE_SR,
	PHY_TYPE_40G_BASE_SR4,
	PHY_TYPE_40G_BASE_CR4,
	PHY_TYPE_40G_BASE_LR4,
	PHY_TYPE_10G_BASE_LR,
	PHY_TYPE_10G_BASE_ER,
	PHY_TYPE_10G_TP
};

struct mce_vsi;
struct mce_q_vector;

struct mce_vsi_stats {
	struct mce_ring_stats **tx_ring_stats; /* Tx ring stats array */
	struct mce_ring_stats **rx_ring_stats; /* Rx ring stats array */
};

struct mce_res_tracker {
	u16 num_entries;
	u16 end;
	u16 list[];
};

enum mce_dvlan_type {
	MCE_VLAN_TYPE_8100 = 0,
	MCE_VLAN_TYPE_88a8,
};

struct mce_vlan_hdr {
	u16 vid;
	enum mce_dvlan_type type;
} __attribute__((packed));

struct mce_dvlan_ctrl {
	int en;
	struct mce_vlan_hdr outer_hdr;
	struct mce_vlan_hdr inner_hdr;
	int cnt;
} __attribute__((packed));

enum mce_fc_mode {
	MCE_FC_NONE = 0,
	MCE_FC_FULL,
	MCE_FC_RX_PAUSE,
	MCE_FC_TX_PAUSE,
};

enum mce_pause_state { // autoneg state
	MCE_PAUSE_UN = 0,
	MCE_PAUSE_EN = 1,
};

struct mce_flow_control {
	enum mce_fc_mode current_mode; /* FC mode in effect */
	enum mce_fc_mode req_mode; /* FC mode requested by caller */
	u32 auto_pause;
};

#ifdef HAVE_DEVLINK_HEALTH
enum mce_mdd_src {
	MCE_MDD_SRC_NONE = 0,
	MCE_MDD_SRC_TX_PQM,
	MCE_MDD_SRC_TX_TCLAN,
	MCE_MDD_SRC_TX_TDPU,
	MCE_MDD_SRC_RX
};

struct mce_mdd_event {
	struct list_head list;
	enum mce_mdd_src src;
	u8 pf_num;
	u16 vf_num;
	u8 event;
	u16 queue;
};

struct mce_mdd_reporter {
	struct devlink_health_reporter *reporter;
	u16 count;
	struct list_head event_list;
};
#endif /* HAVE_DEVLINK_HEALTH */

/* CEE or IEEE 802.1Qaz ETS Configuration data */
struct mce_ets_cfg {
	u8 willing;
	u8 ets_cap;
	u8 curtcs;
	u8 prio_table[MCE_MAX_PRIORITY];
	u8 tcbwtable[MCE_MAX_PRIORITY];
	u8 tsatable[MCE_MAX_PRIORITY];
	DECLARE_BITMAP(etc_state, MCE_MAX_PRIORITY); //该tc是否被使用
};

/* CEE or IEEE 802.1Qaz PFC Configuration data */
struct mce_pfc_cfg {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcena;
	u8 enacnt;
	int fifo_depth[MCE_MAX_PRIORITY];
	int fifo_head[MCE_MAX_PRIORITY];
	int fifo_tail[MCE_MAX_PRIORITY];
	u8 tx_pri2buf[MCE_MAX_PRIORITY];
	u8 rx_pri2buf[MCE_MAX_PRIORITY];
};

struct mce_pfc_cfg_v1 {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcena;
	u8 enacnt;
};

struct mce_tc_cfg {
	u32 min_rate[MCE_MAX_QGS]; //最小带宽保证，单位Mb
	u32 max_rate[MCE_MAX_QGS]; //最大带宽限制，单位Mb
	u8 qg_qs[MCE_MAX_QGS]; //qg[i]中队列数量，最多4个
	u8 tc_prios_bit[8]; //该tc中有哪些prio 是个位图；
	u8 tc_prios_cnt[8]; //该tc中优先级的数量
	u8 prio_tc[8]; //优先级[i]对应的tc
	u8 etc_tc[8]; //ets使用的第i个tc映射到实际使用的tc
	u8 tc_qgs[8]; //tc[i]中QG的数量
	u8 tc_bw[8]; //tc[i]的百分比
	u8 tc_cnt;
	u8 qg_cnt;


	u8 ntc_cnt;
	u8 prio_ntc[8]; //优先级[i]对应的netdev中的tc
	u16 ntc_txq_base[8]; //netdev中的tc i 使用的第一个队列号
	u16 ntc_txq_cunt[8]; //netdev中的tc i 使用的队列数量
	u16 pfc_txq_base[8][8]; // tc x prio i tx queue base
	u16 pfc_txq_count[8][8]; // tc x prio i tx queue count
	u16 pfc_txq_base_temp[8]; // prio i tx queue base
	u16 pfc_txq_count_temp[8]; // prio i tx queue count
	int qg_base_off;
};

enum mce_dcb_flags {
	MCE_DCB_EN = 0,
	MCE_ETS_EN,
	MCE_PFC_EN,
	MCE_DSCP_EN,
	MCE_MQPRIO_CHANNEL,
	MCE_DCB_FLAG_NBITS
};

enum mce_prio_mode {
	MCE_DSCP_MODE,
	MCE_PCP_MODE
};

struct mce_dcb {
	struct mutex dcb_mutex;
	struct mce_pf *back;
	/* when DSCP mapping defined by user set its bit to 1 */
	DECLARE_BITMAP(dscp_mapped, MCE_MAX_DSCP);
	/* array holding DSCP -> priority for DSCP L3 QoS mode */
	u8 dscp_map[MCE_MAX_DSCP];
	DECLARE_BITMAP(flags, MCE_DCB_FLAG_NBITS);

	u16 dcbx_cap;
	struct mce_tc_cfg cur_tccfg;
	struct mce_tc_cfg new_tccfg;
	struct mce_ets_cfg cur_etscfg;
	struct mce_ets_cfg new_etscfg;
	struct mce_pfc_cfg cur_pfccfg;
	struct mce_pfc_cfg new_pfccfg;
	struct ieee_pfc pfc_os;
	struct ieee_ets ets_os;
};

/* ring debug infomation */
struct mce_d_ringinfo {
	u16 txring_start;
	u16 txring_end;
	u16 rxring_start;
	u16 rxring_end;
	bool txring_vaild;
	bool rxring_vaild;
} __attribute__((packed));

/* desc debug infomation */
struct mce_d_descinfo {
	u16 txring_idx;
	u16 txdesc_idx;
	u16 rxring_idx;
	u16 rxdesc_idx;
} __attribute__((packed));

/* te queue debug infomation */
struct mce_d_tx_queue {
	u16 s_id;
	u16 e_id;
	bool en;
	bool permit;
	u16 r_id;
} __attribute__((packed));

struct mce_priv_header {
	int en;
#define MCE_PRIV_HEADER_LEN 254
#define MCE_PRIV_HEADER_LEN_LINIT (MCE_PRIV_HEADER_LEN + 1)
	u8 priv_header[MCE_PRIV_HEADER_LEN_LINIT];
	u16 len;
};

enum mrdma_status{
	MRDMA_REMOVE,
	MRDMA_INSMOD
};

struct mce_pf {
	struct pci_dev *pdev;
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#ifdef HAVE_DEVLINK_REGIONS
	struct devlink_region *nvm_region;
	struct devlink_region *sram_region;
	struct devlink_region *devcaps_region;
#endif /* HAVE_DEVLINK_REGIONS */
	/* devlink port data */
	struct devlink_port devlink_port;
#ifdef HAVE_DEVLINK_HEALTH
	struct mce_mdd_reporter mdd_reporter;
#endif /* HAVE_DEVLINK_HEALTH */
#endif /* CONFIG_NET_DEVLINK */
	// add for chengjian
	const struct gmac_hwtimestamp *hwts_ops;
	unsigned int default_addend;
	u64 clk_ptp_rate; /*uint is HZ 1MHz＝1 000 000Hz*/
	u8 __iomem *ptp_addr;
	int gmac4;
	u32 sub_second_inc;
	u32 systime_flags;

	u16 max_pf_txqs; /* Total Tx queues PF wide */
	u16 max_pf_rxqs; /* Total Rx queues PF wide */
	u16 num_msix_cnt; /* Total MSIX vectors */
	u16 num_avail_msix; /* remaining MSIX vectors left unclaimed */
	u16 qvec_irq_base; /* 队列使用的中断从第几个开始 */
	u16 mbox_irq_base; /* mbox使用的中断从第几个开始 */
	u16 num_mbox_irqs; /* mbox irqs */
	u16 rdma_irq_base; /* rdma使用的中断从第几个开始 */
	u16 num_rdma_irqs; /* rdma irqs */
	u16 num_max_tc; /* max tc supported */
	u16 num_q_for_tc; /* queue for each tc */

	u16 next_vsi; /* Next free slot in pf->vsi[] - 0-based! */
	u16 num_alloc_vsi;
	struct mce_vsi **vsi; /* VSIs created by the driver */
	u16 eswitch_mode;
	struct mce_vsi_stats **vsi_stats;
	struct mce_dcb *dcb;
	enum mrdma_status m_status;

#ifdef CONFIG_DEBUG_FS
	struct dentry *mce_debugfs_hw;
#endif /* CONFIG_DEBUG_FS */

#ifdef HAVE_TC_SETUP_CLSFLOWER
	/* count of tc_flower filters specific to channel (aka where filter
	 * action is "hw_tc <tc_num>")
	 */
	u16 num_dmac_chnl_fltrs;
	struct hlist_head tc_flower_fltr_list;
#endif /* HAVE_TC_SETUP_CLSFLOWER */

	struct msix_entry *msix_entries;
	struct mce_res_tracker *irq_tracker;

	struct mutex sw_mutex; /* lock for protecting VSI alloc flow */
	struct mutex adev_mutex; /* lock to protect aux device access */

	struct mce_hw_stats stats;
	struct mce_hw_stats prev_stats;
	struct mce_hw hw;

	unsigned long serv_tmr_period;
	unsigned long serv_tmr_prev;
	struct timer_list serv_tmr;
	struct work_struct serv_task;

	char int_name[MCE_INT_NAME_STR_LEN];

	struct iidc_core_dev_info *cdev_infos;

	DECLARE_BITMAP(state, MCE_STATE_NBITS);
	DECLARE_BITMAP(flags, MCE_PF_FLAGS_NBITS);

	u32 msg_enable;

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
#ifdef HAVE_UDP_TUNNEL_NIC_SHARED
	struct udp_tunnel_nic_shared udp_tunnel_shared;
#endif /* HAVE_UDP_TUNNEL_NIC_SHARED */
	struct udp_tunnel_nic_info udp_tunnel_nic;
#endif /* HAVE_UDP_TUNNEL_NIC_INFO */

	struct mce_flow_control fc;

	/* sriov */
	int num_vfs;
	unsigned int max_vfs;
	struct mce_vf vf; /* VF associated with this VSI */
	s32 vf_trust_num;
	s32 default_vport;
	s32 debug_tx;
	s32 tx_drop_en;
	u16 vlan_strip_cnt;
	struct mce_dvlan_ctrl dvlan_ctrl;

	/* add for ptp */
	struct work_struct tx_hwtstamp_work;
	//const struct mce_hwtimestamp *hwts_ops;
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_clock_ops;
	struct sk_buff *ptp_tx_skb;
	struct hwtstamp_config tstamp_config;
	spinlock_t ptp_lock; /* Used to protect the SYSTIME registers. */
	//u64 clk_ptp_rate; /* uint is HZ 1MHz＝1 000 000Hz */
	bool ptp_tx_en;
	bool ptp_rx_en;
	u32 flags2;
#define MCE_FLAG2_PTP_ENABLED ((u32)(1 << 10))
	//u8 __iomem *ptp_addr;
	u32 ptp_config_value;
	//struct net_device *netdev;
	unsigned long tx_hwtstamp_start;
	unsigned long tx_timeout_factor;
	u64 tx_hwtstamp_timeouts;
	u32 ptp_default_int;
	u32 ptp_default_dec;

	struct mce_flow_engine_module *flow_engine;
	enum mce_fdir_mode_type fdir_mode;
	struct mce_d_ringinfo d_ringinfo;
	struct mce_d_descinfo d_descinfo;
#define MCE_SELECT_QUEUE_DEBUG (0)
#if MCE_SELECT_QUEUE_DEBUG
	struct mce_d_tx_queue d_txqueue;
#endif
	struct vf_data_storage pfinfo[2];
	int pcie_irq_mode;
	u32 mac_misc_irq;
	bool mac_misc_irq_retry;
	bool npu_capable;
	bool npu_en;
	/* ring mbx numbers */
	int mbx_ring_id;
	bool tun_inner;
	struct mce_priv_header priv_h;
	bool is_checksumed;
};

struct mce_q_vector {
	char name[MCE_INT_NAME_STR_LEN];
	struct mce_vsi *vsi;
	int v_idx;
	u8 wb_on_itr : 1; /* if true, WB on ITR is enabled */
	u8 num_ring_rx; /* total number of Rx rings in vector */
	u8 num_ring_tx; /* total number of Tx rings in vector */
	int cpu;
	int numa_node;
	u16 total_events;
	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;
	struct mce_hw *rdev;
	struct napi_struct napi;
	struct mce_ring_container rx;
	struct mce_ring_container tx;
};

struct mce_port_info {
	u8 addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];
};

struct mce_vsi {
	u16 alloc_txq; /* Allocated Tx queues */
	u16 alloc_rxq; /* Allocated Rx queues */
	u16 num_txq; /* Used Tx queues */
	u16 num_txq_real; /* tx-queue to statck */
	u16 num_tc_offset;
	u16 num_rxq; /* Used Rx queues */
	u16 req_txq; /* User requested Tx queues */
	u16 req_rxq; /* User requested Rx queues */
	u16 num_tx_desc;
	u16 num_rx_desc;
	u16 num_q_vectors;
	u16 base_vector; /* IRQ base for OS reserved vectors */

	u16 max_frame;
	u16 rx_buf_len;

	u16 valid_prio;

	u16 idx; /* software index in pf->vsi[] */
	enum mce_vsi_type type;

	struct net_device *netdev;
	struct mce_pf *back;
	struct mce_port_info *port_info; /* back pointer to port_info */

	struct mce_ring **rx_rings; /* Rx ring array */
	struct mce_ring **tx_rings; /* Tx ring array */
	struct mce_q_vector **q_vectors; /* q_vector array */
	struct task_struct *mce_poll_thread;
	bool quit_poll_thread;
	irqreturn_t (*irq_handler)(int irq, void *data);

	DECLARE_BITMAP(state, MCE_VSI_STATE_NBITS);
	unsigned int current_netdev_flags;

	u32 tx_restart;
	u32 tx_busy;
	u32 rx_buf_failed;
	u32 rx_page_failed;
	u64 tx_linearize;
	/* VSI stats */
	struct rtnl_link_stats64 net_stats;
	struct rtnl_link_stats64 net_stats_prev;
	struct mce_ofld_stats ofld_stats;

	int link;
	u8 irqs_ready;
	u8 rx_flags;
#define RX_FLAG_VLAN_STRIP BIT(0)
	struct mce_vf *vf; /* VF associated with this VSI */
} ____cacheline_internodealigned_in_smp;

struct mce_netdev_priv {
	struct mce_vsi *vsi;
};

static inline bool mce_is_xdp_ena_vsi(struct mce_vsi *vsi)
{
	return false;
}

/**
 * mce_get_main_vsi - Get the PF VSI
 * @pf: PF instance
 *
 * returns pf->vsi[0], which by definition is the PF VSI
 */
static inline struct mce_vsi *mce_get_main_vsi(struct mce_pf *pf)
{
	return pf->vsi[0];
}

/* Attempt to maximize the headroom available for incoming frames. We use a 2K
 * buffer for MTUs <= 1500 and need 1536/1534 to store the data for the frame.
 * This leaves us with 512 bytes of room.  From that we need to deduct the
 * space needed for the shared info and the padding needed to IP align the
 * frame.
 *
 * Note: For cache line sizes 256 or larger this value is going to end
 *	 up negative.  In these cases we should fall back to the legacy
 *	 receive path.
 */
#if (PAGE_SIZE < 8192)
#define MCE_2K_TOO_SMALL_WITH_PADDING                   \
	((unsigned int)(NET_SKB_PAD + MCE_RXBUF_1536) > \
	 SKB_WITH_OVERHEAD(MCE_RXBUF_2048))

/**
 * mce_compute_pad - compute the padding
 * @rx_buf_len: buffer length
 *
 * Figure out the size of half page based on given buffer length and
 * then subtract the skb_shared_info followed by subtraction of the
 * actual buffer length; this in turn results in the actual space that
 * is left for padding usage
 */
static inline int mce_compute_pad(int rx_buf_len)
{
	int half_page_size;

	half_page_size = ALIGN(rx_buf_len, PAGE_SIZE / 2);
	return SKB_WITH_OVERHEAD(half_page_size) - rx_buf_len;
}

/**
 * mce_skb_pad - determine the padding that we can supply
 *
 * Figure out the right Rx buffer size and based on that calculate the
 * padding
 */
static inline int mce_skb_pad(void)
{
	int rx_buf_len;

	/* If a 2K buffer cannot handle a standard Ethernet frame then
	 * optimize padding for a 3K buffer instead of a 1.5K buffer.
	 *
	 * For a 3K buffer we need to add enough padding to allow for
	 * tailroom due to NET_IP_ALIGN possibly shifting us out of
	 * cache-line alignment.
	 */
	if (MCE_2K_TOO_SMALL_WITH_PADDING)
		rx_buf_len = MCE_RXBUF_3072 + SKB_DATA_ALIGN(NET_IP_ALIGN);
	else
		rx_buf_len = MCE_RXBUF_1536;

	/* if needed make room for NET_IP_ALIGN */
	rx_buf_len -= NET_IP_ALIGN;

	return mce_compute_pad(rx_buf_len);
}

#define MCE_SKB_PAD mce_skb_pad()
#else
#define MCE_2K_TOO_SMALL_WITH_PADDING false
#define MCE_SKB_PAD (NET_SKB_PAD + NET_IP_ALIGN)
#endif

/* mce_hw_n20.c */
int mce_get_n20_caps(struct mce_hw *rdev);

/* mce_main.c */
void mce_service_task_schedule(struct mce_pf *pf);

/* mce_ethtool.c */
void mce_set_ethtool_ops(struct net_device *netdev);

/* mce_idc.c */
int mce_plug_aux_devs(struct mce_pf *pf, const char *name);
void mce_unplug_aux_devs(struct mce_pf *pf);
void mce_send_event_to_auxs(struct mce_pf *pf, struct iidc_event *event);

#ifdef MCE_SYSFS
void mce_sysfs_exit(struct mce_pf *pf);
int mce_sysfs_init(struct mce_pf *pf);
#endif /* IXGBE_SYSFS */

#ifdef CONFIG_DEBUG_FS
void mce_debugfs_pf_init(struct mce_pf *pf);
void mce_debugfs_pf_exit(struct mce_pf *pf);
void mce_debugfs_init(void);
void mce_debugfs_exit(void);
#else
static inline void mce_debugfs_pf_init(struct mce_pf *pf)
{
}
static inline void mce_debugfs_pf_exit(struct mce_pf *pf)
{
}
static inline void mce_debugfs_init(void)
{
}
static inline void mce_debugfs_exit(void)
{
}
#endif /* CONFIG_DEBUG_FS */
#ifdef MCE_DEBUG_VF
void mce_clean_mailboxq_subtask(struct mce_pf *pf);
#endif
#endif /* _MCE_H_ */
