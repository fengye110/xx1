/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2024 Mucse Corporation */

#ifndef _MCE_TYPE_H_
#define _MCE_TYPE_H_
#include "mce_vf_lib.h"
#include "mce_fdir_flow.h"
#include "mce_profile_mask.h"

// #define MCE_TX_WB_COAL
// #define MCE_RX_WB_COAL

#define MCE_MAX_RSS_KEY_SIZE (64)
#define MCE_MAX_RSS_INDIR_TABLE_SIZE (512)
#define MCE_TUNNEL_MAX_ENTRIES (8)
#define MCE_MAX_VF_NUM (128)
#define MCE_VM_MAX_VF_MACVLAN_NUMS (1)

struct mce_ring;
struct mce_fdir_fltr;
struct mce_hw;
struct mce_ets_cfg;
struct mce_dcb;

#define MCE_PCIE_IRQ_MODE_NO_MSIX_MAX_VECTORS (1)
/* pcie irq mode. */
enum mce_pcie_irq_mode {
	MCE_PCIE_IRQ_MODE_NONE,
	MCE_PCIE_IRQ_MODE_MSIX,
	MCE_PCIE_IRQ_MODE_MSI,
	MCE_PCIE_IRQ_MODE_LEGENCY,
};

/* Software VSI types. */
enum mce_vsi_type {
	MCE_VSI_PF = 0,
	MCE_VSI_VF = 1,
};

enum mce_sw_fwd_act_type {
	MCE_FWD_TO_VSI = 0,
	MCE_FWD_TO_VSI_LIST, /* Do not use this when adding filter */
	MCE_FWD_TO_Q,
	MCE_FWD_TO_QGRP,
	MCE_DROP_PACKET,
	MCE_LG_ACTION,
	MCE_INVAL_ACT
};

enum mce_evb_mode {
	MCE_EVB_VEB = 0,
	MCE_EVB_VEPA,
};

/* PCI bus types */
enum mce_bus_type {
	mce_bus_unknown = 0,
	mce_bus_pci_express,
	mce_bus_embedded, /* Is device Embedded versus card */
	mce_bus_reserved
};

/* PCI bus speeds */
enum mce_pcie_bus_speed {
	mce_pcie_speed_unknown = 0xff,
	mce_pcie_speed_2_5GT = 0x14,
	mce_pcie_speed_5_0GT = 0x15,
	mce_pcie_speed_8_0GT = 0x16,
	mce_pcie_speed_16_0GT = 0x17
};

/* PCI bus widths */
enum mce_pcie_link_width {
	mce_pcie_lnk_width_resrv = 0x00,
	mce_pcie_lnk_x1 = 0x01,
	mce_pcie_lnk_x2 = 0x02,
	mce_pcie_lnk_x4 = 0x04,
	mce_pcie_lnk_x8 = 0x08,
	mce_pcie_lnk_x12 = 0x0C,
	mce_pcie_lnk_x16 = 0x10,
	mce_pcie_lnk_x32 = 0x20,
	mce_pcie_lnk_width_unknown = 0xff,
};

#define MCE_TC_FLWR_IPSEC_NAT_T_PORT0 (4500)
#define MCE_TC_FLWR_IPSEC_NAT_T_PORT1 (500)

/* rx tunnel offload type */
enum mce_tunnel_type {
	TNL_VXLAN = 0,
	TNL_GENEVE,
	TNL_GRETAP,
	TNL_GTP,
	TNL_GTPC,
	TNL_GTPU,
	TNL_ECPRI,
	TNL_VXLAN_GPE,
	TNL_IPSEC,
	TNL_ALL = 0xFF,
	TNL_LAST = 0xFF, // must be last
};

enum mce_l2_fltr_flag {
	DMAC_FILTER_EN = 0,
	VLAN_FILTER_EN,
	TNL_INNER_EN,
	L2_FLAGS_LAST,
};

struct mce_tunnel_entry {
	u16 default_port;
	u16 port;
	u16 ref_cnt;
	bool in_use;
};

struct mce_tunnel_table {
	struct mce_tunnel_entry tbl[MCE_TUNNEL_MAX_ENTRIES];
	u16 tnl_cnt;
};

struct mce_ofld_stats {
	u64 tx_inserted_vlan;
	u64 rx_stripped_vlan;
	u64 rx_csum_err;
	u64 rx_csum_unnecessary;
	u64 rx_csum_none;
};

struct mce_hw_stats {
	// NIC  part
	u64 pause_tx;
	u64 pause_rx;

	// RDMA part
	u64 tx_vport_rdma_unicast_packets;
	u64 tx_vport_rdma_unicast_bytes;
	u64 rx_vport_rdma_unicast_packets;
	u64 rx_vport_rdma_unicast_bytes;
	u64 np_cnp_sent;
	u64 rn_cnp_handled;
	u64 np_ecn_marked_roce_packets;
	u64 rp_cnp_ignored;
	u64 out_of_sequence;
	u64 packet_seq_err;
	u64 ack_timeout_err;
};

/* Bus parameters */
struct mce_bus_info {
	enum mce_pcie_bus_speed speed;
	enum mce_pcie_link_width width;
	enum mce_bus_type type;
	u16 domain_num;
	u16 device;
	u8 func;
	u8 bus_num;
};

/* Common HW capabilities for SW use */
struct mce_hw_common_caps {
	/* Tx/Rx queues */
	u16 num_rxq; /* Number/Total Rx queues */
	u16 num_txq; /* Number/Total Tx queues */

	/* RSS related capabilities */
	u16 rss_table_size; /* 512 for PFs*/
	u16 rss_key_size;

	/* IRQs */
	u16 max_irq_cnts; /* 硬件能支持的最大中断数量 */
	u16 mbox_irq_base;
	u16 qvec_irq_base;
	u16 num_mbox_irqs;
	u16 rdma_irq_base;
	u16 num_rdma_irqs;

	/* SR-IOV virtualization */
	u16 max_vfs;
	u16 vlan_strip_cnt;
	u16 vf_num_rxq; //开启sriov后vf可用的最大rx队列数量(也是pf可用的最大rx队列数量)
	u16 vf_num_txq; //开启sriov后vf可用的最大tx队列数量(也是pf可用的最大tx队列数量)
	u8 sr_iov; /* SR-IOV enabled */
	u8 max_tc;
	u8 queue_for_tc;
	bool nvm_update_pending_nvm;
	bool nvm_update_pending_orom;
	u8 pcie_irq_capable;
	u32 mac_misc_irq;
	bool mac_misc_irq_retry;
	bool npu_capable;
	bool npu_en;
};

/* Function specific capabilities */
struct mce_hw_func_caps {
	struct mce_hw_common_caps common_cap;
	u32 num_allocd_vfs; /* Number of allocated VFs */
	u32 guar_num_vsi;
	u32 fd_fltr_guar;
};

struct mce_mbx_stats {
	u32 msgs_tx;
	u32 msgs_rx;

	u32 acks;
	u32 reqs;
	u32 rsts;
};

struct mbx_fw_cmd_reply;

typedef void (*cookie_cb)(struct mbx_fw_cmd_reply *reply, void *priv);

enum cookie_stat {
	COOKIE_FREE = 0,
	COOKIE_FREE_WAIT_TIMEOUT,
	COOKIE_ALLOCED,
};

struct mbx_req_cookie {
	u64 alloced_jiffies;
	enum cookie_stat stat;
	cookie_cb cb;
	int timeout_jiffes;
	int errcode;
	wait_queue_head_t wait;
	int done;
	int priv_len;
#define MAX_PRIV_LEN 64
	char priv[MAX_PRIV_LEN];
};

struct mbx_req_cookie_pool {
#define MAX_COOKIES_ITEMS (20 * 400)
	struct mbx_req_cookie cookies[MAX_COOKIES_ITEMS];
	int next_idx;
};

#include "mce_mbx.h"

#define UP_ALIGH(x, y) ((x + y - 1) / y)

#ifndef HAVE_NETIF_SET_TSO_MAX
// maybe reletive with mtu, do it later?
#define MAX_DMA_NEED_FOR_TSO (UP_ALIGH(65536, 1480) * UP_ALIGH(1526, 64))
#else
#define MAX_DMA_NEED_FOR_TSO \
	(UP_ALIGH(55 * 1024, 1480) * UP_ALIGH(1526, 64))
#endif

struct mce_mbx_operations {
	s32 (*init_params)(struct mce_hw *hw);
	s32 (*read)(struct mce_hw *hw, u32 *, u16, enum MBX_ID);
	s32 (*write)(struct mce_hw *hw, u32 *, u16, enum MBX_ID);
	s32 (*read_posted)(struct mce_hw *hw, u32 *, u16, enum MBX_ID);
	s32 (*write_posted)(struct mce_hw *hw, u32 *, u16, enum MBX_ID);
	s32 (*check_for_msg)(struct mce_hw *hw, enum MBX_ID);
	s32 (*check_for_ack)(struct mce_hw *hw, enum MBX_ID);
	//	s32 (*check_for_rst)(struct mce_hw *, enum MBX_ID);
	s32 (*configure)(struct mce_hw *hw, int nr_vec, bool enable);
};

enum mce_mbx_feature {
	MCE_MBX_FEATURE_NO_ZERO,
	MCE_MBX_FEATURE_WRITE_DELAY,

	MCE_MBX_FEATURE_NBITS /* must be last */
};

struct mce_ts_dev_info {
	/* Device specific info */
	u32 tmr_own_map;
	u8 tmr0_owner;
	u8 tmr1_owner;
	u8 tmr0_owned : 1;
	u8 tmr1_owned : 1;
	u8 ena : 1;
	u8 tmr0_ena : 1;
	u8 tmr1_ena : 1;
	u8 ts_ll_read : 1;
	u8 ts_ll_int_read : 1;
};

struct mce_nac_topology {
	u32 mode;
	u8 id;
};

/* Device wide capabilities */
struct mce_hw_dev_caps {
	struct mce_hw_common_caps common_cap;
	u32 num_vfs_exposed; /* Total number of VFs exposed */
	u32 num_vsi_allocd_to_host; /* Excluding EMP VSI */
	u32 num_flow_director_fltr; /* Number of FD filters available */
	struct mce_ts_dev_info ts_dev_info;
	u32 num_funcs;
	struct mce_nac_topology nac_topo;
	/* bitmap of supported sensors */
	u32 supported_sensors;
#define MCE_SENSOR_SUPPORT_E810_INT_TEMP BIT(0)
};

/* Option ROM version information */
struct mce_orom_info {
	u8 major; /* Major version of OROM */
	u8 patch; /* Patch version of OROM */
	u16 build; /* Build version of OROM */
	u32 srev; /* Security revision */
};

/* NVM version information */
struct mce_nvm_info {
	u32 eetrack;
	u32 srev;
	u8 major;
	u8 minor;
};

/* netlist version information */
struct mce_netlist_info {
	u32 major; /* major high/low */
	u32 minor; /* minor high/low */
	u32 type; /* type high/low */
	u32 rev; /* revision high/low */
	u32 hash; /* SHA-1 hash word */
	u16 cust_ver; /* customer version */
};
enum mce_flash_bank {
	MCE_INVALID_FLASH_BANK,
	MCE_1ST_FLASH_BANK,
	MCE_2ND_FLASH_BANK,
};

/* Enumeration of which flash bank is desired to read from, either the active
 * bank or the inactive bank. Used to abstract 1st and 2nd bank notion from
 * code which just wants to read the active or inactive flash bank.
 */
enum mce_bank_select {
	MCE_ACTIVE_FLASH_BANK,
	MCE_INACTIVE_FLASH_BANK,
};

/* information for accessing NVM, OROM, and Netlist flash banks */
struct mce_bank_info {
	u32 nvm_ptr; /* Pointer to 1st NVM bank */
	u32 nvm_size; /* Size of NVM bank */
	u32 orom_ptr; /* Pointer to 1st OROM bank */
	u32 orom_size; /* Size of OROM bank */
	u32 netlist_ptr; /* Pointer to 1st Netlist bank */
	u32 netlist_size; /* Size of Netlist bank */
	enum mce_flash_bank nvm_bank; /* Active NVM bank */
	enum mce_flash_bank orom_bank; /* Active OROM bank */
	enum mce_flash_bank netlist_bank; /* Active Netlist bank */
};

struct mce_flash_info {
	struct mce_orom_info orom; /* Option ROM version info */
	struct mce_nvm_info nvm; /* NVM version information */
	struct mce_netlist_info netlist; /* Netlist version info */
	struct mce_bank_info banks; /* Flash Bank information */
	u16 sr_words; /* Shadow RAM size in words */
	u32 flash_size; /* Size of available flash in bytes */
	u8 blank_nvm_mode; /* is NVM empty (no FW present) */
};

struct mce_mbx_info {
	struct mce_mbx_operations *ops;
	struct mce_mbx_stats stats;
	u32 timeout;
	u32 usec_delay;
	u32 v2p_mailbox;
	u16 size;

	u16 vf_req[MCE_MAX_VF_NUM];
	u16 vf_ack[MCE_MAX_VF_NUM];
	u16 cpu_req;
	u16 cpu_ack;

	struct mutex lock;

	bool other_irq_enabled;
	// add reg define
	int mbx_size;

	int mbx_mem_size;
	DECLARE_BITMAP(mbx_feature, MCE_MBX_FEATURE_NBITS);
	// cm3 <-> pf mbx
	u32 cpu_pf_shm_base;
	u32 pf2cpu_mbox_ctrl;
	u32 cpu2pf_mbox_ctrl;
	u32 cpu2pf_mbox_vec;

	// pf <--> vf mbx
	u32 pf_vf_shm_base;
	u32 pf2vf_mbox_ctrl_base;
	// u32 pf2vf_mbox_vec_base;
	u32 vf2pf_mbox_vec_base;

	u32 cpu_vf_share_ram;
	int share_size;
	struct mbx_req_cookie_pool cookie_pool;
};

#define MCE_MISC_IRQ_CLEAR_ALL (0xffffffff)

enum mce_misc_irq_type {
	MCE_MAC_MISC_IRQ_NONE = 0,
	MCE_MAC_MISC_IRQ_PCS_LINK = MCE_MAC_MISC_IRQ_NONE,
	MCE_MAC_MISC_IRQ_PTP,
	MCE_MAC_MISC_IRQ_FLR,
	MCE_MAC_MISC_IRQ_MAX,
	MCE_MAC_MISC_IRQ_ALL = MCE_MAC_MISC_IRQ_MAX,
};

enum mce_misc_irq_flr {
	MCE_MISC_IRQ_FLR_NONE = 0,
	MCE_MISC_IRQ_FLR_0_31 = MCE_MISC_IRQ_FLR_NONE,
	MCE_MISC_IRQ_FLR_32_63,
	MCE_MISC_IRQ_FLR_64_95,
	MCE_MISC_IRQ_FLR_96_127,
	MCE_MISC_IRQ_FLR_MAX,
};

struct mce_hw_operations {
	int (*update_fltr_macaddr)(struct mce_hw *hw, u8 *mac_addr,
				   u32 index, bool active);
	int (*dump_debug_regs)(struct mce_hw *, char *);
	int (*cfg_txring_bw_lmt)(struct mce_ring *, u32);
	void (*reset_hw)(struct mce_hw *);
	void (*init_hw)(struct mce_hw *);
	void (*enable_proc)(struct mce_hw *);
	void (*enable_proc_old)(struct mce_hw *);
	void (*disable_proc)(struct mce_hw *);
	void (*enable_axi_tx)(struct mce_hw *);
	void (*disable_axi_tx)(struct mce_hw *);
	void (*enable_axi_rx)(struct mce_hw *);
	void (*disable_axi_rx)(struct mce_hw *);
	void (*cfg_vec2tqirq)(struct mce_hw *, u16,
			      u16); //告诉硬件这个txq使用的中断
	void (*cfg_vec2rqirq)(struct mce_hw *, u16,
			      u16); //告诉硬件这个rxq使用的中断
	void (*set_max_pktlen)(struct mce_hw *, u32);
	void (*get_hw_stats)(struct mce_hw *, struct mce_hw_stats *,
			     struct mce_hw_stats *);
	void (*set_rxring_ctx)(struct mce_ring *, struct mce_hw *);
	void (*set_txring_ctx)(struct mce_ring *, struct mce_hw *);
	void (*enable_rxring_irq)(struct mce_ring *);
	void (*enable_txring_irq)(struct mce_ring *);
	void (*disable_rxring_irq)(struct mce_ring *);
	void (*disable_txring_irq)(struct mce_ring *);
	void (*enable_txrxring_irq)(struct mce_ring *);
	void (*disable_txrxring_irq)(struct mce_ring *);
	void (*start_rxring)(struct mce_ring *);
	void (*stop_rxring)(struct mce_ring *);
	void (*start_txring)(struct mce_ring *);
	void (*stop_txring)(struct mce_ring *);
	void (*set_rxring_intr_coal)(struct mce_ring *);
	void (*set_txring_intr_coal)(struct mce_ring *);
	void (*set_rxring_hw_dim)(struct mce_ring *, bool);
	void (*set_txring_hw_dim)(struct mce_ring *, bool);
	void (*set_vlan_filter)(struct mce_hw *, netdev_features_t);
	void (*add_vlan_filter)(struct mce_hw *, u16);
	void (*del_vlan_filter)(struct mce_hw *, u16);
	void (*set_vlan_strip)(struct mce_hw *, netdev_features_t);
	void (*set_rx_csumofld)(struct mce_hw *, netdev_features_t);
	void (*set_rss_hash)(struct mce_hw *, netdev_features_t);
	void (*set_rss_key)(struct mce_hw *);
	void (*set_rss_hash_type)(struct mce_hw *);
	int (*set_rss_table)(struct mce_hw *hw, u16 q_cnt);
	void (*set_ucmc_hash_type_fltr)(struct mce_hw *);
	void (*set_uc_filter)(struct mce_hw *, bool);
	void (*add_uc_filter)(struct mce_hw *, const u8 *);
	void (*del_uc_filter)(struct mce_hw *, const u8 *);
	void (*set_mc_filter)(struct mce_hw *, bool);
	void (*add_mc_filter)(struct mce_hw *, const u8 *);
	void (*del_mc_filter)(struct mce_hw *, const u8 *);
	void (*clr_mc_filter)(struct mce_hw *);
	void (*set_mc_promisc)(struct mce_hw *, bool);
	void (*set_rx_promisc)(struct mce_hw *, bool);
	void (*add_ntuple_filter)(struct mce_hw *, struct mce_fdir_fltr *);
	void (*del_ntuple_filter)(struct mce_hw *, struct mce_fdir_fltr *);
	void (*add_tnl)(struct mce_hw *, enum mce_tunnel_type, u16);
	void (*del_tnl)(struct mce_hw *, enum mce_tunnel_type, u16);
	void (*set_pause)(struct mce_hw *, int mtu);
	void (*set_pause_en_only)(struct mce_hw *);
	void (*enable_tc)(struct mce_hw *, struct mce_dcb *);
	void (*disable_tc)(struct mce_hw *);
	void (*enable_rdma_tc)(struct mce_hw *, struct mce_dcb *);
	void (*disable_rdma_tc)(struct mce_hw *);
	void (*set_tc_bw)(struct mce_hw *, struct mce_dcb *);
	void (*set_tc_bw_rdma)(struct mce_hw *, struct mce_dcb *);
	void (*set_qg_ctrl)(struct mce_hw *, struct mce_dcb *);
	void (*set_qg_rate)(struct mce_hw *, struct mce_dcb *);
	void (*set_q_to_tc)(struct mce_hw *,
			    struct mce_dcb *); //为tx队列绑定tc
	void (*clr_q_to_tc)(struct mce_hw *);
	void (*enable_pfc)(struct mce_hw *, struct mce_dcb *);
	void (*setup_rx_buffer)(struct mce_hw *);
	void (*disable_pfc)(struct mce_hw *);
	void (*set_q_to_pfc)(struct mce_hw *, struct mce_dcb *);
	void (*clr_q_to_pfc)(struct mce_hw *);
	void (*set_dscp)(struct mce_hw *, struct mce_dcb *);
	void (*set_tun_select_inner)(struct mce_hw *hw, bool inner);
	void (*set_ddp_extra_en)(struct mce_hw *hw, bool enable);
	void (*set_evb_mode)(struct mce_hw *hw, enum mce_evb_mode mode);
	void (*set_dma_tso_cnts_en)(struct mce_hw *hw, bool en);
	void (*set_fd_fltr_guar)(struct mce_hw *hw);
	void (*set_irq_legency_en)(struct mce_hw *hw, bool en,
				   u32 tick_timer);
	bool (*get_misc_irq_evt)(struct mce_hw *hw,
				 enum mce_misc_irq_type type);
	int (*set_misc_irq)(struct mce_hw *hw, bool en, int nr_vec);
	int (*get_misc_irq_st)(struct mce_hw *hw,
			       enum mce_misc_irq_type type, u32 *val);
	int (*set_misc_irq_mask)(struct mce_hw *hw,
				 enum mce_misc_irq_type type, bool en);
	int (*clear_misc_irq_evt)(struct mce_hw *hw,
				  enum mce_misc_irq_type type, u32 val);
	int (*set_init_ptp)(struct mce_hw *hw);
	/* npu callback */
	int (*npu_download_firmware)(struct mce_hw *hw);
	void (*update_rdma_status)(struct mce_hw *hw, bool en);

	/* ptp ops */
	void (*ptp_get_systime)(struct mce_hw *, u64 *);
	int (*ptp_init_systime)(struct mce_hw *, u32, u32);
	int (*ptp_adjust_systime)(struct mce_hw *, u32, u32, int);
	int (*ptp_adjfine)(struct mce_hw *, long);
	int (*ptp_set_ts_config)(struct mce_hw *,
				 struct hwtstamp_config *config);
	int (*ptp_tx_state)(struct mce_hw *);
	int (*ptp_tx_stamp)(struct mce_hw *, u64 *, u64 *);

	/* fdir ops */
	int (*fd_update_entry_table)(struct mce_hw *hw, int loc,
				     u32 *meta);
	int (*fd_update_hash_table)(struct mce_hw *hw, u16 loc,
				    u32 fdir_hash);
	int (*fd_update_ex_hash_table)(struct mce_hw *hw, u16 loc,
				       u32 fdir_hash);
	int (*fd_verificate_sign_rule)(struct mce_hw *hw,
				       struct mce_fdir_filter *filter,
				       u16 loc, u32 fdir_hash);
	int (*fd_clear_sign_rule)(struct mce_hw *hw, u32 fdir_hash);
	void (*fd_field_bitmask_setup)(struct mce_hw *hw,
				       struct mce_fdir_field_mask *options,
				       u16 loc);
	void (*fd_profile_field_bitmask_update)(struct mce_hw *hw,
						u16 profile_id,
						u32 options);
	int (*fd_profile_update)(struct mce_hw *hw,
				 struct mce_hw_profile *profile, bool add);
	int (*fd_init_hw)(struct mce_hw *hw,
			  struct mce_fdir_handle *fdir_handle);
	int (*set_txring_trig_intr)(struct mce_ring *tx_ring);
};

struct mce_vf_operations {
	/* hw */
	void (*set_vf_virtual_config)(struct mce_hw *hw, bool enable);
	void (*set_vf_dma_qs)(struct mce_hw *hw, enum mce_vf_dma_qs qs);
	void (*set_vf_emac_post_ctrl)(struct mce_hw *hw,
				      enum mce_vf_veb_vlan_type vlan_type,
				      bool vlan_on,
				      enum mce_vf_post_ctrl post_ctrl,
				      bool ctrl_on);
	void (*set_vf_vlan_strip)(struct mce_hw *hw, int vf_id, bool en);
	int (*set_vf_rss_table)(struct mce_hw *hw, int vf_id, u16 q_cnt);
	void (*set_vf_clear_all_rss_table)(struct mce_hw *hw);
	int (*set_vf_spoofchk_mac)(struct mce_hw *hw, int vfid, bool en,
				   bool setmac);
	int (*set_vf_spoofchk_vlan)(struct mce_hw *hw, int vfid, bool en,
				    enum mce_vf_antivlan_ctrl vlanctrl);
	int (*set_vf_trusted)(struct mce_hw *hw, int vfid, bool on);
	int (*set_vf_default_vport)(struct mce_hw *hw, int vfid);
	int (*set_vf_recv_ximit_by_self)(struct mce_hw *hw, bool on);
	int (*set_vf_trust_vport_en)(struct mce_hw *hw, bool on);
	int (*set_vf_update_vm_macaddr)(struct mce_hw *hw, u8 *mac_addr,
					u32 index, bool active);

	int (*set_vf_update_vm_default_vlan)(struct mce_hw *hw, int index);
	void (*set_vf_set_vlan_promisc)(struct mce_hw *hw, int vfid,
					bool on);
	void (*set_vf_set_vtag_vport_en)(struct mce_hw *hw, int vfid,
					 bool on);
	void (*set_vf_add_vlan_filter)(struct mce_hw *hw, int vfid,
				       int entry);
	void (*set_vf_del_vlan_filter)(struct mce_hw *hw, int vfid,
				       int entry);
	void (*set_vf_clear_vlan_filter)(struct mce_hw *hw);
	void (*set_vf_set_veb_act)(struct mce_hw *hw, int vfid, int entry,
				   bool set,
				   enum mce_flag_type set_bcmc_bitmap);
	void (*set_vf_add_mc_fliter)(struct mce_hw *hw,
				     const u8 *mac_addr);
	void (*set_vf_del_mc_filter)(struct mce_hw *hw,
				     const u8 *mac_addr);
	void (*set_vf_clear_mc_filter)(struct mce_hw *hw, bool only_pf);
	void (*set_vf_true_promisc)(struct mce_hw *hw, int vfid, bool on);
	void (*set_vf_rqa_tcp_sync_en)(struct mce_hw *hw, bool on);
	void (*set_vf_rqa_tcp_sync_remapping)(struct mce_hw *hw, int vfnum,
					      struct mce_tcpsync *tcpsync);
	int (*set_vf_bw_limit_init)(struct mce_pf *pf);
	int (*set_vf_bw_limit_rate)(struct mce_pf *pf, int vf_id,
				    u64 max_tx_rate, u16 ring_cnt);
	void (*set_vf_rebase_ring_base)(struct mce_hw *hw);
};

struct mce_vf_info {
	struct mce_vf_operations *ops;
};

struct mce_mc_info {
	u8 addr[ETH_ALEN];
	bool en;
};

struct mce_vlan_list_entry {
	struct list_head vlan_node;
	int status;
	int vid;
};

struct mce_hw_qos {
	u32 link_speed; //支持的最大带宽，单位Mbit
	u32 interal; //清零间隔，单位ms
	u32 rate; //1s除以清零间隔得到的倍数，在设置qg的最大值和最小值时要除以该rate
	u32 qg_mode;
};

struct mce_dim_cq_moder {
	u16 usec;
	u16 pkts;
};

#define MCE_UC_MC_HASH_BITS_WIDTH 12
enum mce_uc_mc_hash_type {
	/* These fixed values are not allowed to be changed */
	MCE_UC_MC_HASH_TYPE_BIT_11_0_OR_47_36 = 0,
	MCE_UC_MC_HASH_TYPE_BIT_12_1_OR_46_35 = 1,
	MCE_UC_MC_HASH_TYPE_BIT_13_2_OR_45_34 = 2,
	MCE_UC_MC_HASH_TYPE_BIT_14_3_OR_44_33 = 3,
	MCE_UC_MC_HASH_TYPE_MAX,
};

struct mce_uc_mc_hash_ctl {
	enum mce_uc_mc_hash_type type;
	bool uc_s_low;
	bool mc_s_low;
};

#define MCE_HW_PROFILE 5
struct mce_hw {
	struct mce_hw_operations *ops;
	u8 __iomem *npu_bar_base;
	u8 __iomem *eth_bar_base;
	u8 __iomem *rdma_bar_base;
	u8 __iomem *vector_bar_base;
	void *back;

	u16 vendor_id;
	u16 device_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	struct mce_bus_info bus;

	u8 pf_id; /* device profile info */
	u8 revision_id;
	u16 msix_vector_bar;
	u32 vector_offset;

	struct mce_hw_func_caps func_caps; /* function capabilities */

	u8 rss_hfunc;
	u8 rss_key[MCE_MAX_RSS_KEY_SIZE];
	u16 rss_table[MCE_MAX_RSS_INDIR_TABLE_SIZE];
	u32 rss_hash_type; /* match whith FLAG REG N20_RSS_HASH_MRQC */
#define MCE_F_HASH_IPV6_SCTP (1UL << 0)
#define MCE_F_HASH_IPV4_SCTP (1UL << 1)
#define MCE_F_HASH_IPV6_UDP (1UL << 2)
#define MCE_F_HASH_IPV4_UDP (1UL << 3)
#define MCE_F_HASH_IPV6_TCP (1UL << 4)
#define MCE_F_HASH_IPV4_TCP (1UL << 5)
#define MCE_F_HASH_IPV6 (1UL << 6)
#define MCE_F_HASH_IPV4 (1UL << 7)
#define MCE_F_HASH_IPV6_TEID (1UL << 8)
#define MCE_F_HASH_IPV4_TEID (1UL << 9)
#define MCE_F_HASH_IPV6_SPI (1UL << 10)
#define MCE_F_HASH_IPV4_SPI (1UL << 11)
#define MCE_F_HASH_IPV6_FLEX (1UL << 12)
#define MCE_F_HASH_IPV4_FLEX (1UL << 13)
#define MCE_F_HASH_ONLY_FLEX (1UL << 14)
	u32 hw_flags;
#define MCE_F_RSS_TABLE_INITED (1UL << 0)

	struct mce_hw_qos qos;
	u8 dma_qs;
	u32 hw_type;
	int nr_lane;
	u32 fw_version;
	u32 nic_version;
	u32 dma_version;
	int vf_uc_addr_offset;
	int vf_macvlan_addr_offset;
	int vf_bcmc_addr_offset;
#define MCE_MAX_MC_WHITE_LISTS (16)
	DECLARE_BITMAP(avail_mc, MCE_MAX_MC_WHITE_LISTS);
	struct mce_mc_info mc_info[MCE_MAX_MC_WHITE_LISTS];
	bool promisc_no_permit;
	DECLARE_BITMAP(l2_fltr_flags, L2_FLAGS_LAST);

	struct mutex fdir_fltr_lock; /* protect Flow Director */
	struct list_head fdir_list_head;
	struct list_head vlan_list_head;
	int fdir_active_fltr;
	int fdir_etype_active_fltr;
	int fdir_ntuple5_active_fltr;
	/* tunneling info */
	struct mutex tnl_lock;
	struct mce_tunnel_table tnl[TNL_LAST];

	struct device *dev;
	struct pci_dev *pdev;

	struct mce_port_info *port_info;
	struct mce_flash_info flash;

	int cur_link_speed;
	int cur_tc_time_for_rdma;
	/* ptp */
	u64 clk_ptp_rate;
	u32 ptp_default_int;
	u32 max_vfs;
	struct mce_mbx_info mbx;
	struct mce_vf_info vf;
#define MCE_ACL_MAX_TUPLE5_CNT (32)
	DECLARE_BITMAP(avail_tuple5, MCE_ACL_MAX_TUPLE5_CNT);
	int ring_base_addr;
	int ring_max_cnt;
	bool pcie_isolate_on;
	bool rx_wrr_en;
	int vmark[8];
	struct mce_uc_mc_hash_ctl uc_mc_hash_ctl;
};
int mce_vf_set_veb_misc_rule(struct mce_hw *hw, int vfid,
			     enum veb_policy_type ptype);
#endif /*_MCE_TYPE_H_*/
