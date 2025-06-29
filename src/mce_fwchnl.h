/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2024 Mucse Corporation */

#ifndef __MCE_FWCHNL_H__
#define __MCE_FWCHNL_H__
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include "mce_type.h"

#ifndef _PACKED_ALIGN4
#define _PACKED_ALIGN4 __attribute__((packed, aligned(4)))
#endif

enum GENERIC_CMD {
	/* generat */
	GET_VERSION = 0x0001,
	READ_REG = 0xFF03,
	WRITE_REG = 0xFF04,
	MODIFY_REG = 0xFF07,
	/* virtualization */
	IFUP_DOWN = 0x0800,
	SEND_TO_PF = 0x0801,
	SEND_TO_VF = 0x0802,
	DRIVER_INSMOD = 0x0803,
	SYSTEM_SUSPUSE = 0x0804,
	FORCE_LINK_ON_CLOSE = 0x0805,
	/* link configuration admin commands */
	GET_PHY_ABALITY = 0x0601,
	GET_MAC_ADDRESS = 0x0602,
	RESET_PHY = 0x0603,
	LED_SET = 0x0604,
	GET_LINK_STATUS = 0x0607,
	LINK_STATUS_EVENT = 0x0608,
	SET_LANE_FUN = 0x0609,
	GET_LANE_STATUS = 0x0610,
	SFP_SPEED_CHANGED_EVENT = 0x0611,
	SET_EVENT_MASK = 0x0613,
	SET_LOOPBACK_MODE = 0x0618,
	SET_PHY_REG = 0x0628,
	GET_PHY_REG = 0x0629,
	PHY_LINK_SET = 0x0630,
	GET_PHY_STATISTICS = 0x0631,
	PHY_PAUSE_SET = 0x0632,
	/*sfp-module*/
	SFP_MODULE_READ = 0x0900,
	SFP_MODULE_WRITE = 0x0901,
	/* fw update */
	FW_UPDATE = 0x0700,
	FW_MAINTAIN = 0x0701,
	WOL_EN = 0x0910,
	GET_DUMP = 0x0a00,
	SET_DUMP = 0x0a10,
	GET_TEMP = 0x0a11,
	SET_WOL = 0x0a12,
	LLDP_TX_CTL = 0x0a13,
	SET_DDR_CSL = 0xFF11,
};

enum link_event_mask {
	EVT_LINK_UP = 1,
	EVT_NO_MEDIA = 2,
	EVT_LINK_FAULT = 3,
	EVT_PHY_TEMP_ALARM = 4,
	EVT_EXCESSIVE_ERRORS = 5,
	EVT_SIGNAL_DETECT = 6,
	EVT_AUTO_NEGOTIATION_DONE = 7,
	EVT_MODULE_QUALIFICATION_FAILED = 8,
	EVT_PORT_TX_SUSPEND = 9,
};

#define PHY_C45 (BIT(30))
#define PHY_MMD(i) (i << 16)
#define PHY_MMD_PMAPMD PHY_MMD(1)
#define PHY_MMD_AN PHY_MMD(7)
#define PHY_MMD_VEND2 PHY_MMD(31)
#define PHY_826x_MDIX (PHY_C45 | PHY_MMD_VEND2 | 0xa430)
#define PHY_826x_SPEED (PHY_C45 | PHY_MMD_PMAPMD | 0)
#define PHY_826x_DUPLEX (PHY_C45 | PHY_MMD_VEND2 | 0xa44)
#define PHY_826x_AN (PHY_C45 | PHY_MMD_AN | 0)
#define PHY_826x_ADV (PHY_C45 | PHY_MMD_AN | 16)
#define PHY_826x_GBASE_ADV (PHY_C45 | PHY_MMD_AN | 0x20)
#define PHY_826x_GBASE_ADV_2 (PHY_C45 | PHY_MMD_VEND2 | 0xa412)
struct phy_abilities {
	unsigned char dma_qs;
	unsigned char lane_mask;
	int speed;
	short phy_type;
	short nic_mode;
	short pfnum;
	unsigned int fw_version;
	unsigned int axi_mhz;
	union {
		unsigned char port_id[4];
		unsigned int port_ids;
	};
	unsigned int bd_uid;
	int phy_id;
	int wol_status;

	union {
		unsigned int ext_ablity;
		struct {
			unsigned int valid : 1; /* 0 */
			unsigned int wol_en : 1; /* 1 */
			unsigned int pci_preset_runtime_en : 1; /* 2 */
			unsigned int smbus_en : 1; /* 3 */
			unsigned int ncsi_en : 1; /* 4 */
			unsigned int rpu_en : 1; /* 5 */
			unsigned int v2 : 1; /* 6 */
			unsigned int pxe_en : 1; /* 7 */
			unsigned int mctp_en : 1; /* 8 */
			unsigned int yt8614 : 1; /* 9 */
			unsigned int pci_ext_reset : 1; /* 10 */
			unsigned int rpu_availble : 1; /* 11 */
			unsigned int fw_lldp_ablity : 1; /* 12 */
			unsigned int lldp_enabled : 1; /* 13 */
			unsigned int only_1g : 1; /* 14 */
			unsigned int force_down_en : 4; /* 15-18 */
			unsigned int force_link_supported : 1; /* 19 */
			unsigned int ports_is_sgmii_valid : 1; /* [20] */
			unsigned int lane0_is_sgmii : 1; /* [21] */
			unsigned int lane1_is_sgmii : 1; /* [22] */
			unsigned int lane2_is_sgmii : 1; /* [23] */
			unsigned int lane3_is_sgmii : 1; /* [24] */
		} e;
	};

} _PACKED_ALIGN4;

enum LOOPBACK_LEVEL {
	LOOPBACK_DISABLE = 0,
	LOOPBACK_MAC = 1,
	LOOPBACK_PCS = 5,
	LOOPBACK_EXTERNAL = 6,
};
enum LOOPBACK_TYPE {
	/* Tx->Rx */
	LOOPBACK_TYPE_LOCAL = 0x0,
};

enum LOOPBACK_FORCE_SPEED {
	LOOPBACK_FORCE_SPEED_NONE = 0x0,
	LOOPBACK_FORCE_SPEED_1GBS = 0x1,
	LOOPBACK_FORCE_SPEED_10GBS = 0x2,
	LOOPBACK_FORCE_SPEED_40_25GBS = 0x3,
};

enum PHY_INTERFACE {
	PHY_INTERNAL_PHY = 0,
	PHY_EXTERNAL_PHY_MDIO = 1,
};

/* Table 3-54.  Get link status response (opcode: 0x0607) */
struct link_stat_data {
	char phy_type;
	unsigned char speed;
#define LNK_STAT_SPEED_UNKNOWN 0
#define LNK_STAT_SPEED_10 1
#define LNK_STAT_SPEED_100 2
#define LNK_STAT_SPEED_1000 3
#define LNK_STAT_SPEED_10000 4
#define LNK_STAT_SPEED_25000 5
#define LNK_STAT_SPEED_40000 6
	/* 2 */
	char link_stat : 1;
#define LINK_UP 1
#define LINK_DOWN 0
	char link_fault : 4;
#define LINK_LINK_FAULT BIT(0)
#define LINK_TX_FAULT BIT(1)
#define LINK_RX_FAULT BIT(2)
#define LINK_REMOTE_FAULT BIT(3)
	char extern_link_stat : 1;
	char media_available : 1;
	char rev1 : 1;
	/* 3:ignore */
	char an_completed : 1;
	char lp_an_ablity : 1;
	char parallel_detection_fault : 1;
	char fec_enabled : 1;
	char low_power_state : 1;
	char link_pause_status : 2;
	char qualified_odule : 1;
	/* 4 */
	char phy_temp_alarm : 1;
	char excessive_link_errors : 1;
	char port_tx_suspended : 2;
	char force_40G_enabled : 1;
	char external_25G_phy_err_code : 3;
#define EXTERNAL_25G_PHY_NOT_PRESENT 1
#define EXTERNAL_25G_PHY_NVM_CRC_ERR 2
#define EXTERNAL_25G_PHY_MDIO_ACCESS_FAILED 6
#define EXTERNAL_25G_PHY_INIT_SUCCED 7
	/* 5 */
	char loopback_enabled_status : 4;
#define LOOPBACK_DISABLE 0x0
#define LOOPBACK_MAC 0x1
#define LOOPBACK_SERDES 0x2
#define LOOPBACK_PHY_INTERNAL 0x3
#define LOOPBACK_PHY_EXTERNAL 0x4
	char loopback_type_status : 1;
#define LOCAL_LOOPBACK 0 /* tx->rx */
#define FAR_END_LOOPBACK 0 /* rx->Tx */
	char rev3 : 1;
	char external_dev_power_ability : 2;
	/* 6-7 */
	short max_frame_sz;
	/* 8 */
	char _25gb_kr_fec_enabled : 1;
	char _25gb_rs_fec_enabled : 1;
	char crc_enabled : 1;
	char rev4 : 5;
	/* 9 */
	int link_type; /* same as Phy type */
	char link_type_ext;
} _PACKED_ALIGN4;

struct port_stat {
	u8 phyid;
	u8 duplex : 1;
	u8 autoneg : 1;
	u8 fec : 1;
	u8 rev : 1;
	u8 link_traing : 1;
	u8 is_sgmii : 1;
	u8 lldp_status : 1;
	u32 speed;
} __attribute__((packed));

struct lane_stat_data {
	u8 nr_lane;
	u8 pci_gen : 4;
	u8 pci_lanes : 4;
	u8 pma_type;
	u8 phy_type;
	u16 linkup : 1;
	u16 duplex : 1;
	u16 autoneg : 1;
	u16 fec : 1;
	u16 an : 1;
	u16 link_traing : 1;
	u16 media_available : 1;
	u16 is_sgmii : 1; //
	u16 link_fault : 4;
#define LINK_LINK_FAULT BIT(0)
#define LINK_TX_FAULT BIT(1)
#define LINK_RX_FAULT BIT(2)
#define LINK_REMOTE_FAULT BIT(3)
	u16 is_backplane : 1;
	u16 tp_mdx : 2;
	union {
		u8 phy_addr;
		struct {
			u8 mod_abs : 1;
			u8 fault : 1;
			u8 tx_dis : 1;
			u8 los : 1;
		} sfp;
	};
	u8 sfp_connector;
	u32 speed;
	u32 si_main;
	u32 si_pre;
	u32 si_post;
	u32 si_tx_boost;
	u32 supported_link;
	u32 phy_id;
	u32 advertised_link;
} __attribute__((packed));

struct yt_phy_statistics {
	u32 pkg_ib_valid; /* rx crc good and length 64-1518 */
	u32 pkg_ib_os_good; /* rx crc good and length >1518 */
	u32 pkg_ib_us_good; /* rx crc good and length <64 */
	u16 pkg_ib_err; /* rx crc wrong and length 64-1518 */
	u16 pkg_ib_os_bad; /* rx crc wrong and length >1518 */
	u16 pkg_ib_frag; /* rx crc wrong and length <64 */
	u16 pkg_ib_nosfd; /* rx sfd missed */
	u32 pkg_ob_valid; /* tx crc good and length 64-1518 */
	u32 pkg_ob_os_good; /* tx crc good and length >1518 */
	u32 pkg_ob_us_good; /* tx crc good and length <64 */
	u16 pkg_ob_err; /* tx crc wrong and length 64-1518 */
	u16 pkg_ob_os_bad; /* tx crc wrong and length >1518 */
	u16 pkg_ob_frag; /* tx crc wrong and length <64 */
	u16 pkg_ob_nosfd; /* tx sfd missed */
} __attribute__((packed));

struct phy_statistics {
	union {
		struct yt_phy_statistics yt;
	};
} __attribute__((packed));
/* == flags == */
#define FLAGS_DD BIT(0) /* driver clear 0, FW must set 1 */
#define FLAGS_CMP BIT(1) /* driver clear 0, FW mucst set */
#define FLAGS_ERR BIT(2)
/* driver clear 0, FW must set only if it reporting an error */
#define FLAGS_LB BIT(9)
#define FLAGS_RD \
	BIT(10) /* set if additional buffer has command parameters */
#define FLAGS_BUF BIT(12) /* set 1 on indirect command */
#define FLAGS_SI BIT(13) /* not irq when command complete */
#define FLAGS_EI BIT(14) /* interrupt on error */
#define FLAGS_FE BIT(15) /* flush erro */

#ifndef SHM_DATA_MAX_BYTES
#define SHM_DATA_MAX_BYTES (64 - 2 * 4)
#endif

#define MBX_REQ_HDR_LEN 24
#define MBX_REPLYHDR_LEN 16
#define MBX_REQ_MAX_DATA_LEN (SHM_DATA_MAX_BYTES - MBX_REQ_HDR_LEN)
#define MBX_REPLY_MAX_DATA_LEN (SHM_DATA_MAX_BYTES - MBX_REPLYHDR_LEN)

// TODO req is little endian. bigendian should be conserened

struct mbx_fw_cmd_req {
	unsigned short flags; /* 0-1 */
	unsigned short opcode; /* 2-3 enum LINK_ADM_CMD */
	unsigned short datalen; /* 4-5 */
	unsigned short ret_value; /* 6-7 */
	union {
		struct {
			unsigned int cookie_lo; /* 8-11 */
			unsigned int cookie_hi; /* 12-15 */
		};
		void *cookie;
	};
	unsigned int reply_lo; /* 16-19 5dw */
	unsigned int reply_hi; /* 20-23 */
	/*=== data === 7dw [24-64] */
	union {
		char data[0];

		struct {
			unsigned int addr;
			unsigned int bytes;
		} r_reg;

		struct {
			unsigned int addr;
			unsigned int bytes;
			unsigned int data[4];
		} w_reg;

		struct {
			unsigned int lanes;
		} ptp;

		struct {
			int lane;
			int up;
		} ifup;

		struct {
			int nr_lane;
#define LLDP_TX_ALL_LANES 0xFF
			int op;
#define LLDP_TX_SET 0x0
#define LLDP_TX_GET 0x1
			int enable;
		} lldp_tx;

		struct {
			int lane;
			int status;
		} ifinsmod;

		struct {
			int lane;
			int status;
		} ifsuspuse;

		struct {
			int nr_lane;
			int status;
		} ifforce;

		struct {
			int nr_lane;
		} get_lane_st;

		struct {
			int nr_lane;
			int func;
#define LANE_FUN_AN 0
#define LANE_FUN_LINK_TRAING 1
#define LANE_FUN_FEC 2
#define LANE_FUN_SI 3
#define LANE_FUN_SFP_TX_DISABLE 4
#define LANE_FUN_PCI_LANE 5
#define LANE_FUN_PRBS 6
#define LANE_FUN_SPEED_CHANGE 7

			int value0;
			int value1;
			int value2;
			int value3;
		} set_lane_fun;

		struct {
			int flag;
			int nr_lane;
		} set_dump;

		struct {
			int lane;
			int enable;
		} wol;

		struct {
			unsigned int bytes;
			unsigned int nr_lane;
			unsigned int bin_phy_lo;
			unsigned int bin_phy_hi;
		} get_dump;

		struct {
			unsigned int nr_lane;
			int value;
#define LED_IDENTIFY_INACTIVE 0
#define LED_IDENTIFY_ACTIVE 1
#define LED_IDENTIFY_ON 2
#define LED_IDENTIFY_OFF 3
		} led_set;

		struct {
			unsigned int addr;
			unsigned int data;
			unsigned int mask;
		} modify_reg;

		struct {
			unsigned int adv_speed_mask;
			unsigned int autoneg;
			unsigned int speed;
			unsigned int duplex;
			int nr_lane;
			unsigned int tp_mdix_ctrl;
		} phy_link_set;

		struct {
			unsigned int pause_mode;
			int nr_lane;
		} phy_pause_set;

		struct {
			unsigned int nr_lane;
			unsigned int sfp_adr;
			unsigned int reg;
			unsigned int cnt;
		} sfp_read;

		struct {
			unsigned int nr_lane;
			unsigned int sfp_adr;
			unsigned int reg;
			unsigned int val;
		} sfp_write;

		struct {
			unsigned int nr_lane; /* 0-3 */
		} get_linkstat;
		struct {
			unsigned short changed_lanes;
			unsigned short lane_status;
			unsigned int port_st_magic;
#define SPEED_VALID_MAGIC 0xa4a6a8a9
			struct port_stat st[4];
		} link_stat;

		struct {
			unsigned short enable_stat;
			unsigned short event_mask;
		} stat_event_mask;

		struct { /* set loopback */
			unsigned char loopback_level;
			unsigned char loopback_type;
			unsigned char loopback_force_speed;

			char loopback_force_speed_enable : 1;
		} loopback;

		struct {
			int cmd;
			int arg0;
			int req_bytes;
			int reply_bytes;
			int ddr_lo;
			int ddr_hi;
		} maintain;

		struct { /* set phy register */
			char phy_interface;
			union {
				char page_num;
				char external_phy_addr;
			};
			int phy_reg_addr;
			int phy_w_data;
			int reg_addr;
			int w_data;
			/* 1 = ignore page_num, use last QSFP */
			char recall_qsfp_page : 1;
			/* page value */
			/* 0 = use page_num for QSFP */
			char nr_lane;
		} set_phy_reg;

		struct {
			int enable;
			int ddr_phy_hi;
			int ddr_phy_lo;
			int bytes;
		} ddr_csl;

		struct {
		} get_phy_ablity;

		struct {
			int lane_mask;
			int pfvf_num;
		} get_mac_addr;

		struct {
			char phy_interface;
			union {
				char page_num;
				char external_phy_addr;
			};
			int phy_reg_addr;
			char nr_lane;
		} get_phy_reg;

		struct {
			unsigned int nr_lane;
		} phy_statistics;

		struct {
			char paration;
			unsigned int bytes;
			unsigned int bin_phy_lo;
			unsigned int bin_phy_hi;
		} fw_update;
	};
} _PACKED_ALIGN4;

/* firmware -> driver */
struct mbx_fw_cmd_reply {
	unsigned short flags;
	/* fw must set: DD, CMP, Error(if error), copy value */
	/* from command: LB,RD,VFC,BUF,SI,EI,FE */
	unsigned short opcode; /* 2-3: copy from req */
	unsigned short error_code; /* 4-5: 0 if no error */
	unsigned short datalen;
	/* 6-7: */
	union {
		struct {
			unsigned int cookie_lo; /* 8-11: */
			unsigned int cookie_hi; /* 12-15: */
		};
		void *cookie;
	};
	/* ===== data ==== [16-64] */
	union {
		char data[0];

		struct version {
			unsigned int major;
			unsigned int sub;
			unsigned int modify;
		} version;

		struct {
			unsigned int value[4];
		} r_reg;

		struct {
			unsigned int new_value;
		} modify_reg;

		struct get_temp {
			int temp;
			int volatage;
		} get_temp;

		struct lldp_stat {
			int enable_stat;
		} lldp;

		struct {
#define MBX_SFP_READ_MAX_CNT 32
			char value[MBX_SFP_READ_MAX_CNT];
		} sfp_read;

		struct mac_addr {
			int lanes;
			struct _addr {
				/* for macaddr:01:02:03:04:05:06
				 *  mac-hi=0x01020304 mac-lo=0x05060000
				 */
				unsigned char mac[8];
			} addrs[4];
			u32 pcode;
		} mac_addr;

		struct get_dump_reply {
			int flags;
			int version;
			int bytes;
			int data[4];
		} get_dump;

		struct lane_stat_data lanestat;
		struct link_stat_data linkstat;
		struct phy_abilities phy_abilities;
		struct phy_statistics phy_statistics;
	};
} _PACKED_ALIGN4;

static inline void build_lldp_ctrl_set(struct mbx_fw_cmd_req *req,
				       int nr_lane, int enable)
{
	req->flags = 0;
	req->opcode = LLDP_TX_CTL;
	req->datalen = sizeof(req->lldp_tx);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->lldp_tx.op = LLDP_TX_SET;
	req->lldp_tx.nr_lane = nr_lane;
	req->lldp_tx.enable = enable;
}

static inline void build_lldp_ctrl_get(struct mbx_fw_cmd_req *req,
				       int nr_lane, void *cookie)
{
	req->flags = 0;
	req->opcode = LLDP_TX_CTL;
	req->datalen = sizeof(req->lldp_tx);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->lldp_tx.op = LLDP_TX_GET;
	req->lldp_tx.nr_lane = nr_lane;
}

static inline void build_maintain_req(struct mbx_fw_cmd_req *req,
				      void *cookie, int cmd, int arg0,
				      int req_bytes, int reply_bytes,
				      u32 dma_phy_lo, u32 dma_phy_hi)
{
	req->flags = 0;
	req->opcode = FW_MAINTAIN;
	req->datalen = sizeof(req->maintain);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->maintain.cmd = cmd;
	req->maintain.arg0 = arg0;
	req->maintain.req_bytes = req_bytes;
	req->maintain.reply_bytes = reply_bytes;
	req->maintain.ddr_lo = dma_phy_lo;
	req->maintain.ddr_hi = dma_phy_hi;
}

static inline void build_fw_update_req(struct mbx_fw_cmd_req *req,
				       void *cookie, int partition,
				       u32 fw_bin_phy_lo,
				       u32 fw_bin_phy_hi, int fw_bytes)
{
	req->flags = 0;
	req->opcode = FW_UPDATE;
	req->datalen = sizeof(req->fw_update);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->fw_update.paration = partition;
	req->fw_update.bytes = fw_bytes;
	req->fw_update.bin_phy_lo = fw_bin_phy_lo;
	req->fw_update.bin_phy_hi = fw_bin_phy_hi;
}

static inline void build_reset_phy_req(struct mbx_fw_cmd_req *req,
				       void *cookie)
{
	req->flags = 0;
	req->opcode = RESET_PHY;
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->cookie = cookie;
}

static inline void build_phy_abalities_req(struct mbx_fw_cmd_req *req,
					   void *cookie)
{
	req->flags = 0;
	req->opcode = GET_PHY_ABALITY;
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->cookie = cookie;
}

static inline void build_get_macaddress_req(struct mbx_fw_cmd_req *req,
					    int lane_mask, int pfvfnum,
					    void *cookie)
{
	req->flags = 0;
	req->opcode = GET_MAC_ADDRESS;
	req->datalen = sizeof(req->get_mac_addr);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_mac_addr.lane_mask = lane_mask;
	req->get_mac_addr.pfvf_num = pfvfnum;
}

static inline void build_version_req(struct mbx_fw_cmd_req *req,
				     void *cookie)
{
	req->flags = 0;
	req->opcode = GET_VERSION;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->datalen = 0;
	req->cookie = cookie;
}

/* 7.10.11.8 Read egister admin command */
static inline void build_readreg_req(struct mbx_fw_cmd_req *req,
				     int reg_addr, void *cookie)
{
	req->flags = 0;
	req->opcode = READ_REG;
	req->datalen = sizeof(req->r_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->r_reg.addr = reg_addr & ~(3);
	req->r_reg.bytes = 4;
}

static inline void mbx_fw_req_set_reply(struct mbx_fw_cmd_req *req,
					dma_addr_t reply)
{
	u64 address = reply;

	req->reply_hi = (address >> 32);
	req->reply_lo = (address) & 0xffffffff;
}

/* 7.10.11.9 Write egister admin command */
static inline void build_writereg_req(struct mbx_fw_cmd_req *req,
				      void *cookie, int reg_addr,
				      int bytes, int value[4])
{
	int i;

	req->flags = 0;
	req->opcode = WRITE_REG;
	req->datalen = sizeof(req->w_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->w_reg.addr = reg_addr & ~3;
	req->w_reg.bytes = bytes;
	for (i = 0; i < bytes / 4; i++)
		req->w_reg.data[i] = value[i];
}

/* 7.10.11.10 modify egister admin command */
static inline void build_modifyreg_req(struct mbx_fw_cmd_req *req,
				       void *cookie, int reg_addr,
				       int value, unsigned int mask)
{
	req->flags = 0;
	req->opcode = MODIFY_REG;
	req->datalen = sizeof(req->modify_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->modify_reg.addr = reg_addr;
	req->modify_reg.data = value;
	req->modify_reg.mask = mask;
}

static inline void build_get_lane_status_req(struct mbx_fw_cmd_req *req,
					     int nr_lane, void *cookie)
{
	req->flags = 0;
	req->opcode = GET_LANE_STATUS;
	req->datalen = sizeof(req->get_lane_st);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_lane_st.nr_lane = nr_lane;
}

static inline void build_get_link_status_req(struct mbx_fw_cmd_req *req,
					     int nr_lane, void *cookie)
{
	req->flags = 0;
	req->opcode = GET_LINK_STATUS;
	req->datalen = sizeof(req->get_linkstat);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_linkstat.nr_lane = nr_lane;
}

static inline void build_get_temp(struct mbx_fw_cmd_req *req, void *cookie)
{
	req->flags = 0;
	req->opcode = GET_TEMP;
	req->datalen = 0;
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
}
static inline void build_get_dump_req(struct mbx_fw_cmd_req *req,
				      void *cookie, int nr_lane,
				      u32 fw_bin_phy_lo, u32 fw_bin_phy_hi,
				      int bytes)
{
	req->flags = 0;
	req->opcode = GET_DUMP;
	req->datalen = sizeof(req->get_dump);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_dump.bytes = bytes;
	req->get_dump.nr_lane = nr_lane;
	req->get_dump.bin_phy_lo = fw_bin_phy_lo;
	req->get_dump.bin_phy_hi = fw_bin_phy_hi;
}

static inline void build_set_dump(struct mbx_fw_cmd_req *req, int nr_lane,
				  int flag)
{
	req->flags = 0;
	req->opcode = SET_DUMP;
	req->datalen = sizeof(req->set_dump);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->set_dump.flag = flag;
	req->set_dump.nr_lane = nr_lane;
}

static inline void build_led_set(struct mbx_fw_cmd_req *req,
				 unsigned int nr_lane, int value,
				 void *cookie)
{
	req->flags = 0;
	req->opcode = LED_SET;
	req->datalen = sizeof(req->led_set);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->led_set.nr_lane = nr_lane;
	req->led_set.value = value;
}

static inline void build_set_lane_fun(struct mbx_fw_cmd_req *req,
				      int nr_lane, int fun, int value0,
				      int value1, int value2, int value3)
{
	req->flags = 0;
	req->opcode = SET_LANE_FUN;
	req->datalen = sizeof(req->set_lane_fun);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->set_lane_fun.func = fun;
	req->set_lane_fun.nr_lane = nr_lane;
	req->set_lane_fun.value0 = value0;
	req->set_lane_fun.value1 = value1;
	req->set_lane_fun.value2 = value2;
	req->set_lane_fun.value3 = value3;
}

static inline void build_set_phy_reg(struct mbx_fw_cmd_req *req,
				     void *cookie,
				     enum PHY_INTERFACE phy_inf,
				     char nr_lane, int reg, int w_data,
				     int recall_qsfp_page)
{
	req->flags = 0;
	/* TODO: only test for set vf qs */
	req->opcode = 0xff01;
	req->datalen = sizeof(req->set_phy_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->set_phy_reg.phy_interface = phy_inf;
	req->set_phy_reg.nr_lane = nr_lane;
	req->set_phy_reg.phy_reg_addr = reg;
	req->set_phy_reg.phy_w_data = w_data;

	if (recall_qsfp_page)
		req->set_phy_reg.recall_qsfp_page = 1;
	else
		req->set_phy_reg.recall_qsfp_page = 0;
}

static inline void build_get_phy_reg(struct mbx_fw_cmd_req *req,
				     void *cookie,
				     enum PHY_INTERFACE phy_inf,
				     char nr_lane, int reg)
{
	req->flags = 0;
	req->opcode = GET_PHY_REG;
	req->datalen = sizeof(req->get_phy_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->get_phy_reg.phy_interface = phy_inf;

	req->get_phy_reg.nr_lane = nr_lane;
	req->get_phy_reg.phy_reg_addr = reg;
}

static inline void build_phy_pause_set(struct mbx_fw_cmd_req *req,
				       int pause_mode, int nr_lane)
{
	req->flags = 0;
	req->opcode = PHY_PAUSE_SET;
	req->datalen = sizeof(req->phy_pause_set);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->phy_pause_set.nr_lane = nr_lane;
	req->phy_pause_set.pause_mode = pause_mode;
}

static inline void
build_phy_link_set(struct mbx_fw_cmd_req *req, unsigned int adv,
		   int nr_lane, unsigned int autoneg, unsigned int speed,
		   unsigned int duplex, unsigned int tp_mdix_ctrl)
{
	req->flags = 0;
	req->opcode = PHY_LINK_SET;
	req->datalen = sizeof(req->phy_link_set);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->phy_link_set.nr_lane = nr_lane;
	req->phy_link_set.adv_speed_mask = adv;
	req->phy_link_set.autoneg = autoneg;
	req->phy_link_set.speed = speed;
	req->phy_link_set.duplex = duplex;
	req->phy_link_set.tp_mdix_ctrl = tp_mdix_ctrl;
}

static inline void build_ifup_down(struct mbx_fw_cmd_req *req,
				   unsigned int nr_lane, int up)
{
	req->flags = 0;
	req->opcode = IFUP_DOWN;
	req->datalen = sizeof(req->ifup);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifup.lane = nr_lane;
	req->ifup.up = up;
}

static inline void build_ifinsmod(struct mbx_fw_cmd_req *req,
				  unsigned int nr_lane, int status)
{
	req->flags = 0;
	req->opcode = DRIVER_INSMOD;
	req->datalen = sizeof(req->ifinsmod);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifinsmod.lane = nr_lane;
	req->ifinsmod.status = status;
}

static inline void build_ifsuspuse(struct mbx_fw_cmd_req *req,
				   unsigned int nr_lane, int status)
{
	req->flags = 0;
	req->opcode = SYSTEM_SUSPUSE;
	req->datalen = sizeof(req->ifsuspuse);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifinsmod.lane = nr_lane;
	req->ifinsmod.status = status;
}

static inline void build_ifforce(struct mbx_fw_cmd_req *req,
				 unsigned int nr_lane, int status)
{
	req->flags = 0;
	req->opcode = FORCE_LINK_ON_CLOSE;
	req->datalen = sizeof(req->ifforce);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifforce.nr_lane = nr_lane;
	req->ifforce.status = status;
}

static inline void build_mbx_sfp_read(struct mbx_fw_cmd_req *req,
				      unsigned int nr_lane, int sfp_addr,
				      int reg, int cnt, void *cookie)
{
	req->flags = 0;
	req->opcode = SFP_MODULE_READ;
	req->datalen = sizeof(req->sfp_read);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->sfp_read.nr_lane = nr_lane;
	req->sfp_read.sfp_adr = sfp_addr;
	req->sfp_read.reg = reg;
	;
	req->sfp_read.cnt = cnt;
}

static inline void build_mbx_sfp_write(struct mbx_fw_cmd_req *req,
				       unsigned int nr_lane, int sfp_addr,
				       int reg, int v)
{
	req->flags = 0;
	req->opcode = SFP_MODULE_WRITE;
	req->datalen = sizeof(req->sfp_write);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->sfp_write.nr_lane = nr_lane;
	req->sfp_write.sfp_adr = sfp_addr;
	req->sfp_write.reg = reg;
	req->sfp_write.val = v;
}

static inline void build_mbx_wol_set(struct mbx_fw_cmd_req *req,
				     unsigned int nr_lane, u32 mode)
{
	req->flags = 0;
	req->opcode = SET_WOL;
	req->datalen = sizeof(req->sfp_write);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->wol.lane = nr_lane;
	req->wol.enable = mode;
}

/* enum link_event_mask or */
static inline void build_link_set_event_mask(struct mbx_fw_cmd_req *req,
					     unsigned short event_mask,
					     unsigned short enable,
					     void *cookie)
{
	req->flags = 0;
	req->opcode = SET_EVENT_MASK;
	req->datalen = sizeof(req->stat_event_mask);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->stat_event_mask.event_mask = event_mask;
	req->stat_event_mask.enable_stat = enable;
}

static inline void
build_link_set_loopback_req(struct mbx_fw_cmd_req *req, void *cookie,
			    enum LOOPBACK_LEVEL level,
			    enum LOOPBACK_FORCE_SPEED force_speed)
{
	req->flags = 0;
	req->opcode = SET_LOOPBACK_MODE;
	req->datalen = sizeof(req->loopback);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->loopback.loopback_level = level;
	req->loopback.loopback_type = LOOPBACK_TYPE_LOCAL;
	if (force_speed != LOOPBACK_FORCE_SPEED_NONE) {
		req->loopback.loopback_force_speed = force_speed;
		req->loopback.loopback_force_speed_enable = 1;
	}
}

static inline void build_ddr_csl(struct mbx_fw_cmd_req *req, void *cookie,
				 bool enable, dma_addr_t dma_phy,
				 int bytes)
{
	req->flags = 0;
	req->opcode = SET_DDR_CSL;
	req->datalen = sizeof(req->ddr_csl);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->ddr_csl.enable = enable;

	if (enable) {
		req->ddr_csl.bytes = bytes;
		req->ddr_csl.ddr_phy_hi = (dma_phy >> 32);
		req->ddr_csl.ddr_phy_lo = dma_phy & 0xffffffff;
	} else {
		req->ddr_csl.bytes = 0;
	}
}

/* =========== errcode======= */
enum MBX_ERR {
	MBX_OK = 0,
	MBX_ERR_NO_PERM,
	MBX_ERR_INVAL_OPCODE,
	MBX_ERR_INVALID_PARAM,
	MBX_ERR_INVALID_ADDR,
	MBX_ERR_INVALID_LEN,
	MBX_ERR_NODEV,
	MBX_ERR_IO,
};

struct maintain_req {
	int magic;
#define MAINTAIN_MAGIC 0xa6a7a8a9

	int cmd;
	int arg0;
	int req_data_bytes;
	int reply_bytes;
	char data[0];
} __attribute__((packed));

struct ucfg_mac_sn {
	unsigned char macaddr[64];
	unsigned char sn[32];
	int magic;
#define MAC_SN_MAGIC 0x87654321
	char rev[52];
	unsigned char pn[32];
} __attribute__((packed, aligned(4)));

static inline int pn_sn_dlen(char *v, int v_len)
{
	int i, len = 0;

	for (i = 0; i < v_len; i++) {
		if (isascii(v[i]))
			len++;
		else
			break;
	}
	return len;
}

enum MBX_ID;
int mce_fw_process_mailbox_msg(struct mce_pf *pf, enum MBX_ID mbx_id);
int mce_fw_get_capability(struct mce_hw *hw, struct phy_abilities *ablity);
int mce_mbx_get_lane_stat(struct mce_hw *hw);
int mce_mbx_set_vf_qs(struct mce_hw *hw, u32 val);
int mce_mbx_get_pn_sn(struct mce_hw *hw, char *pn, char *sn);
#endif /* _MCE_FWCHNL_H_ */