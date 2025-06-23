/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2024 Mucse Corporation */

#ifndef _MCE_MBX_H_
#define _MCE_MBX_H_
#include <linux/wait.h>
#include <linux/sem.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include "mce.h"
#include "mce_fwchnl.h"

#define MCE_DEBUG_MBX_FPGA

#define MCE_MBX_DEBUG (0)
#if MCE_MBX_DEBUG
#define mce_mbx_dbg(hw, fmt, args...) \
	dev_info(mce_hw_to_dev(hw), "%s:" fmt, __func__, ##args)
#else
#define mce_mbx_dbg(hw, fmt, args...) \
	do {                            \
	} while (0)
#endif
/* 14 32 bit words - 56 bytes for data */
#define MCE_VFMAILBOX_SIZE (14)
#define MCE_FW_MAILBOX_SIZE MCE_VFMAILBOX_SIZE
#define MCE_ERR_MBX (-100)

#define MBX_RET_SUCCESS (0)
#define MBX_RET_ERR (-1)

/* Messages below or'd with this are the ACK */
#define MCE_VT_MSGTYPE_ACK (0x80000000)
/* Messages below or'd with this are the NACK */
#define MCE_VT_MSGTYPE_NACK (0x40000000)
/* Indicates that VF is still clear to send requests */
#define MCE_VT_MSGTYPE_CTS 0x20000000

#define MCE_VT_MSGINFO_SHIFT (14)
/* bits 23:16 are used for exra info for certain messages */
#define MCE_VT_MSGINFO_MASK (0x7F << MCE_VT_MSGINFO_SHIFT)
/* VLAN pool filtering masks */
#define MCE_VLVF_VIEN (0x80000000)
#define MCE_VLVF_ENTRIES (64)
#define MCE_VLVF_VLANID_MASK (0x00000FFF)

/* mailbox msg index */
#define MCE_VF_LINK_STATUS_WORD (8)

enum PF_STATUS {
	PF_SET_VLAN_STATUS,
	PF_SET_RESET_STATUS,
};
#define MCE_VNUM_OFFSET (21)
#define MCE_VF_MASK (0x7f << 21)
#define MCE_MAIL_CMD_MASK (0x3fff)
/* mailbox vf msg cmd */
#define __VF_CMD_OFFSET (0x0000)
#define MCE_VF_RESET (__VF_CMD_OFFSET + 0x1)
/* length of permanent address message returned from PF */
#define MCE_VF_RESET_MSG_LEN (11)
#define F_VF_RESET_RING_MAX_CNT (3)
#define F_VF_RESETDMA_VERSION (4)
#define F_VF_RESET_VLAN (5)
#define MCE_VF_SET_MBX_INTR_EN (__VF_CMD_OFFSET + 0x2)
#define MCE_VF_REMOVED (__VF_CMD_OFFSET + 0x3)
#define MCE_VF_SET_VLAN (__VF_CMD_OFFSET + 0x4)
#define MCE_VF_SET_VLAN_STRIP (__VF_CMD_OFFSET + 0x5)
#define MCE_VF_SET_MAC_ADDR (__VF_CMD_OFFSET + 0x6)
#define MCE_VF_SET_PROMISC_MODE (__VF_CMD_OFFSET + 0x7)
#define MCE_VF_SET_MACVLAN_ADDR (__VF_CMD_OFFSET + 0x8)
#define MCE_VF_DEL_MACVLAN_ADDR (__VF_CMD_OFFSET + 0x9)

/* mailbox pf msg cmd */
#define __PF_CMD_OFFSET (0x10000)
#define MCE_PF_SET_VLAN (__PF_CMD_OFFSET + 0x1)
#define MCE_PF_SET_RESET (__PF_CMD_OFFSET + 0x2)

enum MBX_ID {
	MBX_VF0 = 0,
	MBX_VF1,
	MBX_VF2,
	MBX_VF3,
	MBX_VF4,
	MBX_VF5,
	MBX_VF6,
	MBX_VF7,
	MBX_VF8,
	MBX_VF9,
	MBX_VF10,
	MBX_VF11,
	MBX_VF12,
	MBX_VF13,
	MBX_VF14,
	MBX_VF15,
	MBX_VF16,
	MBX_VF17,
	MBX_VF18,
	MBX_VF19,
	MBX_VF20,
	MBX_VF21,
	MBX_VF22,
	MBX_VF23,
	MBX_VF24,
	MBX_VF25,
	MBX_VF26,
	MBX_VF27,
	MBX_VF28,
	MBX_VF29,
	MBX_VF30,
	MBX_VF31,
	MBX_VF32,
	MBX_VF33,
	MBX_VF34,
	MBX_VF35,
	MBX_VF36,
	MBX_VF37,
	MBX_VF38,
	MBX_VF39,
	MBX_VF40,
	MBX_VF41,
	MBX_VF42,
	MBX_VF43,
	MBX_VF44,
	MBX_VF45,
	MBX_VF46,
	MBX_VF47,
	MBX_VF48,
	MBX_VF49,
	MBX_VF50,
	MBX_VF51,
	MBX_VF52,
	MBX_VF53,
	MBX_VF54,
	MBX_VF55,
	MBX_VF56,
	MBX_VF57,
	MBX_VF58,
	MBX_VF59,
	MBX_VF60,
	MBX_VF61,
	MBX_VF62,
	MBX_VF63,
	MBX_VF64,
	MBX_VF65,
	MBX_VF66,
	MBX_VF67,
	MBX_VF68,
	MBX_VF69,
	MBX_VF70,
	MBX_VF71,
	MBX_VF72,
	MBX_VF73,
	MBX_VF74,
	MBX_VF75,
	MBX_VF76,
	MBX_VF77,
	MBX_VF78,
	MBX_VF79,
	MBX_VF80,
	MBX_VF81,
	MBX_VF82,
	MBX_VF83,
	MBX_VF84,
	MBX_VF85,
	MBX_VF86,
	MBX_VF87,
	MBX_VF88,
	MBX_VF89,
	MBX_VF90,
	MBX_VF91,
	MBX_VF92,
	MBX_VF93,
	MBX_VF94,
	MBX_VF95,
	MBX_VF96,
	MBX_VF97,
	MBX_VF98,
	MBX_VF99,
	MBX_VF100,
	MBX_VF101,
	MBX_VF102,
	MBX_VF103,
	MBX_VF104,
	MBX_VF105,
	MBX_VF106,
	MBX_VF107,
	MBX_VF108,
	MBX_VF109,
	MBX_VF110,
	MBX_VF111,
	MBX_VF112,
	MBX_VF113,
	MBX_VF114,
	MBX_VF115,
	MBX_VF116,
	MBX_VF117,
	MBX_VF118,
	MBX_VF119,
	MBX_VF120,
	MBX_VF121,
	MBX_VF122,
	MBX_VF123,
	MBX_VF124,
	MBX_VF125,
	MBX_VF126,
	//...
	MBX_VF127,
	MBX_CM3CPU,
	MBX_FW = MBX_CM3CPU,
	MBX_VFCNT
};

extern struct mce_mbx_operations mbx_ops_generic;

s32 mce_read_mbx(struct mce_hw *hw, u32 *msg, u16 size,
		 enum MBX_ID mbx_id);
s32 mce_write_mbx(struct mce_hw *hw, u32 *msg, u16 size,
		  enum MBX_ID mbx_id);
s32 mce_check_for_msg(struct mce_hw *hw, enum MBX_ID mbx_id);
s32 mce_check_for_ack(struct mce_hw *hw, enum MBX_ID mbx_id);
s32 mce_check_for_rst(struct mce_hw *hw, enum MBX_ID mbx_id);
unsigned int __maybe_unused mce_mbx_change_timeout(struct mce_hw *hw,
						   int timeout_ms);
bool mce_mbx_cookie_is_valid(struct mce_hw *hw, void *cookie);
void mce_mbx_cookie_free(struct mbx_req_cookie *cookie, bool force_free);
struct mbx_req_cookie *mce_mbx_cookie_zalloc(struct mce_hw *hw,
					     int priv_len);
int mce_mbx_fw_post_req(struct mce_hw *hw, struct mbx_fw_cmd_req *req,
			struct mbx_req_cookie *cookie);
int mce_fw_send_cmd_wait(struct mce_hw *hw, struct mbx_fw_cmd_req *req,
			 struct mbx_fw_cmd_reply *reply);
int mce_mbx_fw_reply_handler(struct mce_hw *hw,
			     struct mbx_fw_cmd_reply *reply);
int mce_mbx_write_posted_locked(struct mce_hw *hw,
				struct mbx_fw_cmd_req *req);
#endif /*_MCE_MBX_H_*/
