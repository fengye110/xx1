// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include "mce.h"
#include "mce_mbx.h"

#define MBX_FORMAT_FLAG(var, cmd, width, offset)                  \
	(var = (((var) & (~((~((~(0x0)) << width)) << offset))) | \
		(((cmd) & (~((~0x0) << width))) << offset)))

//== VEC ==
#define VF2PF_MBOX_VEC(mbx, vf) (mbx->vf2pf_mbox_vec_base + 4 * (vf))
#define CPU2PF_MBOX_VEC(mbx) (mbx->cpu2pf_mbox_vec)

//== PF <--> VF mailbox ====
#define SHARE_MEM_BYTES 64 //64bytes
#define PF_VF_SHM(mbx, vf)     \
	(mbx->pf_vf_shm_base + \
	 mbx->mbx_mem_size * vf) //for PF1 rtl will remap 6000 to 0xb000
#define PF2VF_COUNTER(mbx, vf) (PF_VF_SHM(mbx, vf) + 0)
#define VF2PF_COUNTER(mbx, vf) (PF_VF_SHM(mbx, vf) + 4)
#define PF_VF_SHM_DATA(mbx, vf) (PF_VF_SHM(mbx, vf) + 8)
#define PF2VF_MBOX_CTRL(mbx, vf) (mbx->pf2vf_mbox_ctrl_base + 4 * vf)

#define CPU_PF_SHM(mbx) (mbx->cpu_pf_shm_base)
#define CPU2PF_COUNTER(mbx) (CPU_PF_SHM(mbx) + 0)
#define PF2CPU_COUNTER(mbx) (CPU_PF_SHM(mbx) + 4)
#define CPU_PF_SHM_DATA(mbx) (CPU_PF_SHM(mbx) + 8)

#define PF2CPU_MBOX_CTRL(mbx) (mbx->pf2cpu_mbox_ctrl)
#define CPU2PF_MBOX_CTRL(mbx) (mbx->cpu2pf_mbox_ctrl)

#define MBOX_CTRL_REQ BIT(0) // WO
#define MBOX_CTRL_PF_HOLD_SHM BIT(3) // VF:RO, PF:WR
#define MBOX_CTRL_INTR BIT(4)
#define MBOX_CTRL_REQ_MASK BIT(16)
#define MBOX_CTRL_PF_HOLD_SHM_MASK BIT(19)
#define MBOX_CTRL_INTR_MASK BIT(20)

#define __MBX_CTRL_WITH_REQ_MASK(val) ((val) | MBOX_CTRL_REQ_MASK)
#define __MBX_CTRL_WITH_PFU_MASK(val) ((val) | MBOX_CTRL_PF_HOLD_SHM_MASK)
#define __MBX_CTRL_WITH_INTR_MASK(val) ((val) | MBOX_CTRL_INTR_MASK)
#define __MBX_CTRL_WITH_NO_INTR_MASK(val) \
	((val) | MBOX_CTRL_REQ_MASK | MBOX_CTRL_PF_HOLD_SHM_MASK)

#define MBOX_IRQ_EN 0
#define MBOX_IRQ_DISABLE 1

#define _mbx_rd32(reg) readl((void *)(reg))
#define _mbx_wr32(reg, val) writel((val), (void *)(reg))
#define mbx_rd32(hw, reg) _mbx_rd32((hw)->eth_bar_base + (reg))
#define mbx_wr32(hw, reg, val) _mbx_wr32((hw)->eth_bar_base + (reg), (val))

bool mce_mbx_cookie_is_valid(struct mce_hw *hw, void *cookie)
{
	u8 *begin = (u8 *)(&hw->mbx.cookie_pool.cookies[0]);
	u8 *end = (u8 *)(&hw->mbx.cookie_pool.cookies[MAX_COOKIES_ITEMS]);

	if (((u8 *)cookie) >= begin && ((u8 *)cookie) < end)
		return true;
	return false;
}

void mce_mbx_cookie_free(struct mbx_req_cookie *cookie, bool force_free)
{
	if (!cookie)
		return;

	if (force_free)
		cookie->stat = COOKIE_FREE;
	else
		cookie->stat = COOKIE_FREE_WAIT_TIMEOUT;
}

struct mbx_req_cookie *mce_mbx_cookie_zalloc(struct mce_hw *hw,
					     int priv_len)
{
	struct mbx_req_cookie *cookie = NULL;
	int loop_cnt = MAX_COOKIES_ITEMS, i;
	bool find = false;

	u64 now_jiffies = get_jiffies_64();

	if (mutex_lock_interruptible(&hw->mbx.lock)) {
		dev_err(mce_hw_to_dev(hw),
			"%s: mutex lock interruptible failed! priv_len:%d\n",
			__func__, priv_len);
		return NULL;
	}

	i = hw->mbx.cookie_pool.next_idx;
	while (loop_cnt--) {
		cookie = &(hw->mbx.cookie_pool.cookies[i]);
		if (cookie->stat == COOKIE_FREE ||
		    /* force free cookie if cookie not freed after 120 seconds */
		    time_after64(now_jiffies, cookie->alloced_jiffies +
						      (2 * 60) * HZ)) {
			find = true;
			cookie->alloced_jiffies = get_jiffies_64();
			cookie->stat = COOKIE_ALLOCED;
			hw->mbx.cookie_pool.next_idx =
				(i + 1) % MAX_COOKIES_ITEMS;
			break;
		}
		i = (i + 1) % MAX_COOKIES_ITEMS;
	}

	mutex_unlock(&hw->mbx.lock);

	if (!find) {
		dev_err(mce_hw_to_dev(hw),
			"%s: no free cookies availble\n", __func__);
		return NULL;
	}

	cookie->timeout_jiffes = 30 * HZ;
	cookie->priv_len = priv_len;

	return cookie;
}

int mce_mbx_fw_post_req(struct mce_hw *hw, struct mbx_fw_cmd_req *req,
			struct mbx_req_cookie *cookie)
{
	int err = 0;

	if (pci_channel_offline(hw->pdev))
		return -EIO;

	cookie->errcode = 0;
	cookie->done = 0;
	init_waitqueue_head(&cookie->wait);

	if (mutex_lock_interruptible(&hw->mbx.lock)) {
		dev_err(mce_hw_to_dev(hw),
			"[%s] wait mbx lock timeout opcode:0x%x\n",
			__func__, req->opcode);
		return -EAGAIN;
	}

	//mce_logd(LOG_MBX_LOCK, "%s %d lock:%p hw:%p opcode:0x%x\n",
	//	 __func__, hw->pfvfnum, &hw->mbx.lock, hw, req->opcode);

	err = mce_write_mbx(hw, (u32 *)req,
			    (req->datalen + MBX_REQ_HDR_LEN) / 4, MBX_FW);
	if (err) {
		dev_err(mce_hw_to_dev(hw),
			"%s: mce write mbx failed! err:%d opcode:0x%x\n",
			__func__, err, req->opcode);
		mutex_unlock(&hw->mbx.lock);
		return err;
	}

	if (cookie->timeout_jiffes != 0) {
		int retry_cnt = 4;
retry:
		err = wait_event_interruptible_timeout(
			cookie->wait, cookie->done == 1,
			cookie->timeout_jiffes);

		if (err == -ERESTARTSYS && retry_cnt) {
			retry_cnt--;
			goto retry;
		}
		if (err == 0) {
			dev_err(mce_hw_to_dev(hw),
				"%s: mce write mbx failed! err:%d opcode:0x%x\n",
				__func__, err, req->opcode);

			dev_err(mce_hw_to_dev(hw),
				"%s: failed! hw:%p timeout err:%d opcode:%x\n",
				__func__, hw, err, req->opcode);
			err = -ETIME;
		} else if (err > 0) {
			err = 0;
		}
	} else {
		wait_event_interruptible(cookie->wait, cookie->done == 1);
	}

	mutex_unlock(&hw->mbx.lock);

	if (cookie->errcode)
		err = cookie->errcode;

	return err;
}

int mce_fw_send_cmd_wait(struct mce_hw *hw, struct mbx_fw_cmd_req *req,
			 struct mbx_fw_cmd_reply *reply)
{
	int err;
	int retry_cnt = 3;

	if (!hw || !req || !reply || !hw->mbx.ops->read_posted) {
		dev_err(mce_hw_to_dev(hw), "%s: hw:%p req:%p reply:%p\n",
			__func__, hw, req, reply);
		return -EINVAL;
	}

	if (pci_channel_offline(hw->pdev))
		return -EIO;

	if (mutex_lock_interruptible(&hw->mbx.lock)) {
		dev_err(mce_hw_to_dev(hw),
			"%s: get mbx lock failed opcode:0x%x\n", __func__,
			req->opcode);
		return -EAGAIN;
	}

	//mce_logd(LOG_MBX_LOCK, "%s %d lock:%p hw:%p opcode:0x%x\n",
	//	 __func__, hw->pfvfnum, &hw->mbx.lock, hw, req->opcode);
	err = hw->mbx.ops->write_posted(
		hw, (u32 *)req, (req->datalen + MBX_REQ_HDR_LEN) / 4,
		MBX_FW);
	if (err) {
		dev_err(mce_hw_to_dev(hw),
			"%s: write_posted failed! err:0x%x opcode:0x%x\n",
			__func__, err, req->opcode);
		mutex_unlock(&hw->mbx.lock);
		return err;
	}

retry:
	retry_cnt--;
	if (retry_cnt < 0) {
		dev_err(mce_hw_to_dev(hw),
			"%s: retry timeout opcode:0x%x\n", __func__,
			req->opcode);
		return -EIO;
	}
	err = hw->mbx.ops->read_posted(hw, (u32 *)reply,
				       sizeof(*reply) / 4, MBX_FW);
	if (err) {
		dev_err(mce_hw_to_dev(hw),
			"%s: read_posted failed! err:0x%x opcode:0x%x\n",
			__func__, err, req->opcode);
		mutex_unlock(&hw->mbx.lock);
		return err;
	}
	if (reply->opcode != req->opcode)
		goto retry;

	mutex_unlock(&hw->mbx.lock);

	if (reply->error_code) {
		dev_err(mce_hw_to_dev(hw), "%s: reply err:0x%x req:0x%x\n",
			__func__, reply->error_code, req->opcode);
		return -reply->error_code;
	}
	return 0;
}

int mce_mbx_write_posted_locked(struct mce_hw *hw,
				struct mbx_fw_cmd_req *req)
{
	int err = 0;
	int retry = 3;

	if (pci_channel_offline(hw->pdev)) {
		return -EIO;
	}

	if (mutex_lock_interruptible(&hw->mbx.lock)) {
		dev_err(mce_hw_to_dev(hw),
			"[%s] get mbx lock failed opcode:0x%x\n", __func__,
			req->opcode);
		return -EAGAIN;
	}

try_again:
	retry--;
	if (retry < 0) {
		mutex_unlock(&hw->mbx.lock);
		dev_err(mce_hw_to_dev(hw),
			"%s: write_posted failed! err:0x%x opcode:0x%x\n",
			__func__, err, req->opcode);
		return -EIO;
	}

	err = hw->mbx.ops->write_posted(
		hw, (u32 *)req, (req->datalen + MBX_REQ_HDR_LEN) / 4,
		MBX_FW);
	if (err) {
		goto try_again;
	}
	mutex_unlock(&hw->mbx.lock);

	return err;
}

int mce_mbx_fw_reply_handler(struct mce_hw *hw,
			     struct mbx_fw_cmd_reply *reply)
{
	struct mbx_req_cookie *cookie;

	cookie = reply->cookie;
	if (!cookie || mce_mbx_cookie_is_valid(hw, cookie) == false ||
	    cookie->stat != COOKIE_ALLOCED) {
		return -EIO;
	}

	if (cookie->priv_len > 0)
		memcpy(cookie->priv, reply->data, cookie->priv_len);

	cookie->done = 1;

	if (reply->flags & FLAGS_ERR)
		cookie->errcode = reply->error_code;
	else
		cookie->errcode = 0;

	if (cookie->stat == COOKIE_ALLOCED)
		wake_up_interruptible(&cookie->wait);
	/* not really free cookie, mark as free-able */
	mce_mbx_cookie_free(cookie, false);

	return 0;
}

/**
 *  mce_read_mbx - Reads a message from the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox/vfnum to read
 *
 *  returns SUCCESS if it successfully read message from buffer
 **/
s32 mce_read_mbx(struct mce_hw *hw, u32 *msg, u16 size,
		   enum MBX_ID mbx_id)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	s32 ret_val = MCE_ERR_MBX;

	/* limit read to size of mailbox */
	if (size > mbx->size)
		size = mbx->size;

	if (mbx->ops->read)
		ret_val = mbx->ops->read(hw, msg, size, mbx_id);

	return ret_val;
}

/**
 *  mce_write_mbx - Write a message to the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully copied message into the buffer
 **/
s32 mce_write_mbx(struct mce_hw *hw, u32 *msg, u16 size,
		    enum MBX_ID mbx_id)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	s32 ret_val = 0;

	if (size > mbx->size)
		ret_val = MCE_ERR_MBX;
	else if (mbx->ops->write)
		ret_val = mbx->ops->write(hw, msg, size, mbx_id);

	return ret_val;
}

static inline u16 mce_mbx_get_req(struct mce_hw *hw, int reg)
{
	mb();
	return ioread32(hw->eth_bar_base + reg) & 0xffff;
}

static inline u16 mce_mbx_get_ack(struct mce_hw *hw, int reg)
{
	mb();
	return (mbx_rd32(hw, reg) >> 16);
}

static inline void mce_mbx_inc_pf_req(struct mce_hw *hw,
					enum MBX_ID mbx_id)
{
	u16 req;
	int reg;
	struct mce_mbx_info *mbx = &hw->mbx;
	u32 v;

	reg = (mbx_id == MBX_CM3CPU) ? PF2CPU_COUNTER(mbx) :
				       PF2VF_COUNTER(mbx, mbx_id);
	v = mbx_rd32(hw, reg);

	req = (v & 0xffff);
	req++;
	v &= ~(0x0000ffff);
	v |= req;
	mb();
	mbx_wr32(hw, reg, v);

	/* update stats */
	hw->mbx.stats.msgs_tx++;
}

static inline void mce_mbx_inc_pf_ack(struct mce_hw *hw,
					enum MBX_ID mbx_id)
{
	u16 ack;
	struct mce_mbx_info *mbx = &hw->mbx;
	int reg = (mbx_id == MBX_CM3CPU) ? PF2CPU_COUNTER(mbx) :
					   PF2VF_COUNTER(mbx, mbx_id);
	u32 v = mbx_rd32(hw, reg);

	ack = (v >> 16) & 0xffff;
	ack++;
	v &= ~(0xffff0000);
	v |= (ack << 16);
	mb();
	mbx_wr32(hw, reg, v);

	/* update stats */
	hw->mbx.stats.msgs_rx++;
}

/**
 *  mce_check_for_msg - checks to see if someone sent us mail
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to check
 *
 *  returns SUCCESS if the Status bit was found or else ERR_MBX
 **/
s32 mce_check_for_msg(struct mce_hw *hw, enum MBX_ID mbx_id)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	s32 ret_val = MCE_ERR_MBX;

	if (mbx->ops->check_for_msg)
		ret_val = mbx->ops->check_for_msg(hw, mbx_id);

	return ret_val;
}

/**
 *  mce_check_for_ack - checks to see if someone sent us ACK
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to check
 *
 *  returns SUCCESS if the Status bit was found or else ERR_MBX
 **/
s32 mce_check_for_ack(struct mce_hw *hw, enum MBX_ID mbx_id)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	s32 ret_val = MCE_ERR_MBX;

	if (mbx->ops->check_for_ack)
		ret_val = mbx->ops->check_for_ack(hw, mbx_id);

	return ret_val;
}

/**
 *  mce_poll_for_msg - Wait for message notification
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message notification
 **/
static s32 mce_poll_for_msg(struct mce_hw *hw, enum MBX_ID mbx_id)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	if (!countdown || !mbx->ops->check_for_msg)
		goto out;

	while (countdown && mbx->ops->check_for_msg(hw, mbx_id)) {
		countdown--;
		if (!countdown) {
			dev_info(mce_hw_to_dev(hw),
				 "vfnum:%d mbx poll for msg timeout!\n",
				 mbx_id);
			break;
		}
		udelay(mbx->usec_delay);
	}

out:
	return countdown ? 0 : -ETIME;
}

/**
 *  mce_poll_for_ack - Wait for message acknowledgment
 *  @hw: pointer to the HW structure
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message acknowledgment
 **/
static s32 mce_poll_for_ack(struct mce_hw *hw, enum MBX_ID mbx_id)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	int countdown = mbx->timeout;

	if (!countdown || !mbx->ops->check_for_ack)
		goto out;

	while (countdown && mbx->ops->check_for_ack(hw, mbx_id)) {
		countdown--;
		if (!countdown) {
			dev_info(
				mce_hw_to_dev(hw),
				"vfnum:%d mbx poll for poll ack timeout!\n",
				mbx_id);
			break;
		}
		udelay(mbx->usec_delay);
	}

out:
	return countdown ? 0 : MCE_ERR_MBX;
}

/**
 *  mce_read_posted_mbx - Wait for message notification and receive message
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully received a message notification and
 *  copied it into the receive buffer.
 **/
static s32 mce_read_posted_mbx(struct mce_hw *hw, u32 *msg, u16 size,
				 enum MBX_ID mbx_id)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	s32 ret_val = MCE_ERR_MBX;

	if (!mbx->ops->read)
		goto out;

	ret_val = mce_poll_for_msg(hw, mbx_id);

	/* if ack received read message, otherwise we timed out */
	if (!ret_val)
		ret_val = mbx->ops->read(hw, msg, size, mbx_id);
out:
	return ret_val;
}

/**
 *  mce_write_posted_mbx - Write a message to the mailbox, wait for ack
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: id of mailbox to write
 *
 *  returns SUCCESS if it successfully copied message into the buffer and
 *  received an ack to that message within delay * timeout period
 **/
static s32 mce_write_posted_mbx(struct mce_hw *hw, u32 *msg, u16 size,
				  enum MBX_ID mbx_id)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	s32 ret_val = MCE_ERR_MBX;

	if (pci_channel_offline(hw->pdev))
		return -EIO;

	/* exit if either we can't write or there isn't a defined timeout */
	if (!mbx->ops->write || !mbx->timeout)
		goto out;

	/* send msg and hold buffer lock */
	ret_val = mbx->ops->write(hw, msg, size, mbx_id);

	/* if msg sent wait until we receive an ack */
	if (!ret_val)
		ret_val = mce_poll_for_ack(hw, mbx_id);

out:
	return ret_val;
}

/**
 *  mce_check_for_msg_pf - checks to see if the VF has sent mail
 *  @hw: pointer to the HW structure
 *  @vf_number: the VF index
 *
 *  returns SUCCESS if the VF has set the Status bit or else ERR_MBX
 **/
static s32 mce_check_for_msg_pf(struct mce_hw *hw, enum MBX_ID mbx_id)
{
	s32 ret_val = MCE_ERR_MBX;
	u16 hw_req_count = 0;
	struct mce_mbx_info *mbx = &hw->mbx;

	if (mbx_id == MBX_CM3CPU) {
		hw_req_count = mce_mbx_get_req(hw, CPU2PF_COUNTER(mbx));
		if (test_bit(MCE_MBX_FEATURE_NO_ZERO,
			     mbx->mbx_feature)) {
			if ((hw_req_count != 0) &&
			    (hw_req_count != hw->mbx.cpu_req)) {
				ret_val = 0;
				hw->mbx.stats.reqs++;
			}

		} else {
			if (hw_req_count != hw->mbx.cpu_req) {
				ret_val = 0;
				hw->mbx.stats.reqs++;
			}
		}
	} else {
		if (mce_mbx_get_req(hw, VF2PF_COUNTER(mbx, mbx_id)) !=
		    hw->mbx.vf_req[mbx_id]) {
			ret_val = 0;
			hw->mbx.stats.reqs++;
		}
	}

	return ret_val;
}

/**
 *  mce_check_for_ack_pf - checks to see if the VF has ACKed
 *  @hw: pointer to the HW structure
 *  @vf_number: the VF index
 *
 *  returns SUCCESS if the VF has set the Status bit or else ERR_MBX
 **/
static s32 mce_check_for_ack_pf(struct mce_hw *hw, enum MBX_ID mbx_id)
{
	s32 ret_val = MCE_ERR_MBX;
	struct mce_mbx_info *mbx = &hw->mbx;

	if (pci_channel_offline(hw->pdev))
		return -EIO;

	if (mbx_id == MBX_CM3CPU) {
		if (mce_mbx_get_ack(hw, CPU2PF_COUNTER(mbx)) !=
		    hw->mbx.cpu_ack) {
			ret_val = 0;
			hw->mbx.stats.acks++;
		}
	} else {
		if (mce_mbx_get_ack(hw, VF2PF_COUNTER(mbx, mbx_id)) !=
		    hw->mbx.vf_ack[mbx_id]) {
			ret_val = 0;
			hw->mbx.stats.acks++;
		}
	}

	return ret_val;
}

/**
 *  mce_obtain_mbx_lock_pf - obtain mailbox lock
 *  @hw: pointer to the HW structure
 *  @mbx_id: the VF index or CPU
 *
 *  return SUCCESS if we obtained the mailbox lock
 **/
static s32 mce_obtain_mbx_lock_pf(struct mce_hw *hw,
				    enum MBX_ID mbx_id)
{
	int try_cnt = 5000; // wait 500ms
	struct mce_mbx_info *mbx = &hw->mbx;
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
			       PF2CPU_MBOX_CTRL(mbx) :
			       PF2VF_MBOX_CTRL(mbx, mbx_id);

	while (try_cnt-- > 0) {
		/* Take ownership of the buffer */
		mbx_wr32(hw, CTRL_REG,
			 __MBX_CTRL_WITH_NO_INTR_MASK(
				 MBOX_CTRL_PF_HOLD_SHM));
		wmb();
		/* reserve mailbox for cm3 use */
		if (mbx_rd32(hw, CTRL_REG) & MBOX_CTRL_PF_HOLD_SHM)
			return 0;
		udelay(100);
	}

	dev_err(mce_hw_to_dev(hw), "%s: failed to get:%d lock \n",
		__func__, mbx_id);
	return -EPERM;
}

/**
 *  mce_write_mbx_pf - Places a message in the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @mbx_id: the VF index
 *
 *  returns SUCCESS if it successfully copied message into the buffer
 **/
static s32 mce_write_mbx_pf(struct mce_hw *hw, u32 *msg, u16 size,
			      enum MBX_ID mbx_id)
{
	s32 ret_val = 0;
	int i;
	struct mce_mbx_info *mbx = &hw->mbx;
	u32 DATA_REG = (mbx_id == MBX_CM3CPU) ?
			       CPU_PF_SHM_DATA(mbx) :
			       PF_VF_SHM_DATA(mbx, mbx_id);
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
			       PF2CPU_MBOX_CTRL(mbx) :
			       PF2VF_MBOX_CTRL(mbx, mbx_id);

	if (pci_channel_offline(hw->pdev))
		return -EIO;

	if (size > MCE_VFMAILBOX_SIZE) {
		dev_info(mce_hw_to_dev(hw), "%s: size:%d should <%d\n",
			 __func__, size, MCE_VFMAILBOX_SIZE);
		return -EINVAL;
	}

	/* lock the mailbox to prevent pf/vf/cpu race condition */
	ret_val = mce_obtain_mbx_lock_pf(hw, mbx_id);
	if (ret_val) {
		dev_err(mce_hw_to_dev(hw),
			"%s: get mbx:%d wlock failed. ret:%d. req:0x%08x-0x%08x\n",
			__func__, mbx_id, ret_val, msg[0], msg[1]);
		goto out_no_write;
	}

	/* copy the caller specified message to the mailbox memory buffer */
	for (i = 0; i < size; i++)
		mbx_wr32(hw, DATA_REG + i * 4, msg[i]);

	/* flush msg and acks as we are overwriting the message buffer */
	if (mbx_id == MBX_CM3CPU) {
		hw->mbx.cpu_ack =
			mce_mbx_get_ack(hw, CPU2PF_COUNTER(mbx));
	} else {
		hw->mbx.vf_ack[mbx_id] =
			mce_mbx_get_ack(hw, VF2PF_COUNTER(mbx, mbx_id));
	}

	/* print debug info */
	for (i = -2; i < size; i++)
		mce_mbx_dbg(hw, "mbxid:0x%04x addr:0x%04x data:0x%04x\n",
			      mbx_id, (i + 2) * 4,
			      mbx_rd32(hw, DATA_REG + i * 4));
	mce_mbx_inc_pf_req(hw, mbx_id);

	if (test_bit(MCE_MBX_FEATURE_WRITE_DELAY, mbx->mbx_feature))
		udelay(300);
	/* Interrupt VF/CM3 to tell it a message has been sent and
	 * release buffer
	 */
	mbx_wr32(hw, CTRL_REG,
		 __MBX_CTRL_WITH_NO_INTR_MASK(MBOX_CTRL_REQ));
out_no_write:

	return ret_val;
}

/**
 *  mce_read_mbx_pf - Read a message from the mailbox
 *  @hw: pointer to the HW structure
 *  @msg: The message buffer
 *  @size: Length of buffer
 *  @vf_number: the VF index
 *
 *  This function copies a message from the mailbox buffer to the caller's
 *  memory buffer.  The presumption is that the caller knows that there was
 *  a message due to a VF/CPU request so no polling for message is needed.
 **/
static s32 mce_read_mbx_pf(struct mce_hw *hw, u32 *msg, u16 size,
			     enum MBX_ID mbx_id)
{
	s32 ret_val = -EIO;
	int i;
	struct mce_mbx_info *mbx = &hw->mbx;
	u32 BUF_REG = (mbx_id == MBX_CM3CPU) ? CPU_PF_SHM_DATA(mbx) :
					       PF_VF_SHM_DATA(mbx, mbx_id);
	u32 CTRL_REG = (mbx_id == MBX_CM3CPU) ?
			       PF2CPU_MBOX_CTRL(mbx) :
			       PF2VF_MBOX_CTRL(mbx, mbx_id);

	if (pci_channel_offline(hw->pdev))
		return -EIO;

	if (size > MCE_VFMAILBOX_SIZE) {
		dev_err(mce_hw_to_dev(hw), "%s: size:%d should <%d\n",
			__func__, size, MCE_VFMAILBOX_SIZE);
		return -EINVAL;
	}
	/* lock the mailbox to prevent pf/vf race condition */
	ret_val = mce_obtain_mbx_lock_pf(hw, mbx_id);
	if (ret_val)
		goto out_no_read;

	mb();
	/* copy the message from the mailbox memory buffer */
	for (i = 0; i < size; i++)
		msg[i] = mbx_rd32(hw, BUF_REG + 4 * i);

	// mbx_wr32(hw, BUF_REG, 0);

	/* update req. used by check_for_msg_vf  */
	if (mbx_id == MBX_CM3CPU) {
		hw->mbx.cpu_req =
			mce_mbx_get_req(hw, CPU2PF_COUNTER(mbx));
	} else {
		hw->mbx.vf_req[mbx_id] =
			mce_mbx_get_req(hw, VF2PF_COUNTER(mbx, mbx_id));
	}
	/* print debug info */
	for (i = -2; i < size; i++)
		mce_mbx_dbg(hw, "mbxid:0x%04x addr:0x%04x data:0x%04x\n",
			      mbx_id, (i + 2) * 4,
			      mbx_rd32(hw, BUF_REG + i * 4));
	/* this ack maybe too earier? */
	/* Acknowledge receipt and release mailbox, then we're done */
	mce_mbx_inc_pf_ack(hw, mbx_id);

	/* free ownership of the buffer */
	mbx_wr32(hw, CTRL_REG, __MBX_CTRL_WITH_NO_INTR_MASK(0));

out_no_read:

	return ret_val;
}

static void mce_mbx_reset(struct mce_hw *hw)
{
	int idx, v;
	struct mce_mbx_info *mbx = &hw->mbx;

	for (idx = 0; idx < hw->max_vfs; idx++) {
		mbx_wr32(hw, VF2PF_COUNTER(mbx, idx), 0);
		mbx_wr32(hw, PF2VF_COUNTER(mbx, idx), 0);

		hw->mbx.vf_req[idx] = 0;
		hw->mbx.vf_ack[idx] = 0;
		/* release pf<->vf pfu buffer lock */
		mbx_wr32(hw, PF2VF_MBOX_CTRL(mbx, idx),
			 __MBX_CTRL_WITH_NO_INTR_MASK(0));
		mbx_wr32(hw, PF2VF_MBOX_CTRL(mbx, idx),
			 __MBX_CTRL_WITH_INTR_MASK(MBOX_CTRL_INTR));
	}

	/* reset pf->cm3 status */
	v = mbx_rd32(hw, CPU2PF_COUNTER(mbx));
	hw->mbx.cpu_req = v & 0xffff;
	hw->mbx.cpu_ack = (v >> 16) & 0xffff;

	dev_info(mce_hw_to_dev(hw),
		 "now mbx.cpu_req %d mbx.cpu_ack %d\n", hw->mbx.cpu_req,
		 hw->mbx.cpu_ack);
	/* release   pf->cm3 buffer lock */
	mbx_wr32(hw, PF2CPU_MBOX_CTRL(mbx),
		 __MBX_CTRL_WITH_NO_INTR_MASK(0));
	mbx_wr32(hw, PF2CPU_MBOX_CTRL(mbx), __MBX_CTRL_WITH_INTR_MASK(0));
}

static int mce_mbx_configure_pf(struct mce_hw *hw, int nr_vec,
				  bool enable)
{
	struct mce_mbx_info *mbx = &hw->mbx;
	int idx = 0;
	u32 v;

	if (pci_channel_offline(hw->pdev))
		return -EIO;

	hw->mbx.ops->init_params(hw);
	if (enable) {
		for (idx = 0; idx < hw->max_vfs; idx++) {
			mbx_wr32(hw, VF2PF_COUNTER(mbx, idx), 0);
			mbx_wr32(hw, PF2VF_COUNTER(mbx, idx), 0);
			hw->mbx.vf_req[idx] = 0;
			hw->mbx.vf_ack[idx] = 0;
			mbx_wr32(hw, PF2VF_MBOX_CTRL(mbx, idx),
				 __MBX_CTRL_WITH_NO_INTR_MASK(0));
		}
		/* reset pf->cm3 status */
		v = mbx_rd32(hw, CPU2PF_COUNTER(mbx));
		hw->mbx.cpu_req = v & 0xffff;
		hw->mbx.cpu_ack = (v >> 16) & 0xffff;
		/* release   pf->cm3 buffer lock */
		mbx_wr32(hw, PF2CPU_MBOX_CTRL(mbx),
			 __MBX_CTRL_WITH_NO_INTR_MASK(0));
#ifdef MCE_DEBUG_VF
#ifdef MCE_DEBUG_XINSI_PCIE
		/* bind cm3 to cpu mbx to irq */
		mbx_wr32(hw, CPU2PF_MBOX_VEC(mbx), nr_vec);
		/* enable cm3 irq to pf */
		mbx_wr32(hw, CPU2PF_MBOX_CTRL(mbx),
			 __MBX_CTRL_WITH_INTR_MASK(0));
		for (idx = 0; idx < hw->max_vfs; idx++)
			mbx_wr32(hw, VF2PF_MBOX_VEC(mbx, idx), nr_vec);
#else
		/* tmp setup for fpga debug bit*/
#define VF2PF_IRQ_VECTORS(i) (0x20000 + 0x10000 + 0xf040 + (i) * 0x4)
		v = mbx_rd32(hw, VF2PF_IRQ_VECTORS(0));
		MBX_FORMAT_FLAG(v, 0x0, 16, 16);
		mbx_wr32(hw, VF2PF_IRQ_VECTORS(0), v);
		v = mbx_rd32(hw, VF2PF_IRQ_VECTORS(1));
		MBX_FORMAT_FLAG(v, 0x0, 16, 16);
		mbx_wr32(hw, VF2PF_IRQ_VECTORS(1), v);
#endif
#endif
	} else {
		/* disable cm3 irq to pf */
		mbx_wr32(hw, CPU2PF_MBOX_CTRL(mbx),
			 __MBX_CTRL_WITH_INTR_MASK(MBOX_CTRL_INTR));
		/* release   pf->cm3 buffer lock */
		mbx_wr32(hw, PF2CPU_MBOX_CTRL(mbx),
			 __MBX_CTRL_WITH_NO_INTR_MASK(0));
		/* reset vf->pf status/ctrl */
		for (idx = 0; idx < hw->max_vfs; idx++)
			mbx_wr32(hw, PF2VF_MBOX_CTRL(mbx, idx),
				 __MBX_CTRL_WITH_NO_INTR_MASK(0));
	}
	return 0;
}

unsigned int __maybe_unused mce_mbx_change_timeout(struct mce_hw *hw,
						     int timeout_ms)
{
	unsigned int old_timeout = hw->mbx.timeout;

	hw->mbx.timeout = timeout_ms * 1000 / hw->mbx.usec_delay;

	return old_timeout;
}

/**
 *  mce_init_mbx_params_pf - set initial values for pf mailbox
 *  @hw: pointer to the HW structure
 *
 *  Initializes the hw->mbx struct to correct values for pf mailbox
 */
static s32 mce_init_mbx_params_pf(struct mce_hw *hw)
{
	struct mce_mbx_info *mbx = &hw->mbx;

	mbx->usec_delay = 100;
	// wait 4s
	mbx->timeout = (4 * 1000 * 1000) / mbx->usec_delay;

	mbx->stats.msgs_tx = 0;
	mbx->stats.msgs_rx = 0;
	mbx->stats.reqs = 0;
	mbx->stats.acks = 0;
	mbx->stats.rsts = 0;
	mbx->size = MCE_VFMAILBOX_SIZE;

	mutex_init(&mbx->lock);
	mce_mbx_reset(hw);
	return 0;
}

struct mce_mbx_operations mbx_ops_generic = {
	.init_params = mce_init_mbx_params_pf,
	.read = mce_read_mbx_pf,
	.write = mce_write_mbx_pf,
	.read_posted = mce_read_posted_mbx,
	.write_posted = mce_write_posted_mbx,
	.check_for_msg = mce_check_for_msg_pf,
	.check_for_ack = mce_check_for_ack_pf,
	.configure = mce_mbx_configure_pf,
};
