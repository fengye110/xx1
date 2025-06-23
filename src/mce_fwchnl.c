// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#include <linux/wait.h>
#include <linux/sem.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include "mce.h"
#include "mce_fwchnl.h"
#include "mce_vf_lib.h"

static int mce_mbx_fw_handle_link_event(struct mce_hw *hw,
					struct mbx_fw_cmd_req *req)
{
	dev_info(mce_hw_to_dev(hw), "%s:print link stat magic:0x%x \n",
		 __func__, req->link_stat.port_st_magic);
	return 0;
}

#ifdef MCE_DEBUG_CM3
static int __mce_fw_get_capability(struct mce_hw *hw,
				   struct phy_abilities *ablity)
{
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));

	build_phy_abalities_req(&req, &req);
	err = mce_fw_send_cmd_wait(hw, &req, &reply);

	if (err == 0)
		memcpy(ablity, &reply.phy_abilities, sizeof(*ablity));

	return err;
}
#endif

static int __mce_mbx_get_lane_stat(struct mce_hw *hw,
				   struct lane_stat_data *st)
{
	struct mbx_fw_cmd_req req;
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_reply reply;
	int err = 0;

	memset(&req, 0, sizeof(req));
	if (hw->mbx.other_irq_enabled) {
		cookie = mce_mbx_cookie_zalloc(
			hw, sizeof(struct lane_stat_data));
		if (!cookie) {
			dev_err(mce_hw_to_dev(hw),
				"%s: alloc cookie failed1\n", __func__);
			return -ENOMEM;
		}
		st = (struct lane_stat_data *)cookie->priv;

		build_get_lane_status_req(&req, hw->nr_lane, cookie);
		err = mce_mbx_fw_post_req(hw, &req, cookie);
		if (err) {
			dev_err(mce_hw_to_dev(hw),
				"%s: mbx fw post req err:%d\n", __func__,
				err);
			goto quit;
		}
	} else {
		memset(&reply, 0, sizeof(reply));

		build_get_lane_status_req(&req, hw->nr_lane, &req);
		err = mce_fw_send_cmd_wait(hw, &req, &reply);
		if (err) {
			dev_err(mce_hw_to_dev(hw),
				"%s: mbx fw semd cmd wait err:%d\n",
				__func__, err);
			goto quit;
		}
		st = (struct lane_stat_data *)&(reply.data);
	}
	dev_info(
		mce_hw_to_dev(hw),
		"mce_mbx_get_lane_stat other_irq_enabled:%d phy_type:0x%x\n",
		hw->mbx.other_irq_enabled, st->phy_type);
quit:
	if (cookie)
		mce_mbx_cookie_free(cookie, err ? false : true);
	return err;
}

int mce_mbx_get_lane_stat(struct mce_hw *hw)
{
	struct lane_stat_data *st = NULL;

	return __mce_mbx_get_lane_stat(hw, st);
}

int mce_fw_get_capability(struct mce_hw *hw, struct phy_abilities *ablity)
{
	u32 fw_version;

#ifdef MCE_DEBUG_CM3
	int err;
	int try_cnt = 3;

	while (try_cnt--) {
		err = __mce_fw_get_capability(hw, ablity);
		if (err == MBX_RET_SUCCESS)
			break;
	}

	if (try_cnt == 0)
		return -1;
	fw_version = ablity->fw_version;
#else
	fw_version = 0xffff0000;
	ablity->dma_qs = 0;
#endif

	if (ablity->dma_qs >= MCE_VF_DMA_QS_PCIE_ISOLATE_BASE) {
		ablity->dma_qs -= MCE_VF_DMA_QS_PCIE_ISOLATE_BASE;
		hw->pcie_isolate_on = true;
	}

	dev_info(mce_hw_to_dev(hw),
		 "mce_fw_get_capability pcie isolate off:%d dma_qs:0x%x\n",
		 hw->pcie_isolate_on, ablity->dma_qs);
	dev_info(mce_hw_to_dev(hw),
		 "mce_fw_get_capability fw_version:0x%x\n", fw_version);
	/* TODO: these params need get from fw */

	return 0;
}

/* TODO: only test for setup vf ring qs */
int mce_mbx_set_vf_qs(struct mce_hw *hw, u32 val)
{
	struct mbx_fw_cmd_req req;

	memset(&req, 0, sizeof(req));
	build_set_phy_reg(&req, NULL, val, 0, 0, 0, 0);

	return mce_mbx_write_posted_locked(hw, &req);
}

static int mce_maintain_req(struct mce_hw *hw, int cmd, int arg0,
			    int req_data_bytes, int reply_bytes,
			    dma_addr_t dma_phy_addr)
{
	int err;
	struct mbx_req_cookie *cookie = NULL;
	struct mbx_fw_cmd_req req;
	struct mbx_fw_cmd_reply reply;
	u64 address = dma_phy_addr;

	cookie = mce_mbx_cookie_zalloc(hw, 0);
	if (!cookie) {
		return -ENOMEM;
	}

	memset(&req, 0, sizeof(req));
	memset(&reply, 0, sizeof(reply));
	cookie->timeout_jiffes = 60 * HZ;

	build_maintain_req(&req, cookie, cmd, arg0, req_data_bytes,
			   reply_bytes, address & 0xffffffff,
			   (address >> 32) & 0xffffffff);

	if (hw->mbx.other_irq_enabled) {
		cookie->timeout_jiffes = 400 * HZ;
		err = mce_mbx_fw_post_req(hw, &req, cookie);
	} else {
		int old_mbx_timeout = hw->mbx.timeout;
		hw->mbx.timeout = (400 * 1000 * 1000) / hw->mbx.usec_delay;
		err = mce_fw_send_cmd_wait(hw, &req, &reply);
		hw->mbx.timeout = old_mbx_timeout;
	}

	if (cookie)
		mce_mbx_cookie_free(cookie, err ? false : true);

	return (err) ? -EIO : 0;
}

int mce_mbx_get_pn_sn(struct mce_hw *hw, char *pn, char *sn)
{
	struct maintain_req *req;
	void *dma_buf = NULL;
	dma_addr_t dma_phy;
	struct ucfg_mac_sn *cfg;

	int err = 0, bytes = sizeof(*req) + sizeof(struct ucfg_mac_sn);

	memset(pn, 0, 33);
	memset(sn, 0, 33);

	dma_buf = dma_alloc_coherent(&hw->pdev->dev, bytes, &dma_phy,
				     GFP_KERNEL);
	if (!dma_buf) {
		printk("%s: no memory:%d!", __func__, bytes);
		return -ENOMEM;
	}

	req = (struct maintain_req *)dma_buf;
	memset(dma_buf, 0, bytes);
	cfg = (struct ucfg_mac_sn *)(req + 1);
	req->magic = MAINTAIN_MAGIC;
	req->cmd = 0;
	req->arg0 = 3;
	req->req_data_bytes = 0;
	req->reply_bytes = bytes - sizeof(*req);

	err = mce_maintain_req(hw, req->cmd, req->arg0,
			       req->req_data_bytes, req->reply_bytes,
			       dma_phy);
	if (err != 0) {
		goto err_quit;
	}
	if (cfg->magic == MAC_SN_MAGIC) {
		int sz = pn_sn_dlen(cfg->pn, 32);
		if (sz) {
			memcpy(pn, cfg->pn, sz);
			pn[sz] = 0;
		}
		sz = pn_sn_dlen(cfg->sn, 32);
		if (sz) {
			memcpy(sn, cfg->sn, sz);
			sn[sz] = 0;
		}
	}

err_quit:
	if (dma_buf)
		dma_free_coherent(&hw->pdev->dev, bytes, dma_buf, dma_phy);

	return 0;
}

static int mce_mbx_fw_req_handler(struct mce_hw *hw,
				  struct mbx_fw_cmd_req *req)
{
	switch (req->opcode) {
	case LINK_STATUS_EVENT:
		mce_mbx_fw_handle_link_event(hw, req);
		break;
	}
	return 0;
}

static int mce_rcv_msg_from_fw(struct mce_hw *hw)
{
	u32 msgbuf[MCE_FW_MAILBOX_SIZE];
	s32 retval;

	retval = mce_read_mbx(hw, msgbuf, MCE_FW_MAILBOX_SIZE, MBX_FW);
	if (retval) {
		dev_err(mce_hw_to_dev(hw),
			"%s: receive message form fw err:%d\n", __func__,
			retval);
		return retval;
	}

	//mce_logd(LOG_MBX_MSG_IN,
	//	 "msg from fw: msg[0]=0x%08x_0x%08x_0x%08x_0x%08x\n",
	//	 msgbuf[0], msgbuf[1], msgbuf[2], msgbuf[3]);

	/* this is a message we already processed, do nothing */
	if (((unsigned short *)msgbuf)[0] & FLAGS_DD)
		return mce_mbx_fw_reply_handler(
			hw, (struct mbx_fw_cmd_reply *)msgbuf);
	return mce_mbx_fw_req_handler(hw, (struct mbx_fw_cmd_req *)msgbuf);
}

static void mce_rcv_ack_from_fw(struct mce_hw *hw)
{
	/* do nothing */
}

int mce_fw_process_mailbox_msg(struct mce_pf *pf, enum MBX_ID mbx_id)
{
	struct mce_hw *hw = &(pf->hw);
	int ret = -1;

	if ((mbx_id != MBX_FW))
		return -1;

	ret = mce_check_for_msg(hw, mbx_id);
	if (ret == MBX_RET_SUCCESS)
		mce_rcv_msg_from_fw(hw);

	ret = mce_check_for_ack(hw, mbx_id);
	if (ret == MBX_RET_SUCCESS)
		mce_rcv_ack_from_fw(hw);

	return ret;
}