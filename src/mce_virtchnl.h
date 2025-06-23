/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2024 Mucse Corporation */

#ifndef _MCE_CONTROLQ_H_
#define _MCE_CONTROLQ_H_

#define FLAG_VF_NONE_PROMISC (0x00000000)
#define FLAG_VF_UNICAST_PROMISC (0x00000001)
#define FLAG_VF_MULTICAST_PROMISC (0x00000002)

/* Different control queue types: These are mainly for SW consumption. */
enum mce_ctl_q {
	MCE_CTL_Q_UNKNOWN = 0,
	MCE_CTL_Q_MAILBOX,
};

int mce_vc_process_mailbox_msg(struct mce_pf *pf, enum MBX_ID mbx_id);
int mce_msg_post_status_signle(struct mce_pf *pf,
				 enum PF_STATUS status, int vf);
#endif /* _MCE_CONTROLQ_H_ */