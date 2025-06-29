/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Muse Corporation */

#ifndef _KCOMPAT_DEFS_H_
#define _KCOMPAT_DEFS_H_

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#endif /* LINUX_VERSION_CODE */

#ifndef UTS_RELEASE
#include <generated/utsrelease.h>
#endif

/*
 * Include the definitions file for HAVE/NEED flags for the standard upstream
 * kernels.
 *
 * Then, based on the distribution we detect, load the distribution specific
 * definitions file that customizes the definitions for the target
 * distribution.
 */
#include "kcompat_std_defs.h"

#ifdef CONFIG_SUSE_KERNEL
#include "kcompat_sles_defs.h"
#elif UBUNTU_VERSION_CODE
#include "kcompat_ubuntu_defs.h"
#elif RHEL_RELEASE_CODE
#include "kcompat_rhel_defs.h"
#else
#if defined(KYLIN_OS) || defined(CONFIG_KYLINOS_SERVER) || defined(CONFIG_KYLINOS_DESKTOP)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,4,130))
#define NONEED_NAPI_CONSUME_SKB
#define NONEED_CSUM_REPLACE_BY_DIFF
#define NONEED_PCI_REQUEST_IO_REGIONS
#define NONEED_ETH_TYPE_VLAN
#define NONEED_UUID_SIZE
#endif /* keylin linux version > 4.4.130*/

#if defined(KYLIN_RELEASE_CODE)
#if (KYLIN_RELEASE_CODE <= KYLIN_RELEASE_VERSION(10,2))
#define NEED_SKB_FRAG_OFF
#define NEED_SKB_FRAG_OFF_ADD
#else /* keylin_release <= 10.2 */
#undef NEED_SKB_FRAG_OFF
#undef NEED_SKB_FRAG_OFF_ADD
#endif /* keylin_release > 10.2 */
#endif /* KYLIN_RELEASE_CODE */
#endif /* keylin os */
#endif

#include "kcompat_generated_defs.h"

#endif /* _KCOMPAT_DEFS_H_ */
