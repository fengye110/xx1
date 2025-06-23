/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _MCE_DEVLINK_H_
#define _MCE_DEVLINK_H_

#if IS_ENABLED(CONFIG_NET_DEVLINK)

struct mce_pf *mce_allocate_pf(struct device *dev);

void mce_devlink_register(struct mce_pf *pf);
void mce_devlink_unregister(struct mce_pf *pf);

#else /* CONFIG_NET_DEVLINK */
static inline struct mce_pf *mce_allocate_pf(struct device *dev)
{
	return devm_kzalloc(dev, sizeof(struct mce_pf), GFP_KERNEL);
}

static inline void mce_devlink_register(struct mce_pf *pf) { }
static inline void mce_devlink_unregister(struct mce_pf *pf) { }

#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
static inline int mce_devlink_create_vf_port(struct mce_vf *vf) { return 0; }
static inline void mce_devlink_destroy_vf_port(struct mce_vf *vf) { }
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#endif /* !CONFIG_NET_DEVLINK */

#if IS_ENABLED(CONFIG_NET_DEVLINK) && defined(HAVE_DEVLINK_REGIONS)
void mce_devlink_init_regions(struct mce_pf *pf);
void mce_devlink_destroy_regions(struct mce_pf *pf);
#else
static inline void mce_devlink_init_regions(struct mce_pf *pf) { }
static inline void mce_devlink_destroy_regions(struct mce_pf *pf) { }
#endif


#endif /* _MCE_DEVLINK_H_ */
