/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2024 Mucse Corporation */

#ifndef _MCE_SRIOV_H_
#define _MCE_SRIOV_H_
#include "mce_netdev.h"
#include "mce.h"
#include "mce_vf_lib.h"

int mce_sriov_configure(struct pci_dev *dev, int num_vfs);
int mce_disable_sriov(struct mce_pf *pf);

#ifdef CONFIG_PCI_IOV
int mce_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac);
int mce_get_vf_cfg(struct net_device *netdev, int vf_id,
		     struct ifla_vf_info *ivi);
#ifdef IFLA_VF_VLAN_INFO_MAX
int mce_set_vf_port_vlan(struct net_device *netdev, int vf_id,
			   u16 vlan_id, u8 qos, __be16 vlan_proto);
#else
int mce_set_vf_port_vlan(struct net_device *netdev, int vf_id,
			   u16 vlan_id, u8 qos);
#endif
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
int mce_set_vf_bw(struct net_device *netdev, int vf_id, int min_tx_rate,
		  int max_tx_rate);
#else
int mce_set_vf_bw(struct net_device *netdev, int vf_id, int tx_rate);
#endif
#ifdef HAVE_NDO_SET_VF_TRUST
int mce_set_vf_trust(struct net_device *netdev, int vf_id, bool trusted);
#endif

int mce_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena);

#else
static inline int
mce_set_vf_mac(struct net_device __always_unused *netdev,
		 int __always_unused vf_id, u8 __always_unused *mac)
{
	return -EOPNOTSUPP;
}

static inline int
mce_get_vf_cfg(struct net_device __always_unused *netdev,
		 int __always_unused vf_id,
		 struct ifla_vf_info __always_unused *ivi)
{
	return -EOPNOTSUPP;
}

#ifdef IFLA_VF_VLAN_INFO_MAX
static inline int
mce_set_vf_port_vlan(struct net_device __always_unused *netdev,
		       int __always_unused vf_id, u16 __always_unused vid,
		       u8 __always_unused qos,
		       __be16 __always_unused v_proto)
{
	return -EOPNOTSUPP;
}
#else
static inline int
mce_set_vf_port_vlan(struct net_device __always_unused *netdev,
		       int __always_unused vf_id, u16 __always_unused vid,
		       u8 __always_unused qos)
{
	return -EOPNOTSUPP;
}
#endif /* IFLA_VF_VLAN_INFO_MAX */

#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
static inline int mce_set_vf_bw(struct net_device __always_unused *netdev,
				int __always_unused vf_id,
				int __always_unused min_tx_rate,
				int __always_unused max_tx_rate)
#else
static inline int mce_set_vf_bw(struct net_device __always_unused *netdev,
				int __always_unused vf_id,
				int __always_unused max_tx_rate)
#endif
{
	return -EOPNOTSUPP;
}

#ifdef HAVE_NDO_SET_VF_TRUST
static inline int
mce_set_vf_trust(struct net_device __always_unused *netdev,
		   int __always_unused vf_id, bool __always_unused trusted)
{
	return -EOPNOTSUPP;
}
#endif /* HAVE_NDO_SET_VF_TRUST */
static inline int
mce_set_vf_spoofchk(struct net_device __always_unused *netdev,
		      int __always_unused vf_id, bool __always_unused ena)
{
	return -EOPNOTSUPP;
}

#endif

#endif /* _MCE_SRIOV_H_ */