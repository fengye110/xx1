#ifndef _MCE_DCBNL_H_
#define _MCE_DCBNL_H_

#ifdef CONFIG_DCB
void mce_set_dcbnl_ops(struct net_device *netdev);
void mce_dcbnl_set_app(struct mce_dcb *dcb,
			 struct net_device *netdev);
void mce_dcbnl_del_app(struct mce_dcb *dcb,
			 struct net_device *netdev);
#else
static inline void mce_set_dcbnl_ops(struct net_device *netdev) {}
void mce_dcbnl_set_app(struct mce_dcb *dcb,
			 struct net_device *netdev) {}
void mce_dcbnl_del_app(struct mce_dcb *dcb,
			 struct net_device *netdev) {}
#endif /* CONFIG_DCB */

#endif /* _MCE_DCBNL_H_ */