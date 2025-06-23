#ifndef _MCE_FLTR_H_
#define _MCE_FLTR_H_

int mce_add_uc_filter(struct net_device *netdev, const u8 *addr);
int mce_del_uc_filter(struct net_device *netdev, const u8 *addr);
int mce_add_mc_filter(struct net_device *netdev, const u8 *addr);
int mce_del_mc_filter(struct net_device *netdev, const u8 *addr);

#endif /* _MCE_FLTR_H_ */
