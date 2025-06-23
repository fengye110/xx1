#ifndef _MCE_ESWITCH_H_
#define _MCE_ESWITCH_H_

int mce_eswitch_mode_get(struct devlink *devlink, u16 *mode);

#ifdef HAVE_DEVLINK_ESWITCH_OPS_EXTACK
#ifdef HAVE_METADATA_PORT_INFO
int
mce_eswitch_mode_set(struct devlink *devlink, u16 mode,
		     struct netlink_ext_ack *extack);
#else
static inline int
mce_eswitch_mode_set(struct devlink __always_unused *devlink,
		     u16 __always_unused mode,
		     struct netlink_ext_ack __always_unused *extack)
{
	return -EOPNOTSUPP;
}
#endif /* HAVE_METADATA_PORT_INFO */
#else
#ifdef HAVE_METADATA_PORT_INFO
int mce_eswitch_mode_set(struct devlink *devlink, u16 mode);
#else
static inline int mce_eswitch_mode_set(struct devlink __always_unused *devlink,
				       u16 __always_unused mode)
{
	return -EOPNOTSUPP;
}
#endif /* HAVE_METADATA_PORT_INFO */
#endif /* HAVE_DEVLINK_ESWITCH_OPS_EXTACK */

#endif /* _MCE_ESWITCH_H_ */

