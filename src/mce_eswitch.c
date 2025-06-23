#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include "mce.h"
#include "mce_lib.h"
#include "mce_eswitch.h"
#include "mce_fltr.h"
//#include "mce_repr.h"
#include "mce_devlink.h"
//#include "mce_tc_lib.h"

/**
 * mce_eswitch_mode_get - get current eswitch mode
 * @devlink: pointer to devlink structure
 * @mode: output parameter for current eswitch mode
 */
int mce_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct mce_pf *pf = devlink_priv(devlink);

	*mode = pf->eswitch_mode;
	return 0;
}

#ifdef HAVE_METADATA_PORT_INFO
#ifdef HAVE_DEVLINK_ESWITCH_OPS_EXTACK
/**
 * mce_eswitch_mode_set - set new eswitch mode
 * @devlink: pointer to devlink structure
 * @mode: eswitch mode to switch to
 * @extack: pointer to extack structure
 */

int
mce_eswitch_mode_set(struct devlink *devlink, u16 mode,
		     struct netlink_ext_ack *extack)
#else
int mce_eswitch_mode_set(struct devlink *devlink, u16 mode)
#endif /* HAVE_DEVLINK_ESWITCH_OPS_EXTACK */
{
	struct mce_pf *pf = devlink_priv(devlink);

	if (pf->eswitch_mode == mode)
		return 0;

//	if (mce_has_vfs(pf)) {
//		dev_info(mce_pf_to_dev(pf), "Changing eswitch mode is allowed only if there is no VFs created");
//		return -EOPNOTSUPP;
//	}

	switch (mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		dev_info(mce_pf_to_dev(pf), "PF %d changed eswitch mode to legacy",
			 pf->hw.pf_id);
		break;
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
	{
#ifdef NETIF_F_HW_TC
//		if (mce_is_adq_active(pf)) {
//			dev_err(mce_pf_to_dev(pf), "switchdev cannot be configured - ADQ is active. Delete ADQ configs using TC and try again\n");
//			return -EOPNOTSUPP;
//		}
#endif /* NETIF_F_HW_TC */

#ifdef HAVE_NDO_DFWD_OPS
//		if (mce_is_offloaded_macvlan_ena(pf)) {
//			dev_err(mce_pf_to_dev(pf), "switchdev cannot be configured -  L2 Forwarding Offload is currently enabled.\n");
//			return -EOPNOTSUPP;
//		}
#endif /* HAVE_NDO_DFWD_OPS */

		if (!test_bit(MCE_FLAG_ESWITCH_CAPABLE, pf->flags)) {
			dev_err(mce_pf_to_dev(pf), "switchdev cannot be configured - eswitch isn't supported in hw or there was not enough msix\n");
			return -EOPNOTSUPP;
		}

		dev_info(mce_pf_to_dev(pf), "PF %d changed eswitch mode to switchdev",
			 pf->hw.pf_id);
		break;
	}
	default:
#ifdef HAVE_DEVLINK_ESWITCH_OPS_EXTACK
		NL_SET_ERR_MSG_MOD(extack, "Unknown eswitch mode");
#else
		dev_err(mce_pf_to_dev(pf), "Unknown eswitch mode");
#endif /* HAVE_DEVLINK_ESWITCH_OPS_EXTACK */
		return -EINVAL;
	}

	pf->eswitch_mode = mode;
	return 0;
}
#endif /* HAVE_METADATA_PORT_INFO */



#endif /* CONFIG_NET_DEVLINK */

