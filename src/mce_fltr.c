#include "mce.h"
#include "mce_fltr.h"

/**
 * mce_add_uc_filter - Add an address for unicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 */
int mce_add_uc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	hw->ops->add_uc_filter(hw, addr);

	return 0;
}

/**
 * mce_add_uc_filter - Del an address for unicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 */
int mce_del_uc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);

	hw->ops->del_uc_filter(hw, addr);
	return 0;
}

/**
 * mce_add_uc_filter - Add an address for multicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 */
int mce_add_mc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		hw->vf.ops->set_vf_add_mc_fliter(hw, addr);
	else
		hw->ops->add_mc_filter(hw, addr);
	return 0;
}

/**
 * mce_add_uc_filter - Del an address for multicast filtering
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 */
int mce_del_mc_filter(struct net_device *netdev, const u8 *addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_hw *hw = &(vsi->back->hw);
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		hw->vf.ops->set_vf_del_mc_filter(hw, addr);
	else
		hw->ops->del_mc_filter(hw, addr);
	return 0;
}
