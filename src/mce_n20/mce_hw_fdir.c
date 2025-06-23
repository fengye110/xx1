#include "../mce.h"
#include "../mce_lib.h"
#include "../mce_base.h"
#include "mce_hw_n20.h"
#include "mce_hw_fdir.h"
#include "../mce_fdir_flow.h"

int n20_fd_update_entry_table(struct mce_hw *hw, int loc, u32 *meta)
{
	u32 hw_state = 0, i;

	do {
		hw_state = rd32(hw, MCE_FDIR_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);

	wr32(hw, MCE_FDIR_ENTRY_ID_EDIT, loc);
	for (i = 0; i < MCE_FDIR_META_LEN; i++) {
		if (meta)
			wr32(hw, MCE_FDIR_ENTRY_META_EDIT(i), meta[i]);
		else
			wr32(hw, MCE_FDIR_ENTRY_META_EDIT(i), 0);
	}
	wr32(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_WR_CMD);
	return 0;
}

int n20_fd_update_hash_table(struct mce_hw *hw, u16 loc, u32 fdir_hash)
{
	u32 hw_state = 0, hw_code = 0;

	do {
		hw_state = rd32(hw, MCE_FDIR_HASH_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	wr32(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
	hw_code = MCE_HASH_ENTRY_EN | loc;
	wr32(hw, MCE_FDIR_HASH_LOC, hw_code);
	wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	return 0;
}

int n20_fd_update_ex_hash_table(struct mce_hw *hw, u16 loc, u32 fdir_hash)
{
	u32 hw_state = 0, hw_code = 0;

	do {
		hw_state = rd32(hw, MCE_FDIR_EX_HASH_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	wr32(hw, MCE_FDIR_EX_HASH_ADDR_W, fdir_hash);
	hw_code = MCE_HASH_ENTRY_EN | loc;
	wr32(hw, MCE_FDIR_EX_HASH_DATA_W, hw_code);
	wr32(hw, MCE_FDIR_EX_HASH_CTRL, MCE_FDIR_WR_CMD);
	return 0;
}

int n20_fd_verificate_sign_rule(struct mce_hw *hw,
				struct mce_fdir_filter *filter, u16 loc,
				u32 fdir_hash)
{
	u32 hw_state = 0, hw_code = 0;

	do {
		hw_state = rd32(hw, MCE_FDIR_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	wr32(hw, MCE_FDIR_ENTRY_ID_READ, loc);
	wr32(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_RD_CMD);
	/* edit hw quick find hash table */
	if (filter->hash_child == 0) {
		do {
			hw_state = rd32(hw, MCE_FDIR_HASH_CMD_CTRL);
			if (!(hw_state & MCE_FDIR_HW_RD))
				break;
		} while (1);
		wr32(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
		hw_code = MCE_HASH_ENTRY_EN | loc;
		wr32(hw, MCE_FDIR_HASH_LOC, hw_code);
		wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	}
	do {
		hw_state = rd32(hw, MCE_FDIR_HASH_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	wr32(hw, MCE_FDIR_HASH_ENTRY_R, fdir_hash);
	wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_RD_CMD);

	dev_info(hw->dev, "dump hash entry table offset 0x4c=> 0x%.2x\n",
		 rd32(hw, MCE_FDIR_HASH_ENTRY_R));
	dev_info(hw->dev, "dump hash entry table offset 0x44=> 0x%.2x\n",
		 rd32(hw, MCE_FDIR_HASH_ADDR_W));
	dev_info(hw->dev, "dump hash entry table offset 0x50=> 0x%.2x\n",
		 rd32(hw, MCE_FDIR_HASH_ENTRY_V));
	return 0;
}

int n20_fd_clear_sign_rule(struct mce_hw *hw, u32 fdir_hash)
{
	u32 hw_state = 0;

	do {
		hw_state = rd32(hw, MCE_FDIR_HASH_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	wr32(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
	wr32(hw, MCE_FDIR_HASH_LOC, 0);
	wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	return 0;
}

void n20_fd_field_bitmask_setup(struct mce_hw *hw,
				struct mce_fdir_field_mask *options,
				u16 loc)
{
	u32 ctrl = 0;

	ctrl |= options->key_off / 2;
	ctrl |= options->mask << MCE_FIELD_VECTOR_MASK_S;
	wr32(hw, MCE_FIELD_VECTOR_MASK(loc), ctrl);
}

void n20_fd_profile_field_bitmask_update(struct mce_hw *hw, u16 profile_id,
					 u32 options)
{
	wr32(hw, MCE_PROFILE_MASK_SEL(profile_id), options);
}

int n20_fd_profile_update(struct mce_hw *hw,
			  struct mce_hw_profile *profile, bool add)
{
	u64 addr_base;
	u32 cfg_shift;
	u32 reg;

	addr_base = MCE_PROFILE_FIELD_MASK_SELECT(profile->profile_id);
	cfg_shift = MCE_PROFILE_FIELD_LOC_SHIFT(profile->profile_id);

	if (add) {
		reg = rd32(hw, addr_base);
		reg &= ~(0XFF << cfg_shift);
		reg |= (profile->fied_mask << cfg_shift);
	} else {
		reg = rd32(hw, addr_base);
		reg &= ~(0XFF << cfg_shift);
	}
	wr32(hw, addr_base, reg);
	reg = rd32(hw, addr_base);

	return 0;
}

int n20_fd_init_hw(struct mce_hw *hw, struct mce_fdir_handle *fdir_handle)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 reg = 0;

	/* init fdir hash key */
	wr32(hw, MCE_FDIR_LK_KEY, MCE_ATR_BUCKET_HASH_KEY);
	wr32(hw, MCE_FDIR_SIGN_LK_KEY, MCE_ATR_SIGNATURE_HASH_KEY);
	if (fdir_handle->mode == MCE_FDIR_SIGN_M_MODE)
		reg |= MCE_FDIR_SIGN_M_EN;
	reg |= MCE_FDIR_HASH_PORT;
	reg |= MCE_FDIR_PRF_MASK_EN;
	reg |= MCE_FDIR_TUN_TYPE_HASH_EN;

	if (pf->fdir_mode == MCE_FDIR_MACVLAN_MODE) {
		reg |= MCE_FDIR_L2_M_MAC << MCE_FDIR_L2_M_S;
	} else {
		reg |= MCE_FDIR_UDP_ESP_SPI_EN;
		reg |= MCE_FDIR_IP_DSCP_EN;
		reg |= MCE_FDIR_PAY_PROTO_EN;
	}
	wr32(hw, MCE_FDIR_CTRL, reg);

	/* init hw age engine */
	wr32(hw, MCE_FDIR_RULE_AGE, MCE_FDIR_AGE_EN);
	mdelay(100);
#define MCE_AUTO_AGE_TM (10)
	reg = MCE_AUTO_AGE_TM << MCE_FDIR_AGE_TM_VAL_S |
	      MCE_FDIR_AGE_AUTO_EN;
	wr32(hw, MCE_FDIR_RULE_AGE, reg);
	return 0;
}
