#include "../mce.h"
#include "../mce_lib.h"
#include "mce_hw_n20.h"
#include "mce_hw_npu.h"
#include "../mce_npu.h"
#include "mce_npu_firmware.h"

int n20_npu_download_firmware(struct mce_hw *hw)
{
	u32 val = 0;

	val = npu_rd(hw, 0x6060);
	dev_info(mce_hw_to_dev(hw), "npu versionn 0x%x\n", val);
	npu_wr(hw, N20_NPU_START_REG + 0x6000, 0x0);
	npu_wr(hw, N20_CLUSTER_OFFSET + 0x10, 0x1);
	npu_wr(hw, N20_CLUSTER_OFFSET + 0x20, 0x0);
	npu_wr(hw, N20_SWITCH_OFFSET + 0x8028, 0x1);

	npu_wr(hw, N20_CLUSTER_OFFSET + 0x18, 0x7b);
	val = npu_rd(hw, N20_CLUSTER_OFFSET + 0x18);
	dev_info(mce_hw_to_dev(hw), "npu addr:0x%x val:0x%x\n",
		 N20_CLUSTER_OFFSET + 0x18, val);

	npu_wr(hw, N20_CLUSTER_OFFSET + 0x1c, 0x7c);
	val = npu_rd(hw, N20_CLUSTER_OFFSET + 0x1c);
	dev_info(mce_hw_to_dev(hw), "npu addr:0x%x val:0x%x\n",
		 N20_CLUSTER_OFFSET + 0x1c, val);

	MCE_NPU_IOWRITE32_CFG_ARRAY(N20_RPU_FW_BORAD_OFFSET, cfg_inst,
				    INST_SIZE);
	MCE_NPU_CHECK_CFG_ARRAY(N20_RPU_FW_CHECK_OFFSET, cfg_inst,
				INST_SIZE);
	npu_wr(hw, N20_CLUSTER_OFFSET + 0xc, 0x3);
	npu_wr(hw, N20_NPU_START_REG + 0x6000, 0x1);
	return 0;
}
