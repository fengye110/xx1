#include "mce.h"
#include "mce_lib.h"
#include "mce_npu.h"
#include "mce_n20/mce_hw_n20.h"

int mce_npu_download_firmware(struct mce_hw *hw)
{
	hw->ops->npu_download_firmware(hw);
	return 0;
}
