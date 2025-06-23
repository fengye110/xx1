#ifndef _MCE_BASE_H_
#define _MCE_BASE_H_

#include "mce.h"

#define MCE_TX_INT_DELAY_TIME (8)
#define MCE_RX_INT_DELAY_TIME (8)
#define MCE_TX_INT_DELAY_PKTS (128)
#define MCE_RX_INT_DELAY_PKTS (128)

int mce_vsi_alloc_q_vectors(struct mce_vsi *vsi);
void mce_vsi_free_q_vectors(struct mce_vsi *vsi);
u32 mce_rd32(struct mce_hw *hw, u32 off);
void mce_wr32(struct mce_hw *hw, u32 off, u32 val);
u32 mce_rdma_rd32(struct mce_hw *hw, u32 off);
u64 mce_rdma_rd64(struct mce_hw *hw, u32 off);
void mce_rdma_wr32(struct mce_hw *hw, u32 off, u32 val);

#endif /* _MCE_BASE_H_ */
