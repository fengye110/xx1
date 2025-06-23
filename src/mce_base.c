#include "mce_base.h"
#include "mce_lib.h"
#include "mce_irq.h"

/**
 * mce_free_q_vector - Free memory allocated for a specific interrupt vector
 * @vsi: VSI having the memory freed
 * @v_idx: index of the vector to be freed
 */
static void mce_free_q_vector(struct mce_vsi *vsi, int v_idx)
{
	struct mce_q_vector *q_vector;
	struct mce_pf *pf = vsi->back;
	struct mce_ring *ring;
	struct device *dev;

	dev = mce_pf_to_dev(pf);
	if (!vsi->q_vectors[v_idx]) {
		dev_dbg(dev, "Queue vector at index %d not found\n", v_idx);
		return;
	}
	q_vector = vsi->q_vectors[v_idx];

	mce_rc_for_each_ring(ring, q_vector->tx)
		ring->q_vector = NULL;
	mce_rc_for_each_ring(ring, q_vector->rx)
		ring->q_vector = NULL;

	/* only VSI with an associated netdev is set up with NAPI */
	if (vsi->netdev)
		netif_napi_del(&q_vector->napi);

	devm_kfree(dev, q_vector);
	vsi->q_vectors[v_idx] = NULL;
}

/**
 * mce_vsi_free_q_vectors - Free memory allocated for interrupt vectors
 * @vsi: the VSI having memory freed
 */
void mce_vsi_free_q_vectors(struct mce_vsi *vsi)
{
	int v_idx;

	mce_for_each_q_vector(vsi, v_idx)
		mce_free_q_vector(vsi, v_idx);
}

/**
 * mce_vsi_alloc_q_vector - Allocate memory for a single interrupt vector
 * @vsi: the VSI being configured
 * @v_idx: index of the vector in the VSI struct
 *
 * We allocate one q_vector and set default value for ITR setting associated
 * with this q_vector. If allocation fails we return -ENOMEM.
 */
static int mce_vsi_alloc_q_vector(struct mce_vsi *vsi, u16 v_idx)
{
	struct mce_pf *pf = vsi->back;
	struct mce_q_vector *q_vector;

	/* allocate q_vector */
	q_vector = devm_kzalloc(mce_pf_to_dev(pf), sizeof(*q_vector),
				GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	q_vector->vsi = vsi;
	q_vector->v_idx = v_idx;
	q_vector->tx.type = MCE_TX_CONTAINER;
	q_vector->rx.type = MCE_RX_CONTAINER;

	if (!test_bit(MCE_FLAG_HW_DIM_ENA, pf->flags)) {
		// if hw_dim off, we should alloc from setup
		if (test_bit(MCE_FLAG_SW_DIM_ENA, pf->flags)) {
			q_vector->tx.dim_params.mode = ITR_SW_DYNAMIC;
			q_vector->rx.dim_params.mode = ITR_SW_DYNAMIC;
		} else {
			q_vector->tx.dim_params.mode = ITR_STATIC;
			q_vector->rx.dim_params.mode = ITR_STATIC;

		}

	} else {
		q_vector->tx.dim_params.mode = ITR_HW_DYNAMIC;
		q_vector->rx.dim_params.mode = ITR_HW_DYNAMIC;
	}

	q_vector->rx.dim_params.usecs = MCE_RX_INT_DELAY_TIME;
	q_vector->rx.dim_params.frames = MCE_RX_INT_DELAY_PKTS;
	q_vector->tx.dim_params.usecs = MCE_TX_INT_DELAY_TIME;
	q_vector->tx.dim_params.frames = MCE_TX_INT_DELAY_PKTS;

	cpumask_copy(&q_vector->affinity_mask, cpu_possible_mask);
	/* only set affinity_mask if the CPU is online */
	// if (cpu_online(v_idx))
	// 	cpumask_set_cpu(v_idx, &q_vector->affinity_mask);

	/* This will not be called in the driver load path because the netdev
	 * will not be created yet. All other cases with register the NAPI
	 * handler here (i.e. resume, reset/rebuild, etc.)
	 */
	if (vsi->netdev)
		netif_napi_add(vsi->netdev, &q_vector->napi,
			       mce_napi_poll);

	/* tie q_vector and VSI together */
	vsi->q_vectors[v_idx] = q_vector;

	return 0;
}

/**
 * mce_vsi_alloc_q_vectors - Allocate memory for interrupt vectors
 * @vsi: the VSI being configured
 *
 * We allocate one q_vector per queue interrupt. If allocation fails we
 * return -ENOMEM.
 */
int mce_vsi_alloc_q_vectors(struct mce_vsi *vsi)
{
	struct device *dev = mce_pf_to_dev(vsi->back);
	u16 v_idx = 0;
	int err = 0;

	if (vsi->q_vectors[0]) {
		dev_dbg(dev, "VSI %d has existing q_vectors\n", vsi->idx);
		return -EEXIST;
	}

	for (v_idx = 0; v_idx < vsi->num_q_vectors; v_idx++) {
		err = mce_vsi_alloc_q_vector(vsi, v_idx);
		if (err)
			goto err_out;
	}

	return 0;

err_out:
	while (v_idx--)
		mce_free_q_vector(vsi, v_idx);

	dev_err(dev, "Failed to allocate %d q_vector for VSI %d",
		vsi->num_q_vectors, vsi->idx);
	vsi->num_q_vectors = 0;
	return err;
}

//#define DEBUG_SHOW
u32 mce_rd32(struct mce_hw *hw, u32 off)
{
	u8 __iomem *addr = READ_ONCE(hw->eth_bar_base);
	u32 value = 0;

#ifdef DEBUG_SHOW
	struct device *dev = &(hw->pdev->dev);

	dev_info(dev, "nic: try to read %x\n", off);
#endif
	if (unlikely(!(addr)))
		return ~value;
	
	value = readl(addr + off);
	if (!(~value)) {
		// check me later
		//hw->eth_bar_base = NULL;
		//dev_info(dev, "nic: maybe pcie link lost\n");
	} else {
		//dev_info(dev, "%s reg 0x%x : 0x%x\n", __func__, off, value);
	}

#ifdef DEBUG_SHOW
	dev_info(dev, "nic: read ok %x\n", value);
#endif
	return value;
}

void mce_wr32(struct mce_hw *hw, u32 off, u32 val)
{
	u8 __iomem *addr = READ_ONCE(hw->eth_bar_base);
	struct device *dev = &(hw->pdev->dev);

#ifdef DEBUG_SHOW
	dev_info(dev, "nic: try to write %x %x\n", off, val);
#endif
	if (addr) {
		writel((val), (void *)(addr + off));	
	} else {
		dev_info(dev, "nic: write after pcie lost\n");
		//dev_info(dev, "%s reg 0x%x : 0x%x\n", __func__, off, val);
	}
}

u32 mce_rdma_rd32(struct mce_hw *hw, u32 off)
{
	u8 __iomem *addr = READ_ONCE(hw->rdma_bar_base);
	struct device *dev = &(hw->pdev->dev);
	u32 value = 0;

#ifdef DEBUG_SHOW
	dev_info(dev, "rdma: try to read %x\n", off);
#endif
	if (unlikely(!(addr)))
		return ~value;
	
	value = readl(addr + off);
	if (!(~value)) {
		hw->rdma_bar_base = NULL;
		dev_info(dev, "rdma: pcie link lost\n");
	} else {
		//dev_info(dev, "%s reg 0x%x : 0x%x\n", __func__, off, value);
	}

#ifdef DEBUG_SHOW
	dev_info(dev, "rdma: read ok %x\n", value);
#endif
	return value;
}

u64 mce_rdma_rd64(struct mce_hw *hw, u32 off)
{
	u8 __iomem *addr = READ_ONCE(hw->rdma_bar_base);
	struct device *dev = &(hw->pdev->dev);
	u32 value = 0;
	u64 value_64 = 0;

#ifdef DEBUG_SHOW
	dev_info(dev, "rdma64: try to read %x\n", off);
#endif
	if (unlikely(!(addr)))
		return ~value;
	
	value = readl(addr + off);
	if (!(~value)) {
		hw->rdma_bar_base = NULL;
		dev_info(dev, "rdma64: pcie link lost\n");
	} else {
		//dev_info(dev, "%s reg 0x%x : 0x%x\n", __func__, off, value);
	}
	value_64 = value;
	if (unlikely(!(addr)))
		return ~value;

	value = readl(addr + off + 4);
	if (!(~value)) {
		hw->rdma_bar_base = NULL;
		dev_info(dev, "rdma64: pcie link lost\n");
	} else {
		//dev_info(dev, "%s reg 0x%x : 0x%x\n", __func__, off, value);
	}
	value_64 |= (((u64)value) << 32);
#ifdef DEBUG_SHOW
	dev_info(dev, "rdma64: read ok %x\n", value);
#endif
	return value_64;
}

void mce_rdma_wr32(struct mce_hw *hw, u32 off, u32 val)
{
	u8 __iomem *addr = READ_ONCE(hw->rdma_bar_base);
	struct device *dev = &(hw->pdev->dev);

#ifdef DEBUG_SHOW
	dev_info(dev, "rdma: try to write %x %x\n", off, val);
#endif
	if (addr) {
		writel((val), (void *)(addr + off));	
	} else {
		dev_info(dev, "rdma: write after pcie lost\n");
		//dev_info(dev, "%s reg 0x%x : 0x%x\n", __func__, off, val);
	}
}
