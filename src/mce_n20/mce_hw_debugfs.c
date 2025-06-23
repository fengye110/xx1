#include "../mce.h"
#include "../mce_base.h"
#include "mce_hw_n20.h"
#include "mce_hw_debugfs.h"

static void n20_dump_rings_regs(struct mce_hw *hw)
{
	struct mce_pf *pf = hw->back;
	struct mce_vsi *vsi = NULL;
	struct mce_ring *tx_ring = NULL;
	struct mce_ring *rx_ring = NULL;
	struct device *dev = hw->dev;
	u16 q_idx = 0;
	u32 head_val = 0;
	u32 tail_val = 0;
	u32 drop_val = 0;

	if (pf == NULL)
		return;

	vsi = mce_get_main_vsi(pf);

	if (vsi == NULL)
		return;

	dev_info(dev, "Debug - Dump Ring Regs :\n");
	mce_for_each_txq_new(vsi, q_idx) {
		tx_ring = vsi->tx_rings[q_idx];
		if (!tx_ring->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, q_idx);
			continue;
		}
		head_val = ring_rd32(tx_ring,
					N20_DMA_REG_TX_DESC_HEAD);
		tail_val = ring_rd32(tx_ring,
					N20_DMA_REG_TX_DESC_TAIL);
		dev_info(dev,
			 "\tTxq-%-3u "
			 "(0x%08x)-head : 0x%08x (%4u),\t"
			 "(0x%08x)-tail : 0x%08x (%4u)\n",
			 tx_ring->q_index,
			 N20_RING_OFF(tx_ring->q_index) +
				N20_DMA_REG_TX_DESC_HEAD,
			 head_val, head_val,
			 N20_RING_OFF(tx_ring->q_index) +
				N20_DMA_REG_TX_DESC_TAIL,
			 tail_val, tail_val);
	}

	mce_for_each_txq_new(vsi, q_idx) {
		tx_ring = vsi->tx_rings[q_idx];
		if (!tx_ring->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, q_idx);
			continue;
		}
		dev_info(
			dev,
			"\tTxq-%-3u next_to_clean 0x%08x (%4u)\n",
			tx_ring->q_index,
			tx_ring->next_to_clean, tx_ring->next_to_clean);
	}

	mce_for_each_rxq_new(vsi, q_idx) {
		rx_ring = vsi->rx_rings[q_idx];
		if (!rx_ring->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, q_idx);
			continue;
		}
		head_val = ring_rd32(rx_ring,
					N20_DMA_REG_RX_DESC_HEAD);
		tail_val = ring_rd32(rx_ring,
					N20_DMA_REG_RX_DESC_TAIL);
		dev_info(
			dev,
			"\tRxq-%-3u (0x%08x)-head : 0x%08x (%4u),\t"
			"(0x%08x)-tail : 0x%08x (%4u)\n",
			rx_ring->q_index,
			N20_RING_OFF(rx_ring->q_index) +
				N20_DMA_REG_RX_DESC_HEAD,
			head_val, head_val,
			N20_RING_OFF(rx_ring->q_index) +
				N20_DMA_REG_RX_DESC_TAIL,
			tail_val, tail_val);
	}

	mce_for_each_rxq_new(vsi, q_idx) {
		rx_ring = vsi->rx_rings[q_idx];
		if (!rx_ring->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, q_idx);
			continue;
		}
		drop_val = ring_rd32(rx_ring,
					N20_DMA_REG_RX_TIMEOUT_DROP);
		dev_info(
			dev,
			"\tRxq-%-3u timeout drop 0x%08x (%4u)\n",
			rx_ring->q_index, drop_val, drop_val);
	}

	mce_for_each_rxq_new(vsi, q_idx) {
		rx_ring = vsi->rx_rings[q_idx];
		if (!rx_ring->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, q_idx);
			continue;
		}
		dev_info(
			dev,
			"\tRxq-%-3u next_to_clean 0x%08x (%4u)\n",
			rx_ring->q_index,
			rx_ring->next_to_clean, rx_ring->next_to_clean);
	}

}

static void n20_dump_dma_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump DMA Regs :\n");
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_IRQ_CNT));
	dev_info(dev,
		 "\t(0x%08x) tx irq cnt\t\t\t\t: 0x%08x (%u)\n",
		 N20_DMA_OFF(N20_DMA_D_TX_IRQ_CNT), val, val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_IRQ_CNT));
	dev_info(dev,
		 "\t(0x%08x) rx irq cnt\t\t\t\t: 0x%08x (%u)\n",
		 N20_DMA_OFF(N20_DMA_D_RX_IRQ_CNT), val, val);
	val = rd32(
		hw,
		N20_DMA_OFF(N20_DMA_D_CH0_TX_CTRL_DATA_FRAG_CNT));
	dev_info(
		dev,
		"\t(0x%08x) chanel-0 tx ctrl data frag cnt\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_CH0_TX_CTRL_DATA_FRAG_CNT),
		val, val);
	val = rd32(
		hw,
		N20_DMA_OFF(N20_DMA_D_CH1_TX_CTRL_DATA_FRAG_CNT));
	dev_info(
		dev,
		"\t(0x%08x) chanel-1 tx ctrl data frag cnt\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_CH1_TX_CTRL_DATA_FRAG_CNT),
		val, val);
	val = rd32(
		hw,
		N20_DMA_OFF(N20_DMA_D_CH2_TX_CTRL_DATA_FRAG_CNT));
	dev_info(
		dev,
		"\t(0x%08x) chanel-2 tx ctrl data frag cnt\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_CH2_TX_CTRL_DATA_FRAG_CNT),
		val, val);
	val = rd32(
		hw,
		N20_DMA_OFF(N20_DMA_D_CH3_TX_CTRL_DATA_FRAG_CNT));
	dev_info(
		dev,
		"\t(0x%08x) chanel-3 tx ctrl data frag cnt\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_CH3_TX_CTRL_DATA_FRAG_CNT),
		val, val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_CTRL_RD_DESC_CNT));
	dev_info(
		dev,
		"\t(0x%08x) tx ctrl read desc cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_CTRL_RD_DESC_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_CTRL_RD_PKGS_CNT));
	dev_info(
		dev,
		"\t(0x%08x) tx ctrl read pkgs cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_CTRL_RD_PKGS_CNT), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_TX_CTRL_FIFO0_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) tx ctrl fifo-0 desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_CTRL_FIFO0_DESC_AVG), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_TX_CTRL_FIFO1_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) tx ctrl fifo-1 desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_CTRL_FIFO1_DESC_AVG), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_TX_CTRL_FIFO2_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) tx ctrl fifo-2 desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_CTRL_FIFO2_DESC_AVG), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_TX_CTRL_FIFO3_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) tx ctrl fifo-3 desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_CTRL_FIFO3_DESC_AVG), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_CTRL_PCIE_RD_REQ));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl pcie read req cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_PCIE_RD_REQ), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_CTRL_PCIE_WR_REQ));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl pcie write req cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_PCIE_WR_REQ), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_CTRL_WR_DESC_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl received desc cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_WR_DESC_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_CTRL_RD_PKGS_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl read pkgs cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RD_PKGS_CNT), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_RX_CTRL_FIFO0_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl fifo-0 desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_FIFO0_DESC_AVG), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_RX_CTRL_FIFO1_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl fifo-1 desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_FIFO1_DESC_AVG), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_RX_CTRL_FIFO2_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl fifo-2 desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_FIFO2_DESC_AVG), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_RX_CTRL_FIFO3_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl fifo-3 desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_FIFO3_DESC_AVG), val,
		val);
	val = rd32(
		hw,
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RING0_NO_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl ring-0 no desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RING0_NO_DESC_AVG),
		val, val);
	val = rd32(
		hw,
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RING1_NO_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl ring-1 no desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RING1_NO_DESC_AVG),
		val, val);
	val = rd32(
		hw,
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RING2_NO_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl ring-2 no desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RING2_NO_DESC_AVG),
		val, val);
	val = rd32(
		hw,
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RING3_NO_DESC_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx ctrl ring-3 no desc average\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_CTRL_RING3_NO_DESC_AVG),
		val, val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_AXI_RD_CMD_CNT));
	dev_info(
		dev,
		"\t(0x%08x) tx axi read cmd cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_AXI_RD_CMD_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_AXI_WR_CMD_CNT));
	dev_info(
		dev,
		"\t(0x%08x) tx axi write cmd cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_AXI_WR_CMD_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_AXI_RD_PKGS_CNT));
	dev_info(
		dev,
		"\t(0x%08x) tx axi read pkgs cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_AXI_RD_PKGS_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_AXI_WR_PKGS_CNT));
	dev_info(
		dev,
		"\t(0x%08x) tx axi write pkgs cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_AXI_WR_PKGS_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_AXI_RD_CMD_AVG));
	dev_info(
		dev,
		"\t(0x%08x) tx axi read cmd average\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_AXI_RD_CMD_AVG), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_AXI_WR_CMD_AVG));
	dev_info(
		dev,
		"\t(0x%08x) tx axi write cmd average\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_AXI_WR_CMD_AVG), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_AXI_RD_PKGS_AVG));
	dev_info(
		dev,
		"\t(0x%08x) tx axi read pkgs average\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_AXI_RD_PKGS_AVG), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_AXI_WR_PKGS_AVG));
	dev_info(
		dev,
		"\t(0x%08x) tx axi write pkgs average\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_TX_AXI_WR_PKGS_AVG), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_AXI_RD_CMD_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx axi read cmd cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_AXI_RD_CMD_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_AXI_WR_CMD_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx axi write cmd cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_AXI_WR_CMD_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_AXI_RD_PKGS_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx axi read pkgs cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_AXI_RD_PKGS_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_AXI_WR_PKGS_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx axi write pkgs cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_AXI_WR_PKGS_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_AXI_RD_CMD_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx axi read cmd average\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_AXI_RD_CMD_AVG), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_AXI_WR_CMD_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx axi write cmd average\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_AXI_WR_CMD_AVG), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_AXI_RD_PKGS_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx axi read pkgs average\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_AXI_RD_PKGS_AVG), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_AXI_WR_PKGS_AVG));
	dev_info(
		dev,
		"\t(0x%08x) rx axi write pkgs average\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_AXI_WR_PKGS_AVG), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_RX_IFIFO_PKGS_IN_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx ififo pkgs in cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_IFIFO_PKGS_IN_CNT), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_RX_IFIFO_PKGS_OUT_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx ififo pkgs out cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_IFIFO_PKGS_OUT_CNT), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_RX_OFIFO_PKGS_IN_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx ofifo pkgs in cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_OFIFO_PKGS_IN_CNT), val,
		val);
	val = rd32(hw,
			N20_DMA_OFF(N20_DMA_D_RX_OFIFO_PKGS_OUT_CNT));
	dev_info(
		dev,
		"\t(0x%08x) rx ofifo pkgs out cnt\t\t: 0x%08x (%u)\n",
		N20_DMA_OFF(N20_DMA_D_RX_OFIFO_PKGS_OUT_CNT), val,
		val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_RING0_INT_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) tx int ring-0 irq status\t\t: 0x%08x\n",
		N20_DMA_OFF(N20_DMA_D_TX_RING0_INT_STATUS), val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_RING1_INT_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) tx int ring-1 irq status\t\t: 0x%08x\n",
		N20_DMA_OFF(N20_DMA_D_TX_RING1_INT_STATUS), val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_RING2_INT_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) tx int ring-2 irq status\t\t: 0x%08x\n",
		N20_DMA_OFF(N20_DMA_D_TX_RING2_INT_STATUS), val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_TX_RING3_INT_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) tx int ring-3 irq status\t\t: 0x%08x\n",
		N20_DMA_OFF(N20_DMA_D_TX_RING3_INT_STATUS), val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_RING0_INT_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) rx int ring-0 irq status\t\t: 0x%08x\n",
		N20_DMA_OFF(N20_DMA_D_RX_RING0_INT_STATUS), val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_RING1_INT_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) rx int ring-1 irq status\t\t: 0x%08x\n",
		N20_DMA_OFF(N20_DMA_D_RX_RING1_INT_STATUS), val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_RING2_INT_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) rx int ring-2 irq status\t\t: 0x%08x\n",
		N20_DMA_OFF(N20_DMA_D_RX_RING2_INT_STATUS), val);
	val = rd32(hw, N20_DMA_OFF(N20_DMA_D_RX_RING3_INT_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) rx int ring-3 irq status\t\t: 0x%08x\n",
		N20_DMA_OFF(N20_DMA_D_RX_RING3_INT_STATUS), val);
}

static void n20_dump_mux_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump mux Regs :\n");
	val = rd32(hw, N20_ETH_OFF(N20_ETH_PORT0_RX_PKTS));
	dev_info(dev,
		 "\t(0x%08x) rx port0 pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_OFF(N20_ETH_PORT0_RX_PKTS), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_PORT1_RX_PKTS));
	dev_info(dev,
		 "\t(0x%08x) rx port1 pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_OFF(N20_ETH_PORT1_RX_PKTS), val, val);
}

static void n20_dump_parser_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump parser Regs :\n");
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_PKTS_INGRESS));
	dev_info(
		dev,
		"\t(0x%08x) rx ingeress pkts\t\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_PKTS_INGRESS), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_PKTS_EGRESS));
	dev_info(dev,
		 "\t(0x%08x) rx egress pkts\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_OFF(N20_ETH_RX_PKTS_EGRESS), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_EXCEPT_SHORT));
	dev_info(
		dev,
		"\t(0x%08x) rx except short pkts\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_EXCEPT_SHORT), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_INNER_SCTP));
	dev_info(
		dev,
		"\t(0x%08x) rx inner sctp pkts\t\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_INNER_SCTP), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_INNER_TCPSYN));
	dev_info(
		dev,
		"\t(0x%08x) rx inner tcpsyn pkts\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_INNER_TCPSYN), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_INNER_TCP));
	dev_info(
		dev,
		"\t(0x%08x) rx inner tcp pkts\t\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_INNER_TCP), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_INNER_UDP));
	dev_info(
		dev,
		"\t(0x%08x) rx inner udp pkts\t\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_INNER_UDP), val, val);
}

static void n20_dump_fwd_proc_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump fwd proc Regs :\n");
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_INGRESS_PKT_IN));
	dev_info(
		dev,
		"\t(0x%08x) rx ingeress pkt in\t\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_INGRESS_PKT_IN), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_INGRESS_PKT_DROP));
	dev_info(
		dev,
		"\t(0x%08x) rx egress pkt drop\t\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_INGRESS_PKT_DROP), val,
		val);
}

static void n20_dump_editor_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump editor Regs :\n");
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_EDTUP_PKT_IN));
	dev_info(dev,
		 "\t(0x%08x) rx edtup pkt in\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_OFF(N20_ETH_RX_EDTUP_PKT_IN), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_EDTUP_PKT_OUT));
	dev_info(
		dev,
		"\t(0x%08x) rx edtup pkt out\t\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_EDTUP_PKT_OUT), val, val);
}

static void n20_dump_fwd_attr_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump fwd attr Regs :\n");
	val = rd32(hw,
		   N20_ETH_OFF(N20_ETH_RX_ATTR_INGRESS_PKT_IN));
	dev_info(
		dev,
		"\t(0x%08x) rx attr ingeress pkt in\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_ATTR_INGRESS_PKT_IN), val,
		val);
	val = rd32(hw,
		   N20_ETH_OFF(N20_ETH_RX_ATTR_EGRESS_PKT_OUT));
	dev_info(
		dev,
		"\t(0x%08x) rx attr egress pkt out\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_ATTR_EGRESS_PKT_OUT), val,
		val);
	val = rd32(hw,
		   N20_ETH_OFF(N20_ETH_RX_ATTR_EGRESS_PKT_DROP));
	dev_info(
		dev,
		"\t(0x%08x) rx attr egress pkt drop\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_RX_ATTR_EGRESS_PKT_DROP), val,
		val);
}

static void n20_dump_opp_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u32 val = 0;

	dev_info(dev, "Debug - Dump opp Regs :\n");
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TSO_MAX_LEN));
	dev_info(dev,
		 "\t(0x%08x) tso max len\t\t\t: 0x%08x (%u)\n",
		 N20_ETH_OFF(N20_ETH_TSO_MAX_LEN), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TX_DBG_INPUT_PKTS));
	dev_info(
		dev,
		"\t(0x%08x) tx debug input pkts\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_TX_DBG_INPUT_PKTS), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TX_DBG_OUTPUT_PKTS));
	dev_info(
		dev,
		"\t(0x%08x) tx debug output pkts\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_TX_DBG_OUTPUT_PKTS), val, val);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TX_DBG_STATE_STATUS));
	dev_info(
		dev,
		"\t(0x%08x) tx debug state status\t\t: 0x%08x (%u)\n",
		N20_ETH_OFF(N20_ETH_TX_DBG_STATE_STATUS), val,
		val);
}

static void n20_dump_hw_pfc_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_dcb *dcb = pf->dcb;
	u32 val = 0;
	int i;
	
	// show fifo status
	if (test_bit(MCE_PFC_EN, dcb->flags)) {
		dev_info(dev, "\tPFC is enabled\n");
	} else {
		dev_info(dev, "\tPFC is disabled\n");
		return;
	}
	dev_info(dev, "Debug pfc :\n");

	for (i = 0; i < N20_HW_FIFO_CNT; i++) { 
		val = rd32(hw, N20_ETH_OFF(N20_ETH_TXADDR_N_RAM(i)));
		dev_info(dev, "tx %d fifo head %d tail %d\n", i, val >> 16, val & 0xffff);
		val = rd32(hw, N20_ETH_OFF(N20_ETH_RXADDR_N_RAM(i)));
		dev_info(dev, "rx %d fifo head %d tail %d\n", i, val >> 16, val & 0xffff);
		val = rd32(hw, N20_ETH_OFF(N20_ETH_RXFIFO_N_LEAVEL(i)));
		dev_info(dev, "rx %d downline %d highline %d\n", i, val >> 16, val & 0xffff);
	}
	// show fifo map 
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TX_UP2FIFO_MAP));
	for (i = 0; i < N20_HW_FIFO_CNT; i++)
		dev_info(dev, "tx map pri %d to fifo %d\n", i, (val >> (i * 4)) & 0xf);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_UP2FIFO_MAP));
	for (i = 0; i < N20_HW_FIFO_CNT; i++)
		dev_info(dev, "rx map pri %d to fifo %d\n", i, (val >> (i * 4)) & 0xf);
	// show rx mode
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RXMUX_CTRL));
	if (val & BIT(1))
		dev_info(dev, "rx rr enabled\n");
	if (val & BIT(0)) {
		dev_info(dev, "rx wrr enabled\n");
		dev_info(dev, "wrr_timer %d\n", (val >> 2) & 0xffffff);
		for (i = 0; i < 8; i++) {
			val = rd32(hw, N20_ETH_OFF(N20_ETH_RXMUX_WRR(i)));
			dev_info(dev, "rx[%d] %d\n", i, val);
		}
	}
	// show dma fifo map
	val = rd32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(0)));
	dev_info(dev, "dma fifo1 0 -depth %d %d\n", (val >> 16) & 0x3fff, val & 0x3fff);
	val = rd32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(1)));
	dev_info(dev, "dma fifo3 2 -depth %d %d\n", (val >> 16) & 0x3fff, val & 0x3fff);
	val = rd32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(2)));
	dev_info(dev, "dma fifo5 4 -depth %d %d\n", (val >> 16) & 0x3fff, val & 0x3fff);
	val = rd32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(3)));
	dev_info(dev, "dma fifo7 6 -depth %d %d\n", (val >> 16) & 0x3fff, val & 0x3fff);
	val = rd32(hw, N20_DMA_OFF(N20_PFC_FIFO_SELECT));
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		dev_info(dev, "pri %d en %s map to fifo %d\n", i, (val >> (i * 4)) & 0x8 ? "ON" : "OFF",
			(val >> (i * 4)) & 0x7);
	}
	dev_info(dev, "dma_pfc_control:\n");
	/*
	val = rd32(hw, N20_DMA_OFF(N20_DEBUG_PROBE_10)); 
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		dev_info(dev, "fifo %d, err_cnt %d\n", i, ((val >> (i * 0x4)) & 0xf));
	} */

	dev_info(dev, "rdma pfc:\n");
	// show rdma pfifo setup
	for (i = 0; i < N20_HW_FIFO_CNT; i++) {
		val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO(i)));
		dev_info(dev, "rdma %d pfifo val %d\n", i, val);
	}
	for (i = 0; i < N20_HW_FIFO_CNT; i++) {
		val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_FIFO_FULL_TH(i)));
		dev_info(dev, "rdma %d fifo full %d\n", i, val);
	}

}

static void n20_dump_hw_ets_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = &(dcb->cur_etscfg);
	u32 val = 0;
	int i;
	struct mce_vsi *vsi = pf->vsi[0];

	if (test_bit(MCE_ETS_EN, dcb->flags)) {
		dev_info(dev, "\tETS is enabled\n");
	} else {
		dev_info(dev, "\tETS is disabled\n");
		return;
	}
	dev_info(dev, "Debug ETS nic :\n");

	for (i = 0; i < MCE_MAX_PRIORITY; i++)
		dev_info(dev, "prio_talbe[%d] : %d\n", i, etscfg->prio_table[i]); 

	dev_info(dev, "q_base is %d\n", vsi->num_tc_offset);

	for (i = 0; i < MCE_MAX_TC_CNT_NIC; i++) {
		val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_BW(i)));
		dev_info(dev, "tc %d bw percent %d burst_len %d\n", i, val & 0x7f, 2 ^ ((val >> 12) & 7));
	}
	val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_CTRL));
	if (val & BIT(31)) {
		dev_info(dev, "tc is enable\n");
		dev_info(dev, "tc mode is %s\n", val & BIT(30) ? "bps" : "not bps");
		dev_info(dev, "tc mode is %s\n", val & BIT(29) ? "pps" : "not pps");
		dev_info(dev, "len consider crc:%s\n", val & BIT(28) ? "yes" : "no");
		dev_info(dev, "tc valid : 0x%x\n", (val >> 8) & 0xff);
		dev_info(dev, "tc mode : %s\n", val & BIT(0) ? "sp" : "ets");
	} else {
		dev_info(dev, "tc is disable\n");
	}

	val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_TIMEOUT));
	dev_info(dev, "sp timeout %d, ets timeout %d\n", val >> 16, val & 0xffff);

	dev_info(dev, "qg info:\n");

	for (i = 0; i < pf->max_pf_txqs / MCE_MAX_QCNT_IN_QG; i++) {
		val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_QG_CTRL(i)));
		dev_info(dev, "qg %i ctrl %x\n", i, val);
		dev_info(dev, "qg %i %s, queue valid %x\n", i, (val & F_RESTRIC_BYTE) ? "enable" : "disable", (val >> 8) & 0xf);
		val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_QG_BPS_CIR(i)));
		dev_info(dev, "qg %i bps cir %d\n", i, val);
		val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_QG_BPS_PIR(i)));
		dev_info(dev, "qg %i bps pir %d\n", i, val);
	}

	for (i = 0; i < pf->max_pf_txqs; i++) {
		// not so good
		val = rd32(hw, N20_DMA_REG_TX_PRIO_LVL + 0x100 * i);
		dev_info(dev, "hw idx %d, map to tc %d with %s\n", i, fls((val & 0xff0000) >> 16) - 1, (val & BIT(31)) ? "enable" : "disable");
	}

	dev_info(dev, "Debug ETS rdma :\n");
	for (i = 0; i < MCE_MAX_TC_CNT_RDMA; i++) {
		val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO_TC(i)));
		dev_info(dev, "pri %d to tc %d\n", i, val);
		val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_BYTES_TC(i)));
		dev_info(dev, "tc %d max bytes %d\n", i, val);
	}
	val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TOTAL_BYTE));
	dev_info(dev, "total bytes %d\n", val);
	val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_MODE));
	dev_info(dev, "tc en %s, mode %x\n", (val & BIT(8)) ? "on" : "off", val);
	val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_TIME));
	dev_info(dev, "time cnt %d\n", val);
}

static void n20_dump_tc_regs(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi = pf->vsi[0];
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = NULL;
	struct mce_pfc_cfg *pfccfg = NULL;
	struct mce_tc_cfg *tccfg = NULL;
	struct device *dev = hw->dev;
	int q_base = vsi->num_tc_offset;
	int qg_base = 0;
	u8 i = 0;
	u8 j = 0;
	u8 k = 0;

	dev_info(dev, "Debug - tc state :\n");

	if (test_bit(MCE_DCB_EN, dcb->flags))
		dev_info(dev,
			 "\tDCB is enabled dcbx mode is %u\n",
			 dcb->dcbx_cap);
	else
		dev_info(dev,
			 "\tDCB is disabled dcbx mode is %u\n",
			 dcb->dcbx_cap);

	if (test_bit(MCE_DSCP_EN, dcb->flags))
		dev_info(dev, "\tDSCP is enabled\n");
	else
		dev_info(dev, "\tDSCP is disabled\n");

	for (i = 0; i < 8; i++) {
		dev_info(dev,
			 "\tdscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u, "
			 "dscp-%02u: %u\n",
			 ((i*8)+0), dcb->dscp_map[(i*8)+0],
			 ((i*8)+1), dcb->dscp_map[(i*8)+1],
			 ((i*8)+2), dcb->dscp_map[(i*8)+2],
			 ((i*8)+3), dcb->dscp_map[(i*8)+3],
			 ((i*8)+4), dcb->dscp_map[(i*8)+4],
			 ((i*8)+5), dcb->dscp_map[(i*8)+5],
			 ((i*8)+6), dcb->dscp_map[(i*8)+6],
			 ((i*8)+7), dcb->dscp_map[(i*8)+7]);
	}

	if (test_bit(MCE_PFC_EN, dcb->flags))
		dev_info(dev, "\tPFC is enabled\n");
	else
		dev_info(dev, "\tPFC is disabled\n");

	pfccfg = &(dcb->cur_pfccfg);
	etscfg = &(dcb->cur_etscfg);
	tccfg  = &(dcb->cur_tccfg);
	if (test_bit(MCE_ETS_EN, dcb->flags)) {
		for (j = 0; j < tccfg->ntc_cnt; j++) {
			dev_info(dev, "\t\t tc num %u\n", j);
			for (i = 0; i < MCE_MAX_PRIORITY; i++) {

				if ((tccfg->tc_prios_bit[j] & (1 << i)) == 0)
					continue;
				if (pfccfg->pfcena & (1 << i))
					dev_info(dev, "\t\t\tpriority:%u - pfc on\n", i);
				else
					dev_info(dev, "\t\t\tpriority:%u - pfc off\n", i);
				dev_info(dev, "\t\t\tpriority:%u - q_base %u, q_cnt %u\n", i, q_base * j + tccfg->pfc_txq_base[j][i], tccfg->pfc_txq_count[j][i]);
			}
		}
	} else {
		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			if (pfccfg->pfcena & (1 << i))
				dev_info(dev, "\t\t\tpriority:%u - pfc on\n", i);
			else
				dev_info(dev, "\t\t\tpriority:%u - pfc off\n", i);
			dev_info(dev, "\t\t\tpriority:%u - q_base %u, q_cnt %u\n", i, tccfg->pfc_txq_base[0][i], tccfg->pfc_txq_count[0][i]);
		}
	}

	if (test_bit(MCE_ETS_EN, dcb->flags))
		dev_info(dev, "\tETS is enabled\n");
	else
		dev_info(dev, "\tETS is disabled\n");


	dev_info(dev, "\tthe number of TCS that ETS can use is %u\n",
		 etscfg->ets_cap);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		char tsa[4];
		u8 t = 0;

		if ((!test_bit(i, etscfg->etc_state)) &&
		    test_bit(MCE_ETS_EN, dcb->flags))
			continue;

		switch (etscfg->tsatable[i]) {
		case IEEE_8021QAZ_TSA_ETS:
			strcpy(tsa, "ets");
			break;
		case IEEE_8021QAZ_TSA_STRICT:
			strcpy(tsa, "sp");
			break;
		default:
			strcpy(tsa, "xxx");
			break;
		}

		t = tccfg->etc_tc[i];

		dev_info(dev,
			 "\tets-tc: %u hwtc: %u tsa: %s bw: %u\n",
			 i, t, tsa,
			 etscfg->tcbwtable[i]);

		for (j = 0; j < MCE_MAX_PRIORITY; j++){
			if (etscfg->prio_table[j] == i) {
				u8 nt = tccfg->prio_ntc[j];
				dev_info(dev,
					 "\t\tpriority: %u ntc: %u "
					 "q_base: %-3u q_cnt: %u\n",
					 j, nt,
					 tccfg->ntc_txq_base[nt] + nt * q_base,
					 tccfg->ntc_txq_cunt[nt]);
			}
		}

		if (!test_bit(i, etscfg->etc_state))
			continue;

		for (j = 0; j < tccfg->tc_qgs[t]; j++) {
			//
			k = j + qg_base;
			dev_info(dev,
				 "\t\tqueue_group: %-3u "
				 "q_cnt: %-3u "
				 "minrate: %-3u(Mb) "
				 "maxrate: %-3u(Mb)\n",
				 k,
				 tccfg->qg_qs[k],
				 tccfg->min_rate[k],
				 tccfg->max_rate[k]);
		}
		qg_base += tccfg->tc_qgs[t];
	}
	/*
	 * todo 
	if (test_bit(MCE_MQPRIO_CHANNEL, dcb->flags))
		dev_info(dev, "\tMQPRIO_CHANNEL is enabled\n");
	else
		dev_info(dev, "\tMQPRIO_CHANNEL is disabled\n");

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		u8 ht = tccfg->prio_tc[i];
		u8 nt = tccfg->prio_ntc[i];
		dev_info(dev,
			 "\t\tprio: %u hwtc: %u qg:%-3u (%-3uqs) "
			 "minrate: %-3u(Mb) maxrate: %-3u(Mb) "
			 "ntc:%u q_base: %-3u q_cnt:%-3u ",
			 i, ht, ht, tccfg->qg_qs[ht],
			 tccfg->min_rate[ht],
			 tccfg->max_rate[ht],
			 nt,
			 tccfg->ntc_txq_base[nt],
			 tccfg->ntc_txq_cunt[nt]);
	}

	for (i = 0; i < TC_MAX_QUEUE; i++)
		dev_info(dev, "\tdev->prio_tc_map %d -- %d \n", i, netdev->prio_tc_map[i]); 
	
	for (i = 0; i < TC_MAX_QUEUE; i++)
		dev_info(dev, "\ttc %d tc_to_txq.offset %d tc_to_txq.count %d\n", i, netdev->tc_to_txq[i].offset, netdev->tc_to_txq[i].count);
	*/
}

static void n20_dump_db_regs(struct mce_hw *hw)
{
	struct device *dev = hw->dev;
	u64 sum = 0;
	u32 val = 0;
	u32 i = 0;

	dev_info(dev, "Debug - db state :\n");

	val = rd32(hw, N20_ETH_OFF(0x6510));
	dev_info(dev, "\tto txtrans pkt: 0x%-8x\t(%u)\n", val, val);

	val = rd32(hw, N20_ETH_OFF(0x0474));
	FORMAT_FLAG(val, 2, 5, 24);
	wr32(hw, N20_ETH_OFF(0x0474), val);
	val = rd32(hw, N20_ETH_OFF(0x6554));
	dev_info(dev, "\trecv sop pkt cnt: 0x%-8x\t(%u)\n", val, val);

	val = rd32(hw, N20_ETH_OFF(0x0474));
	FORMAT_FLAG(val, 3, 5, 24);
	wr32(hw, N20_ETH_OFF(0x0474), val);
	val = rd32(hw, N20_ETH_OFF(0x6554));
	dev_info(dev, "\trecv eop pkt cnt: 0x%-8x\t(%u)\n", val, val);

	for (i = 4; i < 12; i++) {
		val = rd32(hw, N20_ETH_OFF(0x0474));
		FORMAT_FLAG(val, i, 5, 24);
		wr32(hw, N20_ETH_OFF(0x0474), val);
		val = rd32(hw, N20_ETH_OFF(0x6554));
		dev_info(dev, "\tsend pkt-%u cnt: 0x%-8x\t(%u)\n",
			 (i-4), val, val);
		sum += val;
	}
	dev_info(dev, "\tsend pkt sum: 0x%-8llx\t(%llu)\n", sum, sum);

	for (i = 0; i < 5; i++) {
		dev_info(dev, "\ttso-%u\n", i);
		val = rd32(hw, N20_ETH_OFF(0x80f8));
		FORMAT_FLAG(val, i, 4, 28);
		wr32(hw, N20_ETH_OFF(0x80f8), val);
		val = rd32(hw, N20_ETH_OFF(0x6500));
		dev_info(dev, "\t\ttso input h-pkt: 0x%-8x\t(%u)\n",
			 (val>>16), (val>>16));
		dev_info(dev, "\t\ttso input l-pkt: 0x%-8x\t(%u)\n",
			 (val&0xffff), (val&0xffff));
		dev_info(dev, "\t\ttso input  pkt: 0x%-8x\t(%u)\n", val, val);
		val = rd32(hw, N20_ETH_OFF(0x6504));
		dev_info(dev, "\t\ttso output pkt: 0x%-8x\t(%u)\n", val, val);
		val = rd32(hw, N20_ETH_OFF(0x6508));
		dev_info(dev, "\t\ttso state stat: 0x%-8x\t(%u)\n", val, val);
	}

}

int n20_dump_debug_regs(struct mce_hw *hw, char *cmd)
{
	int ret = -1;

	if (!strncmp(cmd, "ring", 4) || !strncmp(cmd, "all", 3)) {
		n20_dump_rings_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "dma", 3) || !strncmp(cmd, "all", 3)) {
		n20_dump_dma_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "mux", 3) || !strncmp(cmd, "all", 3)) {
		n20_dump_mux_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "parser", 6) || !strncmp(cmd, "all", 3)) {
		n20_dump_parser_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "fwd_proc", 8) || !strncmp(cmd, "all", 3)) {
		n20_dump_fwd_proc_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "editor", 6) || !strncmp(cmd, "all", 3)) {
		n20_dump_editor_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "fwd_attr", 8) || !strncmp(cmd, "all", 3)) {
		n20_dump_fwd_attr_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "opp", 3) || !strncmp(cmd, "all", 3)) {
		n20_dump_opp_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "tc", 2) || !strncmp(cmd, "all", 3)) {
		n20_dump_tc_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "hwpfc", 5) || !strncmp(cmd, "all", 3)) {
		n20_dump_hw_pfc_regs(hw);
		ret = 0;
	}

	if (!strncmp(cmd, "hwets", 5) || !strncmp(cmd, "all", 3)) {
		n20_dump_hw_ets_regs(hw);
		ret = 0;
	}
	if (!strncmp(cmd, "db", 2)) {
		n20_dump_db_regs(hw);
		ret = 0;
	}

	return ret;
}
