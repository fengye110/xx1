#include "../mce.h"
#include "../mce_base.h"
#include "mce_hw_dcb.h"
#include "mce_hw_n20.h"

void n20_enable_tc(struct mce_hw *hw,
		   struct mce_dcb *dcb)
{
	struct mce_tc_cfg *tccfg = &(dcb->cur_tccfg);
	u32 val = 0;
	//u64 tmp = 0;
	u8 i = 0;

	val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_CTRL));
	val |= F_TC_EN;
	val |= F_TC_BP_MOD;
	val |= F_TC_CRC;
	val |= F_TC_INTERAL_EN;
	for (i = 0; i < tccfg->tc_cnt; i++)
		val |= (1 << (F_TC_VALID_OFFSET + i));
	FORMAT_FLAG(val, hw->qos.interal,
		    10, F_TC_INTERAL_OFFSET);
	wr32(hw, N20_DMA_OFF(N20_DMA_TC_CTRL), val);

	/* limit pf speed for debug only ? */
	// remove it now is 25G
	val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_TAL_BW));
	//val |= F_TC_BW_EN;
	val |= F_TC_BW_SHARE_EN;
	//tmp = ((u64)(hw->qos.link_speed) * 1000000);
	//tmp = tmp >> 9; /* in 512 bits */
	//tmp = tmp / hw->qos.rate;
	// tmp = tmp * 25 / 10; //250M时钟
	//FORMAT_FLAG(val, tmp, 30, F_TC_BW_OFFSET);
	wr32(hw, N20_DMA_OFF(N20_DMA_TC_TAL_BW), val);
	// setup timeout default
	val = ETS_TIMEOUT;
	FORMAT_FLAG(val, SP_TIMEOUT, 16, 16);
	wr32(hw, N20_DMA_OFF(N20_DMA_TC_TIMEOUT), val);
}

void n20_enable_rdma_tc(struct mce_hw *hw,
			struct mce_dcb *dcb)
{
	struct mce_ets_cfg *etscfg = &(dcb->cur_etscfg);
	u8 i = 0;
	u32 val;
	// u64 true_speed;
	// setup prio to tc map
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		val = etscfg->prio_table[i];
		rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO_TC(i)), val);
	}
	
	/* fixed use prio 7 */
	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO_TC(7)), 7);
	

	val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_MODE));
	val |= RDMA_ETS_EN;
	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_MODE), val);

	// no need setup this
	//true_speed = hw->cur_link_speed * 1024 * 128;
	//rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TOTAL_BYTE), true_speed); 

}

void n20_disable_tc(struct mce_hw *hw)
{
	u32 val = 0;

	wr32(hw, N20_DMA_OFF(N20_DMA_TC_CTRL), val);
	wr32(hw, N20_DMA_OFF(N20_DMA_TC_TAL_BW), val);
}

void n20_disable_rdma_tc(struct mce_hw *hw)
{
	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_MODE), 0);
	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TOTAL_BYTE), 0); 
}

void n20_set_tc_bw_rdma(struct mce_hw *hw,
		   struct mce_dcb *dcb)
{
	struct mce_ets_cfg *etscfg = NULL;
	struct mce_tc_cfg *tccfg = NULL;
	u32 val = 0;
	u8 i = 0;
	u64 true_speed;
	u8 tmp;

	etscfg = &(dcb->cur_etscfg);
	tccfg = &(dcb->cur_tccfg);

	for (i = 0; i < MCE_MAX_TC_CNT; i++)
		rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_BYTES_TC(i)), 0);

	val = rdma_rd32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_MODE));
	for (i = 0; i < MCE_MAX_TC_CNT; i++) {
		tmp = tccfg->etc_tc[i];

		if (etscfg->tsatable[i] != IEEE_8021QAZ_TSA_ETS) {
			val &= (~BIT(i));
			continue;
		}
		val |= BIT(i);

		// in bytes, link_speed in Mbps
		true_speed = hw->cur_link_speed * 1024 * 128 * etscfg->tcbwtable[i] / 100;
		true_speed = true_speed * 93 / 100;
		rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_BYTES_TC(tmp)), true_speed);
	}

	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_MODE), val);
	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_TC_TIME), hw->cur_tc_time_for_rdma);
}

void n20_set_tc_bw(struct mce_hw *hw,
		   struct mce_dcb *dcb)
{
	struct mce_ets_cfg *etscfg = NULL;
	struct mce_tc_cfg *tccfg = NULL;
	u32 val = 0;
	u8 i = 0;

	etscfg = &(dcb->cur_etscfg);
	tccfg = &(dcb->cur_tccfg);

	for (i = 0; i < MCE_MAX_TC_CNT; i++)
		wr32(hw, N20_DMA_OFF(N20_DMA_TC_BW(i)), 0);

	val = rd32(hw, N20_DMA_OFF(N20_DMA_TC_CTRL));
	for (i = 0; i < MCE_MAX_TC_CNT; i++) {
		u8 t = tccfg->etc_tc[i];

		if (etscfg->tsatable[i] != IEEE_8021QAZ_TSA_ETS)
			continue;

		wr32(hw, N20_DMA_OFF(N20_DMA_TC_BW(t)),
		     etscfg->tcbwtable[i]);

		val |= (1 << t);
	}
	wr32(hw, N20_DMA_OFF(N20_DMA_TC_CTRL), val);
}

void n20_set_qg_ctrl(struct mce_hw *hw,
		     struct mce_dcb *dcb)
{
	struct mce_tc_cfg *tccfg = &(dcb->cur_tccfg);
	u32 val = 0;
	u8 i = 0, j = 0;
	int qg_base = 0;
	int qg_base_off = tccfg->qg_base_off;

	/* first close it */
	for (i = 0; i < MCE_MAX_QGS; i++)
		wr32(hw, N20_DMA_OFF(N20_DMA_TC_QG_CTRL(i)), 0);

	for (i = 0; i < tccfg->tc_cnt; i++) {
		for (j = 0; j < tccfg->tc_qgs[i]; j++) {
			val = 0;
			val |= F_RESTRIC_BYTE;
			val |= F_WEIGHT_EN;
			switch (tccfg->qg_qs[qg_base + j]) {
			case 1:
				FORMAT_FLAG(val, 1, 4, 8);
				break;
			case 2:
				FORMAT_FLAG(val, 3, 4, 8);
				break;
			case 3:
				FORMAT_FLAG(val, 7, 4, 8);
				break;
			case 4:
				FORMAT_FLAG(val, 15, 4, 8);
				break;
			default:
				return;
			}
			wr32(hw, N20_DMA_OFF(N20_DMA_TC_QG_CTRL(qg_base_off * i + j)),
					val);

		}
		qg_base += tccfg->tc_qgs[i];
	}
}

void n20_set_qg_rate(struct mce_hw *hw,
		     struct mce_dcb *dcb)
{
	struct mce_tc_cfg *tccfg = &(dcb->cur_tccfg);
	u32 val = 0;
	u64 tmp = 0;
	u8 i = 0, j = 0;
	int qg_base = 0;
	int qg_base_off = tccfg->qg_base_off;


	for (i = 0; i < MCE_MAX_QGS; i++) {
		wr32(hw, N20_DMA_OFF(N20_DMA_TC_QG_BPS_CIR(i)),
		     0);

		wr32(hw, N20_DMA_OFF(N20_DMA_TC_QG_BPS_PIR(i)),
		     0);
	}

	for (i = 0; i < tccfg->tc_cnt; i++) {
		for (j = 0; j < tccfg->tc_qgs[i]; j++) {
			/* in 512bits */
			tmp = (u64)(tccfg->min_rate[qg_base + j]) * 1000000;
			tmp = tmp >> 9;
			tmp = tmp / hw->qos.rate;
			val = (u32)tmp;
			wr32(hw, N20_DMA_OFF(N20_DMA_TC_QG_BPS_CIR(qg_base_off * i + j)),
					val);

			/* in 512bits */
			tmp = (u64)(tccfg->max_rate[qg_base + j]) * 1000000;
			tmp = tmp >> 9;
			tmp = tmp / hw->qos.rate;
			val = (u32)tmp;
			wr32(hw, N20_DMA_OFF(N20_DMA_TC_QG_BPS_PIR(qg_base_off * i + j)),
					val);

		}
		qg_base += tccfg->tc_qgs[i];
	}
}

void n20_set_q_to_tc(struct mce_hw *hw,
		     struct mce_dcb *dcb)
{
	struct mce_tc_cfg *tccfg = &(dcb->cur_tccfg);
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_ring *txq = NULL;
	u32 val = 0;
	u16 qid = 0;
	u8 i = 0, j = 0, z = 0;
	u16 qg_cnt = 0;
	u16 qg_base = 0;
	u32 tmp;
	u16 ring_base;
	/* for each tc */
	for (i = 0; i < tccfg->tc_cnt; i++) {

		qg_cnt = tccfg->tc_qgs[i];
		ring_base = tccfg->qg_base_off * i * MCE_MAX_QCNT_IN_QG;

		/* for each qg in this tc */
		for (j = 0; j < qg_cnt; j++) {
			/* check each valid queue */
			for (z = 0; z < tccfg->qg_qs[j + qg_base]; z++) {
				qid = ring_base + j * MCE_MAX_QCNT_IN_QG + z;

				txq = vsi->tx_rings[qid];

				// check ring is valid
				if (!txq->q_vector) {
					//printk("%s skip q %d\n", __func__, qid);
					continue;
				}
				val = ring_rd32(txq, N20_DMA_REG_TX_PRIO_LVL);
				/* should clear_bit first */
				val &= (~0xff0000);
				tmp = (1 << (i + F_RING_TC_LOC));
				val |= F_RING_TC_EN;
				val |= tmp;

				ring_wr32(txq, N20_DMA_REG_TX_PRIO_LVL, val);
				++qid;
			}
		}
		qg_base += qg_cnt;
	}
}

void n20_clr_q_to_tc(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_ring *txq = NULL;
	u32 val = 0;
	u16 qid = 0;

	for(qid = 0; qid < vsi->num_txq; qid++) {
		txq = vsi->tx_rings[qid];

		// if ring is used
		if (!txq->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, qid);
			continue;
		}
		if (txq == NULL) {
			dev_err(hw->dev,
				"failed to set queue to tc"
				"txq-%u is null\n",
				qid);
			continue;
		}
		val = ring_rd32(txq, N20_DMA_REG_TX_PRIO_LVL);
		val &= ~F_RING_TC_EN;
		FORMAT_FLAG(val, 0, 8, F_RING_TC_LOC);
		ring_wr32(txq, N20_DMA_REG_TX_PRIO_LVL, val);
	}
}

/**
 * n20_set_dft_fifo_space - reset default hw fifo space
 */
void n20_set_dft_fifo_space(struct mce_hw *hw)
{
	u32 highline = 0; //high waterline
	u32 downline = 0; //low waterline
	u32 head = 0;
	u32 tail = 0; // fifo deep = tail - head + 1
	u32 val = 0;
	u8 i = 0;
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &(dcb->cur_pfccfg);

	/* Configure the size of space used for FIFO 0 */
	val = 0;
	head = 0;
	tail = N20_FIFO0_DFT_DEEP - 1;
	FORMAT_FLAG(val, head, 16, 16);
	FORMAT_FLAG(val, tail, 16, 0);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_N_RAM(0)), val);
	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
		pfccfg->fifo_head[0] = head;
		pfccfg->fifo_tail[0] = tail;
		pfccfg->fifo_depth[0] = tail - head + 1;
		wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_N_RAM(0)), val);
	}

	/* Configure the size of space used for FIFO 1-7 */
	for (i = 1; i < 8; i++) {
		u32 tmp_deep = 16;

		head = tail + 1;
		tail = head + tmp_deep - 1;
		FORMAT_FLAG(val, head, 16, 16);
		FORMAT_FLAG(val, tail, 16, 0);

		if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
			pfccfg->fifo_head[i] = head;
			pfccfg->fifo_tail[i] = tail;
			pfccfg->fifo_depth[i] = tail - head + 1;
			wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_N_RAM(i)), val);
		}
		wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_N_RAM(i)), val);
	}

	/* Make the configuration about FIFO space take effect */
	val = 0;
	val = F_RXTXADDR_EN;
	wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_ENA), val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_ENA), val);
	val = (F_RXTXADDR_EN | F_RXTXADDR_VALID);
	wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_ENA), val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_ENA), val);

	/* Set high and low water levels for FIFO 0 */
	val = 0;
	if (hw->func_caps.common_cap.num_txq == 8)
		highline = 0x250;
	else
		highline = N20_FIFO0_DFT_DEEP - 2048;
	// downline = 128;
	downline = 64;
	FORMAT_FLAG(val, highline, 16, 16);
	FORMAT_FLAG(val, downline, 16, 0);
	wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO_N_LEAVEL(0)), val);
	/* Set high and low water levels for FIFO 1-7 */
	for (i = 1; i < 8; i++) {
		highline = 12;
		downline = 4;
		FORMAT_FLAG(val, highline, 16, 16);
		FORMAT_FLAG(val, downline, 16, 0);
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO_N_LEAVEL(i)),
		     val);
	}
}

void n20_setup_rx_buffer(struct mce_hw *hw)
{
	int i;
	u32 val, pri2val = 0;
	struct mce_pf *pf = (struct mce_pf *)hw->back;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg = &(dcb->cur_pfccfg);
	u32 lowfifo = 0, highfifo = 0;
	u32 highline, downline;
	// reset rx buffer and pri_map
	n20_enable_proc(hw);

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		u8 id = pfccfg->rx_pri2buf[i];

		val = 0;
		FORMAT_FLAG(val, pfccfg->fifo_head[i], 16, 16); //head
		FORMAT_FLAG(val, pfccfg->fifo_tail[i], 16, 0);  //tail
		wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_N_RAM(i)), val);
		FORMAT_FLAG(pri2val, id, 4, (4 * i));
		if (id < 4) //The first four FIFOs
			lowfifo |= ((1 << (i + (8 * id))));
		else //The last four FIFOs
			highfifo |= ((1 << (i + (8 * (id - 4)))));
		// setup down/high line
		highline = pfccfg->fifo_depth[i] - N20_UP_DEEP_FOR_FIFO;
		downline = 0x40;
		val = 0;
		FORMAT_FLAG(val, highline, 16, 16);
		FORMAT_FLAG(val, downline, 16, 0);
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO_N_LEAVEL(i)),
		     val);
	}
	wr32(hw, N20_ETH_OFF(N20_ETH_RX_UP2FIFO_MAP), pri2val);
	wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO03_PRIO), lowfifo);
	wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO47_PRIO), highfifo);

	n20_disable_proc(hw);
}

void n20_enable_pfc(struct mce_hw *hw, struct mce_dcb *dcb)
{
	struct mce_pfc_cfg *pfccfg = &(dcb->cur_pfccfg);
	struct mce_pf *pf = (struct mce_pf *)hw->back;
	u32 highline = 0; //high waterline
	u32 downline = 0; //low waterline
	u32 val = 0, dma_pfc = 0;
	u32 tmp = 0;
	u32 rdma_en = 0;
	u32 rem_deep = 0;
	u32 rx_fifo_thresh[N20_FIFO_PROG_CNT] = {
		0x9a, 0x9a, 0x9a, 0x9a,
		0x9a, 0x9a, 0x9a, 0x9a
	};
	u32 paus_tx_cdc_fifo_thresh = 480;
	u32 prio_fifo[8] = {0};
	u8 fifo_cnt = 0;
	u8 i = 0;

	/* Stop transmitting and receiving packets. */
	// maybe error ?
	//printk("call enable pfc\n");
	n20_enable_proc(hw);

	/* Configure the size of space used for FIFO 0-7 */
	/* if not all pro, we use 1 more fifo for other not enable prio */
	if (pfccfg->enacnt < MCE_MAX_PRIORITY)
		fifo_cnt = pfccfg->enacnt + 1;
	else
		fifo_cnt = MCE_MAX_PRIORITY;

	val = 0x20;

	for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
		wr32(hw, N20_ETH_OFF(N20_ETH_PORT_TX_PROGFULL(i)),
		     val);
		wr32(hw, N20_ETH_OFF(N20_ETH_PORT_RX_PROGFULL(i)),
		     rx_fifo_thresh[i]);
	}

	val = rd32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0));
	FORMAT_FLAG(val, paus_tx_cdc_fifo_thresh, 9, F_TX_CDC);
	wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0), val);

	/* set fifo size */
	tmp = 0; // head base
	val = 0;
	rem_deep = N20_FIFO_TAL_DEEP;

#ifndef HAVE_NETIF_SET_TSO_MAX
	if (fifo_cnt <= (MAX_PFC_NO_TSO_MAX_SET + 1)) {
#endif
		for (i = 0; i < fifo_cnt; i++) {
			u32 deep_per_fifo = (u32)DIV_ROUND_UP(rem_deep,
					(fifo_cnt - i));
			u32 head = tmp;
			u32 tail = head + deep_per_fifo - 1;
			u32 value;

			FORMAT_FLAG(val, head, 16, 16); //head
			FORMAT_FLAG(val, tail, 16, 0);  //tail
			if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
				wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_N_RAM(i)), val);
				pfccfg->fifo_head[i] = head;
				pfccfg->fifo_tail[i] = tail;
				pfccfg->fifo_depth[i] = deep_per_fifo;
			}
			wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_N_RAM(i)), val);
			rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_FIFO_FULL_TH(i)), deep_per_fifo * 2 / 3);

			value = rd32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)));

			if (!(i % 2)) {
				/* reserv 3 */
				FORMAT_FLAG(value, deep_per_fifo - 3, 13, 0);
				/* update new to hw */
				FORMAT_FLAG(value, 0x2, 2, 14);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
				FORMAT_FLAG(value, 0x3, 2, 14);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
			} else {

				/* reserv 3 */
				FORMAT_FLAG(value, deep_per_fifo - 3, 13, 16);
				/* update new to hw */
				FORMAT_FLAG(value, 0x2, 2, 30);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
				FORMAT_FLAG(value, 0x3, 2, 30);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
			}
			tmp += deep_per_fifo;
			rem_deep -= deep_per_fifo;
		}
		/* Priorty i map to FIFO */
		tmp = 0; // for fifo id
		val = 0;
		dma_pfc = 0;
		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			if ((pfccfg->pfcena & (1 << i)) != 0) {
				prio_fifo[i] = (pfccfg->enacnt - 1 - tmp);
				rdma_en |= (1 << i);
				dma_pfc |= (0x8 << (4 * i));
				tmp++;
			} else {
				/* not valid pfc use the last fifo */
				// if not en pfc fifo_depth more than tso
				//printk("prio %d fifo %d tsoneed %d\n", i, pfccfg->fifo_depth[i], MAX_DMA_NEED_FOR_TSO);
				prio_fifo[i] = (fifo_cnt - 1);
				if (pfccfg->fifo_depth[prio_fifo[i]] > MAX_DMA_NEED_FOR_TSO)	
					dma_pfc |= (0x8 << (4 * i));
			}
			FORMAT_FLAG(val, prio_fifo[i], 4, (4 * i));
			FORMAT_FLAG(dma_pfc, prio_fifo[i], 3, (4 * i));
			// setup for rdma
			rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO(i)), prio_fifo[i]);

		}
		/* setup for dma */
		wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_SELECT), dma_pfc);
		//rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_HOL_BLOCKING_EN), rdma_en);

		if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
			wr32(hw, N20_ETH_OFF(N20_ETH_RX_UP2FIFO_MAP), val);

		wr32(hw, N20_ETH_OFF(N20_ETH_TX_UP2FIFO_MAP), val);

#ifndef HAVE_NETIF_SET_TSO_MAX
	} else if (pfccfg->enacnt == MCE_MAX_PRIORITY) {
		rem_deep = N20_FIFO_TAL_DEEP - N20_RESEVER;
		/* we set the last to 0.5 fifo, and not open dma */
		for (i = 0; i < fifo_cnt; i++) {
			u32 deep_per_fifo, head, tail, value;

			// can do 
			if (i == (fifo_cnt - 1)) {
				deep_per_fifo = N20_RESEVER;
			} else {
				/* we resrv one */
				deep_per_fifo = (u32)DIV_ROUND_UP(rem_deep,
					(fifo_cnt - i - 1));
			}

			head = tmp;
			tail = head + deep_per_fifo - 1;

			FORMAT_FLAG(val, head, 16, 16); //head
			FORMAT_FLAG(val, tail, 16, 0);  //tail

			if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
				wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_N_RAM(i)), val);
				pfccfg->fifo_head[i] = head;
				pfccfg->fifo_tail[i] = tail;
				pfccfg->fifo_depth[i] = deep_per_fifo;
			}
			wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_N_RAM(i)), val);
			rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_FIFO_FULL_TH(i)), deep_per_fifo * 2 / 3);

			value = rd32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)));

			if (!(i % 2)) {
				/* reserv 3 */
				FORMAT_FLAG(value, deep_per_fifo - 3, 13, 0);
				/* update new to hw */
				FORMAT_FLAG(value, 0x2, 2, 14);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
				FORMAT_FLAG(value, 0x3, 2, 14);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
			} else {

				/* reserv 3 */
				FORMAT_FLAG(value, deep_per_fifo - 3, 13, 16);
				/* update new to hw */
				FORMAT_FLAG(value, 0x2, 2, 30);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
				FORMAT_FLAG(value, 0x3, 2, 30);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
			}

			tmp += deep_per_fifo;
			rem_deep -= deep_per_fifo;
		}

		/* Priorty i map to FIFO */
		tmp = 0; // for fifo id
		val = 0;
		dma_pfc = 0;
		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			if ((pfccfg->pfcena & (1 << i)) != 0) {
				prio_fifo[i] = (pfccfg->enacnt - 1 - tmp);
				rdma_en |= (1 << i);
				// not open dma for prio 0
				if (i != 0)
					dma_pfc |= (0x8 << (4 * i));
				tmp++;
			} else {
				/* not valid pfc use the last fifo */
				// if not en pfc fifo_depth more than tso
				prio_fifo[i] = (fifo_cnt - 1);
				//printk("prio %d fifo %d tsoneed %d\n", i, pfccfg->fifo_depth[i], MAX_DMA_NEED_FOR_TSO);
				if (pfccfg->fifo_depth[prio_fifo[i]] > MAX_DMA_NEED_FOR_TSO)	
					dma_pfc |= (0x8 << (4 * i));
			}
			FORMAT_FLAG(val, prio_fifo[i], 4, (4 * i));
			FORMAT_FLAG(dma_pfc, prio_fifo[i], 3, (4 * i));
			// setup for rdma
			rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO(i)), prio_fifo[i]);
		}
		/* setup for dma */
		wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_SELECT), dma_pfc);
		//rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_HOL_BLOCKING_EN), rdma_en);

		if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
			wr32(hw, N20_ETH_OFF(N20_ETH_RX_UP2FIFO_MAP), val);

		wr32(hw, N20_ETH_OFF(N20_ETH_TX_UP2FIFO_MAP), val);
	} else {
		/* must 7 pfc, we set not valid fifo */
		rem_deep = N20_FIFO_TAL_DEEP - N20_RESEVER;
		/* we set the last to 0.5 fifo, and not open dma */
		for (i = 0; i < fifo_cnt; i++) {
			u32 deep_per_fifo, head, tail, value;

			// can do 
			if (i == (fifo_cnt - 1)) {
				deep_per_fifo = N20_RESEVER;
			} else {
				// we resv one 
				deep_per_fifo = (u32)DIV_ROUND_UP(rem_deep,
					(fifo_cnt - i - 1));
			}

			head = tmp;
			tail = head + deep_per_fifo - 1;

			FORMAT_FLAG(val, head, 16, 16); //head
			FORMAT_FLAG(val, tail, 16, 0);  //tail
			if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
				wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_N_RAM(i)), val);
				pfccfg->fifo_head[i] = head;
				pfccfg->fifo_tail[i] = tail;
				pfccfg->fifo_depth[i] = deep_per_fifo;
			}
			wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_N_RAM(i)), val);
			rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_FIFO_FULL_TH(i)), deep_per_fifo * 2 / 3);

			value = rd32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)));

			if (!(i % 2)) {
				/* reserv 3 */
				FORMAT_FLAG(value, deep_per_fifo - 3, 13, 0);
				/* update new to hw */
				FORMAT_FLAG(value, 0x2, 2, 14);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
				FORMAT_FLAG(value, 0x3, 2, 14);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
			} else {

				/* reserv 3 */
				FORMAT_FLAG(value, deep_per_fifo - 3, 13, 16);
				/* update new to hw */
				FORMAT_FLAG(value, 0x2, 2, 30);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
				FORMAT_FLAG(value, 0x3, 2, 30);
				wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_DEPTH(i / 2)), value);
			}

			tmp += deep_per_fifo;
			rem_deep -= deep_per_fifo;
			pfccfg->fifo_depth[i] = deep_per_fifo;
		}

		/* Priorty i map to FIFO */
		tmp = 0; // for fifo id
		val = 0;
		dma_pfc = 0;
		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			if ((pfccfg->pfcena & (1 << i)) != 0) {
				prio_fifo[i] = (pfccfg->enacnt - 1 - tmp);
				rdma_en |= (1 << i);
				dma_pfc |= (0x8 << (4 * i));
				tmp++;
			} else {
				/* not valid pfc use the last fifo */
				// if not en pfc fifo_depth more than tso
				prio_fifo[i] = (fifo_cnt - 1);
				//printk("prio %d fifo %d tsoneed %d\n", i, pfccfg->fifo_depth[i], MAX_DMA_NEED_FOR_TSO);
				if (pfccfg->fifo_depth[prio_fifo[i]] > MAX_DMA_NEED_FOR_TSO)	
					dma_pfc |= (0x8 << (4 * i));
			}
			FORMAT_FLAG(val, prio_fifo[i], 4, (4 * i));
			FORMAT_FLAG(dma_pfc, prio_fifo[i], 3, (4 * i));
			// setup for rdma
			rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO(i)), prio_fifo[i]);
		}
		/* setup for dma */
		wr32(hw, N20_DMA_OFF(N20_PFC_FIFO_SELECT), dma_pfc);
		//rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_HOL_BLOCKING_EN), rdma_en);

		if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
			wr32(hw, N20_ETH_OFF(N20_ETH_RX_UP2FIFO_MAP), val);

		wr32(hw, N20_ETH_OFF(N20_ETH_TX_UP2FIFO_MAP), val);
	}
#endif
	/* Set default FIFO for packets that is not PSP or DSCP */
	wr32(hw, N20_ETH_OFF(N20_ETH_RX_DEFAULT_FIFO), (fifo_cnt - 1));
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TXMUX_CTRL));
	FORMAT_FLAG(val, (fifo_cnt - 1), 3, 24);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXMUX_CTRL),val);

	/* enable fifo drop */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TXMUX_CTRL));
	FORMAT_FLAG(val, 0xff, 8, 0);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXMUX_CTRL),val); // debug

	/* Make the configuration about FIFO space take effect */
	val = 0;
	val = F_RXTXADDR_EN;
	wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_ENA), val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_ENA), val);
	val = (F_RXTXADDR_EN | F_RXTXADDR_VALID);
	wr32(hw, N20_ETH_OFF(N20_ETH_RXADDR_ENA), val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXADDR_ENA), val);

	/* FIFO i map to Priorty (bitmap) */
	val = 0; // first four FIFOs prio
	tmp = 0; // last  four FIFOs prio
	wr32(hw, N20_ETH_OFF(N20_ETH_TXFIFO03_PRIO), val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXFIFO47_PRIO), tmp);
	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO03_PRIO), val);
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO47_PRIO), tmp);
	}
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		u8 id = prio_fifo[i];

		if (id < 4) //The first four FIFOs
			val |= ((1 << (i + (8 * id))));
		else //The last four FIFOs
			tmp |= ((1 << (i + (8 * (id - 4)))));

		/* store it */
		if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
			pfccfg->rx_pri2buf[i] = prio_fifo[i];
	}
	wr32(hw, N20_ETH_OFF(N20_ETH_TXFIFO03_PRIO), val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXFIFO47_PRIO), tmp);
	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO03_PRIO), val);
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO47_PRIO), tmp);
	}

	/* Set high and low water levels for FIFO 0-7 */
	val = 0;
	for (i = 0; i < fifo_cnt; i++) {
		if (hw->func_caps.common_cap.num_txq == 8) {
			highline = 0x250;
			downline = 0x40;
		} else {
			highline = pfccfg->fifo_depth[i] - N20_UP_DEEP_FOR_FIFO;
			downline = 0x40;
		}
		FORMAT_FLAG(val, highline, 16, 16);
		FORMAT_FLAG(val, downline, 16, 0);
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO_N_LEAVEL(i)),
		     val);
	}

	/* open pfc for the priorty */
	// only do this if open ?
	val = rd32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL));
	val &= (~F_RX_PAUSE_EN);
	val &= (~F_TX_PAUSE_EN);
	FORMAT_FLAG(val, pfccfg->pfcena, 8, 16); //rx
	FORMAT_FLAG(val, pfccfg->pfcena, 8, 24); //tx
	wr32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL), val);

	/* open rx fifo RR mode */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RXMUX_CTRL));
	val &= (~(F_MAC_RR_MODE | F_MAC_WRR_MODE));
	if (hw->rx_wrr_en) {
		val |= F_MAC_WRR_MODE;
		for (i = 0; i < 8; i++)
			wr32(hw, N20_ETH_OFF(N20_ETH_RXMUX_WRR(i)), hw->vmark[i]);
	} else { 
		val |= F_MAC_RR_MODE;
		for (i = 0; i < 8; i++)
			wr32(hw, N20_ETH_OFF(N20_ETH_RXMUX_WRR(i)), 0);
	}
	wr32(hw, N20_ETH_OFF(N20_ETH_RXMUX_CTRL), val);
	// if set wrr, setup here

	/* open tx fifo RR mode */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC));
	FORMAT_FLAG(val, 1, 1, 9);
	FORMAT_FLAG(val, 0, 1, 8);
	wr32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC), val);

	/* enalbe post crtl pfc */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_EMAC_POST_CTRL));
	val |= F_EMAC_PFC_EN;
	wr32(hw, N20_ETH_OFF(N20_ETH_EMAC_POST_CTRL), val);

	/* setup pfc lock 1000ms count */
	wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL1), 1000 * N20_USECSTOCOUNT);

	val = 0;
	val |= PFC_LOCK_EN;
#define LOCK_TIME (10000)
	val |= (LOCK_TIME << 16) | LOCK_TIME;
	for (i = 0; i < fifo_cnt; i++) {
		wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL(i)), val); 	
	}

	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_DEADLOCK_VALUE), 100);
	/* Start transmitting and receiving packets. */
	// setup rr for rx ?
	// update me later
	n20_disable_proc(hw);
}

void n20_disable_pfc(struct mce_hw *hw)
{
	u32 val = 0;
	u32 dflt_thresh[N20_FIFO_PROG_CNT] = {
		0x100, 0x8, 0x8, 0x8,
		0x8, 0x8, 0x8, 0x8
	};
	struct mce_pf *pf = (struct mce_pf *)hw->back;
	u32 dflt_tx_cdc_fifo_thresh = 352;
	u8 i = 0;

	printk("call stop enable pfc\n");
	/* Stop transmitting and receiving packets. */
	n20_enable_proc(hw);

	/* set tso fifo thresh */
	wr32(hw, N20_ETH_OFF(N20_ETH_TSO_IFIFO_THRESH), 0x100);
	wr32(hw, N20_ETH_OFF(N20_ETH_TSO_DATA_THRESH),  0x80100);
	wr32(hw, N20_ETH_OFF(N20_ETH_TSO_OFIFO_THRESH), 0x100);

	/* set fifo default threshold */
	for (i = 0; i < N20_FIFO_PROG_CNT; i ++) {
		wr32(hw, N20_ETH_OFF(N20_ETH_PORT_TX_PROGFULL(i)),
		     dflt_thresh[i]);
		wr32(hw, N20_ETH_OFF(N20_ETH_PORT_RX_PROGFULL(i)),
		     dflt_thresh[i]);
		// setup default value
		rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_FIFO_FULL_TH(i)), 512);
	}

	val = rd32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0));
	FORMAT_FLAG(val, dflt_tx_cdc_fifo_thresh, 9, F_TX_CDC);
	wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0), val);

	n20_set_dft_fifo_space(hw);

	/* Priorty i map to FIFO i */
	val = 0;

	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags))
		wr32(hw, N20_ETH_OFF(N20_ETH_RX_UP2FIFO_MAP), val);

	wr32(hw, N20_ETH_OFF(N20_ETH_TX_UP2FIFO_MAP), val);

	for (i = 0; i < MCE_MAX_PRIORITY; i++)
		rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_CFG_PRIO(i)), 0);

	//rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_HOL_BLOCKING_EN), 0);


	/* FIFO i map to Priorty (bitmap)*/
	val = 0;
	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO03_PRIO), val);
		wr32(hw, N20_ETH_OFF(N20_ETH_RXFIFO47_PRIO), val);
	}
	wr32(hw, N20_ETH_OFF(N20_ETH_TXFIFO03_PRIO), val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXFIFO47_PRIO), val);

	/* reset pfc for the priorty */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL));
	FORMAT_FLAG(val, 0, 8, 16); //rx
	FORMAT_FLAG(val, 0, 8, 24); //tx
	wr32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL), val);

	/* disable post crtl pfc */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_EMAC_POST_CTRL));
	val &= ~F_EMAC_PFC_EN;
	wr32(hw, N20_ETH_OFF(N20_ETH_EMAC_POST_CTRL), val);

	/* Set default FIFO for packets that is not PSP or DSCP */
	wr32(hw, N20_ETH_OFF(N20_ETH_RX_DEFAULT_FIFO), 0);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TXMUX_CTRL));
	FORMAT_FLAG(val, 0, 3, 24);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXMUX_CTRL),val); // debug
	/* disable fifo drop */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TXMUX_CTRL));
	FORMAT_FLAG(val, 0, 8, 0);
	wr32(hw, N20_ETH_OFF(N20_ETH_TXMUX_CTRL),val); // debug

	/* disable rx fifo RR mode */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_RXMUX_CTRL));
	val &= ~F_MAC_RR_MODE;
	wr32(hw, N20_ETH_OFF(N20_ETH_RXMUX_CTRL), val);
	/* disable tx fifo rr mode */
	val = rd32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC));
	FORMAT_FLAG(val, 0, 1, 9);
	wr32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC), val);

	for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
		wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL(i)), 0); 	
	}
	/* Start transmitting and receiving packets. */
	n20_disable_proc(hw);
}

void n20_set_q_to_pfc(struct mce_hw *hw,
		      struct mce_dcb *dcb)
{
	struct mce_tc_cfg *tccfg = &(dcb->cur_tccfg);
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_ring *txq = NULL;
	int ring_base;
	u32 val = 0;
	u16 j = 0;
	u8 i = 0;
	u16 z = 0;

	/* setup pfc to queue map */
	if (!tccfg->tc_cnt) {

		/* if tc is 0; ets not open */
		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			u16 base = tccfg->pfc_txq_base[0][i];
			u16 qcnt = tccfg->pfc_txq_count[0][i];

			for (j = 0; j < qcnt; j++) {
				if (base + j > vsi->num_txq)
					break;
				txq = vsi->tx_rings[base + j];
				val = ring_rd32(txq, N20_DMA_REG_TX_PRIO_LVL);
				FORMAT_FLAG(val, 0, 8, 0);
				val |= F_RING_PFC_EN;
				val |= (1 << i);
				ring_wr32(txq, N20_DMA_REG_TX_PRIO_LVL, val);
			}
		}

	} else {
		/* should setup pfc info for each tc */
		for (z = 0; z < tccfg->tc_cnt; z++) {
			ring_base = tccfg->qg_base_off * z * MCE_MAX_QCNT_IN_QG;
			for (i = 0; i < MCE_MAX_PRIORITY; i++) {
				//u16 base = tccfg->pfc_txq_base[z][i];
				u16 base = ring_base + tccfg->pfc_txq_base[z][i];
				u16 qcnt = tccfg->pfc_txq_count[z][i];

				if (tccfg->tc_prios_bit[z] & (1 << i)) {
					// if this prio valid in this tc
					/* setup it to hw */
					for (j = 0; j < qcnt; j++) {
						if (base + j > vsi->num_txq)
							break;
						txq = vsi->tx_rings[base + j];
						if (!txq->q_vector) {
							//printk("%s skip q %d\n", __func__, (base + j));
							continue;
						}
						val = ring_rd32(txq, N20_DMA_REG_TX_PRIO_LVL);
						FORMAT_FLAG(val, 0, 8, 0);
						val |= F_RING_PFC_EN;
						val |= (1 << i);
						ring_wr32(txq, N20_DMA_REG_TX_PRIO_LVL, val);
					}
				}
			}
		}
	}
}

void n20_clr_q_to_pfc(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_ring *txq = NULL;
	u16 qid = 0;
	u32 val = 0;

	for (qid = 0; qid < vsi->num_txq; qid++) {
		txq = vsi->tx_rings[qid];

		if (!txq->q_vector) {
			//printk("%s skip tx queue %d\n", __func__, qid);
			continue;
		}
		val = ring_rd32(txq, N20_DMA_REG_TX_PRIO_LVL);
		val &= ~F_RING_PFC_EN;
		FORMAT_FLAG(val, 0, 8, 0);
		ring_wr32(txq, N20_DMA_REG_TX_PRIO_LVL, val);
	}
}

void n20_set_dscp(struct mce_hw *hw, struct mce_dcb *dcb)
{
	u32 val = 0;
	u8 i = 0, j = 0, k = 0;

	for (i = 0; i < 8; i++) {
		val = 0;
		for (j = 0; j < 8; j++) {
			FORMAT_FLAG(val, dcb->dscp_map[k], 4, (4 * j));
			k++;
		}
		wr32(hw, N20_ETH_OFF(N20_ETH_RX_DSCP2UP_MAP(i)), val);
		wr32(hw, N20_ETH_OFF(N20_ETH_TX_DSCP2UP_MAP(i)), val);
		rdma_wr32(hw, N20_RDMA_BTH(N20_RDMA_DSCP_TABLE(i)), val);
	}

	// the last 8 dscp use fixed prio 7
	rdma_wr32(hw, N20_RDMA_BTH(N20_RDMA_DSCP_TABLE(7)), 0x77777777);

	val = rd32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL));
	if (test_bit(MCE_DSCP_EN, dcb->flags)) {
		val |= F_DSCP_MODE_EN;
		rdma_wr32(hw, N20_RDMA_BTH(N20_RDMA_PRIO_TYPE), 1);
	} else {
		val &= ~F_DSCP_MODE_EN;
		rdma_wr32(hw, N20_RDMA_BTH(N20_RDMA_PRIO_TYPE), 0);
	}
	wr32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL), val);
}
