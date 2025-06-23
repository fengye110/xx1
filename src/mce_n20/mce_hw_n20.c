#include "../mce.h"
#include "../mce_fdir.h"
#include "../mce_vf_lib.h"
#include "../mce_lib.h"
#include "../mce_mbx.h"
#include "../mce_base.h"
#include "mce_hw_n20.h"
#include "mce_hw_debugfs.h"
#include "mce_hw_dcb.h"
#include "mce_hw_npu.h"
#include "mce_hw_ptp.h"
#include "mce_hw_fdir.h"

static void __n20_init_vport_bitmap_clear_ram(struct mce_hw *hw)
{
	int i;

	for (i = 0; i < 1024; i++) {
		wr32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_BITMAP_MEM0(i)),
		     0);
		wr32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_BITMAP_MEM1(i)),
		     0);
		wr32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_BITMAP_MEM2(i)),
		     0);
		wr32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_BITMAP_MEM3(i)),
		     0);
	}
}

static void __n20_init_etype_clear_ram(struct mce_hw *hw)
{
	int i, j;

	for (i = 0; i < MCE_LIMIT_VFS; i++) {
		for (j = 0; j < 16; j++) {
			wr32(hw, N20_ETH_RQA_ETQF_OFF(i, j), 0);
			wr32(hw, N20_ETH_RQA_ETQS_OFF(i, j), 0);
		}
	}
}

static void __n20_init_fd_clear_ram(struct mce_hw *hw)
{
	/* TODO: */
}

static void __n20_init_mbx_clear_ram(struct mce_hw *hw)
{
	int i = 0;

	for (i = 0; i < 2048; i++)
		wr32(hw, 0x30000 + i * 4, 0x0);
}

static void __n20_init_vport_mc_vlan_clear_ram(struct mce_hw *hw)
{
	/* clear vf muiticast filter table */
	hw->vf.ops->set_vf_clear_mc_filter(hw, false);
	/* clear vf vlan filter table */
	hw->vf.ops->set_vf_clear_vlan_filter(hw);
}

static void __n20_init_rss_clear_ram(struct mce_hw *hw)
{
	int i, j;

#define __N20_RSS_HASH_ENTRY(i, j) ((0x0000 + ((j) << 2)) + (i) * 0x40)
	for (i = 0; i < MCE_LIMIT_VFS; i++) {
		for (j = 0; j < 14; j++)
			wr32(hw, N20_RSS_OFF(__N20_RSS_HASH_ENTRY(i, j)),
			     0);
	}
}

static void n20_reset_hw(struct mce_hw *hw)
{
	u32 val;
	int time = 0;
	/* reset nic */
	wr32(hw, N20_NIC_OFF(N20_NIC_RESET), 0 | F_NIC_RESET_MASK);
	udelay(1000);
	wr32(hw, N20_NIC_OFF(N20_NIC_RESET),
	     F_NIC_RESET_EN | F_NIC_RESET_MASK);
	udelay(1000);
	/* reset rdma */ 
	rdma_wr32(hw, N20_RDMA_BTH(0x1c), 1);
	
	do {
		val = rdma_rd32(hw, N20_RDMA_BTH(0x20));
		udelay(1000);
		time++;
		if (time > 10) {
			printk("reset rdma timeout\n");
			break;
		}
	} while(val != 1); 

	if (time < 10) {
		rdma_wr32(hw, N20_RDMA_BTH(0x18), 0);
		udelay(1000);
		rdma_wr32(hw, N20_RDMA_BTH(0x18), 1);
		udelay(1000);
		rdma_wr32(hw, N20_RDMA_BTH(0x1c), 0);
		printk("reset rdma ok\n");
	}
	/* mask all msic intrrupt when nic reset */
	hw->ops->set_misc_irq_mask(hw, MCE_MAC_MISC_IRQ_ALL, true);
	wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR), 0x0);
	/* clear nic ram */
	__n20_init_vport_bitmap_clear_ram(hw);
	__n20_init_etype_clear_ram(hw);
	__n20_init_fd_clear_ram(hw);
	__n20_init_vport_mc_vlan_clear_ram(hw);
	__n20_init_rss_clear_ram(hw);
	__n20_init_mbx_clear_ram(hw);
}

static void n20_init_hw(struct mce_hw *hw)
{
	int i = 0;
	u32 val = 0;

	/* clean DMA AXI */
	wr32(hw, N20_DMA_OFF(N20_DMA_AXI_EN), 0);
	while (rd32(hw, N20_DMA_OFF(N20_DMA_AXI_STATUS)) == 0)
		;

#ifdef MCE_TX_WB_COAL
	val = rd32(hw, N20_DMA_OFF(N20_DMA_CONFIG));
	val |= F_TX_WB_EN;
	FORMAT_FLAG(val, 2, 2, 2); //设置为32个一回写
	wr32(hw, N20_DMA_OFF(N20_DMA_CONFIG), val);
#endif

#ifdef MCE_RX_WB_COAL
	val = rd32(hw, N20_DMA_OFF(N20_DMA_CONFIG));
	val |= F_RX_WB_EN;
	FORMAT_FLAG(val, 1, 2, 0); //设置为2个一回写
	wr32(hw, N20_DMA_OFF(N20_DMA_CONFIG), val);
#endif

	// 2 write back is ok, it is 64bytes
	// we default setup rx 
//	val = rd32(hw, N20_DMA_OFF(N20_DMA_CONFIG));
//	FORMAT_FLAG(val, 1, 2, 0); //设置为2个一回写
//	wr32(hw, N20_DMA_OFF(N20_DMA_CONFIG), val);

	/* enable hw rx dim (just enable not start) */
	/* setup dim sample_inval 1ms */
//	val = rd32(hw, N20_DMA_OFF(N20_DMA_CONFIG));
//	FORMAT_FLAG(val, 1, 2, 28);
//	wr32(hw, N20_DMA_OFF(N20_DMA_CONFIG), val);

	/* get MAC addr */
	val = rd32(hw, N20_NIC_OFF(N20_NIC_MAC_OUI));
	hw->port_info->perm_addr[0] = ((val >> 16) & 0xff);
	hw->port_info->perm_addr[1] = ((val >> 8) & 0xff);
	hw->port_info->perm_addr[2] = (val & 0xff);
	val = rd32(hw, N20_NIC_OFF(N20_NIC_MAC_SN));
	if (val == 0) {
		memset(hw->port_info->perm_addr, 0, ETH_ALEN);
	} else {
		hw->port_info->perm_addr[3] = ((val >> 16) & 0xff);
		hw->port_info->perm_addr[4] = ((val >> 8) & 0xff);
		hw->port_info->perm_addr[5] = (val & 0xff);
	}

	/* clean VLAN type in nic */
	for (i = 0; i < 8; i++) {
		wr32(hw, N20_ETH_OFF(N20_ETH_VLAN_TPID(i)), 0);
		wr32(hw, N20_ETH_OFF(N20_ETH_O_VLAN_TYPE(i)), 0);
		wr32(hw, N20_ETH_OFF(N20_ETH_I_VLAN_TYPE(i)), 0);
	}
	/* set VLAN type that we can support */
	wr32(hw, N20_ETH_OFF(N20_ETH_VLAN_TPID(0)), ETH_P_8021Q);
	wr32(hw, N20_ETH_OFF(N20_ETH_VLAN_TPID(1)), ETH_P_8021AD);
	wr32(hw, N20_ETH_OFF(N20_ETH_O_VLAN_TYPE(0)), ETH_P_8021Q);
	wr32(hw, N20_ETH_OFF(N20_ETH_O_VLAN_TYPE(1)), ETH_P_8021AD);
	wr32(hw, N20_ETH_OFF(N20_ETH_I_VLAN_TYPE(0)), ETH_P_8021Q);
	wr32(hw, N20_ETH_OFF(N20_ETH_I_VLAN_TYPE(1)), ETH_P_8021AD);

	/* enable redirection (rss rx_csum) */
	if (hw->func_caps.common_cap.num_txq == 8) {
		// chengjian no fd
		wr32(hw, N20_ETH_OFF(N20_ETH_RQA_CTRL),
		     (F_REDIR_EN | F_RSS_EN | F_MULTI_FILTER_TABLE_EN |
		     F_VF_VLAN_FLR_EN | F_ARP_RSS_EN | 0x3f));
	} else {
		wr32(hw, N20_ETH_OFF(N20_ETH_RQA_CTRL),
		     (F_REDIR_EN | F_FD_EN | F_RSS_EN | F_MULTI_FILTER_TABLE_EN |
		     F_VF_VLAN_FLR_EN | F_ARP_RSS_EN | F_ETYPE_EN | F_TUPLE5_EN |
		     0x3f));
	}

	/* enable L2 filter */
	set_bit(DMAC_FILTER_EN, hw->l2_fltr_flags);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));
	val |= (F_L2_FILTER_EN | F_DMAC_FILTER_EN);
	val |= (F_BC_BYPASS_EN | F_UC_SEL | F_MC_SEL);
	/* close rdma in default */
	val &= (~BIT(8));
	wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), val);

	/* defalut turn on vport attr vlan promisc */
	hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX, true);
	/* default turn off vport vtag filter. */
	hw->vf.ops->set_vf_set_vtag_vport_en(hw, PFINFO_IDX, false);
	wr32(hw, N20_ETH_OFF(N20_ETH_EMAC_POST_CTRL),
	     F_PORT_CTRL_MUL_ANTI_SPOOF_EN);
	/* setup default to rdma */
	rdma_wr32(hw, N20_RDMA_DCNQCN_OFF(N20_RDMA_US_VALUE), N20_USECSTOCOUNT);

	val = rd32(hw, N20_MSIX_OFF(N20_IRQ_MB_ST_CLR));
	val |= F_IRQ_AVOID_DROP_INTR_EN;
	wr32(hw, N20_MSIX_OFF(N20_IRQ_MB_ST_CLR), val);
	/* setup esp udp port */
	for (i = 0; i < 8; i++)
		wr32(hw, N20_ETH_OFF(N20_ETH_IPSEC_PORT + i * 4),
		     MCE_TC_FLWR_IPSEC_NAT_T_PORT0);
	wr32(hw, N20_ETH_OFF(N20_ETH_IPSEC_PORT),
	     MCE_TC_FLWR_IPSEC_NAT_T_PORT1);
	hw->ops->set_ucmc_hash_type_fltr(hw);
}

/**
 * n20_enable_proc_old - 使能接收和发送方向的异常处理
 * @hw:  ptr to the hw
 */
void n20_enable_proc_old(struct mce_hw *hw)
{
	u32 val = 0;

	val = rd32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_RX_PROC));
	val |= 1;
	wr32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_RX_PROC), val);

	/*
	val = rd32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC));
	val |= 1;
	wr32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC), val);
	*/
}

/**
 * n20_enable_proc - 使能接收和发送方向的异常处理
 * @hw:  ptr to the hw
 */
void n20_enable_proc(struct mce_hw *hw)
{
	u32 val = 0;
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi;
	int time = 0;
	u32 target;

	vsi = mce_get_main_vsi(pf);
	/* first stop tx */
	rdma_wr32(hw, N20_RDMA_BTH(N20_RDMA_TX_RX_ENABLE), 0);

	set_bit(MCE_VSI_DROP_TX, vsi->state);
	usleep_range(1000, 2000);
	/* check tx fifo empty */
	if (pf->max_pf_rxqs == 8)
		target = 0xff3fffff;
	else
		target = 0xffffffff;
	do {
		val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_DEBUG0));
		usleep_range(100, 200);
		time++;
		
	} while ((val != target) && (time < 100));

	if (time == 100)
		printk("wait tx fifo timeout\n");
	time = 0;
	do {
		val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_DEBUG4));
		usleep_range(100, 200);
		time++;

	} while ((val != 0xffffffff) && (time < 100));

	if (time == 100)
		printk("wait rx fifo timeout\n");
	time = 0;
	if (pf->max_pf_rxqs == 8)
		target = 0xffff;
	else
		target = 0x3fff;
	do {
		val = rd32(hw, N20_ETH_OFF(N20_ETH_RX_DEBUG5));
		usleep_range(100, 200);
		time++;

	} while ((val != target) && (time < 100));

	if (time == 100)
		printk("wait rx fifo timeout debug5\n");

	val = rd32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_RX_PROC));
	val |= 1;
	wr32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_RX_PROC), val);

	/*
	val = rd32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC));
	val |= 1;
	wr32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC), val);
	*/
}

/**
 * n20_disable_proc - 关闭接收和发送方向的异常处理
 * @hw:  ptr to the hw
 */
void n20_disable_proc(struct mce_hw *hw)
{
	u32 val = 0;
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_vsi *vsi;

	vsi = mce_get_main_vsi(pf);

	val = rd32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_RX_PROC));
	val &= ~1;
	wr32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_RX_PROC), val);

	val = rd32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC));
	val &= ~1;
	wr32(hw, N20_ETH_OFF(N20_ETH_EXCEPT_TX_PROC), val);

	rdma_wr32(hw,  N20_RDMA_BTH(N20_RDMA_TX_RX_ENABLE), 3);

	clear_bit(MCE_VSI_DROP_TX, vsi->state);
}

static void n20_enable_axi_tx(struct mce_hw *hw)
{
	u32 dma_axi_ctl;

	dma_axi_ctl = rd32(hw, N20_DMA_OFF(N20_DMA_AXI_EN));
	dma_axi_ctl |= F_TX_AXI_RW_EN;
	dma_axi_ctl |= F_TX_AXI_RW_MS;
	wr32(hw, N20_DMA_OFF(N20_DMA_AXI_EN), dma_axi_ctl);
}

static void n20_disable_axi_tx(struct mce_hw *hw)
{
	u32 dma_axi_ctl;

	dma_axi_ctl = rd32(hw, N20_DMA_OFF(N20_DMA_AXI_EN));
	dma_axi_ctl &= ~(F_TX_AXI_RW_EN);
	dma_axi_ctl |= F_TX_AXI_RW_MS;
	wr32(hw, N20_DMA_OFF(N20_DMA_AXI_EN), dma_axi_ctl);
}

static void n20_enable_axi_rx(struct mce_hw *hw)
{
	u32 dma_axi_ctl;

	dma_axi_ctl = rd32(hw, N20_DMA_OFF(N20_DMA_AXI_EN));
	dma_axi_ctl |= F_RX_AXI_RW_EN;
	dma_axi_ctl |= F_RX_AXI_RW_MS;
	wr32(hw, N20_DMA_OFF(N20_DMA_AXI_EN), dma_axi_ctl);
}

static void n20_disable_axi_rx(struct mce_hw *hw)
{
	u32 dma_axi_ctl;

	dma_axi_ctl = rd32(hw, N20_DMA_OFF(N20_DMA_AXI_EN));
	dma_axi_ctl &= ~(F_RX_AXI_RW_EN);
	dma_axi_ctl |= F_RX_AXI_RW_MS;
	wr32(hw, N20_DMA_OFF(N20_DMA_AXI_EN), dma_axi_ctl);
}

#ifdef MCE_13P_DEBUG_MSIX
enum mce_ring_type {
        MCE_RING_TYPE_TX,
        MCE_RING_TYPE_RX
};

#define MCE_RING_VEC_RXID_MASK        GENMASK(10, 0)
#define MCE_RING_VEC_TXID_MASK        GENMASK(21, 11)
#define MCE_RING_VEC_TXID_S           (11)
#define MCE_RING_VEC_VFID_MASK        GENMASK(30, 24)
#define MCE_RING_VEC_VFID_S           (24)
#define MCE_RING_VEC_SRIOV_EN         BIT(31)

#define BIT_TO_BYTES(bit)              ((bit) / 8)
#define _MSIX_EX_(off)                 ((off) + (0x20000 + 0x10000))
#define MCE_RING_VEC_C(n)              _MSIX_EX_(0x7000 + ((n) * BIT_TO_BYTES(32)))
static int mce_intr_bind(struct mce_hw *hw,
                        enum mce_ring_type type,
                        uint16_t q_id, uint16_t vec_id)
{
        uint32_t reg = 0;

        reg = rd32(hw, MCE_RING_VEC_C(q_id));
#if 0
       if (hw->is_vf) {
               reg &= ~RNPCE_RING_VEC_VFID_MASK;
               reg |= hw->sriov << RNPCE_RING_VEC_VFID_S;
       }
#endif
        if (type == MCE_RING_TYPE_RX) {
                reg &= ~MCE_RING_VEC_RXID_MASK;
                reg |= vec_id;
               //printk("rx reg 0x%.2x\n", reg);
        }
        if (type == MCE_RING_TYPE_TX) {
                reg &= ~MCE_RING_VEC_TXID_MASK;
                reg |= vec_id << MCE_RING_VEC_TXID_S;
        }
        wr32(hw, MCE_RING_VEC_C(q_id), reg);

        return 0;
}

static int mce_intr_unbind(struct mce_hw *hw, enum mce_ring_type type, uint16_t q_id)
{

       uint32_t reg = 0;

        reg = rd32(hw, N20_MSIX_OFF(N20_MSIX_RING_VEC(q_id)));
	reg &= ~MCE_RING_VEC_VFID_MASK;
        if (type == MCE_RING_TYPE_RX) {
                reg &= ~MCE_RING_VEC_RXID_MASK;
        }
        if (type == MCE_RING_TYPE_TX) {
                reg &= ~MCE_RING_VEC_TXID_MASK;
        }
        wr32(hw, N20_MSIX_OFF(N20_MSIX_RING_VEC(q_id)), reg);

        return 0;
}
#endif

static void n20_cfg_vec2tqirq(struct mce_hw *hw, u16 vec, u16 tirq)
{
#ifdef MCE_13P_DEBUG_MSIX
       //(void *)val;
       //printk("txq[%d] bind to vec %d\n", vec, tirq);
       if (tirq)
               mce_intr_bind(hw, MCE_RING_TYPE_TX, vec, tirq);
       else
               mce_intr_unbind(hw, MCE_RING_TYPE_TX, vec);
#else
	u32 val = 0;
#ifndef MCE_DEBUG_XINSI_PCIE
	val = rd32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))));
	FORMAT_FLAG(val, 0, 16, 16);
	FORMAT_FLAG(val, tirq, 8, 8);
	wr32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))), val);
#else
	val = rd32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))));
	val &= ~BIT(31);
	FORMAT_FLAG(val, tirq, 11, 11);
	wr32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))), val);
#endif /* _MCE_DEBUG_XINSI_PCIE_ */
#endif /* _MCE_13P_DEBUG_MSIX_ */
}

static void n20_cfg_vec2rqirq(struct mce_hw *hw, u16 vec, u16 rirq)
{
#ifdef MCE_13P_DEBUG_MSIX
       //(void *)val;
       //printk("rxq[%d] bind to vec %d\n", vec, rirq);
       if (rirq)
               mce_intr_bind(hw, MCE_RING_TYPE_RX, vec, rirq);
       else
               mce_intr_unbind(hw, MCE_RING_TYPE_RX, vec);
#else
	u32 val = 0;
#ifndef MCE_DEBUG_XINSI_PCIE

	val = rd32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))));
	FORMAT_FLAG(val, 0, 16, 16);
	FORMAT_FLAG(val, rirq, 8, 0);
	wr32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))), val);
#else
	val = rd32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))));
	val &= ~BIT(31);
	FORMAT_FLAG(val, rirq, 11, 0);
	wr32(hw, N20_MSIX_OFF((N20_MSIX_RING_VEC(vec))), val);
#endif /* _MCE_DEBUG_XINSI_PCIE_ */
#endif /* _MCE_13P_DEBUG_MSIX_ */
}

static int n20_set_vf_update_vm_macaddr(struct mce_hw *hw, u8 *mac_addr,
					u32 index, bool active)
{
	u32 rar_lo = 0, rar_hi = 0;
	u32 val = 0;
	int err = 0;

	rar_lo = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
		  (((u32)(mac_addr[3])) << 16) |
		  (((u32)(mac_addr[2])) << 24));

	rar_hi = (u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8;
	if (!active) {
		rar_lo = 0;
		rar_hi = 0;
	}
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_DMAC_RAH(index)), rar_hi);
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_DMAC_RAL(index)), rar_lo);
	val = rd32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_IPORT_PVF(index)));
	val = active ? val | F_MAC_FILTER_PVF_EN :
		       val & ~F_MAC_FILTER_PVF_EN;
	val |= F_MATCH_TYPE_PVF_EN;
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_IPORT_PVF(index)), val);

	return err;
}

static int n20_set_vf_update_vm_default_vlan(struct mce_hw *hw, int index)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);

	vf->t_info.vlanid = 0xfff;
	mce_vf_set_veb_misc_rule(hw, index, __VEB_POLICY_TYPE_UC_ADD_VLAN);
	return 0;
}

#define __MCE_MC_FILTER_PER_BANK (8)
static bool __is_mc_filter_bank1(int avail_id)
{
	return !!(avail_id >= __MCE_MC_FILTER_PER_BANK);
}

static void __config_vf_mc_mac_to_bank(struct mce_hw *hw, int num,
				       int avail_id, bool en,
				       const u8 *mac_addr)
{
	u32 t_mac = 0, val = 0, idx = 0;

	if (num)
		avail_id -= __MCE_MC_FILTER_PER_BANK;

	if (avail_id % 2) {
		idx = (avail_id / 2) * 3 + 1;
		t_mac = (u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8);
		// t_mac <<= 16;
		if (!en)
			t_mac = 0;
		val = rd32(hw, N20_ETH_VF_MC_OFF(
				       num, N20_FPGA_VFNUM(hw, PFINFO_IDX),
				       idx));
		FORMAT_FLAG(val, t_mac, 16, 16);
		wr32(hw,
		     N20_ETH_VF_MC_OFF(num, N20_FPGA_VFNUM(hw, PFINFO_IDX),
				       idx),
		     val);
		t_mac = (u32)(mac_addr[0]) << 24 |
			(u32)(mac_addr[1]) << 16 |
			(u32)(mac_addr[2]) << 8 | (u32)(mac_addr[3]) << 0;
		if (!en)
			t_mac = 0;
		wr32(hw,
		     N20_ETH_VF_MC_OFF(num, N20_FPGA_VFNUM(hw, PFINFO_IDX),
				       idx + 1),
		     t_mac);
	} else {
		idx = (avail_id / 2) * 3;
		t_mac = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
			 (((u32)(mac_addr[3])) << 16) |
			 (((u32)(mac_addr[2])) << 24));
		if (!en)
			t_mac = 0;
		wr32(hw,
		     N20_ETH_VF_MC_OFF(num, N20_FPGA_VFNUM(hw, PFINFO_IDX),
				       idx),
		     t_mac);
		val = rd32(hw, N20_ETH_VF_MC_OFF(
				       num, N20_FPGA_VFNUM(hw, PFINFO_IDX),
				       idx + 1));
		t_mac = ((u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8);
		if (!en)
			t_mac = 0;
		FORMAT_FLAG(val, t_mac, 16, 0);
		wr32(hw,
		     N20_ETH_VF_MC_OFF(num, N20_FPGA_VFNUM(hw, PFINFO_IDX),
				       idx + 1),
		     val);
	}
}

static void n20_set_vf_clear_mc_filter(struct mce_hw *hw, bool only_pf)
{
	int i, vfnum = 0, vfs_cnt = 0;

	vfs_cnt = only_pf ? 1 : MCE_LIMIT_VFS;
	for (vfnum = 0; vfnum < vfs_cnt; vfnum++) {
		for (i = 0; i < 0x40; i += 4) {
			wr32(hw, N20_ETH_VF_MC_OFF(0, vfnum, i / 4), 0);
			wr32(hw, N20_ETH_VF_MC_OFF(1, vfnum, i / 4), 0);
		}
	}
}

static void n20_set_vf_true_promisc(struct mce_hw *hw, int vfid, bool on)
{
	u32 val, idx;

	idx = N20_FPGA_VFNUM(hw, vfid);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TRUE_PROMISC_VPORT_ADDR(idx)));

	on ? F_SET_TRUE_PROMISC_VPORT_CTRL(idx, val) :
	     F_CLR_TRUE_PROMISC_VPORT_CTRL(idx, val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TRUE_PROMISC_VPORT_ADDR(idx)), val);
}

static void n20_set_vf_rqa_tcp_sync_en(struct mce_hw *hw, bool on)
{
	u32 val;

	val = rd32(hw, N20_ETH_OFF(N20_ETH_RQA_CTRL));
	val = on ? val | F_TCP_SYNC_EN : val & ~F_TCP_SYNC_EN;
	wr32(hw, N20_ETH_OFF(N20_ETH_RQA_CTRL), val);
}

static void n20_set_vf_rqa_tcp_sync_remapping(struct mce_hw *hw, int vfnum,
					      struct mce_tcpsync *tcpsync)
{
	u32 val, idx;

	idx = N20_FPGA_VFNUM(hw, vfnum);
	val = tcpsync->acl.data;
	wr32(hw, N20_RQA_TCP_SYNC_OFF(N20_RQA_TCP_SYNC_ACL(idx)), val);
	val = tcpsync->pri.data;
	wr32(hw, N20_RQA_TCP_SYNC_OFF(N20_RQA_TCP_SYNC_PRI(idx)), val);
}

static bool __mce_check_user_config_dma_qs_invalid(int user_qs)
{
	if (user_qs < MCE_VF_DMA_QS_START ||
	    user_qs >= MCE_VF_DMA_QS_UNDEFINED)
		return true;
	return false;
}

static int n20_set_vf_bw_limit_init(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	u32 val = 0, qgnum;

	if (__mce_check_user_config_dma_qs_invalid(hw->qos.qg_mode))
		return -1;

	qgnum = hw->qos.qg_mode - MCE_VF_DMA_QS_START;
	val |= F_VF_LIMIT_EN;
	F_SET_VF_QG_NUM(val, qgnum);
	wr32(hw, N20_DMA_OFF(N20_DMA_VF_QG_CTRL), val);

	val |= F_TC_EN | F_TC_BP_MOD;
	val |= F_TC_CRC | F_TC_INTERAL_EN;
	val |= hw->qos.interal << F_TC_INTERAL_OFFSET;
	/* tc0~7 mode setup ETS mode*/
	val |= 0xffff;
	wr32(hw, N20_DMA_OFF(N20_DMA_TC_CTRL), val);

	return 0;
}

static int n20_set_vf_bw_limit_rate(struct mce_pf *pf, int vf_id,
				    u64 max_tx_rate, u16 ring_cnt)
{
#define __MCE_TM_RATE_UNIT (512)
	struct mce_hw *hw = &pf->hw;
	u32 val = 0, data, hw_rate;
	int idx, qg_offset, qg_num, i, j;

	idx = N20_FPGA_VFNUM(hw, vf_id);
	qg_num = mce_int_pow(2, hw->qos.qg_mode - MCE_VF_DMA_QS_START);
	qg_offset = qg_num * idx;

	if (ring_cnt > qg_num * 4)
		return 0;
	/* calc real rate */
	// should update later
	hw_rate = (max_tx_rate / hw->qos.rate) / __MCE_TM_RATE_UNIT;
	wr32(hw, N20_DMA_OFF(N20_DMA_TC_VF_QG_BYTE_LIMIT(idx)), hw_rate);

	printk("call n20_set_vf_bw_limit_rate\n");
	for (i = qg_offset; i < qg_offset + qg_num; i++) {
		val = 0;
		for (j = 0; j < 4; j++) {
			/* one qg include 4 rings */
			if (ring_cnt)
				val |= BIT(j);
			else
				break;
			ring_cnt--;
		}
		data = rd32(hw, N20_DMA_OFF(N20_DMA_TC_QG_CTRL(i)));
		FORMAT_FLAG(data, val, 4, 8);
		wr32(hw, N20_DMA_OFF(N20_DMA_TC_QG_CTRL(i)), data);
	}

	return 0;
}

static void n20_set_vf_rebase_ring_base(struct mce_hw *hw)
{
	u32 val;
#if defined(MCE_DEBUG_XINSI_PCIE) || defined(MCE_DEBUG_VF)
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		hw->ring_max_cnt =
			mce_int_pow(2, MCE_USER_CONFIG_VF_DMA_QS + 2);
#if defined(MCE_DEBUG_XINSI_PCIE)
		hw->ring_base_addr = N20_MAX_Q_CNT - hw->ring_max_cnt;
		wr32(hw, N20_MSIX_OFF(N20_MSIX_CFG_VF_NUM),
		     N20_MAX_RING_CNT / hw->ring_max_cnt);
#else
		hw->ring_base_addr = 0;
		wr32(hw, N20_MSIX_OFF(N20_MSIX_CFG_VF_NUM), 128);
#endif
	} else
#endif
	{
		hw->ring_max_cnt = N20_MAX_Q_CNT;
		hw->ring_base_addr = 0;
		/* default 128 vfs */
		wr32(hw, N20_MSIX_OFF(N20_MSIX_CFG_VF_NUM), 128);
	}
	/* setup vf default ring */
	val = rd32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(
			       N20_FPGA_VFNUM(hw, PFINFO_IDX))));
	F_SET_VPORT_DEFAULT_RING(val, hw->ring_base_addr);
	wr32(hw,
	     N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(
		     N20_FPGA_VFNUM(hw, PFINFO_IDX))),
	     val);
}

static void n20_set_vf_clear_vlan_filter(struct mce_hw *hw)
{
	int i, vfnum = 0;

	for (vfnum = 0; vfnum < MCE_LIMIT_VFS; vfnum++) {
		for (i = 0; i < MCE_MAX_VF_VLAN_WHITE_LISTS; i++) {
			wr32(hw, N20_ETH_VF_VLAN_OFF(vfnum, i), 0);
		}
	}
}

static void n20_set_vf_set_vlan_promisc(struct mce_hw *hw, int vfid,
					bool on)
{
	u32 val;

	val = rd32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(
			       N20_FPGA_VFNUM(hw, vfid))));
	if (on)
		val |= F_VPORT_VLAN_PROMISC_EN;
	else
		val &= (~F_VPORT_VLAN_PROMISC_EN);

	wr32(hw,
	     N20_ETH_VPORT_OFF(
		     N20_ETH_VPORT_ATTR_TABLE(N20_FPGA_VFNUM(hw, vfid))),
	     val);
}

static void n20_set_vf_set_vtag_vport_en(struct mce_hw *hw, int vfid,
					 bool on)
{
	u32 val, idx;

	idx = N20_FPGA_VFNUM(hw, vfid);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_VTAG_VPORT_FILTER_ADDR(idx)));

	on ? F_SET_VTAG_VPORT_FILTER_CTRL(idx, val) :
	     F_CLR_VTAG_VPORT_FILTER_CTRL(idx, val);
	wr32(hw, N20_ETH_OFF(N20_ETH_VTAG_VPORT_FILTER_ADDR(idx)), val);
}

static void n20_set_vf_add_mc_fliter(struct mce_hw *hw, const u8 *mac_addr)
{
	int avail_id;
	u32 num = 0;

	avail_id =
		find_first_zero_bit(hw->avail_mc, MCE_MAX_MC_WHITE_LISTS);
	if (avail_id >= MCE_MAX_MC_WHITE_LISTS) {
		dev_err(mce_hw_to_dev(hw),
			"vf:%d the multicast nums exceeds maximum allowed:%d\n",
			N20_FPGA_VFNUM(hw, PFINFO_IDX),
			MCE_MAX_MC_WHITE_LISTS);
		return;
	}

	if (__is_mc_filter_bank1(avail_id))
		num = 1;
	set_bit(avail_id, hw->avail_mc);
	hw->mc_info[avail_id].en = true;
	ether_addr_copy(hw->mc_info[avail_id].addr, mac_addr);
	__config_vf_mc_mac_to_bank(hw, num, avail_id, true, mac_addr);
}

static void n20_set_vf_del_mc_filter(struct mce_hw *hw, const u8 *mac_addr)
{
	int id, num = 0;
	u8 addr[ETH_ALEN];

	for (id = 0; id < MCE_MAX_MC_WHITE_LISTS; id++) {
		if (hw->mc_info[id].en) {
			if (ether_addr_equal(hw->mc_info[id].addr,
					     mac_addr))
				break;
		}
	}
	if (id >= MCE_MAX_MC_WHITE_LISTS) {
		dev_err(mce_hw_to_dev(hw),
			"vf:%d not found mc addr:%02x:%02x:%02x:%02x:%02x:%02x, cannot delete it\n",
			N20_FPGA_VFNUM(hw, PFINFO_IDX), mac_addr[0],
			mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4],
			mac_addr[5]);
		return;
	}
	if (__is_mc_filter_bank1(id)) {
		num = 1;
	}
	__config_vf_mc_mac_to_bank(hw, num, id, false, mac_addr);
	clear_bit(id, hw->avail_mc);
	hw->mc_info[id].en = false;
	memset(addr, 0, ETH_ALEN);
	ether_addr_copy(hw->mc_info[id].addr, addr);
}

static void n20_set_vf_add_vlan_filter(struct mce_hw *hw, int vfid,
				       int entry)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 val = 0;

	val = rd32(hw,
		   N20_ETH_VF_VLAN_OFF(N20_FPGA_VFNUM(hw, vfid), entry));
	if (entry % 2)
		FORMAT_FLAG(val, vf->t_info.vlanid, 16, 16);
	else
		FORMAT_FLAG(val, vf->t_info.vlanid, 16, 0);
	wr32(hw, N20_ETH_VF_VLAN_OFF(N20_FPGA_VFNUM(hw, vfid), entry),
	     val);
}

static void n20_set_vf_del_vlan_filter(struct mce_hw *hw, int vfid,
				       int entry)
{
	u32 val = 0;

	val = rd32(hw,
		   N20_ETH_VF_VLAN_OFF(N20_FPGA_VFNUM(hw, vfid), entry));
	if (entry % 2)
		FORMAT_FLAG(val, 0, 16, 16);
	else
		FORMAT_FLAG(val, 0, 16, 0);
	wr32(hw, N20_ETH_VF_VLAN_OFF(N20_FPGA_VFNUM(hw, vfid), entry),
	     val);
}

static void n20_set_vf_set_veb_act(struct mce_hw *hw, int vfid, int entry,
				   bool set,
				   enum mce_flag_type set_bcmc_bitmap)
{
	u32 val = 0;

	/* uc/bcmc action */
	val = rd32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_T4_ACT_PVF(entry)));
	if (set) {
		if (vfid != PFINFO_BCMC)
			F_SET_VM_MATCH_INDEX(val,
					     N20_VM_T4_VF_UC_INDEX(entry));
		else
			F_SET_VM_MATCH_INDEX(val, entry);
	} else {
		F_SET_VM_MATCH_INDEX(val, 0);
	}
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_T4_ACT_PVF(entry)), val);

	if (vfid != PFINFO_BCMC) {
		/* uc bitmap */
		val = rd32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_SET_BITMAP(
				       N20_FPGA_VFNUM(hw, vfid),
				       N20_VM_T4_VF_UC_INDEX(entry))));
		if (set)
			val |= BIT(N20_FPGA_VFNUM(hw, vfid));
		else
			val &= ~BIT(N20_FPGA_VFNUM(hw, vfid));
		wr32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_SET_BITMAP(
			     N20_FPGA_VFNUM(hw, vfid),
			     N20_VM_T4_VF_UC_INDEX(entry))),
		     val);
		if (set_bcmc_bitmap == MCE_F_HOLD)
			goto out;
		entry = hw->vf_bcmc_addr_offset;
		val = rd32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_SET_BITMAP(
				       N20_FPGA_VFNUM(hw, vfid), entry)));
		if (set_bcmc_bitmap == MCE_F_SET)
			val |= BIT(N20_FPGA_VFNUM(hw, vfid));
		if (set_bcmc_bitmap == MCE_F_CLEAR)
			val &= ~BIT(N20_FPGA_VFNUM(hw, vfid));
		wr32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_SET_BITMAP(
			     N20_FPGA_VFNUM(hw, vfid), entry)),
		     val);
	} else {
		/* bcmc bitmap */
		entry = hw->vf_bcmc_addr_offset;
		vfid = PFINFO_IDX;
		wr32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_SET_BITMAP(
			     N20_FPGA_VFNUM(hw, vfid), entry)),
		     BIT(N20_FPGA_VFNUM(hw, vfid)));
	}
out:
	return;
}

static int n20_update_fltr_macaddr(struct mce_hw *hw, u8 *mac_addr,
				   u32 index, bool active)
{
	u32 rar_lo = 0;
	u32 rar_hi = 0;
	int err = 0;

	rar_lo = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
		  (((u32)(mac_addr[3])) << 16) |
		  (((u32)(mac_addr[2])) << 24));

	rar_hi = ((u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8);
	if (!active)
		memset(mac_addr, 0x0, ETH_ALEN);
	rar_hi = active ? rar_hi | F_MAC_FLTR_EN : rar_hi & ~F_MAC_FLTR_EN;
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_FLTR_DMAC_RAH(index)), rar_hi);
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_FLTR_DMAC_RAL(index)), rar_lo);

	return err;
}

static void n20_set_max_pktlen(struct mce_hw *hw, u32 mtu)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 value = 0, max_len;
	u32 vfid = 0;

	/*mtu + mac_hdr + 2 vlan_hdr + fcs*/
	max_len = mtu + 14 + 2 * 4 + 4;
	if (pf->priv_h.en)
		max_len += pf->priv_h.len;
	vfid = N20_FPGA_VFNUM(hw, PFINFO_IDX);
	value = rd32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(vfid)));
	value &= ~(F_VPORT_DROP);
	value |= F_VPORT_LIMIT_LEN_EN;
	F_SET_VPORT_MAX_LEN(value, max_len); // clean max len
	wr32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(vfid)), value);
}

/**
 * n20_set_rx_csumofld - Enable or disable the function of the rx checksum offload at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_rx_csumofld(struct mce_hw *hw,
				netdev_features_t features)
{
	u32 value = 0;

	value = rd32(hw, N20_ETH_OFF(N20_ETH_RQA_CTRL));

	if (features & NETIF_F_RXCSUM)
		value &= (~F_RX_CSM_MASK);
	else
		value |= F_RX_CSM_MASK;

	wr32(hw, N20_ETH_OFF(N20_ETH_RQA_CTRL), value);
}

static void n20_set_vf_vlan_strip(struct mce_hw *hw, int vf_id, bool en)
{
	int i = 0;
	u32 value = 0;
	u32 strip_en;
	u32 strip_cnt, offset;
	u16 txq_cnt = hw->func_caps.common_cap.vf_num_txq;

	if (en) {
		strip_en = 1;
		strip_cnt = 1;
	} else {
		strip_en = 0;
		strip_cnt = 0;
	}
	/* TODO: for FPGA, vf id offset need plus 4 */
	vf_id = N20_FPGA_VFNUM(hw, vf_id);
	offset = vf_id * txq_cnt;
	for (i = offset; txq_cnt + offset; i++) {
		value = rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
		F_SET_VLAN_STRIP_EN(value, strip_en);
		F_SET_VLAN_STRIP_CNT(value, strip_cnt);
#ifdef MCE_DEBUG_VF
		F_SET_RETA_HASH_QUEUE_ID(value, 0);
#endif
		wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), value);
	}
}

static int n20_set_vf_rss_table(struct mce_hw *hw, int vf_id, u16 q_cnt)
{
	u16 i = 0, offset, vfnum = N20_FPGA_VFNUM(hw, vf_id);
	u32 act_reta = 0, vft_reta = 0, val;
	u32 table_size = hw->func_caps.common_cap.rss_table_size;

	if (!q_cnt)
		q_cnt = table_size;

	offset = vfnum * table_size;
	for (i = offset; i < table_size + offset; i++) {
		val = (i - offset) % q_cnt;
		hw->rss_table[i - offset] = val;
		if (i % 2 == 0) {
			vft_reta = val & 0xffff;
		} else {
			vft_reta |= val << 16;
			wr32(hw,
			     N20_RSS_OFF(N20_RSS_VFT_CONFIG_MEM(i / 2)),
			     vft_reta);
		}
		act_reta =
			rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
		act_reta |= (F_RSS_RETA_QUEUE_EN | F_RSS_RETA_MASK_EN);
		wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), act_reta);
	}
	return 0;
}

static void n20_clear_vf_all_rss_table(struct mce_hw *hw)
{
	u32 i;

	for (i = 0; i < 256; i++)
		wr32(hw, N20_RSS_OFF(N20_RSS_VFT_CONFIG_MEM_BASE(i)), 0);
}

static int __set_vf_spoofchk_mac(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 rar_lo, rar_hi, val, idx;
	u8 *mac_addr = vf->vfinfo[vfid].vf_mac_addresses;

	idx = N20_FPGA_VFNUM(hw, vfid);
	rar_lo = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
		  (((u32)(mac_addr[3])) << 16) |
		  (((u32)(mac_addr[2])) << 24));

	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_SMAC_RAL(idx)),
	     rar_lo);

	val = rd32(hw,
		   N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx)));
	val &= 0xffff0000;
	rar_hi = ((u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8);
	val |= rar_hi;
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx)),
	     val);
	return 0;
}

static int n20_set_vf_spoofchk_mac(struct mce_hw *hw, int vfid, bool en,
				   bool setmac)
{
	u32 val, idx;

	idx = N20_FPGA_VFNUM(hw, vfid);
	val = rd32(hw,
		   N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx)));

	val = en ? val | F_ANTI_SPOOF_MAC_VALID :
		   val & ~(F_ANTI_SPOOF_MAC_VALID);
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx)),
	     val);

	if (setmac) {
		__set_vf_spoofchk_mac(hw, vfid);
	}

	return 0;
}

static int __set_vf_spoofchk_vlan(struct mce_hw *hw, int vfid,
				  enum mce_vf_antivlan_ctrl vlanctrl)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 val, idx;

	if (vlanctrl == MCE_VF_ANTI_VLAN_HOLD)
		return 0;

	idx = N20_FPGA_VFNUM(hw, vfid);
	val = rd32(hw,
		   N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx)));
	if (vlanctrl == MCE_VF_ANTI_VLAN_CLEAR)
		F_SET_ANTI_SPOOF_VLAN_ID(val, 0);
	else
		F_SET_ANTI_SPOOF_VLAN_ID(val, vf->vfinfo[vfid].pf_vlan);
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx)),
	     val);
	return 0;
}

static int n20_set_vf_spoofchk_vlan(struct mce_hw *hw, int vfid, bool en,
				    enum mce_vf_antivlan_ctrl vlanctrl)
{
	u32 val, idx;

	idx = N20_FPGA_VFNUM(hw, vfid);
	val = rd32(hw,
		   N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx)));

	val = en ? val | F_ANTI_SPOOF_VLAN_VALID :
		   val & ~(F_ANTI_SPOOF_VLAN_VALID);
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_ANTI_VTAG_SMAC_RAH(idx)),
	     val);
	__set_vf_spoofchk_vlan(hw, vfid, vlanctrl);
	return 0;
}

static int n20_set_vf_trusted(struct mce_hw *hw, int vfid, bool on)
{
	u32 val, idx;

	idx = N20_FPGA_VFNUM(hw, vfid);
	val = rd32(hw, N20_ETH_OFF(N20_ETH_TRUSTED_VPORT_ADDR(idx)));

	on ? F_SET_TRUSTED_VPORT_CTRL(idx, val) :
	     F_CLR_TRUSTED_VPORT_CTRL(idx, val);
	wr32(hw, N20_ETH_OFF(N20_ETH_TRUSTED_VPORT_ADDR(idx)), val);

	return 0;
}

static int n20_set_vf_default_vport(struct mce_hw *hw, int vfid)
{
	u32 val = 0, idx;

	idx = N20_FPGA_VFNUM(hw, vfid);

	wr32(hw, N20_ETH_OFF(N20_ETH_DEFAULT_VPORT_ADDR(0)), 0);
	wr32(hw, N20_ETH_OFF(N20_ETH_DEFAULT_VPORT_ADDR(1)), 0);
	wr32(hw, N20_ETH_OFF(N20_ETH_DEFAULT_VPORT_ADDR(2)), 0);
	wr32(hw, N20_ETH_OFF(N20_ETH_DEFAULT_VPORT_ADDR(3)), 0);

	F_SET_DEFAULT_VPORT_CTRL(idx, val);
	wr32(hw, N20_ETH_OFF(N20_ETH_DEFAULT_VPORT_ADDR(idx)), val);

	return 0;
}

static int n20_set_vf_recv_ximit_by_self(struct mce_hw *hw, bool on)
{
	u32 val;

	val = rd32(hw, N20_ETH_OFF(N20_ETH_FWD_CTRL));
	val = on ? val | F_RX_SELF_EN : val & ~F_RX_SELF_EN;
	wr32(hw, N20_ETH_OFF(N20_ETH_FWD_CTRL), val);

	return 0;
}

static int n20_set_vf_trust_vport_en(struct mce_hw *hw, bool on)
{
	u32 val;

	val = rd32(hw, N20_ETH_OFF(N20_ETH_FWD_CTRL));
	val = on ? val | F_TRUST_VPORT_EN : val & ~F_TRUST_VPORT_EN;
	wr32(hw, N20_ETH_OFF(N20_ETH_FWD_CTRL), val);
	if (on)
		hw->vf.ops->set_vf_emac_post_ctrl(
			hw, MCE_VF_VEB_VLAN_OUTER1, false,
			MCE_VF_POST_CTRL_ALLIN_TO_TXTRANS_AND_RX, true);
	else
		hw->vf.ops->set_vf_emac_post_ctrl(
			hw, MCE_VF_VEB_VLAN_OUTER1, false,
			MCE_VF_POST_CTRL_FILTER_TX_TO_RX, true);
	return 0;
}

static void n20_stat_update32(struct mce_hw *hw, u32 reg, bool is_rdma,
			      bool flag_64, u64 *prev_stat, u64 *cur_stat)
{
	u64 new_data = 0;

	if (is_rdma) {
		if (flag_64)
			new_data = rdma_rd64(hw, reg);
		else
			new_data = rdma_rd32(hw, reg) & (BIT_ULL(32) - 1);
	} else {
		if (flag_64)
			new_data = rd64(hw, reg);
		else
			new_data = rd32(hw, reg) & (BIT_ULL(32) - 1);
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (new_data + BIT_ULL(32)) - *prev_stat;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

static void n20_get_hw_stats(struct mce_hw *hw,
			     struct mce_hw_stats *prev_stats,
			     struct mce_hw_stats *cur_stats)
{
	// consider vsi count
	// update nic value todo
	
	n20_stat_update32(hw, N20_ETH_PAUSE_TX, false, false,
			  &(prev_stats->pause_tx),
			  &(cur_stats->pause_tx));

	n20_stat_update32(hw, N20_ETH_PAUSE_RX, false, false,
			  &(prev_stats->pause_rx),
			  &(cur_stats->pause_rx));
	
	/* should trig reg first */
	rdma_wr32(hw, N20_RDMA_TRIG, 0xffffffff);

	n20_stat_update32(hw, N20_RDMA_TX_VPORT_UNICAST_PKTS, true, false,
			  &(prev_stats->tx_vport_rdma_unicast_packets),
			  &(cur_stats->tx_vport_rdma_unicast_packets));

	n20_stat_update32(hw, N20_RDMA_TX_VPORT_UNICAST_BYTS, true, true,
			  &(prev_stats->tx_vport_rdma_unicast_bytes),
			  &(cur_stats->tx_vport_rdma_unicast_bytes));

	n20_stat_update32(hw, N20_RDMA_RX_VPORT_UNICAST_PKTS, true, false,
			  &(prev_stats->rx_vport_rdma_unicast_packets),
			  &(cur_stats->rx_vport_rdma_unicast_packets));

	n20_stat_update32(hw, N20_RDMA_RX_VPORT_UNICAST_BYTS, true, true,
			  &(prev_stats->rx_vport_rdma_unicast_bytes),
			  &(cur_stats->rx_vport_rdma_unicast_bytes));

	n20_stat_update32(hw, N20_RDMA_NP_CNP_SENT, true, false,
			  &(prev_stats->np_cnp_sent),
			  &(cur_stats->np_cnp_sent));

	n20_stat_update32(hw, N20_RDMA_RP_CNP_HANDLED, true, false,
			  &(prev_stats->rn_cnp_handled),
			  &(cur_stats->rn_cnp_handled));

	n20_stat_update32(hw, N20_RDMA_NP_ECN_MARKED_ROCE_PACKETS, true,
			  false, &(prev_stats->np_ecn_marked_roce_packets),
			  &(cur_stats->np_ecn_marked_roce_packets));

	n20_stat_update32(hw, N20_RDMA_RP_CNP_IGNORED, true, false,
			  &(prev_stats->rp_cnp_ignored),
			  &(cur_stats->rp_cnp_ignored));

	n20_stat_update32(hw, N20_RDMA_OUT_OF_SEQUENCE, true, false,
			  &(prev_stats->out_of_sequence),
			  &(cur_stats->out_of_sequence));

	n20_stat_update32(hw, N20_RDMA_PACKET_SEQ_ERR, true, false,
			  &(prev_stats->packet_seq_err),
			  &(cur_stats->packet_seq_err));

	n20_stat_update32(hw, N20_RDMA_ACK_TIMEOUT_ERR, true, false,
			  &(prev_stats->ack_timeout_err),
			  &(cur_stats->ack_timeout_err));
}

static void n20_enable_txring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (ring == NULL)
		return;

	CLR_BIT(F_TX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_disable_txring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (ring == NULL)
		return;

	status = 0;
	SET_BIT(F_TX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_enable_txrxring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (ring == NULL)
		return;

	CLR_BIT(F_TX_INT_MASK_EN_BIT, status);
	CLR_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_disable_txrxring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (ring == NULL)
		return;

	status = 0;
	SET_BIT(F_TX_INT_MASK_EN_BIT, status);
	SET_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_start_txring(struct mce_ring *tx_ring)
{
	if (tx_ring == NULL)
		return;

	/* enable queue */
	ring_wr32(tx_ring, N20_DMA_REG_TX_START, 1);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);
	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_TAIL, tx_ring->next_to_use);
}

static void n20_stop_txring(struct mce_ring *tx_ring)
{
	u32 head = 0;
	u32 tail = 0;
	u32 timeout = 0;

	if (tx_ring == NULL)
		return;

	do {
		usleep_range(30000, 50000);
		head = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_HEAD);
		tail = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_TAIL);
		if ((++timeout) > 200) {
			dev_err(tx_ring->dev,
				"200 wait tx-%u done timeout, "
				"head-%u tail-%u\n",
				tx_ring->q_index, head, tail);
			break;
		}
	} while (head != tail);

	// disable queue
	ring_wr32(tx_ring, N20_DMA_REG_TX_START, 0);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);
	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_TAIL, 0);
}

static void n20_set_rxring_hw_dim(struct mce_ring *rx_ring, bool enable)
{
	u32 reg = 0;
	struct mce_dim_cq_moder mce_rx_dim[2][MCE_HW_PROFILE] = {
		{ 
#ifdef MCE_RX_WB_COAL
// soc can remove this
		     {16, 256},
		     {16, 128},
#else
		     {2, 256},
		     {8, 128},
#endif
		     {16, 64},
		     {32, 64},
		     {64, 64}
		}, 
		{ 
		 // 2 is 1 since hw is 1 << x*/
		 // 1 << (fls(2) - 1) == 1 us
		     {2, 256},
		     {8, 256},
		     {64, 256},
		     {128, 256},
		     {256, 256}
		
		}
	};
	int i;
#define MCE_RX_DIM_MODE (0)

	if (!enable) {
		reg = ring_rd32(rx_ring, DMA_REG_RX_INT_FRAMES);
		FORMAT_FLAG(reg, 0, 1, 31);
		ring_wr32(rx_ring, DMA_REG_RX_INT_FRAMES, reg);
		return;
	}

	ring_wr32(rx_ring, DMA_REG_RX_PKT_RATE_LOW, IRQ_MIN_200K_RX);
	ring_wr32(rx_ring, DMA_REG_RX_PKT_RATE_HIGH, IRQ_MAX_200K_RX);
#ifdef STEP_DIM
	reg = ring_rd32(rx_ring, DMA_REG_RX_INT_FRAMES);
	FORMAT_FLAG(reg, 1, 1, 31);
	FORMAT_FLAG(reg, 1, 1, 30);
	FORMAT_FLAG(reg, 5, 8, 20);
	ring_wr32(rx_ring, DMA_REG_RX_INT_FRAMES, reg);
#else
	reg = ring_rd32(rx_ring, DMA_REG_RX_INT_FRAMES);
	FORMAT_FLAG(reg, 1, 1, 31);
	FORMAT_FLAG(reg, 1, 8, 20);

	FORMAT_FLAG(reg, 1, 2, 28);

	for (i = 0; i < MCE_HW_PROFILE; i++) {
		FORMAT_FLAG(reg, fls(mce_rx_dim[MCE_RX_DIM_MODE][i].pkts) - 1,
			4, (MCE_HW_PROFILE - i - 1) * 4);
	}
	ring_wr32(rx_ring, DMA_REG_RX_INT_FRAMES, reg);
	reg = ring_rd32(rx_ring, DMA_REG_RX_INT_USECS);
	for (i = 0; i < MCE_HW_PROFILE; i++) {
		FORMAT_FLAG(reg, fls(mce_rx_dim[MCE_RX_DIM_MODE][i].usec) - 1,
			4, (MCE_HW_PROFILE - i - 1) * 4);
	}
	ring_wr32(rx_ring, DMA_REG_RX_INT_USECS, reg);
#endif
}

static void n20_set_txring_hw_dim(struct mce_ring *tx_ring, bool enable)
{
	u32 reg = 0;
	struct mce_dim_cq_moder mce_tx_dim[2][MCE_HW_PROFILE] = {
		{ 
		     {5, 128},
		     {8, 64},
		     {16, 32},
		     {32, 32},
		     {64, 32}
		}, 
		{ 
		 // 2 is 1 since hw is 1 << x*/
		 // 1 << (fls(2) - 1) == 1 us
		     {2, 128},
		     {8, 128},
		     {32, 128},
		     {64, 128},
		     {128, 128}
		
		}
	};
	int i;
#define MCE_TX_DIM_MODE (1)

	if (!enable) {
		reg = ring_rd32(tx_ring, DMA_REG_TX_INT_FRAMES);
		FORMAT_FLAG(reg, 0, 1, 31);
		ring_wr32(tx_ring, DMA_REG_TX_INT_FRAMES, reg);
		return;
	}

	ring_wr32(tx_ring, DMA_REG_TX_PKT_RATE_LOW, IRQ_MIN_200K);
	ring_wr32(tx_ring, DMA_REG_TX_PKT_RATE_HIGH, IRQ_MAX_200K);
#ifdef STEP_DIM
	reg = ring_rd32(tx_ring, DMA_REG_TX_INT_FRAMES);
	FORMAT_FLAG(reg, 1, 1, 31);
	FORMAT_FLAG(reg, 1, 1, 30);
	FORMAT_FLAG(reg, 5, 8, 20);
	ring_wr32(tx_ring, DMA_REG_TX_INT_FRAMES, reg);
#else
	reg = ring_rd32(tx_ring, DMA_REG_TX_INT_FRAMES);
	FORMAT_FLAG(reg, 1, 1, 31);
	/* 1 << xx */
	FORMAT_FLAG(reg, 1, 8, 20);

	FORMAT_FLAG(reg, 1, 2, 28);


	for (i = 0; i < MCE_HW_PROFILE; i++) {
		FORMAT_FLAG(reg, fls(mce_tx_dim[MCE_TX_DIM_MODE][i].pkts) - 1,
			4, (MCE_HW_PROFILE - i - 1) * 4);
	}
	ring_wr32(tx_ring, DMA_REG_TX_INT_FRAMES, reg);

	reg = ring_rd32(tx_ring, DMA_REG_TX_INT_USECS);

	for (i = 0; i < MCE_HW_PROFILE; i++) {
		FORMAT_FLAG(reg, fls(mce_tx_dim[MCE_TX_DIM_MODE][i].usec) - 1,
			4, (MCE_HW_PROFILE - i - 1) * 4);
	}
	ring_wr32(tx_ring, DMA_REG_TX_INT_USECS, reg);
#endif
}

static void n20_set_txring_ctx(struct mce_ring *tx_ring, struct mce_hw *hw)
{
	struct mce_vsi *vsi = tx_ring->vsi;

	if (tx_ring == NULL || vsi == NULL)
		return;

	tx_ring->ring_addr =
		hw->eth_bar_base +
		N20_RING_OFF(tx_ring->q_index + hw->ring_base_addr);
	tx_ring->tail = tx_ring->ring_addr + N20_DMA_REG_TX_DESC_TAIL;
	tx_ring->next_to_use =
		ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_HEAD);
	tx_ring->next_to_clean = tx_ring->next_to_use;

	if (tx_ring->next_to_use > tx_ring->count)
		return;

	// disable queue
	ring_wr32(tx_ring, N20_DMA_REG_TX_START, 0);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_BASE_ADDR_LO,
		  (u32)tx_ring->dma);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_BASE_ADDR_HI,
		  (u32)((tx_ring->dma) >> 32));

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_FETCH_CTRL,
		  (56 << 0) | (4 << 16));

	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_TIMER,
		  tx_ring->q_vector->tx.dim_params.usecs *
			  N20_USECSTOCOUNT);

	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_PKTCNT,
		  tx_ring->q_vector->tx.dim_params.frames);

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TH, 0);

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TM, 0);
}

/* 设置tx队列的中断延时和帧数 */
static void n20_set_txring_intr_coal(struct mce_ring *tx_ring)
{
	struct mce_ring_container *tx = NULL;
	//u32 reg = 0;

	if (tx_ring == NULL)
		return;

	tx = &(tx_ring->q_vector->tx);
	if (tx == NULL)
		return;

	/* maybe not setup always? */
	//reg = ring_rd32(tx_ring, DMA_REG_TX_INT_FRAMES);
	//FORMAT_FLAG(reg, 0, 1, 31);
	//ring_wr32(tx_ring, DMA_REG_TX_INT_FRAMES, reg);

	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_TIMER,
		  tx->dim_params.usecs * N20_USECSTOCOUNT);

	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_PKTCNT,
		  tx->dim_params.frames);
}

static int n20_cfg_txring_bw_lmt(struct mce_ring *tx_ring, u32 maxrate)
{
	u32 th = (maxrate * 1000) >> 3;
	// chengjian is 120Mhz ?
	u32 tm = 1000 * 1000 * 12 / 100;

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TH, th);
	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TM, tm);

	return 0;
}

static void n20_enable_rxring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (ring == NULL)
		return;

	CLR_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_disable_rxring_irq(struct mce_ring *ring)
{
	u32 status = 0;

	if (ring == NULL)
		return;

	status = 0;
	SET_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_start_rxring(struct mce_ring *rx_ring)
{
	if (rx_ring == NULL)
		return;

	/* enable queue */
	ring_wr32(rx_ring, N20_DMA_REG_RX_START, 1);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, rx_ring->count);
	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TAIL, rx_ring->next_to_use);
}

static void n20_stop_rxring(struct mce_ring *rx_ring)
{
	if (rx_ring == NULL)
		return;

	// disable rxring
	ring_wr32(rx_ring, N20_DMA_REG_RX_START, 0);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, 0);
	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TAIL, 0);
}

static void n20_set_rxring_ctx(struct mce_ring *rx_ring, struct mce_hw *hw)
{
	struct mce_vsi *vsi = rx_ring->vsi;

	if (rx_ring == NULL || vsi == NULL) {
		return;
	}

	rx_ring->ring_addr =
		hw->eth_bar_base +
		N20_RING_OFF(rx_ring->q_index + hw->ring_base_addr);
	rx_ring->tail = rx_ring->ring_addr + N20_DMA_REG_RX_DESC_TAIL;
	rx_ring->next_to_use =
		ring_rd32(rx_ring, N20_DMA_REG_RX_DESC_HEAD);
	rx_ring->next_to_clean = rx_ring->next_to_use;

	if (rx_ring->next_to_use > rx_ring->count)
		return;

	// disable queue
	ring_wr32(rx_ring, N20_DMA_REG_RX_START, 0);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_BASE_ADDR_LO,
		  (u32)rx_ring->dma);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_BASE_ADDR_HI,
		  (u32)((rx_ring->dma) >> 32));

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, rx_ring->count);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_FETCH_CTRL,
		  (48 << 0) | (16 << 16));

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_TIMER,
		  rx_ring->q_vector->rx.dim_params.usecs *
			  N20_USECSTOCOUNT);

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_PKTCNT,
		  rx_ring->q_vector->rx.dim_params.frames);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TIMEOUT_TH,
		  N20_VAL_RX_TIMEOUT * N20_USECSTOCOUNT);

	ring_wr32(rx_ring, N20_DMA_REG_RX_SCATTER_LENGH,
		  DIV_ROUND_UP(rx_ring->rx_buf_len, 64));
}

/* 设置rx队列的中断延时和帧数 */
static void n20_set_rxring_intr_coal(struct mce_ring *rx_ring)
{
	struct mce_ring_container *rx = NULL;
	//u32 reg = 0;

	if (rx_ring == NULL)
		return;

	rx = &(rx_ring->q_vector->rx);
	if (rx == NULL)
		return;

	/* maybe not setup always */
	// todo
	//reg = ring_rd32(rx_ring, DMA_REG_RX_INT_FRAMES);
	//FORMAT_FLAG(reg, 0, 1, 31);
	//ring_wr32(rx_ring, DMA_REG_RX_INT_FRAMES, reg);

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_TIMER,
		  rx->dim_params.usecs * N20_USECSTOCOUNT);

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_PKTCNT,
		  rx->dim_params.frames);
}

/**
 * n20_set_vlan_strip - Enable or disable the function of the rx vlan offload at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_vlan_strip(struct mce_hw *hw,
			       netdev_features_t features)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 strip_cnt = pf->vlan_strip_cnt;
	u32 i = 0, value = 0, strip_en = 0;

	if (strip_cnt < 0 || strip_cnt > N20_VLAN_MAX_STRIP_CNT) {
		dev_warn(
			mce_hw_to_dev(hw),
			"pf vlan strip count:%d exceed!"
			"(which range is >= 0 and <= %d), force setup to 1.\n",
			strip_cnt, N20_VLAN_MAX_STRIP_CNT);
		strip_cnt = pf->vlan_strip_cnt = 1;
	}

	if ((features & NETIF_F_HW_VLAN_CTAG_RX) ||
	    (features & NETIF_F_HW_VLAN_STAG_RX)) {
		strip_en = 1;
	} else if (test_bit(MCE_FLAG_VF_INSERT_VLAN, pf->flags))
		strip_en = 1;

	for (i = 0; i < hw->func_caps.common_cap.rss_table_size; i++) {
		value = rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
		F_SET_VLAN_STRIP_EN(value, strip_en);
		F_SET_VLAN_STRIP_CNT(value, strip_cnt);
#ifdef MCE_DEBUG_VF
		F_SET_RETA_HASH_QUEUE_ID(value, 0);
#endif
		wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), value);
	}
}

/**
 * n20_set_rss_hash - Enable or disable the function of RSS at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_rss_hash(struct mce_hw *hw, netdev_features_t features)
{
	u32 mrqc_id = ((hw->func_caps.common_cap.rss_key_size) / 4);
	u16 vfnum = N20_FPGA_VFNUM(hw, PFINFO_IDX);
	u32 value =
		rd32(hw, N20_RSS_OFF(N20_RSS_HASH_ENTRY(mrqc_id, vfnum)));

	if (features & NETIF_F_RXHASH) {
		value |= F_RSS_HASH_EN;
		if (hw->rss_hfunc == ETH_RSS_HASH_TOP)
			value &= (~F_RSS_HASH_XOR_EN);
		if (hw->rss_hfunc == ETH_RSS_HASH_XOR)
			value |= F_RSS_HASH_XOR_EN;
	} else {
		value &= (~F_RSS_HASH_EN);
		value &= (~F_RSS_HASH_XOR_EN);
	}

	wr32(hw, N20_RSS_OFF(N20_RSS_HASH_ENTRY(mrqc_id, vfnum)), value);
}

/**
 * n20_set_rss_key - Set RSS key to hw
 * @hw:  ptr to the hw
 */
static void n20_set_rss_key(struct mce_hw *hw)
{
	u32 i = 0;
	u32 tmp_rss_key = 0;
	u32 entry_size = ((hw->func_caps.common_cap.rss_key_size) / 4);
	u16 vfnum = N20_FPGA_VFNUM(hw, PFINFO_IDX);

	for (i = 0; i < entry_size; i++) {
		tmp_rss_key = (hw->rss_key[(i * 4)]);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 1] << 8);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 2] << 16);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 3] << 24);
		tmp_rss_key = htonl(tmp_rss_key);
		wr32(hw,
		     N20_RSS_OFF(N20_RSS_HASH_ENTRY(entry_size - i - 1,
						    vfnum)),
		     tmp_rss_key);
	}
}

/**
 * n20_set_rss_hash_type - Set the hash type that triggers RSS
 * @hw:  ptr to the hw
*/
static void n20_set_rss_hash_type(struct mce_hw *hw)
{
	u32 mrqc_id = ((hw->func_caps.common_cap.rss_key_size) / 4);
	u16 vfnum = N20_FPGA_VFNUM(hw, PFINFO_IDX);
	u32 value =
		rd32(hw, N20_RSS_OFF(N20_RSS_HASH_ENTRY(mrqc_id, vfnum)));

	if (hw->rss_hash_type == 0) {
		hw->rss_hash_type |= F_IPV6_HASH_EN;
		hw->rss_hash_type |= F_IPV4_HASH_EN;
		hw->rss_hash_type |= F_IPV6_HASH_TCP_EN;
		hw->rss_hash_type |= F_IPV4_HASH_TCP_EN;
		hw->rss_hash_type |= F_IPV6_HASH_UDP_EN;
		hw->rss_hash_type |= F_IPV4_HASH_UDP_EN;
		hw->rss_hash_type |= F_ONLY_HASH_FLEX_EN;
	}

	FORMAT_FLAG(value, hw->rss_hash_type, 15, 0);

	wr32(hw, N20_RSS_OFF(N20_RSS_HASH_ENTRY(mrqc_id, vfnum)), value);
}

static int map_to_real_queue(struct mce_pf *pf, int q)
{
	u16 q_base_dcb_r = 0;
	int q_id_rx = 0;
	int i;
	int q_cnt = pf->max_pf_rxqs;
	int step = pf->max_pf_rxqs / pf->num_max_tc;
	int ret;

	for (i = 0; i <= q; i++) {
		ret = q_id_rx;

		q_id_rx = q_id_rx + step;	
		if (q_id_rx >= q_cnt) {
			q_base_dcb_r++; 
			q_id_rx = q_base_dcb_r;
		}
	}

	return ret;
}
/**
 * n20_set_rss_table - Set the hash indirect table at hw level
 * @hw:  ptr to the hw
 * @q_cnt: queue count
*/
static int n20_set_rss_table(struct mce_hw *hw, u16 q_cnt)
{
	u16 i = 0;
	u32 act_reta = 0;
	u32 pft_reta = 0;
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_dcb *dcb = pf->dcb;
	u32 table_size = hw->func_caps.common_cap.rss_table_size;
	u32 temp;

	if (!q_cnt)
		q_cnt = table_size;
	for (i = 0; i < table_size; i++) {
		// add for chengjian	
		if ((pf->max_pf_rxqs == 8) && (test_bit(MCE_DCB_EN, dcb->flags))) {
			// if dcb on 
			// mapping to the real rx idx
			if (!(hw->hw_flags & MCE_F_RSS_TABLE_INITED)) {
				hw->rss_table[i] = i % q_cnt;  
			}
			temp = map_to_real_queue(pf, hw->rss_table[i]);
			//printk("map %d to %d \n", hw->rss_table[i], temp);
			if (i % 2 == 0) {
				pft_reta =
					(temp + hw->ring_base_addr) &
					0xffff;
			} else {
				pft_reta |=
					(((temp + hw->ring_base_addr) &
					  0xffff)
					 << 16);
				wr32(hw, N20_RSS_OFF(N20_RSS_PFT_CONFIG_MEM(i / 2)),
				     pft_reta);
			}
			act_reta = rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
			act_reta |= (F_RSS_RETA_QUEUE_EN | F_RSS_RETA_MASK_EN);
			wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), act_reta);
		} else { 
			// if should reset rss table
			if (!(hw->hw_flags & MCE_F_RSS_TABLE_INITED)) {
				hw->rss_table[i] = i % q_cnt;
			}
			if (i % 2 == 0) {
				pft_reta =
					(hw->rss_table[i] + hw->ring_base_addr) &
					0xffff;
			} else {
				pft_reta |=
					(((hw->rss_table[i] + hw->ring_base_addr) &
					  0xffff)
					 << 16);
				wr32(hw,
						N20_RSS_OFF(N20_RSS_PFT_CONFIG_MEM(i / 2)),
						pft_reta);
			}
			act_reta =
				rd32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)));
			act_reta |= (F_RSS_RETA_QUEUE_EN | F_RSS_RETA_MASK_EN);
			wr32(hw, N20_RSS_OFF(N20_RSS_ACT_CONFIG_MEM(i)), act_reta);
		}
	}

	hw->hw_flags |= MCE_F_RSS_TABLE_INITED;
	return 0;
}

static void n20_set_ucmc_hash_type_fltr(struct mce_hw *hw)
{
	u32 val, type = hw->uc_mc_hash_ctl.type;

	if (type >= MCE_UC_MC_HASH_TYPE_MAX) {
		type = MCE_UC_MC_HASH_TYPE_BIT_11_0_OR_47_36;
		hw->uc_mc_hash_ctl.uc_s_low = true;
		hw->uc_mc_hash_ctl.mc_s_low = true;
	}

	val = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));
	val &= ~GENMASK(3, 0);
	val |= type;
	if (hw->uc_mc_hash_ctl.uc_s_low)
		val |= BIT(2);
	if (hw->uc_mc_hash_ctl.mc_s_low)
		val |= BIT(3);
	wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), val);
}

/**
 * n20_set_uc_filter - Enable or disable the uc filter at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_uc_filter(struct mce_hw *hw, bool enable)
{
	u32 value;

	/* when turn on sriov, no support setup L2 filter */
	if (hw->promisc_no_permit)
		return;

	value = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));
	if (enable)
		value |= F_UC_HASH_EN;
	else
		value &= (~F_UC_HASH_EN);

	wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), value);
}

static void __n20_calc_uc_mc_hash_cfg(struct mce_hw *hw, const u8 *addr,
				      u32 *idx, u32 *bit, bool s_low)
{
	u16 vector = 0;

	if (hw->uc_mc_hash_ctl.type >= MCE_UC_MC_HASH_TYPE_MAX)
		hw->uc_mc_hash_ctl.type =
			MCE_UC_MC_HASH_TYPE_BIT_11_0_OR_47_36;

	if (s_low)
		vector = htons(*((u16 *)&addr[4])) >>
			 hw->uc_mc_hash_ctl.type;
	else
		vector = htons(*((u16 *)&addr[0])) >>
			 (16 - MCE_UC_MC_HASH_BITS_WIDTH -
			  hw->uc_mc_hash_ctl.type);
	*idx = (vector >> 5) & 0x7f;
	*bit = 1 << (vector & 0x1f);

	dev_dbg(hw->dev,
		"hw calc hash idx:%d bit:0x%08x vector:0x%x addr:%02x:%02x:%02x:%02x:%02x:%02x\n",
		*idx, *bit, vector, addr[0], addr[1], addr[2], addr[3],
		addr[4], addr[5]);
}

/**
 * n20_add_uc_filter - Add addr for uc filter at the hw level
 * @hw:  ptr to the hw
 * @addr: mac addr for uc filter
 */
static void n20_add_uc_filter(struct mce_hw *hw, const u8 *addr)
{
	bool s_low = hw->uc_mc_hash_ctl.uc_s_low;
	u32 val, idx, bit;

	__n20_calc_uc_mc_hash_cfg(hw, addr, &idx, &bit, s_low);
	val = rd32(hw, N20_ETH_FILTER_OFF(N20_ETH_UC_HASH_TABLE(idx)));
	val |= bit;
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_UC_HASH_TABLE(idx)), val);
	dev_dbg(hw->dev,
		"hw add uc idx:%d bit:0x%08x addr:%02x:%02x:%02x:%02x:%02x:%02x\n",
		idx, bit, (u32)addr[0], (u32)addr[1], (u32)addr[2],
		(u32)addr[3], (u32)addr[4], (u32)addr[5]);
}

/**
 * n20_del_uc_filter - Del addr for uc filter at the hw level
 * @hw:  ptr to the hw
 * @addr: mac addr for uc filter
 */
static void n20_del_uc_filter(struct mce_hw *hw, const u8 *addr)
{
	bool s_low = hw->uc_mc_hash_ctl.uc_s_low;
	u32 val, idx, bit;

	__n20_calc_uc_mc_hash_cfg(hw, addr, &idx, &bit, s_low);
	val = rd32(hw, N20_ETH_FILTER_OFF(N20_ETH_UC_HASH_TABLE(idx)));
	val &= ~bit;
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_UC_HASH_TABLE(idx)), val);
	dev_dbg(hw->dev,
		"hw del uc idx:%d bit:0x%08x addr:%02x:%02x:%02x:%02x:%02x:%02x\n",
		idx, bit, (u32)addr[0], (u32)addr[1], (u32)addr[2],
		(u32)addr[3], (u32)addr[4], (u32)addr[5]);
}

/**
 * n20_set_mc_filter - Enable or disable the mc filter at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_mc_filter(struct mce_hw *hw, bool enable)
{
	u32 value;

	if (hw->promisc_no_permit)
		return;

	value = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));
	if (enable)
		value |= F_MC_HASH_EN;
	else
		value &= (~F_MC_HASH_EN);

	wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), value);
}

/**
 * n20_add_mc_filter - Add addr for mc filter at the hw level
 * @hw:  ptr to the hw
 * @addr: mac addr for mc filter
 */
static void n20_add_mc_filter(struct mce_hw *hw, const u8 *addr)
{
	bool s_low = hw->uc_mc_hash_ctl.mc_s_low;
	u32 val, idx, bit;

	__n20_calc_uc_mc_hash_cfg(hw, addr, &idx, &bit, s_low);
	val = rd32(hw, N20_ETH_FILTER_OFF(N20_ETH_MC_HASH_TABLE(idx)));
	val |= bit;
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_MC_HASH_TABLE(idx)), val);
}

/**
 * n20_del_mc_filter - Add addr for mc filter at the hw level
 * @hw:  ptr to the hw
 * @addr: mac addr for mc filter
 */
static void n20_del_mc_filter(struct mce_hw *hw, const u8 *addr)
{
	bool s_low = hw->uc_mc_hash_ctl.mc_s_low;
	u32 val, idx, bit;

	__n20_calc_uc_mc_hash_cfg(hw, addr, &idx, &bit, s_low);
	val = rd32(hw, N20_ETH_FILTER_OFF(N20_ETH_MC_HASH_TABLE(idx)));
	val &= ~bit;
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_MC_HASH_TABLE(idx)), val);
}

static void n20_clr_mc_filter(struct mce_hw *hw)
{
	int i;

	for (i = 0; i < 128; i++)
		wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_MC_HASH_TABLE(i)), 0);
}

/**
 * n20_set_mc_promisc - Enable or disable the mc promisc at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_mc_promisc(struct mce_hw *hw, bool enable)
{
	u32 value = rd32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(
				     N20_FPGA_VFNUM(hw, PFINFO_IDX))));

	if (enable)
		value |= F_VPORT_MC_PROMISC_EN;
	else
		value &= (~F_VPORT_MC_PROMISC_EN);

	wr32(hw,
	     N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(
		     N20_FPGA_VFNUM(hw, PFINFO_IDX))),
	     value);
}

/**
 * n20_set_rx_promisc - Enable or disable the rx promisc at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_rx_promisc(struct mce_hw *hw, bool enable)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 value = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));

	if (enable) {
		value &= (~F_DMAC_FILTER_EN);
		value &= (~F_VLAN_FILTER_EN);
	} else {
		if (test_bit(DMAC_FILTER_EN, hw->l2_fltr_flags))
			value |= F_DMAC_FILTER_EN;
		if (test_bit(VLAN_FILTER_EN, hw->l2_fltr_flags))
			value |= F_VLAN_FILTER_EN;
	}

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		value |= F_DMAC_FILTER_EN;

	wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), value);

	value = rd32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(
				 N20_FPGA_VFNUM(hw, PFINFO_IDX))));
	if (enable)
		value |= F_VPORT_UC_PROMISC_EN | F_VPORT_TRUE_PROMISC_EN;
	else
		value &=
			~(F_VPORT_UC_PROMISC_EN | F_VPORT_TRUE_PROMISC_EN);
	wr32(hw,
	     N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(
		     N20_FPGA_VFNUM(hw, PFINFO_IDX))),
	     value);
}

/**
 * n20_set_vlan_filter - Enable or disable vlan filter at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_vlan_filter(struct mce_hw *hw,
				netdev_features_t features)
{
	u32 value;

	/* when turn on sriov, no support setup L2 filter */
	if (hw->promisc_no_permit)
		return;
	value = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));
	if ((features & NETIF_F_HW_VLAN_CTAG_FILTER) ||
	    (features & NETIF_F_HW_VLAN_STAG_FILTER)) {
		value |= F_VLAN_FILTER_EN;
		set_bit(VLAN_FILTER_EN, hw->l2_fltr_flags);
	} else {
		value &= (~F_VLAN_FILTER_EN);
		clear_bit(VLAN_FILTER_EN, hw->l2_fltr_flags);
	}

	wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), value);
}

/**
 * n20_add_vlan_filter - Add vlan id  for vlan filter at the hw level
 * @hw:  ptr to the hw
 * @vid: vlan id for filter
 */
static void n20_add_vlan_filter(struct mce_hw *hw, u16 vid)
{
	u32 value = 0;
	u32 vid_idx = 0;
	u32 vid_bit = 0;

	vid_idx = (u32)((vid >> 5) & (0x7f));
	vid_bit = (u32)(1 << (vid & 0x1f));
	value = rd32(hw,
		     N20_ETH_FILTER_OFF(N20_ETH_VLAN_HASH_TABLE(vid_idx)));
	value |= vid_bit;
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VLAN_HASH_TABLE(vid_idx)),
	     value);
}

/**
 * n20_del_vlan_filter - Del vlan id  for vlan filter at the hw level
 * @hw:  ptr to the hw
 * @vid: vlan id for filter
 */
static void n20_del_vlan_filter(struct mce_hw *hw, u16 vid)
{
	u32 value = 0;
	u32 vid_idx = 0;
	u32 vid_bit = 0;

	vid_idx = (u32)((vid >> 5) & (0x7f));
	vid_bit = (u32)(1 << (vid & 0x1f));
	value = rd32(hw,
		     N20_ETH_FILTER_OFF(N20_ETH_VLAN_HASH_TABLE(vid_idx)));
	value &= (~vid_bit);
	wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VLAN_HASH_TABLE(vid_idx)),
	     value);
}

/**
 * __n20_add_ntuple_filter - add ntuple rule to hw
 * @hw:  ptr to the hw
 * @rule: ntuple-t rule
 */
static void __n20_add_ntuple_filter(struct mce_hw *hw,
				    struct mce_fdir_fltr *rule)
{
	u32 filter = 0, policy = 0, src_ip = 0, dst_ip = 0, port = 0;
	enum mce_fltr_ptype flow_type = rule->flow_type;
	int vfid = N20_FPGA_VFNUM(hw, rule->vfid - 1);
	u32 loc;

	if (NULL == rule)
		return;

	// filter = rd32(hw, N20_NTUPLE_OFF(N20_NTUPLE_FILTER(loc)));
	// policy = rd32(hw, N20_NTUPLE_OFF(N20_NTUPLE_POLICY(loc)));
	loc = MCE_ACL_MAX_TUPLE5_CNT - 1 - rule->tuple5_loc;
	filter |= F_T5_L4_TYPE_MASK;
	switch (flow_type) {
	case MCE_FLTR_PTYPE_IPV4_TCP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_TCP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV4_UDP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_UDP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV4_SCTP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_SCTP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV6_TCP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_TCP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV6_UDP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_UDP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV6_SCTP:
		F_T5_SET_L4_TYPE(filter, IPPROTO_SCTP);
		filter &= ~F_T5_L4_TYPE_MASK;
		break;
	case MCE_FLTR_PTYPE_IPV4_OTHER:
	case MCE_FLTR_PTYPE_IPV6_OTHER:
		break;
	default:
		return;
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV4_OTHER ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_TCP ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_UDP ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_SCTP) {
		src_ip = htonl(rule->ip.v4.src_ip);
		if (src_ip == 0)
			filter |= F_T5_SIP_MASK;
		else
			filter &= ~F_T5_SIP_MASK;

		dst_ip = htonl(rule->ip.v4.dst_ip);
		if (dst_ip == 0)
			filter |= F_T5_DIP_MASK;
		else
			filter &= ~F_T5_DIP_MASK;

		F_T5_SET_IP4_TYPE(filter);
	}


	if (flow_type == MCE_FLTR_PTYPE_IPV4_TCP ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_UDP ||
	    flow_type == MCE_FLTR_PTYPE_IPV4_SCTP) {
		if (rule->ip.v4.src_port == 0)
			filter |= F_T5_SPORT_MASK;
		else
			filter &= ~F_T5_SPORT_MASK;
		F_T5_SET_SPORT(port, htons(rule->ip.v4.src_port));

		if (rule->ip.v4.dst_port == 0)
			filter |= F_T5_DPORT_MASK;
		else
			filter &= ~F_T5_DPORT_MASK;
		F_T5_SET_DPORT(port, htons(rule->ip.v4.dst_port));
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV4_OTHER) {
		// other type should mask sport dport
		filter |= F_T5_SPORT_MASK;
		filter |= F_T5_DPORT_MASK;
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV6_OTHER ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_TCP ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_UDP ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_SCTP) {
		F_T5_SET_IP6_TYPE(filter);
	}

	if (flow_type == MCE_FLTR_PTYPE_IPV6_TCP ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_UDP ||
	    flow_type == MCE_FLTR_PTYPE_IPV6_SCTP) {
		if (rule->ip.v6.src_port == 0)
			filter |= F_T5_SPORT_MASK;
		else
			filter &= ~F_T5_SPORT_MASK;
		F_T5_SET_SPORT(port, htons(rule->ip.v6.src_port));

		if (rule->ip.v6.dst_port == 0)
			filter |= F_T5_DPORT_MASK;
		else
			filter &= ~F_T5_DPORT_MASK;
		F_T5_SET_DPORT(port, htons(rule->ip.v6.dst_port));
	}

	filter |= F_T5_FILTER_EN;

	if (rule->fltr_action & F_FLTR_ACTION_DROP)
		policy |= F_ACL_ACTION_DROP;
	else
		policy &= ~F_ACL_ACTION_DROP;
	policy |= F_ACL_ACTION_RING_EN;
	F_ACL_ACTION_SET_RING_ID(policy, rule->q_id);
	F_T5_SET_VPORT_ID(filter, vfid);
	filter |= F_T5_VPORT_EN;
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_SIP(loc)), src_ip);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_DIP(loc)), dst_ip);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_PORT(loc)), port);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_FILTER(loc)), filter);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_POLICY(loc)), policy);

	hw->fdir_ntuple5_active_fltr++;

	dev_dbg(hw->dev,
		"[debug] add ntuple loc is : %u, ntuple cnt : %u "
		"action q_id is %u\n",
		loc, hw->fdir_ntuple5_active_fltr, rule->q_id);
}

static void __n20_add_l2_filter(struct mce_hw *hw,
				struct mce_fdir_fltr *rule)
{
	int vfid = N20_FPGA_VFNUM(hw, rule->vfid - 1);
	u32 loc;
	u32 etqs = 0, etqf = 0;

	if (NULL == rule)
		return;
	loc = MCE_MAX_ETYPE_CNT - 1 - rule->etype_loc;
	// etqf = rd32(hw, N20_ETH_RQA_ETQF_OFF(vfid, loc));
	rule->eth.type = rule->eth.type;
	etqf |= BIT(31);
	FORMAT_FLAG(etqf, rule->eth.type, 16, 0);
	wr32(hw, N20_ETH_RQA_ETQF_OFF(vfid, loc), etqf);
	// etqs = rd32(hw, N20_ETH_RQA_ETQS_OFF(vfid, loc));
	etqs |= F_ACL_ACTION_RING_EN;
	if (rule->fltr_action & F_FLTR_ACTION_DROP)
		etqs |= F_ACL_ACTION_DROP;
	else
		etqs &= ~F_ACL_ACTION_DROP;
	F_ACL_ACTION_SET_RING_ID(etqs, rule->q_id);
	wr32(hw, N20_ETH_RQA_ETQS_OFF(vfid, loc), etqs);
	hw->fdir_etype_active_fltr++;
}

static void n20_add_filter(struct mce_hw *hw, struct mce_fdir_fltr *rule)
{
	if (rule->flow_type == MCE_FLTR_PTYPE_NONF_ETH)
		__n20_add_l2_filter(hw, rule);
	else
		__n20_add_ntuple_filter(hw, rule);
}

static void n20_del_ntuple_filter(struct mce_hw *hw,
				  struct mce_fdir_fltr *rule)
{
	u32 loc;

	loc = MCE_ACL_MAX_TUPLE5_CNT - 1 - rule->tuple5_loc;
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_SIP(loc)), 0);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_DIP(loc)), 0);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_PORT(loc)), 0);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_FILTER(loc)), 0);
	wr32(hw, N20_NTUPLE_OFF(N20_NTUPLE_POLICY(loc)), 0);

	hw->fdir_ntuple5_active_fltr--;
	dev_dbg(hw->dev,
		"[debug] del ntuple loc is : %u, ntuple cnt : %u\n", loc,
		hw->fdir_ntuple5_active_fltr);
}

static void __n20_del_l2_filter(struct mce_hw *hw,
				struct mce_fdir_fltr *rule)
{
	int vfid = N20_FPGA_VFNUM(hw, rule->vfid - 1);
	u32 loc;
	u32 etqs = 0, etqf = 0;

	if (NULL == rule)
		return;
	loc = MCE_MAX_ETYPE_CNT - 1 - rule->etype_loc;
	wr32(hw, N20_ETH_RQA_ETQF_OFF(vfid, loc), etqf);
	wr32(hw, N20_ETH_RQA_ETQS_OFF(vfid, loc), etqs);
	hw->fdir_etype_active_fltr--;
}

static void n20_del_filter(struct mce_hw *hw, struct mce_fdir_fltr *rule)
{
	if (rule->flow_type == MCE_FLTR_PTYPE_NONF_ETH)
		__n20_del_l2_filter(hw, rule);
	else
		n20_del_ntuple_filter(hw, rule);
}

static void n20_add_tnl(struct mce_hw *hw, enum mce_tunnel_type tnl_type,
			u16 port)
{
	struct mce_tunnel_entry *tnl_entry;
	u32 reg = 0;
	int i = 0;

	if (tnl_type >= TNL_LAST)
		return;

	switch (tnl_type) {
	case TNL_VXLAN:
		reg = N20_ETH_OFF(N20_ETH_VXLAN_PORT);
		break;
	case TNL_GENEVE:
		reg = N20_ETH_OFF(N20_ETH_GENEVE_PORT);
		break;
	case TNL_VXLAN_GPE:
		reg = N20_ETH_OFF(N20_ETH_VXLAN_GPE_PORT);
		break;
	default:
		return;
	}

	for (i = 0; i < MCE_TUNNEL_MAX_ENTRIES; i++) {
		tnl_entry = &(hw->tnl[tnl_type].tbl[i]);
		if (tnl_entry->in_use == true)
			continue;

		reg += (0x4 * (i));
		if (tnl_entry->default_port == 0)
			tnl_entry->default_port = rd32(hw, reg);

		wr32(hw, reg, port);
		tnl_entry->port = port;
		tnl_entry->in_use = true;
		tnl_entry->ref_cnt = 1;
		++(hw->tnl[tnl_type].tnl_cnt);
	}
}

static void n20_del_tnl(struct mce_hw *hw, enum mce_tunnel_type tnl_type,
			u16 port)
{
	struct mce_tunnel_entry *tnl_entry;
	u32 reg = 0;
	int i = 0;

	if (tnl_type >= TNL_LAST)
		return;

	switch (tnl_type) {
	case TNL_VXLAN:
		reg = N20_ETH_OFF(N20_ETH_VXLAN_PORT);
		break;
	case TNL_GENEVE:
		reg = N20_ETH_OFF(N20_ETH_GENEVE_PORT);
		break;
	case TNL_VXLAN_GPE:
		reg = N20_ETH_OFF(N20_ETH_VXLAN_GPE_PORT);
		break;
	default:
		return;
	}

	for (i = 0; i < MCE_TUNNEL_MAX_ENTRIES; i++) {
		tnl_entry = &(hw->tnl[tnl_type].tbl[i]);
		if (tnl_entry->in_use == false)
			continue;

		if (tnl_entry->port != port)
			continue;

		if (tnl_entry->ref_cnt > 1) {
			--(tnl_entry->ref_cnt);
		} else if (tnl_entry->ref_cnt == 0) {
			return;
		} else {
			reg += (0x4 * (i));
			wr32(hw, reg, tnl_entry->default_port);
			tnl_entry->in_use = false;
			tnl_entry->port = 0;
			tnl_entry->ref_cnt = 0;
			++(hw->tnl[tnl_type].tnl_cnt);
		}
	}
}

static void n20_set_tun_select_inner(struct mce_hw *hw, bool inner)
{
	u32 val = 0;
	int vfid = N20_FPGA_VFNUM(hw, PFINFO_IDX);

	val = rd32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(vfid)));
	if (inner)
		val |= F_VPORT_TUN_SELECT_INNER;
	else
		val &= (~F_VPORT_TUN_SELECT_INNER);
	val |= F_VPORT_TUN_SELECT_INNER_OUTER_EN;
	wr32(hw, N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(vfid)), val);
}

static void n20_set_pause(struct mce_hw *hw, int mtu)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_flow_control *fc = &(pf->fc);
	u32 val = 0;
	u32 tx_fifo_thresh[N20_FIFO_PROG_CNT] = { 0x100, 0x8, 0x8, 0x8,
						  0x8,	 0x8, 0x8, 0x8 };
	/* should reltive with mtu */
	u32 rx_fifo_thresh[N20_FIFO_PROG_CNT] = { 0x20, 0x8, 0x8, 0x8,
						  0x8,	0x8, 0x8, 0x8 };
	u32 dflt_thresh[N20_FIFO_PROG_CNT] = { 0x100, 0x8, 0x8, 0x8,
					       0x8,   0x8, 0x8, 0x8 };
	u32 dflt_tx_cdc_fifo_thresh = 352;
	u32 paus_tx_cdc_fifo_thresh = 480;
	u32 cfg_adap = 0;
	u8 i = 0;
	/* up assign to 64 */
	int fifo_thresh = ((mtu + 26 + 63) & (~63));

	rx_fifo_thresh[0] = fifo_thresh / 64 + 8;

	/* if current_mode equal req_mode, nothing todo */
	if (fc->current_mode == fc->req_mode)
		return;
	/* Stop transmitting and receiving packets. */
	n20_enable_proc(hw);
	n20_set_dft_fifo_space(hw);

	val = rd32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL));

	switch (fc->req_mode) {
	case MCE_FC_TX_PAUSE:
		val |= F_TX_PAUSE_EN;
		val &= ~F_RX_PAUSE_EN;

		for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
			wr32(hw, N20_ETH_OFF(N20_ETH_PORT_TX_PROGFULL(i)),
			     tx_fifo_thresh[i]);
			wr32(hw, N20_ETH_OFF(N20_ETH_PORT_RX_PROGFULL(i)),
			     dflt_thresh[i]);
		}

		cfg_adap =
			rd32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0));
		FORMAT_FLAG(cfg_adap, paus_tx_cdc_fifo_thresh, 9,
			    F_TX_CDC);
		wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0), cfg_adap);
		break;
	case MCE_FC_RX_PAUSE:
		val |= F_RX_PAUSE_EN;
		val &= ~F_TX_PAUSE_EN;

		for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
			wr32(hw, N20_ETH_OFF(N20_ETH_PORT_TX_PROGFULL(i)),
			     dflt_thresh[i]);
			wr32(hw, N20_ETH_OFF(N20_ETH_PORT_RX_PROGFULL(i)),
			     rx_fifo_thresh[i]);
		}

		cfg_adap =
			rd32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0));
		FORMAT_FLAG(cfg_adap, dflt_tx_cdc_fifo_thresh, 9,
			    F_TX_CDC);
		wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0), cfg_adap);
		break;
	case MCE_FC_FULL:
		val |= F_RX_PAUSE_EN;
		val |= F_TX_PAUSE_EN;

		for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
			wr32(hw, N20_ETH_OFF(N20_ETH_PORT_TX_PROGFULL(i)),
			     tx_fifo_thresh[i]);
			wr32(hw, N20_ETH_OFF(N20_ETH_PORT_RX_PROGFULL(i)),
			     rx_fifo_thresh[i]);
		}

		cfg_adap =
			rd32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0));
		FORMAT_FLAG(cfg_adap, paus_tx_cdc_fifo_thresh, 9,
			    F_TX_CDC);
		wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0), cfg_adap);
		break;
	case MCE_FC_NONE:
		val &= ~F_RX_PAUSE_EN;
		val &= ~F_TX_PAUSE_EN;

		for (i = 0; i < N20_FIFO_PROG_CNT; i++) {
			wr32(hw, N20_ETH_OFF(N20_ETH_PORT_TX_PROGFULL(i)),
			     dflt_thresh[i]);
			wr32(hw, N20_ETH_OFF(N20_ETH_PORT_RX_PROGFULL(i)),
			     dflt_thresh[i]);
		}

		cfg_adap =
			rd32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0));
		FORMAT_FLAG(cfg_adap, dflt_tx_cdc_fifo_thresh, 9,
			    F_TX_CDC);
		wr32(hw, N20_ETH_OFF(N20_ETH_CFG_ADAPTER_CTRL0), cfg_adap);
		break;
	default:
		break;
	}

	wr32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL), val);

	/* Start transmitting and receiving packets. */
	n20_disable_proc(hw);

	fc->current_mode = fc->req_mode;
}

static void n20_set_pause_en_only(struct mce_hw *hw)
{
	struct mce_pf *pf = (struct mce_pf *)(hw->back);
	struct mce_flow_control *fc = &(pf->fc);
	u32 val = 0;

	val = rd32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL));

	switch (fc->req_mode) {
	case MCE_FC_TX_PAUSE:
		val |= F_TX_PAUSE_EN;
		val &= ~F_RX_PAUSE_EN;

		break;
	case MCE_FC_RX_PAUSE:
		val |= F_RX_PAUSE_EN;
		val &= ~F_TX_PAUSE_EN;

		break;
	case MCE_FC_FULL:
		val |= F_RX_PAUSE_EN;
		val |= F_TX_PAUSE_EN;

		break;
	case MCE_FC_NONE:
		val &= ~F_RX_PAUSE_EN;
		val &= ~F_TX_PAUSE_EN;

		break;
	default:
		break;
	}

	//set pause will close pf?
	
	wr32(hw, N20_ETH_OFF(N20_ETH_PAUSE_CTRL), val);

	fc->current_mode = fc->req_mode;
}

static void n20_set_ddp_extra_en(struct mce_hw *hw, bool enable)
{
	u32 val;

	val = rd32(hw, N20_ETH_OFF(N20_ETH_PARSER_CTRL));
	if (enable)
		val |= F_DDP_EXTRA_EN;
	else
		val &= (~F_DDP_EXTRA_EN);

	wr32(hw, N20_ETH_OFF(N20_ETH_PARSER_CTRL), val);
}

static void n20_set_evb_mode(struct mce_hw *hw, enum mce_evb_mode mode)
{
	u32 val;

	val = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));
	if (mode == MCE_EVB_VEPA)
		val |= F_VEPA_SW_EN;
	else
		val &= (~F_VEPA_SW_EN);
	wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), val);
	if (mode == MCE_EVB_VEPA)
		hw->vf.ops->set_vf_emac_post_ctrl(
			hw, 0, false, MCE_VF_POST_CTRL_NORMAL, true);
	else
		hw->vf.ops->set_vf_emac_post_ctrl(
			hw, 0, false, MCE_VF_POST_CTRL_FILTER_TX_TO_RX,
			true);
}
static void n20_set_dma_tso_cnts_en(struct mce_hw *hw, bool en)
{
	u32 val;

	val = rd32(hw, N20_DMA_OFF(N20_DMA_CONFIG));
	val = en ? val | F_DMA_TSO_CNTS_EN : val & ~F_DMA_TSO_CNTS_EN;
	wr32(hw, N20_DMA_OFF(N20_DMA_CONFIG), val);
}

static void n20_set_fd_fltr_guar(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	hw->func_caps.fd_fltr_guar = N20_LOC_FDIR_CNT;
}

void n20_set_irq_legency_en(struct mce_hw *hw, bool en, u32 tick_timer)
{
	u32 reg_val = 0;

	if (en) {
		F_NIC_MSI_CONFIG_MSIX_TICK_TIMER(reg_val, tick_timer);
		reg_val |= F_NIC_MSI_CONFIG_LEGENCY_EN;
	}
	wr32(hw, N20_NIC_OFF(N20_NIC_MSI_CONFIG), reg_val);
}

bool n20_get_misc_irq_evt(struct mce_hw *hw, enum mce_misc_irq_type type)
{
	bool ret = false;
	u32 s_val, c_val = 0, t_val;

	s_val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_ST));
	// c_val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR));
	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		ret = !!(s_val & BIT(0));
		if (ret)
			c_val = BIT(0);
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		ret = !!(s_val & BIT(4));
		if (ret)
			c_val = BIT(4);
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		ret = !!(s_val & BIT(8));
		if (ret)
			c_val = BIT(8);
		break;
	default:
		ret = false;
		break;
	}
	/* clear misc link event */
	if (ret) {
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR), c_val);
		t_val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR));
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR), 0);
		t_val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_CLR));
	}

	return !!ret;
}

int n20_set_misc_irq(struct mce_hw *hw, bool en, int nr_vec)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 val = 0;

	nr_vec = en ? nr_vec : 0;

	if (pf->mac_misc_irq & BIT(MCE_MAC_MISC_IRQ_PCS_LINK)) {
		val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(0)));
		FORMAT_FLAG(val, nr_vec, 11, 0);
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(0)), val);
		hw->ops->set_misc_irq_mask(hw, MCE_MAC_MISC_IRQ_PCS_LINK,
					   !en);
	}

	if (pf->mac_misc_irq & BIT(MCE_MAC_MISC_IRQ_PTP)) {
		val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(2)));
		FORMAT_FLAG(val, nr_vec, 11, 0);
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(2)), val);
		hw->ops->set_misc_irq_mask(hw, MCE_MAC_MISC_IRQ_PTP, !en);
	}

	if (pf->mac_misc_irq & BIT(MCE_MAC_MISC_IRQ_FLR)) {
		val = rd32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(4)));
		FORMAT_FLAG(val, nr_vec, 11, 0);
		wr32(hw, N20_MSIX_OFF(N20_MSIX_MISC_IRQ_VEC(4)), val);
		hw->ops->set_misc_irq_mask(hw, MCE_MAC_MISC_IRQ_FLR, !en);
	}

/* T = 1s / system f * tick_timer */
#define N20_MISC_IRQ_RETRY_TIMES 0x1212d0 /* 50ms */
	val = pf->mac_misc_irq_retry && en ?
		      N20_MISC_IRQ_RETRY_TIMES | BIT(31) :
		      0;
	wr32(hw, N20_NIC_OFF(N20_NIC_MSIX_CONFIG), val);
	return 0;
}

int n20_get_misc_irq_st(struct mce_hw *hw, enum mce_misc_irq_type type,
			u32 *val)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	int ret = 0;
	u32 t_val = 0;

	if (!(pf->mac_misc_irq & BIT(type)))
		return -EINVAL;

	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		*val = rd32(hw, N20_MAC_OFF(N20_MAC_INT_STAT(0)));
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		*val = rd32(hw, N20_MAC_OFF(N20_MAC_INT_STAT(4)));
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		if (*val == MCE_MISC_IRQ_FLR_0_31)
			t_val = rd32(
				hw,
				N20_DMA_OFF(N20_NIC_DMA_FLR_STATUS(0)));
		if (*val == MCE_MISC_IRQ_FLR_32_63)
			t_val = rd32(
				hw,
				N20_DMA_OFF(N20_NIC_DMA_FLR_STATUS(1)));
		if (*val == MCE_MISC_IRQ_FLR_64_95)
			t_val = rd32(
				hw,
				N20_DMA_OFF(N20_NIC_DMA_FLR_STATUS(2)));
		if (*val == MCE_MISC_IRQ_FLR_96_127)
			t_val = rd32(
				hw,
				N20_DMA_OFF(N20_NIC_DMA_FLR_STATUS(3)));
		*val = t_val;
		break;
	default:
		*val = 0;
		ret = -EINVAL;
		break;
	}
	return ret;
}

int n20_set_misc_irq_mask(struct mce_hw *hw, enum mce_misc_irq_type type,
			  bool en)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 val = 0;
	int ret = 0;

	if (!(pf->mac_misc_irq & BIT(type)) &&
	    (type != MCE_MAC_MISC_IRQ_ALL))
		return -EINVAL;

	val = en ? 0xffffffff : 0x0;
	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(0)), val);
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(4)), val);
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(4)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_MASK(0)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_MASK(1)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_MASK(2)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_MASK(3)), val);
		break;
	case MCE_MAC_MISC_IRQ_ALL:
		/* mac intrrupt */
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(0)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(1)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(2)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(3)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(4)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(5)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_MASK(6)), val);
		/* nic dma flr intrrupt */
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_MASK(0)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_MASK(1)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_MASK(2)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_MASK(3)), val);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

int n20_clear_misc_irq_evt(struct mce_hw *hw, enum mce_misc_irq_type type,
			   u32 val)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 flr_idx = 0;
	int ret = 0;

	if (!(pf->mac_misc_irq & BIT(type)) &&
	    (type != MCE_MAC_MISC_IRQ_ALL))
		return -EINVAL;
	if (val != MCE_MISC_IRQ_CLEAR_ALL) {
		flr_idx = val;
		val = MCE_MISC_IRQ_CLEAR_ALL;
	}

	switch (type) {
	case MCE_MAC_MISC_IRQ_PCS_LINK:
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(0)), val);
		break;
	case MCE_MAC_MISC_IRQ_PTP:
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(4)), val);
		break;
	case MCE_MAC_MISC_IRQ_FLR:
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(flr_idx)), val);
		udelay(10);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(flr_idx)), 0);
		break;
	case MCE_MAC_MISC_IRQ_ALL:
		/* mac intrrupt clear */
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(0)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(1)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(2)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(3)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(4)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(5)), val);
		wr32(hw, N20_MAC_OFF(N20_MAC_INT_CLR(6)), val);
		/* nic dma flr intrrupt */
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(0)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(1)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(2)), val);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(3)), val);
		udelay(10);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(0)), 0);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(1)), 0);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(2)), 0);
		wr32(hw, N20_DMA_OFF(N20_NIC_DMA_FLR_CLR(3)), 0);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

/* TODO: only test for ptp intrrupt, remove in future */
int n20_set_init_ptp(struct mce_hw *hw)
{
	/* reset ptp */
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x683c, 0x43);
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x683c, 0x40);
	/* parse ptp */
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x4000, 0xc418444);
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x4390, 0x6c0000);
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x4060, 0x107);
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x430C, 0x0);
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x4300, 0x1);
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x4304, 0x500);
	wr32(hw, N20_MAC_PCS_REG_BASE + 0x430C, 0x1);
	return 0;
}

static void n20_update_rdma_status(struct mce_hw *hw, bool en)
{
	u32 val = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));

	if (en)
		val |= BIT(8);
	else
		val &= (~BIT(8));

	wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), val);
}

static int n20_set_txring_trig_intr(struct mce_ring *tx_ring)
{
	ring_wr32(tx_ring, N20_DMA_REG_INT_TRIG,
		  _F_N20_DMA_INT_CLR_TRIG_TX);
	ring_wr32(tx_ring, N20_DMA_REG_INT_TRIG,
		  _F_N20_DMA_INT_SET_TRIG_TX);
	return 0;
}

struct mce_hw_operations n20_ops = {
	.reset_hw = n20_reset_hw,
	.init_hw = n20_init_hw,
	.enable_proc = n20_enable_proc,
	.enable_proc_old = n20_enable_proc_old,
	.disable_proc = n20_disable_proc,
	.enable_axi_tx = n20_enable_axi_tx,
	.disable_axi_tx = n20_disable_axi_tx,
	.enable_axi_rx = n20_enable_axi_rx,
	.disable_axi_rx = n20_disable_axi_rx,
	.cfg_vec2tqirq = n20_cfg_vec2tqirq,
	.cfg_vec2rqirq = n20_cfg_vec2rqirq,
	.set_max_pktlen = n20_set_max_pktlen,
	.get_hw_stats = n20_get_hw_stats,
	.dump_debug_regs = n20_dump_debug_regs,
	.update_fltr_macaddr = n20_update_fltr_macaddr,

	.set_rxring_ctx = n20_set_rxring_ctx,
	.set_txring_ctx = n20_set_txring_ctx,
	.enable_rxring_irq = n20_enable_rxring_irq,
	.enable_txring_irq = n20_enable_txring_irq,
	.disable_rxring_irq = n20_disable_rxring_irq,
	.disable_txring_irq = n20_disable_txring_irq,
	.enable_txrxring_irq = n20_enable_txrxring_irq,
	.disable_txrxring_irq = n20_disable_txrxring_irq,
	.start_rxring = n20_start_rxring,
	.start_txring = n20_start_txring,
	.stop_rxring = n20_stop_rxring,
	.stop_txring = n20_stop_txring,
	.set_rxring_intr_coal = n20_set_rxring_intr_coal,
	.set_txring_intr_coal = n20_set_txring_intr_coal,
	.set_txring_hw_dim = n20_set_txring_hw_dim,
	.set_rxring_hw_dim = n20_set_rxring_hw_dim,
	.cfg_txring_bw_lmt = n20_cfg_txring_bw_lmt,

	.set_rss_hash = n20_set_rss_hash,
	.set_rss_key = n20_set_rss_key,
	.set_rss_table = n20_set_rss_table,
	.set_rss_hash_type = n20_set_rss_hash_type,

	.set_rx_csumofld = n20_set_rx_csumofld,
	.set_vlan_strip = n20_set_vlan_strip,

	.set_ucmc_hash_type_fltr = n20_set_ucmc_hash_type_fltr,
	.set_uc_filter = n20_set_uc_filter,
	.add_uc_filter = n20_add_uc_filter,
	.del_uc_filter = n20_del_uc_filter,
	.set_mc_filter = n20_set_mc_filter,
	.add_mc_filter = n20_add_mc_filter,
	.del_mc_filter = n20_del_mc_filter,
	.clr_mc_filter = n20_clr_mc_filter,

	.set_mc_promisc = n20_set_mc_promisc,
	.set_rx_promisc = n20_set_rx_promisc,

	.set_vlan_filter = n20_set_vlan_filter,
	.add_vlan_filter = n20_add_vlan_filter,
	.del_vlan_filter = n20_del_vlan_filter,

	.add_ntuple_filter = n20_add_filter,
	.del_ntuple_filter = n20_del_filter,

	.add_tnl = n20_add_tnl,
	.del_tnl = n20_del_tnl,

	.set_pause = n20_set_pause,
	.set_pause_en_only = n20_set_pause_en_only,

	.enable_tc = n20_enable_tc,
	.disable_tc = n20_disable_tc,
	.enable_rdma_tc = n20_enable_rdma_tc,
	.disable_rdma_tc = n20_disable_rdma_tc,
	.set_tc_bw = n20_set_tc_bw,
	.set_tc_bw_rdma = n20_set_tc_bw_rdma,
	.set_qg_ctrl = n20_set_qg_ctrl,
	.set_qg_rate = n20_set_qg_rate,
	.set_q_to_tc = n20_set_q_to_tc,
	.clr_q_to_tc = n20_clr_q_to_tc,
	.enable_pfc = n20_enable_pfc,
	.disable_pfc = n20_disable_pfc,
	.setup_rx_buffer = n20_setup_rx_buffer,
	.set_q_to_pfc = n20_set_q_to_pfc,
	.clr_q_to_pfc = n20_clr_q_to_pfc,
	.set_dscp = n20_set_dscp,
	.set_tun_select_inner = n20_set_tun_select_inner,
	.set_ddp_extra_en = n20_set_ddp_extra_en,
	.set_evb_mode = n20_set_evb_mode,
	.set_dma_tso_cnts_en = n20_set_dma_tso_cnts_en,
	.set_fd_fltr_guar = n20_set_fd_fltr_guar,

	.set_irq_legency_en = n20_set_irq_legency_en,
	.get_misc_irq_evt = n20_get_misc_irq_evt,
	.set_misc_irq = n20_set_misc_irq,
	.get_misc_irq_st = n20_get_misc_irq_st,
	.set_misc_irq_mask = n20_set_misc_irq_mask,
	.clear_misc_irq_evt = n20_clear_misc_irq_evt,
	/* TODO: only test for ptp intrrupt, remove in future */
	.set_init_ptp = n20_set_init_ptp,
	/* npu callback */
	.npu_download_firmware = n20_npu_download_firmware,
	.update_rdma_status = n20_update_rdma_status,

// ptp control
#ifdef HAVE_PTP_1588_CLOCK
	.ptp_get_systime = n20_get_systime,
	.ptp_init_systime = n20_init_systime,
	.ptp_adjust_systime = n20_adjust_systime,
	.ptp_adjfine = n20_adjfine,
	.ptp_set_ts_config = n20_ptp_set_ts_config,
	.ptp_tx_state = n20_ptp_tx_status,
	.ptp_tx_stamp = n20_ptp_tx_stamp,
#endif

	/* fdir callback */
	.fd_update_entry_table = n20_fd_update_entry_table,
	.fd_update_hash_table = n20_fd_update_hash_table,
	.fd_update_ex_hash_table = n20_fd_update_ex_hash_table,
	.fd_verificate_sign_rule = n20_fd_verificate_sign_rule,
	.fd_clear_sign_rule = n20_fd_clear_sign_rule,
	.fd_field_bitmask_setup = n20_fd_field_bitmask_setup,
	.fd_profile_field_bitmask_update =
		n20_fd_profile_field_bitmask_update,
	.fd_profile_update = n20_fd_profile_update,
	.fd_init_hw = n20_fd_init_hw,
	.set_txring_trig_intr = n20_set_txring_trig_intr,
};

static void _set_vf_init_config(struct mce_hw *hw, bool en)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	u32 val = 0;

	if (en) {
		val = F_T4_T10_CONFIG_MASK | F_MC_CONVERT_TO_BC_EN;
		wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL1), val);

		val = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));
		val |= N20_ETH_L2_CTRL0_DEFAULT_CFG;
		wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), val);

		/* turn on true promisc switch for vf*/
		val = rd32(hw, N20_ETH_OFF(N20_ETH_FWD_CTRL));
		val |= F_PROMISC_VPORT_UPLINK_EN | F_PROMISC_VPORT_VEB_EN;
		wr32(hw, N20_ETH_OFF(N20_ETH_FWD_CTRL), val);

		/* set pf action and bitmap, pf take as vf0 */
		memset(vf->t_info.macaddr, 0x0, ETH_ALEN);
		vf->t_info.bcmc_bitmap = MCE_F_HOLD;
		mce_vf_set_veb_misc_rule(
			hw, PFINFO_IDX,
			__VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT);
		/* config default bc/mc mac or vlan, mc take as bc */
		vf->t_info.bcmc_bitmap = MCE_F_HOLD;
		mce_vf_set_veb_misc_rule(
			hw, PFINFO_BCMC,
			__VEB_POLICY_TYPE_BCMC_ADD_MACADDR_WITH_ACT);
	} else {
		val = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL1));
		val &= ~(F_T4_T10_CONFIG_MASK | F_MC_CONVERT_TO_BC_EN);
		wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL1), val);

		/* turn off true promisc switch for vf*/
		val = rd32(hw, N20_ETH_OFF(N20_ETH_FWD_CTRL));
		val &= ~(F_PROMISC_VPORT_UPLINK_EN |
			 F_PROMISC_VPORT_VEB_EN);
		wr32(hw, N20_ETH_OFF(N20_ETH_FWD_CTRL), val);

		val = rd32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0));
		val &= ~N20_ETH_L2_CTRL0_DEFAULT_CFG;
		wr32(hw, N20_ETH_OFF(N20_ETH_L2_CTRL0), val);
		vf->t_info.bcmc_bitmap = MCE_F_HOLD;
		mce_vf_set_veb_misc_rule(
			hw, PFINFO_BCMC,
			__VEB_POLICY_TYPE_BCMC_ADD_MACADDR_WITH_ACT);
	}
}

/* data path reg will be cleared after nic-reset, manager patch reg will not */
static void _clear_vf_init_config(struct mce_hw *hw, bool en)
{
	u8 mac_addr[ETH_ALEN];
	u32 i, val;

	memset(mac_addr, 0x00, ETH_ALEN);
	/* not clear pf setup */
	for (i = N20_VM_T4_VF_ADDR_ENTRY_OFF;
	     i <= N20_VM_T4_BCMC_ADDR_ENTRY_OFF; i++) {
		/* clear l2 dmac */
		hw->ops->update_fltr_macaddr(hw, mac_addr, i, false);
		wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_DMAC_RAL(i)), 0);
		wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_DMAC_RAH(i)), 0);
		wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_IPORT_PVF(i)), 0);
		val = rd32(hw,
			   N20_ETH_FILTER_OFF(N20_ETH_VM_T4_ACT_PVF(i)));
		F_SET_VM_MATCH_INDEX(val, 0);
		wr32(hw, N20_ETH_FILTER_OFF(N20_ETH_VM_T4_ACT_PVF(i)), 0);
		/* clear bitmap */
		wr32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_BITMAP_MEM0(
			     N20_VM_T4_VF_UC_INDEX(i))),
		     0);
		wr32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_BITMAP_MEM1(
			     N20_VM_T4_VF_UC_INDEX(i))),
		     0);
		wr32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_BITMAP_MEM2(
			     N20_VM_T4_VF_UC_INDEX(i))),
		     0);
		wr32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_BITMAP_MEM3(
			     N20_VM_T4_VF_UC_INDEX(i))),
		     0);
	}
	/* clear vf attr table except pf*/
	for (i = 0; i < N20_VF_CNT; i++) {
		wr32(hw,
		     N20_ETH_VPORT_OFF(N20_ETH_VPORT_ATTR_TABLE(
			     N20_FPGA_VFNUM(hw, i))),
		     0);
	}
	hw->vf.ops->set_vf_clear_all_rss_table(hw);
}

static void n20_set_vf_virtual_config(struct mce_hw *hw, bool en)
{
	u32 val;

	val = rd32(hw, N20_NIC_OFF(N20_NIC_CONFIG));
	en ? SET_BIT(F_VIRTUAAL_SW_OFFSET, val) :
	     CLR_BIT(F_VIRTUAAL_SW_OFFSET, val);
	wr32(hw, N20_NIC_OFF(N20_NIC_CONFIG), val);

	/* active vf */
	val = rd32(hw, N20_DMA_OFF(N20_DMA_CONFIG));
	en ? SET_BIT(F_VF_ACTIVE_OFFSET, val) :
	     CLR_BIT(F_VF_ACTIVE_OFFSET, val);
	en ? FORMAT_FLAG(val, N20_FPGA_VFNUM(hw, PFINFO_IDX), 9, 16) :
	     FORMAT_FLAG(val, 0, 9, 16);
	wr32(hw, N20_DMA_OFF(N20_DMA_CONFIG), val);
	_clear_vf_init_config(hw, en);
	_set_vf_init_config(hw, en);
}

static void n20_set_vf_dma_qs(struct mce_hw *hw, enum mce_vf_dma_qs qs)
{
	u32 val = rd32(hw, N20_DMA_OFF(N20_DMA_CONFIG));

	FORMAT_FLAG(val, qs + 2, 3, 9);
	wr32(hw, N20_DMA_OFF(N20_DMA_CONFIG), val);

	val = rd32(hw, N20_ETH_OFF(N20_ETH_RQA_CTRL));
	FORMAT_FLAG(val, qs, 3, 16);
	wr32(hw, N20_ETH_OFF(N20_ETH_RQA_CTRL), val);
}

static void n20_set_vf_emac_post_ctrl(struct mce_hw *hw,
				      enum mce_vf_veb_vlan_type vlan_type,
				      bool vlan_on,
				      enum mce_vf_post_ctrl post_ctrl,
				      bool ctrl_on)
{
	u32 val = 0;

	val = rd32(hw, N20_ETH_OFF(N20_ETH_EMAC_POST_CTRL));
	if (vlan_on)
		FORMAT_FLAG(val, vlan_type, 2, 2);

	if (ctrl_on)
		FORMAT_FLAG(val, post_ctrl, 2, 0);
	wr32(hw, N20_ETH_OFF(N20_ETH_EMAC_POST_CTRL), val);
}

static void n20_init_mbx_info(struct mce_hw *hw)
{
	hw->mbx.mbx_mem_size = 64;
#ifdef MCE_DEBUG_XINSI_PCIE
	hw->mbx.pf_vf_shm_base = N20_MSIX_MBX_OFF(0x0);
	hw->mbx.pf2vf_mbox_ctrl_base = N20_MSIX_MBX_OFF(0x2200);
	hw->mbx.cpu_pf_shm_base = N20_MSIX_MBX_OFF(0x6040);
	hw->mbx.pf2cpu_mbox_ctrl = N20_MSIX_MBX_OFF(0x6100);
	hw->mbx.cpu2pf_mbox_ctrl = N20_MSIX_MBX_OFF(0x6200);
	hw->mbx.vf2pf_mbox_vec_base = N20_MSIX_OFF(0x8200);
	hw->mbx.cpu2pf_mbox_vec = N20_MSIX_OFF(0x8600);
#else
	hw->mbx.pf_vf_shm_base = N20_MSIX_MBX_OFF(0x0);
	hw->mbx.pf2vf_mbox_ctrl_base = N20_MSIX_MBX_OFF(0x2200);
	hw->mbx.cpu_pf_shm_base = N20_MSIX_MBX_OFF(0x6040);
	hw->mbx.pf2cpu_mbox_ctrl = N20_MSIX_MBX_OFF(0x6100);
	hw->mbx.cpu2pf_mbox_ctrl = N20_MSIX_MBX_OFF(0x6200);
#endif
	set_bit(MCE_MBX_FEATURE_WRITE_DELAY, hw->mbx.mbx_feature);
}

struct mce_vf_operations n20_vf_ops = {
	.set_vf_virtual_config = n20_set_vf_virtual_config,
	.set_vf_dma_qs = n20_set_vf_dma_qs,
	.set_vf_emac_post_ctrl = n20_set_vf_emac_post_ctrl,
	.set_vf_vlan_strip = n20_set_vf_vlan_strip,
	.set_vf_rss_table = n20_set_vf_rss_table,
	.set_vf_clear_all_rss_table = n20_clear_vf_all_rss_table,
	.set_vf_spoofchk_mac = n20_set_vf_spoofchk_mac,
	.set_vf_spoofchk_vlan = n20_set_vf_spoofchk_vlan,
	.set_vf_trusted = n20_set_vf_trusted,
	.set_vf_default_vport = n20_set_vf_default_vport,
	.set_vf_recv_ximit_by_self = n20_set_vf_recv_ximit_by_self,
	.set_vf_trust_vport_en = n20_set_vf_trust_vport_en,
	.set_vf_update_vm_macaddr = n20_set_vf_update_vm_macaddr,
	.set_vf_update_vm_default_vlan = n20_set_vf_update_vm_default_vlan,
	.set_vf_add_vlan_filter = n20_set_vf_add_vlan_filter,
	.set_vf_del_vlan_filter = n20_set_vf_del_vlan_filter,
	.set_vf_clear_vlan_filter = n20_set_vf_clear_vlan_filter,
	.set_vf_set_veb_act = n20_set_vf_set_veb_act,
	.set_vf_set_vlan_promisc = n20_set_vf_set_vlan_promisc,
	.set_vf_set_vtag_vport_en = n20_set_vf_set_vtag_vport_en,
	.set_vf_add_mc_fliter = n20_set_vf_add_mc_fliter,
	.set_vf_del_mc_filter = n20_set_vf_del_mc_filter,
	.set_vf_clear_mc_filter = n20_set_vf_clear_mc_filter,
	.set_vf_true_promisc = n20_set_vf_true_promisc,
	.set_vf_rqa_tcp_sync_en = n20_set_vf_rqa_tcp_sync_en,
	.set_vf_rqa_tcp_sync_remapping = n20_set_vf_rqa_tcp_sync_remapping,
	.set_vf_bw_limit_init = n20_set_vf_bw_limit_init,
	.set_vf_bw_limit_rate = n20_set_vf_bw_limit_rate,
	.set_vf_rebase_ring_base = n20_set_vf_rebase_ring_base,
};

int mce_get_n20_caps(struct mce_hw *hw)
{
	u8 rss_default_key[N20_RSS_HASH_KEY_SIZE] = {
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41,
		0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca,
		0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d,
		0xa3, 0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b,
		0xbe, 0xac, 0x01, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	struct phy_abilities ability;
	int ret = 0;
	u32 value;

	hw->mbx.ops = &mbx_ops_generic;
	n20_init_mbx_info(hw);
	/* get capability from fw */
	hw->mbx.ops->init_params(hw);
	ret = mce_fw_get_capability(hw, &ability);
	if (ret < 0)
		return ret;

	//hw->qos.link_speed = 10000; // unit Mbit
	// later should get this from phy
	hw->qos.link_speed = 25000; // unit Mbit
	hw->qos.interal = 100; // unit ms

	hw->qos.rate = (1000 / hw->qos.interal); //interal*rate=1s
	hw->dma_qs = hw->qos.qg_mode = ability.dma_qs;
	hw->func_caps.common_cap.num_txq = N20_MAX_Q_CNT;
	hw->func_caps.common_cap.num_rxq = N20_MAX_Q_CNT;
	hw->func_caps.common_cap.max_tc = MCE_MAX_TC_CNT;
	hw->func_caps.common_cap.queue_for_tc = MCE_QUEUE_FOR_TC; 
	hw->func_caps.common_cap.vf_num_txq =
		mce_int_pow(2, ability.dma_qs + 2);
	hw->func_caps.common_cap.vf_num_rxq =
		mce_int_pow(2, ability.dma_qs + 2);
	hw->func_caps.common_cap.max_vfs =
		N20_MAX_Q_CNT / hw->func_caps.common_cap.vf_num_rxq - 1;
	hw->vf_uc_addr_offset = N20_VM_T4_VF_ADDR_ENTRY_OFF;
	hw->vf_macvlan_addr_offset = N20_VM_T4_MACVLAN_ADDR_ENTRY_OFF;
	hw->vf_bcmc_addr_offset = N20_VM_T4_BCMC_ADDR_ENTRY_OFF;

	hw->func_caps.common_cap.pcie_irq_capable =
		BIT(MCE_PCIE_IRQ_MODE_MSIX)
#ifdef MCE_DEBUG_XINSI_PCIE
		| BIT(MCE_PCIE_IRQ_MODE_MSI) |
		BIT(MCE_PCIE_IRQ_MODE_LEGENCY)
#endif
		;
	hw->func_caps.guar_num_vsi = 1;
	hw->func_caps.common_cap.vlan_strip_cnt =
		N20_VLAN_DEFAULT_STRIP_CNT;

	hw->func_caps.common_cap.mbox_irq_base = N20_MBOX_IRQ_BASE;
	hw->func_caps.common_cap.num_mbox_irqs = N20_NUM_MBOX_IRQS;
	hw->func_caps.common_cap.rdma_irq_base = N20_RDMA_IRQ_BASE;
	hw->func_caps.common_cap.num_rdma_irqs = N20_NUM_RDMA_IRQS;
	hw->func_caps.common_cap.qvec_irq_base = N20_QVEC_IRQ_BASE;
	hw->func_caps.common_cap.max_irq_cnts = N20_MAX_IRQS;

	hw->func_caps.common_cap.rss_table_size = N20_RSS_PF_TABLE_SIZE;
	hw->func_caps.common_cap.rss_key_size = N20_RSS_HASH_KEY_SIZE;
#ifdef HAVE_SRIOV_CONFIGURE
	hw->func_caps.common_cap.sr_iov = 1;
#endif
	hw->func_caps.common_cap.mac_misc_irq_retry = true;
	hw->func_caps.common_cap.mac_misc_irq = 0
		/* BIT(MCE_MAC_MISC_IRQ_PCS_LINK) |
		BIT(MCE_MAC_MISC_IRQ_PTP) | BIT(MCE_MAC_MISC_IRQ_FLR) */
		;
	hw->func_caps.common_cap.npu_capable = false;
	memcpy(hw->rss_key, rss_default_key, sizeof(rss_default_key));
	hw->rss_hash_type |= F_IPV6_HASH_EN;
	hw->rss_hash_type |= F_IPV4_HASH_EN;
	hw->rss_hash_type |= F_IPV6_HASH_TCP_EN;
	hw->rss_hash_type |= F_IPV4_HASH_TCP_EN;
	hw->rss_hash_type |= F_IPV6_HASH_UDP_EN;
	hw->rss_hash_type |= F_IPV4_HASH_UDP_EN;
	hw->rss_hash_type |= F_ONLY_HASH_FLEX_EN;
	hw->rss_hfunc = ETH_RSS_HASH_TOP;

	hw->nic_version = rd32(hw, N20_NIC_OFF(N20_NIC_VERSION));
	hw->dma_version = rd32(hw, N20_DMA_OFF(N20_DMA_VERSION));
	/* fix queue num */
	value = (rd32(hw, N20_DMA_OFF(N20_DMA_STATUS))) >> 24;

	if (value < N20_MAX_Q_CNT) {
		printk("hw has smaller queue %x\n", value);
			hw->func_caps.common_cap.num_txq = value;
			hw->func_caps.common_cap.num_rxq = value;
			hw->func_caps.common_cap.max_vfs =
				value / hw->func_caps.common_cap.vf_num_rxq - 1;
	} else {
		printk("hw queue num match\n");

	}

	hw->ops = &n20_ops;
	hw->vf.ops = &n20_vf_ops;
	printk("dma_version %x\n", hw->dma_version);
	/* setup mbx */

	hw->cur_tc_time_for_rdma = 1024;
	/* only for test 25Gbps in tc_time */
	hw->cur_link_speed = 25 * 1024 / hw->cur_tc_time_for_rdma;
	hw->uc_mc_hash_ctl.type = MCE_UC_MC_HASH_TYPE_BIT_11_0_OR_47_36;
	hw->uc_mc_hash_ctl.uc_s_low = true;
	hw->uc_mc_hash_ctl.mc_s_low = true;
	return 0;
}
