#ifndef _MCE_HW_N20_H_
#define _MCE_HW_N20_H_

#define N20_VLAN_MAX_STRIP_CNT (2)
#define N20_VLAN_DEFAULT_STRIP_CNT (1)

/* ==============================N20 invariants start ====================*/
#define N20_MAX_Q_CNT (16)
/* TODO: in FPGA, soc must modify this */
#define N20_PF_CNT (1)
#define N20_VF_CNT (hw->func_caps.common_cap.max_vfs)
#define N20_MAX_PKT_LEN (9722)
#define N20_RSS_PF_TABLE_SIZE (512)
#define N20_MAX_RING_CNT N20_RSS_PF_TABLE_SIZE
#define N20_RSS_VF_TABLE_SIZE (hw->ring_max_cnt)
#define N20_RSS_HASH_KEY_SIZE (13 * 4)
#define N20_MAX_NTUPLE_CNT MCE_ACL_MAX_TUPLE5_CNT
#define N20_MAX_ETYPE_CNT MCE_MAX_ETYPE_CNT
#define N20_MAX_FDIR_CNT      \
	(N20_MAX_NTUPLE_CNT + \
	 (N20_VF_CNT + N20_PF_CNT) * N20_MAX_ETYPE_CNT)
#define N20_LOC_FDIR_CNT      \
	(N20_MAX_NTUPLE_CNT + \
	 (pf->num_vfs + N20_PF_CNT) * N20_MAX_ETYPE_CNT)
#ifdef MCE_DEBUG_XINSI_PCIE
#define N20_MBOX_IRQ_BASE (0)
#define N20_NUM_MBOX_IRQS (1)
#define N20_RDMA_IRQ_BASE (N20_MAX_Q_CNT + N20_NUM_MBOX_IRQS)
#define N20_NUM_RDMA_IRQS (2)
#define N20_QVEC_IRQ_BASE (1)
#define N20_MAX_IRQS (1536)
#else

#ifdef MCE_13P_DEBUG_MSIX
#define N20_MBOX_IRQ_BASE (0)
#else
#define N20_MBOX_IRQ_BASE (7)
#endif
#define N20_NUM_MBOX_IRQS (1)
#define N20_RDMA_IRQ_BASE (4)
#define N20_NUM_RDMA_IRQS (2)
#ifdef MCE_13P_DEBUG_MSIX
#define N20_QVEC_IRQ_BASE (1)
#else
#define N20_QVEC_IRQ_BASE (0)
#endif
#define N20_MAX_IRQS (8)
#endif
#define N20_VAL_RX_TIMEOUT (1000)
//#define N20_USECSTOCOUNT (250)
#define N20_USECSTOCOUNT (100)
#define N20_FIFO_PROG_CNT (8)
#define N20_FIFO_TAL_DEEP (8192)
#define N20_RESEVER (512)
/* vf num start from 4 */
#define N20_VM_MAX_VF_MACVLAN_NUMS MCE_VM_MAX_VF_MACVLAN_NUMS

/* the vf max entries is 512, setup 32 for fpga debug */
#define N20_VF_MAX_ENTRIES (32)
/* T4 invariants*/
#define N20_VM_T4_BCMC_ADDR_ENTRY_OFF (N20_VF_MAX_ENTRIES - 1)
#define N20_VM_T4_VF_ADDR_ENTRY_OFF \
	(N20_VM_T4_BCMC_ADDR_ENTRY_OFF - N20_VF_CNT)
#define N20_VM_T4_PF_ADDR_ENTRY_OFF (N20_VM_T4_VF_ADDR_ENTRY_OFF - 1)
#define N20_VM_T4_PF_DAFAULT_ADDR_ENTRY N20_VM_T4_PF_ADDR_ENTRY_OFF
/* one vf support max macvlan nums */
#define N20_VM_T4_MACVLAN_ADDR_ENTRY_OFF   \
	(N20_VM_T4_PF_DAFAULT_ADDR_ENTRY - \
	 N20_VF_CNT * N20_VM_MAX_VF_MACVLAN_NUMS)

#define __N20_VM_T4_IS_FPGA (1)
#if __N20_VM_T4_IS_FPGA
#define N20_VM_T4_VF_UC_INDEX(loc)                                   \
	(loc) >= N20_VM_T4_PF_ADDR_ENTRY_OFF ?                       \
		((loc) + N20_PF_CNT - N20_VM_T4_VF_ADDR_ENTRY_OFF) : \
		N20_VM_T4_PF_ADDR_ENTRY_OFF - (loc) + N20_PF_CNT +   \
			N20_VF_CNT - 1
#else
#define N20_VM_T4_VF_UC_INDEX(loc)                  \
	((loc) == N20_VM_T4_PF_DAFAULT_ADDR_ENTRY ? \
		 N20_VF_CNT :                       \
		 (loc) - N20_VM_T4_VF_ADDR_ENTRY_OFF)
#endif
#define FORMAT_FLAG(reg, val, width, offset)                      \
	(reg = (((reg) & (~((~((~(0x0)) << width)) << offset))) | \
		(((val) & (~((~0x0) << width))) << offset)))

/* MAC + PCS reg */
#define N20_MAC_PCS_REG_BASE (0x60000)
/* MAC reg offset */
#define N20_MAC_OFF(off) (N20_MAC_PCS_REG_BASE + 0x6800 + (off))
#define N20_MAC_INT_STAT(i) (0x0100 + (i) * 0x4)
#define N20_MAC_INT_MASK(i) (0x0120 + (i) * 0x4)
#define N20_MAC_INT_CLR(i) (0x0140 + (i) * 0x4)

/* PCS reg offset */
#define N20_PCS_OFF(off) (N20_MAC_PCS_REG_BASE + (off))
/* NIC reg*/
#define N20_NIC_REG_BASE (0x70000)
#define N20_NIC_VERSION (0x0000)
#define N20_NIC_CONFIG (0x0004)
#define F_VIRTUAAL_SW_OFFSET (0)
#define N20_NIC_STATUS (0x0008)
#define N20_NIC_DUMMY (0x000c)
#define N20_NIC_RESET (0x0010)
#define F_NIC_RESET_NIC BIT(0)
#define F_NIC_RESET_BMC BIT(1)
#define F_NIC_RESET_REG BIT(2)
#define F_NIC_RESET_EN \
	(F_NIC_RESET_NIC | F_NIC_RESET_BMC | F_NIC_RESET_REG)
#define F_NIC_RESET_NIC_MASK BIT(16)
#define F_NIC_RESET_BMC_MASK BIT(17)
#define F_NIC_RESET_REG_MASK BIT(18)
#define F_NIC_RESET_MASK                               \
	(F_NIC_RESET_NIC_MASK | F_NIC_RESET_BMC_MASK | \
	 F_NIC_RESET_REG_MASK)

#define N20_NIC_MSI_CONFIG (0x0014)
#define F_NIC_MSI_CONFIG_LEGENCY_EN BIT(31)
#define F_NIC_MSI_CONFIG_MSIX_TICK_TIMER(reg, val) \
	FORMAT_FLAG(reg, val, 31, 0)

#define N20_NIC_MSIX_CONFIG (0x0018)

#define N20_NIC_MAC_OUI (0x2000)
#define N20_NIC_MAC_SN (0x2004)

#define N20_NIC_OFF(off) (N20_NIC_REG_BASE + (off))

/* DMA reg */
#define N20_DMA_REG_BASE (0x40000)
#define N20_DMA_OFF(off) (N20_DMA_REG_BASE + (off))

#define N20_DMA_VERSION (0x0)
#define N20_DMA_CONFIG (0x4)
#define N20_DMA_STATUS (0x8)
#define F_DMA_TSO_CNTS_EN BIT(30)
#define F_TX_WB_EN BIT(31) //DMA 0x4 flags tx回写聚合使能
#define F_RX_WB_EN BIT(30) //DMA 0x4 flags rx回写聚合使能
#define F_VF_ACTIVE_OFFSET (25) //DMA 0x4 flags
#define N20_DMA_DUMY (0xc)
#define N20_DMA_AXI_EN (0x10)
#define F_TX_AXI_RW_MS (0xc0000) //DMA 0x10 flags tx 掩码
#define F_TX_AXI_RW_EN (0x0000c) //DMA 0x10 flags
#define F_RX_AXI_RW_MS (0x30000) //DMA 0x10 flags rx 掩码
#define F_RX_AXI_RW_EN (0x00003) //DMA 0x10 flags
#define N20_DMA_AXI_STATUS (0x14)
#define N20_PFC_FIFO_DEPTH(i) (0xd0 + (i) * 0x4)
#define N20_PFC_FIFO_SELECT (0xe0)

#define N20_DEBUG_PROBE_10 (0x150)
#define N20_NIC_DMA_FLR_STATUS(i) (0x30 + (i) * 4)
#define N20_NIC_DMA_FLR_MASK(i) (0x40 + (i) * 4)
#define N20_NIC_DMA_FLR_CLR(i) (0x50 + (i) * 4)
// tc
#define N20_DMA_TC_BW(i) (0x1000 + (0x4 * (i)))
#define N20_DMA_TC_CTRL (0x1020)
#define F_TC_EN BIT(31) //使能TC
#define F_TC_BP_MOD BIT(30) //BPS模式
#define F_TC_PP_MOD BIT(29) //PPS模式
#define F_TC_CRC BIT(28) //是否将报文中的CRC计入流量
#define F_TC_INTERAL_EN BIT(27) //清零使能信号
#define F_TC_INTERAL_OFFSET (16) //[25:16] 清零间隔 单位ms
#define F_TC_VALID_OFFSET (8) //[15:8] TC有效标识
#define F_TC_TSA_OFFSET (0) //[7:0] TC算法属性 1是ets 0是sp
#define N20_DMA_TC_TAL_BW (0x1024) //TC带宽调试
#define SP_TIMEOUT (0x61a8)
#define ETS_TIMEOUT (0x0400)
#define N20_DMA_TC_TIMEOUT \
	(0x1028) //bit[31:16] sp timeout bit[15:0] ets timeout
#define F_TC_BW_EN BIT(31) //TC带宽有效使能
#define F_TC_BW_SHARE_EN BIT(30) //TC带宽共享使能
#define F_TC_BW_OFFSET (0) //[29:0]TC总带宽 单位512bit
#define N20_DMA_TC_QG_CTRL(i) (0x1200 + (0x4 * (i)))
#define F_BURST_EN BIT(31) //支持突发流量补偿
#define F_RESTRIC_BYTE BIT(30) //高精度字节限流
#define F_WEIGHT_EN BIT(7) //这里必须要配置
#define N20_DMA_VF_QG_CTRL (0x102c)
#define F_VF_LIMIT_EN BIT(31)
#define F_SET_VF_QG_NUM(reg, val) FORMAT_FLAG(reg, val, 3, 0)

#define N20_DMA_TC_QG_PPS_CIR (0x1400)
#define N20_DMA_TC_QG_PPS_PIR (0x1600)
#define N20_DMA_TC_QG_BPS_CIR(i) (0x1800 + (0x4 * (i)))
#define N20_DMA_TC_QG_BPS_PIR(i) (0x1a00 + (0x4 * (i)))
#define N20_DMA_TC_VF_QG_BYTE_LIMIT(i) (0x1c00 + (0x4 * (i)))

// DMA debug
#define N20_DMA_D_TX_IRQ_CNT (0x200) //发送中断计数器
#define N20_DMA_D_RX_IRQ_CNT (0x204) //接收中断计数器
#define N20_DMA_D_CH0_TX_CTRL_DATA_FRAG_CNT (0x208) //通道0发送数据分片计数
#define N20_DMA_D_CH1_TX_CTRL_DATA_FRAG_CNT (0x20c) //通道1发送数据分片计数
#define N20_DMA_D_CH2_TX_CTRL_DATA_FRAG_CNT (0x210) //通道2发送数据分片计数
#define N20_DMA_D_CH3_TX_CTRL_DATA_FRAG_CNT (0x214) //通道3发送数据分片计数
#define N20_DMA_D_TX_CTRL_RD_DESC_CNT (0x218) //读描述符计数
#define N20_DMA_D_TX_CTRL_RD_PKGS_CNT (0x21c) //读数据包计数
#define N20_DMA_D_TX_CTRL_FIFO0_DESC_AVG (0x220) //下行fifo0描述符平均值
#define N20_DMA_D_TX_CTRL_FIFO1_DESC_AVG (0x224) //下行fifo1描述符平均值
#define N20_DMA_D_TX_CTRL_FIFO2_DESC_AVG (0x228) //下行fifo2描述符平均值
#define N20_DMA_D_TX_CTRL_FIFO3_DESC_AVG (0x22c) //下行fifo3描述符平均值
#define N20_DMA_D_RX_CTRL_PCIE_RD_REQ (0x230) //pcie读请求计数
#define N20_DMA_D_RX_CTRL_PCIE_WR_REQ (0x234) //pcie读请求计数
#define N20_DMA_D_RX_CTRL_WR_DESC_CNT (0x238) //描述符写入计数
#define N20_DMA_D_RX_CTRL_RD_PKGS_CNT (0x23c) //读数据包计数
#define N20_DMA_D_RX_CTRL_FIFO0_DESC_AVG (0x240) //上行fifo0描述符平均值
#define N20_DMA_D_RX_CTRL_FIFO1_DESC_AVG (0x244) //上行fifo1描述符平均值
#define N20_DMA_D_RX_CTRL_FIFO2_DESC_AVG (0x248) //上行fifo2描述符平均值
#define N20_DMA_D_RX_CTRL_FIFO3_DESC_AVG (0x24c) //上行fifo3描述符平均值
#define N20_DMA_D_RX_CTRL_RING0_NO_DESC_AVG \
	(0x250) //上行ring0数据无对应描述符出现计数平均值
#define N20_DMA_D_RX_CTRL_RING1_NO_DESC_AVG \
	(0x254) //上行ring1数据无对应描述符出现计数平均值
#define N20_DMA_D_RX_CTRL_RING2_NO_DESC_AVG \
	(0x258) //上行ring2数据无对应描述符出现计数平均值
#define N20_DMA_D_RX_CTRL_RING3_NO_DESC_AVG \
	(0x25c) //上行ring3数据无对应描述符出现计数平均值
#define N20_DMA_D_TX_AXI_RD_CMD_CNT (0x260) //发送读cmd计数器
#define N20_DMA_D_TX_AXI_WR_CMD_CNT (0x264) //发送写cmd计数器
#define N20_DMA_D_TX_AXI_RD_PKGS_CNT (0x268) //发送读pkt计数器
#define N20_DMA_D_TX_AXI_WR_PKGS_CNT (0x26c) //发送写pkt计数器
#define N20_DMA_D_TX_AXI_RD_CMD_AVG (0x270) //发送读cmd计数平均值
#define N20_DMA_D_TX_AXI_WR_CMD_AVG (0x274) //发送写cmd计数平均值
#define N20_DMA_D_TX_AXI_RD_PKGS_AVG (0x278) //发送读pkt计数平均值
#define N20_DMA_D_TX_AXI_WR_PKGS_AVG (0x27c) //发送写pkt计数平均值
#define N20_DMA_D_RX_AXI_RD_CMD_CNT (0x280) //上行读cmd计数器
#define N20_DMA_D_RX_AXI_WR_CMD_CNT (0x284) //上行写cmd计数器
#define N20_DMA_D_RX_AXI_RD_PKGS_CNT (0x288) //上行读pkt计数器
#define N20_DMA_D_RX_AXI_WR_PKGS_CNT (0x28c) //上行写pkt计数器
#define N20_DMA_D_RX_AXI_RD_CMD_AVG (0x290) //上行读cmd计数平均值
#define N20_DMA_D_RX_AXI_WR_CMD_AVG (0x294) //上行写cmd计数平均值
#define N20_DMA_D_RX_AXI_RD_PKGS_AVG (0x298) //上行读pkt计数平均值
#define N20_DMA_D_RX_AXI_WR_PKGS_AVG (0x29c) //上行写pkt计数平均值
#define N20_DMA_D_RX_IFIFO_PKGS_IN_CNT (0x2a0) //接收数据输入数据包计数
#define N20_DMA_D_RX_IFIFO_PKGS_OUT_CNT (0x2a4) //接收数据输出数据包计数
#define N20_DMA_D_RX_OFIFO_PKGS_IN_CNT (0x2a8) //接收数据输入数据包计数
#define N20_DMA_D_RX_OFIFO_PKGS_OUT_CNT (0x2ac) //接收数据输出数据包计数
#define N20_DMA_D_TX_RING0_INT_STATUS (0x2c8) //发送方向ring0中断状态
#define N20_DMA_D_TX_RING1_INT_STATUS (0x2cc) //发送方向ring1中断状态
#define N20_DMA_D_TX_RING2_INT_STATUS (0x2d0) //发送方向ring2中断状态
#define N20_DMA_D_TX_RING3_INT_STATUS (0x2d4) //发送方向ring3中断状态
#define N20_DMA_D_RX_RING0_INT_STATUS (0x2d8) //接收方向ring0中断状态
#define N20_DMA_D_RX_RING1_INT_STATUS (0x2dc) //接收方向ring1中断状态
#define N20_DMA_D_RX_RING2_INT_STATUS (0x2e0) //接收方向ring2中断状态
#define N20_DMA_D_RX_RING3_INT_STATUS (0x2e4) //接收方向ring3中断状态

/* Ring common REG */
#define N20_RING_BASE (0x0000)
#define N20_RING_OFF(i) (N20_RING_BASE + (0x100 * (i)))

/* Ring Enable and interrupt status REG*/
#define N20_DMA_REG_RX_START (0x10)
#define N20_DMA_REG_RX_READY (0x14)
#define N20_DMA_REG_TX_START (0x18)
#define N20_DMA_REG_TX_READY (0x1c)
#define N20_DMA_REG_INT_STAT (0x20)
#define N20_DMA_REG_INT_MASK (0x24)
#define N20_DMA_REG_INT_CLEAR (0x28)
#define N20_DMA_REG_INT_TRIG (0x2c)
#define _F_N20_DMA_INT_SET_TRIG_TX (BIT(19) | BIT(3))
#define _F_N20_DMA_INT_CLR_TRIG_TX BIT(19)

/*HW RX DIM*/
//#define IRQ_MAX_200K (2000000)
// 200,000 -- 1500,000 should use hw dim
#define IRQ_MAX_200K (30 * 1024 * 1024) /* 30 / ms 30000 /s */
#define IRQ_MIN_200K (10) /* 5 / ms 5000 /s */

#define IRQ_MAX_200K_RX (30 * 1024 * 1024) /* 30 / ms 30000 /s */
#define IRQ_MIN_200K_RX (1000) /* 5 / ms 5000 /s */

#define IRQ_MAX_50K (50000)
#define DMA_REG_RX_PKT_RATE_LOW (0xA0)
#define DMA_REG_RX_PKT_RATE_HIGH (0xA4)
#define DMA_REG_RX_INT_FRAMES (0xA8)
#define DMA_REG_RX_INT_USECS (0xAC)
/*HW TX DIM*/
#define DMA_REG_TX_PKT_RATE_LOW (0xB0)
#define DMA_REG_TX_PKT_RATE_HIGH (0xB4)
#define DMA_REG_TX_INT_FRAMES (0xB8)
#define DMA_REG_TX_INT_USECS (0xBC)
#define DMA_INT_INTERVAL_EN (1UL << 31)

#define F_TX_INT_MASK_MS_BIT (17) // 0x24 flags tx掩码
#define F_TX_INT_MASK_EN_BIT (1) // 0x24 flags
#define F_RX_INT_MASK_MS_BIT (16) // 0x24 flags rx掩码
#define F_RX_INT_MASK_EN_BIT (0) // 0x24 flags
#define F_TX_INT_TRIG_MS_BIT (17) // 0x2c flags tx掩码
#define F_TX_INT_TRIG_EN_BIT (1) // 0x2c flags
#define F_RX_INT_TRIG_MS_BIT (16) // 0x2c flags rx掩码
#define F_RX_INT_TRIG_EN_BIT (0) // 0x2c flags

/* TxRing REG */
#define N20_DMA_REG_TX_DESC_BASE_ADDR_HI (0x60)
#define N20_DMA_REG_TX_DESC_BASE_ADDR_LO (0x64)
#define N20_DMA_REG_TX_DESC_LEN (0x68)
#define N20_DMA_REG_TX_DESC_HEAD (0x6c)
#define N20_DMA_REG_TX_DESC_TAIL (0x70)
#define N20_DMA_REG_TX_DESC_FETCH_CTRL (0x74)
#define N20_DMA_REG_TX_INT_DELAY_TIMER (0x78)
#define N20_DMA_REG_TX_INT_DELAY_PKTCNT (0x7c)
#define N20_DMA_REG_TX_PRIO_LVL (0x80)
#define F_RING_TC_EN (1UL << 31)
#define F_RING_PFC_EN (1UL << 30)
#define F_RING_TC_LOC (16) //[23:16]对应tc7-0
#define N20_DMA_REG_TX_FLOW_CTRL_TH (0x84)
#define N20_DMA_REG_TX_FLOW_CTRL_TM (0x88)

/* RxRing REG */
#define N20_DMA_REG_RX_DESC_BASE_ADDR_HI (0x30)
#define N20_DMA_REG_RX_DESC_BASE_ADDR_LO (0x34)
#define N20_DMA_REG_RX_DESC_LEN (0x38)
#define N20_DMA_REG_RX_DESC_HEAD (0x3c)
#define N20_DMA_REG_RX_DESC_TAIL (0x40)
#define N20_DMA_REG_RX_DESC_FETCH_CTRL (0x44)
#define N20_DMA_REG_RX_INT_DELAY_TIMER (0x48)
#define N20_DMA_REG_RX_INT_DELAY_PKTCNT (0x4c)
#define N20_DMA_REG_RX_ARB_DEF_LVL (0x50)
#define N20_DMA_REG_RX_DESC_TIMEOUT_TH (0x54)
#define N20_DMA_REG_RX_SCATTER_LENGH (0x58)
#define N20_DMA_REG_RX_TIMEOUT_DROP (0x5c)
#define N20_DMA_REG_RX_MPKT_L (0xd0)
#define N20_DMA_REG_RX_MPKT_H (0xd4)
#define N20_DMA_REG_RX_BPKT_L (0xd8)
#define N20_DMA_REG_RX_BPKT_H (0xdc)
/* ETH reg */
#define N20_ETH_REG_BASE (0x80000)
#define N20_ETH_OFF(off) (N20_ETH_REG_BASE + (off))

#define N20_ETH_RX_DEBUG0 (0x6400)
#define N20_ETH_RX_DEBUG4 (0x6410)
#define N20_ETH_RX_DEBUG5 (0x6414)
#define N20_ETH_PARSER_CTRL (0x8000)
#define F_DDP_EXTRA_EN BIT(28)

#define N20_ETH_VXLAN_PORT (0x1000)
#define N20_ETH_VXLAN_GPE_PORT (0x1100)
#define N20_ETH_GENEVE_PORT (0x1200)
#define N20_ETH_IPSEC_PORT (0x1500)

#define N20_ETH_EXCEPT_RX_PROC (0x0470)
#define N20_ETH_EXCEPT_TX_PROC (0x0474)
#define N20_ETH_EMAC_POST_CTRL (0x047c)
#define F_PORT_CTRL_MUL_ANTI_SPOOF_EN BIT(31)
#define F_EMAC_PFC_EN (1UL << 6)
#define N20_ETH_VLAN_TPID(i) (0x0480 + (4 * (i)))
#define N20_ETH_CFG_ADAPTER_CTRL0 (0x04c0)
#define N20_ETH_CFG_ADAPTER_CTRL1 (0x04c4)
#define N20_ETH_CFG_ADAPTER_CTRL(i) (0x04c8 + 0x4 * (i))
#define PFC_LOCK_EN BIT(31)
#define F_TX_CDC (16)
#define N20_ETH_O_VLAN_TYPE(i) (0x1700 + (4 * (i)))
#define N20_ETH_I_VLAN_TYPE(i) (0x1800 + (4 * (i)))

#define N20_ETH_PTP_TX_TSVALUE_STATUS (0x6488)
#define N20_ETH_PTP_TX_LTIMES (0x6480)
#define N20_ETH_PTP_TX_HTIMES (0x6484)
#define N20_ETH_PTP_TX_CLEAR (0x4c0)

#define N20_ETH_L2_CTRL0 (0x8010)
#define F_L2_FILTER_EN (1UL << 31) //ETH 0x8010 flags
#define F_DMAC_FILTER_EN (1UL << 30) //ETH 0x8010 flags
#define F_ANTI_SPOOF_SMAC_FLR_EN BIT(29) //ETH 0x8010 flags
#define F_ANTI_SPOOF_VTAG_FLR_EN BIT(28) //ETH 0x8010 flags
#define F_VLAN_FILTER_EN (1UL << 26) //ETH 0x8010 flags
#define F_UC_HASH_EN (1UL << 24) //ETH 0x8010 flags
#define F_MC_HASH_EN (1UL << 23) //ETH 0x8010 flags
#define F_BC_BYPASS_EN (1UL << 20) //ETH 0x8010 flags
#define F_DN_ANTI_SPOOF_SMAC_FILTER_EN BIT(19) //ETH 0x8010 flags
#define F_DN_ANTI_SPOOF_VTAG_FILTER_EN BIT(18) //ETH 0x8010 flags
#define F_DN_ANTI_SPOOF_DMAC_FILTER_EN BIT(17) //ETH 0x8010 flags
#define F_VEPA_SW_EN BIT(7) //ETH 0x8010 flags
#define F_DN2UP_FLR_EN BIT(6) //ETH 0x8010 flags
#define F_UC_SEL (1UL << 2) //ETH 0x8010 flags
#define F_MC_SEL (1UL << 3) //ETH 0x8010 flags
#define N20_ETH_L2_CTRL0_DEFAULT_CFG                           \
	(F_ANTI_SPOOF_VTAG_FLR_EN | F_ANTI_SPOOF_SMAC_FLR_EN | \
	 F_DN_ANTI_SPOOF_SMAC_FILTER_EN |                      \
	 F_DN_ANTI_SPOOF_VTAG_FILTER_EN |                      \
	 F_DN_ANTI_SPOOF_DMAC_FILTER_EN | F_DN2UP_FLR_EN)

#define N20_ETH_L2_CTRL1 (0x8014)
#define F_MC_CONVERT_TO_BC_EN BIT(31)
#define F_T10_MATCH_EN BIT(21)
#define F_T10_MASK_MATCH BIT(20)
#define F_T4_UP_MASK_MATCH BIT(19)
#define F_T4_DN_MASK_MATCH BIT(18)
#define F_T4_DN_TUNNEL_MASK_MATCH BIT(17)
#define F_T4_DN_VLAN_MATCH_MASK BIT(16)
#define F_T4_DN_IPORT_MATCH_MASK BIT(14)
#define F_T4_UP_TUNNEL_MASK_MATCH BIT(13)
#define F_T4_UP_VLAN_MATCH_MASK BIT(12)
#define F_T4_UP_IPORT_MATCH_MASK BIT(10)
#define F_T4_T10_CONFIG_MASK \
	(F_T10_MATCH_EN | F_T10_MASK_MATCH | F_T4_UP_MASK_MATCH | \
	 F_T4_DN_MASK_MATCH /* | F_T4_UP_TUNNEL_MASK_MATCH |               \
	 F_T4_DN_TUNNEL_MASK_MATCH | F_T4_DN_IPORT_MATCH_MASK |         \
	 F_T4_UP_IPORT_MATCH_MASK */)

#define N20_ETH_FWD_CTRL (0x801c)
#define F_PROMISC_VPORT_UPLINK_EN BIT(11)
#define F_PROMISC_VPORT_VEB_EN BIT(10)
#define F_TRUST_VPORT_EN BIT(9)
#define F_RX_SELF_EN BIT(3)

#define N20_ETH_RQA_CTRL (0x8020)
#define N20_ETH_OFF(off) (N20_ETH_REG_BASE + (off))
#define F_REDIR_EN BIT(31) //ETH 0x8020 flags
#define F_FD_EN BIT(30) //ETH 0x8020 flags
#define F_ETYPE_EN BIT(29) //ETH 0x8020 flags
#define F_TCP_SYNC_EN BIT(28) //ETH 0x8020 flags
#define F_TUPLE5_EN BIT(27) //ETH 0x8020 flags
#define F_RSS_EN BIT(26) //ETH 0x8020 flags
#define F_VF_VLAN_FLR_EN BIT(23) //ETH 0x8020 flags
#define F_ARP_RSS_EN BIT(22) //ETH 0x8020 flags
#define F_MULTI_FILTER_TABLE_EN BIT(25) //ETH 0x8020 flags
#define F_IN_L4_CSM_EN BIT(15) //ETH 0x8020 flags
#define F_IN_L3_CSM_EN BIT(14) //ETH 0x8020 flags
#define F_EX_L4_CSM_EN BIT(13) //ETH 0x8020 flags
#define F_EX_L3_CSM_EN BIT(12) //ETH 0x8020 flags
#define F_EX_LEN_CSM_EN BIT(11) //ETH 0x8020 flags
#define F_EX_MAC_CSM_EN BIT(10) //ETH 0x8020 flags
#define F_RX_CSM_MASK                                       \
	(F_IN_L4_CSM_EN | F_IN_L3_CSM_EN | F_EX_L4_CSM_EN | \
	 F_EX_L3_CSM_EN | F_EX_LEN_CSM_EN |                 \
	 F_EX_MAC_CSM_EN) //ETH 0x8020 flags

#define N20_ETH_RX_PKTS_INGRESS (0x6000) // rx parser输入SOP数据报文数
#define N20_ETH_RX_PKTS_EGRESS (0x6004) // rx parser输入EOP数据报文数
#define N20_ETH_RX_EXCEPT_SHORT (0x6008) // rx parser输入长度异常数据报文数
#define N20_ETH_RX_INNER_SCTP \
	(0x6084) // rx parser输入隧道内层SCTP数据报文数
#define N20_ETH_RX_INNER_TCPSYN \
	(0x6088) // rx parser输入隧道内层SCTP数据报文数
#define N20_ETH_RX_INNER_TCP \
	(0x608c) // rx parser输入隧道内层TCP SYN数据报文数
#define N20_ETH_RX_INNER_UDP (0x6090) // rx parser输入隧道内层UDP数据报文数

#define N20_ETH_RX_INGRESS_PKT_IN (0x61a0) // rx fwd proc
#define N20_ETH_RX_INGRESS_PKT_DROP (0x61a4) // rx fwd proc l2过滤丢包

#define N20_ETH_RX_EDTUP_PKT_IN (0x61d0) // rx editor up
#define N20_ETH_RX_EDTUP_PKT_OUT (0x61d4) // rx editor up

#define N20_ETH_PORT0_RX_PKTS (0x6200) // rx mux模块计数
#define N20_ETH_PORT1_RX_PKTS (0x6204) // rx mux模块计数

#define N20_ETH_RX_ATTR_INGRESS_PKT_IN (0x6230) // rx fwd addr
#define N20_ETH_RX_ATTR_EGRESS_PKT_OUT (0x6234) // rx fwd addr
#define N20_ETH_RX_ATTR_EGRESS_PKT_DROP (0x6238) // rx fwd addr vport丢包

#define N20_ETH_TSO_MAX_LEN (0x80f8) // control
#define N20_ETH_TX_DBG_INPUT_PKTS (0x6500) // rx oop top
#define N20_ETH_TX_DBG_OUTPUT_PKTS (0x6504) // rx oop top
#define N20_ETH_TX_DBG_STATE_STATUS (0x6508) // rx oop top

#define N20_ETH_PAUSE_TX (0)
#define N20_ETH_PAUSE_RX (0)

#define N20_RDMA_TX_VPORT_UNICAST_PKTS (0x20118)
#define N20_RDMA_TX_VPORT_UNICAST_BYTS (0x202e8)
#define N20_RDMA_RX_VPORT_UNICAST_PKTS (0x20210)
#define N20_RDMA_RX_VPORT_UNICAST_BYTS (0x202f0)
#define N20_RDMA_NP_CNP_SENT (0x2015c)
#define N20_RDMA_RP_CNP_HANDLED (0x3007c)
#define N20_RDMA_NP_ECN_MARKED_ROCE_PACKETS (0x202b0)
#define N20_RDMA_RP_CNP_IGNORED (0x30080)
#define N20_RDMA_OUT_OF_SEQUENCE (0x1f21c)
#define N20_RDMA_PACKET_SEQ_ERR (0x1f220)
#define N20_RDMA_ACK_TIMEOUT_ERR (0x1f26c)
#define N20_RDMA_TRIG (0x18004)

// eth reg -- mac wap
#define N20_ETH_RX_DSCP2UP_MAP(n) \
	(0xe300 +                 \
	 ((n) *                   \
	  0x4)) //MAC接收方向的dscp字段映射到UP，每个UP字段占4bit，有效值为0-7
#define N20_ETH_TX_DSCP2UP_MAP(n) \
	(0xe400 +                 \
	 ((n) *                   \
	  0x4)) //MAC发送方向的dscp字段映射到UP，每个UP字段占4bit，有效值为0-7
#define N20_HW_FIFO_CNT (8)
#define N20_ETH_RXADDR_N_RAM(n) \
	(0xe500 + ((n) * 0x4)) //[31:16]-head，[15:0]-tail
#define N20_ETH_TXADDR_N_RAM(n) \
	(0xe520 + ((n) * 0x4)) //[31:16]-head，[15:0]-tail
#define N20_ETH_RX_UP2FIFO_MAP \
	(0xe540) //MAC接收方向的UP映射到MAC接收FIFO通道，每个UP占4bit，有效值为0-7，对应RX_FIFO[0:7]
#define N20_ETH_TX_UP2FIFO_MAP \
	(0xe544) //MAC发送方向的UP映射到MAC接收FIFO通道，每个UP占4bit，有效值为0-7，对应RX_FIFO[0:7]
#define N20_ETH_RX_DEFAULT_FIFO \
	(0xe548) //pfc开启时，MAC接收方向非ip包或者非vlan包对应的fifo，有效值为0-7
#define N20_ETH_RXADDR_ENA (0xe550)
#define N20_ETH_TXADDR_ENA (0xe554)
#define F_RXTXADDR_EN \
	(1UL << 1) //配置MAC接收方向FIFO_0-FIFO7地址分配使能，高电平有效
#define F_RXTXADDR_VALID \
	(1UL << 0) //配置MAC接收方向FIFO_0-FIFO7地址分配生效，上升沿有效
#define N20_ETH_RXFIFO03_PRIO \
	(0xe558) //接收方向FIFO0-FIFO3对应的UP，每个FIFO占8bit，bitmap形式
#define N20_ETH_RXFIFO47_PRIO \
	(0xe55c) //接收方向FIFO4-FIFO7对应的UP，每个FIFO占8bit，bitmap形式
#define N20_ETH_TXFIFO03_PRIO \
	(0xe5d0) //发送方向FIFO0-FIFO3对应的UP，每个FIFO占8bit，bitmap形式
#define N20_ETH_TXFIFO47_PRIO \
	(0xe5d4) //发送方向FIFO4-FIFO7对应的UP，每个FIFO占8bit，bitmap形式
#define N20_ETH_RXFIFO_N_LEAVEL(n) \
	(0xe560 +                  \
	 ((n) *                    \
	  0x4)) //bit[15:00]：MAC接收方向FIFO0低水位线；bit[31:16]：MAC接收方向FIFO0高水位线
#define N20_ETH_PAUSE_CTRL (0xe580)
#define F_RX_PAUSE_EN (1UL << 0) // ETH 0xe580 flags
#define F_TX_PAUSE_EN (1UL << 1) // ETH 0xe580 flags
#define F_DSCP_MODE_EN (1UL << 2)
#define N20_ETH_RXMUX_CTRL (0xe584)
#define N20_ETH_RXMUX_WRR(i) (0xe590 + 0x4 * (i))
#define F_MAC_RR_MODE (1UL << 1) //以RR的模式对各FIFO进行遍历
#define F_MAC_WRR_MODE (1UL << 0) //以RR的模式对各FIFO进行遍历
#define N20_ETH_TXMUX_CTRL (0xe588)
#define N20_ETH_PORT_RX_PROGFULL(n) \
	(0x4000 + ((n) * 0x4)) //prot(0-7) rx fifo 阈值
#define N20_ETH_PORT_TX_PROGFULL(n) \
	(0x4020 + ((n) * 0x4)) //prot(0-7) tx fifo 阈值
#define N20_ETH_TSO_IFIFO_THRESH (0x40d0)
#define N20_ETH_TSO_DATA_THRESH (0x40d4)
#define N20_ETH_TSO_OFIFO_THRESH (0x40d8)

/* ETH FWD ATTR */
#define N20_ETH_TRUSTED_VPORT_ADDR(vfid) (0xe000 + ((vfid) / 32) * 4)
#define F_SET_TRUSTED_VPORT_CTRL(vfid, val) ((val) |= BIT((vfid) % 32))
#define F_CLR_TRUSTED_VPORT_CTRL(vfid, val) ((val) &= ~BIT((vfid) % 32))

#define N20_ETH_TRUE_PROMISC_VPORT_ADDR(vfid) (0xe010 + ((vfid) / 32) * 4)
#define F_SET_TRUE_PROMISC_VPORT_CTRL(vfid, val) \
	((val) |= BIT((vfid) % 32))
#define F_CLR_TRUE_PROMISC_VPORT_CTRL(vfid, val) \
	((val) &= ~BIT((vfid) % 32))

#define N20_ETH_VTAG_VPORT_FILTER_ADDR(vfid) (0xe210 + ((vfid) / 32) * 4)
#define F_SET_VTAG_VPORT_FILTER_CTRL(vfid, val) ((val) |= BIT((vfid) % 32))
#define F_CLR_VTAG_VPORT_FILTER_CTRL(vfid, val) \
	((val) &= ~BIT((vfid) % 32))

#define N20_ETH_DEFAULT_VPORT_ADDR(vfid) (0xe100 + ((vfid) / 32) * 4)
#define F_SET_DEFAULT_VPORT_CTRL(vfid, val) ((val) |= BIT((vfid) % 32))

/* ETH filter reg */
#define N20_ETH_FILTER_REG_BASE (0x90000)
#define N20_ETH_T4_VM_VLAN_PVF(i) (0x1800 + 4 * (i))
#define N20_ETH_VM_T4_ACT_PVF(i) (0x2800 + 4 * (i))
#define F_SET_VM_MATCH_INDEX(reg, val) FORMAT_FLAG(reg, val, 10, 8)

#define N20_ETH_FLTR_DMAC_RAL(i) (0x5000 + (4 * (i)))
#define N20_ETH_FLTR_DMAC_RAH(i) (0x5800 + (4 * (i)))
#define F_MAC_FLTR_EN BIT(31)

#define N20_ETH_VM_IPORT_PVF(i) (0x0000 + (4 * (i)))
#define F_MAC_FILTER_PVF_EN BIT(14)
#define F_VLAN_FILTER_PVF_EN BIT(13)
#define F_MATCH_TYPE_PVF_EN BIT(11)

#define N20_ETH_VM_DMAC_RAL(i) (0x0800 + (4 * (i)))
#define N20_ETH_VM_DMAC_RAH(i) (0x1000 + (4 * (i)))
#define N20_ETH_UC_HASH_TABLE(i) (0x4200 + (4 * (i)))
#define N20_ETH_MC_HASH_TABLE(i) (0x4400 + (4 * (i)))
#define N20_ETH_VLAN_HASH_TABLE(i) (0x4600 + (4 * (i)))

#define N20_ETH_FILTER_OFF(off) (N20_ETH_FILTER_REG_BASE + (off))

/* ETH filter anti-spoof reg */
#define N20_ETH_VM_ANTI_SMAC_RAL(i) (0x4c00 + (4 * (i)))
#define N20_ETH_VM_ANTI_VTAG_SMAC_RAH(i) (0x4e00 + (4 * (i)))
#define F_SET_ANTI_SPOOF_VLAN_ID(reg, val) FORMAT_FLAG(reg, val, 12, 16)
#define F_ANTI_SPOOF_MAC_VALID (BIT(30) | BIT(29))
#define F_ANTI_SPOOF_VLAN_VALID BIT(31)

/* ETH vport attr */
#define N20_ETH_VPORT_ATTR_BASE (0xa0000)
#define N20_ETH_VPORT_ATTR_TABLE(i) (0x0000 + (4 * (i)))
#define N20_ETH_VPORT_OFF(off) (N20_ETH_VPORT_ATTR_BASE + (off))
#define F_VPORT_TRUE_PROMISC_EN BIT(31) //ETH 0x0000 flags
#define F_VPORT_LIMIT_LEN_EN BIT(30) //ETH 0x0000 flags
#define F_SET_VPORT_MAX_LEN(val, len) \
	FORMAT_FLAG(val, len, 14, 16) //ETH 0xe100 flags
#define F_SET_VPORT_DEFAULT_RING(val, len) \
	FORMAT_FLAG(val, len, 9, 7) //ETH 0xe100 flags
#define F_VPORT_TUN_SELECT_INNER BIT(6) //ETH 0x0000 flags
#define F_VPORT_TUN_SELECT_INNER_OUTER_EN BIT(5) //ETH 0x0000 flags
#define F_VPORT_MC_PROMISC_EN BIT(4) //ETH 0x0000 flags
#define F_VPORT_UC_PROMISC_EN BIT(3) //ETH 0x0000 flags
#define F_VPORT_VLAN_PROMISC_EN BIT(2) //ETH 0x0000 flags
#define F_VPORT_DROP BIT(0) //ETH 0x0000 flags
#define N20_ETH_VPORT_BITMAP_MEM0(i) (0x1000 + 4 * (i))
#define N20_ETH_VPORT_BITMAP_MEM1(i) (0x2000 + 4 * (i))
#define N20_ETH_VPORT_BITMAP_MEM2(i) (0x3000 + 4 * (i))
#define N20_ETH_VPORT_BITMAP_MEM3(i) (0x4000 + 4 * (i))

#define N20_ETH_VPORT_BITMAP_MEM_INDEX(vfnum) \
	(0x1000 * (((vfnum) / 32) + 1))
#define N20_ETH_VPORT_BITMAP_MEM_OFFSET(off) (4 * ((off) % 1024))
#define N20_ETH_VPORT_SET_BITMAP(vfnum, off)     \
	(N20_ETH_VPORT_BITMAP_MEM_INDEX(vfnum) + \
	 N20_ETH_VPORT_BITMAP_MEM_OFFSET(off))

/* ACL rule action */
#define F_ACL_ACTION_DROP BIT(31)
#define F_ACL_ACTION_RING_EN BIT(30)
#define F_ACL_ACTION_VLAN_EN BIT(29)
#define F_ACL_ACTION_MARK_EN BIT(28)
#define F_ACL_ACTION_PRIO_EN BIT(27)
#define F_ACL_ACTION_SET_RING_ID(val, id) FORMAT_FLAG(val, id, 9, 18)
#define F_ACL_ACTION_SET_MARK(val, mr) FORMAT_FLAG(val, mr, 16, 0)

#define N20_ETH_RQA_ETYPE_BASE (0xb0000)
/* every vf has it's own etype filter */
#define N20_ETH_RQA_ETQF_OFF(vfid, off) \
	(N20_ETH_RQA_ETYPE_BASE + (vfid) * 0x40 + (off) * 4)
#define N20_ETH_RQA_ETQS_OFF(vfid, off) \
	(N20_ETH_RQA_ETYPE_BASE + 0x2000 + (vfid) * 0x40 + (off) * 4)

/* VF MC white lists table */
#define N20_ETH_VF_MC_FILTER_MEM_BASE(bank) (0xb4000 + (bank) * 0x2000)
#define N20_ETH_VF_MC_OFF(bank, vfnum, idx)                  \
	(N20_ETH_VF_MC_FILTER_MEM_BASE((bank)) + (idx) * 4 + \
	 (vfnum) * 0x40)

/* VF VLAN white lists table */
#define N20_ETH_VF_VLAN_FILTER_MEM_BASE (0xb8000)
#define N20_ETH_VF_VLAN_OFF(vfnum, entry)                      \
	(N20_ETH_VF_VLAN_FILTER_MEM_BASE + ((entry) / 2) * 4 + \
	 (vfnum) * 0x20)

/* RQA tcpsync filter */
#define N20_RQA_TCP_SYNC_BASE (0xc0000)
#define N20_RQA_TCP_SYNC_OFF(off) (N20_RQA_TCP_SYNC_BASE + (off))
#define N20_RQA_TCP_SYNC_ACL(loc) (0x00 + 0x8 * (loc))
#define N20_RQA_TCP_SYNC_PRI(loc) (0x04 + 0x8 * (loc))

/* RQA tuple5 filter */
#define N20_NTUPLE_REG_BASE (0xd0000)
#define N20_NTUPLE_SIP(i) (0x00 + (0x20 * (i)))
#define N20_NTUPLE_DIP(i) (0x04 + (0x20 * (i)))
#define N20_NTUPLE_PORT(i) (0x08 + (0x20 * (i)))
#define N20_NTUPLE_FILTER(i) (0x0c + (0x20 * (i)))
#define N20_NTUPLE_POLICY(i) (0x10 + (0x20 * (i)))

#define N20_NTUPLE_OFF(off) (N20_NTUPLE_REG_BASE + (off))
#define F_T5_SET_DPORT(val, port) FORMAT_FLAG(val, port, 16, 16)
#define F_T5_SET_SPORT(val, port) FORMAT_FLAG(val, port, 16, 0)
#define F_T5_FILTER_EN BIT(31)
#define F_T5_VPORT_EN BIT(30)
#define F_T5_SET_VPORT_ID(val, id) FORMAT_FLAG(val, id, 7, 23)
#define F_T5_SET_PRIO_ID(val, id) FORMAT_FLAG(val, id, 3, 20)
#define F_T5_L4_TYPE_MASK BIT(19)
#define F_T5_DPORT_MASK BIT(18)
#define F_T5_SPORT_MASK BIT(17)
#define F_T5_DIP_MASK BIT(16)
#define F_T5_SIP_MASK BIT(15)
#define F_T5_SET_IP4_TYPE(val) FORMAT_FLAG(val, 0, 1, 8)
#define F_T5_SET_IP6_TYPE(val) FORMAT_FLAG(val, 1, 1, 8)
#define F_T5_SET_L4_TYPE(val, t) FORMAT_FLAG(val, t, 8, 0)

/* RQA RSS reg*/
#define N20_RSS_REG_BASE (0xe0000)
#define N20_RSS_HASH_ENTRY(i, vfid) (0x0000 + ((i) << 2) + (vfid) * 0x40)
#define N20_RSS_VFT_CONFIG_MEM_BASE(i) (0x2000 + (4 * (i)))
#define N20_RSS_VFT_CONFIG_MEM(i) (0x2000 + (4 * (i)))
#define N20_RSS_ACT_CONFIG_MEM(i) (0x4000 + (4 * (i)))
#define N20_RSS_PFT_CONFIG_MEM(i) (0x6000 + (4 * (i)))

#define N20_RSS_OFF(off) (N20_RSS_REG_BASE + (off))
#define F_SET_VLAN_STRIP_EN(val, cmd) \
	FORMAT_FLAG(val, cmd, 1, 29) //RSS 0x4000 flags
#define F_SET_VLAN_STRIP_CNT(val, cnt) \
	FORMAT_FLAG(val, cnt, 2, 16) //RSS 0x4000 flags
#define F_SET_RETA_HASH_QUEUE_ID(val, id) \
	FORMAT_FLAG(val, id, 9, 18) //RSS 0x4000 flags
#define F_RSS_RETA_QUEUE_EN (1UL << 30) //RSS 0x4000 flags
#define F_RSS_RETA_MASK_EN (1UL << 28) //RSS 0x4000 flags
#define F_IPV6_HASH_SCTP_EN \
	MCE_F_HASH_IPV6_SCTP //RSS 0x0000 mrqc reg flags
#define F_IPV4_HASH_SCTP_EN \
	MCE_F_HASH_IPV4_SCTP //RSS 0x0000 mrqc reg flags
#define F_IPV6_HASH_UDP_EN MCE_F_HASH_IPV6_UDP //RSS 0x0000 mrqc reg flags
#define F_IPV4_HASH_UDP_EN MCE_F_HASH_IPV4_UDP //RSS 0x0000 mrqc reg flags
#define F_IPV6_HASH_TCP_EN MCE_F_HASH_IPV6_TCP //RSS 0x0000 mrqc reg flags
#define F_IPV4_HASH_TCP_EN MCE_F_HASH_IPV4_TCP //RSS 0x0000 mrqc reg flags
#define F_IPV6_HASH_EN MCE_F_HASH_IPV6 //RSS 0x0000 mrqc reg flags
#define F_IPV4_HASH_EN MCE_F_HASH_IPV4 //RSS 0x0000 mrqc reg flags
#define F_IPV6_HASH_TEID_EN \
	MCE_F_HASH_IPV6_TEID //RSS 0x0000 mrqc reg flags
#define F_IPV4_HASH_TEID_EN \
	MCE_F_HASH_IPV4_TEID //RSS 0x0000 mrqc reg flags
#define F_IPV6_HASH_SPI_EN MCE_F_HASH_IPV6_SPI //RSS 0x0000 mrqc reg flags
#define F_IPV4_HASH_SPI_EN MCE_F_HASH_IPV4_SPI //RSS 0x0000 mrqc reg flags
#define F_IPV6_HASH_FLEX_EN \
	MCE_F_HASH_IPV6_FLEX //RSS 0x0000 mrqc reg flags
#define F_IPV4_HASH_FLEX_EN \
	MCE_F_HASH_IPV4_FLEX //RSS 0x0000 mrqc reg flags
#define F_ONLY_HASH_FLEX_EN \
	MCE_F_HASH_ONLY_FLEX //RSS 0x0000 mrqc reg flags
#define F_RSS_HASH_ORDER_EN (1UL << 29) //RSS 0x0000 mrqc reg flags
#define F_RSS_HASH_XOR_EN (1UL << 30) //RSS 0x0000 mrqc reg flags
#define F_RSS_HASH_EN (1UL << 31) //RSS 0x0000 mrqc reg flags

/* PHY reg */
#define N20_PHY_BASE (0x30000)
#define N20_PHY_CTRL0 (0x0)
#define N20_PHY_RGMI_CTRL0 (0x200)

#define N20_PHY_OFF(off) (N20_PHY_BASE + (off))

#ifndef MCE_DEBUG_XINSI_PCIE
/* MSIX reg */
#define N20_MSIX_BASE (0x30000)
#ifdef MCE_13P_DEBUG_MSIX
#define N20_MSIX_RING_VEC(n) (0x7000 + (0x04 * (n)))
#else
#define N20_MSIX_RING_VEC(n) (0xf000 + (0x04 * (n)))
#endif
#else
/* MSIX reg */
#define N20_MSIX_BASE (0x30000)
#define N20_MSIX_RING_VEC(n) (0x7000 + (0x04 * (n)))
#endif
#define N20_IRQ_MB_ST_CLR (0xf108)
#define F_IRQ_AVOID_DROP_INTR_EN BIT(31)
#define N20_MSIX_OFF(off) (N20_MSIX_BASE + (off))
#define N20_MSIX_CFG_VF_NUM (0xb000)
#define N20_MSIX_MISC_IRQ_ST (0xb048)
#define N20_MSIX_MISC_IRQ_CLR (0xb044)
#define N20_MSIX_MISC_IRQ_VEC(i) (0xa000 + (i) * 4)

#define N20_MSIX_MBX_BASE (0x20000 + 0x10000)
#define N20_MSIX_MBX_OFF(off) (N20_MSIX_MBX_BASE + (off))

#define N20_PTP_BASE (0x64000)
#define N20_PTP_OFF(off) (N20_PTP_BASE + (off))

#define N20_MAC_CFG (0)
#define BYPASS_PTP_TIMER_EN BIT(28)
#define N20_PTP_CFG_1 (0x283c)
#define N20_PTP_CFG (0x60)
#define N20_TS_CFG_S (0x300)
#define N20_TS_CFG_NS (0x304)
#define N20_TS_INCR_CNT (0x308) //[15:0] 2  bit[31:16] 16
#define N20_INCR_CNT_NS_FINE (0x310)
#define N20_INCR_CNT_NS_FINE_2 (0x31c)
#define N20_INITIAL_UPDATE_CMD (0x30c)
#define N20_TS_GET_S (0x314)
#define N20_TS_GET_NS (0x318)
#define N20_TS_COMP (0x390)

#define N20_PTP_TCR_TSENA BIT(0) /*Timestamp Enable*/
#define N20_PTP_TX_EN BIT(1)
#define N20_PTP_RX_EN BIT(2)
/* Enable Timestamp for All Frames */
#define N20_PTP_TCR_TSENALL BIT(8)
/* Enable Processing of PTP over Ethernet Frames */
#define N20_PTP_TCR_TSIPENA BIT(9)
/* Enable Processing of PTP Frames Sent over IPv4-UDP */
#define N20_PTP_TCR_TSIPV4ENA BIT(10)
/* Enable Processing of PTP Frames Sent over IPv6-UDP */
#define N20_PTP_TCR_TSIPV6ENA BIT(11)
/* Enable Timestamp Snapshot for Event Messages */
#define N20_PTP_TCR_TSEVNTENA BIT(12)

/* pause fifo */
//#define N20_FIFO0_DFT_DEEP (3984)
#define N20_FIFO0_DFT_DEEP (8192 - 112)
#define N20_UP_DEEP_FOR_FIFO (0x100)

#define N20_RDMA_REG_FUNC_SIZE (0x1C)

#define N20_RDMA_HOL_BLOCKING_EN (0x200)
#define N20_RDMA_CFG_PRIO(i) (0x204 + (i) * 0x4)
#define N20_RDMA_FIFO_FULL_TH(i) (0x224 + (i) * 0x4)
#define N20_RDMA_US_VALUE (0x038)
#define N20_RDMA_DEADLOCK_VALUE (0x244)
#define N20_RDMA_DEADLOCK_EN (0x248)
#define N20_RDMA_DSCP_TABLE(i) (0x30 + (i) * 0x4)
#define N20_RDMA_CFG_PRIO_TC(i) (0x320 + (i) * 0x4)
#define N20_RDMA_BYTES_TC(i) (0x340 + (i) * 0x4)
#define N20_RDMA_TOTAL_BYTE (0x360)
#define N20_RDMA_TC_MODE (0x364)
#define N20_RDMA_TC_TIME (0x368)
#define RDMA_ETS_EN BIT(8)
#define N20_RDMA_TX_RX_ENABLE (0x24)
#define N20_RDMA_PRIO_TYPE (0x2c)
#define N20_RDMA_DCNQCN_OFF(i) (0x30000 + (i))
#define N20_RDMA_BTH(i) (0x20000 + (i))
void n20_enable_proc(struct mce_hw *hw);
void n20_disable_proc(struct mce_hw *hw);

#endif /*_MCE_HW_N20_H_*/
