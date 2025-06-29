/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#ifndef __MCE_PTP_H__
#define __MCE_PTP_H__

/* hardware ts can't so fake ts from the software clock */
#ifdef HAVE_PTP_1588_CLOCK
int mce_ptp_get_ts_config(struct mce_pf *pf, struct ifreq *ifr);
int mce_ptp_set_ts_config(struct mce_pf *pf, struct ifreq *ifr);
int mce_ptp_register(struct mce_pf *pf);
void mce_ptp_unregister(struct mce_pf *pf);
void mce_ptp_get_rx_hwstamp(struct mce_pf *pf, struct mce_rx_desc_up *desc,
			    struct sk_buff *skb);
void mce_tx_hwtstamp_work(struct work_struct *work);
#endif
#define PTP_HWTX_TIME_VALUE_MASK GENMASK(31, 0)
#define MCE_RX_SEC_MASK GENMASK(30, 0)
#define MCE_RX_NSEC_MASK GENMASK(30, 0)

/* add for chengjian temp */
/* IEEE 1588 PTP register offsets */
#define PTP_TCR 0x00 /* Timestamp Control Reg */
#define PTP_SSIR 0x04 /* Sub-Second Increment Reg */
#define PTP_STSR 0x08 /* System Time – Seconds Regr */
#define PTP_STNSR 0x0c /* System Time – Nanoseconds Reg */
#define PTP_STSUR 0x10 /* System Time – Seconds Update Reg */
#define PTP_STNSUR 0x14 /* System Time – Nanoseconds Update Reg */
#define PTP_TAR 0x18 /* Timestamp Addend Reg */
#define PTP_PPS_CONTROL 0x2c
#define RNP_PTP_STNSUR_ADDSUB_SHIFT 31
#define RNP_PTP_DIGITAL_ROLLOVER_MODE 0x3B9ACA00 /* 10e9-1 ns */
#define RNP_PTP_BINARY_ROLLOVER_MODE 0x80000000 /* ~0.466 ns */
/* PTP Timestamp control register defines */
#define RNP_PTP_TCR_TSENA BIT(0) /*Timestamp Enable*/
#define RNP_PTP_TCR_TSCFUPDT BIT(1) /* Timestamp Fine/Coarse Update */
#define RNP_PTP_TCR_TSINIT BIT(2) /* Timestamp Initialize */
#define RNP_PTP_TCR_TSUPDT BIT(3) /* Timestamp Update */
#define RNP_PTP_TCR_TSTRIG BIT(4) /* Timestamp Interrupt Trigger Enable */
#define RNP_PTP_TCR_TSADDREG BIT(5) /* Addend Reg Update */
#define RNP_PTP_TCR_TSENALL BIT(8) /* Enable Timestamp for All Frames */
#define RNP_PTP_TCR_TSCTRLSSR BIT(9) /* Digital or Binary Rollover Control */
#define RNP_PTP_TCR_TSVER2ENA                                                  \
        BIT(10) /* Enable PTP packet Processing for Version 2 Format */
#define RNP_PTP_TCR_TSIPENA                                                    \
        BIT(11) /* Enable Processing of PTP over Ethernet Frames */
#define RNP_PTP_TCR_TSIPV6ENA                                                  \
        BIT(12) /* Enable Processing of PTP Frames Sent over IPv6-UDP */
#define RNP_PTP_TCR_TSIPV4ENA                                                  \
        BIT(13) /* Enable Processing of PTP Frames Sent over IPv4-UDP */
#define RNP_PTP_TCR_TSEVNTENA                                                  \
        BIT(14) /* Enable Timestamp Snapshot for Event Messages */
#define RNP_PTP_TCR_TSMSTRENA                                                  \
        BIT(15) /* Enable Snapshot for Messages Relevant to Master */
/* Sub Second increament define */
#define RNP_PTP_SSIR_SSINC_MASK (0xff) /* Sub-second increment value */
#define RNP_PTP_SSIR_SSINC_SHIFT (16) /* Sub-second increment offset */
#define RNP_MAC_TXTSC BIT(15) /* TX timestamp reg is fill complete */
#define RNP_MAC_TXTSSTSLO GENMASK(30, 0) /* nano second avalid value  */
#define RNP_RX_SEC_MASK GENMASK(30, 0)
#define RNP_RX_NSEC_MASK GENMASK(30, 0)
#define RNP_RX_TIME_RESERVE (8)
#define RNP_RX_SEC_SIZE (4)
#define RNP_RX_NANOSEC_SIZE (4)
#define RNP_RX_HWTS_OFFSET                                                     \
        (RNP_RX_SEC_SIZE + RNP_RX_NANOSEC_SIZE + RNP_RX_TIME_RESERVE)
#define PTP_HWTX_TIME_VALUE_MASK GENMASK(31, 0)
#define PTP_GET_TX_HWTS_FINISH (1)
#define PTP_GET_TX_HWTS_UPDATE (0)

struct gmac_hwtimestamp {
        void (*config_hw_tstamping)(void __iomem *ioaddr, u32 data);
        void (*config_sub_second_increment)(void __iomem *ioaddr, u32 ptp_clock,
                                            int gmac4, u32 *ssinc);
        void (*config_mac_irq_enable)(void __iomem *ioaddr, bool on);
        int (*init_systime)(void __iomem *ioaddr, u32 sec, u32 nsec);
        int (*config_addend)(void __iomem *ioaddr, u32 addend);
        int (*adjust_systime)(void __iomem *ioaddr, u32 sec, u32 nsec,
                              int add_sub, int gmac4);
        void (*get_systime)(void __iomem *ioaddr, u64 *systime);
};

#define RNP_PTP_TCR_SNAPTYPSEL_1 BIT(16)
#endif
