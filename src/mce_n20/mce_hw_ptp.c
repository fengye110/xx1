#include "../mce.h"
#include "../mce_base.h"
#include "mce_hw_n20.h"
#include <linux/ptp_classify.h>

static void config_close_tstamping(struct mce_hw *hw)
{
	u32 value;
	
	value = rd32(hw, N20_PTP_OFF(N20_PTP_CFG));
	value &= (~(N20_PTP_TX_EN | N20_PTP_RX_EN));
	wr32(hw, N20_PTP_OFF(N20_PTP_CFG), value);
}

void n20_get_systime(struct mce_hw *hw, u64 *systime)
{
	u64 ns;

	ns = rd32(hw, N20_PTP_OFF(N20_TS_GET_NS));

	ns += rd32(hw, N20_PTP_OFF(N20_TS_GET_S)) * 1000000000ULL;

	if (systime)
		*systime = ns;

}

int n20_init_systime(struct mce_hw *hw, u32 sec, u32 nsec)
{
	wr32(hw, N20_PTP_OFF(N20_TS_CFG_S), sec);
	wr32(hw, N20_PTP_OFF(N20_TS_CFG_NS), nsec);

	wr32(hw, N20_PTP_OFF(N20_INITIAL_UPDATE_CMD), BIT(0));

	return 0;
}

int n20_adjust_systime(struct mce_hw *hw, u32 sec, u32 nsec, int add_sub)
{
	if (add_sub) {
		/* if sub */
		nsec = 1000000000 - nsec;
		nsec |= BIT(31);
	}

	wr32(hw, N20_PTP_OFF(N20_TS_CFG_S), sec);
	wr32(hw, N20_PTP_OFF(N20_TS_CFG_NS), nsec);
	/* update time */
	wr32(hw, N20_PTP_OFF(N20_INITIAL_UPDATE_CMD), BIT(1));

	return 0;
}

/* do adjfine */
int n20_adjfine(struct mce_hw *hw, long scaled_ppm)
{
        u64 comp;
        u64 adj;
        u32 temp, temp1;
        bool neg_adj = false;

        if (scaled_ppm < 0) {
                neg_adj = true;
                scaled_ppm = -scaled_ppm;
        }

        /* The hardware adds the clock compensation value to the PTP clock
         * on every coprocessor clock cycle. Typical convention is that it
         * represent number of nanosecond betwen each cycle. In this
         * convention compensation value is in 64 bit fixed-point
         * representation where upper 32 bits are number of nanoseconds
         * and lower is fractions of nanosecond.
         * The scaled_ppm represent the ratio in "parts per bilion" by which the
         * compensation value should be corrected.
         * To calculate new compenstation value we use 64bit fixed point
         * arithmetic on following formula
         * comp = tbase + tbase * scaled_ppm / (1M * 2^16)
         * where tbase is the basic compensation value calculated initialy
         * in cavium_ptp_init() -> tbase = 1/Hz. Then we use endian
         * independent structure definition to write data to PTP register.
         */
        comp = ((u64)1000000000ull << 32) / hw->clk_ptp_rate;
        adj = comp * scaled_ppm;
        adj >>= 16;
        adj = div_u64(adj, 1000000ull);
        comp = neg_adj ? comp - adj : comp + adj;
        /* upper 32 is nsec, lower is the fractions of nanosecond */
        temp = (u32)(comp >> 32);

        /* low32 is fractions part, hw must 2 base with 16 bits;
         * 0.xxxx * 2^16
         * so we can do it use this :
         * low32 >> 32 * 2^16 = low32 >> 16
         */

	wr32(hw, N20_PTP_OFF(N20_TS_INCR_CNT), (temp << 16) | temp);
        temp1 = (u32)((comp & 0xffffffff));
	wr32(hw, N20_PTP_OFF(N20_INCR_CNT_NS_FINE), temp1);
	wr32(hw, N20_PTP_OFF(N20_INCR_CNT_NS_FINE_2), temp1);
        /* trig to hw INITIAL_UPDATE_CMD bit2 */
	wr32(hw, N20_PTP_OFF(N20_INITIAL_UPDATE_CMD), BIT(2));
	return 0;
}

static int n20_ptp_setup_ptp(struct mce_hw *hw, u32 value)
{
        u32 temp;
        struct timespec64 now;
        u64 comp;

	wr32(hw, N20_PTP_OFF(N20_PTP_CFG_1), 0x40);
        /* 1 clear mac_cfg bit28 */
	temp = rd32(hw, N20_PTP_OFF(N20_MAC_CFG));
        temp &= (~BYPASS_PTP_TIMER_EN);
	wr32(hw, N20_PTP_OFF(N20_MAC_CFG), temp);
        /* setup mode */
	wr32(hw, N20_PTP_OFF(N20_PTP_CFG), value);
        comp = ((u64)1000000000ull << 32) / hw->clk_ptp_rate;
        temp = (u32)(comp >> 32);
	wr32(hw, N20_PTP_OFF(N20_TS_INCR_CNT), (temp << 16) | temp);
        hw->ptp_default_int = temp;
        temp = (u32)((comp & 0xffffffff));
	wr32(hw, N20_PTP_OFF(N20_INCR_CNT_NS_FINE), temp);
	wr32(hw, N20_PTP_OFF(N20_INCR_CNT_NS_FINE_2), temp);
        /* trig to hw INITIAL_UPDATE_CMD bit2 */
	wr32(hw, N20_PTP_OFF(N20_INITIAL_UPDATE_CMD), BIT(2));

        /* initialize system time */
        ktime_get_real_ts64(&now);
        /* lower 32 bits of tv_sec are safe until y2106 */
	hw->ops->ptp_init_systime(hw, (u32)now.tv_sec, now.tv_nsec);
	wr32(hw, N20_PTP_OFF(N20_TS_COMP), 0);

        return 0;
}

/* get tx status */
int n20_ptp_tx_status(struct mce_hw *hw)
{
	u32 value;

	value = rd32(hw, N20_ETH_OFF(N20_ETH_PTP_TX_TSVALUE_STATUS)); 
	//printk("value is %x\n", value);
	return (value & BIT(0));
}

int n20_ptp_set_ts_config(struct mce_hw *hw, struct hwtstamp_config *in_config)
{
	struct hwtstamp_config config;
	u32 tstamp_all = 0;
	u32 ptp_over_ipv4_udp = 0;
	u32 ptp_over_ipv6_udp = 0;
	u32 ptp_over_ethernet = 0;
	u32 ts_event_en = 0;
	u32 value = 0;
	s32 ret = -1;

	/* copy old value */
	memcpy(&config, in_config, sizeof(config));

	/* reserved for future extensions */
	if (config.flags)
		return -EINVAL;

	if (config.tx_type != HWTSTAMP_TX_OFF &&
	    config.tx_type != HWTSTAMP_TX_ON)
		return -ERANGE;

	switch (config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		/* time stamp no incoming packet at all */
		config.rx_filter = HWTSTAMP_FILTER_NONE;
		break;

	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
		/* PTP v1, UDP, any kind of event packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_EVENT;
		/* 'mac' hardware can support Sync, Pdelay_Req and
		 * Pdelay_resp by setting bit14 and bits17/16 to 01
		 * This leaves Delay_Req timestamps out.
		 * Enable all events *and* general purpose message
		 * timestamping
		 */
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
		/* PTP v1, UDP, Sync packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_SYNC;
		/* take time stamp for SYNC messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;

		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		/* PTP v1, UDP, Delay_req packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ;
		/* take time stamp for Delay_Req messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;

		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
		/* PTP v2, UDP, any kind of event packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_EVENT;

		/* take time stamp for all event messages */
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
		/* PTP v2, UDP, Sync packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_SYNC;
		/* take time stamp for SYNC messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		/* PTP v2, UDP, Delay_req packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ;
		/* take time stamp for Delay_Req messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_EVENT:
		/* PTP v2/802.AS1 any layer, any kind of event packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_SYNC:
		/* PTP v2/802.AS1, any layer, Sync packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_SYNC;
		/* take time stamp for SYNC messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		/* PTP v2/802.AS1, any layer, Delay_req packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_DELAY_REQ;
		/* take time stamp for Delay_Req messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

#ifdef HWTSTAMP_FILTER_NTP_ALL
	case HWTSTAMP_FILTER_NTP_ALL:
#endif
	case HWTSTAMP_FILTER_ALL:
		/* time stamp any incoming packet */
		config.rx_filter = HWTSTAMP_FILTER_ALL;
		tstamp_all = N20_PTP_TCR_TSENALL;
		break;

	default:
		return -ERANGE;
	}

	if ((config.rx_filter == HWTSTAMP_FILTER_NONE) && (config.tx_type != HWTSTAMP_TX_ON)) {
		/*rx and tx is not use hardware ts so clear the ptp register */
		config_close_tstamping(hw);
	} else {
		value = (N20_PTP_TCR_TSENA | N20_PTP_TX_EN | N20_PTP_RX_EN |
			 tstamp_all |
			 ptp_over_ethernet | ptp_over_ipv6_udp |
			 ptp_over_ipv4_udp | ts_event_en);
		ret = n20_ptp_setup_ptp(hw, value);
		if (ret < 0)
			return ret;
	}
	memcpy(in_config, &config, sizeof(config));

	return 0;

}

/* get tx hwstamp and clear flags */
int n20_ptp_tx_stamp(struct mce_hw *hw, u64 *sec, u64 *nsec)
{
	u32 temp;
	/* read tx stamp */
	*nsec = rd32(hw, N20_ETH_OFF(N20_ETH_PTP_TX_LTIMES)); 
	*sec = rd32(hw, N20_ETH_OFF(N20_ETH_PTP_TX_HTIMES));

	/* clean tx */
#define CLEAR_MASK BIT(15)
	temp = rd32(hw, N20_ETH_OFF(N20_ETH_PTP_TX_CLEAR));
	temp |= CLEAR_MASK;
	wr32(hw, N20_ETH_OFF(N20_ETH_PTP_TX_CLEAR), temp);
	wmb();
	temp &= (~CLEAR_MASK);
	wr32(hw, N20_ETH_OFF(N20_ETH_PTP_TX_CLEAR), temp);
	
	return 0;
}
