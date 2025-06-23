#ifndef _MCE_ETHTOOL_H_
#define _MCE_ETHTOOL_H_

struct mce_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

#define MCE_STAT(_type, _name, _stat) { \
	.stat_string = _name, \
	.sizeof_stat = sizeof_field(_type, _stat), \
	.stat_offset = offsetof(_type, _stat) \
}

#define MCE_NETDEV_STAT(_name, _stat) \
		MCE_STAT(struct mce_vsi, _name, _stat)

#define MCE_OFLD_STAT(_name, _stat) \
		MCE_STAT(struct mce_vsi, _name, _stat)

#define MCE_HW_STAT(_name, _stat) \
		MCE_STAT(struct mce_pf, _name, _stat)

#define MCE_QUEUE_STAT(_name, _stat) \
		MCE_STAT(struct mce_ring_stats, _name, _stat)

struct mce_ring_reg {
	char stat_string[ETH_GSTRING_LEN];
	u32 reg;
	int isu64;	
};

#define MCE_QUEUE_REG(_name, _offset, u64_f) {\
	.stat_string = _name,\
	.reg = _offset,\
	.isu64= u64_f, \
}

#define MCE_MAX_INTR_TIME	(256)
#define MCE_MAX_INTR_PKTS	(256)

#endif /* _MCE_ETHTOOL_H_ */
