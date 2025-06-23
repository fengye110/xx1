#include "mce.h"
#include "mce_fdir.h"
#include "mce_fdir_flow.h"
#include "mce_pattern.h"
#include "mce_tc_lib.h"
/* L2 */
enum mce_flow_item_type fdir_compose_eth[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_END,
};
/* L2 VLAN */
enum mce_flow_item_type fdir_compose_eth_vlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_VLAN,
	MCE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv4 VXLAN */
enum mce_flow_item_type fdir_compose_eth_inner_ipv4_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv4 GENEVE */
enum mce_flow_item_type fdir_compose_eth_inner_ipv4_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv4 GRE */
enum mce_flow_item_type fdir_compose_eth_inner_ipv4_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv4 NVGRE */
enum mce_flow_item_type fdir_compose_eth_inner_ipv4_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv6 VXLAN */
enum mce_flow_item_type fdir_compose_eth_inner_ipv6_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv6 GENEVE */
enum mce_flow_item_type fdir_compose_eth_inner_ipv6_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv6 GRE */
enum mce_flow_item_type fdir_compose_eth_inner_ipv6_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv6 NVGRE */
enum mce_flow_item_type fdir_compose_eth_inner_ipv6_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4 */
enum mce_flow_item_type fdir_compose_ipv4[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-TCP */
enum mce_flow_item_type fdir_compose_ipv4_tcp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_TCP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-UDP */
enum mce_flow_item_type fdir_compose_ipv4_udp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-SCTP */
enum mce_flow_item_type fdir_compose_ipv4_sctp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_SCTP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-ESP */
enum mce_flow_item_type fdir_compose_ipv4_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-UDP ESP */
enum mce_flow_item_type fdir_compose_ipv4_udp_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-VXLAN */
enum mce_flow_item_type fdir_compose_ipv4_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GENEVE */
enum mce_flow_item_type fdir_compose_ipv4_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-NVGRE*/
enum mce_flow_item_type fdir_compose_ipv4_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN TCP */
enum mce_flow_item_type fdir_compose_ipv4_tcp_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_TCP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE TCP */
enum mce_flow_item_type fdir_compose_ipv4_tcp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_TCP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE TCP */
enum mce_flow_item_type fdir_compose_ipv4_tcp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_TCP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE TCP */
enum mce_flow_item_type fdir_compose_ipv4_tcp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_TCP,	  MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN UDP */
enum mce_flow_item_type fdir_compose_ipv4_udp_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE UDP */
enum mce_flow_item_type fdir_compose_ipv4_udp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE UDP */
enum mce_flow_item_type fdir_compose_ipv4_udp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE UDP */
enum mce_flow_item_type fdir_compose_ipv4_udp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	  MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN SCTP */
enum mce_flow_item_type fdir_compose_ipv4_sctp_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_SCTP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE SCTP */
enum mce_flow_item_type fdir_compose_ipv4_sctp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_SCTP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE SCTP */
enum mce_flow_item_type fdir_compose_ipv4_sctp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_SCTP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE SCTP */
enum mce_flow_item_type fdir_compose_ipv4_sctp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_SCTP,  MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-UDP-ESP SCTP */
enum mce_flow_item_type fdir_compose_ipv4_sctp_inner_udp_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_IPV4, MCE_FLOW_ITEM_TYPE_SCTP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN ESP */
enum mce_flow_item_type fdir_compose_ipv4_esp_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_ESP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE ESP */
enum mce_flow_item_type fdir_compose_ipv4_esp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_ESP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE ESP */
enum mce_flow_item_type fdir_compose_ipv4_esp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_ESP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE ESP */
enum mce_flow_item_type fdir_compose_ipv4_esp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_ESP,	  MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN UDP-ESP */
enum mce_flow_item_type fdir_compose_ipv4_udp_esp_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE UDP-ESP */
enum mce_flow_item_type fdir_compose_ipv4_udp_esp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE UDP-ESP */
enum mce_flow_item_type fdir_compose_ipv4_udp_esp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE UDP-ESP */
enum mce_flow_item_type fdir_compose_ipv4_udp_esp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	  MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN */
enum mce_flow_item_type fdir_compose_ipv4_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE */
enum mce_flow_item_type fdir_compose_ipv4_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE */
enum mce_flow_item_type fdir_compose_ipv4_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE */
enum mce_flow_item_type fdir_compose_ipv4_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPU-IPV4 */
enum mce_flow_item_type fdir_compose_ipv4_gtpu_inner_ipv4[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_IPV4, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GTPU TCP */
enum mce_flow_item_type fdir_compose_ipv4_tcp_inner_gtpu[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_IPV4, MCE_FLOW_ITEM_TYPE_TCP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GTPU UDP */
enum mce_flow_item_type fdir_compose_ipv4_udp_inner_gtpu[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_IPV4, MCE_FLOW_ITEM_TYPE_UDP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GTPU SCTP */
enum mce_flow_item_type fdir_compose_ipv4_sctp_inner_gtpu[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_IPV4, MCE_FLOW_ITEM_TYPE_SCTP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPtunnel ipv4 */
enum mce_flow_item_type fdir_compose_ipv4_iptun_inner_ipv4[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPU */
enum mce_flow_item_type fdir_compose_ipv4_gtpu[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GTPU */
enum mce_flow_item_type fdir_compose_ipv6_gtpu[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPU GPDU */
enum mce_flow_item_type fdir_compose_ipv4_gtpu_gpdu[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	    MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	    MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_GTP_PSC, MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPC */
enum mce_flow_item_type fdir_compose_ipv4_gtpc[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GTPC,
	MCE_FLOW_ITEM_TYPE_END,
};

/* IPV6 */
enum mce_flow_item_type fdir_compose_ipv6[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6_FRAG */
enum mce_flow_item_type fdir_compose_ipv6_frag[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
	MCE_FLOW_ITEM_TYPE_END,
};

/* IPV6-TCP */
enum mce_flow_item_type fdir_compose_ipv6_tcp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_TCP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-UDP */
enum mce_flow_item_type fdir_compose_ipv6_udp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-SCTP */
enum mce_flow_item_type fdir_compose_ipv6_sctp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_SCTP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-ESP */
enum mce_flow_item_type fdir_compose_ipv6_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-UDP ESP */
enum mce_flow_item_type fdir_compose_ipv6_udp_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-VXLAN */
enum mce_flow_item_type fdir_compose_ipv6_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GENEVE */
enum mce_flow_item_type fdir_compose_ipv6_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-NVGRE*/
enum mce_flow_item_type fdir_compose_ipv6_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_NVGRE,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN TCP */
enum mce_flow_item_type fdir_compose_ipv6_tcp_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_TCP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE TCP */
enum mce_flow_item_type fdir_compose_ipv6_tcp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_TCP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GRE TCP */
enum mce_flow_item_type fdir_compose_ipv6_tcp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_TCP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE TCP */
enum mce_flow_item_type fdir_compose_ipv6_tcp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_TCP,	  MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN UDP */
enum mce_flow_item_type fdir_compose_ipv6_udp_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE UDP */
enum mce_flow_item_type fdir_compose_ipv6_udp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GRE UDP */
enum mce_flow_item_type fdir_compose_ipv6_udp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE UDP */
enum mce_flow_item_type fdir_compose_ipv6_udp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP,	  MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN SCTP */
enum mce_flow_item_type fdir_compose_ipv6_sctp_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_SCTP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE SCTP */
enum mce_flow_item_type fdir_compose_ipv6_sctp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_SCTP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GRE SCTP */
enum mce_flow_item_type fdir_compose_ipv6_sctp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE,	 MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_SCTP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE SCTP */
enum mce_flow_item_type fdir_compose_ipv6_sctp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_SCTP,  MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN ESP */
enum mce_flow_item_type fdir_compose_ipv6_vxlan_inner_ipv6_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_ESP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE ESP */
enum mce_flow_item_type fdir_compose_ipv6_esp_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_ESP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GRE ESP */
enum mce_flow_item_type fdir_compose_ipv6_esp_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_ESP, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE ESP */
enum mce_flow_item_type fdir_compose_ipv6_esp_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_ESP,	  MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-VXLAN inner UDP-ESP */
enum mce_flow_item_type fdir_compose_ipv6_vxlan_inner_ipv6_udp_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GENEVE inner UDP-ESP */
enum mce_flow_item_type fdir_compose_ipv6_geneve_inner_ipv6_udp_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GRE inner UDP-ESP */
enum mce_flow_item_type fdir_compose_ipv6_gre_inner_ipv6_udp_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-NVGRE inner UDP-ESP */
enum mce_flow_item_type fdir_compose_ipv6_nvgre_inner_ipv6_udp_esp[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP,	  MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN */
enum mce_flow_item_type fdir_compose_ipv6_inner_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_END,
};
/* ip VXLAN in ipv6 frag*/
enum mce_flow_item_type fdir_compose_ipv4_vxlan_inner_ipv6_frag[] = {
	MCE_FLOW_ITEM_TYPE_ETH,		  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,		  MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_ETH,		  MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, MCE_FLOW_ITEM_TYPE_END,
};

/* inner IPV6-GENEVE */
enum mce_flow_item_type fdir_compose_ipv6_inner_geneve[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE */
enum mce_flow_item_type fdir_compose_ipv4_geneve_inner_ipv6_frag[] = {
	MCE_FLOW_ITEM_TYPE_ETH,		  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,		  MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_ETH,		  MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, MCE_FLOW_ITEM_TYPE_END,
};

/* inner IPV6-GRE */
enum mce_flow_item_type fdir_compose_ipv6_inner_gre[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GRE-IPV6-FRAG */
enum mce_flow_item_type fdir_ipv4_gre_inner_ipv6_frag[] = {
	MCE_FLOW_ITEM_TYPE_ETH,		  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_GRE,		  MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE */
enum mce_flow_item_type fdir_compose_ipv6_inner_nvgre[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-NVGRE-IPV6-FRAG */
enum mce_flow_item_type fdir_ipv4_nvgre_inner_ipv6_frag[] = {
	MCE_FLOW_ITEM_TYPE_ETH,		  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE,	  MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, MCE_FLOW_ITEM_TYPE_END,
};

/* inner IPV6-NVGRE */
enum mce_flow_item_type fdir_compose_ipv4_nvgre_inner_ipv6[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	  MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_NVGRE, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPU-IPV6 */
enum mce_flow_item_type fdir_compose_ipv4_gtpu_inner_ipv6[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_IPV6, MCE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPU-IPV6-EXT_FRAGA */
enum mce_flow_item_type fdir_compose_ipv4_gtpu_inner_ipv6_frag[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_IPV6, MCE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
	MCE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GTPU UDP */
enum mce_flow_item_type fdir_compose_ipv6_udp_inner_gtpu[] = {
	MCE_FLOW_ITEM_TYPE_ETH,	 MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP,	 MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_IPV6, MCE_FLOW_ITEM_TYPE_UDP,
	MCE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GTPC */
enum mce_flow_item_type fdir_compose_ipv6_gtpc[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_GTPC,
	MCE_FLOW_ITEM_TYPE_END,
};

#define MCE_FDIR_OPT_IPV4                                         \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_L4_PROTO | \
	 MCE_OPT_IPV4_DSCP)
#define MCE_FDIR_OPT_IPV4_FRAG                                     \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_IPV4_FRAG | \
	 MCE_OPT_IPV4_DSCP)
#define MCE_FDIR_OPT_IPV4_TCP_SYNC \
	(MCE_OPT_IPV4_DIP | MCE_OPT_TCP_DPORT | MCE_OPT_TCP_SYNC)
#define MCE_FDIR_OPT_IPV4_TCP                                      \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_TCP_SPORT | \
	 MCE_OPT_TCP_DPORT)
#define MCE_FDIR_OPT_IPV4_UDP                                      \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_UDP_SPORT | \
	 MCE_OPT_UDP_DPORT)
#define MCE_FDIR_OPT_IPV4_SCTP                                      \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_SCTP_SPORT | \
	 MCE_OPT_SCTP_DPORT)
#define MCE_FDIR_OPT_IPV4_ESP \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_ESP_SPI)
#define MCE_FDIR_OPT_IPV4_VXLAN \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_VXLAN_VNI)
#define MCE_FDIR_OPT_IPV4_GENEVE \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_GENEVE_VNI)
#define MCE_FDIR_OPT_IPV4_NVGRE \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_NVGRE_TNI)
#define MCE_FDIR_OPT_IPV4_GTP_U_GPDU \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_GTP_U_TEID)
#define MCE_FDIR_OPT_IPV4_GTP_C_TEID \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_GTP_C_TEID)
#define MCE_FDIR_OPT_IPV4_GTP_C_NOTEID \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_IPV4_SIP)
#define MCE_FDIR_OPT_IPV6                                         \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_L4_PROTO | \
	 MCE_OPT_IPV6_DSCP)
#define MCE_FDIR_OPT_IPV6_FRAG                                     \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_FRAG | \
	 MCE_OPT_IPV6_DSCP)
#define MCE_FDIR_OPT_IPV6_TCP_SYNC \
	(MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | MCE_OPT_TCP_DPORT)
#define MCE_FDIR_OPT_IPV6_TCP                                      \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | \
	 MCE_OPT_TCP_SPORT | MCE_OPT_TCP_DPORT)
#define MCE_FDIR_OPT_IPV6_UDP                                      \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | \
	 MCE_OPT_UDP_SPORT | MCE_OPT_UDP_DPORT)
#define MCE_FDIR_OPT_IPV6_SCTP                                     \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | \
	 MCE_OPT_SCTP_SPORT | MCE_OPT_SCTP_DPORT)
#define MCE_FDIR_OPT_IPV6_ESP                                      \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | \
	 MCE_OPT_ESP_SPI)
#define MCE_FDIR_OPT_IPV6_VXLAN \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_VXLAN_VNI)
#define MCE_FDIR_OPT_IPV6_GENEVE \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_GENEVE_VNI)
#define MCE_FDIR_OPT_IPV6_NVGRE \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_NVGRE_TNI)
#define MCE_FDIR_OPT_IPV6_GTP_U_GPDU \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_GTP_U_TEID)
#define MCE_FDIR_OPT_IPV6_GTP_C_TEID \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_GTP_C_TEID)
#define MCE_FDIR_OPT_IPV6_GTP_C_NOTEID \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP)

#define MCE_FDIR_L2_MAC (MCE_OPT_SMAC | MCE_OPT_DMAC)
#define MCE_FDIR_L2_MACVLAN (MCE_FDIR_L2_MAC | MCE_OPT_VLAN_VID)
static struct mce_flow_ptype_match mce_fdir_l2_mode_support[] = {
	{ fdir_compose_eth, MCE_PTYPE_L2_ONLY, MCE_FDIR_L2_MAC },
	{ fdir_compose_eth_vlan, MCE_PTYPE_L2_ONLY, MCE_FDIR_L2_MACVLAN },
};
static struct mce_flow_ptype_match mce_fdir_inner_l2_mode_support[] = {
	{ fdir_compose_eth, MCE_PTYPE_L2_ONLY, MCE_FDIR_L2_MAC },
	/* tunnel ipv4 inner eth */
	{ fdir_compose_eth_inner_ipv4_vxlan, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MAC },
	{ fdir_compose_eth_inner_ipv4_geneve, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MAC },
	{ fdir_compose_eth_inner_ipv4_gre, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MAC },
	{ fdir_compose_eth_inner_ipv4_nvgre, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MAC },
};

static struct mce_flow_ptype_match mce_fdir_ptype_tun_inner_sup[] = {
	/* normal non-tunnel ipv6 ipv4 */
	{ fdir_compose_eth, MCE_PTYPE_L2_ETHTYPE, MCE_OPT_ETHTYPE },
	/* nromal ipv4 */
	{ fdir_compose_ipv4, MCE_PTYPE_IPV4_PAY, MCE_FDIR_OPT_IPV4 },
	{ fdir_compose_ipv4, MCE_PTYPE_IPV4_FRAG, MCE_FDIR_OPT_IPV4_FRAG },
	{ fdir_compose_ipv4_tcp, MCE_PTYPE_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP },
	{ fdir_compose_ipv4_udp, MCE_PTYPE_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP },
	{ fdir_compose_ipv4_sctp, MCE_PTYPE_IPV4_SCTP,
	  MCE_FDIR_OPT_IPV4_SCTP },
	/* normal ipv6 */
	{ fdir_compose_ipv6, MCE_PTYPE_IPV6_PAY, MCE_FDIR_OPT_IPV6 },
	{ fdir_compose_ipv6, MCE_PTYPE_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv6_frag, MCE_PTYPE_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv6_tcp, MCE_PTYPE_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP },
	{ fdir_compose_ipv6_udp, MCE_PTYPE_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP },
	{ fdir_compose_ipv6_sctp, MCE_PTYPE_IPV6_SCTP,
	  MCE_FDIR_OPT_IPV6_SCTP },
	/* tunnel ipv4 inner eth */
	{ fdir_compose_eth_inner_ipv4_vxlan,
	  MCE_PTYPE_TUN_INNER_L2_ETHTYPE, MCE_OPT_ETHTYPE },
	{ fdir_compose_eth_inner_ipv4_geneve,
	  MCE_PTYPE_TUN_INNER_L2_ETHTYPE, MCE_OPT_ETHTYPE },
	{ fdir_compose_eth_inner_ipv4_gre, MCE_PTYPE_TUN_INNER_L2_ETHTYPE,
	  MCE_OPT_ETHTYPE },
	{ fdir_compose_eth_inner_ipv4_nvgre,
	  MCE_PTYPE_TUN_INNER_L2_ETHTYPE, MCE_OPT_ETHTYPE },
	/* tunnel inner is ipv6 pay or frag */
	{ fdir_compose_ipv6_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6 },
	{ fdir_compose_ipv6_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv4_vxlan_inner_ipv6_frag,
	  MCE_PTYPE_TUN_INNER_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv6_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6 },
	{ fdir_compose_ipv6_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv4_geneve_inner_ipv6_frag,
	  MCE_PTYPE_TUN_INNER_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv6_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6 },
	{ fdir_compose_ipv6_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_ipv4_gre_inner_ipv6_frag, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv6_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6 },
	{ fdir_compose_ipv6_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_ipv4_nvgre_inner_ipv6_frag, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG },
	/* tunnel inner is ipv6 tcp */
	{ fdir_compose_ipv6_tcp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP },
	{ fdir_compose_ipv6_tcp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP },
	{ fdir_compose_ipv6_tcp_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP },
	{ fdir_compose_ipv6_tcp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP },
	/* tunnel inner is ipv6 udp */
	{ fdir_compose_ipv6_udp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP },
	{ fdir_compose_ipv6_udp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP },
	{ fdir_compose_ipv6_udp_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP },
	{ fdir_compose_ipv6_udp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP },
	/* tunnel inner is ipv6 sctp */
	{ fdir_compose_ipv6_sctp_inner_vxlan,
	  MCE_PTYPE_TUN_INNER_IPV6_SCTP, MCE_FDIR_OPT_IPV6_SCTP },
	{ fdir_compose_ipv6_sctp_inner_geneve,
	  MCE_PTYPE_TUN_INNER_IPV6_SCTP, MCE_FDIR_OPT_IPV6_SCTP },
	{ fdir_compose_ipv6_sctp_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_SCTP,
	  MCE_FDIR_OPT_IPV6_SCTP },
	{ fdir_compose_ipv6_sctp_inner_nvgre,
	  MCE_PTYPE_TUN_INNER_IPV6_SCTP, MCE_FDIR_OPT_IPV6_SCTP },
	/* tunnel inner is ipv6 esp */
	{ fdir_compose_ipv6_vxlan_inner_ipv6_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_ESP, MCE_FDIR_OPT_IPV6_ESP },
	{ fdir_compose_ipv6_esp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_ESP,
	  MCE_FDIR_OPT_IPV6_ESP },
	{ fdir_compose_ipv6_esp_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_ESP,
	  MCE_FDIR_OPT_IPV6_ESP },
	{ fdir_compose_ipv6_esp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_ESP,
	  MCE_FDIR_OPT_IPV6_ESP },
	/* tunnel inner is ipv6 udp esp */
	{ fdir_compose_ipv6_vxlan_inner_ipv6_udp_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP, MCE_FDIR_OPT_IPV6_ESP },
	{ fdir_compose_ipv6_geneve_inner_ipv6_udp_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP, MCE_FDIR_OPT_IPV6_ESP },
	{ fdir_compose_ipv6_gre_inner_ipv6_udp_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP, MCE_FDIR_OPT_IPV6_ESP },
	{ fdir_compose_ipv6_nvgre_inner_ipv6_udp_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP, MCE_FDIR_OPT_IPV6_ESP },
	/* tunnel inner is ipv4 pay or frag */
	{ fdir_compose_ipv4_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4 },
	{ fdir_compose_ipv4_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG },
	{ fdir_compose_ipv4_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4 },
	{ fdir_compose_ipv4_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG },
	{ fdir_compose_ipv4_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4 },
	{ fdir_compose_ipv4_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG },
	{ fdir_compose_ipv4_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4 },
	{ fdir_compose_ipv4_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG },
#if 0
	/* fdir maybe donnot support ip_in_ip tunnel */
	{ fdir_compose_ipv4_iptun_inner_ipv4, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4 },
	{ fdir_compose_ipv4_iptun_inner_ipv4,
	  MCE_PTYPE_TUN_INNER_IPV4_FRAG, MCE_FDIR_OPT_IPV4_FRAG },
#endif
	/* tunnel inner ipv4 tcp */
	{ fdir_compose_ipv4_tcp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP },
	{ fdir_compose_ipv4_tcp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP },
	{ fdir_compose_ipv4_tcp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP },
	{ fdir_compose_ipv4_tcp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP },
	/* tunnel inner is ipv4 udp */
	{ fdir_compose_ipv4_udp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP },
	{ fdir_compose_ipv4_udp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP },
	{ fdir_compose_ipv4_udp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP },
	{ fdir_compose_ipv4_udp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP },
	/* tunnel inner is ipv4 sctp */
	{ fdir_compose_ipv4_sctp_inner_vxlan,
	  MCE_PTYPE_TUN_INNER_IPV4_SCTP, MCE_FDIR_OPT_IPV4_SCTP },
	{ fdir_compose_ipv4_sctp_inner_geneve,
	  MCE_PTYPE_TUN_INNER_IPV4_SCTP, MCE_FDIR_OPT_IPV4_SCTP },
	{ fdir_compose_ipv4_sctp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_SCTP,
	  MCE_FDIR_OPT_IPV4_SCTP },
	{ fdir_compose_ipv4_sctp_inner_nvgre,
	  MCE_PTYPE_TUN_INNER_IPV4_SCTP, MCE_FDIR_OPT_IPV4_SCTP },
	/* tunnel inner is ipv4 udp esp */
	{ fdir_compose_ipv4_esp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP },
	{ fdir_compose_ipv4_esp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP },
	{ fdir_compose_ipv4_esp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP },
	{ fdir_compose_ipv4_esp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP },
	/* tunnel inner is ipv4 esp */
	{ fdir_compose_ipv4_udp_esp_inner_vxlan,
	  MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP, MCE_FDIR_OPT_IPV4_ESP },
	{ fdir_compose_ipv4_udp_esp_inner_geneve,
	  MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP, MCE_FDIR_OPT_IPV4_ESP },
	{ fdir_compose_ipv4_udp_esp_inner_gre,
	  MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP, MCE_FDIR_OPT_IPV4_ESP },
	{ fdir_compose_ipv4_udp_esp_inner_nvgre,
	  MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP, MCE_FDIR_OPT_IPV4_ESP },
	/* tunnel gtp inner ipv4/ipv6 */
	{ fdir_compose_ipv4_gtpu_inner_ipv4,
	  MCE_PTYPE_GTP_U_INNER_IPV4_PAY, MCE_FDIR_OPT_IPV4 },
	{ fdir_compose_ipv4_gtpu_inner_ipv4,
	  MCE_PTYPE_GTP_U_INNER_IPV4_FRAG, MCE_FDIR_OPT_IPV4_FRAG },
	{ fdir_compose_ipv4_gtpu_inner_ipv6,
	  MCE_PTYPE_GTP_U_INNER_IPV6_PAY, MCE_FDIR_OPT_IPV6 },
	{ fdir_compose_ipv4_gtpu_inner_ipv6,
	  MCE_PTYPE_GTP_U_INNER_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv4_gtpu_inner_ipv6_frag,
	  MCE_PTYPE_GTP_U_INNER_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv4_tcp_inner_gtpu, MCE_PTYPE_GTP_U_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP },
	{ fdir_compose_ipv4_udp_inner_gtpu, MCE_PTYPE_GTP_U_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP },
	{ fdir_compose_ipv4_sctp_inner_gtpu,
	  MCE_PTYPE_GTP_U_INNER_IPV4_SCTP, MCE_FDIR_OPT_IPV4_SCTP },
};

static struct mce_flow_ptype_match mce_fdir_ptype_support[] = {
	{ fdir_compose_eth, MCE_PTYPE_L2_ETHTYPE, MCE_OPT_ETHTYPE },
	/* nromal ipv4 */
	{ fdir_compose_ipv4, MCE_PTYPE_IPV4_PAY, MCE_FDIR_OPT_IPV4 },
	{ fdir_compose_ipv4, MCE_PTYPE_IPV4_FRAG, MCE_FDIR_OPT_IPV4_FRAG },
	{ fdir_compose_ipv4_tcp, MCE_PTYPE_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP },
	{ fdir_compose_ipv4_udp, MCE_PTYPE_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP },
	{ fdir_compose_ipv4_sctp, MCE_PTYPE_IPV4_SCTP,
	  MCE_FDIR_OPT_IPV4_SCTP },
	/* normal ipv6 */
	{ fdir_compose_ipv6, MCE_PTYPE_IPV6_PAY, MCE_FDIR_OPT_IPV6 },
	{ fdir_compose_ipv6, MCE_PTYPE_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv6_frag, MCE_PTYPE_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG },
	{ fdir_compose_ipv6_tcp, MCE_PTYPE_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP },
	{ fdir_compose_ipv6_udp, MCE_PTYPE_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP },
	{ fdir_compose_ipv6_sctp, MCE_PTYPE_IPV6_SCTP,
	  MCE_FDIR_OPT_IPV6_SCTP },
	/* tunnel out ipv4 */
	{ fdir_compose_ipv4_esp, MCE_PTYPE_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP },
	{ fdir_compose_ipv4_udp_esp, MCE_PTYPE_IPV4_UDP_ESP,
	  MCE_FDIR_OPT_IPV4_ESP },
	{ fdir_compose_ipv4_vxlan, MCE_PTYPE_TUN_IPV4_VXLAN,
	  MCE_FDIR_OPT_IPV4_VXLAN },
	{ fdir_compose_ipv4_geneve, MCE_PTYPE_TUN_IPV4_GENEVE,
	  MCE_FDIR_OPT_IPV4_GENEVE },
	{ fdir_compose_ipv4_nvgre, MCE_PTYPE_TUN_IPV4_GRE,
	  MCE_FDIR_OPT_IPV4_NVGRE },
	/* tunnel out ipv6 */
	{ fdir_compose_ipv6_esp, MCE_PTYPE_IPV6_ESP,
	  MCE_FDIR_OPT_IPV6_ESP },
	{ fdir_compose_ipv6_udp_esp, MCE_PTYPE_IPV6_UDP_ESP,
	  MCE_FDIR_OPT_IPV6_ESP },
	{ fdir_compose_ipv6_vxlan, MCE_PTYPE_TUN_IPV6_VXLAN,
	  MCE_FDIR_OPT_IPV6_VXLAN },
	{ fdir_compose_ipv6_geneve, MCE_PTYPE_TUN_IPV6_GENEVE,
	  MCE_FDIR_OPT_IPV6_GENEVE },
	{ fdir_compose_ipv6_nvgre, MCE_PTYPE_TUN_IPV6_GRE,
	  MCE_FDIR_OPT_IPV6_NVGRE },
	/* tunnel out gtp */
	{ fdir_compose_ipv4_gtpc, MCE_PTYPE_GTP_C_TEID_IPV4,
	  MCE_FDIR_OPT_IPV4_GTP_C_TEID },
	{ fdir_compose_ipv6_gtpc, MCE_PTYPE_GTP_C_TEID_IPV6,
	  MCE_FDIR_OPT_IPV6_GTP_C_TEID },
	{ fdir_compose_ipv4_gtpu, MCE_PTYPE_GTP_U_GPDU_IPV4,
	  MCE_FDIR_OPT_IPV4_GTP_U_GPDU },
	{ fdir_compose_ipv6_gtpu, MCE_PTYPE_GTP_U_GPDU_IPV6,
	  MCE_FDIR_OPT_IPV6_GTP_U_GPDU },
};

static void mce_set_fdir_entry_bit(struct mce_fdir_handle *handle,
				     u16 loc)
{
	u16 rank = loc / 32;
	u16 cow = loc % 32;

	handle->entry_bitmap[rank] |= (1 << cow);
}

int mce_compose_find_prof_id(struct mce_pf *pf, u8 *compose, u16 *prof_id,
			     struct mce_tc_flower_fltr *tc_fltr)
{
	struct mce_flow_ptype_match *ptype_support = NULL;
	enum mce_flow_item_type *pattern = NULL;
	int i, j, find = 0;
	int arry_size;

	if (pf->fdir_mode == MCE_FDIR_MACVLAN_MODE) {
		if (tc_fltr->parsed_inner) {
			ptype_support = mce_fdir_inner_l2_mode_support;
			arry_size =
				ARRAY_SIZE(mce_fdir_inner_l2_mode_support);
		} else {
			ptype_support = mce_fdir_l2_mode_support;
			arry_size = ARRAY_SIZE(mce_fdir_l2_mode_support);
		}
	} else {
		if (tc_fltr->parsed_inner) {
			ptype_support = mce_fdir_ptype_tun_inner_sup;
			arry_size =
				ARRAY_SIZE(mce_fdir_ptype_tun_inner_sup);
		} else {
			ptype_support = mce_fdir_ptype_support;
			arry_size = ARRAY_SIZE(mce_fdir_ptype_support);
		}
	}

	for (i = 0; i < arry_size; i++) {
		pattern = ptype_support[i].pattern_list;

		for (j = 0; j < MCE_FLOW_ITEM_TYPE_MAX_NUM; j++) {
			if (pattern[j] == MCE_FLOW_ITEM_TYPE_END)
				break;
			if (pattern[j] != compose[j])
				break;
		}

		if (pattern[j] == MCE_FLOW_ITEM_TYPE_END &&
		    compose[j] == MCE_FLOW_ITEM_TYPE_END) {
			find = 1;
			if (tc_fltr->filter->options & MCE_OPT_IPV4_FRAG)
				i++;
			if (tc_fltr->filter->options & MCE_OPT_IPV6_FRAG)
				i++;
			*prof_id = ptype_support[i].hw_type;
			break;
		}
	}

	return find;
}

struct mce_fdir_filter *
mce_meta_to_fdir_rule(struct mce_hw *hw,
			struct mce_fdir_handle *handle, u16 meta_num,
			bool is_ipv6, bool is_tunnel)
{
	union mce_fdir_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	struct mce_fdir_filter *filter = NULL;
	int i = 0;

	filter = kzalloc(sizeof(struct mce_fdir_filter), GFP_KERNEL);
	if (filter == NULL)
		return NULL;

	lkup_pattern = &filter->lkup_pattern;
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		if (meta->type == MCE_META_TYPE_MAX)
			continue;
		switch (meta->type) {
		case MCE_ETH_META:
			lkup_pattern->formatted.ether_type =
				meta->hdr.eth_meta.ethtype_id;
			break;
		case MCE_IPV4_META:
			lkup_pattern->formatted.src_addr[0] =
				meta->hdr.ipv4_meta.src_addr;
			lkup_pattern->formatted.dst_addr[0] =
				meta->hdr.ipv4_meta.dst_addr;
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv4_meta.protocol;
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv4_meta.protocol;
			lkup_pattern->formatted.ip_tos =
				meta->hdr.ipv4_meta.dscp;
			break;
		case MCE_IPV6_META:
			lkup_pattern->formatted.src_addr[0] =
				meta->hdr.ipv6_meta.src_addr[0];
			lkup_pattern->formatted.src_addr[1] =
				meta->hdr.ipv6_meta.src_addr[1];
			lkup_pattern->formatted.src_addr[2] =
				meta->hdr.ipv6_meta.src_addr[2];
			lkup_pattern->formatted.src_addr[3] =
				meta->hdr.ipv6_meta.src_addr[3];
			lkup_pattern->formatted.dst_addr[0] =
				meta->hdr.ipv6_meta.dst_addr[0];
			lkup_pattern->formatted.dst_addr[1] =
				meta->hdr.ipv6_meta.dst_addr[1];
			lkup_pattern->formatted.dst_addr[2] =
				meta->hdr.ipv6_meta.dst_addr[2];
			lkup_pattern->formatted.dst_addr[3] =
				meta->hdr.ipv6_meta.dst_addr[3];
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv6_meta.protocol;
			lkup_pattern->formatted.ip_tos =
				meta->hdr.ipv6_meta.dscp;
			/* set filter ipv6 flag */
			filter->is_ipv6 = true;
			break;
		case MCE_UDP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.udp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.udp_meta.src_port;
			break;
		case MCE_TCP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.tcp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.tcp_meta.src_port;
			break;
		case MCE_SCTP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.sctp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.sctp_meta.src_port;
			break;
		case MCE_ESP_META:
			lkup_pattern->formatted.esp_spi =
				meta->hdr.esp_meta.spi;
			break;
		case MCE_VXLAN_META:
			lkup_pattern->formatted.vni =
				meta->hdr.vxlan_meta.vni;
			break;
		case MCE_GENEVE_META:
			lkup_pattern->formatted.vni =
				meta->hdr.geneve_meta.vni;
			break;
		case MCE_NVGRE_META:
			lkup_pattern->formatted.key =
				meta->hdr.nvgre_meta.key;
			break;
		case MCE_GTPC_META:
		case MCE_GTPU_META:
			lkup_pattern->formatted.teid =
				meta->hdr.gtp_meta.teid;
			break;
		default:
			dev_err(hw->dev,
				"%s the rule type:0x%xis not exist option.\n",
				__func__, meta->type);
			break;
		}
	}
	return filter;
}

struct mce_fdir_filter *
mce_meta_to_fdir_rule_l2(struct mce_hw *hw, struct mce_fdir_handle *handle,
			 u16 meta_num, bool is_ipv6, bool is_tunnel)
{
	union mce_fdir_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	struct mce_fdir_filter *filter = NULL;
	int i = 0, j;

	filter = kzalloc(sizeof(struct mce_fdir_filter), GFP_KERNEL);
	if (filter == NULL)
		return NULL;

	lkup_pattern = &filter->lkup_pattern;
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		if (meta->type == MCE_META_TYPE_MAX)
			continue;
		switch (meta->type) {
		case MCE_ETH_META:
			for (j = 0; j < ETH_ALEN; j++) {
				lkup_pattern->formatted.src_mac[j] =
					meta->hdr.eth_meta.src_addr[j];
				lkup_pattern->formatted.dst_mac[j] =
					meta->hdr.eth_meta.dst_addr[j];
			}
			break;
		case MCE_VLAN_META:
			lkup_pattern->formatted.vlan_id =
				meta->hdr.vlan_meta.vlan_id;
			break;
		default:
			dev_err(hw->dev,
				"%s the rule type:0x%xis not exist option.\n",
				__func__, meta->type);
			break;
		}
	}
	return filter;
}

int mce_compose_init_item_type(u8 **compose)
{
	*compose = kzalloc(sizeof(sizeof(**compose)) *
				   MCE_FLOW_ITEM_TYPE_MAX_NUM,
			   GFP_KERNEL);
	if (!(*compose))
		return -1;
	return 0;
}

int mce_compose_deinit_item_type(u8 *compose)
{
	kfree(compose);
	return 0;
}

int mce_compose_set_item_type(u8 *compose,
				enum mce_flow_item_type type)
{
	int i, ret = 0;

	for (i = 0; i < MCE_FLOW_ITEM_TYPE_MAX_NUM; i++) {
		if (compose[i] == 0) {
			compose[i] = type;
			break;
		}
	}

	if (i == MCE_FLOW_ITEM_TYPE_MAX_NUM)
		ret = -1;
	return ret;
}

void mce_init_flow_engine(struct mce_pf *pf, int mode)
{
	pf->flow_engine = &mce_fdir_engine;
	pf->fdir_mode = MCE_FDIR_EXACT_M_MODE;

	if (mode == MCE_FDIR_SIGN_M_MODE)
		pf->fdir_mode = MCE_FDIR_SIGN_M_MODE;
	if (mode == MCE_FDIR_EXACT_M_MODE)
		pf->fdir_mode = MCE_FDIR_EXACT_M_MODE;
	if (mode == MCE_FDIR_MACVLAN_MODE)
		pf->fdir_mode = MCE_FDIR_MACVLAN_MODE;
	pf->flow_engine->init(pf, &(pf->flow_engine->handle));
}

void *mce_get_engine_handle(struct mce_pf *pf,
			      enum mce_flow_module type)
{
	struct mce_flow_engine_module *engine = pf->flow_engine;

	if (engine->type == type)
		return engine->handle;

	return NULL;
}

static u64 mce_fdir_hl_cal_key(struct mce_fdir_handle *handle,
			       union mce_fdir_pattern *lkup_pattern)
{
	int size = sizeof(union mce_fdir_pattern), i;
	u64 cal_key = 0;
	u8 *pdata = (u8 *)lkup_pattern;

	for (i = 0; i < size; i++)
		cal_key += pdata[i];
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		cal_key %= MCE_MAX_FDIR_SIGN_ENTRY;
	else
		cal_key %= MCE_MAX_FDIR_EXACT_ENTRY;
	return cal_key;
}

static struct mce_fdir_filter *
mce_fdir_exact_entry_lookup(struct mce_fdir_handle *handle,
			    const struct mce_fdir_filter *filter)
{
	struct mce_fdir_filter *h_filter = NULL;

	hash_for_each_possible(handle->fdir_exact_tb, h_filter, hl_node,
			       filter->key) {
		if (!strncmp((u8 *)&filter->lkup_pattern,
			     (u8 *)&h_filter->lkup_pattern,
			     sizeof(union mce_fdir_pattern))) {
			return h_filter;
		}
	}
	return NULL;
}

static struct mce_fdir_filter *
mce_fdir_sign_entry_lookup(struct mce_fdir_handle *handle,
			   const struct mce_fdir_filter *filter)
{
	struct mce_fdir_filter *h_filter = NULL;

	hash_for_each_possible(handle->fdir_sign_tb, h_filter, hl_node,
			       filter->key) {
		if (!strncmp((u8 *)&filter->lkup_pattern,
			     (u8 *)&h_filter->lkup_pattern,
			     sizeof(union mce_fdir_pattern))) {
			return h_filter;
		}
	}
	return NULL;
}

static struct mce_fdir_filter *
mce_fdir_entry_lookup(struct mce_fdir_handle *handle,
		      const struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_fdir_sign_entry_lookup(handle, filter);
	return mce_fdir_exact_entry_lookup(handle, filter);
}

static int mce_get_valid_entry_loc(struct mce_fdir_handle *handle,
				   u16 *loc)
{
	u32 wish_bit = 0x1, bitmap = 0;
	int i = 0, j = 0, find_loc = 0;

	for (i = 0; i < 128; i++) {
		bitmap = ~handle->entry_bitmap[i];
		if (!__user_popcount(bitmap))
			continue;
		for (j = 0; j < 32; j++) {
			if ((bitmap & wish_bit) == wish_bit) {
				find_loc = 1;
				break;
			}
			bitmap >>= 1;
		}
		if (find_loc) {
			*loc = i * 32 + j;
			break;
		}
	}
	if (!find_loc)
		return -ENOMEM;
	return 0;
}

static int mce_program_fdir_rule(struct mce_hw *hw,
				   struct mce_fdir_handle *handle,
				   struct mce_fdir_filter *filter,
				   struct mce_tc_flower_fltr *tc_fltr)
{
	struct mce_hw_inset_key *keys = &filter->hw_inset.keys;
	u16 queue_id = 0;
	u32 act = 0;

	memset(keys, 0, sizeof(*keys));
	filter->hw_inset.profile_id = filter->profile_id;
	filter->hw_inset.keys.tun_type = tc_fltr->tunnel_sw_type;
	queue_id = tc_fltr->action.fwd.q.queue;
	if (tc_fltr->action.fltr_act == MCE_DROP_PACKET) {
		act = MCE_RULE_ACTION_DROP | MCE_RULE_ACTION_Q_EN;
	} else {
		act = MCE_RULE_ACTION_Q_EN | MCE_RULE_ACTION_PASS;
		act |= queue_id << MCE_RULE_ACTION_Q_S;
	}

	if (tc_fltr->action.pop_vlan) {
		act |= MCE_RULE_ACTION_VLAN_EN;
		act |= MCE_POP_1VLAN << MCE_RULE_ACTION_POP_VLAN_S;
	}
	filter->hw_inset.action = act;
	filter->hw_inset.profile_id = filter->profile_id;
	mce_fdir_key_setup(filter);
	return 0;
}

static void mce_fdir_exact_encap_node(struct mce_fdir_filter *filter,
					struct mce_fdir_node *node,
					bool new_node);
static struct mce_fdir_node *
mce_fdir_find_insert_node(struct mce_fdir_hash_entry *hash_entry,
			    u8 max_entry);
static void __shift_bits_right(u16 *array, int len, int shift)
{
	u16 array_out[128];
	int i;

	shift = shift % 16;
	memset(array_out, 0, len);
	for (i = 0; i < len; i++) {
		array_out[i] = array[i] >> shift;
		if (array[i + 1] & 0x001)
			array_out[i] |= BIT(15);
	}
	memcpy(array, array_out, len * 2);
}

static void mce_hash_data_encode(struct mce_hw_rule_inset *hw_inset,
				   union mce_hash_data *hash_data)
{
	u32 *ext_key = (u32 *)&hw_inset->keys.inset_ex;
	u32 *key = (u32 *)&hw_inset->keys.inset;

	hash_data->hash_inset[0] = key[0];
	hash_data->hash_inset[1] = ext_key[0];
	hash_data->hash_inset[2] = ext_key[1];
	hash_data->hash_inset[3] = ext_key[2];

	hash_data->hash_inset[4] = key[1];
	hash_data->hash_inset[5] = ext_key[3];
	hash_data->hash_inset[6] = ext_key[4];
	hash_data->hash_inset[7] = ext_key[5];

	hash_data->hash_inset[8] = key[2];
	hash_data->hash_inset[9] = key[3];
}

static u32 mce_inset_compute_hash(struct mce_fdir_handle *handle,
				    struct mce_hw_rule_inset *hw_inset,
				    u16 profile_id, u16 vport_id, u32 key)
{
	union mce_hash_data hash_data;
	struct mce_hash_key fdir_key;
	struct mce_hash_key key_tmp;
	union mce_ext_seg ext_seg;
	u32 hash_result = 0;
	u16 first_seg = 0;
	u16 end_seg = 0;
	u16 *ext = NULL;
	u16 i = 0, j = 0;
	u16 loc;

	memset(&fdir_key, 0, sizeof(fdir_key));
	memset(&ext_seg, 0, sizeof(ext_seg));
	memset(&hash_data, 0, sizeof(hash_data));

	for (i = 0; i < 11; i++)
		key_tmp.key[i] = key;
	__shift_bits_right((u16 *)&key_tmp, sizeof(key_tmp) / 2, 1);
	fdir_key = key_tmp;

	mce_hash_data_encode(hw_inset, &hash_data);
	if (handle->hash_mode == MCE_MODE_HASH_EX_PORT) {
		hash_data.word_stream[20] = vport_id << 6 | profile_id;
		hash_data.word_stream[20] |= hw_inset->keys.tun_type << 13;
	}
#define __DEBUG_FD_HASH__ (1)
#if __DEBUG_FD_HASH__
#if 1
	{
		u32 *p_ext_key = (u32 *)&hw_inset->keys.inset_ex;
		u32 *p_key = (u32 *)&hw_inset->keys.inset;

		printk("hash_data 0x%.2x\n", p_key[0]);
		printk("hash_data 0x%.2x\n", p_key[1]);
		printk("hash_data 0x%.2x\n", p_key[2]);
		printk("hash_data 0x%.2x\n", p_key[3]);
		printk("hash_data 0x%.2x\n", p_ext_key[0]);
		printk("hash_data 0x%.2x\n", p_ext_key[1]);
		printk("hash_data 0x%.2x\n", p_ext_key[2]);
		printk("hash_data 0x%.2x\n", p_ext_key[3]);
		printk("hash_data 0x%.2x\n", p_ext_key[4]);
		printk("hash_data 0x%.2x\n", p_ext_key[5]);
	}
#else
	for (i = 0; i < 10; i++) {
		printk("hash_data 0x%.2x\n", hash_data.hash_inset[i]);
	}
#endif
	printk("profile_id 0x%.2x tun_type:0x%x vport:0x%x\n",
	       hash_data.rev, hw_inset->keys.tun_type, vport_id);
#endif

#define __DEBUG_FD_HASH_OTHER__ (0)
#if __DEBUG_FD_HASH_OTHER__
	for (i = 0; i < 21; i++)
		printk("0x%.4x ", hash_data.word_stream[20 - i]);
	printk("\n");
#endif

	first_seg = (hash_data.word_stream[20]) & GENMASK(15, 1);
	end_seg = (hash_data.word_stream[0] & GENMASK(14, 0));
	for (i = 0; i < 21; i++)
		ext_seg.word_stream[1 + i] = hash_data.word_stream[i];
	ext_seg.word_stream[0] = first_seg;
	ext_seg.word_stream[22] = end_seg;
	__shift_bits_right((u16 *)&ext_seg, sizeof(ext_seg) / 2, 1);

#if __DEBUG_FD_HASH_OTHER__
	for (i = 0; i < 23; i++)
		printk("%.4x ", ext_seg.word_stream[22 - i]);
	printk("\n");
#endif

	for (i = 0; i <= 350; i++) {
		ext = (u16 *)&ext_seg;
		loc = i / 32;
		j = i % 32;
		if (fdir_key.key[loc] & BIT(j))
			hash_result ^= ext[0];
		__shift_bits_right((u16 *)&ext_seg, sizeof(ext_seg) / 2,
				   1);
#if __DEBUG_FD_HASH_OTHER__
		printk("0x%.4x", ext[22]);
		printk(" %.4x", ext[21]);
		printk(" %.4x", ext[20]);
		printk(" %.4x", ext[19]);
		printk(" %.4x", ext[18]);
		printk(" %.4x", ext[17]);
		printk(" %.4x", ext[16]);
		printk(" %.4x", ext[15]);
		printk(" %.4x", ext[14]);
		printk(" %.4x", ext[13]);
		printk(" %.4x", ext[12]);
		printk(" %.4x", ext[11]);
		printk(" %.4x", ext[10]);
		printk(" %.4x", ext[9]);
		printk(" %.4x", ext[8]);
		printk(" %.4x", ext[7]);
		printk(" %.4x", ext[6]);
		printk(" %.4x", ext[5]);
		printk(" %.4x", ext[4]);
		printk(" %.4x", ext[3]);
		printk(" %.4x", ext[2]);
		printk(" %.4x", ext[1]);
		printk(" %.4x", ext[0]);
		printk("\n");
		printk("hash_result 0x%.2x\n", hash_result);
#endif
	}

	printk("fdir:mode:%d hash_result:0x%x\n", handle->mode,
	       hash_result);
	return hash_result;
}

static struct mce_fdir_hash_entry *
mce_fdir_find_hash_entry(struct mce_fdir_handle *handle, u32 fdir_hash,
			 bool is_ipv6)
{
	struct list_head *hash_node_list = NULL;
	struct mce_fdir_hash_entry *it, *tmp;

	if (is_ipv6)
		hash_node_list = &handle->hash_node_v6_list;
	else
		hash_node_list = &handle->hash_node_v4_list;

	list_for_each_entry_safe(it, tmp, hash_node_list, entry) {
		if (it->fdir_hash == fdir_hash)
			return it;
	}
	return NULL;
}

static struct mce_fdir_hash_entry *
mce_fdir_add_hash_entry(struct mce_fdir_handle *handle,
			struct mce_fdir_hash_entry *hash_node,
			bool is_ipv6)
{
	struct list_head *hash_node_list = NULL;

	if (is_ipv6)
		hash_node_list = &handle->hash_node_v6_list;
	else
		hash_node_list = &handle->hash_node_v4_list;
	list_add_tail(&hash_node->entry, hash_node_list);
	return NULL;
}

static struct mce_fdir_node *
mce_fdir_find_insert_node(struct mce_fdir_hash_entry *hash_entry,
			    u8 max_entry)
{
	struct mce_fdir_node *it, *tmp = NULL;
	u8 bit_num = 0;

	list_for_each_entry_safe(it, tmp, &hash_entry->node_entrys,
				 entry) {
		bit_num = __user_popcount(it->node_info.bit_used);
		if (bit_num < max_entry)
			return it;
	}
	return NULL;
}

static void mce_fdir_exact_encap_node(struct mce_fdir_filter *filter,
					struct mce_fdir_node *node,
					bool new_node)
{
	struct mce_node_info *node_info = &node->node_info;
	struct mce_hw_rule_inset *inset = &filter->hw_inset;
	union mce_exact_atr_input *input = &node->exact_meta;
	int i = 0;

	if (new_node) {
		if (filter->is_ipv6) {
			memcpy(&input->v6.inset, &inset->keys.inset,
			       sizeof(inset->keys.inset));
			memcpy(&input->v6.inset_ex, &inset->keys.inset_ex,
			       sizeof(inset->keys.inset_ex));
			input->v6.e_vld = 1;
			input->v6.end = 1;
			input->v6.next_fd_ptr = 0xfff;
			input->v6.action = inset->action;
			input->v6.priority = inset->priority;
			input->v6.profile_id = inset->profile_id;
			input->v6.port = inset->port;
		} else {
			input->v4.entry[i].action = inset->action;
			input->v4.entry[i].priority = inset->priority;
			input->v4.entry[i].profile_id = inset->profile_id;
			input->v4.entry[i].port = inset->port;
			input->v4.entry[i].inset = inset->keys.inset;
			input->v4.entry[i].e_vld = 1;
			input->v4.next_fd_ptr = 0xfff;
		}
		node_info->key[0].hw_inset = filter->hw_inset.keys;
		node->type = MCE_FDIR_EXACT_M_MODE;
		node->loc = filter->loc;
		node->is_ipv6 = filter->is_ipv6;
		if (filter->is_ipv6)
			node_info->bit_used = BIT(0) | BIT(1);
		else
			node_info->bit_used |= BIT(i);
		node_info->key[i].used = 1;
	} else {
		for (i = 0; i < MCE_EXACT_NODE_MAX_ENTRY; i++) {
			if (node_info->key[i].used == 0) {
				input->v4.entry[i].action = inset->action;
				input->v4.entry[i].priority =
					inset->priority;
				input->v4.entry[i].profile_id =
					inset->profile_id;
				input->v4.entry[i].e_vld = 1;
				input->v4.entry[i].port = inset->port;
				input->v4.entry[i].inset =
					inset->keys.inset;

				node_info->key[i].hw_inset.inset =
					inset->keys.inset;
				node_info->bit_used |= BIT(i);
				node_info->key[i].used = 1;
			}
		}
		WARN_ON(filter->is_ipv6);
	}

	memcpy(&filter->data, input, sizeof(*input));
}

static int mce_fdir_exact_insert_entry(struct mce_pf *pf,
					 struct mce_fdir_handle *handle,
					 int vport,
					 struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_fdir_node *node = NULL, *first_node;
	struct mce_fdir_hash_entry *hash_node;
	struct mce_fdir_node *cur = NULL;
	bool is_ipv6 = filter->is_ipv6;
	u16 first_bit = 0;

	hash_node = mce_fdir_find_hash_entry(handle, filter->fdirhash,
					     filter->is_ipv6);
	if (hash_node) {
		if (!is_ipv6)
			cur = mce_fdir_find_insert_node(
				hash_node, MCE_EXACT_NODE_MAX_ENTRY);
		if (cur == NULL) {
			if (mce_get_valid_entry_loc(handle, &filter->loc) <
			    0)
				return -EBUSY;
			first_node = list_last_entry(
				&hash_node->node_entrys,
				struct mce_fdir_node, entry);
			first_bit = first_node->loc;
			if (is_ipv6) {
				first_node->exact_meta.v6.next_fd_ptr =
					filter->loc;
				first_node->exact_meta.v6.end = 0;
			} else {
				first_node->exact_meta.v4.next_fd_ptr =
					filter->loc;
				first_node->exact_meta.v4.end = 0;
			}

			hw->ops->fd_update_entry_table(
				hw, first_bit,
				first_node->exact_meta.dword_stream);
			node = kzalloc(sizeof(*node), GFP_KERNEL);
			filter->hash_child = 1;
			hash_node->nb_child++;
			mce_fdir_exact_encap_node(filter, node, 1);
			list_add_tail(&node->entry,
				      &hash_node->node_entrys);
			mce_set_fdir_entry_bit(handle, filter->loc);
		} else {
			filter->loc = cur->loc;
			node = cur;
			mce_fdir_exact_encap_node(filter, node, 0);
		}
		filter->hash_child = 1;
		hash_node->nb_child++;
	} else {
		if (mce_get_valid_entry_loc(handle, &filter->loc) < 0)
			return -EBUSY;
		hash_node = kzalloc(sizeof(*hash_node), GFP_KERNEL);
		if (hash_node == NULL)
			return -ENOMEM;
		hash_node->fdir_hash = filter->fdirhash;
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		if (node == NULL)
			return -ENOMEM;
		filter->hash_child = 0;
		mce_fdir_add_hash_entry(handle, hash_node, is_ipv6);
		mce_fdir_exact_encap_node(filter, node, 1);
		mce_set_fdir_entry_bit(handle, filter->loc);
		INIT_LIST_HEAD(&hash_node->node_entrys);
		list_add_tail(&node->entry, &hash_node->node_entrys);
	}
	return 0;
}

static void mce_fdir_sign_encap_node(struct mce_fdir_filter *filter,
				       struct mce_fdir_node *node,
				       bool new_node)
{
	struct mce_node_info *node_info = &node->node_info;
	struct mce_hw_rule_inset *inset = &filter->hw_inset;
	union mce_sign_atr_input *input = &node->sign_meta;
	uint8_t *sign_hash = (uint8_t *)&filter->signhash;
	int i = 0;

	if (new_node) {
		input->entry[i].actions = inset->action;
		input->entry[i].priority = inset->priority;
		input->entry[i].profile_id = inset->profile_id;
		input->entry[i].e_vld = 1;
		input->entry[i].port = inset->port;
		input->entry[i].sign_p1 = sign_hash[0];
		input->entry[i].sign[0] = sign_hash[1];
		input->entry[i].sign[1] = sign_hash[2];
		input->entry[i].sign[2] = sign_hash[3];
		input->end = 1;
		input->next_fd_ptr = 0xfff;
		node->type = MCE_FDIR_SIGN_M_MODE;
		node->loc = filter->loc;
		node_info->bit_used = BIT(0);
		node_info->key[0].sign_hash = filter->signhash;
		node_info->key[0].used = 1;
	} else {
		for (i = 0; i < MCE_SIGN_NODE_MAX_ENTRY; i++) {
			if (node_info->key[i].used == 0) {
				input->entry[i].actions = inset->action;
				input->entry[i].priority = inset->priority;
				input->entry[i].profile_id =
					inset->profile_id;
				input->entry[i].port = inset->port;
				input->entry[i].e_vld = 1;
				input->entry[i].sign_p1 = sign_hash[0];
				input->entry[i].sign[0] = sign_hash[1];
				input->entry[i].sign[1] = sign_hash[2];
				input->entry[i].sign[2] = sign_hash[3];

				node_info->bit_used = BIT(i);
				node_info->key[i].sign_hash =
					filter->signhash;
				node_info->key[i].used = 1;
			}
		}
	}

	memcpy(&filter->data, input, sizeof(*input));
}

static int mce_fdir_sign_insert_entry(struct mce_pf *pf,
				      struct mce_fdir_handle *handle,
				      int vport,
				      struct mce_fdir_filter *filter)
{
	struct mce_fdir_node *node = NULL, *first_node;
	struct mce_hw *hw = &pf->hw;
	struct mce_fdir_hash_entry *hash_node;
	struct mce_fdir_node *cur;
	uint16_t loc = filter->loc;
	uint16_t first_bit = 0;

	hash_node = mce_fdir_find_hash_entry(handle, filter->fdirhash,
					     filter->is_ipv6);
	if (hash_node) {
		cur = mce_fdir_find_insert_node(
			hash_node, MCE_SIGN_NODE_MAX_ENTRY);
		if (cur == NULL) {
			/* add a new node */
			/* edit last node to the new node and last noed end = 0 */
			if (mce_get_valid_entry_loc(handle, &filter->loc) <
			    0)
				return -EBUSY;
			first_node = list_last_entry(
				&hash_node->node_entrys,
				struct mce_fdir_node, entry);
			first_bit = first_node->loc;
			first_node->sign_meta.next_fd_ptr = filter->loc;
			first_node->sign_meta.end = 1;
			/* edit node filter->entry */
			hw->ops->fd_update_entry_table(
				hw, first_bit,
				first_node->sign_meta.dword_stream);
			node = kzalloc(sizeof(*node), GFP_KERNEL);
			node->is_ipv6 = filter->is_ipv6;
			mce_fdir_sign_encap_node(filter, node, 1);
			list_add_tail(&node->entry,
				      &hash_node->node_entrys);
			mce_set_fdir_entry_bit(handle, loc);
		} else {
			/* a node can insert a entry */
			/* redit filter->mce_fdir[0]
			 * add new entry to the node entry
			 */
			filter->loc = cur->loc;
			node = cur;
			mce_fdir_sign_encap_node(filter, node, 0);
		}
		filter->hash_child = 1;
		hash_node->nb_child++;
	} else {
		if (mce_get_valid_entry_loc(handle, &filter->loc) < 0)
			return -EBUSY;
		hash_node = kzalloc(sizeof(*hash_node), GFP_KERNEL);
		hash_node->fdir_hash = filter->fdirhash;
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		filter->hash_child = 0;
		mce_fdir_add_hash_entry(handle, hash_node,
					filter->is_ipv6);
		mce_fdir_sign_encap_node(filter, node, 1);
		mce_set_fdir_entry_bit(handle, loc);
		INIT_LIST_HEAD(&hash_node->node_entrys);
		list_add_tail(&node->entry, &hash_node->node_entrys);
	}
	return 0;
}

static int mce_fdir_insert_entry(struct mce_pf *pf,
				   struct mce_fdir_handle *handle,
				   int vport,
				   struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_fdir_sign_insert_entry(pf, handle, vport,
						  filter);
	return mce_fdir_exact_insert_entry(pf, handle, vport, filter);
}

static void mce_edit_exact_rule(struct mce_pf *pf,
				  struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = &pf->hw;
	u16 loc = filter->loc;
	u32 fdir_hash = 0;

	hw->ops->fd_update_entry_table(hw, loc, filter->data.dword_stream);
	/* edit hw quick find hash table */
	if (filter->hash_child == 0) {
		fdir_hash = filter->fdirhash;
		if (filter->is_ipv6)
			hw->ops->fd_update_ex_hash_table(hw, loc,
							 fdir_hash);
		else
			hw->ops->fd_update_hash_table(hw, loc, fdir_hash);
	}
}

static void mce_edit_sign_rule(struct mce_pf *pf,
				 struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = &pf->hw;
	u16 loc = filter->loc;
	u32 fdir_hash = 0;

	fdir_hash = filter->fdirhash;
	hw->ops->fd_update_entry_table(hw, loc, filter->data.dword_stream);

	hw->ops->fd_verificate_sign_rule(hw, filter, loc, fdir_hash);
}

static void mce_edit_hw_rule(struct mce_pf *pf,
			       struct mce_fdir_handle *handle,
			       struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_edit_sign_rule(pf, filter);
	return mce_edit_exact_rule(pf, filter);
}

static int mce_fdir_insert_hash_map(struct mce_fdir_handle *handle,
				      struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		hash_add(handle->fdir_sign_tb, &filter->hl_node,
			 filter->key);
	else
		hash_add(handle->fdir_exact_tb, &filter->hl_node,
			 filter->key);
	return 0;
}

static int mce_fdir_flow_create(struct mce_pf *pf,
				  struct mce_fdir_filter *filter,
				  struct mce_tc_flower_fltr *fltr)
{
	struct mce_fdir_handle *handle = NULL;
	struct mce_flow_engine_module *flow_engine;
	struct mce_fdir_filter *find = NULL;
	struct mce_hw_profile *profile = NULL;
	u64 field_mask_options = 0;
	struct mce_hw *hw = &pf->hw;
	int ret = 0;
	bool new_profile = false;

	flow_engine = pf->flow_engine;
	handle = (struct mce_fdir_handle *)mce_get_engine_handle(
		pf, MCE_FLOW_FDIR);
	filter->key = mce_fdir_hl_cal_key(handle, &filter->lkup_pattern);
	find = mce_fdir_entry_lookup(handle, filter);
	if (find) {
		dev_err(hw->dev, "error: add fdir rule is exist!\n");
		return -EEXIST;
	}

	if (handle->profiles[filter->profile_id] == NULL) {
		profile = mce_fdir_alloc_profile(handle, filter);
		if (profile == NULL) {
			dev_err(hw->dev,
				"fdir profile mask alloc failed!\n");
			return -EINVAL;
		}
		handle->profiles[filter->profile_id] = profile;
		hw->ops->fd_profile_update(hw, profile, true);
		new_profile = true;
	} else {
		if (!mce_conflct_profile_check(handle, filter)) {
			if (filter->mask_info) {
				kfree(filter->mask_info->field_bitmask);
				kfree(filter->mask_info);
				kfree(filter);
			}

			dev_err(hw->dev,
				"fdir filter field_mask is conflicted with preset profile!\n");
			return -EINVAL;
		}
		profile = handle->profiles[filter->profile_id];
	}

	if (filter->mask_info) {
		if (profile->mask_info) {
			ret = mce_check_conflct_filed_bitmask(
				profile, filter->mask_info);
			if (ret) {
				kfree(filter->mask_info->field_bitmask);
				kfree(filter->mask_info);
				kfree(filter);
				dev_err(hw->dev,
					"fdir profile mask is inval!\n");
				return -EINVAL;
			}
		} else {
			if (new_profile) {
				field_mask_options = mce_prof_bitmask_alloc(
					hw, handle, filter->mask_info);
				if (field_mask_options == 0) {
					if (new_profile) {
						hw->ops->fd_profile_update(
							hw, profile,
							false);
						handle->profiles
							[filter->profile_id] =
							NULL;
						kfree(profile);
					}
					kfree(filter->mask_info
						      ->field_bitmask);
					kfree(filter->mask_info);
					kfree(filter);
					dev_err(hw->dev,
						"fdir profile field mask resource is not enough!\n");
					return -EINVAL;
				}
				hw->ops->fd_profile_field_bitmask_update(
					hw, profile->profile_id,
					field_mask_options);
				profile->mask_info = filter->mask_info;
			} else {
				kfree(filter->mask_info);
				kfree(filter);
				dev_err(hw->dev,
					"fdir filter field_mask is conflict with "
					"old profile it is all mask!\n");
				return -EINVAL;
			}
		}
	} else {
		if (profile->mask_info) {
			/* need to check bitmask rule is conflict with file_mask rule */
			kfree(filter);
			dev_err(hw->dev,
				"fdir profile field_bitmask is enable will conflict"
				" whit field mask so don't allow user set it");
			return -EINVAL;
		}
	}

	mce_program_fdir_rule(&pf->hw, handle, filter, fltr);
	filter->fdirhash = mce_inset_compute_hash(handle,
						  &filter->hw_inset,
						  filter->profile_id, 0,
						  MCE_ATR_BUCKET_HASH_KEY);
	filter->fdirhash &= MCE_HASH_VALID_BIT;

	if (handle->mode == MCE_FDIR_SIGN_M_MODE) {
		filter->signhash = mce_inset_compute_hash(
			handle, &filter->hw_inset, filter->profile_id,
			/*vport->attr.vport_id*/ 0,
			MCE_ATR_SIGNATURE_HASH_KEY);
		filter->signhash &= MCE_SIGN_HASH_VALID_BIT;
	}
	ret = mce_fdir_insert_entry(pf, handle, /*vport*/ 0, filter);
	if (ret < 0)
		goto mat_res_out_range;
	mce_edit_hw_rule(pf, handle, filter);
	mce_fdir_insert_hash_map(handle, filter);
	profile->ref_cnt++;
	if (filter->mask_info)
		filter->mask_info->ref_cnt++;
	return 0;
mat_res_out_range:
	if (filter->mask_info) {
		kfree(filter->mask_info->field_bitmask);
		kfree(filter->mask_info);
		kfree(filter);
	}
	if (new_profile) {
		hw->ops->fd_profile_update(hw, profile, false);
		handle->profiles[filter->profile_id] = NULL;
		kfree(profile);
	}
	return -1;
}

static int mce_fdir_flow_engine_init(struct mce_pf *pf, void **handle)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_fdir_handle *fdir_handle;

	fdir_handle =
		kzalloc(sizeof(struct mce_fdir_handle), GFP_KERNEL);
	if (fdir_handle == NULL)
		return -ENOMEM;

	if (pf->fdir_mode == MCE_FDIR_SIGN_M_MODE) {
		fdir_handle->mode = MCE_FDIR_SIGN_M_MODE;
		hash_init(fdir_handle->fdir_sign_tb);
	} else {
		fdir_handle->mode = MCE_FDIR_EXACT_M_MODE;
		hash_init(fdir_handle->fdir_exact_tb);
	}

	INIT_LIST_HEAD(&fdir_handle->hash_node_v4_list);
	INIT_LIST_HEAD(&fdir_handle->hash_node_v6_list);
	fdir_handle->hash_mode = MCE_MODE_HASH_EX_PORT;
	hw->ops->fd_init_hw(hw, fdir_handle);
	*handle = fdir_handle;
	dev_info(
		mce_hw_to_dev(hw),
		"N20 fdir pattern size:%ld, handle mode:%d, fdir mode:%d\n",
		sizeof(union mce_fdir_pattern), fdir_handle->mode,
		pf->fdir_mode);
	return 0;
}

static struct mce_fdir_node *
mce_exact_search_node(struct mce_fdir_hash_entry *hash_node,
			struct mce_fdir_filter *filter)
{
	struct mce_fdir_node *it;

	list_for_each_entry(it, &hash_node->node_entrys, entry) {
		if (it->loc == filter->loc)
			return it;
	}
	return NULL;
}

static struct mce_fdir_node *
mce_fdir_sign_search_node(struct mce_fdir_hash_entry *hash_node,
			    struct mce_fdir_filter *filter)
{
	struct mce_fdir_node *it;
	int i = 0;

	list_for_each_entry(it, &hash_node->node_entrys, entry) {
		if (it->loc == filter->loc) {
			for (i = 0; i < MCE_SIGN_NODE_MAX_ENTRY; i++) {
				if (it->node_info.key[i].sign_hash ==
				    filter->signhash)
					return it;
			}
		}
	}

	return NULL;
}

static void mce_clear_fdir_entry_bit(struct mce_fdir_handle *handle,
				       u16 loc)
{
	u16 rank = loc / 32;
	u16 cow = loc % 32;
	handle->entry_bitmap[rank] &= ~(1 << cow);
}

static void mce_fdir_exact_remove_entry(struct mce_pf *pf,
					  struct mce_fdir_handle *handle,
					  int vport,
					  struct mce_fdir_filter *filter)
{
	struct mce_fdir_hash_entry *hash_node = NULL;
	struct mce_hw *hw = &pf->hw;
	struct mce_fdir_node /**node = NULL,*/ *it = NULL;
	struct mce_fdir_node *next = NULL, *pre = NULL;
	bool find = false;
	int i = 0;

	hash_node = mce_fdir_find_hash_entry(handle, filter->fdirhash,
					     filter->is_ipv6);
	if (!hash_node)
		return;

	it = mce_exact_search_node(hash_node, filter);
	WARN_ON(it == NULL);
	for (i = 0; i < MCE_EXACT_NODE_MAX_ENTRY; i++) {
		if (!memcmp(&it->node_info.key[i].hw_inset,
			    &filter->hw_inset.keys,
			    sizeof(filter->hw_inset.keys))) {
			find = 1;
			memset(&it->node_info.key[i], 0,
			       sizeof(struct mce_node_key));
			memset(&it->exact_meta.v4.entry[i], 0,
			       sizeof(it->exact_meta.v4.entry[i]));
			it->node_info.key[i].used = 0;
			it->node_info.bit_used &= ~BIT(i);
			break;
		}
	}
	WARN_ON(find == 0);
	next = list_next_entry(it, entry);
	pre = list_prev_entry(it, entry);
	memcpy(&filter->data, &it->exact_meta, sizeof(filter->data));
	if (filter->is_ipv6 || it->node_info.bit_used == 0) {
		filter->clear_node = 1;
		list_del(&it->entry);
		memset(it, 0, sizeof(*it));
		memset(&filter->data, 0, sizeof(filter->data));
		hash_node->nb_child--;
		mce_clear_fdir_entry_bit(handle, filter->loc);
		kfree(it);
	}

	if (filter->clear_node && !list_empty(&hash_node->node_entrys)) {
		if (pre) {
			if (next == NULL) {
				if (pre->is_ipv6) {
					pre->exact_meta.v6.next_fd_ptr =
						0x1fff;
					pre->exact_meta.v6.end = 1;
				} else {
					pre->exact_meta.v4.next_fd_ptr =
						0x1fff;
					pre->exact_meta.v4.end = 1;
				}
			} else {
				if (pre->is_ipv6) {
					pre->exact_meta.v6.next_fd_ptr =
						next->loc;
				} else {
					pre->exact_meta.v4.next_fd_ptr =
						next->loc;
				}
			}

			hw->ops->fd_update_entry_table(
				hw, pre->loc,
				pre->exact_meta.dword_stream);
		} else {
			if (next != NULL) {
				if (next->is_ipv6)
					hw->ops->fd_update_ex_hash_table(
						hw, next->loc,
						hash_node->fdir_hash);
				else
					hw->ops->fd_update_hash_table(
						hw, next->loc,
						hash_node->fdir_hash);
			}
		}
		mce_clear_fdir_entry_bit(handle, filter->loc);
	}
	if (list_empty(&hash_node->node_entrys))
		list_del(&hash_node->entry);
}

static void mce_clear_exact_rule(struct mce_pf *pf, int vport,
				   struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = &pf->hw;
	u32 fdir_hash = 0;
	u16 loc = 0;

	fdir_hash = filter->fdirhash;
	loc = filter->loc;
	hw->ops->fd_update_entry_table(hw, loc, filter->data.dword_stream);
	if (filter->hash_child == 0) {
		if (filter->is_ipv6)
			hw->ops->fd_update_ex_hash_table(hw, 0, fdir_hash);
		else
			hw->ops->fd_update_hash_table(hw, 0, fdir_hash);
	}
}

static void mce_clear_sign_rule(struct mce_pf *pf, int vport,
				  struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = &pf->hw;
	u32 fdir_hash = 0;
	u16 loc = 0;

	if (filter->clear_node) {
		fdir_hash = filter->fdirhash;
		loc = filter->loc;
		hw->ops->fd_update_entry_table(hw, loc, NULL);
	}
	/************************************************************/
	if (filter->hash_child == 0)
		hw->ops->fd_clear_sign_rule(hw, fdir_hash);
}

static void mce_clear_hw_rule(struct mce_pf *pf,
				struct mce_fdir_handle *handle,
				int vport,
				struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_clear_sign_rule(pf, vport, filter);
	return mce_clear_exact_rule(pf, vport, filter);
}

static void mce_fdir_sign_remove_entry(struct mce_pf *pf,
					 struct mce_fdir_handle *handle,
					 int vport,
					 struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = &pf->hw;
	struct mce_fdir_hash_entry *hash_node;
	struct mce_fdir_node *it;
	struct mce_fdir_node *next;
	struct mce_fdir_node *pre;

	bool find = false;
	int i = 0;

	hash_node = mce_fdir_find_hash_entry(handle, filter->fdirhash,
					     filter->is_ipv6);
	if (hash_node) {
		it = mce_fdir_sign_search_node(hash_node, filter);
		for (i = 0; i < MCE_SIGN_NODE_MAX_ENTRY; i++) {
			if (it->node_info.key[i].sign_hash ==
			    filter->signhash) {
				find = 1;
				it->node_info.key[i].sign_hash = 0;
				it->node_info.key[i].used = 0;
				it->node_info.bit_used &= BIT(i);
				memset(&it->sign_meta.entry[i], 0,
				       sizeof(it->sign_meta.entry[i]));
				break;
			}
		}
		WARN_ON(find == 0);
		next = list_next_entry(it, entry);
		pre = list_prev_entry(it, entry);
		memcpy(&filter->data, &it->sign_meta,
		       sizeof(filter->data));
		if (it->node_info.bit_used == 0) {
			filter->clear_node = 1;
			list_del(&it->entry);
			memset(it, 0, sizeof(*it));
			memset(&filter->data, 0, sizeof(filter->data));
			hash_node->nb_child--;
			kfree(it);
		}
		if (filter->clear_node &&
		    !list_empty(&hash_node->node_entrys)) {
			if (pre) {
				if (next == NULL) {
					pre->sign_meta.next_fd_ptr = 0xfff;
					pre->sign_meta.end = 1;
				} else {
					pre->sign_meta.next_fd_ptr =
						next->loc;
				}
				hw->ops->fd_update_entry_table(
					hw, pre->loc,
					pre->exact_meta.dword_stream);
			} else {
				if (next != NULL)
					hw->ops->fd_update_hash_table(
						hw, next->loc,
						hash_node->fdir_hash);
			}
			mce_clear_fdir_entry_bit(handle, filter->loc);
		}
	}
	if (list_empty(&hash_node->node_entrys))
		list_del(&hash_node->entry);
}

static void mce_fdir_remove_entry(struct mce_pf *pf,
				    struct mce_fdir_handle *handle,
				    int vport,
				    struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_fdir_sign_remove_entry(pf, handle, vport,
						    filter);
	return mce_fdir_exact_remove_entry(pf, handle, vport, filter);
}

static int mce_fdir_remove_hash_map(struct mce_fdir_handle *handle,
				      struct mce_fdir_filter *filter)
{
	hash_del(&filter->hl_node);
	return 0;
}

static int mce_fdir_flow_delete(struct mce_pf *pf,
				  struct mce_fdir_filter *filter,
				  struct mce_tc_flower_fltr *fltr)
{
	struct mce_fdir_handle *handle = NULL;
	struct mce_fdir_filter *find = NULL;
	struct mce_hw *hw = &pf->hw;

	handle = (struct mce_fdir_handle *)mce_get_engine_handle(
		pf, MCE_FLOW_FDIR);
	find = mce_fdir_entry_lookup(handle, filter);
	if (find == NULL) {
		dev_err(hw->dev, "error: fdir rule entry isn't exist\n");
		return -1;
	}
	mce_fdir_remove_entry(pf, handle, 0, filter);
	mce_clear_hw_rule(pf, handle, 0, filter);
	mce_fdir_remove_hash_map(handle, filter);
	mce_fdir_remove_profile(hw, handle, filter);

	return 0;
}

static int mce_fdir_l2_encode(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_inset_key *key = &filter->hw_inset.keys.inset;

	if (filter->options & MCE_OPT_ETHTYPE) {
		/* check ether_type is valid */
		key->inset_key0 = lkup_pattern->formatted.ether_type;
	}

	return 0;
}

static int mce_fdir_l2_only_encode(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_hw_inset_key *keys = &filter->hw_inset.keys;
	struct mce_inset_key *key = &keys->inset;
	u64 inset0 = 0, inset1 = 0;
	u8 *inset_temp = NULL;

	if (filter->options & (MCE_OPT_SMAC | MCE_OPT_DMAC)) {
		inset_temp = (u8 *)(&inset0);
		inset_temp[4] = lkup_pattern->formatted.src_mac[5];
		inset_temp[5] = lkup_pattern->formatted.src_mac[4];
		inset_temp[6] = lkup_pattern->formatted.src_mac[3];
		inset_temp[7] = lkup_pattern->formatted.src_mac[2];
		inset_temp = (u8 *)(&inset1);
		inset_temp[0] = lkup_pattern->formatted.src_mac[1];
		inset_temp[1] = lkup_pattern->formatted.src_mac[0];
		inset_temp[2] = lkup_pattern->formatted.dst_mac[5];
		inset_temp[3] = lkup_pattern->formatted.dst_mac[4];
		inset_temp[4] = lkup_pattern->formatted.dst_mac[3];
		inset_temp[5] = lkup_pattern->formatted.dst_mac[2];
		inset_temp[6] = lkup_pattern->formatted.dst_mac[1];
		inset_temp[7] = lkup_pattern->formatted.dst_mac[0];
	}
	if (filter->options & MCE_OPT_VLAN_VID)
		inset0 |= lkup_pattern->formatted.vlan_id;
#if 0
	/* l2 only mode unsupport ethtype */
	else if (filter->options & MCE_OPT_ETHTYPE)
		inset0 |= lkup_pattern->formatted.ether_type;
#endif
	key->inset_key0 = inset0;
	key->inset_key1 = inset1;
	return 0;
}

static int mce_fdir_encode_ip(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_hw_inset_key *keys = &filter->hw_inset.keys;
	struct mce_inset_key_extend *ex_key = &keys->inset_ex;
	struct mce_inset_key *key = &keys->inset;
	u64 inset = 0;

	if (filter->is_ipv6) {
		if (filter->options & MCE_OPT_IPV6_DIP ||
		    filter->options & MCE_OPT_OUT_IPV6_DIP) {
			inset = lkup_pattern->formatted.dst_addr[0];
			inset = inset << 32;
			key->inset_key0 = inset;

			ex_key->dword_key[3] =
				lkup_pattern->formatted.dst_addr[1];
			ex_key->dword_key[4] =
				lkup_pattern->formatted.dst_addr[2];
			ex_key->dword_key[5] =
				lkup_pattern->formatted.dst_addr[3];
		}
		if (filter->options & MCE_OPT_IPV6_SIP ||
		    filter->options & MCE_OPT_OUT_IPV6_SIP) {
			inset = lkup_pattern->formatted.src_addr[0];
			key->inset_key0 |= inset;

			ex_key->dword_key[0] =
				lkup_pattern->formatted.src_addr[1];
			ex_key->dword_key[1] =
				lkup_pattern->formatted.src_addr[2];
			ex_key->dword_key[2] =
				lkup_pattern->formatted.src_addr[3];
		}
		if (filter->options & MCE_OPT_IPV6_DSCP) {
			inset = lkup_pattern->formatted.ip_tos >> 2;
			inset <<= 32;
			key->inset_key1 |= inset;
		}
	} else {
		if (filter->options & MCE_OPT_IPV4_DIP ||
		    filter->options & MCE_OPT_OUT_IPV4_DIP) {
			inset = lkup_pattern->formatted.dst_addr[0];
			inset = inset << 32;
		}
		if (filter->options & MCE_OPT_IPV4_SIP ||
		    filter->options & MCE_OPT_OUT_IPV4_SIP)
			inset |= lkup_pattern->formatted.src_addr[0];
		key->inset_key0 = inset;
		if (filter->options & MCE_OPT_IPV4_DSCP) {
			inset = lkup_pattern->formatted.ip_tos >> 2;
			inset <<= 32;
			key->inset_key1 |= inset;
		}
	}

	return 0;
}

static int mce_fdir_encode_l4_port(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_inset_key *keys = &filter->hw_inset.keys.inset;
	u64 inset = 0;

	if (filter->options & MCE_OPT_L4_DPORT ||
	    filter->options & MCE_OPT_OUT_L4_DPORT) {
		inset = lkup_pattern->formatted.l4_dport;
		inset <<= 16;
	}
	if (filter->options & MCE_OPT_L4_SPORT ||
	    filter->options & MCE_OPT_OUT_L4_SPORT)
		inset |= lkup_pattern->formatted.l4_sport;
	keys->inset_key1 |= inset;

	return 0;
}

static int mce_fdir_tun_inner_encode(struct mce_fdir_filter *filter)
{
	mce_fdir_encode_ip(filter);
	mce_fdir_encode_l4_port(filter);

	return 0;
}

static int mce_fdir_ip_frag_encode(struct mce_fdir_filter *filter)
{
	return mce_fdir_encode_ip(filter);
}

static int mce_fdir_ip_pay_encode(struct mce_fdir_filter *filter)
{
	mce_fdir_encode_ip(filter);
	/* todo add ip_proto inset key */

	return 0;
}

static int mce_fdir_tcp_sync(struct mce_fdir_filter *filter)
{
	mce_fdir_encode_ip(filter);
	mce_fdir_encode_l4_port(filter);

	return 0;
}

static int mce_fdir_tun_out_encode(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_inset_key *keys = &filter->hw_inset.keys.inset;
	u64 inset = 0;

	mce_fdir_encode_ip(filter);
	if (filter->profile_id != MCE_PTYPE_TUN_IPV4_GRE)
		mce_fdir_encode_l4_port(filter);
	if (filter->options & (MCE_OPT_VXLAN_VNI | MCE_OPT_GENEVE_VNI)) {
		inset = lkup_pattern->formatted.vni;
		inset <<= 32;
	} else if (filter->options &
		   (MCE_OPT_GTP_U_TEID | MCE_OPT_GTP_C_TEID)) {
		inset = (lkup_pattern->formatted.teid);
		inset <<= 32;
	} else if (filter->options & MCE_OPT_ESP_SPI) {
		inset = lkup_pattern->formatted.esp_spi;
	} else if (filter->options & MCE_OPT_NVGRE_TNI) {
		inset = lkup_pattern->formatted.key;
		//inset >>= 8;
		inset <<= 32;
	} else {
		inset = 0;
	}
	keys->inset_key1 |= inset;

	return 0;
}

static struct mce_fdir_key_encode mce_profile_encode[] = {
	{ MCE_PTYPE_UNKNOW, NULL }, /* 0 */
	{ MCE_PTYPE_L2_ONLY, mce_fdir_l2_only_encode }, /* 1 */
	{ MCE_PTYPE_TUN_INNER_L2_ONLY, mce_fdir_l2_only_encode }, /* 2 */
	{ MCE_PTYPE_TUN_OUTER_L2_ONLY, mce_fdir_l2_only_encode }, /* 3 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_FRAG,
	  mce_fdir_ip_frag_encode }, /* 4 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_FRAG,
	  mce_fdir_ip_frag_encode }, /* 5 */
	{ MCE_PTYPE_L2_ETHTYPE, mce_fdir_l2_encode }, /* 6 */
	{ MCE_PTYPE_TUN_INNER_L2_ETHTYPE, mce_fdir_l2_encode }, /* 7 */
	{ MCE_PTYPE_IPV4_FRAG, mce_fdir_ip_frag_encode }, /* 8*/
	{ MCE_PTYPE_IPV4_TCP_SYNC, mce_fdir_tcp_sync }, /* 9 */
	{ MCE_PTYPE_IPV4_TCP, mce_fdir_tun_inner_encode }, /* 10 */
	{ MCE_PTYPE_IPV4_UDP, mce_fdir_tun_inner_encode }, /* 11 */
	{ MCE_PTYPE_IPV4_SCTP, mce_fdir_tun_inner_encode }, /* 12 */
	{ MCE_PTYPE_IPV4_ESP, mce_fdir_tun_out_encode }, /* 13 */
	{ MCE_PTYPE_IPV4_PAY, mce_fdir_ip_pay_encode }, /* 14 */
	{ 0, 0 }, /* 15 */
	{ MCE_PTYPE_IPV6_FRAG, mce_fdir_ip_pay_encode }, /* 16 */
	{ MCE_PTYPE_IPV6_TCP_SYNC, mce_fdir_tcp_sync }, /* 17 */
	{ MCE_PTYPE_IPV6_TCP, mce_fdir_tun_inner_encode }, /* 18 */
	{ MCE_PTYPE_IPV6_UDP, mce_fdir_tun_inner_encode }, /* 19 */
	{ MCE_PTYPE_IPV6_SCTP, mce_fdir_tun_inner_encode }, /* 20 */
	{ MCE_PTYPE_IPV6_ESP, mce_fdir_tun_inner_encode }, /* 21 */
	{ MCE_PTYPE_IPV6_PAY, mce_fdir_ip_pay_encode }, /* 22 */
	{ 0, 0 }, /* 23 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_PAY,
	  mce_fdir_ip_pay_encode }, /* 24 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_TCP,
	  mce_fdir_tun_inner_encode }, /* 25 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_UDP,
	  mce_fdir_tun_inner_encode }, /* 26 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_SCTP,
	  mce_fdir_tun_inner_encode }, /* 27 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_PAY,
	  mce_fdir_ip_pay_encode }, /* 28 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_TCP,
	  mce_fdir_tun_inner_encode }, /* 29 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_UDP,
	  mce_fdir_tun_inner_encode }, /* 30 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_SCTP,
	  mce_fdir_tun_inner_encode }, /* 31 */
	/* outer gtp_u/gtp_c pattern */
	{ MCE_PTYPE_GTP_U_GPDU_IPV4, mce_fdir_tun_out_encode }, /* 32 */
	{ MCE_PTYPE_GTP_U_IPV4, mce_fdir_ip_pay_encode }, /* 33 */
	{ MCE_PTYPE_GTP_C_TEID_IPV4, mce_fdir_tun_out_encode }, /* 34 */
	{ MCE_PTYPE_GTP_C_IPV4, mce_fdir_tun_out_encode }, /* 35 */
	{ MCE_PTYPE_GTP_U_GPDU_IPV6, mce_fdir_tun_out_encode }, /* 36 */
	{ MCE_PTYPE_GTP_U_IPV6, mce_fdir_tun_out_encode }, /* 37 */
	{ MCE_PTYPE_GTP_C_TEID_IPV6, mce_fdir_tun_out_encode }, /* 38 */
	{ MCE_PTYPE_GTP_C_IPV6, mce_fdir_tun_out_encode }, /* 39 */

	{ MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  mce_fdir_ip_frag_encode }, /* 40 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP_SYNC, mce_fdir_tcp_sync }, /* 41 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  mce_fdir_tun_inner_encode }, /* 42 */
	{ MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  mce_fdir_tun_inner_encode }, /* 43 */
	{ MCE_PTYPE_TUN_INNER_IPV4_SCTP,
	  mce_fdir_tun_inner_encode }, /* 44 */
	{ MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  mce_fdir_tun_inner_encode }, /* 45 */
	{ MCE_PTYPE_TUN_INNER_IPV4_PAY, mce_fdir_ip_pay_encode }, /* 46 */
	{ 0, 0 }, /* 47 */
	{ MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  mce_fdir_ip_frag_encode }, /* 48 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP_SYNC,
	  mce_fdir_tun_out_encode }, /* 49 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  mce_fdir_tun_inner_encode }, /* 50 */
	{ MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  mce_fdir_tun_inner_encode }, /* 51 */
	{ MCE_PTYPE_TUN_INNER_IPV6_SCTP,
	  mce_fdir_tun_inner_encode }, /* 52 */
	{ MCE_PTYPE_TUN_INNER_IPV6_ESP,
	  mce_fdir_tun_inner_encode }, /* 53 */
	{ MCE_PTYPE_TUN_INNER_IPV6_PAY, mce_fdir_ip_pay_encode }, /* 54 */
	{ 0, 0 }, /* 55 */
	{ MCE_PTYPE_TUN_IPV4_VXLAN, mce_fdir_tun_out_encode }, /* 56 */
	{ MCE_PTYPE_TUN_IPV4_GENEVE, mce_fdir_tun_out_encode }, /* 57 */
	{ MCE_PTYPE_TUN_IPV4_GRE, mce_fdir_tun_out_encode }, /* 58 */
	{ 0, 0 }, /* 59 */
	{ MCE_PTYPE_TUN_IPV6_VXLAN, mce_fdir_tun_out_encode }, /* 60 */
	{ MCE_PTYPE_TUN_IPV6_GENEVE, mce_fdir_tun_out_encode }, /* 61 */
	{ MCE_PTYPE_TUN_IPV6_GRE, mce_fdir_tun_out_encode }, /* 62 */
};

int mce_fdir_key_setup(struct mce_fdir_filter *filter)
{
	return mce_profile_encode[filter->profile_id].key_encode(filter);
}

struct mce_flow_engine_module mce_fdir_engine = {
	.create = mce_fdir_flow_create,
	.destroy = mce_fdir_flow_delete,
	.init = mce_fdir_flow_engine_init,
	.type = MCE_FLOW_FDIR,
};