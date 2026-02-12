#ifndef __pe_abort_reasons_h
#define __pe_abort_reasons_h
#define NO_ERROR                        0   /* no error occurred*/
#define REASON_INGR_PARSER_ERROR        3   /* see error code reported in last byte */
#define REASON_INGR_EXCEPTION           4   /* Ingress exception processing discard */
#define REASON_INGR_INTERWORKING_OPT    5   /* Undefined interworking option in ITP configuration*/
#define REASON_INGR_ETHERTYPE_FILT_B    6   /* Discard due to Ethertype blacklist */
#define REASON_INGR_ETHERTYPE_FILT_W    7   /* Discard due to Ethertype whitelist */
#define REASON_INGR_PPPoE_FILTER        8   /* Non-PPPoE packet discarded due to PPPoE Filter */
#define REASON_INGR_VLAN_COPERR         9   /* ExtVLAN active discard or unsuccessful lookup */
#define REASON_INGR_BRIDGEPORT_INVALID  11  /* Undefined ingress bridge port */
#define REASON_INGR_BRIDGEPORT_PSTATE   12  /* Ingress Bridge Port in Discard or Reserved state */
#define REASON_INGR_TAG_FILTER          13  /* Ingress Tagging Filter active discard or unsuccessful lookup */
#define REASON_INGR_ACL_FILTER          14  /* ACL Filtering was not passed */
#define REASON_INGR_SIMPLE_POLICER      15  /* UNI Ingress simple policer periodic discard */
#define REASON_LEARN_PORT_LOCK          18  /* Bridge Port change, but port is locked */
#define REASON_LEARN_STATIC             19  /* Bridge Port change, but entry is static */
#define REASON_LEARN_ADD_ERR_NOT0_4     20  /* Learning Limit exceeded or Fwd Table full */
#define REASON_LEARN_PSTATE_NOT_FWD     21  /* Bridge Port not in Forwarding state */
#define REASON_FWD1_NO_KEY_BUILD        22  /* Illegal Forwarding Method */
#define REASON_FWD_UNKNOWN_MC           25  /* Forwarding: Unknown MC group */
#define REASON_FWD_UNKNOWN              26  /* Forwarding: Unknown forwarding without (FloodAllow==1) means ForwardingMethode>=2 and CrossConnect==1 */
#define REASON_FWD_UUC_FLOOD_DISABLED   27  /* Forwarding: Unknown L2 UC address, but flooding is disabled */
#define REASON_METER_DISCARD            28  /* Discard due to metering result = red */
#define REASON_FWD_UNKOWN_L3_MC         29  /* Discard due to unkown L3 multicast */
#define REASON_EGR_EXCEPTION            36  /* Egress exception processing discard */
#define REASON_EGR_PMAPPER_INVALID      37  /* Invalid P-Mapper ID */
#define REASON_EGR_ANI_US_GEM_ERR       38  /* Invalid GEM Port (upstream) */
#define REASON_EGR_UNI_INVALID          39  /* Invalid UNI ID (downstream) */
#define REASON_EGR_VLAN_COPERR          41  /* ExtVLAN active discard or unsuccessful lookup */
#define REASON_EGR_BRIDGEPORT_INVALID   43  /* Undefined egress bridge port */
#define REASON_EGR_BRIDGEPORT_PSTATE    44  /* Egress Bridge Port not in Forwarding state */
#define REASON_EGR_TAG_FILTER           45  /* Egress Tagging Filter active discard or unsuccessful lookup */
#define REASON_EGR_BRIDGE_NO_LOC_SWITCH 46  /* Local Switching not allowed */
#define REASON_EGR_BRIDGE2_FILTERING    47  /* Egress Bridge Port Filtering not passed */
#define REASON_SA_FILTERING             48  /* MAC SA Filtering not passed */
#define REASON_DA_FILTERING             49  /* MAC DA Filtering not passed */

#define PDUT_ERR_OFFS                    1  /* bit 0 */
#define EthLength_ERR_OFFS               2  /* bit 1 */
#define VLAN_ERR_OFFS                    4  /* bit 2 */
#define IP_ERR_OFFS                      8  /* bit 3 */
#define INGR_AGING_ERR_OFFS             16  /* bit 4 */
#endif
