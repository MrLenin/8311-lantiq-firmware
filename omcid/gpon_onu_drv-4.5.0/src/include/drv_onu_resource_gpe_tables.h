/******************************************************************************

                               Copyright (c) 2013
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* attention, this file was automatically generated
   by update_sce.py at 31 Jan 2013 08:25:50 +000 */

/**
   \file drv_onu_resource_gpe_tables.h
*/

#ifndef _drv_onu_resource_gpe_tables_h_
#define _drv_onu_resource_gpe_tables_h_

/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/

/** \addtogroup GPON_GPE_TABLES GPON Packet Engine Table Definitions
   @{
*/

/** Table identifier */
#define ONU_GPE_DS_GEM_PORT_TABLE_ID ((ONU_GPE_COP_TBL << GPE_TABLE_COP_OFFSET) | 1)
/** HW coprocessor identifier */
#define ONU_GPE_DS_GEM_PORT_TABLE_COP_ID ONU_GPE_COP_TBL
/** Table size */
#define ONU_GPE_DS_GEM_PORT_TABLE_SIZE 256
/** Table entry size */
#define ONU_GPE_DS_GEM_PORT_TABLE_ENTRY_SIZE 128

/** Table identifier */
#define ONU_GPE_US_GEM_PORT_TABLE_ID ((ONU_GPE_COP_EXT << GPE_TABLE_COP_OFFSET) | 1)
/** HW coprocessor identifier */
#define ONU_GPE_US_GEM_PORT_TABLE_COP_ID ONU_GPE_COP_EXT
/** Table size */
#define ONU_GPE_US_GEM_PORT_TABLE_SIZE 256
/** Table entry size */
#define ONU_GPE_US_GEM_PORT_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_FID_ASSIGNMENT_TABLE_ID ((ONU_GPE_COP_EXT << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_FID_ASSIGNMENT_TABLE_COP_ID ONU_GPE_COP_EXT
/** Table size */
#define ONU_GPE_FID_ASSIGNMENT_TABLE_SIZE 256
/** Table entry size */
#define ONU_GPE_FID_ASSIGNMENT_TABLE_ENTRY_SIZE 64

/** Table identifier */
#define ONU_GPE_FID_HASH_TABLE_ID ((ONU_GPE_COP_EXT << GPE_TABLE_COP_OFFSET) | 3)
/** HW coprocessor identifier */
#define ONU_GPE_FID_HASH_TABLE_COP_ID ONU_GPE_COP_EXT
/** Table size */
#define ONU_GPE_FID_HASH_TABLE_SIZE 1024
/** Table entry size */
#define ONU_GPE_FID_HASH_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_BRIDGE_PORT_TABLE_ID (GPE_TABLE_PE_MIN_ID + 1)
/** HW coprocessor identifier */
#define ONU_GPE_BRIDGE_PORT_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_BRIDGE_PORT_TABLE_SIZE 128
/** Table entry size */
#define ONU_GPE_BRIDGE_PORT_TABLE_ENTRY_SIZE 128

/** Table identifier */
#define ONU_GPE_TAGGING_FILTER_TABLE_ID ((ONU_GPE_COP_TAG << GPE_TABLE_COP_OFFSET) | 1)
/** HW coprocessor identifier */
#define ONU_GPE_TAGGING_FILTER_TABLE_COP_ID ONU_GPE_COP_TAG
/** Table size */
#define ONU_GPE_TAGGING_FILTER_TABLE_SIZE 128
/** Table entry size */
#define ONU_GPE_TAGGING_FILTER_TABLE_ENTRY_SIZE 64

/** Table identifier */
#define ONU_GPE_VLAN_TABLE_ID ((ONU_GPE_COP_TAG << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_VLAN_TABLE_COP_ID ONU_GPE_COP_TAG
/** Table size */
#define ONU_GPE_VLAN_TABLE_SIZE 1024
/** Table entry size */
#define ONU_GPE_VLAN_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_EXTENDED_VLAN_TABLE_ID ((ONU_GPE_COP_EXT << GPE_TABLE_COP_OFFSET) | 4)
/** HW coprocessor identifier */
#define ONU_GPE_EXTENDED_VLAN_TABLE_COP_ID ONU_GPE_COP_EXT
/** Table size */
#define ONU_GPE_EXTENDED_VLAN_TABLE_SIZE 128
/** Table entry size */
#define ONU_GPE_EXTENDED_VLAN_TABLE_ENTRY_SIZE 64

/** Table identifier */
#define ONU_GPE_VLAN_RULE_TABLE_ID ((ONU_GPE_COP_EXT << GPE_TABLE_COP_OFFSET) | 5)
/** HW coprocessor identifier */
#define ONU_GPE_VLAN_RULE_TABLE_COP_ID ONU_GPE_COP_EXT
/** Table size */
#define ONU_GPE_VLAN_RULE_TABLE_SIZE 1024
/** Table entry size */
#define ONU_GPE_VLAN_RULE_TABLE_ENTRY_SIZE 64

/** Table identifier */
#define ONU_GPE_VLAN_TREATMENT_TABLE_ID ((ONU_GPE_COP_EXT << GPE_TABLE_COP_OFFSET) | 6)
/** HW coprocessor identifier */
#define ONU_GPE_VLAN_TREATMENT_TABLE_COP_ID ONU_GPE_COP_EXT
/** Table size */
#define ONU_GPE_VLAN_TREATMENT_TABLE_SIZE 1024
/** Table entry size */
#define ONU_GPE_VLAN_TREATMENT_TABLE_ENTRY_SIZE 64

/** Table identifier */
#define ONU_GPE_PMAPPER_TABLE_ID (GPE_TABLE_PE_MIN_ID + 2)
/** HW coprocessor identifier */
#define ONU_GPE_PMAPPER_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_PMAPPER_TABLE_SIZE 32
/** Table entry size */
#define ONU_GPE_PMAPPER_TABLE_ENTRY_SIZE 96

/** Table identifier */
#define ONU_GPE_SHORT_FWD_HASH_TABLE_ID ((ONU_GPE_COP_FWD << GPE_TABLE_COP_OFFSET) | 1)
/** HW coprocessor identifier */
#define ONU_GPE_SHORT_FWD_HASH_TABLE_COP_ID ONU_GPE_COP_FWD
/** Table size */
#define ONU_GPE_SHORT_FWD_HASH_TABLE_SIZE 1024
/** Table entry size */
#define ONU_GPE_SHORT_FWD_HASH_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_SHORT_FWD_TABLE_MAC_ID ((ONU_GPE_COP_FWD << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_SHORT_FWD_TABLE_MAC_COP_ID ONU_GPE_COP_FWD
/** Table size */
#define ONU_GPE_SHORT_FWD_TABLE_MAC_SIZE 1024
/** Table entry size */
#define ONU_GPE_SHORT_FWD_TABLE_MAC_ENTRY_SIZE 128

/** Table identifier */
#define ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID ((ONU_GPE_COP_FWD << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_SHORT_FWD_TABLE_MAC_MC_COP_ID ONU_GPE_COP_FWD
/** Table size */
#define ONU_GPE_SHORT_FWD_TABLE_MAC_MC_SIZE 0
/** Table entry size */
#define ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ENTRY_SIZE 128

/** Table identifier */
#define ONU_GPE_SHORT_FWD_TABLE_IPV4_ID ((ONU_GPE_COP_FWD << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_SHORT_FWD_TABLE_IPV4_COP_ID ONU_GPE_COP_FWD
/** Table size */
#define ONU_GPE_SHORT_FWD_TABLE_IPV4_SIZE 0
/** Table entry size */
#define ONU_GPE_SHORT_FWD_TABLE_IPV4_ENTRY_SIZE 128

/** Table identifier */
#define ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID ((ONU_GPE_COP_FWD << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_COP_ID ONU_GPE_COP_FWD
/** Table size */
#define ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_SIZE 0
/** Table entry size */
#define ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ENTRY_SIZE 128

/** Table identifier */
#define ONU_GPE_LONG_FWD_HASH_TABLE_ID ((ONU_GPE_COP_MSF << GPE_TABLE_COP_OFFSET) | 1)
/** HW coprocessor identifier */
#define ONU_GPE_LONG_FWD_HASH_TABLE_COP_ID ONU_GPE_COP_MSF
/** Table size */
#define ONU_GPE_LONG_FWD_HASH_TABLE_SIZE 1024
/** Table entry size */
#define ONU_GPE_LONG_FWD_HASH_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_LONG_FWD_TABLE_IPV6_ID ((ONU_GPE_COP_MSF << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_LONG_FWD_TABLE_IPV6_COP_ID ONU_GPE_COP_MSF
/** Table size */
#define ONU_GPE_LONG_FWD_TABLE_IPV6_SIZE 128
/** Table entry size */
#define ONU_GPE_LONG_FWD_TABLE_IPV6_ENTRY_SIZE 256

/** Table identifier */
#define ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID ((ONU_GPE_COP_MSF << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_LONG_FWD_TABLE_IPV6_MC_COP_ID ONU_GPE_COP_MSF
/** Table size */
#define ONU_GPE_LONG_FWD_TABLE_IPV6_MC_SIZE 0
/** Table entry size */
#define ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ENTRY_SIZE 256

/** Table identifier */
#define ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID ((ONU_GPE_COP_MSF << GPE_TABLE_COP_OFFSET) | 3)
/** HW coprocessor identifier */
#define ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_COP_ID ONU_GPE_COP_MSF
/** Table size */
#define ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_SIZE 512
/** Table entry size */
#define ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ENTRY_SIZE 64

/** Table identifier */
#define ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID ((ONU_GPE_COP_MSF << GPE_TABLE_COP_OFFSET) | 4)
/** HW coprocessor identifier */
#define ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_COP_ID ONU_GPE_COP_MSF
/** Table size */
#define ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_SIZE 128
/** Table entry size */
#define ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ENTRY_SIZE 256

/** Table identifier */
#define ONU_GPE_LEARNING_LIMITATION_TABLE_ID ((ONU_GPE_COP_FWD << GPE_TABLE_COP_OFFSET) | 3)
/** HW coprocessor identifier */
#define ONU_GPE_LEARNING_LIMITATION_TABLE_COP_ID ONU_GPE_COP_FWD
/** Table size */
#define ONU_GPE_LEARNING_LIMITATION_TABLE_SIZE 128
/** Table entry size */
#define ONU_GPE_LEARNING_LIMITATION_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_LAN_PORT_TABLE_ID (GPE_TABLE_PE_MIN_ID + 3)
/** HW coprocessor identifier */
#define ONU_GPE_LAN_PORT_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_LAN_PORT_TABLE_SIZE 8
/** Table entry size */
#define ONU_GPE_LAN_PORT_TABLE_ENTRY_SIZE 128

/** Table identifier */
#define ONU_GPE_PCP_DECODING_TABLE_ID (GPE_TABLE_PE_MIN_ID + 5)
/** HW coprocessor identifier */
#define ONU_GPE_PCP_DECODING_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_PCP_DECODING_TABLE_SIZE 32
/** Table entry size */
#define ONU_GPE_PCP_DECODING_TABLE_ENTRY_SIZE 8

/** Table identifier */
#define ONU_GPE_DSCP_DECODING_TABLE_ID (GPE_TABLE_PE_MIN_ID + 6)
/** HW coprocessor identifier */
#define ONU_GPE_DSCP_DECODING_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_DSCP_DECODING_TABLE_SIZE 512
/** Table entry size */
#define ONU_GPE_DSCP_DECODING_TABLE_ENTRY_SIZE 8

/** Table identifier */
#define ONU_GPE_PCP_ENCODING_TABLE_ID (GPE_TABLE_PE_MIN_ID + 7)
/** HW coprocessor identifier */
#define ONU_GPE_PCP_ENCODING_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_PCP_ENCODING_TABLE_SIZE 64
/** Table entry size */
#define ONU_GPE_PCP_ENCODING_TABLE_ENTRY_SIZE 8

/** Table identifier */
#define ONU_GPE_DSCP_ENCODING_TABLE_ID (GPE_TABLE_PE_MIN_ID + 8)
/** HW coprocessor identifier */
#define ONU_GPE_DSCP_ENCODING_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_DSCP_ENCODING_TABLE_SIZE 32
/** Table entry size */
#define ONU_GPE_DSCP_ENCODING_TABLE_ENTRY_SIZE 8

/** Table identifier */
#define ONU_GPE_EXCEPTION_TABLE_ID (GPE_TABLE_PE_MIN_ID + 14)
/** HW coprocessor identifier */
#define ONU_GPE_EXCEPTION_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_EXCEPTION_TABLE_SIZE 8
/** Table entry size */
#define ONU_GPE_EXCEPTION_TABLE_ENTRY_SIZE 64

/** Table identifier */
#define ONU_GPE_REDIRECTION_TABLE_ID (GPE_TABLE_PE_MIN_ID + 9)
/** HW coprocessor identifier */
#define ONU_GPE_REDIRECTION_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_REDIRECTION_TABLE_SIZE 32
/** Table entry size */
#define ONU_GPE_REDIRECTION_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_MAC_FILTER_TABLE_ID ((ONU_GPE_COP_TBL << GPE_TABLE_COP_OFFSET) | 2)
/** HW coprocessor identifier */
#define ONU_GPE_MAC_FILTER_TABLE_COP_ID ONU_GPE_COP_TBL
/** Table size */
#define ONU_GPE_MAC_FILTER_TABLE_SIZE 256
/** Table entry size */
#define ONU_GPE_MAC_FILTER_TABLE_ENTRY_SIZE 64

/** Table identifier */
#define ONU_GPE_ACL_FILTER_TABLE_ID (GPE_TABLE_PE_MIN_ID + 11)
/** HW coprocessor identifier */
#define ONU_GPE_ACL_FILTER_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_ACL_FILTER_TABLE_SIZE 32
/** Table entry size */
#define ONU_GPE_ACL_FILTER_TABLE_ENTRY_SIZE 256

/** Table identifier */
#define ONU_GPE_ACL_FILTER_TABLE_2_ID ((ONU_GPE_COP_FID << GPE_TABLE_COP_OFFSET) | 1)
/** HW coprocessor identifier */
#define ONU_GPE_ACL_FILTER_TABLE_2_COP_ID ONU_GPE_COP_FID
/** Table size */
#define ONU_GPE_ACL_FILTER_TABLE_2_SIZE 32
/** Table entry size */
#define ONU_GPE_ACL_FILTER_TABLE_2_ENTRY_SIZE 256

/** Table identifier */
#define ONU_GPE_BRIDGE_TABLE_ID (GPE_TABLE_PE_MIN_ID + 12)
/** HW coprocessor identifier */
#define ONU_GPE_BRIDGE_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_BRIDGE_TABLE_SIZE 8
/** Table entry size */
#define ONU_GPE_BRIDGE_TABLE_ENTRY_SIZE 256

/** Table identifier */
#define ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ID (GPE_TABLE_PE_MIN_ID + 15)
/** HW coprocessor identifier */
#define ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_SIZE 8
/** Table entry size */
#define ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ENTRY_SIZE 16

/** Table identifier */
#define ONU_GPE_ETHERTYPE_FILTER_TABLE_ID ((ONU_GPE_COP_TAG << GPE_TABLE_COP_OFFSET) | 3)
/** HW coprocessor identifier */
#define ONU_GPE_ETHERTYPE_FILTER_TABLE_COP_ID ONU_GPE_COP_TAG
/** Table size */
#define ONU_GPE_ETHERTYPE_FILTER_TABLE_SIZE 64
/** Table entry size */
#define ONU_GPE_ETHERTYPE_FILTER_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_ENQUEUE_TABLE_ID (GPE_TABLE_PE_MIN_ID + 4)
/** HW coprocessor identifier */
#define ONU_GPE_ENQUEUE_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_ENQUEUE_TABLE_SIZE 8
/** Table entry size */
#define ONU_GPE_ENQUEUE_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_COUNTER_TABLE_ID ((ONU_GPE_COP_TAG << GPE_TABLE_COP_OFFSET) | 4)
/** HW coprocessor identifier */
#define ONU_GPE_COUNTER_TABLE_COP_ID ONU_GPE_COP_TAG
/** Table size */
#define ONU_GPE_COUNTER_TABLE_SIZE 704
/** Table entry size */
#define ONU_GPE_COUNTER_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_STATUS_TABLE_ID (GPE_TABLE_PE_MIN_ID + 13)
/** HW coprocessor identifier */
#define ONU_GPE_STATUS_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_STATUS_TABLE_SIZE 25
/** Table entry size */
#define ONU_GPE_STATUS_TABLE_ENTRY_SIZE 32

/** Table identifier */
#define ONU_GPE_CONSTANTS_TABLE_ID (GPE_TABLE_PE_MIN_ID + 0)
/** HW coprocessor identifier */
#define ONU_GPE_CONSTANTS_TABLE_COP_ID ONU_GPE_COP_NONE
/** Table size */
#define ONU_GPE_CONSTANTS_TABLE_SIZE 18
/** Table entry size */
#define ONU_GPE_CONSTANTS_TABLE_ENTRY_SIZE 32

#ifndef SWIG
static inline uint32_t a2x_table_id(uint32_t table_id)
{
	switch (table_id) {
		default:
			return table_id;
	}
}
#endif

/** @} */

/** @} */

#endif
