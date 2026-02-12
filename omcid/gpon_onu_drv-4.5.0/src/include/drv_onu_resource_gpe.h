/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_resource_gpe.h
   This header file holds the definitions of hardware and software resources
   that are related to the GPON Packet Engine (GPE).
*/
#ifndef _drv_onu_resource_gpe_h
#define _drv_onu_resource_gpe_h

#include "drv_onu_std_defs.h"

/** \addtogroup ONU_MAPI_REFERENCE
@{
*/

/** \addtogroup ONU_RESOURCE
@{
*/

/**
   This file holds the definitions that are provided to reflect the available
   resources and other limit values that are related to the implementation.
   \remark Changing of any of these values will lead to system malfunction if
           the hardware does not support the assigned value(s)!
*/

/* ------------- replace all references to TBD by real values --------------- */
#define TBD 0
/* -------------------------------------------------------------------------- */

/*  Shared Segment Buffer (SSB) properties
*/
/** Start offset for Logical Link Table (LLT) value */
#ifndef ONU_GPE_LLT_MIN
#define ONU_GPE_LLT_MIN  0
#endif
/** Maximum Logical Link Table (LLT) value */
#define ONU_GPE_LLT_MAX  0x4800
#define RCNT_INIT        0x1

/** Logical Link Table NIL pointer */
#define ONU_GPE_LLT_NIL   0x7FFF

/** Maximum Number of physically available Processing Elements */
#define ONU_GPE_NUMBER_OF_PE_MAX		6

/* Selection of all PE's */
#define ONU_GPE_ALL_PE_MASK 			0x3F

/** Total number of threads per Processing Element*/
#ifndef ONU_GPE_NUMBER_OF_PE_THREADS
#define ONU_GPE_NUMBER_OF_PE_THREADS	8
#endif

/** Total number of Processing Element Threads */
#ifndef ONU_GPE_NUMBER_OF_THREADS
#define ONU_GPE_NUMBER_OF_THREADS		56
#endif

/** Size of the PE host interface buffer, in 32-bit units */
#define ONU_GPE_PE_BUFFER_SIZE			8

/** Size of the PE message buffer, in 32-bit units
	16 units = 64 byte = 1 SSB buffer segment */
#define ONU_GPE_PE_MESSAGE_BUFFER_SIZE	16

/** Physical limits of the SCE firmware code and data memory
	for each Processing Element, given in number of bytes */

/*	Code memory: 2.0 K of 64-bit instructions = 16 Kbyte */
#define ONU_GPE_MAX_FW_CODE_SIZE		0x4000
/*	Data memory: 1.5 K of 64-bit data words   = 12 Kbyte */
#define ONU_GPE_MAX_FW_DATA_SIZE		0x3000

#define ONU_GPE_BASE_ADDRESS			0x400000
#define ONU_GPE_UNIT_OFFSET				TBD

/*  SCE maximum table sizes and table IDs
    The size definitions may be changed to a value smaller than the given
    maximum.
    The table count provided the information if a table is implemented more
    than once in hardware (multiple hardware instances that shall hold identical
    information).

    \remark The IDs and count values must not be changed!
*/

/** GPE tables are either part of the HW accelerators or part of the FW data
    memory.
    Each HW table is a single instance while the software tables provide one
    instance per Processing Element
*/
#define ONU_GPE_HW_TABLE		1
#define ONU_GPE_FW_TABLE		ONU_GPE_NUMBER_OF_PE_MAX

/** Number of supported COPs */
#define ONU_GPE_NUMBER_OF_COP		8
#define ONU_GPE_NUMBER_OF_COPWMC	6

/* Attention:
 * ============================================================
 * All define values concerning SCE/COP tables are reviewed and
 * updated based on SCE_Tables_100920.xls by schallem on 28.09.2010
 * Please update this comment if you change values !!!!!
 */

/** Hardware coprocessor identification codes mapped to coprocessor names
    \remark Within each coprocessor, table IDs are numbered ascending
            from 1 to 7.
	    Multiple logical tables can share the same physical table and thus
	    can have the same table ID.
	    Table ID = 0 is used for table configuration access.
*/
#define ONU_GPE_COP_NONE        255     /* by firmware, no hardware coprocessor
                                           involved */
#define ONU_GPE_COP_FID          0
#define ONU_GPE_COP_FWD          1
#define ONU_GPE_COP_TAG          2
#define ONU_GPE_COP_TBL          3
#define ONU_GPE_COP_MSF          4
#define ONU_GPE_COP_EXT          5
#define ONU_GPE_COP_TBM         14
#define ONU_GPE_COP_LOOP        15	/* LOOP is a dummy coprocessor for
					   testing */

/** Hardware coprocessor error codes
    Incorrect access to one of the hardware coprocessors might result in an
    error. The coding is given by:  */
#define ONU_GPE_COP_ERR_INVALID_INDEX   1
#define ONU_GPE_COP_ERR_END_OF_TABLE    2
#define ONU_GPE_COP_ERR_OUT_OF_MEMORY   3
#define ONU_GPE_COP_ERR_ENTRY_EXISTS    4
#define ONU_GPE_COP_ERR_DISCARD_FRAME   5
#define ONU_GPE_COP_ERR_SOFT_ERROR_1    6
#define ONU_GPE_COP_ERR_SOFT_ERROR_2    7

/** Minimum PE table ID */
#define GPE_TABLE_PE_MIN_ID		64

/** Table COP field offset */
#define GPE_TABLE_COP_OFFSET		3

/** Maximum ID for FW table */
#define ONU_GPE_FW_TABLE_ID_MAX	 (ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ID - GPE_TABLE_PE_MIN_ID)

/** Check if the given table ID corresponds to the PE table */
#define GPE_IS_PE_TABLE(ID) \
	(ID >= GPE_TABLE_PE_MIN_ID)

#ifndef SWIG
/** Get table ID
   \param id Processor table identifier.
*/
static INLINE uint32_t GPE_TABLE_ID(uint32_t id)
{
	static const uint32_t id_mask = 0x00000007;
	static const uint32_t id_offset = 0;

	if (id >= GPE_TABLE_PE_MIN_ID)
		return id - GPE_TABLE_PE_MIN_ID;
	else
		return (id & id_mask) >> id_offset;
}

/** Get table module
   \param id Coprocessor table identifier.
*/
static INLINE uint32_t GPE_TABLE_COP(uint32_t id)
{
	static const uint32_t cop_mask = 0xfffffff8;

	if (id >= GPE_TABLE_PE_MIN_ID)
		return ONU_GPE_COP_NONE;
	else
		return (id & cop_mask) >> GPE_TABLE_COP_OFFSET;
}
#endif /* #ifndef SWIG*/

#include "drv_onu_resource_gpe_tables.h"

/** Hardware PE/COP table field definitions */
#define ONU_GPE_UNIINTOPT_BRIDGING 0 /* bridged forwarding */
#define	ONU_GPE_UNIINTOPT_PMAPPER 1 /* direct forwarding */

/* termination point type */
#define ONU_GPE_TPTYPE_UNI 0
#define ONU_GPE_TPTYPE_PMAPPER 2
#define ONU_GPE_TPTYPE_ITP 3

/* Forwarding method */
#define ONU_GPE_FWDMTHD_L2 0
#define ONU_GPE_FWDMTHD_MAC 1
#define ONU_GPE_FWDMTHD_VLAN 2
#define ONU_GPE_FWDMTHD_L3 3

/* GEM port type */
#define ONU_GPE_GEMPTYPE_UC 0 /* unicast */
#define ONU_GPE_GEMPTYPE_MC 1 /* multicast */

/* ANI interworking option */
#define ONU_GPE_ANIINTOPT_MACBRIDGE 1
#define ONU_GPE_ANIINTOPT_IP 3
#define ONU_GPE_ANIINTOPT_PMAPPER 5
#define ONU_GPE_ANIINTOPT_GEMMC 6

/* Hash table access key codes */
#define ONU_GPE_KEYCODE_L2 0
#define ONU_GPE_KEYCODE_ETH 1
#define ONU_GPE_KEYCODE_VLAN 2
#define ONU_GPE_KEYCODE_IPV4 3
#define ONU_GPE_KEYCODE_IPV6 4
#define ONU_GPE_KEYCODE_MPLS 5
#define ONU_GPE_KEYCODE_GPIX 6

/* Color marking mode */
#define ONU_GPE_MARKING_MODE_NONE      0
#define ONU_GPE_MARKING_MODE_INTERNAL  1
#define ONU_GPE_MARKING_MODE_DEI       2
#define ONU_GPE_MARKING_MODE_8P0D      3
#define ONU_GPE_MARKING_MODE_7P1D      4
#define ONU_GPE_MARKING_MODE_6P2D      5
#define ONU_GPE_MARKING_MODE_5P1D      6
#define ONU_GPE_MARKING_MODE_DSCP      7

/* LAN Port ingress queue numbering, other code points are forbidden */
/** Ingress queue of UNI port 0 */
#define ONU_GPE_INGRESS_QUEUE_LAN_0     0
/** Ingress queue of UNI port 1 */
#define ONU_GPE_INGRESS_QUEUE_LAN_1     1
/** Ingress queue of UNI port 2 */
#define ONU_GPE_INGRESS_QUEUE_LAN_2     2
/** Ingress queue of UNI port 3 */
#define ONU_GPE_INGRESS_QUEUE_LAN_3     3

/* CPU Port ingress queue numbers, other code points are forbidden */
/** Ingress queue of CPU for data in upstream direction (to the OLT) */
#define ONU_GPE_INGRESS_QUEUE_CPU_US    4
/** Ingress queue of CPU for data in downstream direction (to the LAN ports) */
#define ONU_GPE_INGRESS_QUEUE_CPU_DS    8

/* GEM Port ingress queue numbering, other code points are forbidden */
/** Ingress queue of ANI port, non-OMCI data, unicast */
#define ONU_GPE_INGRESS_QUEUE_GEM_UC    5
/** Ingress queue of ANI port, non-OMCI data, multicast */
#define ONU_GPE_INGRESS_QUEUE_GEM_MC    6
/** Ingress queue of ANI port, OMCI only */
#define ONU_GPE_INGRESS_QUEUE_OMCI      7

/** \todo */
#define ONU_GPE_ICTRLG_GEM_PORT_CONFIG_TABLE_ID 0xff

/** Multicast address table limit */
#define ONU_GPE_MC_ADDRESS_TABLE_SIZE 128

/** OMCI hardware resource assignment */
/** Egress queue used for high priority OMCI in downstream direction */
#define ONU_GPE_QUEUE_INDEX_OMCI_HI_DS      ONU_GPE_MAX_QUEUE - 2
/** Egress queue used for low priority OMCI in downstream direction */
#define ONU_GPE_QUEUE_INDEX_OMCI_LO_DS      ONU_GPE_MAX_QUEUE - 3
/** Egress queue used for high priority OMCI in upstream direction */
#define ONU_GPE_QUEUE_INDEX_OMCI_HI_US      ONU_GPE_MAX_QUEUE - 1
/** Egress queue used for low priority OMCI in upstream direction */
#define ONU_GPE_QUEUE_INDEX_OMCI_LO_US      ONU_GPE_MAX_QUEUE - 1
/** Default egress queue for mirroring */
#define ONU_GPE_DEFAULT_MIRROR_QUEUE        ONU_GPE_MAX_QUEUE - 3
/** Default egress queue for exceptions */
#define ONU_GPE_DEFAULT_EXCEPTION_QUEUE     ONU_GPE_MAX_QUEUE - 4
/** Scheduler used for all OMCI in upstream direction */
#define ONU_GPE_SCHEDULER_INDEX_OMCI_US     126
/** Scheduler used for exceptions */
#define ONU_GPE_SCHEDULER_INDEX_EXCEPTION   125
/** Scheduler used for TCONT's */
#define ONU_GPE_SCHEDULER_INDEX_TCONT       ONU_GPE_SCHEDULER_INDEX_EXCEPTION - ONU_GPE_MAX_TCONT

/** Hardware UNI port resource assignment */
#define ONU_GPE_MAX_UNI                       4

/** Maximum number of Egress CPU ports */
#define ONU_GPE_MAX_EGRESS_CPU_PORT           4

/** Virtual UNI port resource assignment */
#define ONU_GPE_MAX_VUNI                      4

/** Egress ports used for data to the software (Virtual UNI) */
#define ONU_GPE_EPN_VUNI0                    68
#define ONU_GPE_EPN_VUNI1                    69
#define ONU_GPE_EPN_VUNI2                    70
#define ONU_GPE_EPN_VUNI3                    71

/** Number of "traffic colors" that are supported by the TMU. */
#define ONU_GPE_QUEUE_MAX_COLOR               4

/** Maximum number of bridge ports per bridge*/
#define ONU_GPE_MAX_BRIDGE_PORT_PER_BRIDGE    16

/** Exception bit offset definition for Exception masking. */

/** All Ethernet packets */
#define ONU_GPE_EXCEPTION_OFFSET_ETH             0
/** Ethernet broadcast packets */
#define ONU_GPE_EXCEPTION_OFFSET_ETH_BC          1
/** Ethernet multicast packets */
#define ONU_GPE_EXCEPTION_OFFSET_ETH_MC          2
/** TCP packets */
#define ONU_GPE_EXCEPTION_OFFSET_TCP             3
/** UDP packets */
#define ONU_GPE_EXCEPTION_OFFSET_UDP             4
/** IPv4 packets */
#define ONU_GPE_EXCEPTION_OFFSET_IPV4            5
/** IPv6 packets */
#define ONU_GPE_EXCEPTION_OFFSET_IPV6            6
/** PPPoE packets with Ethertype 0x8864 */
#define ONU_GPE_EXCEPTION_OFFSET_PPPOE_8864      7
/** Type/Length-encapsulated packets (reserved) */
#define ONU_GPE_EXCEPTION_OFFSET_LEN             8
/** MPLS packets (reserved) */
#define ONU_GPE_EXCEPTION_OFFSET_MPLS            9
/** IPv4 broadcast packets */
#define ONU_GPE_EXCEPTION_OFFSET_IPV4_BC        10
/** IPv4 multicast packets */
#define ONU_GPE_EXCEPTION_OFFSET_IPV4_MC        11
/** IPv6 multicast packets */
#define ONU_GPE_EXCEPTION_OFFSET_IPV6_MC        12
/** PPPoE broadcast packets with Ethertype 0x8863 */
#define ONU_GPE_EXCEPTION_OFFSET_PPPOE_8863_BC  13
/** AppleTalk packets */
#define ONU_GPE_EXCEPTION_OFFSET_APPLETALK      14
/** IPX packets */
#define ONU_GPE_EXCEPTION_OFFSET_IPX            15
/** ARP packets */
#define ONU_GPE_EXCEPTION_OFFSET_ARP            16
/** RARP packets */
#define ONU_GPE_EXCEPTION_OFFSET_RARP           17
/** NetBEUI packets */
#define ONU_GPE_EXCEPTION_OFFSET_NETBEUI        18
/** BPDU packets */
#define ONU_GPE_EXCEPTION_OFFSET_BPDU           19
/** DHCP packets */
#define ONU_GPE_EXCEPTION_OFFSET_DHCP           20
/** Special Ethertype (reserved) */
#define ONU_GPE_EXCEPTION_OFFSET_SPECTAG        21
/** ICMP packets */
#define ONU_GPE_EXCEPTION_OFFSET_ICMP           22
/** IGMP or MLD control packets */
#define ONU_GPE_EXCEPTION_OFFSET_IGMP_MLD       23
/** CFM packets */
#define ONU_GPE_EXCEPTION_OFFSET_CFM            24
/** MAC control packets */
#define ONU_GPE_EXCEPTION_OFFSET_MAC_CTRL       25
/** PPPoE packets with Ethertype 0x8863 */
#define ONU_GPE_EXCEPTION_OFFSET_PPPOE_8863     26
/** OMCI packets (reserved) */
#define ONU_GPE_EXCEPTION_OFFSET_OMCI           27
/** Local MAC filtering */
#define ONU_GPE_EXCEPTION_OFFSET_LOCAL_MAC      28
/** Denial of Service packets */
#define ONU_GPE_EXCEPTION_OFFSET_DOS            29
/** Denial of Service packets */
#define ONU_GPE_EXCEPTION_OFFSET_DOS_LEARN      30
/** Parser warnings (reserved for debugging) */
#define ONU_GPE_EXCEPTION_OFFSET_PARSER         31

/** Exception profile number for UNI0*/
#define ONU_GPE_EXCEPTION_PROFILE_UNI0		0
/** Exception profile number for UNI1*/
#define ONU_GPE_EXCEPTION_PROFILE_UNI1		1
/** Exception profile number for UNI2*/
#define ONU_GPE_EXCEPTION_PROFILE_UNI2		2
/** Exception profile number for UNI3*/
#define ONU_GPE_EXCEPTION_PROFILE_UNI3		3
/** Exception profile number for all GEM ports in Upstream */
#define ONU_GPE_EXCEPTION_PROFILE_GEM_US	4
/** Exception profile number for all GEM ports in Downstream */
#define ONU_GPE_EXCEPTION_PROFILE_GEM_DS	5
/** Exception profile number for multicast GEM ports*/
#define ONU_GPE_EXCEPTION_PROFILE_MC_GEM	6
/** Exception profile number for broadcast GEM ports*/
#define ONU_GPE_EXCEPTION_PROFILE_BC_GEM	7


/** Constants table entries, default each 32 bit */
/** Constants table firmware enable entry*/
#define ONU_GPE_CONST_PACKET_ENABLE		0
/** Constants table default FID entry*/
#define ONU_GPE_CONST_DEFAULT_FID		1
/** Constants table default VID entry.
    Two 16 bit values, 47 32: nDefaultOuterVID, 
    63 48: nDefaultInnerVID*/
#define ONU_GPE_CONST_VID			2
/** Constants table default DSCP entry*/
#define ONU_GPE_CONST_DEFAULT_DSCP		3
/** Unused constant, just a placeholder */
#define ONU_GPE_CONST_UNUSED0			4
/** Constants table default FWD table size used for the aging process */
#define ONU_GPE_CONST_FWD_TABLESIZE		5
/** Constants table default HWORDFWD TABLESIZE entry.
    Two 16 bit values, 175 160: C,
		       191 176: D */
#define ONU_GPE_CONST_TPID_CD			6
/** Constants table default TPID A, B entry */
#define ONU_GPE_CONST_TPID_AB			7
/** Unused constant, just a placeholder */
#define ONU_GPE_CONST_UNUSED			8
/** Preload value for delay loop counter. 
    unit = 9 clock cycles (3 cycles of the HW thread) */
#define ONU_GPE_CONST_ADDED_LATENCY		9
/** Constants table default MIRROR QID entry*/
#define ONU_GPE_CONST_UNUSED1		10
/** MAC Address of Local CPU, used for LCT, Higher Part. 
    Bits [31:0]=MAC_DA[47:16] */
#define ONU_GPE_CONST_LOCALMAC_ADRH		11
/** MAC Address of Local CPU, used for LCT. Lower Part.
    Bits [31:16]=MAC_DA[15:0] */
#define ONU_GPE_CONST_LOCALMAC_ADRL		12
/** Constant to specify ANI side exception meter.
    Bits[0:8] - dual token bucket meter ID for ANI exception traffic for both
		the ANI ingress as well as the ANI egress, the upper 8 bits of
		this value are used to address one of up to 256 meter units,
		the LSB must be set to 0.
    Bit [9]   - enable bit for both ingress and egress dual token bucket meter
                selection for ANI exception traffic for both diretions the ANI
		ingress as weel as the ANI egress.*/
#define ONU_GPE_CONST_ANI_EXCEPTION_METER	13
#define ONU_GPE_ANI_EXCEPT_POLICER_THRESHOLD	14
#define ONU_GPE_UNI_EXCEPT_POLICER_THRESHOLD	15
#define ONU_GPE_IGMP_EXCEPT_POLICER_THRESHOLD	16
/** Constant to specify Meter mode. */
#define ONU_GPE_CONST_METER_L2_MODE		17

/** Maximum number of GPE constants */
#define ONU_GPE_CONST_MAX (ONU_GPE_CONST_METER_L2_MODE + 1)

/** Constants table entries, default values */

/** Default FID default value */
#define ONU_GPE_CONSTANT_VAL_DEFAULT_FID		0
/** VID default value */
#define ONU_GPE_CONSTANT_VAL_VID			0
/** Default DSCP default value */
#define ONU_GPE_CONSTANT_VAL_DEFAULT_DSCP		0
/** BYTE BREAK TICK default value */
#define ONU_GPE_CONSTANT_VAL_BYTE_BREAK_TICK	0
/** ADDED LATENCY default value */
#define ONU_GPE_CONSTANT_VAL_ADDED_LATENCY		0
/** Unused 0 constant default value */
#define ONU_GPE_CONSTANT_VAL_UNUSED0		0
/** MIRROR_QID default value */
#define ONU_GPE_CONSTANT_VAL_UNUSED1		0
/** Meter mode default value (use layer 3 by default). */
#define ONU_GPE_CONSTANT_VAL_METER_L2_MODE		0

/** status table FW version */
#define ONU_GPE_STATUS_VERS 24

/** Default FID mask setting for Outer VLAN*/
#define ONU_GPE_FID_OUTER_VID_MASK	1
/** Default FID mask setting for Outer PCP*/
#define ONU_GPE_FID_OUTER_PCP_MASK	0
/** Default FID mask setting for Inner VLAN*/
#define ONU_GPE_FID_INNER_VID_MASK	0
/** Default FID mask setting for Inner PCP*/
#define ONU_GPE_FID_INNER_PCP_MASK	0

/* safety margin define for GPONSW-869 */
#define ONU_GPE_SHORT_FWD_TABLE_SAFETY_MARGIN 100
/*! @} */

/* end ONU_RESOURCE */

/*! @} */
#endif
