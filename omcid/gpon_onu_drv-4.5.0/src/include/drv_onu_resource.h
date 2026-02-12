/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_resource.h
   This header file holds the definition of global hardwrae and software
   resources.
*/
#ifndef _drv_onu_resource_h
#define _drv_onu_resource_h

#include "drv_onu_default.h"

/** \addtogroup ONU_MAPI_REFERENCE
@{
*/

/** \defgroup ONU_RESOURCE Hardware and Software Resources
    This chapter defines values that are related to the FALCON hardware and
    software.
@{
*/

/**
   This file holds the definitions that are provided to reflect the available
   resources and other limit values that are related to the implementation.
   \remark Changing of any of these values will lead to system malfunction if
           the hardware does not support the assigned value(s)!
*/

/** Device identification for PSB98010 */
#define ONU_DEVICE_PSB98010 10
/** Device identification for PSB98020 */
#define ONU_DEVICE_PSB98020 20
/** Device identification for PSB98030 */
#define ONU_DEVICE_PSB98030 30

/** Maximum value to be used as GEM port ID + 1 */
#define ONU_GPE_MAX_GEM_PORT_ID           4096

/** Maximum value to be used as Allocation ID */
#define ONU_GPE_MAX_ALLOCATION_ID         4096

/** Number of MAC table entries */
#define ONU_GPE_MAX_MAC_TABLE_ENTRIES     1024

/** Depth of the receive PLOAM message FIFOs
    (limited by the GTC hardware). Do not change. */
#define ONU_GTC_MAX_DS_PLOAM_FIFO        8
/** Depth of the transmit PLOAM message FIFOs
    (limited by the GTC hardware). Do not change. */
#define ONU_GTC_MAX_US_PLOAM_FIFO        8

/** Maximum GEM payload size that is supported by hardware.
    The value is given in number of bytes (12-bit value), not including the
    5-byte GEM header (limited by the GTC hardware). Do not change. */
#define ONU_GTC_MAX_GEM_PAYLOAD_SIZE      4095
/** Minimum GEM payload size that is supported by hardware.
    The value is given in number of bytes, not including the 5-byte GEM header
    (limited by the GTC hardware). Do not change. */
#define ONU_GTC_MIN_GEM_PAYLOAD_SIZE         1

/** Maximum Ethernet frame size that is supported by hardware.
    The value is given in number of bytes.
    9990 byte is the hardware limit of the on-chip PHYs.
    A smaller value (such as 1518) may be defined instead. */
#ifndef ONU_GPE_MAX_ETHERNET_FRAME_LENGTH
/**
 * FIXME: with the value 9990 the structures gpe_eth_rcv and
   gpe_eth_send get too big for using in ioctl interface definition
   (macros _IOW and _IOWR)
 */
/* #define ONU_GPE_MAX_ETHERNET_FRAME_LENGTH 9990 */
#define ONU_GPE_MAX_ETHERNET_FRAME_LENGTH 2047
#endif
/** Minimum Ethernet frame size that is supported by hardware.
    The value is given in number of bytes. */
#define ONU_GPE_MIN_ETHERNET_FRAME_LENGTH   64

/** Maximum OMCI frame size */
#define ONU_GPE_MAX_OMCI_FRAME_LENGTH 1980

/** Maximum IP frame size */
#ifndef ONU_GPE_MAX_IP_FRAME_LENGTH
#define ONU_GPE_MAX_IP_FRAME_LENGTH GPON_DEFAULT_MAX_IP_FRAME_LENGTH
#endif

/** Maximum MPLS frame size */
#ifndef ONU_GPE_MAX_MPLS_FRAME_LENGTH
#define ONU_GPE_MAX_MPLS_FRAME_LENGTH GPON_DEFAULT_MAX_MPLS_FRAME_LENGTH
#endif

/** Smallest data rate limit that can be assigned to a shaper
    The value is given in bit/s (limited by the GPE hardware). Do not change. */
#define ONU_GPE_MIN_SHAPER_RATE           5000

/** Largest data rate limit that can be assigned to a shaper
    The value is given in bit/s (limited by the GPE hardware). Do not change. */
#define ONU_GPE_MAX_SHAPER_RATE     1000000000

/** Token bucket unit used to configure the shaper rate
    - 0b00:   1 byte
    - 0b01:   8 byte
    - 0b10:  64 byte
    - 0b11: 256 byte */
#ifndef ONU_GPE_TOKEN_BUCKET_UNIT
#define ONU_GPE_TOKEN_BUCKET_UNIT  0
#endif

/** Maximum VLAN filter table size (number of possible entries) */
#ifndef ONU_GPE_VLAN_FILTER_TABLE_SIZE
#define ONU_GPE_VLAN_FILTER_TABLE_SIZE 42
#endif

/** Maximum extended VLAN filter table size (number of possible entries) */
#ifndef ONU_GPE_EXTENDED_VLAN_FILTER_TABLE_SIZE
#define ONU_GPE_EXTENDED_VLAN_FILTER_TABLE_SIZE 42
#endif

/** Maximum number of bridges */
#ifndef ONU_GPE_MAX_BRIDGES
#define ONU_GPE_MAX_BRIDGES 8
#endif

/** Number of available bridge ports */
#define ONU_GPE_MAX_BRIDGE_PORT 126

/** Maximum number of ingress queues */
#ifndef ONU_GPE_MAX_INGRESS_QUEUES
#define ONU_GPE_MAX_INGRESS_QUEUES 9
#endif

/** Maximum number of egress queues,
    the queues are numbered 0 to ONU_GPE_MAX_EGRESS_QUEUES - 1 */
#ifndef ONU_GPE_MAX_EGRESS_QUEUES
#define ONU_GPE_MAX_EGRESS_QUEUES 256
#endif

/** Number of GEM Port ID based Performance counters in TMU,
    shall be set to 128 or ONU_MAX_GEM_PORT, whatever is smaller */
#ifndef ONU_GPE_TMU_GEM_COUNTERS
#define ONU_GPE_TMU_GEM_COUNTERS 128
#endif

/** Maximum number of T-CONTs */
#define ONU_GPE_MAX_TCONT                   32

/** Maximum number of GEM ports that can be assigned to a T-CONT */
#define ONU_GPE_MAX_TCONT_PORT              64

/** Maximum number of queues that can be used
    This does not include the special "discard queue" (index = 255) */
#define ONU_GPE_MAX_QUEUE                  255

/** Number of available scheduler blocks */
#define ONU_GPE_MAX_SCHEDULER              128

/** Maximum scheduling hierarchy level */
#define ONU_GPE_MAX_SCHEDULER_LEVEL        2

/** Maximum number of VLANs that can be handled concurrently. */
#define ONU_GPE_MAX_VLANS                   64

/** Maximum number of Ethertype filters that can be handled concurrently. */
#define ONU_GPE_MAX_ETHFILT                 32

/** Half duplex capability */
#define ONU_GPE_HALF_DUPLEX_CAPABILITY       0

/* TMU egress port numbers */
/** Minimum egress port number for ANI-side */
#define ONU_GPE_MIN_ANI_TMU_EGRESS_PORT      0
/** Maximum egress port number for ANI-side */
#define ONU_GPE_MAX_ANI_TMU_EGRESS_PORT     63
/** OMCI egress port number */
#define ONU_GPE_OMCI_EGRESS_PORT            63
/** UNI egress port numbers */
#define ONU_GPE_UNI0_EGRESS_PORT_NUMBER     64
#define ONU_GPE_UNI1_EGRESS_PORT_NUMBER     65
#define ONU_GPE_UNI2_EGRESS_PORT_NUMBER     66
#define ONU_GPE_UNI3_EGRESS_PORT_NUMBER     67
/** CPU egress port numbers */
#define ONU_GPE_CPU0_EGRESS_PORT_NUMBER     68
#define ONU_GPE_CPU1_EGRESS_PORT_NUMBER     69
#define ONU_GPE_CPU2_EGRESS_PORT_NUMBER     70
#define ONU_GPE_CPU3_EGRESS_PORT_NUMBER     71

/** Number of token bucket meter instances */
#define ONU_GPE_MAX_TBM                    512

/** Number of traffic shaper instances */
#define ONU_GPE_MAX_SHAPER                 256

/** Number of input-only GPIO pins
   \todo Define the number of GPIO input ports.
   ### The value is t.b.d. The port number assignment is also t.b.d. */
#define ONU_GPIO_MAX_IN                      0

/** Number of output-only GPIO pins
   ### The value is t.b.d. The port number assignment is also t.b.d.
   \todo Define the number of GPIO output ports. */
#define ONU_GPIO_MAX_OUT                     0

/** Number of bi-directional GPIO pins
   \todo Define the number of GPIO input/output ports.
   ### The value is t.b.d. The port number assignment is also t.b.d. */
#define ONU_GPIO_MAX_INOUT                   0

/** Ingress Queue Manager (IQM) internal clock rate (in MHz) */
#define ONU_GPE_IQM_CLOCK_RATE             312.5

/** GTC bandwidth map trace buffer depth */
#define ONU_GTC_TRACE_BUFFER_SIZE          256

/** Buffer segment size, in number of bytes */
#define ONU_GPE_BUFFER_SEGMENT_SIZE 64

/** Number of Shared Segment Buffer segments */
#ifndef ONU_GPE_BUFFER_SEGMENTS
#define ONU_GPE_BUFFER_SEGMENTS 18432
#endif

/** Number of Egress Buffer PDUs */
#ifndef ONU_GPE_EGRESS_BUFFER_PDUS
#define ONU_GPE_EGRESS_BUFFER_PDUS 9216
#endif

/** Bridge port index used to drop packets */
#define ONU_GPE_NULL_BRIDGE_PORT 126

/** Egress queue index used to drop packets */
#define ONU_GPE_NULL_QUEUE 255

/* Ethernet and GPON port type definitions (see ITU-T G.984.4, Table 9.1.5-1)
    Other interface types are not supported on-chip. */

/* Ethernet port type values defined by ITU,
    the assignment must not be modified. */

/** Ethernet port type is 10BASE-T          */
#define ONU_EIM_PORT_TYPE_10_BASE_T           22
/** Ethernet port type is 100BASE-T         */
#define ONU_EIM_PORT_TYPE_100_BASE_T          23
/** Ethernet port type is 1000BASE-T        */
#define ONU_EIM_PORT_TYPE_1000_BASE_T         34
/** Ethernet port type is 10/100BASE-T      */
#define ONU_EIM_PORT_TYPE_10_100_BASE_T       24
/** Ethernet port type is 10/100/1000BASE-T */
#define ONU_EIM_PORT_TYPE_10_100_1000_BASE_T  47

/** Port type is POTS */
#define ONU_EIM_PORT_TYPE_POTS                32
/** Port type is GPON (downstream 2.488 Gbit/s, upstream 1.244 Gbit/s) */
#define ONU_EIM_PORT_TYPE_GPON24881244       248

/* Vendor-specific values (within the range from 192 to 223),
    the assignment may be changed within the allowed range. */

/** Port type is GMII, MAC mode */
#define ONU_EIM_PORT_TYPE_GMII_MAC           192
/** Port type is GMII, PHY mode */
#define ONU_EIM_PORT_TYPE_GMII_PHY           193
/** Port type is RGMII, MAC mode */
#define ONU_EIM_PORT_TYPE_RGMII_MAC          194
/** Port type is RGMII, PHY mode */
#define ONU_EIM_PORT_TYPE_RGMII_PHY          195
/** Port type is MII, MAC mode */
#define ONU_EIM_PORT_TYPE_MII_MAC            196
/** Port type is MII, PHY mode */
#define ONU_EIM_PORT_TYPE_MII_PHY            197
/** Port type is SMII */
#define ONU_EIM_PORT_TYPE_SMII               198
/** Port type is SGMII at 1.0 Gbit/s */
#define ONU_EIM_PORT_TYPE_SGMII_1_0          199
/** Port type is SGMII at 2.5 Gbit/s */
#define ONU_EIM_PORT_TYPE_SGMII_2_5          200

/* Ethernet port mode values defined by ITU,
    the assignment must not be modified. */

/** Ethernet port mode is automatic rate, automatic duplex */
#define ONU_EIM_PORT_MODE_AUTO_RATE_AUTO_DUPLEX  0x00
/** Ethernet port mode is automatic rate, full duplex */
#define ONU_EIM_PORT_MODE_AUTO_RATE_FULL_DUPLEX  0x04
/** Ethernet port mode is  automatic rate, half duplex */
#define ONU_EIM_PORT_MODE_AUTO_RATE_HALF_DUPLEX  0x14

/** Ethernet port mode is 10BASE-T, full duplex */
#define ONU_EIM_PORT_MODE_10M_FULL_DUPLEX        0x01
/** Ethernet port mode is 100BASE-T, full duplex */
#define ONU_EIM_PORT_MODE_100M_FULL_DUPLEX       0x02
/** Ethernet port mode is 1000BASE-T, full duplex */
#define ONU_EIM_PORT_MODE_1000M_FULL_DUPLEX      0x03

/** Ethernet port mode is 10BASE-T, half duplex */
#define ONU_EIM_PORT_MODE_10M_HALF_DUPLEX        0x11
/** Ethernet port mode is 100BASE-T, half duplex */
#define ONU_EIM_PORT_MODE_100M_HALF_DUPLEX       0x12
/** Ethernet port mode is 1000BASE-T, half duplex */
#define ONU_EIM_PORT_MODE_1000M_HALF_DUPLEX      0x13

/** Ethernet port mode is 100BASE-T, automatic duplex */
#define ONU_EIM_PORT_MODE_100M_AUTO_DUPLEX       0x30
/** Ethernet port mode is 1000BASE-T, automatic duplex */
#define ONU_EIM_PORT_MODE_1000M_AUTO_DUPLEX      0x20

/** Ethernet PHY address of UNI port 0 */
#define ONU_EIM_PHY_ADDR_0 0x0
/** Ethernet PHY address of UNI port 1 */
#define ONU_EIM_PHY_ADDR_1 0x1
/** Ethernet PHY address of UNI port 2 */
#define ONU_EIM_PHY_ADDR_2 0x2
/** Ethernet PHY address of UNI port 3 */
#define ONU_EIM_PHY_ADDR_3 0x3

/* Counter interrupt times */
/** Fast counter readout time interval in ms */
#define ONU_COUNTER_FAST_INTERVAL      1000
/** Medium fast counter readout time interval in ms */
#define ONU_COUNTER_MEDUIM_INTERVAL   15000
/** Slow counter readout time interval in ms */
#define ONU_COUNTER_SLOW_INTERVAL     60000

/** Maximum number of egress ports,
    the egress ports are numbered 0 to ONU_GPE_MAX_EGRESS_PORT - 1 */
#ifndef ONU_GPE_MAX_EGRESS_PORT
#define ONU_GPE_MAX_EGRESS_PORT 72
#endif

/*! @} */

/* end ONU_RESOURCE */

/*! @} */

#endif
