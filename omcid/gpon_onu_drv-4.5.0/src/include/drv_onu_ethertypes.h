/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_ethertypes.h
*/
#ifndef _drv_onu_ethertypes_h
#define _drv_onu_ethertypes_h

#include "drv_onu_default.h"

/** \addtogroup GPON_IMPLEMENTATION
@{
*/

/** \addtogroup GPON_RESOURCE
@{
*/

/**
   This file holds the definitions of Ethertype values that are used for
   filtering.
*/

/** IPv4 */
#define ONU_ETHERTYPE_IPV4         0x0800
/** IPv6 */
#define ONU_ETHERTYPE_IPV6         0x86DD
/** Special Tag */
#define ONU_ETHERTYPE_IFX          0x88C3
/* There is no specific Lantiq Ethertype available, we re-use Infineon's */
#define ONU_ETHERTYPE_LTQ          0x88C3
/** MPLS */
#define ONU_ETHERTYPE_MPLS_UC      0x8847
#define ONU_ETHERTYPE_MPLS_MC      0x8848
/** VLAN */
#define ONU_ETHERTYPE_CVLAN        0x8100
#define ONU_ETHERTYPE_SVLAN        0x88A8
/** IEEE 1588 PTP */
#define ONU_ETHERTYPE_IEEE1588     0x88F7
/** PPPoE */
#define ONU_ETHERTYPE_PPPOE_DISC   0x8863
#define ONU_ETHERTYPE_PPPOE_SESS   0x8864
/** OUI extended Ethertype */
#define ONU_ETHERTYPE_OUI          0x88B7
/** ARP, RARP */
#define ONU_ETHERTYPE_ARP          0x0806
#define ONU_ETHERTYPE_RARP         0x8035
/** AppleTalk */
#define ONU_ETHERTYPE_APPLETALK_1  0x809B
#define ONU_ETHERTYPE_APPLETALK_2  0x80F3
/** IPX */
#define ONU_ETHERTYPE_IPX          0x8137
/** Wake on LAN */
#define ONU_ETHERTYPE_WOL          0x0842
/** MAC control frames */
#define ONU_ETHERTYPE_MAC_CONTROL  0x8808
/** Homeplug */
#define ONU_ETHERTYPE_HOMEPLUG     0x88E1
/** Q-in-Q */
#define ONU_ETHERTYPE_QINQ         0x9100
/** CFM */
#define ONU_ETHERTYPE_CFM          0x8902

/*! @} */
/* end GPON_RESOURCE */

/*! @} */

#endif
