/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_dot1p_rate_limiter_h
#define _omci_dot1p_rate_limiter_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_DOT1P_RATE_LIMITER IEEE 802.1p Rate Limiter Managed Entity

    This Managed Entity allows rate limits to be defined for various types of
    upstream traffic that are processed by IEEE 802.1 bridges or related
    structures.
    An instance of this Managed Entity may be linked to an instance of the MAC
    bridge service profile, an 802.1p mapper, or other Managed Entities.

    @{
*/

/** This structure holds the attributes of the IEEE 802.1p Rate Limiter
    Managed Entity.
*/
struct omci_me_dot1p_rate_limiter {
	/** Parent Managed Entity Pointer

	    This attribute points to an instance of a Managed Entity.
	    The type of Managed Entity is determined by the Termination Point
	    Type attribute.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t parent_me_ptr;

	/** Termination Point Type

	    This attribute identifies the type of termination point that is
	    associated with this rate limiter. Valid values are:
	    - 0x00 MAC bridge configuration data
	    - 0x01 IEEE 802.1p mapper service profile

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t tp_type;

	/** Upstream Unicast Flood Rate Pointer

	    This attribute points to an instance of the Traffic Descriptor that
	    specifies the maximum rate of upstream unicast packets whose
	    destination address is unknown to the bridge.
	    A null pointer specifies that no administrative limit is to be
	    imposed.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t us_unicast_flood_rate_ptr;

	/** Upstream Broadcast Rate Pointer

	    This attribute points to an instance of the Traffic Descriptor that
	    specifies the maximum rate of upstream broadcast packets.
	    A null pointer specifies that no administrative limit is to be
	    imposed.

	    This attribute is readable and writable by the OLT.
	    */
	uint16_t us_broadcast_rate_ptr;

	/** Upstream Multicast Payload Rate Pointer

	    This attribute points to an instance of the Traffic Descriptor that
	    specifies the maximum rate of upstream multicast payload packets.
	    A null pointer specifies that no administrative limit is to be
	    imposed.

	    This attribute is readable and writable by the OLT.
	    */
	uint16_t us_multicast_payload_rate_ptr;

} __PACKED__;

/** This enumerator holds the attribute numbers of the IEEE 802.1p Rate Limiter
    Managed Entity.
*/
enum {
	omci_me_dot1p_rate_limiter_parent_me_ptr = 1,
	omci_me_dot1p_rate_limiter_tp_type = 2,
	omci_me_dot1p_rate_limiter_us_unicast_flood_rate_ptr = 3,
	omci_me_dot1p_rate_limiter_us_broadcast_rate_ptr = 4,
	omci_me_dot1p_rate_limiter_us_multicast_payload_rate_ptr = 5
};

/** @} */

/** @} */

__END_DECLS

#endif
