/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_multicast_subscriber_config_h
#define _omci_multicast_subscriber_config_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MULTICAST_SUBSCRIBER_CONFIG Multicast Subscriber Configuration Information Managed Entity

    This Managed Entity organizes data associated with multicast management at
    subscriber ports of IEEE 802.1 bridges, including IEEE 802.1p mappers when
    the provisioning model is mapper-based rather than bridge-based.
    Instances of this Managed Entity are created and deleted by the OLT.
    Because of backward compatibility considerations, a subscriber port without
    an associated multicast subscriber config info Managed Entity would be
    expected to support unrestricted multicast access. This Managed Entity may
    therefore be viewed as restrictive, rather than permissive.
    An instance of this Managed Entity is associated with one instance of the
    MAC bridge port configuration data or the IEEE 802.1p mapper service
    profile.

    @{
*/

/** This structure holds the attributes of the Multicast Subscriber
    Configuration Information Managed Entity.
*/
struct omci_me_multicast_subscriber_config {
	/** Managed Entity Type

	    This attribute indicates the type of the managed Entity implicitly
	    linked by the Managed Entity ID attribute.
	    The coding is:
	    - 0x00 MAC bridge port config data
	    - 0x01 IEEE 802.1p mapper service profile

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t me_type;

	/** Multicast Operations Profile Pointer

	    This attribute points to an instance of the multicast operations
	    profile.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t mc_ops_profile_ptr;

	/** Maximum Simultaneous Groups

	    This attribute specifies the maximum number of dynamic multicast
	    groups that may be replicated to the client port at any one time.
	    The default value 0x0000 specifies that no administrative limit is
	    to be imposed.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t max_simultaneous_groups;

	/** Maximum Multicast Bandwidth

	    This attribute specifies the maximum imputed dynamic bandwidth, in
	    bytes per second, that may be delivered to the client port at any
	    one time.
	    The default value 0x00000000 specifies that no administrative limit
	    is to be imposed.

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t max_mc_bw;

	/** Bandwidth Enforcement

	    The default value of this boolean attribute is OMCI_FALSE and
	    specifies that attempts to exceed the max multicast bandwidth be
	    counted but honored.
	    The value OMCI_TRUE specifies that such attempts be counted and
	    denied. The imputed bandwidth value is taken from the dynamic access
	    control list table, both for a new join request and for pre-existing
	    groups.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t bw_enforcement;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Multicast Subscriber
    Configuration Information Managed Entity.
*/
enum {
	omci_me_multicast_subscriber_config_me_type = 1,
	omci_me_multicast_subscriber_config_mc_ops_profile_ptr = 2,
	omci_me_multicast_subscriber_config_max_simultaneous_group = 3,
	omci_me_multicast_subscriber_config_max_mc_bw = 4,
	omci_me_multicast_subscriber_config_bw_enforcement = 5
};

/** @} */

/** @} */

__END_DECLS

#endif
