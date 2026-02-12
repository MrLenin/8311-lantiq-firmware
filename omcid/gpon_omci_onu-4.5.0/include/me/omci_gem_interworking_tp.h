/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_gem_interworking_tp_h
#define _omci_gem_interworking_tp_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_GEM_INTERWORKING_TP GEM Interworking Termination Point Managed Entity

    An instance of this Managed Entity represents a point in the ONU where the
    interworking of a service (such as CES or IP) or underlying physical
    infrastructure (such as Ethernet) to the GEM layer takes place.
    At this point, GEM packets are generated from a bit stream (for example
    Ethernet) or a bit stream is reconstructed from GEM packets.

    Instances of this Managed Entity are created and deleted by the OLT.
    One instance of this Managed Entity exists for each transformation of a
    data stream into GEM packets and vice versa.

    @{
*/

/** This structure holds the attributes of the GEM Interworking Termination
    Point Managed Entity.
*/
struct omci_me_gem_interworking_tp {
	/** GEM Port Network CTP Pointer

	    This attribute points to an instance of the related GEM port network
	    CTP Managed Entity.
	    This attribute is readable and writable by the OLT.

	    /remark If the OLT tries to link this Managed Entity to a
	    non-existing GEM port network CTP or to a Managed Entity of a wrong
	    type, this is refused.
	*/
	uint16_t gem_port_network_ctp_ptr;

	/** Interworking Option

	    This attribute identifies the type of non-GEM function that is being
	    interworked. The options are:
	    - 0x00 Unstructured TDM
	    - 0x01 MAC bridge LAN
	    - 0x02 Reserved
	    - 0x03 IP data service
	    - 0x04 Video return path
	    - 0x05 802.1p mapper
	    - 0x06 Downstream broadcast
	    This attribute is readable and writable by the OLT.

	    /remark If the OLT tries to assign an option that is not supported
	    by the application, this is refused.
	*/
	uint8_t interworking_option;

	/** Service Profile Pointer

	    This attribute points to an instance of a service profile, such as:
	    - CES service profile-G if interworking option = 0x00
	    - MAC bridge service profile if interworking option = 0x01
	    - IP router service profile if interworking option = 0x03
	    - Video return path service profile if interworking option = 0x04
	    - 802.1p mapper service profile if interworking option = 0x05
	    - Null pointer, if interworking option = 0x06
	    This attribute is readable and writable by the OLT.

	    /remark If the OLT tries to link this to a non-existing
	    service profile Managed Entity or to a Managed Entity of a wrong
	    type, this is refused.
	*/
	uint16_t service_profile_ptr;

	/** Interworking Termination Point Pointer

	    This attribute is used for circuit emulation service and 802.1p
	    mapper service without a MAC bridge. Depending on the service
	    provided, it
	    points to the associated instance of the following Managed Entities:
	    - Physical path termination point CES UNI
            - Logical N x 64 kbit/s sub-port connection termination point
	    - Physical path termination point Ethernet UNI
	    - TU CTP
	    In all other GEM services, the relationship between the related
	    service termination point and this GEM interworking termination
	    point is derived from other Managed Entity relations; this
	    attribute is set to 0 and not used.

	    This attribute is readable and writable by the OLT.

	    /remark If the OLT tries to link this to a non-existing
	    service profile Managed Entity or to a Managed Entity of a wrong
	    type, this is refused.
	*/
	uint16_t interworking_tp_ptr;

	/** PPTP Counter

	    This value reports the number of PPTP Managed Entity instances
	    associated with this GEM interworking termination point.
	    This attribute is read-only by the OLT, the default value is
	    application dependent.
	*/
	uint8_t pptp_counter;

	/** Operational State

	    This attribute reports whether the Managed Entity is currently
	    capable of performing its function. Valid values are
	    OMCI_OPERATIONAL_STATE_ENABLED (0x00) and
	    OMCI_OPERATIONAL_STATE_DISABLED (0x01).
	    It is set to OMCI_OPERATIONAL_STATE_ENABLED as soon as all other
	    attributes as well as the directly related Managed Entities are
	    defined and can be accessed by the OLT.
	    This attribute is read-only by the OLT.
	*/
	uint8_t oper_state;

	/** GAL Profile Pointer

	    This attribute points to an instance of the GAL profile. The
	    relationship between the interworking option and the related GAL
	    profile is:
	    - 0x00 GAL TDM profile
	    - 0x01 GAL Ethernet profile
	    - 0x02 Reserved
	    - 0x03 GAL Ethernet profile for data service
	    - 0x04 GAL Ethernet profile for video return path
	    - 0x05 GAL Ethernet profile for 802.1p mapper
	    - 0x06 Null pointer

	    This attribute is readable and writable by the OLT.

	    /remark If the OLT tries to link this to a non-existing
	    GAL profile Managed Entity, this is refused.
	*/
	uint16_t gal_profile_ptr;

	/** GAL Loopback Configuration

	    This attribute sets the loopback configuration when using GEM mode:
	    - 0x00 no loopback
	    - 0x01 Loopback of downstream traffic after GAL

	    The default value is 0x00. Other values are reserved and not
	    accepted.
	    When the interworking option is 0x06 (downstream broadcast), this
	    attribute is not used.
	    This attribute is readable and writable by the OLT.
	*/
	uint8_t gal_loopback_config;

} __PACKED__;

/** This enumerator holds the attribute numbers of the GEM Interworking
    Termination Point Managed Entity.
*/
enum {
	omci_me_gem_interworking_tp_gem_port_network_ctp_ptr = 1,
	omci_me_gem_interworking_tp_interworking_option = 2,
	omci_me_gem_interworking_tp_service_profile_ptr = 3,
	omci_me_gem_interworking_tp_interworking_tp_ptr = 4,
	omci_me_gem_interworking_tp_pptp_counter = 5,
	omci_me_gem_interworking_tp_oper_state = 6,
	omci_me_gem_interworking_tp_gal_profile_ptr = 7,
	omci_me_gem_interworking_tp_gal_loopback_config = 8
};

/** @} */

/** @} */

__END_DECLS

#endif
