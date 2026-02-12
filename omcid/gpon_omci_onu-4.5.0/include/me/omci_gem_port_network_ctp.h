/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_gem_port_network_ctp_h
#define _omci_gem_port_network_ctp_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_GEM_PORT_NETWORK_CTP GEM Port Network Connection Termination Point Managed Entity

    This Managed Entity represents the termination of a GEM port on an ONT.
    It aggregates connectivity functionality from the network view and alarms
    from the network element view as well as artifacts from trails.

    Instances of the GEM port network CTP Managed Entity are created and
    deleted by the OLT. An instance of GEM port network CTP can be deleted
    only when no GEM interworking termination point or GEM port PM history data
    is associated with it. It is the responsibility of the OLT to make
    sure that the GEM port network CTP meets this condition.

    When a GEM port network CTP is created, its encryption mode is by
    default not-encrypted. If the OLT wishes to configure the GEM port to use
    encryption, then the appropriate PLOAM message must be sent.
    This applies equally to new CTPs or to CTPs that are re-created after an
    MIB reset.

    An instance of the GEM port network CTP Managed Entity may be associated
    with an instance of the T-CONT and GEM interworking termination point
    Managed Entities.

    @{
*/

/** This structure holds the attributes of the GEM Port Network CTP
    Managed Entity.
*/
struct omci_me_gem_port_network_ctp {
	/** Port ID

	    This attribute is the port ID of the GEM port associated with this
	    CTP.
	    The hardware configuration must be set according to this value.

	    This attribute is readable and writable by the OLT.

	    \remarks Resource management is needed because the number of
	    available GEM Port IDs is limited by the hardware.
	*/
	uint16_t gem_port_id;

	/** T-CONT Pointer

	    This attribute points to a T-CONT Managed Entity instance.

	    This attribute is readable and writable by the OLT.

	    /remark If the OLT tries to link this to a non-existing
	    T-CONT Managed Entity or to a Managed Entity of a wrong type,
	    this is refused.
	*/
	uint16_t tcont_ptr;

	/** Direction

	    This attribute specifies the data direction that is related to this
	    Port ID:
	    - 0x01 UNI-to-ANI (upstream) only
	    - 0x02 ANI-to-UNI (downstream) only
	    - 0x03 bidirectional

	    This attribute is readable and writable by the OLT.

	    Invalid code points are rejected.
	*/
	uint8_t direction;

	/** Traffic Management Pointer Upstream

	    If the traffic management option attribute in the ONT-G ME is 0x00
	    (priority controlled) or 0x02 (priority and rate controlled), this
	    pointer specifies the priority queue-G Managed Entity serving this
	    GEM port network CTP.
	    If the traffic management option attribute is 0x01 (rate
	    controlled), this attribute redundantly points to the T-CONT Managed
	    Entity serving this GEM port network CTP.

	    This attribute is readable and writable by the OLT.

	    /remark If the OLT tries to link this to a non-existing
	    Managed Entity or to a Managed Entity of a wrong type,
	    this is refused.
	*/
	uint16_t traffic_management_ptr_us;

	/** Traffic Descriptor Profile Pointer Upstream

	    This attribute points to the instance of the Traffic Descriptor
	    Managed Entity that contains the upstream traffic parameters used
	    for this GEM port network CTP Managed Entity. This attribute is
	    used when the traffic management option attribute in the ONT-G ME
	    is 0x01 (rate controlled), specifying the PIR/PBS to which the
	    upstream traffic is shaped. This attribute is also used when the
	    traffic management option attribute in the ONT-G Managed Entity is
	    0x02 (priority and rate controlled), specifying the CIR/CBS/PIR/PBS
	    to which the upstream traffic is policed.

	    This attribute is readable and writable by the OLT.

	    /remark If the OLT tries to link this to a non-existing
	    Managed Entity or to a Managed Entity of a wrong type,
	    this is refused.
	*/
	uint16_t traffic_descriptor_ptr_us;

	/** UNI Counter

	    This attribute reports the number of instances of UNI-G Managed
	    Entity associated with this GEM port network CTP.

	    This attribute is read-only by the OLT.

	    The default value is application dependent.
	*/
	uint8_t uni_counter;

	/** Priority Queue Pointer Downstream

	    This attribute points to the instance of the priority queue-G used
	    for this GEM port network CTP in the downstream direction. It is
	    the responsibility of the OLT to provision the downstream pointer
	    in a way that is consistent with bridge and mapper connectivity. If
	    the pointer is undefined, downstream queueing is determined by
	    other mechanisms in the ONT.

	    Note: If the GEM port network CTP is associated with more than one
	    UNI (downstream multicast), the downstream priority queue pointer
	    defines a pattern (for example queue number 3 for a given UNI) to
	    be replicated (for example to queue number 3) at the other affected
	    UNIs.

	    This attribute is readable and writable by the OLT.

	    \remark If the OLT tries to link this to a non-existing Priority
	    Queue-G Managed Entity or to a Managed Entity of a wrong type, this
	    is refused.
	*/
	uint16_t priority_queue_ptr_ds;

	/**
		Encryption state

	    This attribute indicates the current state of the GEM port network CTP’s 
	    encryption. Legal values are defined to be the same as those of the security 
	    mode attribute of the ONU2-G, with the exception that attribute value 0 
	    indicates an unencrypted GEM port.
	*/
	uint8_t encryption_state;

	/** Traffic Descriptor Profile Pointer Downstream

	    This attribute points to the instance of the Traffic Descriptor
	    Managed Entity that contains the downstream traffic parameters used
	    for this GEM port network CTP ME. This attribute is used when the
	    traffic management option attribute in the ONT-G ME is 0x02
	    (priority and rate controlled), specifying the CIR/CBS/PIR/PBS to
	    which the downstream traffic is policed.

	    This attribute is readable and writable by the OLT.

	    \remark If the OLT tries to link this to a non-existing
	    Traffic Descriptor Managed Entity or to a Managed Entity of a
	    wrong type, this is refused.
	*/
	uint16_t traffic_descriptor_ptr_ds;

} __PACKED__;

/** This enumerator holds the attribute numbers of the GEM Port Network CTP
    Managed Entity.
*/
enum {
	omci_me_gem_port_network_ctp_gem_port_id = 1,
	omci_me_gem_port_network_ctp_tcont_ptr = 2,
	omci_me_gem_port_network_ctp_direction = 3,
	omci_me_gem_port_network_ctp_traffic_management_ptr_us = 4,
	omci_me_gem_port_network_ctp_traffic_descriptor_ptr_us = 5,
	omci_me_gem_port_network_ctp_uni_counter = 6,
	omci_me_gem_port_network_ctp_priority_queue_ptr_ds = 7,
	omci_me_gem_port_network_ctp_encryption_state = 8,
	omci_me_gem_port_network_ctp_traffic_descriptor_ptr_ds = 9
};

/** @} */

/** @} */

__END_DECLS

#endif
