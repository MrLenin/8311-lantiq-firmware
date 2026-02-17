/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_virtual_ethernet_interface_point_h
#define _omci_virtual_ethernet_interface_point_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_VIRTUAL_ETHERNET_INTERFACE_POINT Virtual Ethernet interface point 

   This Managed Entity represents the data plane hand-off point in an ONU to a
   separate (non-OMCI) management domain. The virtual Ethernet interface point
   is managed by OMCI, and is potentially known to the non-OMCI management
   domain. One or more Ethernet traffic flows are present at thi boundary. 
   Instances of this Managed Entity are automatically created and deleted by the 
   ONU. This is necessary because the required downstream priority queues are
   subject to physical implementation constraints. The OLT may use one or more
   of the virtual Ethernet interface points created by the ONU. 
   It is expected that the ONU would create one virtual Ethernet interface point 
   for each non-OMCI management domain. At the vendor's discretion, a virtual
   Ethernet interface point may be created for each traffic class. 

    @{
*/

/** This structure hold the attributes of the Virtual Ethernet interface point
    Managed Entity.
*/
struct omci_me_virtual_ethernet_interface_point {
	/** Administrative State

	    This attribute locks (1) and unlocks (0) the functions performed by
	    this Managed Entity. Administrative state is further described in
	    clause A.1.6. (R, W) (mandatory). */
	uint8_t admin_state;

	/** Operational State

	    This attribute indicates whether or not the Managed Entity is
	    capable of performing its function. Valid values are enabled (0) and
	    disabled (1). (R) (optional). */
	uint8_t oper_state;
	/** Interdomain name

	    This attribute is a character string that provides an optional way
	    to identify the virtual Ethernet interface point to a non-OMCI
	    management domain. The interface may also be identified by its
	    Managed Entity ID, IANA assigned port and possibly other ways.
	    If the vendor offers no information in this attribute, it should be
	    set to a sequence of null bytes. (R, W) (optional). */
	uint8_t interdomain_name[25];
	/** TCP/UDP pointer

	    This attribute points to an instance of the TCP/UDP config data
	    Managed Entity, which provides for OMCI management of the non-OMCI
	    management domain's IP connectivity. If no OMCI management of the
	    non-OMCI domain's IP connectivity is required, this attribute may
	    be omitted or set to its default, a null pointer.
	    (R, W) (optional) */
	uint16_t tcp_udp_pointer;
	/** IANA assigned port

	    This attribute contains the TCP or UDP port value as assigned by
	    IANA for the management protocol associated with this virtual
	    Ethernet interface. This attribute is to be regarded as a hint,
	    not as a requirement that management communications use this port;
	    the actual port and protocol are specified in the associated TCP/UDP
	    config data Managed Entity. If no port has been assigned, or if
	    the management protocol is free to be chosen at run-time, this
	    attribute should be set to 0xFFFF. (R) (mandatory) */
	uint16_t iana_assigned_port;
} __PACKED__;

/** This enumerator holds the attribute numbers of the Virtual Ethernet
    interface point Managed Entity.
*/
enum {
	omci_me_veip_admin_state = 1,
	omci_me_veip_oper_state = 2,
	omci_me_veip_interdomain_name = 3,
	omci_me_veip_tcp_udp_pointer = 4,
	omci_me_veip_iana_assigned_port = 5
};

/** @} */

/** @} */

__END_DECLS

#endif
