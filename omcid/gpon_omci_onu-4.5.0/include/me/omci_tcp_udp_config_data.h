/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_tcp_udp_config_data_h
#define _omci_tcp_udp_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_TCP_UDP_CONFIG_DATA TCP/UDP config data Managed Entity

   The TCP/UDP config data Managed Entity configures TCP- and UDP-based
   services that are offered from an IP host. If a non-OMCI interface is
   used to manage an IP service, this ME is unnecessary; the non-OMCI
   interface supplies the necessary data.

   An instance of this Managed Entity is created and deleted on request
   of the OLT.

    @{
*/

/** This structure holds the attributes of the TCP/UDP config data Managed Entity.
*/
struct omci_tcp_udp_config_data {
	/** Port id
	    This attribute specifies the port number that offers the
	    TCP/UDP service. */
	uint16_t port_id;
	/** Protocol
	    This attribute specifies the protocol type as defined by IANA
	    (protocol numbers at www.iana.org) for example UDP (0x11). */
	uint8_t protocol;
	/** TOS/deffserv field
	    This attribute specifies the value of the TOS/diffserv field of the
	    IPv4 header. The contents of this attribute may contain the type of
	    service per [IETF RFC 2474] or a differentiated services code point
	    (DSCP). Valid values for DSCP are as defined by IANA (differentiated
	    services field code points at www.iana.org). */
	uint8_t tos_diffserv;
	/** IP host pointer
	    This attribute points to the IP host config data ME associated with
	    this TCP/UDP data. Any number of ports and protocols may be
	    associated with an IP host. */
	uint16_t ip_host_ptr;
} __PACKED__;

/** This enumerator holds the attribute numbers of the TCP/UDP config data
    Managed Entity.
*/
enum {
	omci_me_tcp_udp_config_data_port_id = 1,
	omci_me_tcp_udp_config_data_protocol = 2,
	omci_me_tcp_udp_config_data_tos_diffserv = 3,
	omci_me_tcp_udp_config_data_ip_host_ptr = 4
};

/** @} */

/** @} */

__END_DECLS

#endif
