/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_network_address_h
#define _omci_me_network_address_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_NETWORK_ADDRESS Network Address Managed Entity

   The network address Managed Entity associates a network address with
   security methods required to access a server. It is conditionally required
   for ONUs that support VoIP service. The address may take the form of a URL,
   a fully qualified path or IP address represented as an ACII string.
   If a non-OMCI interface is used to manage VoIP signalling, this ME
   is unnecessary.
   Instances of this Managed Entity are created and deleted by the OLT or the
   ONU, depending on the method used and case.

   @{
*/

/** This structure holds the attributes of the Network Address Managed Entity.
*/
struct omci_me_network_address {
	/** This attribute points to an authentication security method
	    Managed Entity. The authentication security method indicates the
	    username and password to be used when retrieving the network address
	    indicated by this ME. A null pointer indicates that security
	    attributes are not defined for this network address. */
	uint16_t security_ptr;
	/** This attribute points to the large string ME that contains
	    the network address. It may contain a fully qualified domain name,
	    URI or IP address. The URI may also contain a port identifier
	    (eg x.y.z.com:5060). A null pointer indicates that no network
	    address is defined. */
	uint16_t address_ptr;
} __PACKED__;

/** This enumerator holds the attribute numbers of the Network Address
    Managed Entity.
*/
enum {
	omci_me_network_address_security_ptr = 1,
	omci_me_network_address_address_ptr = 2
};

/** @} */

/** @} */

__END_DECLS

#endif
