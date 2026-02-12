/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_port_extension_h
#define _omci_mac_bridge_port_extension_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_PORT_EXTENSION MAC Bridge Port Extension Managed Entity

    This Managed Entity is vendor-specific and used by NSN OLTs.

    @{
*/

/** This structure holds the attributes of the MAC Bridge Port Extension
   Managed Entity.
*/
struct omci_me_mac_bridge_port_extension {
	/** t.b.d.
	    This parameter is readable and writable by the OLT.
	*/
	uint8_t mac_switching_mode;

} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Port Extension
   Managed Entity.
*/
enum {
	omci_me_mac_bridge_port_extension_mac_switching_mode = 1
};

/** @} */

/** @} */

__END_DECLS

#endif
