/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_net_h
#define _omci_net_h

#include "omci_interface.h"

/** \defgroup OMCI_NET Optical Network Unit - Networking functions.
   @{
*/

/** Length of the MAC address (in bytes) */
#define MAC_ADDR_LEN 6

/** Get Network Interface MAC address

	\param[in] if_name Interface Name
	\param[out] mac MAC address buffer (6 bytes)

	\return 0 on success, -1 on error
*/
int omci_net_mac_get(const char *if_name, uint8_t mac[MAC_ADDR_LEN]);

/** Network interface state change callback

    Called when a network interface changes state (up/down).
    Updates IP Host Config Data (ME 134) attributes when DHCP-enabled
    interfaces come up.

    \param[in] context OMCI context pointer
    \param[in] iface_name Interface name (e.g. "wan", "lan")
    \param[in] iface_up true if interface is up, false if down

    \return OMCI error code
*/
enum omci_error omci_net_iface_state_cb(struct omci_context *context,
					const char *iface_name,
					const bool iface_up);

/** @} */

#endif
