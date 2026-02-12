/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_dot1x_port_ext_pkg
#define _omci_api_me_dot1x_port_ext_pkg

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_DOT1X_PORT_EXT_PKG Dot1X Port Extension Package

   802.1X port authentication enforcement via kernel driver ioctl.

   @{
*/

/** Update 802.1X port enforcement state.

   Maps the OMCI dot1x_enable and action_register values to the kernel
   driver's LAN port authorization ioctl (FIO_LAN_PORT_802_1X_AUTH_CFG_SET).

   Decision tree (matches shipping omcid and G.988 spec):
   - dot1x_enable=0 or action_register=3 (force auth) -> OPEN
   - action_register=1 (re-auth) or 2 (force unauth)  -> BLOCK

   \param[in] ctx              OMCI API context pointer
   \param[in] me_id            Managed Entity identifier (matches PPTP ETH UNI)
   \param[in] dot1x_enable     802.1X enable flag
   \param[in] action_register  Action register value (1=re-auth, 2=unauth, 3=auth)
*/
enum omci_api_return
omci_api_dot1x_port_ext_pkg_update(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint8_t dot1x_enable,
				   uint8_t action_register);

/** @} */

/** @} */

__END_DECLS

#endif
