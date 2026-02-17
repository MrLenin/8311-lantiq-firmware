/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_api_veip.h
   v7.5.1 Virtual Ethernet Interface Point API.

   Reverse-engineered from stock omcid v7.5.1:
     FUN_0043fa50 = omci_api_veip_create
     FUN_0043fabc = omci_api_veip_destroy
*/
#ifndef _omci_api_me_veip
#define _omci_api_me_veip

#include "omci_api.h"

__BEGIN_DECLS

/** Register VEIP ME identifier in the mapper and resolve LAN port.

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_veip_create(struct omci_api_ctx *ctx,
		     uint16_t me_id);

/** Remove VEIP ME identifier from the mapper.

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_veip_destroy(struct omci_api_ctx *ctx,
		      uint16_t me_id);

/** Lock (disable) the LAN port associated with this VEIP.

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_veip_lock(struct omci_api_ctx *ctx,
		   uint16_t me_id);

/** Unlock (enable) the LAN port associated with this VEIP.

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_veip_unlock(struct omci_api_ctx *ctx,
		     uint16_t me_id);

__END_DECLS

#endif
