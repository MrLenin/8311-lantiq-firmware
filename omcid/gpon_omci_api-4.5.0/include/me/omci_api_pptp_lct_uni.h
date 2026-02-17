/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_api_pptp_lct_uni.h
   v7.5.1 LCT UNI API — meter creation, exception profile setup for LCT port.
*/
#ifndef _omci_api_me_pptp_lct_uni
#define _omci_api_me_pptp_lct_uni

#include "omci_api.h"

__BEGIN_DECLS

/** Create LCT UNI resources: GPE meter + exception meter association.
    Matches stock v7.5.1 FUN_0043fb20.
    Uses omci_api_uni2lan internally to resolve me_id → lan_port.

   \param[in] ctx         OMCI API context pointer
   \param[in] me_id       PPTP LCT UNI ME instance ID
*/
enum omci_api_return
omci_api_pptp_lct_uni_create(struct omci_api_ctx *ctx,
			     uint16_t me_id);

/** Update LCT UNI exception profile (enable/disable extraction masks).
    Matches stock v7.5.1 FUN_0043fcb8.
    Uses omci_api_uni2lan internally to resolve me_id → lan_port.

   \param[in] ctx          OMCI API context pointer
   \param[in] me_id        PPTP LCT UNI ME instance ID
   \param[in] admin_state  0 = unlocked (enable), 1 = locked (disable)
*/
enum omci_api_return
omci_api_pptp_lct_uni_update(struct omci_api_ctx *ctx,
			     uint16_t me_id,
			     uint8_t admin_state);

/** Destroy LCT UNI resources: delete meter + clear exception association.
    Matches stock v7.5.1 FUN_0043fd84.
    Uses omci_api_uni2lan internally to resolve me_id → lan_port.

   \param[in] ctx         OMCI API context pointer
   \param[in] me_id       PPTP LCT UNI ME instance ID
*/
enum omci_api_return
omci_api_pptp_lct_uni_destroy(struct omci_api_ctx *ctx,
			      uint16_t me_id);

__END_DECLS

#endif
