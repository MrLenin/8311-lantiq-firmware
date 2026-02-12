/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_onu2_g_h
#define _omci_api_me_onu2_g_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_ONU2_G ONU2-G

   This Managed Entity contains additional attributes associated with the GPON
   ONU. The ONU automatically creates an instance of this Managed Entity. Its
   attributes are populated according to the data within the ONU itself.

   @{
*/

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

    \param[in] ctx           OMCI API context pointer
    \param[in] me_id         Managed Entity identifier
    \param[in] security_mode Security mode
*/
enum omci_api_return omci_api_onu2_g_create(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint8_t security_mode);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

    \param[in] ctx   OMCI API context pointer
    \param[in] me_id Managed Entity identifier
*/
enum omci_api_return omci_api_onu2_g_destroy(struct omci_api_ctx *ctx,
					     uint16_t me_id);

/** Updates ONU-G ME resources

   \param[in] ctx           OMCI API context pointer
   \param[in] me_id         Managed Entity identifier
   \param[in] security_mode Security mode
*/
enum omci_api_return omci_api_onu2_g_update(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint8_t security_mode);

/** @} */

/** @} */

__END_DECLS

#endif
