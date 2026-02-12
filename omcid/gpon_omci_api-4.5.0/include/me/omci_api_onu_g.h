/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_onu_g_h
#define _omci_api_me_onu_g_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_OMCI_API_G ONU-G

   This Managed Entity represents the ONU as equipment. The ONU automatically
   creates an instance of this Managed Entity. It assigns values to read-only
   attributes according to data within the ONU itself.

   @{
*/

/** Retrieve serial number

   \param[in]  ctx                 OMCI API context pointer
   \param[in]  me_id               Managed Entity identifier
   \param[out] serial_number       Serial number
*/
enum omci_api_return omci_api_onu_g_serial_number_get(struct omci_api_ctx *ctx,
						       uint16_t me_id,
						       uint8_t *serial_number);

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

    \param[in] ctx            OMCI API context pointer
    \param[in] me_id          Managed Entity identifier
    \param[in] battery_backup Battery backup
   \param[in] traff_mgmt_opt Traffic management option
*/
enum omci_api_return omci_api_onu_g_create(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint8_t battery_backup,
					   uint8_t traff_mgmt_opt);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

    \param[in] ctx   OMCI API context pointer
    \param[in] me_id Managed Entity identifier
*/
enum omci_api_return omci_api_onu_g_destroy(struct omci_api_ctx *ctx,
					    uint16_t me_id);

/** Updates ONU-G ME resources

   \param[in] ctx            OMCI API context pointer
   \param[in] me_id          Managed Entity identifier
   \param[in] battery_backup Battery backup
   \param[in] traff_mgmt_opt Traffic management option
*/
enum omci_api_return omci_api_onu_g_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint8_t battery_backup,
					   uint8_t traff_mgmt_opt);

/** @} */

/** @} */

__END_DECLS

#endif
