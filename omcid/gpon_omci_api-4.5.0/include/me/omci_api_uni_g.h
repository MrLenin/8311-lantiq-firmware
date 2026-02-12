/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_uni_g_h
#define _omci_api_me_uni_g_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_UNI_G UNI-G

   This Managed Entity organizes data associated with user network interfaces
   (UNIs) supported by GEM. One instance of the UNI-G Managed Entity exists for
   each UNI supported by the ONU.

   The ONU automatically creates or deletes instances of this Managed Entity
   upon the creation or deletion of a real or virtual circuit pack managed
   entity, one per port.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of a physical path termination point. */

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

   \param[in] ctx                  OMCI API context pointer
   \param[in] me_id                Managed Entity identifier
   \param[in] config_option_status Configuration option status
*/
enum omci_api_return omci_api_uni_g_create(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t config_option_status);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return omci_api_uni_g_destroy(struct omci_api_ctx *ctx,
					    uint16_t me_id);

/** Update UNI-G resources

   \param[in] ctx                  OMCI API context pointer
   \param[in] me_id                Managed Entity identifier
   \param[in] config_option_status Configuration option status
*/
enum omci_api_return omci_api_uni_g_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t config_option_status);

/** @} */

/** @} */

__END_DECLS

#endif
