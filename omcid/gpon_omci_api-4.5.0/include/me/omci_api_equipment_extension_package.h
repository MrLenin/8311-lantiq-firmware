/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_equipment_extension_package_h
#define _omci_api_me_equipment_extension_package_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_EQUIPMENT_EXTENSION_PACKAGE Equipment Extension Package

   This Managed Entity supports optional extensions to circuit pack managed
   entities. If the circuit pack supports these features, the ONU creates and
   deletes this Managed Entity along with its associated real or virtual
   circuit pack.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the ONU-G or cardholder. */

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

    \param[in] ctx                    OMCI API context pointer
    \param[in] me_id                  Managed Entity identifier
    \param[in] environmental_sense    Environmental sense
    \param[in] contact_closure_output Contact closure output
*/
enum omci_api_return
omci_api_equipment_extension_package_create(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint16_t environmental_sense,
					    uint16_t contact_closure_output);

/** Disable Managed Entity identifier mapping to driver index and clear
   corresponding driver structures

    \param[in] ctx   OMCI API context pointer
    \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_equipment_extension_package_destroy(struct omci_api_ctx *ctx,
					     uint16_t me_id);

/** Update Equipment Extension Package ME resources

    \param[in] ctx                    OMCI API context pointer
    \param[in] me_id                  Managed Entity identifier
    \param[in] environmental_sense    Environmental sense
    \param[in] contact_closure_output Contact closure output
*/
enum omci_api_return
omci_api_equipment_extension_package_update(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint16_t environmental_sense,
					    uint16_t contact_closure_output);

/** @} */

/** @} */

__END_DECLS

#endif
