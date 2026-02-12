/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_dot1_rate_limiter_h
#define _omci_api_me_dot1_rate_limiter_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_DOT1_RATE_LIMITER Dot1 Rate Limiter

   This Managed Entity allows rate limits to be defined for various types of
   upstream traffic that are processed by 802.1 bridges or related structures.

   @{
*/

/** Update Dot1 Rate Limiter ME resources.

    \note Enable Managed Entity identifier mapping to driver index and
    initialize corresponding driver structures when it is called first time
    for the given ME ID.

    \param[in] ctx                         OMCI API context pointer
    \param[in] me_id                       Managed Entity identifier
    \param[in] parent_me_ptr               Parent Managed Entity pointer
    \param[in] tp_type                     Type of parent Managed Entity
    \param[in] us_unicast_flood_rate_ptr   Upstream UC flood rate pointer
    \param[in] us_broadcast_flood_rate_ptr Upstream BC rate pointer
    \param[in] us_multicast_flood_rate_ptr Upstream MC payload rate pointer
*/
enum omci_api_return
omci_api_dot1_rate_limiter_update(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t parent_me_ptr,
				  uint8_t tp_type,
				  uint16_t us_unicast_flood_rate_ptr,
				  uint16_t us_broadcast_flood_rate_ptr,
				  uint16_t us_multicast_flood_rate_ptr);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

    \param[in] ctx		OMCI API context pointer
    \param[in] me_id		Managed Entity identifier
    \param[in] parent_me_ptr	Parent Managed Entity pointer
    \param[in] tp_type		Type of parent Managed Entity
*/
enum omci_api_return
omci_api_dot1_rate_limiter_destroy(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint16_t parent_me_ptr,
				   uint8_t tp_type);

/** @} */

/** @} */

__END_DECLS

#endif
