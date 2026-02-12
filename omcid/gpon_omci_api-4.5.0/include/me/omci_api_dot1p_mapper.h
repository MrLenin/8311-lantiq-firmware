/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_dot1p_mapper_h
#define _omci_api_me_dot1p_mapper_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_8021P_MAPPER_SERVICE_PROFILE 802.1p Mapper Service Profile

   This Managed Entity associates the priorities of priority tagged frames with
   specific connections. The operation of this Managed Entity affects only
   upstream traffic.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/** Update 802.1p Mapper Service Profile ME resources

    \note Enable Managed Entity identifier mapping to driver index and
    initialize corresponding driver structures when it is called first time
    for the given ME ID.

    \param[in] ctx                      OMCI API context pointer
    \param[in] me_id                    Managed Entity identifier
    \param[in] tp_pointer               TP pointer
    \param[in] unmarked_frame_opt       Unmarked frame option
    \param[in] gem_port_id              Array of
                                        Interwork TP pointer for P-bit priority
				        X->GEM port network CTP connectivity
				        pointer->Port id value
    \param[in] dscp_prio_map DSCP to P-bit mapping
    \param[in] default_priority_marking Default P-bit marking
    \param[in] tp_pointer_type          TP type
*/
enum omci_api_return
omci_api_8021p_mapper_service_profile_update(struct omci_api_ctx *ctx,
					     const uint16_t me_id,
					     const uint16_t tp_pointer,
					     const uint16_t *gem_port_id,
					     const uint8_t unmarked_frame_opt,
					     const uint8_t *dscp_prio_map,
					     const uint8_t default_priority_marking,
					     const uint8_t tp_pointer_type);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

    \param[in] ctx                     OMCI API context pointer
    \param[in] me_id                   Managed Entity identifier
    \param[in] tp_pointer              TP pointer
    \param[in] tp_pointer_type         TP type
*/
enum omci_api_return
omci_api_8021p_mapper_service_profile_destroy(struct omci_api_ctx *ctx,
					      const uint16_t me_id,
					      const uint16_t tp_pointer,
					      const uint8_t tp_pointer_type);

/** @} */

/** @} */

__END_DECLS

#endif
