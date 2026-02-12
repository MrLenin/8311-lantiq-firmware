/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_gem_interworking_tp_h
#define _omci_api_me_gem_interworking_tp_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_GEM_INTERWORKING_TP GEM Interworking Termination Point

   An instance of this Managed Entity represents a point in the ONU where the
   interworking of a service (for example CES or IP) or underlying physical
   infrastructure (such as n x DS0, DS1, DS3, E3, or Ethernet) to GEM layer
   takes place. At this point, GEM packets are generated from a bit stream
   (Ethernet, for instance) or a bit stream is reconstructed from GEM packets.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/** Update GEM Interworking TP ME resources.

    \note Enable Managed Entity identifier mapping to driver index and
    initialize corresponding driver structures when it is called first
    time for the given ME ID

    \param[in] ctx                        OMCI API context pointer
    \param[in] me_id                      Managed Entity identifier
    \param[in] gem_port_id                GEM Port Id
    \param[in] interworking_option        Non-GEM function that is being
                                          interworked
    \param[in] service_profile_pointer    Service profile pointer
    \param[in] interworking_tp_pointer    Interworking termination point pointer
    \param[in] gal_loopback_configuration GAL loopback configuration
    \param[in] bridge                     Bridge data
*/
enum omci_api_return
omci_api_gem_interworking_tp_update(struct omci_api_ctx *ctx,
				    uint16_t me_id,
				    uint16_t gem_port_id,
				    uint8_t interworking_option,
				    uint16_t service_profile_pointer,
				    uint16_t interworking_tp_pointer,
				    uint8_t gal_loopback_configuration,
				    struct bridge_data *bridge);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

    \param[in] ctx                     OMCI API context pointer
    \param[in] me_id                   Managed Entity identifier
    \param[in] gem_port_id             GEM Port Id
    \param[in] interworking_option     Non-GEM function that is being
                                       interworked
    \param[in] service_profile_pointer Service profile pointer
*/
enum omci_api_return
omci_api_gem_interworking_tp_destroy(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint16_t gem_port_id,
				     uint8_t interworking_option,
				     uint16_t service_profile_pointer);

/**
   Retrieve the operational state

   \param[in]  ctx                     OMCI API context pointer
   \param[in]  me_id                   Managed Entity identifier
   \param[in]  gem_port_id             GEM Port Id
   \param[out] op_state                Operational state
*/
enum omci_api_return
omci_api_gem_interworking_tp_op_state_get(struct omci_api_ctx *ctx,
					  const uint16_t me_id,
					  const uint16_t gem_port_id,
					  uint8_t *op_state);

/** @} */

/** @} */

__END_DECLS

#endif
