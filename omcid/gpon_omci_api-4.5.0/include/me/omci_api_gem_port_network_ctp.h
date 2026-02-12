/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_gem_port_network_ctp_h
#define _omci_api_me_gem_port_network_ctp_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_GEM_PORT_NETWORK_CTP GEM Port Network CTP

   This Managed Entity represents the termination of a GEM port on an ONU. This
   Managed Entity aggregates connectivity functionality from the network view
   and alarms from the network element view as well as artefacts from trails.

   Instances of the GEM port network CTP Managed Entity are created and deleted
   by the OLT. An instance of GEM port network CTP can be deleted only when no
   GEM interworking termination point or GEM port PM history data is associated
   with it. It is the responsibility of the OLT to make sure that the GEM port
   network CTP meets this condition. If the OLT wishes to configure the GEM
   port to use encryption, then the appropriate PLOAM message must be sent.
   This applies equally to new CTPs or to CTPs that are re-created after a MIB
   reset.

   @{
*/

/** Supported values of Direction parameter in
    \ref omci_api_gem_port_network_ctp_update
*/
enum omci_api_gem_port_network_ctp_direction {
	/** UNI-to-ANI connection */
	OMCI_API_GEMPORTNETCTP_DIRECTION_UPSTREAM = 1,
	/** ANI-to-UNI connection */
	OMCI_API_GEMPORTNETCTP_DIRECTION_DOWNSTREAM = 2,
	/** Bidirectional connection */
	OMCI_API_GEMPORTNETCTP_DIRECTION_BOTH = 3
};

/** Update GEM Port Network CTP ME resources

    \note Enable Managed Entity identifier mapping to driver index and
    initialize corresponding driver structures when it is called first time
    for the given ME ID

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] gem_port_id           Port id value
   \param[in] tcont_ptr             T-CONT pointer
   \param[in] direction             Direction
   \param[in] us_priority_queue_ptr Upstream priority queue (Upstream
                                    Traffic management pointer)
   \param[in] us_priority_queue_drop_precedence_color_marking
              Value of "Drop precedence color marking" attribute of the Priority
              Queue-G pointed by "Upstream traffic management pointer".
   \param[in] us_traffic_descriptor_egress_color_marking
              Value of "Egress color marking attribute" of the Traffic
              Descriptor pointed by "Upstream traffic descriptor profile".
              Set to 255 if "Upstream traffic descriptor profile" is NULL
   \param[in] us_traffic_descriptor_profile_ptr Traffic descriptor profile
              pointer for upstream
   \param[in] ds_priority_queue_ptr Priority queue pointer for downstream
   \param[in] ds_traffic_descriptor_profile_ptr Traffic descriptor profile
              pointer for downstream
*/
enum omci_api_return
omci_api_gem_port_network_ctp_update(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint16_t gem_port_id,
				     uint16_t tcont_ptr,
				     uint8_t direction,
				     uint16_t us_priority_queue_ptr,
				     uint8_t us_priority_queue_drop_precedence_color_marking,
				     uint8_t us_traffic_descriptor_egress_color_marking,
				     uint16_t us_traffic_descriptor_profile_ptr,
 				     uint16_t ds_priority_queue_ptr,
				     uint16_t ds_traffic_descriptor_profile_ptr);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx         OMCI API context pointer
   \param[in] me_id       Managed Entity identifier
   \param[in] gem_port_id Port id value
   \param[in] td_ptr      Traffic Descripor ME Identifier
*/
enum omci_api_return
omci_api_gem_port_network_ctp_destroy(struct omci_api_ctx *ctx,
				      uint16_t me_id,
				      uint16_t gem_port_id,
				      uint16_t td_ptr);

/** @} */

/** @} */

__END_DECLS

#endif
