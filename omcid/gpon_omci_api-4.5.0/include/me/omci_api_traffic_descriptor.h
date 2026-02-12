/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_traffic_descriptor_h
#define _omci_api_me_traffic_descriptor_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_TRAFFIC_DESCRIPTOR Traffic Descriptor

   The traffic descriptor allows for traffic management. A priority controlled
   ONU can point from a MAC bridge port configuration data ME to a traffic
   descriptor in order to implement traffic management (marking, policing).
   A rate controlled ONU can point to a traffic descriptor from either a MAC
   bridge port configuration data ME or GEM port network CTP to implement
   traffic management (marking, shaping).

   Packets are determined to be green, yellow or red as a function of the
   ingress packet rate and the settings in this ME. The color indicates drop
   precedence (eligibility), subsequently used by the priority queue-G ME to
   drop packets conditionally during congestion conditions. Packet color is
   also used by the mode 1 DBA status reporting function described in G.984.3.
   Red packets are dropped immediately. Yellow packets are marked as drop
   eligible, and green packets are marked as not drop eligible, according to
   the egress color marking attribute.

   @{
*/

/** Supported values of Color mode parameter in
   \ref omci_api_traffic_descriptor_update
*/
enum omci_api_traffic_descriptor_color_mode {
	/** Color-blind Mode */
	OMCI_API_TRAFFICDESCRIPTOR_COLOR_BLIND = 0,
	/** Color-aware Mode */
	OMCI_API_TRAFFICDESCRIPTOR_COLOR_AWARE = 1
};

/** Supported values of Ingress/Egress Color Marking parameter in
   \ref omci_api_traffic_descriptor_update
*/
enum omci_api_traffic_descriptor_color_marking {
	/** No marking (ignore ingress marking) */
	OMCI_API_TRAFFICDESCRIPTOR_NO_MARKING = 0,
	/** Internal marking only */
	OMCI_API_TRAFFICDESCRIPTOR_INTERNAL_MARKING = 1,
	/** DEI (802.1ad) Marking */
	OMCI_API_TRAFFICDESCRIPTOR_DEI_MARKING = 2,
	/** PCP 8P0D (802.1ad) Marking */
	OMCI_API_TRAFFICDESCRIPTOR_PCP8P0D_MARKING = 3,
	/** PCP 7P1D (802.1ad) Marking */
	OMCI_API_TRAFFICDESCRIPTOR_PCP7P1D_MARKING = 4,
	/** PCP 6P2D (802.1ad) Marking */
	OMCI_API_TRAFFICDESCRIPTOR_PCP6P2D_MARKING = 5,
	/** PCP 5P3D (802.1ad) Marking */
	OMCI_API_TRAFFICDESCRIPTOR_PCP5P3D_MARKING = 6,
	/** DSCP AF class (RFC 2597) Marking*/
	OMCI_API_TRAFFICDESCRIPTOR_DSCPAFCLASS_MARKING = 7
};

/** Supported values of Meter type parameter in
   \ref omci_api_traffic_descriptor_update
*/
enum omci_api_traffic_descriptor_meter_type {
	/** Not specified Meter type */
	OMCI_API_TRAFFICDESCRIPTOR_NOTSPECIFIED_METERTYPE = 0,
	/** RFC 4115 specified Meter type */
	OMCI_API_TRAfFICDESCRIPTOR_RFC4115_METERTYPE = 1,
	/** RFC 2698 specified Meter type */
	OMCI_API_TRAFFICDESCRIPTOR_RFC2698_METERTYPE = 2
};

/** data structure used to specify meter block */
struct omci_api_block {
	uint8_t index;
	uint8_t enable;
};

#define MAX_TD_METER 32
#define MAX_TD_SHAPER 32

/** data structure used by ressource management */
struct omci_api_traffic_descriptor {
	uint32_t cir;
	uint32_t pir;
	uint32_t cbs;
	uint32_t pbs;
	uint8_t color_mode;
	uint8_t ingress_color_marking;
	uint8_t egress_color_marking;
	uint8_t meter_type;
	struct omci_api_block meter[MAX_TD_METER];
	struct omci_api_block shaper[MAX_TD_SHAPER];
};

/** Update Traffic Descriptor ME resources

    \note Enable Managed Entity identifier mapping to driver index and
    initialize corresponding driver structures when it is called first time
    for the given ME ID

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] cir                   CIR (committed information rate, in byte/s)
   \param[in] pir                   PIR (peak information rate, in byte/s)
   \param[in] cbs                   CBS (committed block size, in bytes)
   \param[in] pbs                   PBS (peak block size, in bytes)
   \param[in] color_mode            Color mode
   \param[in] ingress_color_marking Ingress color marking
   \param[in] egress_color_marking  Egress color marking
   \param[in] meter_type            Meter type
*/
enum omci_api_return
omci_api_traffic_descriptor_update(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint32_t cir,
				   uint32_t pir,
				   uint32_t cbs,
				   uint32_t pbs,
				   uint8_t color_mode,
				   uint8_t ingress_color_marking,
				   uint8_t egress_color_marking,
				   uint8_t meter_type);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_traffic_descriptor_destroy(struct omci_api_ctx *ctx,
				    uint16_t me_id);

/** Retrieve the ME values from the ressource management

   \param[in] ctx   OMCI API context pointer
   \param[in] idx   Traffic descriptor index
   \param[out] dest Structure which will hold the data
*/
enum omci_api_return
omci_api_traffic_descriptor_get(struct omci_api_ctx *ctx,
				const uint32_t idx,
				struct omci_api_traffic_descriptor *dest);

/** Attach meter to the specified TD

   \param[in] ctx       OMCI API context pointer
   \param[in] td_idx    Traffic descriptor index
   \param[in] meter_idx Meter index
*/
enum omci_api_return
omci_api_traffic_descriptor_meter_attach(struct omci_api_ctx *ctx,
					 const uint32_t td_idx,
					 const uint8_t meter_idx);

/** Detach meter from the specified TD

   \param[in] ctx       OMCI API context pointer
   \param[in] td_idx    Traffic descriptor index
   \param[in] meter_idx Meter index
*/
enum omci_api_return
omci_api_traffic_descriptor_meter_detach(struct omci_api_ctx *ctx,
					 const uint32_t td_idx,
					 const uint8_t meter_idx);

/** Attach shaper to the specified TD

   \param[in] ctx          OMCI API context pointer
   \param[in] td_idx       Traffic descriptor index
   \param[in] shaper_idx   Shaper index
*/
enum omci_api_return
omci_api_traffic_descriptor_shaper_attach(struct omci_api_ctx *ctx,
					  const uint32_t td_idx,
					  const uint32_t shaper_idx);

/** Detach all shaper from the specified TD

   \param[in] ctx          OMCI API context pointer
   \param[in] td_idx       Traffic descriptor index
*/
enum omci_api_return
omci_api_traffic_descriptor_shaper_detach(struct omci_api_ctx *ctx,
					  const uint32_t td_idx);

/** Update the shaper configuration with all possible
    traffic descriptor settings.
    In case that more than one TD is pointing to one shaper
    the maximum values are used.

   \param[in] ctx          OMCI API context pointer
   \param[in] shaper_idx   Shaper index
*/
enum omci_api_return
omci_api_shaper_update(struct omci_api_ctx *ctx,
					  const uint32_t shaper_index);

/** Reset all shaper related to this traffic descriptor to zero.

   \param[in] ctx          OMCI API context pointer
   \param[in] td_idx       Traffic descriptor index
*/
enum omci_api_return
omci_api_shaper_clean(struct omci_api_ctx *ctx,
					  const uint32_t td_idx);

/** @} */

/** @} */

__END_DECLS

#endif
