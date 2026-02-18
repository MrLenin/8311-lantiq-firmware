/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _omci_api_mapper_h
#define _omci_api_mapper_h

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "voip/omci_api_voip.h"
#include "voip/omci_api_voip_common.h"

__BEGIN_DECLS

/** \defgroup OMCI_API_MAPPER OMCI API - Low-level indexes mapper

   @{
*/

/** Mapper ID types definition */
enum mapper_id_type {
	MAPPER_IDTYPE_MIN = 0,

	/** OMCI T-CONT ME Identifier
	   to ONU Driver Index mapping
	*/
	MAPPER_TCONT_MEID_TO_IDX = MAPPER_IDTYPE_MIN,

	/** OMCI MAC Bridge Port Configuration Data ME Identifier
	    to ONU Driver Index mapping

	    \note
	    The following ONU_GPE_MAX_BRIDGES ID types are used
	    for OMCI MAC Bridge Port Configuration Data ME
	    Identifier to ONU Driver Index mapping for each
	    MAC Bridge Service Profile separately
	*/
	MAPPER_MACBRIDGEPORT_MEID_TO_IDX,

	/** OMCI Mac Bridge Service Profile ME Identifier
	    to ONU Driver Index mapping
	*/
	MAPPER_MACBRIDGE_MEID_TO_IDX = ONU_GPE_MAX_BRIDGES + 1 +
	    MAPPER_MACBRIDGEPORT_MEID_TO_IDX,

	MAPPER_MACBRIDGEPORT_MEID_TO_INGRESS_METER_IDX,

	MAPPER_MACBRIDGEPORT_MEID_TO_EGRESS_METER_IDX,

	/** OMCI Traffic Scheduler-G ME Identifier
	    to ONU Driver Index mapping
	*/
	MAPPER_TRAFFSHEDG_MEID_TO_IDX,

	/** OMCI 802.1p Mapper Service Profile ME Identifier
	    to ONU Driver Index mapping
	*/
	MAPPER_DOT1PMAPPER_MEID_TO_IDX,

	/** OMCI 802.1p Mapper Service Profile ME Identifier
	    to ONU Driver DSCP Index mapping

	    \todo Describe mapping in more details
	    \todo Add Mapper initialization
	*/
	MAPPER_DOT1PMAPPER_MEID_TO_DSCP_IDX,

	/** OMCI GEM Port Network CTP ME Identifier
	    to Port ID maping
	*/
	MAPPER_GEMPORTCTP_MEID_TO_PORTID,

	/** OMCI GEM Port Network CTP ME Identifier
	    to ONU Driver GEM Port Index (GPIX) mapping (lower 16 bit)
		and GEM Port (upper 16 bit)
	*/
	MAPPER_GEMPORTCTP_MEID_TO_IDX,

	/** OMCI GEM Port Network CTP ME Identifier
	    to meter mapping
	*/
	MAPPER_GEMPORTCTP_MEID_TO_METER_IDX,

	/** OMCI Multicast GEM Port Network ITP ME Identifier
	    to GEM Port Network CTP ME mapping
	*/
	MAPPER_MULCTCAST_GEMPORTITP_MEID_TO_CTP_MEID,

	/** OMCI Priority queue-G ME Identifier
	    to ONU Driver Index mapping
	*/
	MAPPER_PQUEUE_MEID_TO_IDX,

	/** OMCI Traffic Descriptor ME Identifier
	    to ONU Driver Meter Index mapping
	*/
	MAPPER_TRAFFDESCR_TO_IDX,

	/** OMCI Traffic Descriptor ME Identifier
	    to ONU Driver Policer Index mapping
	*/
	MAPPER_TRAFFDESCR_TO_POLICERIDX,

	/** OMCI Traffic Descriptor ME Identifier
	    to ONU Driver Shaper index mapping
	*/
	MAPPER_TRAFFDESCR_TO_SHAPERIDX,

	/** OMCI PPTP Ethernet UNI ME Identifier
	    to ONU Driver Index mapping
	*/
	MAPPER_PPTPETHUNI_MEID_TO_IDX,

	/** OMCI VLAN Tagging Filter Data ME Identifier
	    mapping

	    \todo Describe mapping in more details
	*/
	MAPPER_VLANTFD_MEID_TO_VLANGRP,

	/** OMCI VLAN Tagging Operation Configuration Data
	    ME Identifier mapping - downstream
	*/
	MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_DS,

	/** OMCI VLAN Tagging Operation Configuration Data
	    ME Identifier mapping - upstream
	*/
	MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_US,

	/** OMCI MAC Bridge Port Filter Preassign Table ME
	    identifier to ONU Driver US Exception Configuration
	    Table Entry Index mapping

	    \note This mapping is used when corresponding MAC Bridge Port is
	    located on the ANI side
	*/
	MAPPER_MACBRIDGEPORTFPTD_MEID_TO_USEXCEPTIDX,

	/** OMCI MAC Bridge Port Filter Preassign Table ME
	    identifier to ONU Driver DS Exception Configuration
	    Table Entry Index mapping

	    \note This mapping is used when corresponding MAC Bridge Port is
	    located on the UNI side
	*/
	MAPPER_MACBRIDGEPORTFPTD_MEID_TO_DSEXCEPTIDX,

	/** OMCI VLAN Tagging Operation Config Data & Extended VLAN ME
	    identifier to ONU Driver Extended VLAN Table Entry Index mapping
	*/
	MAPPER_VLAN_MEID_TO_EXTVLANIDX,

	/** OMCI TCONT ME identifier to egress port number

	   \note Used in upstream priority queue
	*/
	MAPPER_TCONT_TO_EPN,

	/** Slot & port identifiers to egress port number

	   \note Used in downstream priority queue
	*/
	MAPPER_PORT_TO_EPN,

	/** SIP Agent ME identifier to index */
	MAPPER_SIP_AGT_TO_IDX,

	/** SIP User ME identifier to index */
	MAPPER_SIP_USR_TO_IDX,

	/** OMCI Extended VLAN Configuration Data ME identifier to ONU Driver
	    Extended VLAN Table Entry Index mapping, US direction */
	MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_US,

	/** OMCI Extended VLAN Configuration Data ME identifier to ONU Driver
	    Extended VLAN Table Entry Index mapping, DS direction */
	MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_DS,

	/** OMCI Extended VLAN Configuration Data ME identifier to ONU Driver
	    MC Extended VLAN Table Entry Index mapping, US direction */
	MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_US,

	/** OMCI Extended VLAN Configuration Data ME identifier to ONU Driver
	    MC Extended VLAN Table Entry Index mapping, DS direction */
	MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_DS,

	/** OMCI Extended VLAN Configuration Data ME identifier to ONU Driver
	    LAN port index */
	MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,

	/** OMCI GEM interworking termination point ME identifier to GEM
	    port index mapping*/
	MAPPER_GEMITP_MEID_TO_GPIX,
	/** OMCI PPTP POTS UNI ME Identifier
	    to TAPI Driver Index mapping
	*/
	MAPPER_PPTPPOTSUNI_MEID_TO_IDX,

	/** OMCI Multicast Profile ME Identifier to Index mapping
	*/
	MAPPER_MCOPPROFILE_MEID_TO_IDX,
	/** OMCI Multicast Subscriber Config Info ME Identifier to Index mapping
	*/
	MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_IDX,

	/** OMCI Multicast Subscriber Config Info ME Identifier to
	    LAN port Index
	*/
	MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_LAN_IDX,

	/** OMCI Multicast Subscriber Monitor ME Identifier to Index mapping
	*/
	MAPPER_MCSUBSCR_MONITOR_MEID_TO_IDX,
 
	/** Priority queue ME Identifier to Token bucket shaper index */
	MAPPER_PQUEUE_MEID_TO_TBS_IDX,

	/** OMCI Virtual Ethernet Interface Point ME Identifier
	    to ONU Driver Index mapping
	*/
	MAPPER_VEIP_MEID_TO_IDX,

	/** PPTP LCT UNI ME Identifier to LAN port index.
	    v7.5.1 stock uses mapper table 0x1c for this. */
	MAPPER_LCT_MEID_TO_LAN_IDX,

	/** PPTP LCT UNI ME Identifier to meter index.
	    v7.5.1 stock uses mapper table 0x1d for this. */
	MAPPER_LCT_MEID_TO_METER_IDX,

	/** IPv6 Host Config Data ME Identifier to LAN port index.
	    v7.5.1 stock uses mapper table 0x1f for this. */
	MAPPER_IPV6HOST_MEID_TO_IDX,

	MAPPER_IDTYPE_MAX
};

/** Key type definition */
enum mapper_key_type {
	/** Key type */
	KEY_TYPE_ID,
	/** Index type */
	KEY_TYPE_INDEX,

	/** Number of key types */
	KEY_TYPE_NUM
};

/** ID to Index (and Index to ID) mapping list definition

   \note List is sorted by ID and Index growth
*/
struct mapper_map_list {
	/** Key array (ID and Index) */
	uint32_t key[KEY_TYPE_NUM];
	/** Array of pointers to the next list node with bigger key value (ID
	   or Index) */
	struct mapper_map_list *next[KEY_TYPE_NUM];
};

/** Mapper definition */
struct mapper {
	/** Minimal key value array */
	uint32_t min_key[KEY_TYPE_NUM];
	/** Maximal key value array*/
	uint32_t max_key[KEY_TYPE_NUM];
	/** List heads array*/
	struct mapper_map_list *list_head[KEY_TYPE_NUM];
};

/** Initialize all mappings

   \param[in] ctx OMCI API context pointer
*/
enum omci_api_return mapper_init(struct omci_api_ctx *ctx);

/** Shutdown mapper

   \param[in] ctx OMCI API context pointer
*/
enum omci_api_return mapper_shutdown(struct omci_api_ctx *ctx);

/** Explicitly map id to index

   \param[in] ctx     OMCI API context pointer
   \param[in] id_type ID Type
   \param[in] id      Id to map
   \param[in] idx     Index to map
*/
enum omci_api_return explicit_map(struct omci_api_ctx *ctx,
				  enum mapper_id_type id_type,
				  uint32_t id,
				  uint32_t idx);

/** Map id to index

   \param[in]  ctx     OMCI API context pointer
   \param[in]  id_type ID Type
   \param[in]  id      Id to map
   \param[out] idx     Return mapped index
*/
enum omci_api_return id_map(struct omci_api_ctx *ctx,
			    enum mapper_id_type id_type,
			    uint32_t id,
			    uint32_t *idx);

/** Map index to id

   \param[in]  ctx     OMCI API context pointer
   \param[in]  id_type ID Type
   \param[out] id      Return mapped id
   \param[in]  idx     Index to map
*/
enum omci_api_return index_map(struct omci_api_ctx *ctx,
			       enum mapper_id_type id_type,
			       uint32_t *id,
			       uint32_t idx);

/** Retrieve id for the given index

   \param[in]  ctx     OMCI API context pointer
   \param[in]  id_type Mapper type
   \param[out] id      Return mapped id
   \param[in]  idx     Index
*/
enum omci_api_return id_get(struct omci_api_ctx *ctx,
			    enum mapper_id_type id_type,
			    uint32_t *id,
			    uint32_t idx);

/** Retrieve index for the given id

   \param[in]  ctx     OMCI API context pointer
   \param[in]  id_type ID Type
   \param[in]  id      Id
   \param[out] idx     Return mapped index
*/
enum omci_api_return index_get(struct omci_api_ctx *ctx,
			       enum mapper_id_type id_type,
			       uint32_t id,
			       uint32_t *idx);

/** Retrieve index for the given id, map if not mapped yet

   \param[in]  ctx     OMCI API context pointer
   \param[in]  id_type ID Type
   \param[in]  id      Id
   \param[out] idx     Return mapped index
*/
enum omci_api_return index_map_or_get(struct omci_api_ctx *ctx,
				      const uint16_t me_id,
				      const enum mapper_id_type id_type,
				      uint32_t *idx);

/** Retrieve the array of mapped ID

   \param[in]  ctx     OMCI API context pointer
   \param[in]  id_type ID Type
   \param[out] id      Pointer to the mapped ID array
   \param[out] size    Size of the mapped ID array

   \note It is user duty to free memory allocated
         for array
*/
enum omci_api_return id_array_get(struct omci_api_ctx *ctx,
				  enum mapper_id_type id_type,
				  uint32_t **id,
				  uint32_t *size);

/** Retrieve the array of mapped Indexes

   \param[in]  ctx     OMCI API context pointer
   \param[in]  id_type ID Type
   \param[out] idx     Pointer to the mapped Index array
   \param[out] size    Size of the mapped Index array

   \note It is user duty to free memory allocated
         for array
*/
enum omci_api_return index_array_get(struct omci_api_ctx *ctx,
				     enum mapper_id_type id_type,
				     uint32_t **idx,
				     uint32_t *size);

/** Remove id from the mapping

   \param[in] ctx     OMCI API context pointer
   \param[in] id_type ID Type
   \param[in] id      Remove index with given id
*/
enum omci_api_return id_remove(struct omci_api_ctx *ctx,
			       enum mapper_id_type id_type,
			       uint32_t id);

/** Remove index from the mapping

   \param[in] ctx     OMCI API context pointer
   \param[in] id_type ID Type
   \param[in] idx     Remove id with given index
*/
enum omci_api_return index_remove(struct omci_api_ctx *ctx,
				  enum mapper_id_type id_type,
				  uint32_t idx);

/** \defgroup OMCI_API_MAPPER_HELPERS OMCI API - Mapper get helpers

   @{
*/

static inline enum omci_api_return bridge_idx_get(struct omci_api_ctx *ctx,
						  uint32_t bridge_id,
						  uint32_t *bridge_idx)
{
	enum omci_api_return ret;

	ret = index_get(ctx, MAPPER_MACBRIDGE_MEID_TO_IDX, bridge_id, bridge_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MAPPER_MACBRIDGE_MEID_TO_IDX: "
				   "can't find %d id\n",
				   bridge_id));
		return OMCI_API_ERROR;
	}

	return ret;
}

static inline enum omci_api_return bridge_port_idx_get(struct omci_api_ctx *ctx,
						       uint32_t bridge_id,
						       uint32_t bridge_port_id,
						       uint32_t *bridge_port_idx)
{
	enum omci_api_return ret;

	ret = index_get(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX/* + bridge_idx*/,
			bridge_port_id, bridge_port_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MAPPER_MACBRIDGEPORT_MEID_TO_IDX: "
				   "can't find %d id for bridge %d\n",
				   bridge_port_id, bridge_id));
		return OMCI_API_ERROR;
	}

	return ret;
}

/** @} */

/** @} */

__END_DECLS

#endif
