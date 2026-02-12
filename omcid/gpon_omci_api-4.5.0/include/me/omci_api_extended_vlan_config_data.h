/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_extended_vlan_config_data
#define _omci_api_me_extended_vlan_config_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_EXTENDED_VLAN_CONFIG_DATA Extended VLAN Tagging Operation Configuration Data

   This Managed Entity organizes data associated with VLAN tagging. Regardless
   of its point of attachment, the specified tagging operations refer to the
   upstream direction.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/**  Update Extended VLAN Tagging Operation Configuration Data ME resources
     related to the association type 0 (MAC bridge port configuration data)

   \note Enable Managed Entity identifier mapping to driver index and
   initialize corresponding driver structures when it is called first time
   for the given ME ID

   \param[in] ctx         	OMCI API context pointer
   \param[in] association_type 	Association type
   \param[in] me_id       	Managed Entity identifier
   \param[in] bridge_me_id	Bridge Managed Entity identifier
   \param[in] input_tpid  	Input TPID
   \param[in] output_tpid 	Output TPID
   \param[in] dscp 		Pointer to the DSCP mapping table
   \param[in] ds_mode     	Downstream mode
*/
enum omci_api_return
omci_api_ext_vlan_cfg_data_update(struct omci_api_ctx *ctx,
				  const bool mc_support,
				  uint8_t association_type,
				  uint16_t me_id,
				  uint16_t associated_ptr,
				  uint16_t input_tpid,
				  uint16_t output_tpid,
				  uint8_t *dscp,
				  uint8_t ds_mode);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_ext_vlan_cfg_data_destroy(struct omci_api_ctx *ctx, uint16_t me_id);

/** Update MC extended VLAN entries

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_extended_vlan_config_data_mc_entries_update(struct omci_api_ctx *ctx,
						     uint16_t me_id);

/** Clear MC extended VLAN entries

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_extended_vlan_config_data_mc_entries_clear(struct omci_api_ctx *ctx,
						    uint16_t me_id);

/** Add new entry to Received frame VLAN tagging operation table

   \param[in] ctx                       OMCI API context pointer
   \param[in] me_id                     Managed Entity identifier
   \param[in] entry_idx                 Entry index
   \param[in] ds_mode                   Downstream mode
   \param[in] filter_outer_priority     Filter outer priority
   \param[in] filter_outer_vid          Filter outer VID
   \param[in] filter_outer_tpid_de      Filter outer TPID/DE
   \param[in] filter_inner_priority     Filter inner priority
   \param[in] filter_inner_vid          Filter inner VID
   \param[in] filter_inner_tpid_de      Filter inner TPID/DE
   \param[in] filter_ethertype          Filter Ethertype
   \param[in] treatment_tags_to_remove  Treatment tags to remove
   \param[in] treatment_outer_priority  Treatment outer priority
   \param[in] treatment_outer_vid       Treatment outer VID
   \param[in] treatment_outer_tpid_de   Treatment outer TPID/DE
   \param[in] treatment_inner_priority  Treatment inner priority
   \param[in] treatment_inner_vid       Treatment inner VID
   \param[in] treatment_inner_tpid_de   Treatment inner TPID/DE

   \note
   The first 7 fields of each entry are guaranteed to be unique,
   and are used to identify table entries.
*/
enum omci_api_return
omci_api_extended_vlan_config_data_tag_oper_table_entry_add(struct omci_api_ctx
							    *ctx,
							    uint16_t me_id,
							    uint32_t entry_idx,
							    uint8_t ds_mode,
							    uint8_t
							    filter_outer_priority,
							    uint16_t
							    filter_outer_vid,
							    uint8_t
							    filter_outer_tpid_de,
							    uint8_t
							    filter_inner_priority,
							    uint16_t
							    filter_inner_vid,
							    uint8_t
							    filter_inner_tpid_de,
							    uint8_t
							    filter_ethertype,
							    uint8_t
							    treatment_tags_to_remove,
							    uint8_t
							    treatment_outer_priority,
							    uint16_t
							    treatment_outer_vid,
							    uint8_t
							    treatment_outer_tpid_de,
							    uint8_t
							    treatment_inner_priority,
							    uint16_t
							    treatment_inner_vid,
							    uint8_t
							    treatment_inner_tpid_de);

/** Remove existing entry from Received frame VLAN tagging operation table

   \param[in] ctx               OMCI API context pointer
   \param[in] me_id             Managed Entity identifier
   \param[in] entry_idx         Entry index
   \param[in] ds_mode     	Downstream mode

   \note
   The first 7 fields of each entry are guaranteed to be unique,
   and are used to identify table entries.
*/
enum omci_api_return
omci_api_extended_vlan_config_data_tag_oper_table_entry_remove(struct
							       omci_api_ctx
							       *ctx,
							       uint16_t
							       me_id,
							       uint32_t
							       entry_idx,
							       uint8_t ds_mode);

/** Remove existing entry from Received frame VLAN tagging operation table

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] ds_mode               Downstream mode

   \note
   The first 7 fields of each entry are guaranteed to be unique,
   and are used to identify table entries.
*/
enum omci_api_return
omci_api_extended_vlan_config_data_tag_oper_table_clear(struct omci_api_ctx
							*ctx,
							uint16_t me_id,
							uint8_t ds_mode);

enum omci_api_return ext_vlan_custom_update(struct omci_api_ctx *ctx,
					    const uint8_t ethertype);

struct vlan_filter {
	int filter_outer_priority;
	int filter_outer_vid;
	int filter_outer_tpid_de;
	int filter_inner_priority;
	int filter_inner_vid;
	int filter_inner_tpid_de;
	int filter_ethertype;
	int treatment_tags_to_remove;
	int treatment_outer_priority;
	int treatment_outer_vid;
	int treatment_outer_tpid_de;
	int treatment_inner_priority;
	int treatment_inner_vid;
	int treatment_inner_tpid_de;
};

/** @} */

/** @} */

__END_DECLS

#endif
