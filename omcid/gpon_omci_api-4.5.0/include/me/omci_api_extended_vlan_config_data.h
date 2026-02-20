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

/* Forward declaration for ext_vlan_rule_add */
struct vlan_filter;

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

/** Add entry to Received frame VLAN tagging operation table (single direction)

   Like _tag_oper_table_entry_add but programs only US or DS, not both.
   Enables independent US/DS index counters in the ME handler.

   \param[in] ctx                       OMCI API context pointer
   \param[in] me_id                     Managed Entity identifier
   \param[in] entry_idx                 Entry index (US or DS specific)
   \param[in] ds_mode                   Downstream mode
   \param[in] ds                        Direction: false=US, true=DS
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
*/
enum omci_api_return
omci_api_extended_vlan_config_data_tag_oper_table_entry_add_dir(
							    struct omci_api_ctx
							    *ctx,
							    uint16_t me_id,
							    uint32_t entry_idx,
							    uint8_t ds_mode,
							    bool ds,
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

/** Add IOP DS passthrough entry (ALCL vendor path)

   Programs a hardcoded single-tag VID=0 passthrough rule into the DS direction
   of the ExtVLAN table. This is the Nokia OLT interop entry from stock v7.5.1
   DAT_0045d514: catches priority-tagged DS frames before VID-specific rules.

   \param[in] ctx       OMCI API context pointer
   \param[in] me_id     Managed Entity identifier
   \param[in] entry_idx DS entry index
   \param[in] ds_mode   Downstream mode
*/
enum omci_api_return
omci_api_extended_vlan_config_data_iop_ds_entry_add(
						    struct omci_api_ctx *ctx,
						    uint16_t me_id,
						    uint32_t entry_idx,
						    uint8_t ds_mode);

/** Get or allocate a GPE ExtVLAN table index for a given ME ID and direction.

   On first call for a given (me_id, ds) pair, allocates a new GPE ExtVLAN
   table and registers the mapping. Subsequent calls return the existing index.

   \param[in]  ctx           OMCI API context pointer
   \param[in]  me_id         Key (ME instance ID or shadow key)
   \param[in]  ds            Direction: false=US, true=DS
   \param[in]  mc_support    Allocate multicast companion table
   \param[out] ext_vlan_idx  Allocated GPE ExtVLAN table index
*/
enum omci_api_return
ext_vlan_idx_get(struct omci_api_ctx *ctx,
		 uint16_t me_id,
		 bool ds,
		 bool mc_support,
		 uint32_t *ext_vlan_idx);

/** Clear all rules from a GPE ExtVLAN table.

   \param[in] ctx           OMCI API context pointer
   \param[in] ds            Direction: false=US, true=DS
   \param[in] ext_vlan_idx  GPE ExtVLAN table index
*/
enum omci_api_return
ext_vlan_rule_clear(struct omci_api_ctx *ctx,
		    const bool ds,
		    uint32_t ext_vlan_idx);

/** Add a rule to a GPE ExtVLAN table.

   \param[in] ctx           OMCI API context pointer
   \param[in] ds            Direction: false=US, true=DS
   \param[in] ext_vlan_idx  GPE ExtVLAN table index
   \param[in] rule_idx      Position in table
   \param[in] omci_idx      OMCI rule template index
   \param[in] f             VLAN filter/treatment parameters
*/
enum omci_api_return
ext_vlan_rule_add(struct omci_api_ctx *ctx,
		  const bool ds,
		  const uint32_t ext_vlan_idx,
		  const uint16_t rule_idx,
		  const uint16_t omci_idx,
		  const struct vlan_filter *f);

/** Create a shadow DS ExtVLAN table and link it to a mapper's GEM ports.

   Allocates a new DS GPE ExtVLAN table keyed by mapper_me_id, then links
   it to all GEM ports under that mapper (same pattern as assoc_type=1).

   \param[in]  ctx            OMCI API context pointer
   \param[in]  mapper_me_id   ME 130 instance ID (used as shadow key)
   \param[out] shadow_idx     Allocated GPE ExtVLAN table index
*/
enum omci_api_return
ext_vlan_shadow_ds_create_and_link(struct omci_api_ctx *ctx,
				   uint16_t mapper_me_id,
				   uint32_t *shadow_idx);

/** Destroy a shadow DS ExtVLAN table and unlink from mapper's GEM ports.

   Clears all rules, unlinks from GEM ports, removes resource mapping,
   and deletes the GPE table.

   \param[in] ctx            OMCI API context pointer
   \param[in] mapper_me_id   ME 130 instance used as shadow key
*/
enum omci_api_return
ext_vlan_shadow_ds_destroy(struct omci_api_ctx *ctx,
			   uint16_t mapper_me_id);

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
