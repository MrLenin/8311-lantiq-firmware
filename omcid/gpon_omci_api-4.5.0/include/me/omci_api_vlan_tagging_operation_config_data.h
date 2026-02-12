/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_vlan_tagging_operation_conf_data
#define _omci_api_me_vlan_tagging_operation_conf_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_VLAN_TAGGING_CONFIG_DATA VLAN Tagging Operation - Configuration Data

   This Managed Entity organizes data associated with VLAN tagging.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/** Maximum number of rules in VLAN rule group */
#define OMCI_API_VLAN_RULE_GRP_SIZE 16

/* When the optional association type attribute is 0 or undefined, this
   attribute value is the same as the id of the Managed Entity with which
   this VLAN tagging operation configuration data instance is associated,
   which may be either a PPTP Ethernet UNI or an IP host config data ME.
   Otherwise, the value of the ME ID is unconstrained except by the need to be
   unique. */

/** Update VLAN Tagging Operation Configuration Data ME resources

   \note Enable Managed Entity identifier mapping to driver index and
   initialize corresponding driver structures when it is called first time
   for the given ME ID

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] us_vlan_tag_oper_mode Upstream VLAN tagging operation mode
   \param[in] us_vlan_tag_tci_value Upstream VLAN tag TCI value
   \param[in] ds_vlan_tag_oper_mode Downstream VLAN tagging operation mode
   \param[in] association_type      Association type
   \param[in] association_ptr       Associated Managed Entity pointer
*/
enum omci_api_return
omci_api_vlan_tagging_operation_conf_data_update(struct omci_api_ctx *ctx,
						 uint16_t me_id,
						 uint8_t us_vlan_tag_oper_mode,
						 uint16_t us_vlan_tag_tci_value,
						 uint8_t ds_vlan_tag_oper_mode,
						 uint8_t association_type,
						 uint16_t association_ptr);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_vlan_tagging_operation_conf_data_destroy(struct omci_api_ctx *ctx,
						  uint16_t me_id);

/** @} */

/** @} */

__END_DECLS

#endif
