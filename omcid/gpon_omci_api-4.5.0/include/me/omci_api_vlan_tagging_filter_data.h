/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_vlan_tagging_filter_data
#define _omci_api_me_vlan_tagging_filter_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_VLAN_TAGGING_FILTER_DATA VLAN Tagging Filter Data

   This Managed Entity organizes data associated with VLAN tagging.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/** Maximum number of TCIs in VLAN group */
#define OMCI_API_VLAN_GRP_SIZE 16

/** Number of supported entries in VLAN filter list attribute in
    \ref omci_api_vlan_tagging_filter_data_update
*/
#define OMCI_API_VLAN_TAGGINGFILTERDATA_FILTERLIST_SIZE 12

/* Through an identical ID, this Managed Entity is implicitly linked to
   an instance of the MAC bridge port configuration data ME. */

/** Update VLAN Tagging Filter Data ME resources

   \note Enable Managed Entity identifier mapping to driver index initialize
    corresponding driver structures when it is called first time

   \param[in] ctx                OMCI API context pointer
   \param[in] me_id              Managed Entity identifier
   \param[in] filter_list        VLAN filter list
   \param[in] entries_num        Number of entries (specifies the number of
                                 valid entries in the VLAN filter list)
   \param[in] forward_operation  Forward operation
*/
enum omci_api_return
omci_api_vlan_tagging_filter_data_update(struct omci_api_ctx *ctx,
					 uint16_t me_id,
					 const uint16_t filter_list[OMCI_API_VLAN_TAGGINGFILTERDATA_FILTERLIST_SIZE],
					 uint8_t entries_num,
					 uint8_t forward_operation);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_vlan_tagging_filter_data_destroy(struct omci_api_ctx *ctx,
					  uint16_t me_id);

/** @} */

/** @} */

__END_DECLS

#endif
