/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_multicast_operations_profile_h
#define _omci_api_me_multicast_operations_profile_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** Maximum number of access control list entries */
#define OMCI_API_MAX_ACL_ENTRIES	50

/** \defgroup OMCI_API_ME_MULTICAST_OPERATIONS_PROFILE Multicast Operations Profile

   This Managed Entity expresses multicast policy. A multi-dwelling unit ONU
   may have several such policies, which are linked to subscribers as required.
   Some of the attributes configure IGMP snooping and proxy parameters, in case
   the defaults do not suffice, as described in [b-IETF RFC 2236],
   [b-IETF RFC 3376], [b-IETF RFC 3810] and [b-IETF RFC 2933].

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/** Supported values of IGMP Version parameter in
   \ref omci_api_multicast_operations_profile_update
*/
enum omci_api_multicast_operations_profile_igmp_version {
	/** IGMP version 1 (deprecated) */
	OMCI_API_MCOPERPROFILE_IGMPVERSION1 = 1,
	/** IGMP version 2 */
	OMCI_API_MCOPERPROFILE_IGMPVERSION2 = 2,
	/** IGMP version 3 */
	OMCI_API_MCOPERPROFILE_IGMPVERSION3 = 3
};

/** Supported values of IGMP Function parameter in
   \ref omci_api_multicast_operations_profile_update
*/
enum omci_api_multicast_operations_profile_igmp_fucntion {
	/** Snooping only */
	OMCI_API_MCOPERPROFILE_IGMPFUNCTION_SNOOPING = 0,
	/** Snooping with proxy reporting (SPR) */
	OMCI_API_MCOPERPROFILE_IGMPFUNCTION_SPR = 1,
	/** IGMP Proxy */
	OMCI_API_MCOPERPROFILE_IGMPFUNCTION_PROXY = 2
};

/** Supported values for Upstream IGMP tag control in
   \ref omci_api_multicast_operations_profile_update
*/
enum omci_api_multicast_operations_profile_us_igmp_tag_control {
	/** Pass upstream IGMP traffic transparently. */
	OMCI_API_MCOPERPROFILE_USIGMPTAGCTRL_TRANSPARENT = 0,
	/** Add a VLAN tag (including P bits) to upstream IGMP traffic. */
	OMCI_API_MCOPERPROFILE_USIGMPTAGCTRL_VLANTAGADD = 1,
	/** Replace the entire TCI (VLAN ID plus P bits). */
	OMCI_API_MCOPERPROFILE_USIGMPTAGCTRL_TCIREPLACE = 2,
	/** Replace only the VLAN ID on upstream IGMP traffic. */
	OMCI_API_MCOPERPROFILE_USIGMPTAGCTRL_VLANIDREPLACE = 3
};

/** Lost Group List Table entry type definition used in
   \ref omci_api_multicast_operations_profile_lost_group_list_table_get
*/
struct omci_api_multicast_operations_profile_lost_group_list_table_entry {
	/** VLAN ID */
	uint16_t vlan_id;
	/** Source IP address */
	uint8_t src_ip_addr[4];
	/** Multicast destination IP address */
	uint8_t mc_dest_ip_addr[4];
};

struct omci_api_multicast_operations_profile_acl_entry {
	/** GEM port ID */
	uint16_t gem_port_id;
	/** VLAN ID */
	uint16_t vlan_id;
	/** Source IP address */
	uint32_t source_ip;
	/** Destination IP address of the start of the multicast range */
	uint32_t dest_start_ip;
	/** Destination IP address of the end of the multicast range */
	uint32_t dest_end_ip;
	/** Imputed group bandwidth */
	uint32_t group_bandwidth;
};

struct omci_api_multicast_operations_profile_acl {
	/** Access control list entry*/
	struct omci_api_multicast_operations_profile_acl_entry entry[OMCI_API_MAX_ACL_ENTRIES];
	/** Number of available access control list entries*/
	uint32_t count;
};


/** Update Multicast extended VLAN entries
*/
enum omci_api_return
omci_api_multicast_operations_profile_mc_ext_vlan_update(struct omci_api_ctx
							 *ctx,
							 const uint16_t lan_idx,
							 const uint16_t
							 ext_vlan_mc_us_idx,
							 const uint16_t
							 ext_vlan_mc_ds_idx,
							 const uint8_t
							 us_igmp_tag_ctrl,
							 const uint16_t
							 us_igmp_tci,
							 const uint8_t
							 ds_igmp_mc_tag_ctrl,
							 const uint16_t
							 ds_igmp_mc_tci);

/** Clear Multicast extended VLAN entries
*/
enum omci_api_return
omci_api_multicast_operations_profile_mc_ext_vlan_clear(struct omci_api_ctx
							 *ctx,
							 const uint16_t lan_idx,
							 const uint16_t
							 ext_vlan_mc_us_idx,
							 const uint16_t
							 ext_vlan_mc_ds_idx);

/** Update Multicast Operations Profile ME resources

   \note Enable Managed Entity identifier mapping to driver index and
   initialize corresponding driver structures when it is called first time
   for the given ME ID

   \param[in] ctx                        OMCI API context pointer
   \param[in] me_id                      Managed Entity identifier
   \param[in] igmp_version               IGMP version
   \param[in] igmp_function              IGMP function
   \param[in] immediate_leave            Immediate leave
   \param[in] us_igmp_tci                Upstream IGMP TCI
   \param[in] us_igmp_tag_control        Upstream IGMP tag control
   \param[in] us_igmp_rate               Upstream IGMP rate
   \param[in] robustness                 Robustness
   \param[in] querier_ip_address         Querier IP address
   \param[in] query_interval             Query interval
   \param[in] query_max_response_time    Query max response time
   \param[in] last_member_query_interval Last member query interval
   \param[in] ds_igmp_mc_tci             Downstream IGMP/MC TCI
   \param[in] ds_igmp_mc_tag_control     Downstream IGMP/MC tag control
*/
enum omci_api_return
omci_api_multicast_operations_profile_update(struct omci_api_ctx *ctx,
					     uint16_t me_id,
					     uint8_t igmp_version,
					     uint8_t igmp_function,
					     uint8_t immediate_leave,
					     uint16_t us_igmp_tci,
					     uint8_t us_igmp_tag_control,
					     uint32_t us_igmp_rate,
					     uint8_t robustness,
					     uint32_t querier_ip_address,
					     uint32_t query_interval,
					     uint32_t query_max_response_time,
					     uint32_t 
					     last_member_query_interval,
					     uint16_t ds_igmp_mc_tci,
					     uint8_t ds_igmp_mc_tag_control);

/** Delete Multicast Operations Profile ME resources

   \param[in] ctx                        OMCI API context pointer
   \param[in] me_id                      Managed Entity identifier
*/
enum omci_api_return
omci_api_multicast_operations_profile_destroy(
	struct omci_api_ctx *ctx,
	uint16_t me_id);

/** Update Dynamic Access Control List Table of Multicast Operations
   Profile ME

   \param[in] ctx                         OMCI API context pointer
   \param[in] me_id                       Managed Entity identifier
   \param[in] acl                   	  Dynamic ACL Table
*/
enum omci_api_return
omci_api_multicast_operations_profile_dynamic_acl_table_update(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	const struct omci_api_multicast_operations_profile_acl *acl);

/** Add entry to Static Access Control List Table of Multicast Operations
   Profile ME

   \param[in] ctx                          OMCI API context pointer
   \param[in] me_id                        Managed Entity identifier
   \param[in] table_idx                    Table index
   \param[in] gem_port_id                  GEM port ID
   \param[in] vlan_id                      VLAN ID
   \param[in] src_ip_addr                  Source IP address
   \param[in] dest_ip_addr_mc_range_start  Destination IP address of the start
					   of the multicast range
   \param[in] dest_ip_addr_mc_range_end    Destination IP address of the end of
                                           the multicast range
   \param[in] imputed_group_bandwidth      Imputed group bandwidth
*/
enum omci_api_return
omci_api_multicast_operations_profile_static_acl_table_entry_add(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t table_idx,
	uint16_t gem_port_id,
	uint16_t vlan_id,
	const uint8_t src_ip_addr[4],
	const uint8_t dest_ip_addr_mc_range_start[4],
	const uint8_t dest_ip_addr_mc_range_end[4],
	uint32_t imputed_group_bandwidth);

/** Remove entry from Static Access Control List Table of Multicast Operations
   Profile ME

   \param[in] ctx        OMCI API context pointer
   \param[in] me_id      Managed Entity identifier
   \param[in] table_idx  Table index
*/
enum omci_api_return
omci_api_multicast_operations_profile_static_acl_table_entry_remove(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t table_idx);

/** Retrieve Lost Group List Table of Multicast Operations Profile ME

   \param[in]  ctx        OMCI API context pointer
   \param[in]  me_id      Managed  Entity identifier
   \param[out] entry_num  Number of entries pointed to by entries
   \param[out] entries    The pointer to the first entry
*/
enum omci_api_return
omci_api_multicast_operations_profile_lost_group_list_table_get(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	unsigned int *entry_num,
	struct omci_api_multicast_operations_profile_lost_group_list_table_entry
	**entries);

/** @} */

/** @} */

__END_DECLS

#endif
