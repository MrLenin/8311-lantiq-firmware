/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_port_filter_table_data
#define _omci_api_me_mac_bridge_port_filter_table_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_PORT_FILTER_TABLE_DATA MAC Bridge Port - Filter Table Data ME

   This Managed Entity organizes data associated with a bridge port. The ONU
   automatically creates or deletes an instance of this Managed Entity upon the
   creation or deletion of a MAC bridge port configuration data Managed Entity.

   \note The OLT should disable learning mode in the MAC bridge service profile
   before writing to the MAC filter table.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the MAC bridge port configuration data ME. */

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_mac_bridge_port_filter_table_data_create(struct omci_api_ctx *ctx,
						  uint16_t me_id);

/** Disable Managed Entity identifier mapping to driver index and clear
   corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_mac_bridge_port_filter_table_data_destroy(struct omci_api_ctx *ctx,
						   uint16_t me_id);

/** Add entry to MAC Bridge Port Filter Table Data ME resources

   \param[in] ctx            OMCI API context pointer
   \param[in] me_id          Managed Entity identifier
   \param[in] bridge_me_id   MAC Bridge Service Profile identifier
   \param[in] idx 	     Table entry index
   \param[in] filter_forward Filter/forward field of Filter byte
   \param[in] mac_address    MAC address
*/
enum omci_api_return
omci_api_mac_bridge_port_filter_table_data_mac_filter_table_entry_add(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t bridge_me_id,
	const uint8_t idx,
	const uint8_t filter_forward,
	const uint8_t mac_address[6]);

/** Remove entry from MAC Bridge Port Filter Table Data ME resources

   \param[in] ctx       OMCI API context pointer
   \param[in] me_id     Managed Entity identifier
   \param[in] bridge_me_id   MAC Bridge Service Profile identifier
   \param[in] idx    table entry index
*/
enum omci_api_return
omci_api_mac_bridge_port_filter_table_data_mac_filter_table_entry_remove(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t bridge_me_id,
	const uint8_t idx);

/** @} */

/** @} */

__END_DECLS

#endif
