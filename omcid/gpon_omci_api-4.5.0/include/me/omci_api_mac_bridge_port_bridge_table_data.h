/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_port_bridge_table_data_h
#define _omci_api_me_mac_bridge_port_bridge_table_data_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA MAC Bridge Port - Bridge Table Data

   This Managed Entity reports status data associated with a MAC bridge port.
   The ONU automatically creates or deletes an instance of this Managed Entity
   upon the creation or deletion of a MAC bridge port configuration data.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the MAC bridge port configuration data ME. */

/** Bridge Table entry type definition used in
    \ref omci_api_mac_bridge_port_bridge_table_data_bridge_table_get
*/
struct omci_api_mac_bridge_port_bridge_table_data_bridge_table_entry {
	/** Information */
	union {
		struct {
			/** Age in seconds (1..4095) */
			uint16_t age:12;
			/** Reserved bit */
			uint16_t reserved2:1;
			/** Dynamic/static bit*/
			uint16_t type:1;
			/** Reserved bit */
			uint16_t reserved1:1;
			/** Filter/forward bit */
			uint16_t mode:1;
		} info_fields;
		uint16_t info_byte;
	} information;

	/** MAC address */
	uint8_t p_mac_adress[6];
};

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_mac_bridge_port_bridge_table_data_create(struct omci_api_ctx *ctx,
						  uint16_t me_id);

/** Disable Managed Entity identifier mapping to driver index and clear
   corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_mac_bridge_port_bridge_table_data_destroy(struct omci_api_ctx *ctx,
						   uint16_t me_id);

/** Retrieve entry from MAC Bridge Port Bridge Table data ME resources

   \param[in] ctx		OMCI API context pointer
   \param[in] me_id		Managed Entity identifier
   \param[in] bridge_me_id	MAC Bridge Service Profile identifier
   \param[out] entry_num	Number of entries pointed to by entries
   \param[out] entries		The pointer to the first entry

   \note
   The memory for Entries should be de-allocated via call to
   \ref omci_api_mac_bridge_port_bridge_table_data_bridge_table_free
*/
enum omci_api_return
omci_api_mac_bridge_port_bridge_table_data_bridge_table_get(struct omci_api_ctx
							    *ctx,
							    uint16_t me_id,
							    uint16_t bridge_me_id,
							    unsigned int *entry_num,
							    struct omci_api_mac_bridge_port_bridge_table_data_bridge_table_entry **entries);

/** Free MAC Bridge Port Bridge Table resources

   \param[in] ctx		OMCI API context pointer
   \param[in] me_id		Managed Entity identifier
   \param[in] bridge_me_id	MAC Bridge Service Profile identifier
   \param[out] entry_num	Number of entries pointed to by entries
   \param[out] entries		The pointer to the first entry
 */
void
omci_api_mac_bridge_port_bridge_table_data_bridge_table_free(struct omci_api_ctx *ctx,
							     uint16_t me_id,
							     uint16_t bridge_me_id,
							     unsigned int *entry_num,
							     struct omci_api_mac_bridge_port_bridge_table_data_bridge_table_entry **entries);

/** @} */

/** @} */

__END_DECLS

#endif
