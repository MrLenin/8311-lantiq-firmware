/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_port_filter_preassign_table
#define _omci_api_me_mac_bridge_port_filter_preassign_table

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE MAC Bridge Port - Filter Preassign Table

   This Managed Entity provides an alternate approach to address filtering from
   that supported through MAC bridge port filter table data. This alternate
   approach is useful when all groups of addresses are stored beforehand in the
   ONU, and this Managed Entity designates which groups are valid or invalid
   for filtering. On a circuit pack in which all groups of addresses are
   preassigned and stored locally, the ONU creates or deletes an instance of
   this Managed Entity automatically upon creation or deletion of a MAC bridge
   port configuration data ME.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the MAC bridge port configuration data ME. */

/** Supported values of parameters in
   \ref omci_api_mac_bridge_port_filter_preassign_table_create and
   \ref omci_api_mac_bridge_port_filter_preassign_table_update
*/
enum omci_api_mac_bridge_port_filter_preassign_table_operation {
	/** Forward packets */
	OMCI_API_MACBRIDGEPORTFILTERPREASSIGNTABLE_OPERATION_FORWARD = 0,
	/** Filter packets */
	OMCI_API_MACBRIDGEPORTFILTERPREASSIGNTABLE_OPERATION_FILTER = 1
};

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

   \param[in] ctx                            OMCI API context pointer
   \param[in] me_id                          ME identifier
   \param[in] ipv4_multicast_filtering       IPv4 multicast filtering
   \param[in] ipv6_multicast_filtering       IPv6 multicast filtering
   \param[in] ipv4_broadcast_filtering       IPv4 broadcast filtering
   \param[in] rarp_filtering                 RARP filtering
   \param[in] ipx_filtering                  IPX filtering
   \param[in] net_beui_filtering             NetBEUI filtering
   \param[in] apple_talk_filtering           AppleTalk filtering
   \param[in] bridge_managment_inf_filtering Bridge management information
                                             filtering
   \param[in] arp_filtering                  ARP filtering
   \param[in] pppoe_filtering                PPPoE filtering
*/
enum omci_api_return
omci_api_mac_bridge_port_filter_preassign_table_create(struct omci_api_ctx *ctx,
						       uint16_t me_id,
						       uint8_t
						       ipv4_multicast_filtering,
						       uint8_t
						       ipv6_multicast_filtering,
						       uint8_t
						       ipv4_broadcast_filtering,
						       uint8_t rarp_filtering,
						       uint8_t ipx_filtering,
						       uint8_t
						       net_beui_filtering,
						       uint8_t
						       apple_talk_filtering,
						       uint8_t
						       bridge_managment_inf_filtering,
						       uint8_t arp_filtering,
						       uint8_t pppoe_filtering);

/** Disable Managed Entity identifier mapping to driver index and clear
   corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_mac_bridge_port_filter_preassign_table_destroy(struct omci_api_ctx
							*ctx,
							uint16_t me_id);

/** Update MAC Bridge Port Filter Preassign Table ME resources

   \param[in] ctx                            OMCI API context pointer
   \param[in] me_id                          ME identifier
   \param[in] ipv4_multicast_filtering       IPv4 multicast filtering
   \param[in] ipv6_multicast_filtering       IPv6 multicast filtering
   \param[in] ipv4_broadcast_filtering       IPv4 broadcast filtering
   \param[in] rarp_filtering                 RARP filtering
   \param[in] ipx_filtering                  IPX filtering
   \param[in] net_beui_filtering             NetBEUI filtering
   \param[in] apple_talk_filtering           AppleTalk filtering
   \param[in] bridge_managment_inf_filtering Bridge management information
                                             filtering
   \param[in] arp_filtering                  ARP filtering
   \param[in] pppoe_filtering                PPPoE filtering
*/
enum omci_api_return
omci_api_mac_bridge_port_filter_preassign_table_update(struct omci_api_ctx *ctx,
						       uint16_t me_id,
						       uint8_t
						       ipv4_multicast_filtering,
						       uint8_t
						       ipv6_multicast_filtering,
						       uint8_t
						       ipv4_broadcast_filtering,
						       uint8_t rarp_filtering,
						       uint8_t ipx_filtering,
						       uint8_t
						       net_beui_filtering,
						       uint8_t
						       apple_talk_filtering,
						       uint8_t
						       bridge_managment_inf_filtering,
						       uint8_t arp_filtering,
						       uint8_t pppoe_filtering);

/** @} */

/** @} */

__END_DECLS

#endif
