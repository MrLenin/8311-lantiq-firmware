/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_multicast_gem_interworking_tp
#define _omci_api_me_multicast_gem_interworking_tp

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MULTICAST_GEM_INTERWORKING_TP Multicast GEM - Interworking Termination Port

   An instance of this Managed Entity represents a point in the ONU where a
   multicast service interworks with the GEM layer. At this point, a multicast
   bit stream is reconstructed from GEM packets.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/** Update Multicast GEM Interworking TP ME resources

    \note Enable Managed Entity identifier mapping to driver index and
    initialize corresponding driver structures when it is called first time
    for given ME ID

   \param[in] ctx     OMCI API context pointer
   \param[in] me_id   Managed Entity identifier
   \param[in] ctp_ptr CTP pointer
*/
enum omci_api_return
omci_api_multicast_gem_interworking_tp_update(struct omci_api_ctx *ctx,
					      uint16_t me_id,
					      uint16_t ctp_ptr);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_multicast_gem_interworking_tp_destroy(struct omci_api_ctx *ctx,
					       uint16_t me_id);

/** Add entry to Multicast GEM Interworking TP ME resources

   \param[in] ctx                              OMCI API context pointer
   \param[in] me_id                            Managed Entity identifier
   \param[in] gem_port_id                      GEM port ID
   \param[in] secondary_idx                    Secondary index
   \param[in] ip_multicast_address_range_start IP multicast address range start
   \param[in] ip_multicast_address_range_stop  IP multicast address range stop

   \note The first four bytes of each entry are treated as the index of the
         list. The secondary index allows the table to contain more than a
         single range for a given GEM port.
*/
enum omci_api_return
omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_add(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t gem_port_id,
	uint16_t secondary_idx,
	uint32_t ip_multicast_address_range_start,
	uint32_t ip_multicast_address_range_stop);

/** Remove entry from Multicast GEM Interworking TP ME resources

   \param[in] ctx           OMCI API context pointer
   \param[in] me_id         Managed Entity identifier
   \param[in] gem_port_id   GEM port ID
   \param[in] secondary_idx Secondary index
*/
enum omci_api_return
omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_remove(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t gem_port_id,
	uint16_t secondary_idx);

/** @} */

/** @} */

__END_DECLS

#endif
