/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_onu_loop_detection
#define _omci_api_me_onu_loop_detection

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME
   @{
*/

/** \defgroup OMCI_API_ME_ONU_LOOP_DETECTION ONU Loop Detection
   Vendor-specific ME (~65528) for LAN-side loop detection.
   @{
*/

/** Create loop detection resources for an ME instance.
    Sets up GPE exception handling for loop detection ethertype (0xFFFA).

    \param[in] ctx    OMCI API context pointer
    \param[in] me_id  Managed Entity identifier
*/
enum omci_api_return
omci_api_onu_loop_detection_create(struct omci_api_ctx *ctx,
				   uint16_t me_id);

/** Update loop detection configuration for a UNI port.

    \param[in] ctx            OMCI API context pointer
    \param[in] me_id          Managed Entity identifier
    \param[in] uni_me_id      PPTP Ethernet UNI ME identifier
    \param[in] enable         Loop detection enable (0=disable, non-zero=enable)
    \param[in] port_shutdown  Port shutdown on detection (0=no, non-zero=yes)
*/
enum omci_api_return
omci_api_onu_loop_detection_update(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint16_t uni_me_id,
				   uint16_t enable,
				   uint16_t port_shutdown);

/** Destroy loop detection resources for an ME instance.
    Logging only — no hardware cleanup needed (matches stock behavior).

    \param[in] ctx    OMCI API context pointer
    \param[in] me_id  Managed Entity identifier
*/
enum omci_api_return
omci_api_onu_loop_detection_destroy(struct omci_api_ctx *ctx,
				    uint16_t me_id);

/** Send a loop detection probe frame on a UNI port.

    \param[in] ctx         OMCI API context pointer
    \param[in] me_id       Managed Entity identifier
    \param[in] svlan       S-VLAN tag for the probe frame
    \param[in] cvlan       C-VLAN tag for the probe frame
    \param[in] uni_me_id   PPTP Ethernet UNI ME identifier
*/
enum omci_api_return
omci_api_onu_loop_detection_packet_send(struct omci_api_ctx *ctx,
					uint16_t me_id,
					uint16_t svlan,
					uint16_t cvlan,
					uint16_t uni_me_id);

/** @} */
/** @} */

__END_DECLS

#endif
