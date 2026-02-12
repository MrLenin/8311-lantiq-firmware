/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_call_control_pmhd
#define _omci_api_call_control_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_CALL_CONTROL_PMHD Call Control PMHD

   This managed entity collects performance monitoring data related to the call
   control channel.

   Instances of this managed entity are created and deleted by the OLT.

   @{
*/

/** Retrieve current value of Call Control PMHD counters

   \param[in]  ctx				OMCI API context pointer
   \param[in]  me_id				Managed Entity identifier
   \param[out] call_setup_failures		Call setup failures
   \param[out] call_setup_timer			Call setup timer
   \param[out] call_terminate_failures		Call terminate failures
   \param[out] analog_port_releases		Analog port releases
   \param[out] analog_port_offhook_timer	Analog port off-hook timer
*/
enum omci_api_return
omci_api_call_control_pmhd_cnt_get(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint32_t *call_setup_failures,
				   uint32_t *call_setup_timer,
				   uint32_t *call_terminate_failures,
				   uint32_t *analog_port_releases,
				   uint32_t *analog_port_offhook_timer);

/** @} */

/** @} */

__END_DECLS

#endif
