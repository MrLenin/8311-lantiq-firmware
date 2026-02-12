/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _omci_api_event_h
#define _omci_api_event_h

#include "omci_api_common.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_COMMON

   @{
*/

/** Start event handling

   \param[in] ctx OMCI API context pointer
*/
enum omci_api_return event_handling_start(struct omci_api_ctx *ctx);

/** Stop event handling

   \param[in] ctx OMCI API context pointer
*/
enum omci_api_return event_handling_stop(struct omci_api_ctx *ctx);

/** Notify OMCI stack about fatal error

   \param[in] ctx         OMCI API context pointer
   \param[in] class_id    Managed Entity class identifier
   \param[in] instance_id Managed Entity instance identifier
   \param[in] action      Action in which error occurred
   \param[in] error       Occurred error code
*/
enum omci_api_return error_notify(struct omci_api_ctx *ctx,
				  uint16_t class_id, uint16_t instance_id,
				  enum omci_api_action_type action,
				  enum omci_api_return ret);

/** @} */

__END_DECLS

#endif
