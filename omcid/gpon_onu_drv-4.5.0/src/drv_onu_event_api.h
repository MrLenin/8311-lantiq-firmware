/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_event_api_h
#define _drv_onu_event_api_h

#include "drv_onu_event_interface.h"

/** \defgroup MAPI_REFERENCE_INTERNAL Management API Reference - Internals
   @{
*/

/** \defgroup ONU_EVENT_API_INTERNAL Internal Event Interface
   @{
*/

enum onu_errorcode onu_event_enable_set(struct onu_device *p_dev,
					const struct onu_event_mask *param);
enum onu_errorcode onu_event_enable_get(struct onu_device *p_dev,
					struct onu_event_mask *param);

/*! @} */

/*! @} */

EXTERN_C_END
#endif
