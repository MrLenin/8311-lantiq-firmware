/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_timer_h
#define _drv_onu_timer_h

#include "drv_onu_std_defs.h"

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_TIMER_INTERNAL Timer Interface
   @{
*/

EXTERN_C_BEGIN

/** dummy timer to ensure the state tranistion in state O1 */
#define ONU_TIMER_TO0			0x00

/** PLOAM TO1 timer

   The event is generated when the activation procedure is not completed within
   a certain time period. This event generates a state transition to Standby
   state (O2).  The value of T01 is 10s. */
#define ONU_TIMER_TO1			0x01
/** PLOAM TO2 timer

   The event is generated when the POPUP message is not received in the
   POPUP-state within a certain time period.  This event generates a state
   transition to Initial-state (01). The proposed value of TO2 is 100 ms. */
#define ONU_TIMER_TO2			0x02
/** Counter Update */
#define ONU_TIMER_COUNTER		0x03
/** Poll the lan status */
#define ONU_TIMER_LAN_POLL		0x04
/** Poll the lan port status */
#define ONU_TIMER_LAN_PORT_POLL		0x05
/** Aging process trigger*/
#define ONU_TIMER_AGING_TRIG		0x06
/** Data stuck watchdog  */
#define ONU_TIMER_STUCK_WD		0x07
/** Maximum of used timers */
#define ONU_MAX_TIMER			0x08
/** Default PLOAM TO1 timeout value */
#define ONU_DEFAULT_TIMER_TO1_VALUE    (11*1000)
/** Default PLOAM TO2 timeout value */
#define ONU_DEFAULT_TIMER_TO2_VALUE    (100)
/** PLOAM kick in timer */
#define ONU_TIMER_COUNTER_VALUE        (1000)
/** lan timer */
#define ONU_TIMER_LAN_POLL_VALUE       (500)
/** lan port timer */
#define ONU_TIMER_LAN_PORT_POLL_VALUE  (500)
/** sync poll timer */
#define ONU_TIMER_SYNC_VALUE           (1000)
/** Data stuck watchdog timer */
#define ONU_TIMER_STUCK_WD_VALUE	(1000)
void onu_timer_start(const uint32_t timer_no, uint32_t timeout);
void onu_timer_stop(const uint32_t timer_no);

/*! @} */
/*! @} */

EXTERN_C_END
#endif
