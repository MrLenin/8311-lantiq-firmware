/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - time handling (Kernel Space)
   ========================================================================= */

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel 
   Time and Sleep.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */

#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#include <linux/sched.h>
#include <asm/delay.h> 
#include <linux/delay.h>

#include "ifx_types.h"
#include "ifxos_time.h"


/* ============================================================================
   IFX Linux adaptation - Kernel time handling
   ========================================================================= */

/** \addtogroup IFXOS_TIME_LINUX_DRV
@{ */
#if (defined(IFXOS_HAVE_TIME_SLEEP_US) && (IFXOS_HAVE_TIME_SLEEP_US == 1))

/**
   LINUX Kernel - Sleep a given time in [us].

\par Implementation
   In case that the system is not calibrated, a calibration will be done.
   The "sleeping" will be performed by looping for a certain amount of loops. Therefore
   no scheduler is involved.

\attention
   The implementation is designed as "busy wait", the scheduler will not be called.

\param
   sleepTime_us   Time to sleep [us]

\return
   None.

\remark
   Available in 
   - Driver space
*/
IFX_void_t IFXOS_USecSleep(
               IFX_time_t sleepTime_us)
{
   udelay(sleepTime_us);

   return;
}
#endif


#if (defined(IFXOS_HAVE_TIME_SLEEP_MS) && (IFXOS_HAVE_TIME_SLEEP_MS == 1))

/**
   LINUX Kernel - Sleep a given time in [ms].

\attention
   The sleep requires a "sleep wait". "busy wait" implementation will not work.

\par Implementation
   Within the Kernel we use the LINUX scheduler to set the thread into "sleep".

\param
   sleepTime_ms   Time to sleep [ms]

\return
   None.

\remark
   Available in 
   - Driver space
*/
IFX_void_t IFXOS_MSecSleep(
               IFX_time_t sleepTime_ms)
{
   /* current->state = TASK_INTERRUPTIBLE; */
   set_current_state(TASK_INTERRUPTIBLE);
   schedule_timeout(HZ * (sleepTime_ms) / 1000);

   return;
}
#endif

#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS == 1))
/**
   LINUX Kernel - Get the elapsed time in [ms].

\par Implementation
   Based on the HZ and jiffies defines we calculate the elapsed time since 
   startup or based on the given ref-time.

\param
   refTime_ms  Reference time to calculate the elapsed time in [ms].

\return 
   Elapsed time in [ms] based on the given reference time

\remark
   Provide refTime_ms = 0 to get the current elapsed time. For messurement provide
   the current time as reference.
*/
IFX_time_t IFXOS_ElapsedTimeMSecGet(
               IFX_time_t refTime_ms)
{
   IFX_time_t currTime_ms = 0;

   currTime_ms = (IFX_time_t)(jiffies * 1000 / HZ);

   return (currTime_ms > refTime_ms) ? (currTime_ms - refTime_ms) 
                                     : (refTime_ms - currTime_ms);
}
#endif

/** @} */

#ifdef MODULE
EXPORT_SYMBOL(IFXOS_USecSleep);
EXPORT_SYMBOL(IFXOS_MSecSleep);
EXPORT_SYMBOL(IFXOS_ElapsedTimeMSecGet);
#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */

