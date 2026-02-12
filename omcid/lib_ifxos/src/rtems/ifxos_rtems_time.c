/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS
/** \file
   This file contains the IFXOS Layer implementation for RTEMS
   Time and Wait.
*/

/* ============================================================================
   RTEMS adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_time.h"
#include "ifxos_rt_if_check.h"

#include "xapi.h"

/* ============================================================================
   RTEMS adaptation - time handling
   ========================================================================= */

/** \addtogroup IFXOS_TIME_RTEMS
@{ */

#if (defined(IFXOS_HAVE_TIME_SLEEP_US) && (IFXOS_HAVE_TIME_SLEEP_US == 1))

/**
   RTEMS - Sleep a given time in [us].

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

\remarks
   Available in Driver and Application Space
*/
IFX_void_t IFXOS_USecSleep(
               IFX_time_t sleepTime_us)
{
   xtm_wkafter( sleepTime_us / 1000  );
   return;
}
#endif

#if (defined(IFXOS_HAVE_TIME_SLEEP_MS) && (IFXOS_HAVE_TIME_SLEEP_MS == 1))

/**
   RTEMS - Sleep a given time in [ms].

\par Implementation
   Use the RTEMS scheduler to set the caller task into "sleep".

\attention
   The sleep requires a "sleep wait". "busy wait" implementation will not work.

\param
   sleepTime_ms   Time to sleep [ms]

\return
   None.

\remarks
   sleepTime_ms = 0 force a rescheduling.

\remarks
   Available in Driver and Application Space
*/
IFX_void_t IFXOS_MSecSleep(
               IFX_time_t sleepTime_ms)
{
   xtm_wkafter(sleepTime_ms);
   return;
}
#endif


#if (defined(IFXOS_HAVE_TIME_SLEEP_SEC) && (IFXOS_HAVE_TIME_SLEEP_SEC == 1))
/**
   RTEMS - Sleep a given time in [seconcds].

\par Implementation
   Use the RTEMS scheduler to set the caller task into "sleep".

\param
   sleepTime_sec  Time to sleep [sec]

\return
   None.

\remarks
   Available in Application Space
*/
IFX_void_t IFXOS_SecSleep(
               IFX_time_t sleepTime_sec)
{
   xtm_wkafter(sleepTime_sec*1000);

   return;
}
#endif



#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS == 1))
/**
   RTEMS - Get the elapsed time in [ms].

\par Implementation
   Based on the "tickGet" and  "sysClkRateGet" function we calculate the
   elapsed time since startup or based on the given ref-time.

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
   IFX_uint32_t currTime_ms = 0;

   currTime_ms = xtm_gettime();

   return (currTime_ms > refTime_ms) ? (currTime_ms - refTime_ms) : (refTime_ms - currTime_ms);
}
#endif

#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC == 1))
/**
   RTEMS - Get the elapsed time since startup in [seconds]

\par Implementation
   Based on the "tickGet" and  "sysClkRateGet" function we calculate the
   elapsed time since startup or based on the given ref-time.

\param
   refTime_sec Reference time to calculate the elapsed time in [sec].

\return
   Elapsed time in [sec] based on the given reference time

\remark
   Provide refTime_sec = 0 to get the elapsed time since startup.

\remarks
   Available in Application Space.
*/
IFX_time_t IFXOS_ElapsedTimeSecGet(
               IFX_time_t refTime_sec)
{
   IFX_uint32_t currTime_sec = 0;
   IFX_uint32_t time_ms = 0;
   time_ms = xtm_gettime();
   currTime_sec = time_ms / 1000;

   if ( (refTime_sec == 0) || (refTime_sec > currTime_sec) )
   {
      return currTime_sec;
   }

   return (currTime_sec - refTime_sec);
}
#endif


#if (defined(IFXOS_HAVE_TIME_SYS_TIME_GET) && (IFXOS_HAVE_TIME_SYS_TIME_GET == 1))
/**
   RTEMS - Reads the actual system time.

\return
   Returns the actual system time in seconds.
*/
IFX_time_t IFXOS_SysTimeGet(void)
{
   IFX_uint32_t time_s;
   IFX_uint32_t time_ms;

   /* xtm_gettime gets the system time in msec. */
   time_ms = xtm_gettime();
   time_s = time_ms / 1000;
   return time_s;
}
#endif


/** @} */

#endif      /* #ifdef RTEMS */

