/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(WIN32) && !defined(NUCLEUS_PLUS)

/** \file
   This file contains the IFXOS Layer implementation for Win32 - 
   Time and Wait.
*/

/* ============================================================================
   IFX Win32 adaptation - Global Includes
   ========================================================================= */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "ifx_types.h"
#include "ifxos_time.h"

/* ============================================================================
   IFX Win32 adaptation - Time and Wait
   ========================================================================= */
/** \addtogroup IFXOS_TIME_WIN32
@{ */

#if (defined(IFXOS_HAVE_TIME_SLEEP_US) && (IFXOS_HAVE_TIME_SLEEP_US == 1))

/**
   Win32 - Sleep a given time in [us].

\par Implementation
   Use the Win32 scheduler to set the caller task into "sleep".

\attention
   The implementation will sleep mili seconds. u-seconds not supported.

\param
   sleepTime_us   Time to sleep [us]

\return
   None.
\remarks
   Available Application Space
*/
IFX_void_t IFXOS_USecSleep(
               IFX_time_t sleepTime_us)
{
   Sleep(sleepTime_us);
   return;
}
#endif

#if (defined(IFXOS_HAVE_TIME_SLEEP_MS) && (IFXOS_HAVE_TIME_SLEEP_MS == 1))

/**
   Win32 - Sleep a given time in [ms].

\par Implementation
   Use the Win32 scheduler to set the caller task into "sleep".

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
   Sleep(sleepTime_ms);
   return;
}
#endif


#if (defined(IFXOS_HAVE_TIME_SLEEP_SEC) && (IFXOS_HAVE_TIME_SLEEP_SEC == 1))
/**
   Win32 - Sleep a given time in [seconcds].

\par Implementation
   Use Sleep

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
   Sleep ((DWORD)sleepTime_sec * 1000);

   return;
}
#endif


#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS == 1))
/**
   Win32 - Get the elapsed time in [ms].

\par Implementation
   based on time - ms ?

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
   time_t nTime = 0;
   
   time(&nTime);

   nTime *= 1000;

   if ( (refTime_ms == 0) || ((IFX_int32_t)refTime_ms > nTime) )
   {
      return nTime;
   }

   return (nTime - refTime_ms);
}
#endif

#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC == 1))
/**
   Win32 - Get the elapsed time since startup in [seconds]

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
   time_t nTime = 0;
   
   time(&nTime);

   if ( (refTime_sec == 0) || ((IFX_int32_t)refTime_sec > nTime) )
   {
      return nTime;
   }

   return (nTime - refTime_sec);
}
#endif

#if (defined(IFXOS_HAVE_TIME_SYS_TIME_GET) && (IFXOS_HAVE_TIME_SYS_TIME_GET == 1))
/**
   Win32 - Reads the actual system time.

\return
   Returns the actual system time in seconds.
*/
IFX_time_t IFXOS_SysTimeGet(void)
{
   return (IFX_time_t)time(NULL);
}
#endif

/** @} */

#endif      /* #ifdef WIN32 */

