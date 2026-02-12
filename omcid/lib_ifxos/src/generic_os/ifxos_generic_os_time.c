/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS
/** \file
   This file contains the IFXOS Layer implementation for GENERIC_OS 
   Time and Wait.
*/

/* ============================================================================
   IFX GENERIC_OS adaptation - Global Includes
   ========================================================================= */

/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"
#include "ifxos_time.h"
#include "ifxos_rt_if_check.h"

/* ============================================================================
   IFX GENERIC_OS adaptation - time handling
   ========================================================================= */

/** \addtogroup IFXOS_TIME_GENERIC_OS
@{ */

#if (defined(IFXOS_HAVE_TIME_SLEEP_US) && (IFXOS_HAVE_TIME_SLEEP_US == 1))

/**
   GENERIC_OS - Sleep a given time in [us].

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   return;
}
#endif

#if (defined(IFXOS_HAVE_TIME_SLEEP_MS) && (IFXOS_HAVE_TIME_SLEEP_MS == 1))

/**
   GENERIC_OS - Sleep a given time in [ms].

\par Implementation
   Use the GENERIC_OS scheduler to set the caller task into "sleep".

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   return;
}
#endif


#if (defined(IFXOS_HAVE_TIME_SLEEP_SEC) && (IFXOS_HAVE_TIME_SLEEP_SEC == 1))
/**
   GENERIC_OS - Sleep a given time in [seconcds].

\par Implementation
   Use the GENERIC_OS scheduler to set the caller task into "sleep".

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   return;
}
#endif



#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS == 1))
/**
   GENERIC_OS - Get the elapsed time in [ms].

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

   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   return (currTime_ms > refTime_ms) ? (currTime_ms - refTime_ms) : (refTime_ms - currTime_ms);
}
#endif

#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC == 1))
/**
   GENERIC_OS - Get the elapsed time since startup in [seconds]

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

   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   if ( (refTime_sec == 0) || (refTime_sec > currTime_sec) )
   {
      return currTime_sec;
   }

   return (currTime_sec - refTime_sec);
}
#endif


#if (defined(IFXOS_HAVE_TIME_SYS_TIME_GET) && (IFXOS_HAVE_TIME_SYS_TIME_GET == 1))
/**
   GENERIC_OS - Reads the actual system time.

\return
   Returns the actual system time in seconds.
*/
IFX_time_t IFXOS_SysTimeGet(void)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   return 0;
}
#endif


/** @} */

#endif      /* #ifdef GENERIC_OS */

