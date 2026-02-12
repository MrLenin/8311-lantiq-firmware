/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX SunOS adaptation - time handling (Application Space)
   ========================================================================= */

#if defined(SUN_OS)

/** \file
   This file contains the IFXOS Layer implementation for SunOS Application 
   Time and Sleep.
*/

/* ============================================================================
   IFX SunOS adaptation - Global Includes - Application
   ========================================================================= */

#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "ifx_types.h"
#include "ifxos_time.h"


#ifdef IFXOS_DEBUG
#define IFXOS_STATIC
#else
#define IFXOS_STATIC   static
#endif

/* ============================================================================
   IFX SunOS adaptation - Application time handling
   ========================================================================= */
#if ( ((defined(IFXOS_HAVE_TIME_SLEEP_MS)  && (IFXOS_HAVE_TIME_SLEEP_MS == 1))) || \
      ((defined(IFXOS_HAVE_TIME_SLEEP_SEC) && (IFXOS_HAVE_TIME_SLEEP_SEC == 1))) )

typedef struct timespec IFXOS_timespec_t;

IFXOS_STATIC IFX_void_t IFXOS_NanoSleep(IFXOS_timespec_t *pTVal);

/**
   Function to sleep a defined time

\param
   pTVal points to the timeval struct containing the sleep time.

\return
   NONE
*/
IFXOS_STATIC IFX_void_t IFXOS_NanoSleep(IFXOS_timespec_t *pTVal)
{
   while (1)
   {
      /* Sleep for the time specified in pTVal. If interrupted by a
      signal, place the remaining time left to sleep back into pTVal. */
      int rval = nanosleep(pTVal, pTVal);
      if (rval == 0)
      {
         /* Completed the entire sleep time; all done. */
         return;
      }
      else 
      {
         if (errno == EINTR)
            /* Interrupted by a signal. Try again. */
            continue;
         else
            /* Some other error; bail out. */
            return;
      }
   }
}
#endif

/** \addtogroup IFXOS_TIME_SUN_OS_APPL
@{ */
#if (defined(IFXOS_HAVE_TIME_SLEEP_MS) && (IFXOS_HAVE_TIME_SLEEP_MS == 1))

/**
   SunOS Application - Sleep a given time in [ms].

\par Implementation
   - sleep for the given time by recall in case of interruption (signal).
     see "nanosleep" (<time.h>)

\param
   sleepTime_ms   Time to sleep [ms]

\return
   None.
*/
IFX_void_t IFXOS_MSecSleep(
               IFX_time_t sleepTime_ms)
{
   struct timespec tv;
   /* Construct the timespec from the number of whole seconds... */
   tv.tv_sec = sleepTime_ms/1000;
   /* ... and the remainder in nanoseconds. */
   tv.tv_nsec = (long) ((sleepTime_ms - (tv.tv_sec * 1000)) * 1000 * 1000);

   IFXOS_NanoSleep(&tv);

   return;
}
#endif

#if (defined(IFXOS_HAVE_TIME_SLEEP_SEC) && (IFXOS_HAVE_TIME_SLEEP_SEC == 1))
/**
   SunOS Application - Sleep a given time in [seconcds].

\par Implementation
   - sleep for the given time by recall in case of interruption (signal).
     see "nanosleep" (<time.h>)

\param
   sleepTime_sec  Time to sleep [sec]

\return
   None.
*/
IFX_void_t IFXOS_SecSleep(
               IFX_time_t sleepTime_sec)
{
   struct timespec tv;
   /* Construct the timespec from the number of whole seconds... */
   tv.tv_sec = sleepTime_sec;
   /* ... and the remainder in nanoseconds. */
   tv.tv_nsec = 0;

   IFXOS_NanoSleep(&tv);

   return;
}
#endif

#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS == 1))
/**
   SunOS Application - Get the elapsed time in [ms].

\par Implementation
   - get the current time from the system and calculate the return
     see "gettimeofday" (<sys/time.h>)

\param
   refTime_ms  Reference time to calculate the elapsed time in [ms].

\return 
   Elapsed time in [ms] based on the given reference time

\remark
   Provide refTime_ms = 0 to get the current elapsed time.
*/
IFX_time_t IFXOS_ElapsedTimeMSecGet(
               IFX_time_t refTime_ms)
{
   struct timeval tv;
   IFX_time_t   nTime_ms = 0;

   memset(&tv, 0, sizeof(tv));
   gettimeofday(&tv, IFX_NULL);
   nTime_ms = (IFX_time_t)(tv.tv_sec*1000 + (tv.tv_usec) / 1000);

   if ( (refTime_ms == 0) || (refTime_ms > nTime_ms) )
   {
      return nTime_ms;
   }

   return (nTime_ms - refTime_ms);
}
#endif

#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC == 1))
/**
   SunOS Application - Get the elapsed time in [sec].

\par Implementation
   - get the current time from the system and calculate the return
     see "gettimeofday" (<sys/time.h>)

\param
   refTime_sec Reference time to calculate the elapsed time in [sec].

\return 
   Elapsed time in [sec] based on the given reference time

\remark
   Provide refTime_sec = 0 to get the current elapsed time.
*/
IFX_time_t IFXOS_ElapsedTimeSecGet(
               IFX_time_t refTime_sec)
{
   struct timeval tv;
   IFX_time_t   nTime_sec = 0;

   memset(&tv, 0, sizeof(tv));
   gettimeofday(&tv, IFX_NULL);
   nTime_sec = (IFX_time_t)tv.tv_sec;

   if ( (refTime_sec == 0) || (refTime_sec > nTime_sec) )
   {
      return nTime_sec;
   }

   return (nTime_sec - refTime_sec);
}
#endif

#if (defined(IFXOS_HAVE_TIME_SYS_TIME_GET) && (IFXOS_HAVE_TIME_SYS_TIME_GET == 1))
/**
   SunOS Application - Reads the actual system time.

\return
   Returns the actual system time in seconds.
*/
IFX_time_t IFXOS_SysTimeGet(void)
{
   return (IFX_time_t)time(NULL);
}
#endif

/** @} */

#endif      /* #if defined(SUN_OS) */

