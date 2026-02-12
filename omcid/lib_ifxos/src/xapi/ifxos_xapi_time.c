/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains the IFXOS Layer implementation for XAPI 
   Time and Wait.
*/

/* ============================================================================
   IFX XAPI adaptation - Global Includes
   ========================================================================= */
#include <xapi.h>

#include "ifx_types.h"
#include "ifxos_common.h"     /* tick */
#include "ifxos_time.h"

#define DELAYLIB_DEBUG 0

#if (DELAYLIB_DEBUG == 1)
unsigned int delayLoop = 0;
#endif /* DELAYLIB_DEBUG */

/* ============================================================================
   IFX XAPI adaptation - time handling
   ========================================================================= */

/** \addtogroup IFXOS_TIME_XAPI
@{ */

#if (defined(IFXOS_HAVE_TIME_SLEEP_US) && (IFXOS_HAVE_TIME_SLEEP_US == 1))

/**
   VxWorks - Sleep a given time in [us].

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
#if (DELAYLIB_DEBUG == 0)
   static unsigned int delayLoop = 0;
#endif /* (DELAYLIB_DEBUG == 0) */
   unsigned int ix;
   unsigned int iy;
   
   if (delayLoop == 0 || sleepTime_us == (unsigned int)0xffffffff)      /* need calibration?          */
   {
       unsigned int maxLoop;
       unsigned int start = 0;
       unsigned int stop = 0;
       unsigned int mpt = 1000; /*(1000 * 1000) / IFXOS_TICKS_PER_SECOND;*/ /* microsecs per tick     */
   
       for (delayLoop = 1; delayLoop < 0x1000 && stop == start; delayLoop<<=1)
       {
           /* wait for clock turn over */
           for (stop = start = xtm_gettime (); start == stop; start = xtm_gettime ());
   
           IFXOS_USecSleep (mpt);            /* single recursion                   */
           stop = xtm_gettime ();
       }
   
       maxLoop = delayLoop / 2;        /* loop above overshoots              */
       #if (DELAYLIB_DEBUG == 1)
       printf ("maxLoop = %d\n", maxLoop);
       #endif /* DELAYLIB_DEBUG */
       start = 0;
       stop = 0;
       if (delayLoop < 4)
           delayLoop = 4;
       for (delayLoop /= 4; delayLoop<maxLoop && stop == start; delayLoop++)
       {
           /* wait for clock turn over */
           for (stop = start = xtm_gettime (); start == stop; start = xtm_gettime ());
   
           IFXOS_USecSleep (mpt);            /* single recursion                   */
           stop = xtm_gettime ();
       }
       #if (DELAYLIB_DEBUG == 1)
       printf ("delayLoop = %d\n", delayLoop);
       #endif /* DELAYLIB_DEBUG */
   }
   
   for (iy = 0; iy < sleepTime_us; iy++)
   {
       for (ix = 0; ix < delayLoop; ix++);
   }
}
#endif

#if (defined(IFXOS_HAVE_TIME_SLEEP_MS) && (IFXOS_HAVE_TIME_SLEEP_MS == 1))

/**
   XAPI - Sleep a given time in [ms].

\par Implementation
   Use the XAPI scheduler to set the caller task into "sleep".

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
   xtm_wkafter (sleepTime_ms);
}
#endif

#if (defined(IFXOS_HAVE_TIME_SLEEP_SEC) && (IFXOS_HAVE_TIME_SLEEP_SEC == 1))
/**
   XAPI - Sleep a given time in [seconds].

\par Implementation
   Use the XAPI scheduler to set the caller task into "sleep".

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
   xtm_wkafter (sleepTime_sec * 1000);
}
#endif


#if (defined(IFXOS_HAVE_TIME_SYS_TIME_GET) && (IFXOS_HAVE_TIME_SYS_TIME_GET == 1))
/**
   XAPI - Reads the actual system time.

\return
   Returns the actual system time in seconds.
*/
IFX_time_t IFXOS_SysTimeGet(void)
{
   return (xtm_gettime()/1000);
}
#endif

#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS == 1))
/**
   XAPI - Reads the actual system time.

\return
   Returns the actual system time in miliseconds.
*/
IFX_time_t IFXOS_ElapsedTimeMSecGet( 
               IFX_time_t refTime_ms)
{
   IFX_time_t currTime_ms;
   
   currTime_ms = xtm_gettime();
   
   return (currTime_ms > refTime_ms) ? (currTime_ms - refTime_ms) : (refTime_ms - currTime_ms);

}
#endif


/** @} */
#endif      /* #ifdef XAPI */

