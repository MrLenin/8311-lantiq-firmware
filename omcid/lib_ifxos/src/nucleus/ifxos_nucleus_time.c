/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS
/** \file
   This file contains the IFXOS Layer implemantation for Nucleus 
   Time and Wait.
*/

/* ============================================================================
   IFX Nucleus adaptation - Global Includes
   ========================================================================= */

#include <nucleus.h>

#include "ifx_types.h"
#include "ifxos_time.h"
#include "ifxos_common.h"

/* ============================================================================
   IFX Nucleus adaptation - time handling
   ========================================================================= */

/** \addtogroup IFXOS_TIME_NUCLEUS
@{ */

#if (defined(IFXOS_HAVE_TIME_SLEEP_US) && (IFXOS_HAVE_TIME_SLEEP_US == 1))

/**
   Nucleus - Sleep a given time in [us].

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
    #if !DELAYLIB_DEBUG
    static unsigned int delayLoop = 0;
    #endif /* !DELAYLIB_DEBUG */
    unsigned int ix;
    unsigned int iy;

    if (delayLoop == 0 || sleepTime_us == (unsigned int)0xffffffff)      /* need calibration?          */
    {
        unsigned int maxLoop;
        unsigned int start = 0;
        unsigned int stop = 0;
        unsigned int mpt = (1000 * 1000) / IFXOS_TICKS_PER_SECOND; /* microsecs per tick     */

        for (delayLoop = 1; delayLoop < 0x1000 && stop == start; delayLoop<<=1)
        {
            /* wait for clock turn over */
            for (stop = start = NU_Retrieve_Clock (); start == stop; start = NU_Retrieve_Clock ());

            IFXOS_USecSleep (mpt);            /* single recursion                   */
            stop = NU_Retrieve_Clock ();
        }

        maxLoop = delayLoop / 2;        /* loop above overshoots              */
        #if DELAYLIB_DEBUG
        printf ("maxLoop = %d\n", maxLoop);
        #endif /* DELAYLIB_DEBUG */
        start = 0;
        stop = 0;
        if (delayLoop < 4)
            delayLoop = 4;
        for (delayLoop /= 4; delayLoop<maxLoop && stop == start; delayLoop++)
        {
            /* wait for clock turn over */
            for (stop = start = NU_Retrieve_Clock (); start == stop; start = NU_Retrieve_Clock ());

            IFXOS_USecSleep (mpt);            /* single recursion                   */
            stop = NU_Retrieve_Clock ();
        }
        #if DELAYLIB_DEBUG
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
   Nucleus - Sleep a given time in [ms].

\par Implementation
   Use the Nucleus scheduler to set the caller task into "sleep".

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
   NU_Sleep(IFXOS_MSEC_TO_TICK(sleepTime_ms));

   return;
}
#endif


#if (defined(IFXOS_HAVE_TIME_SLEEP_SEC) && (IFXOS_HAVE_TIME_SLEEP_SEC == 1))
/**
   Nucleus - Sleep a given time in [seconds].

\par Implementation
   Use the Nucleus scheduler to set the caller task into "sleep".

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
   NU_Sleep(IFXOS_MSEC_TO_TICK(sleepTime_sec*1000));

   return;
}
#endif



#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS == 1))
/**
   Nucleus - Get the elapsed time in [ms].

\par Implementation
   Based on the "NU_Retrieve_Clock" and  "IFXOS_TICKS_PER_SECOND" function we calculate the 
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
               IFX_uint32_t refTime_ms)
{
   IFX_time_t currTime_ms = 0;

   currTime_ms = (IFX_time_t)IFXOS_TICK_TO_MSEC(NU_Retrieve_Clock());

/*
   ToDo: Clarify what's here required.
*/
#if 1
   return (currTime_ms > refTime_ms) ? (currTime_ms - refTime_ms) : (refTime_ms - currTime_ms);
#else
   if ( (refTime_ms == 0) || (refTime_ms > currTime_ms) )
   {
      return currTime_ms;
   }

   return (currTime_ms - refTime_ms);
#endif
}
#endif

#if (defined(IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC) && (IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC == 1))
/**
   Nucleus - Get the elapsed time since startup in [seconds]

\par Implementation
   Based on the "NU_Retrieve_Clock" and  "IFXOS_TICKS_PER_SECOND" function we calculate the 
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
   IFX_time_t currTime_sec = 0;

   currTime_sec = (IFX_time_t)IFXOS_TICK_TO_MSEC(NU_Retrieve_Clock())/1000;

   if ( (refTime_sec == 0) || (refTime_sec > currTime_sec) )
   {
      return currTime_sec;
   }

   return (currTime_sec - refTime_sec);
}
#endif


#if (defined(IFXOS_HAVE_TIME_SYS_TIME_GET) && (IFXOS_HAVE_TIME_SYS_TIME_GET == 1))
/**
   Nucleus - Reads the actual system time.

\return
   Returns the actual system time in seconds.
*/
IFX_time_t IFXOS_SysTimeGet(void)
{
   return (IFX_time_t)IFXOS_TICK_TO_MSEC(NU_Retrieve_Clock())/1000;
}
#endif


/** @} */

#endif      /* #ifdef NUCLEUS_PLUS */

