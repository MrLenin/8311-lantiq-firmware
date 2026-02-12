#ifndef _IFXOS_VXWORKS_MUTEX_H
#define _IFXOS_VXWORKS_MUTEX_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains VxWorks definitions for Mutex handling.
*/

/** \defgroup IFXOS_MUTEX_VXWORKS Mutex (VxWorks).

   This Group contains the VxWorks Mutex definition.

\par Implementation


\attention
   A call to get the MUTEX is not interuptible.
\attention
   Do not use create and get MUTEX on interrupt level.

\ingroup IFXOS_SYNC_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include <vxWorks.h>
#include <semLib.h>

#include "ifx_types.h"

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - support "MUTEX feature" */
#ifndef IFXOS_HAVE_MUTEX
#  define IFXOS_HAVE_MUTEX                            1
#endif

/* ============================================================================
   IFX VxWorks adaptation - MUTEX types
   ========================================================================= */
/** \addtogroup IFXOS_MUTEX_VXWORKS
@{ */

/** VxWorks - MUTEX, type for synchronisation. */
typedef struct
{
   /** mutex identifier */
   SEM_ID object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_mutex_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_MUTEX_H */

