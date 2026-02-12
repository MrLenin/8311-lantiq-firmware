#ifndef _IFXOS_ECOS_MUTEX_H
#define _IFXOS_ECOS_MUTEX_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for Mutex handling.
*/

/** \defgroup IFXOS_MUTEX_ECOS Mutex(eCos).

   This Group contains the eCos Mutex definition.

\par Implementation
   The current implementation is based on a binary semaphore and does 
   not allow recursive calls.

\attention
   A call to get the MUTEX is not interuptible.
\attention
   Do not use create and get MUTEX on interrupt level.

\ingroup IFXOS_SYNC_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */
#include <pkgconf/system.h>
#include <cyg/kernel/kapi.h>  /* All the kernel specific stuff like cyg_flag_t, ... */

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - support "MUTEX feature" */
#ifndef IFXOS_HAVE_MUTEX
#  define IFXOS_HAVE_MUTEX                            1
#endif

/* ============================================================================
   IFX eCos adaptation - MUTEX types
   ========================================================================= */
/** \addtogroup IFXOS_MUTEX_ECOS
@{ */


/** eCos - MUTEX, type for synchronisation. */
typedef struct
{
   /** mutex identifier */
   cyg_mutex_t object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_mutex_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_MUTEX_H */

