#ifndef _IFXOS_ECOS_EVENT_H
#define _IFXOS_ECOS_EVENT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for Event Synchronisation and Signalisation.
*/

/** \defgroup IFXOS_SYNC_ECOS Synchronisation.

   This Group collect the eCos synchronisation and signaling mechanism used within 
   IFXOS.

\par Task level Syncronisation
   For synchronisation on task level a "Event feature" is provided.

\note
   The intention of these signaling feature is to communicate between different
   tasks within the driver space or within the applicaton space.

\ingroup IFXOS_LAYER_ECOS
*/

/** \defgroup IFXOS_EVENT_ECOS Event Synchronisation (eCos).

   This Group contains the eCos Event definitions and function for 
   communication of tasks.

\par Implementation
   The event handling is based on eCos events.

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

/** IFX eCos adaptation - support "EVENT feature" */
#ifndef IFXOS_HAVE_EVENT
#  define IFXOS_HAVE_EVENT                           1
#endif

/* ============================================================================
   IFX eCos adaptation - EVENT types
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_ECOS
@{ */

/** eCos - EVENT, type for synchronisation. */
typedef struct
{
   /** event object */
   cyg_flag_t object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_event_t; 

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_EVENT_H */

