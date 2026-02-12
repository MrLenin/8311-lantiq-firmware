#ifndef _IFXOS_GENERIC_OS_DEVICE_ACCESS_H
#define _IFXOS_GENERIC_OS_DEVICE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains Generic OS definitions for Device Access.
*/

/** \defgroup IFXOS_DEVICE_ACCESS_GENERIC_OS_APPL Device Access (Generic OS)

   This Group contains the Generic OS "Device Access" definitions and function. 

   The standard system calles (open, close, etc) are mapped to devcie specific
   functions.

   The poll/select mechanism is supported. This requires OS support and a
   corresponding implementation on application and driver side.

\remarks
   The IFX OS "Dev IO" layer provides a generic IO Device Access Layer. 
   If the "Dev IO" is used the IFX OS Dev IO implementation for Device Access 
   can be used.

\ingroup IFXOS_LAYER_GENERIC_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Generic OS adaptation - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/


#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
#  include "ifxos_device_io.h"
#endif


/* ============================================================================
   IFX Generic OS adaptation - replace with the OS specific defines
   ========================================================================= */
/*
   Customer-ToDo:
   Fill with your customer os implementation: 
   - set your own define or 
   - include the corresponding header.
*/
#define	IFXOS_IOC_VOID	                  0x20000000
#define	IFXOS_DEFMACRO_IO(x,y)	         (IFXOS_IOC_VOID|((x)<<8)|y)


/* ============================================================================
   IFX Generic OS adaptation - supported features
   ========================================================================= */

/** IFX Generic OS adaptation - User support "device access" */
#define IFXOS_HAVE_DEVICE_ACCESS                 1
/** IFX Generic OS adaptation - User support "device access - select" */
#define IFXOS_HAVE_DEVICE_ACCESS_SELECT          1

/* ============================================================================
   IFX Generic OS adaptation - types
   ========================================================================= */

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))

/** customer OS User - select, type fd_set for device select. */
typedef DEVIO_fd_set_t       IFXOS_devFd_set_t;

#else
/*
   Customer-ToDo:
   If DEVIO is not used, fill with your customer os implementation: 
   - include the corresponding header.
   - set your own define or 
*/

#define GENERIC_OS_MAXFDS       64
/**
 * Device descriptor structure. Used by DEVIO_select() call .
 */
typedef struct
{
   /**
    * - set to 1 if device is marked
    * - set to 0 if device is not selected
    */
   unsigned int fds[GENERIC_OS_MAXFDS];
} IFXOS_customerOS_DevFd_set_t;

/** customer OS User - select, type fd_set for device select. */
typedef IFXOS_customerOS_DevFd_set_t       IFXOS_devFd_set_t;

#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_DEVICE_ACCESS_H */


