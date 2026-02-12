#ifndef _IFXOS_DEVICE_ACCESS_H
#define _IFXOS_DEVICE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for the device access from a application via 
   corresponding system calles to the driver.
*/

/** \defgroup IFXOS_IF_DEVICE_ACCESS Device Access

   This Group contains the Device Access definitions and function. 

   To access the driver via standard system calls this calles are mapped.
   For the poll / select mechanism OS support is required. Furhter the 
   implementation on user and also on driver side is required.

\ingroup IFXOS_INTERFACE
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Global Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_device_access.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_device_access.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_device_access.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_device_access.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_device_access.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_device_access.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_device_access.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_device_access.h"
#  else
#     error "Device Access Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_device_access.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_device_access.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_device_access.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_device_access.h"
#  elif defined(WIN32)
#     include "ifxos_win32_device_access.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_device_access.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_device_access.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_device_access.h"
#  else
#     error "Device Access Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - Device Access
   ========================================================================= */

/** \addtogroup IFXOS_IF_DEVICE_ACCESS
@{ */

#if ( defined(IFXOS_HAVE_DEVICE_ACCESS) && (IFXOS_HAVE_DEVICE_ACCESS == 1) )

#ifndef _IO
   /** not defined by the OS header - use Own definition */
#  define _IO                 IFXOS_DEFMACRO_IO
#endif


/**
   Open a device

\param
   pDevName    device name.

\return
   - If success, device descriptor used for further device access, else
   - IFX_ERROR in case of error.
*/
IFX_int32_t IFXOS_DeviceOpen(
               const IFX_char_t *pDevName);

/**
   Open a device for reading only.

\param
   pDevName    device name.

\return
   - If success, device descriptor used for further device access, else
   - IFX_ERROR in case of error.
*/
IFX_int32_t IFXOS_DeviceOpenRead(
               const IFX_char_t *pDevName);

/**
   Close a device

\param
   devFd    device file descriptor.

\return
   IFX_SUCCESS device close was successful.
   IFX_ERROR   in case of error.

*/
IFX_int32_t IFXOS_DeviceClose(
               const IFX_int32_t devFd);

/**
   Write to a device

\param
   devFd          device file descriptor.
\param
   pData          points to the data to write.
\param
   nSize_byte     number of bytes to write.

\return
   Number of writen bytes (0: nothing written).
   negative value in case of error.
*/
IFX_int32_t IFXOS_DeviceWrite(
               const IFX_int32_t    devFd, 
               const IFX_void_t     *pData, 
               const IFX_uint32_t   nSize_byte);

/**
   Read from a device

\param
   devFd          device file descriptor.
\param
   pDataBuf       points to the buffer used to read the data.
\param
   nSize_byte     number of bytes to write.

\return
   Number of read bytes (0: nothing read)
   negative value in case of error.
*/
IFX_int32_t IFXOS_DeviceRead(
               const IFX_int32_t    devFd, 
               IFX_void_t           *pDataBuf, 
               const IFX_uint32_t   nSize_byte);

/**
   Control a device

\param
   devFd    device file descriptor.
\param
   devCmd   device command.
\param
   param    command parameters.

\return
   0 or a positive value (depends on the command) for successful.
   -1 or a negativ value in case of error.
*/
IFX_int32_t IFXOS_DeviceControl(
               const IFX_int32_t    devFd, 
               const IFX_uint32_t   devCmd, 
               IFX_ulong_t          param);

#endif /* #if ( defined(IFXOS_HAVE_DEVICE_ACCESS) && (IFXOS_HAVE_DEVICE_ACCESS 
== 1) ) */

#if ( defined(IFXOS_HAVE_DEVICE_ACCESS_SELECT) && (IFXOS_HAVE_DEVICE_ACCESS_SELECT == 1) )

/**
   Wait for a device wake up. 

\param
   max_fd      max devFd number to check.  
\param
   read_fd_in  contains the devFd for wakeup.
\param
   read_fd_out returns the waked up devFd.
\param
   timeout_ms  max time to wait [ms].

\return
   IFX_SUCCESS 
   IFX_ERROR   in case of error.
*/
IFX_int32_t IFXOS_DeviceSelect(
               const IFX_uint32_t      max_fd, 
               const IFXOS_devFd_set_t *read_fd_in, 
               IFXOS_devFd_set_t       *read_fd_out, 
               const IFX_uint32_t      timeout_ms);

/**
   Mark a descriptor in use.

\param
   devFd       device file descriptor which will be set.
\param
   pDevFdSet   points to the set mask where the given devFd will be set.

\return
   NONE
*/
IFX_void_t IFXOS_DevFdSet(
               IFX_uint32_t      devFd, 
               IFXOS_devFd_set_t *pDevFdSet);

/**
   Check if a descriptor is set.

\param
   devFd       device file descriptor which will be checked for set.
\param
   pDevFdSet   points to the set mask which contains the devFd for check.

\return
   True if the given descriptor is set witin the mask, else
   0 if the descriptor is not set.
*/
IFX_int_t IFXOS_DevFdIsSet(
               IFX_uint32_t            devFd, 
               const IFXOS_devFd_set_t *pDevFdSet);

/**
   Clear a descriptor mask.

\param
   pDevFdSet   points to the set mask.
*/
IFX_void_t IFXOS_DevFdZero(
               IFXOS_devFd_set_t *pDevFdSet);

#endif /* #if ( defined(IFXOS_HAVE_DEVICE_ACCESS_SELECT) && 
(IFXOS_HAVE_DEVICE_ACCESS_SELECT == 1) ) */


/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_DEVICE_ACCESS_H */

