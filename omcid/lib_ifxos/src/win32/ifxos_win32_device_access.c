/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(WIN32) && !defined(NUCLEUS_PLUS) && !defined(IFXOS_USE_DEV_IO)

/** \file
   This file contains the IFXOS Layer implementation for Win32 - 
   Device Access.
*/

/* ============================================================================
   IFX Win32 adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_device_access.h"

/* ============================================================================
   IFX Win32 adaptation - Device Access
   ========================================================================= */
/** \addtogroup IFXOS_DEVICE_ACCESS_WIN32_APPL
@{ */

#if ( defined(IFXOS_HAVE_DEVICE_ACCESS) && (IFXOS_HAVE_DEVICE_ACCESS == 1) )
/**
   Win32 - Open a device

\param
   pDevName    device name.

\return
   - If success, device descriptor used for further device access, else
   - IFX_ERROR in case of error.
*/
IFX_int32_t IFXOS_DeviceOpen(
               const IFX_char_t *pDevName)
{
   IFXOS_RETURN_IF_POINTER_NULL(pDevName, IFX_ERROR);

   return IFX_ERROR;
}

/**
   Win32 - Close a device

\param
   devFd    device file descriptor.

\return
   IFX_SUCCESS device close was successful.
   IFX_ERROR   in case of error.

*/
IFX_int32_t IFXOS_DeviceClose(
               const IFX_int32_t devFd)
{
   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, IFX_ERROR);

   return IFX_ERROR;
}

/**
   Win32 - Write to a device

\param
   devFd          device file descriptor.
\param
   pData          points to the data to write.
\param
   nSize_byte     number of bytes to write.

\return
   Number of writen bytes (0: nothing written)
   -1 in case of error
*/
IFX_int32_t IFXOS_DeviceWrite(
               const IFX_int32_t    devFd, 
               const IFX_void_t     *pData, 
               const IFX_uint32_t   nSize_byte)
{
   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, -1);
   IFXOS_RETURN_IF_POINTER_NULL(pData, -1);

   return IFX_ERROR;
}

/**
   Win32 - Read from a device

\param
   devFd          device file descriptor.
\param
   pDataBuf       points to the buffer used to read the data.
\param
   nSize_byte     number of bytes to write.

\return
   Number of read bytes (0: nothing read)
   -1 in case of error
*/
IFX_int32_t IFXOS_DeviceRead(
               const IFX_int32_t    devFd, 
               IFX_void_t           *pDataBuf, 
               const IFX_uint32_t   nSize_byte)
{
   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, -1);
   IFXOS_RETURN_IF_POINTER_NULL(pDataBuf, -1);

   return IFX_ERROR;
}

/**
   Win32 - Control a device

\param
   devFd    device file descriptor.
\param
   devCmd   device command.
\param
   param    command parameters.

\return
   0 or >0 for command successful.
   -1  in case of error.
*/
IFX_int32_t IFXOS_DeviceControl(
               const IFX_int32_t    devFd, 
               const IFX_uint32_t   devCmd, 
               IFX_ulong_t          param)
{
   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, -1);

   return IFX_ERROR;
}
#endif      /* #if ( defined(IFXOS_HAVE_DEVICE_ACCESS) && (IFXOS_HAVE_DEVICE_ACCESS == 1) ) */

#if ( defined(IFXOS_HAVE_DEVICE_ACCESS_SELECT) && (IFXOS_HAVE_DEVICE_ACCESS_SELECT == 1) )
/**
   Win32 - Wait for a device wake up. 

\param
   max_fd      max devFd number to check.  
\param
   read_fd_in  contains the devFd for wakeup.
\param
   read_fd_out returns the waked up devFd.
\param
   timeout_ms  max time to wait [ms].

\return
    Number of descriptors contained in the descriptor sets (0: no set or timeout).
   -1 in case of error.
*/
IFX_int32_t IFXOS_DeviceSelect(
               const IFX_uint32_t      max_fd, 
               const IFXOS_devFd_set_t *read_fd_in, 
               IFXOS_devFd_set_t       *read_fd_out, 
               const IFX_uint32_t      timeout_ms)
{
   return IFX_ERROR;
}

/**
   Win32 - Mark a descriptor in use.

\param
   devFd       descriptor which will be set.
\param
   pDevFdSet   points to the set mask where the given descriptors will be set.

\return
   NONE
*/
IFX_void_t IFXOS_DevFdSet(
               IFX_uint32_t      devFd, 
               IFXOS_devFd_set_t *pDevFdSet)
{
   IFXOS_RETURN_VOID_IF_DEVFD_INVALID(devFd, IFX_NULL);
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDevFdSet, IFX_NULL);

   return;
}

/**
   Win32 - Check if a descriptor is set.

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
               const IFXOS_devFd_set_t *pDevFdSet)
{
   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, 0);
   IFXOS_RETURN_IF_POINTER_NULL(pDevFdSet, 0);

   return 0;
}

/**
   Win32 - Clear descriptor set.

\param
   pDevFdSet   points to the descriptor mask.

\return
   NONE
*/
IFX_void_t IFXOS_DevFdZero(
               IFXOS_devFd_set_t *pDevFdSet)
{
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDevFdSet, IFX_NULL);

   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_DEVICE_ACCESS_SELECT) && (IFXOS_HAVE_DEVICE_ACCESS_SELECT == 1) ) */

/** @} */

#endif      /* #if defined(WIN32) && defined(IFXOS_USE_DEV_IO) */

