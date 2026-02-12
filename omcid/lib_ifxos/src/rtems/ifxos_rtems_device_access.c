/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains the IFXOS Layer Implementation Frame
   for RTEMS "Device Access".
*/

/*
   Customer-ToDo:
   For Device Access (open, close, ioctl) the OS specific functions have to be
   mapped here
   The IFXOS Dev IO interface is a generic interface for Device Access and is
   part of the IFX OS Layer which can be used for several OS.
   (If the IFXOS Dev IO Device Access is used no work is required here.)
*/

/* ============================================================================
   RTEMS adaptation frame - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_time.h"
#include "ifxos_device_access.h"

/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

/* ============================================================================
   RTEMS adaptation frame - User Space, Device Access
   ========================================================================= */

#if !defined(IFXOS_USE_DEV_IO) || (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 0))


/** \addtogroup IFXOS_DEVICE_ACCESS_RTEMS_APPL
@{ */

#if ( defined(IFXOS_HAVE_DEVICE_ACCESS) && (IFXOS_HAVE_DEVICE_ACCESS == 1) )
/**
   Open a device

\param
   pDevName    device name.

\return
   - If success, device descriptor used for further device access, else
   - IFX_ERROR in case of error.
*/
IFX_int32_t IFXOS_DeviceOpen(
               const IFX_char_t *pDevName)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      return open((const char*)pDevName, O_RDWR, 0644);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pDevName, IFX_ERROR);

   return 0;
}

/**
   Close a device

\param
   devFd    device file descriptor.

\return
   IFX_SUCCESS device close was successful.
   IFX_ERROR   in case of error.

*/
IFX_int32_t IFXOS_DeviceClose(
               const IFX_int32_t devFd)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      return close(devFd);
   */

   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, IFX_ERROR);

   return IFX_SUCCESS;
}

/**
   Write to a device

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      return write(devFd, (char *)pData, nSize_byte);
   */
   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, -1);
   IFXOS_RETURN_IF_POINTER_NULL(pData, -1);

   return nSize_byte;
}

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
   -1 in case of error
*/
IFX_int32_t IFXOS_DeviceRead(
               const IFX_int32_t    devFd,
               IFX_void_t           *pDataBuf,
               const IFX_uint32_t   nSize_byte)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      return read(devFd, (char *)pDataBuf, nSize_byte);
   */
   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, -1);
   IFXOS_RETURN_IF_POINTER_NULL(pDataBuf, -1);

   return nSize_byte;
}

/**
   Control a device

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

   return DSL_DRV_Ioctls(0,devCmd, param);
}

#endif      /* #if ( defined(IFXOS_HAVE_DEVICE_ACCESS) && (IFXOS_HAVE_DEVICE_ACCESS == 1) ) */

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
    Number of descriptors contained in the descriptor sets (0: no set or timeout).
   -1 in case of error.
*/
IFX_int32_t IFXOS_DeviceSelect(
               const IFX_uint32_t      max_fd,
               const IFXOS_devFd_set_t *read_fd_in,
               IFXOS_devFd_set_t       *read_fd_out,
               const IFX_uint32_t      timeout_ms)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      - setup timeval
      - setup fd_set arguments
      - call selecct like:
            select(max_fd, read_fd_out, NULL, NULL, &tv);
   */


   return 0;
}

/**
   Mark a descriptor in use.

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      FD_SET(devFd, pDevFdSet);
   */
   IFXOS_RETURN_VOID_IF_DEVFD_INVALID(devFd, IFX_NULL);
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDevFdSet, IFX_NULL);

   return;
}

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
               const IFXOS_devFd_set_t *pDevFdSet)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      return FD_ISSET(devFd, pDevFdSet);
   */

   IFXOS_RETURN_IF_DEVFD_INVALID(devFd, 0);
   IFXOS_RETURN_IF_POINTER_NULL(pDevFdSet, 0);

   return 0;
}

/**
   Clear descriptor set.

\param
   pDevFdSet   points to the descriptor mask.

*/
IFX_void_t IFXOS_DevFdZero(
               IFXOS_devFd_set_t *pDevFdSet)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         FD_ZERO(pDevFdSet);
         return;
   */

   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDevFdSet, IFX_NULL);

   return ;
}

#endif      /* #if ( defined(IFXOS_HAVE_DEVICE_ACCESS_SELECT) && (IFXOS_HAVE_DEVICE_ACCESS_SELECT == 1) ) */

/** @} */

#endif      /* #if !defined(IFXOS_USE_DEV_IO) || (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 0)) */

#endif      /* #ifdef RTEMS */



