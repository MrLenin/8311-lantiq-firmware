/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/


/** \file
   This file contains the IFXOS Layer implementation for LINUX Application 
   Device Access.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */
#include <stdio.h>

#if defined(LINUX) && !defined(IFXOS_USE_DEV_IO)

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_time.h"
#include "ifxos_device_access.h"
#include "ifxos_common.h"

/* ============================================================================
   IFX Linux adaptation - Application Space, Device Access
   ========================================================================= */

/** \addtogroup IFXOS_DEVICE_ACCESS_LINUX_APPL
@{ */

#if ( defined(IFXOS_HAVE_DEVICE_ACCESS) && (IFXOS_HAVE_DEVICE_ACCESS == 1) )
/**
   LINUX Application - Open a device

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

   return open((const char*)pDevName, O_RDWR, 0644);
}

/**
   LINUX Application - Close a device

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

   return close(devFd);
}

/**
   LINUX Application - Write to a device

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

   return write(devFd, pData, nSize_byte);
}

/**
   LINUX Application - Read from a device

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

   return read(devFd, (char *)pDataBuf, nSize_byte);
}

/**
   LINUX Application - Control a device

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

   return ioctl(devFd, devCmd, param);
}

#endif      /* #if ( defined(IFXOS_HAVE_DEVICE_ACCESS) && (IFXOS_HAVE_DEVICE_ACCESS == 1) ) */

#if ( defined(IFXOS_HAVE_DEVICE_ACCESS_SELECT) && (IFXOS_HAVE_DEVICE_ACCESS_SELECT == 1) )

/**
   LINUX Application - Wait for a device wake up. 

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
   IFXOS_devFd_set_t tmp;
   struct timeval tv;

   switch (timeout_ms)
   {
      case IFXOS_NO_WAIT:
         tv.tv_sec = 0;
         tv.tv_usec = 0;
         break;
      case IFXOS_WAIT_FOREVER:
         break;
      default:
         tv.tv_sec = timeout_ms / 1000;
         tv.tv_usec = (timeout_ms % 1000) * 1000; 
   }

   if(read_fd_in)
   {
      if(read_fd_out)
      {
         memcpy(read_fd_out, read_fd_in, sizeof(IFXOS_devFd_set_t));
         if (timeout_ms != IFXOS_WAIT_FOREVER)
            return select(max_fd, read_fd_out, NULL, NULL, &tv);
         else
            return select(max_fd, read_fd_out, NULL, NULL, NULL);
      }
      else
      {
         memcpy(&tmp, read_fd_in, sizeof(IFXOS_devFd_set_t));
         if (timeout_ms != IFXOS_WAIT_FOREVER)
            return select(max_fd, &tmp, NULL, NULL, &tv);
         else
            return select(max_fd, &tmp, NULL, NULL, NULL);
      }
   }
   else
   {
      IFXOS_MSecSleep(timeout_ms);
   }

   return 0;
}

/**
   LINUX Application - Mark a descriptor in use.

\param
   devfd       descriptor which will be set.
\param
   pDevFdSet   points to the set mask where the given descriptors will be set.

\return
   NONE
*/
IFX_void_t IFXOS_DevFdSet(
               IFX_uint32_t      devfd, 
               IFXOS_devFd_set_t *pDevFdSet)
{
   IFXOS_RETURN_VOID_IF_DEVFD_INVALID(devFd, IFX_NULL);
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDevFdSet, IFX_NULL);

   FD_SET(devfd, pDevFdSet);
}

/**
   LINUX Application - Check if a descriptor is set.

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

   return FD_ISSET(devFd, pDevFdSet);
}

/**
   LINUX Application - Clear descriptor set.

\param
   pDevFdSet   points to the descriptor mask.

\return
   NONE
*/
IFX_void_t IFXOS_DevFdZero(
               IFXOS_devFd_set_t *pDevFdSet)
{
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDevFdSet, IFX_NULL);

   FD_ZERO(pDevFdSet);
   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_DEVICE_ACCESS_SELECT) && (IFXOS_HAVE_DEVICE_ACCESS_SELECT == 1) ) */

/** @} */

#endif      /* #ifdef LINUX && !defined(IFXOS_USE_DEV_IO) */


