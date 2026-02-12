/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel 
   Socket.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */
#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#include <linux/in.h>
#include <linux/net.h>
#include <asm/uaccess.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_socket.h"
#include "ifxos_debug.h"

/* ============================================================================
   IFX Linux adaptation - Kernel Space, Socket
   ========================================================================= */

/** \addtogroup IFXOS_SOCKET_LINUX
@{ */

#if ( defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1) )
/**
   LINUX Kernel - This function init and setup the socket feature on the system.

\par Implementation
   - Nothing under LINUX Kernel.

\remark
   This function is available for compatibility reasons. On systems where no
   seperate setup is required the function will be empty.

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketInit(void)
{
   return IFX_SUCCESS;
}


/**
   LINUX Kernel - This function cleanup the socket feature on the system.

\par Implementation
   - Nothing under LINUX Application.

\remark
   This function is available for compatibility reasons. On systems where no
   seperate setup is required the function will be empty.

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketCleanup(void)
{
   return IFX_SUCCESS;
}



/**
   LINUX Kernel - This function creates a TCP/IP, UDP/IP or raw socket.

\par Implementation
   - Create a PF_INET socket, no specified protocol.

\param
   socType     specifies the type of the socket
               - IFXOS_SOC_TYPE_STREAM: TCP/IP socket
               - IFXOS_SOC_TYPE_DGRAM:  UDP/IP socket
\param
   pSocketFd   specifies the pointer where the value of the socket should be
               set. Value will be greater or equal zero

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketCreate(
                  IFXOS_socketType_t socType, 
                  IFXOS_socket_t     *pSocketFd)
{
   IFXOS_RETURN_IF_POINTER_NULL(pSocketFd, IFX_ERROR);

   /* arg3 = 0: do not specifiy the protocol */
   if (sock_create(PF_INET, socType, 0, (struct socket **) pSocketFd) == -1)
   {
      return IFX_ERROR;
   }
   return IFX_SUCCESS;
}

/**
   This function closes specified socket.

\par Implementation
   - Close the given socket

\param
   socketFd     socket to close

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketClose(
                  IFXOS_socket_t socketFd)
{
   sock_release((struct socket *)socketFd);
   return IFX_SUCCESS;
}

/**
   LINUX Kernel - Sends data to UDP socket.

\par Implementation
   -  via "sock_sendmsg"

\param
   socFd          specifies the socket. Value has to be greater or equal zero
\param
   pBuffer        specifies the pointer to a buffer where the data will be copied
\param
   bufSize_byte   specifies the size in byte of the buffer 'pBuffer'
\param
   pSocAddr    specifies a pointer to the IFXOS_sockAddr_t structure

\return
   Returns the number of sent bytes. Returns a negative value if an error
   occured
*/ 
IFX_int_t IFXOS_SocketSendTo(
                  IFXOS_socket_t socFd, 
                  IFX_char_t     *pBuffer, 
                  IFX_int_t      bufSize_byte,
                  IFXOS_sockAddr_t  *pSocAddr)
{
   struct msghdr msg;
   struct iovec iov;
   mm_segment_t old_fs;
   int ret;
   
   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_ERROR);

   msg.msg_name = (void *) pSocAddr;
   msg.msg_namelen = sizeof(IFXOS_sockAddr_t);
   msg.msg_iov = &iov;
   msg.msg_iovlen = 1;
   msg.msg_control = IFX_NULL;
   msg.msg_controllen = 0;
   msg.msg_flags = MSG_DONTWAIT;

   msg.msg_iov->iov_base = pBuffer;
   msg.msg_iov->iov_len = (unsigned int) bufSize_byte;

   /* Modify address limitation which is used if user space is calling
      kernel space, otherwise sock_sendmsg() will fail.*/
   old_fs = get_fs();
   set_fs(KERNEL_DS);

   ret = sock_sendmsg((struct socket *) socFd, &msg, bufSize_byte);
   set_fs(old_fs);

   return ret;
}

/**
   LINUX Kernel - Assignes a local address to a TCP/IP, UDP/IP or raw socket.

\par Implementation
   -  via "bind"

\param
   socFd       specifies the socket should be bind to the address
               Value has to be greater or equal zero
\param
   pSocAddr    specifies a pointer to the DSL_SockAddr_t structure

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR if operation failed
*/ 
IFX_int_t IFXOS_SocketBind(
                  IFXOS_socket_t    socFd, 
                  IFXOS_sockAddr_t  *pSocAddr)
{
   IFX_int_t ret;

   IFXOS_RETURN_IF_POINTER_NULL(pSocAddr, IFX_ERROR);

   ret = ((struct socket *)socFd)->ops->bind((struct socket *)socFd, 
      (struct sockaddr*) pSocAddr, sizeof(IFXOS_sockAddr_t));
   
   if (ret != 0)
   {
      return IFX_ERROR;
   }
   return IFX_SUCCESS;
}

/**
   LINUX Application - This function converts a dotted decimal address to a network address.

\par Implementation
   -  convert the given ASCII address via "inet_aton".

\param
   pBufAddr    contains the ASCII address string. Must have size DSL_ADDR_LEN
\param
   pSocAddr    specifies a pointer to the DSL internal address structure

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR if operation failed
*/ 
IFX_int_t IFXOS_SocketAton(
                  const IFX_char_t  *pBufAddr,
                  IFXOS_sockAddr_t  *pSocAddr)
{
   const IFX_char_t* conv = pBufAddr;
   IFX_char_t* temp = IFX_NULL;
   IFX_int32_t ip_addr[4] = {0};
   IFX_int32_t i = 0;

   IFXOS_RETURN_IF_POINTER_NULL(pBufAddr, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(pSocAddr, IFX_ERROR);

   while ((i < 4) && (pBufAddr != IFX_NULL))
   {
      ip_addr[i] = simple_strtol(conv, &temp, 10);
      if ((ip_addr[i] < 0) || (ip_addr[i] > 255))
      {
         /* Error, wrong number for ip adrress */
         return IFX_ERROR;
      }

      if (strlen(conv) == strlen(temp))
      {
         /* Error nothing was converted in the string */
         return IFX_ERROR;
      }

      if ((i < 3) && ((*temp == '\0') || (*temp != '.')))
      {
         /* If there is no DOT ('.') between the numbers or we are at the end
            of string then bail out. */
         return IFX_ERROR;
      }

      if (*temp != '\0')
      {
         conv = temp + 1;
      }
      else
      {
         conv = IFX_NULL;
      }
      temp = IFX_NULL;
      i++;
   }

   /* At the end input string must be empty */
   if (conv == IFX_NULL)
   {
      /* We get number in little endian order */
      for (i = 0; i < 4; i++)
      {
         IFXOS_SOC_ADDR_SET(pSocAddr, 
            pSocAddr->sin_addr.s_addr * 256 + ip_addr[i]);
      }
   }
   else
   {
      /* Error, string has some more invalid values */
      return IFX_ERROR;
   }
   return IFX_SUCCESS;
}

#endif   /* #if ( defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1) ) */

/** @} */

#ifdef MODULE
EXPORT_SYMBOL(IFXOS_SocketInit);
EXPORT_SYMBOL(IFXOS_SocketCleanup);
EXPORT_SYMBOL(IFXOS_SocketCreate);
EXPORT_SYMBOL(IFXOS_SocketClose);
EXPORT_SYMBOL(IFXOS_SocketSendTo);
EXPORT_SYMBOL(IFXOS_SocketBind);
EXPORT_SYMBOL(IFXOS_SocketAton);
#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */

