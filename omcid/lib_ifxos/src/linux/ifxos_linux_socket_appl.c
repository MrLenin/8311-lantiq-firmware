/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX User 
   Socket.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_socket.h"
#include "ifxos_debug.h"

/* ============================================================================
   IFX Linux adaptation - User Space, Socket
   ========================================================================= */

/** \addtogroup IFXOS_SOCKET_LINUX
@{ */

#if ( defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1) )
/**
   LINUX Application - This function init and setup the socket feature on the system.

\par Implementation
   - Nothing under LINUX Application.

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
   LINUX Application - This function cleanup the socket feature on the system.

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
   LINUX Application - This function creates a TCP/IP, UDP/IP or raw socket.

\par Implementation
   - Create a AF_INET socket, no specified protocol.

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
   if((*pSocketFd = socket(AF_INET, socType, 0)) == -1)
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;
}

/**
   This function closes specified socket.

\par Implementation
   - Close the given socket via "closesocket"

\param
   socketFd     socket to close

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketClose(
                  IFXOS_socket_t socketFd)
{
   if (close(socketFd) == -1)
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;
}

#if ( defined(IFXOS_HAVE_SOCKET_SHUTDOWN) && (IFXOS_HAVE_SOCKET_SHUTDOWN == 1) )
/**
   This function shutdown the specified socket.

\par Implementation
   - shutdown the given socket via "shutdown" function.

\param
   socketFd     socket to shutdown
\param
   how         identifiy the operation to shutdown
               - IFXOS_SOCKET_SHUTDOWN_RD     SHUT_RD (shutdown reception).
               - IFXOS_SOCKET_SHUTDOWN_WR     SHUT_WR (shutdown transmission).
               - IFXOS_SOCKET_SHUTDOWN_RDWR   SHUT_RDWR (shutdown both).
\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketShutdown(
                  IFXOS_socket_t socketFd,
                  IFX_int_t      how)
{
   if (shutdown(socketFd, how) == -1)
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;
}
#endif

/**
   LINUX Application - Pend (wait) on multiple file descriptors.

\par Implementation
   -  via "select"

\param
   maxSocFd       specifies the maximum number of descriptors
\param
   pSocFdRead     specifies the file descriptors
\param
   pSocFdWrite    not used
\param
   pSocFdExcept   not used
\param
   timeout_ms     specifies behaviour if event is not available:
                  - DSL_NO_WAIT: do not wait for the event
                  - DSL_WAIT_FOREVER: wait till event is available
                  - other int value: number of system ticks for timeout

\return
   Returns 0 on timeout, a positive value on receiving a event
   or a negative value on error
*/ 
IFX_int_t IFXOS_SocketSelect(
                  IFXOS_socFd_t     maxSocFd,
                  IFXOS_socFd_set_t *pSocFdRead,
                  IFXOS_socFd_set_t *pSocFdWrite,
                  IFXOS_socFd_set_t *pSocFdExcept,
                  IFX_int_t         timeout_ms )
{
   IFX_int_t ret = 0;
   struct timeval   tv, *pTime;

   pTime = &tv;

   /* set timeout value */
   switch (timeout_ms)
   {
      case IFXOS_SOC_WAIT_FOREVER:
         pTime = NULL;
         break;

      case IFXOS_SOC_NO_WAIT:
         tv.tv_sec = 0;
         tv.tv_usec = 0;
         break;

      default:
         tv.tv_sec = timeout_ms / 1000;
         tv.tv_usec = (timeout_ms % 1000) * 1000;
         break;
   }

   /* call selct function itself */
   ret = (IFX_int_t)select(maxSocFd, pSocFdRead, pSocFdWrite, pSocFdExcept,  pTime);

   return ret;
}

/**
   LINUX Application - Receives data from a connected socket.

\par Implementation
   -  via "recv"

\param
   socFd          specifies the socket. Value has to be greater or equal zero
\param
   pBuffer        specifies the pointer to a buffer where the data will be copied
\param
   bufSize_byte   specifies the size in byte of the buffer 'pBuffer'

\return
   Returns the number of received bytes. Returns a negative value if an error
   occured
*/ 
IFX_int_t IFXOS_SocketRecv(
                  IFXOS_socket_t socFd, 
                  IFX_char_t     *pBuffer, 
                  IFX_int_t      bufSize_byte)
{
   int recvBytes = 0;
   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);

   if ( (recvBytes = recv((int)socFd, (char*)pBuffer, (int)bufSize_byte, 0)) < 0)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - recv = (%d) <%s>" IFXOS_CRLF, errno, strerror(errno)));

      return IFX_ERROR;
   }

   return (IFX_int_t)recvBytes;
}

/**
   LINUX - Receives data from a datagramm socket.

\par Implementation
   -  via "recv_from"

\param
   socFd          specifies the socket. Value has to be greater or equal zero
\param
   pBuffer        specifies the pointer to a buffer where the data will be copied
\param
   bufSize_byte   specifies the size in byte of the buffer 'pBuffer'
\param
   pSocAddr    specifies a pointer to the IFXOS_sockAddr_t structure

\return
   Returns the number of received bytes. Returns a negative value if an error
   occured
*/ 
IFX_int_t IFXOS_SocketRecvFrom(
                  IFXOS_socket_t socFd, 
                  IFX_char_t     *pBuffer, 
                  IFX_int_t      bufSize_byte,
                  IFXOS_sockAddr_t  *pSocAddr)
{
   int ret;
   unsigned int pFromlen = sizeof(IFXOS_sockAddr_t);
   
   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_ERROR);

   ret = (IFX_int_t)recvfrom((int)socFd, (char*)pBuffer, (int)bufSize_byte, 
   0, (struct sockaddr *)pSocAddr, &pFromlen);

   return ret;
}

/**
   LINUX Application - Sends data to connected socket.

\par Implementation
   -  via "send"

\param
   socFd          specifies the socket. Value has to be greater or equal zero
\param
   pBuffer        specifies the pointer to a buffer where the data will be copied
\param
   bufSize_byte   specifies the size in byte of the buffer 'pBuffer'

\return
   Returns the number of received bytes. Returns a negative value if an error
   occured
*/ 
IFX_int_t IFXOS_SocketSend(
                  IFXOS_socket_t socFd, 
                  IFX_char_t     *pBuffer, 
                  IFX_int_t      bufSize_byte)
{
   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_ERROR);

   return (IFX_int_t)send((int)socFd, (const char*)pBuffer, (int)bufSize_byte, 0);
}

/**
   LINUX Application - Sends data to UDP socket.

\par Implementation
   -  via "send"

\param
   socFd          specifies the socket. Value has to be greater or equal zero
\param
   pBuffer        specifies the pointer to a buffer where the data will be copied
\param
   bufSize_byte   specifies the size in byte of the buffer 'pBuffer'
\param
   pSocAddr    specifies a pointer to the IFXOS_sockAddr_t structure

\return
   Returns the number of received bytes. Returns a negative value if an error
   occured
*/ 
IFX_int_t IFXOS_SocketSendTo(
                  IFXOS_socket_t socFd, 
                  IFX_char_t     *pBuffer, 
                  IFX_int_t      bufSize_byte,
                  IFXOS_sockAddr_t  *pSocAddr)
{
   int ret;
   
   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_ERROR);

   ret = (IFX_int_t)sendto((int)socFd, (const char*)pBuffer, 
		(int)bufSize_byte, 0, pSocAddr, sizeof(IFXOS_sockAddr_t));

   return ret;
}

/**
   LINUX Application - Assignes a local address to a TCP/IP, UDP/IP or raw socket.

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

   ret = bind(
            (int)socFd,
            (struct sockaddr*)pSocAddr,
            sizeof(struct sockaddr_in) );

   if (ret != 0)
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;

}

/**
   LINUX Application - Indicates that the server is willing to accept connection requests from
   clients for a TCP/IP socket.

\par Implementation
   -  via "listen"

\param
   socFd       specifies the socket should be bind to the address
               Value has to be greater or equal zero
\param
   nBacklog    specifies the number of connections to queue

\return
   Return values are defined within the IFX_int_t definition
   - IFX_SUCCESS in case of success
   - IFX_ERROR if operation failed
*/ 
IFX_int_t IFXOS_SocketListen(
                  IFXOS_socket_t socFd, 
                  IFX_uint16_t   nBacklog)
{
   if (listen(socFd, nBacklog) != 0)
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;
}

/**
   LINUX Application - Accept a Connection from the socket.

\par Implementation
   -  via "accept"

\param
   socFd       specifies the socket. Value has to be greater or equal zero
\param
   pSocAddr    specifies a pointer to the DSL address structure

\return
   Returns the socket of the new accept connection. 
   Is negative if an error occurs.
*/ 
IFXOS_socket_t IFXOS_SocketAccept(
                  IFXOS_socket_t    socFd, 
                  IFXOS_sockAddr_t  *pSocAddr)
{

   socklen_t addrlen = sizeof (struct sockaddr);

   return (IFXOS_socket_t)accept((int)socFd, (struct sockaddr *)pSocAddr, &addrlen);
}


/**
   LINUX Application - Establisch a connection by a TCP client.

\par Implementation
   -  via "connect"

\param
   socFd       specifies the socket. Value has to be greater or equal zero
\param
   pSocAddr    specifies a pointer to the socket address structure
\param
   pSocAddr    length of the socket address structure


\return
   IFX_SUCCESS if the connection has been establieshed, else
   IFX_ERROR   if the operation fails.
*/ 
IFX_int_t IFXOS_SocketConnect(
                  IFXOS_socket_t    socFd, 
                  IFXOS_sockAddr_t  *pSocAddr,
                  IFX_int_t         socAddrLen)
{

   if (connect((int)socFd, (const struct sockaddr *)pSocAddr, socAddrLen))
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Socket Connect = (%d) <%s>" IFXOS_CRLF,
           errno, strerror(errno)));

      return IFX_ERROR;
   }

   return IFX_SUCCESS;
}



/**
   LINUX Application - This function converts a network address to dotted decimal notation.

\par Implementation
   -  convert the given socket address via "inet_ntoa" and copy it to the buffer.

\param
   pSocAddr    specifies a pointer to the DSL internal address structure
\param
   pBuffer     where to return ASCII string. pBuf must have size DSL_ADDR_LEN

\return
   None
*/ 
IFX_void_t IFXOS_SocketNtoa(
                  IFXOS_sockAddr_t  *pSocAddr, 
                  IFX_char_t        *pBuffer)
{
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pSocAddr, IFX_ERROR);
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pBuffer, IFX_ERROR);

   strcpy(pBuffer, inet_ntoa(pSocAddr->sin_addr));
   /* CHECK
   strncpy(pBuffer, inet_ntoa(pSocAddr->sin_addr), IFXOS_SOC_ADDR_LEN_BYTE); */

   return;
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
   IFXOS_RETURN_IF_POINTER_NULL(pBufAddr, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(pSocAddr, IFX_ERROR);

   if (inet_aton(pBufAddr, &pSocAddr->sin_addr) == 0)
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;
}

/**
   LINUX Application - Mark a descriptor in use.

\param
   socFd       soccket file descriptor which will be set.
\param
   pSocFdSet   points to the set mask where the given socFd will be set.

\return
   NONE
*/
IFX_void_t IFXOS_SocFdSet(
               IFXOS_socket_t    socFd, 
               IFXOS_socFd_set_t *pSocFdSet)
{
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pSocFdSet, IFX_ERROR);

   FD_SET(socFd, pSocFdSet);

   return;
}

/**
   LINUX Application - Clear a given descriptor.

\param
   socFd       soccket file descriptor which will be cleared.
\param
   pSocFdSet   points to the set mask where the given socFd will be cleared.

\return
   NONE
*/
IFX_void_t IFXOS_SocFdClr(
               IFXOS_socket_t    socFd, 
               IFXOS_socFd_set_t *pSocFdSet)
{
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pSocFdSet, IFX_ERROR);

   FD_CLR(socFd, pSocFdSet);

   return;
}

/**
   LINUX Application - Check if a descriptor is set.

\param
   socFd       soccket file descriptor which will be checked for set.
\param
   pSocFdSet   points to the set mask which contains the socFd for check.

\return
   True if the given descriptor is set witin the mask, else
   0 if the descriptor is not set.
*/
IFX_int_t IFXOS_SocFdIsSet(
               IFXOS_socket_t          socFd, 
               const IFXOS_socFd_set_t *pSocFdSet)
{
   IFXOS_RETURN_IF_POINTER_NULL(pSocFdSet, 0);

   return FD_ISSET(socFd, pSocFdSet);
}

/**
   LINUX Application - Clear a descriptor mask.

\param
   pSocFdSet   points to the set mask.
*/
IFX_void_t IFXOS_SocFdZero(
               IFXOS_socFd_set_t *pSocFdSet)

{
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pSocFdSet, IFX_ERROR);

   FD_ZERO(pSocFdSet);

   return;
}

#endif   /* #if ( defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1) ) */

/** @} */

#endif      /* #ifdef LINUX */

