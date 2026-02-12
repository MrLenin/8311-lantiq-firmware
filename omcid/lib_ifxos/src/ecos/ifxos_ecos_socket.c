/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains the IFXOS Layer implementation for eCos User 
   Socket.
*/

/* ============================================================================
   IFX eCos adaptation - Global Includes
   ========================================================================= */

#include <pkgconf/system.h>
#if defined(CYGPKG_NET)
#include <network.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif /* CYGPKG_NET */
   
#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_socket.h"
#include "ifxos_debug.h"


/* ============================================================================
   IFX eCos adaptation - User Space, Socket
   ========================================================================= */

/** \addtogroup IFXOS_SOCKET_ECOS
@{ */

#if ( defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1) )
/**
   eCos - This function init and setup the socket feature on the system.

\par Implementation
   - Nothing under eCos.

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
   eCos - This function cleanup the socket feature on the system.

\par Implementation
   - Nothing under eCos.

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
   eCos - This function creates a TCP/IP, UDP/IP or raw socket.

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

\param
   socketFd     socket to shutdown
\param
   how         identifiy the operation to shutdown
               - IFXOS_SOCKET_SHUTDOWN_RD     shutdown reception
               - IFXOS_SOCKET_SHUTDOWN_WR     shutdown transmission
               - IFXOS_SOCKET_SHUTDOWN_RDWR   shutdown both.
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
   eCos - Pend (wait) on multiple file descriptors.

\par Implementation
   -  via "select"

\param
   socFd          specifies the file descriptor numer of the socket
\param
   pSocFdRead     specifies the file descriptors
\param
   pSocFdWrite    not used
\param
   pSocFdExcept   not used
\param
   nTimeout       specifies behaviour if event is not available:
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
   eCos - Receives data from a connected socket.

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
         ("IFXOS ERROR - recv, errno = %d" IFXOS_CRLF, errno));

      return IFX_ERROR;
   }

   return (IFX_int_t)recvBytes;
}

/**
   eCos - Receives data from a datagramm socket.

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
   int recvBytes = 0;
   int pFromlen = sizeof(IFXOS_sockAddr_t);

   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);

   if ( (recvBytes = recvfrom((int)socFd, (char*)pBuffer, (int)bufSize_byte, 
   0, (struct sockaddr *)pSocAddr, &pFromlen)) < 0)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - recvfrom, errno = %d" IFXOS_CRLF, errno));

      return IFX_ERROR;
   }

   return (IFX_int_t)recvBytes;
}

/**
   eCos - Sends data to connected socket.

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
   eCos - Sends data to UDP socket.

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
   eCos - Assignes a local address to a TCP/IP, UDP/IP or raw socket.

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
            sizeof(struct sockaddr_in));

   if (ret != 0)
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;

}

/**
   eCos - Indicates that the server is willing to accept connection requests from
   clients for a TCP/IP socket.

\par Implementation
   -  via "listen"

\param
   socketID    specifies the socket should be bind to the address
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
   if (listen(socFd, nBacklog) == -1)
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;
}

/**
   eCos - Accept a Connection from the socket.

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

   IFX_int_t addrlen = sizeof (struct sockaddr);

   return (IFXOS_socket_t)accept((int)socFd, (struct sockaddr *)pSocAddr, &addrlen);
}


/**
   eCos - Establisch a connection by a TCP client.

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
   if ( (connect((int)socFd, (struct sockaddr *)pSocAddr, socAddrLen)) != 0)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Socket Connect, cannot establish the connection" IFXOS_CRLF));

      return IFX_ERROR;
   }

   return IFX_SUCCESS;
}


/**
   eCos - This function converts a network address to dotted decimal notation.

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
}

/**
   eCos - This function converts a dotted decimal address to a network address.

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
   eCos - Mark a descriptor in use.

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
   eCos - Clear a given descriptor.

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
   eCos - Check if a descriptor is set.

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
   eCos - Clear a descriptor mask.

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

#endif      /* #ifdef ECOS */



