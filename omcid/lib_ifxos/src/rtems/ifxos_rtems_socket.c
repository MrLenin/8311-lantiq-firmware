/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains the IFXOS Layer implementation for RTEMS User
   Socket.
*/

/* ============================================================================
   RTEMS adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_socket.h"
#include "ifxos_debug.h"


/* ============================================================================
   RTEMS adaptation - User Space, Socket
   ========================================================================= */

/** \addtogroup IFXOS_SOCKET_RTEMS
@{ */

#if ( defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1) )
/**
   RTEMS - This function init and setup the socket feature on the system.

\par Implementation
   - Nothing under RTEMS.

\remark
   This function is available for compatibility reasons. On systems where no
   seperate setup is required the function will be empty.

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/
IFX_int_t IFXOS_SocketInit(void)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation - socket library initialisation
   */

   return IFX_SUCCESS;
}


/**
   RTEMS - This function cleanup the socket feature on the system.

\par Implementation
   - Nothing under RTEMS.

\remark
   This function is available for compatibility reasons. On systems where no
   seperate setup is required the function will be empty.

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/
IFX_int_t IFXOS_SocketCleanup(void)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation - socket library cleanup
   */

   return IFX_SUCCESS;
}



/**
   RTEMS - This function creates a TCP/IP, UDP/IP or raw socket.

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      *pSocketFd = socket(AF_INET, socType, 0);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pSocketFd, IFX_ERROR);

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      close(socketFd);
   */

   return IFX_SUCCESS;
}

/**
   RTEMS - Pend (wait) on multiple file descriptors.

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

   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      select(maxSocFd, pSocFdRead, pSocFdWrite, pSocFdExcept,  pTime);
   */


   return ret;
}

/**
   RTEMS - Receives data from a connected socket.

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
   IFX_int_t ret = 0;

   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      return (IFX_int_t)recv((int)socFd, (char*)pBuffer, (int)bufSize_byte, 0);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);

   return ret;
}

/**
   RTEMS - Sends data to connected socket.

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
   IFX_int_t ret = 0;

   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      return (IFX_int_t)send((int)socFd, (const char*)pBuffer, (int)bufSize_byte, 0);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_ERROR);

   return ret;
}

/**
   RTEMS Application - Sends data to UDP socket.

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
   IFX_int_t ret = 0;

   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
   ret = (IFX_int_t)sendto((SOCKET)socFd, (const char*)pBuffer, (int)bufSize_byte, 0, pSocAddr, sizeof(IFXOS_sockAddr_t));
   */
   
   IFXOS_RETURN_IF_POINTER_NULL(pBuffer, IFX_ERROR);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_ERROR);

   return ret;
}

/**
   RTEMS - Assignes a local address to a TCP/IP, UDP/IP or raw socket.

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
   IFX_int_t ret = 0;

   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      ret = bind(socFd, pSocAddr, sizeof(struct sockaddr_in));
   */

   IFXOS_RETURN_IF_POINTER_NULL(pSocAddr, IFX_ERROR);

   return ret;
}

/**
   RTEMS - Indicates that the server is willing to accept connection requests from
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
   IFX_int_t ret = 0;

   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      listen(socFd, nBacklog);
   */

   return ret;
}

/**
   RTEMS - Accept a Connection from the socket.

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
   IFX_int_t ret = 0;

   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      accept((int)socFd, (struct sockaddr *)pSocAddr, &addrlen);
   */

   /*
      --> can be zero
      IFXOS_RETURN_IF_POINTER_NULL(pSocAddr, IFX_ERROR);
   */

   return ret;
}


/**
   RTEMS - This function converts a network address to dotted decimal notation.

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      inet_ntoa_b(pSocAddr->sin_addr, pBuffer);
   */

   IFXOS_RETURN_VOID_IF_POINTER_NULL(pSocAddr, IFX_ERROR);
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pBuffer, IFX_ERROR);

   return;
}

/**
   RTEMS - Mark a descriptor in use.

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      FD_SET(socFd, pSocFdSet);
   */

   IFXOS_RETURN_VOID_IF_POINTER_NULL(pSocFdSet, IFX_ERROR);

   return;
}

/**
   RTEMS - Check if a descriptor is set.

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation - like
      return FD_ISSET(socFd, pSocFdSet);;
   */

   IFXOS_RETURN_IF_POINTER_NULL(pSocFdSet, 0);

   return 0;
}

#endif   /* #if ( defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1) ) */


/** @} */

#endif      /* #ifdef RTEMS */



