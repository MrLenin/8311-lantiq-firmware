#ifndef _IFXOS_SOCKET_H
#define _IFXOS_SOCKET_H
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

/** \defgroup IFXOS_SOCKET Socket

   This Group contains the Socket definitions and function. 

\ingroup IFXOS_INTERFACE
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_socket.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_socket.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_socket.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_socket.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_socket.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_socket.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_socket.h"
#  else
#     error "Socket Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_socket.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_socket.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_socket.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_socket.h"
#  elif defined(WIN32)
#     include "ifxos_win32_socket.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_socket.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_socket.h"
#  else
#     error "Socket Adaptation - Please define your OS"
#  endif
#endif


/* ============================================================================
   IFX OS adaptation - Socket
   ========================================================================= */

/** \addtogroup IFXOS_SOCKET
@{ */

#if ( defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1) )

/**
   This function init and setup the socket feature on the system.

\remark
   This function is available for compatibility reasons. On systems where no
   seperate setup is required the function will be empty.

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketInit(void);

/**
   This function cleanup the socket feature on the system.

\remark
   This function is available for compatibility reasons. On systems where no
   seperate setup is required the function will be empty.

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketCleanup(void);

/**
   This function creates a TCP/IP, UDP/IP or raw socket.

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
                  IFXOS_socket_t     *pSocketFd);


/**
   This function closes specified socket.

\param
   socketFd     socket to close

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR   if operation failed
*/ 
IFX_int_t IFXOS_SocketClose(
                  IFXOS_socket_t socketFd);


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
                  IFX_int_t      how);
#endif

/**
   Pend (wait) on multiple file descriptors.

\param
   maxSocFd       specifies the maximum number of descriptors
\param
   pSocFdRead     specifies the file descriptors
\param
   pSocFdWrite    not used
\param
   pSocFdExcept   not used
\param
   timeout_ms       specifies behaviour if event is not available:
                              - IFXOS_SOC_NO_WAIT: do not wait for the event
                              - IFXOS_SOC_WAIT_FOREVER: wait till event is 
                              available
                              - other int value: number of system ticks for 
                              timeout

\return
   Returns 0 on timeout, a positive value on receiving a event
   or a negative value on error
*/ 
IFX_int_t IFXOS_SocketSelect(
                  IFXOS_socFd_t     maxSocFd,
                  IFXOS_socFd_set_t *pSocFdRead,
                  IFXOS_socFd_set_t *pSocFdWrite,
                  IFXOS_socFd_set_t *pSocFdExcept,
                  IFX_int_t         timeout_ms );

/**
   Receives data from a connected socket.

\param
   socFd          specifies the socket. Value has to be greater or equal zero
\param
   pBuffer        specifies the pointer to a buffer where the data will be 
                  copied
\param
   bufSize_byte   specifies the size in byte of the buffer 'pBuffer'

\return
   Returns the number of received bytes. Returns a negative value if an error
   occured
*/ 
IFX_int_t IFXOS_SocketRecv(
                  IFXOS_socket_t socFd, 
                  IFX_char_t     *pBuffer, 
                  IFX_int_t      bufSize_byte);

/**
   Receives data from a datagramm socket.

\param
   socFd          specifies the socket. Value has to be greater or equal zero
\param
   pBuffer        specifies the pointer to a buffer where the data will be 
                  copied
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
                  IFXOS_sockAddr_t  *pSocAddr);

/**
   Sends data to connected socket.

\param
   socFd          specifies the socket. Value has to be greater or equal zero
\param
   pBuffer        specifies the pointer to a buffer where the data will be 
                  copied
\param
   bufSize_byte   specifies the size in byte of the buffer 'pBuffer'

\return
   Returns the number of sent bytes. Returns a negative value if an error
   occured
*/ 
IFX_int_t IFXOS_SocketSend(
                  IFXOS_socket_t socFd, 
                  IFX_char_t     *pBuffer, 
                  IFX_int_t      bufSize_byte);

/**
   Sends data to datagram socket.

\param
   socFd          specifies the socket. Value has to be greater or equal zero.
\param
   pBuffer        specifies the pointer to a buffer where the data will be 
                  copied.
\param
   bufSize_byte   specifies the size in byte of the buffer 'pBuffer'.
\param
   pSocAddr    specifies a pointer to the IFXOS_sockAddr_t structure.

\return
   Returns the number of sent bytes. Returns a negative value if an error
   occured
*/ 
IFX_int_t IFXOS_SocketSendTo(
                  IFXOS_socket_t socFd, 
                  IFX_char_t     *pBuffer, 
                  IFX_int_t      bufSize_byte,
                  IFXOS_sockAddr_t  *pSocAddr);

/**
   Assignes a local address to a TCP/IP, UDP/IP or raw socket.

\param
   socFd       specifies the socket should be bind to the address
               Value has to be greater or equal zero
\param
   pSocAddr    specifies a pointer to the IFXOS_sockAddr_t structure

\return
   - IFX_SUCCESS in case of success
   - IFX_ERROR if operation failed
*/ 
IFX_int_t IFXOS_SocketBind(
                  IFXOS_socket_t    socFd, 
                  IFXOS_sockAddr_t  *pSocAddr);

/**
   Indicates that the server is willing to accept connection requests from
   clients for a TCP/IP socket.

\param
   socFd    specifies the socket should be bind to the address
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
                  IFX_uint16_t   nBacklog);

/**
   Accept a Connection from the socket.

\param
   socFd       specifies the socket. Value has to be greater or equal zero
\param
   pSocAddr    specifies a pointer to the IFXOS_sockAddr_t structure

\return
   Returns the socket of the new accept connection. 
   Is negative if an error occurs.
*/ 
IFXOS_socket_t IFXOS_SocketAccept(
                  IFXOS_socket_t    socFd, 
                  IFXOS_sockAddr_t  *pSocAddr);


/**
   Establisch a connection by a TCP client.

\param
   socFd       specifies the socket. Value has to be greater or equal zero
\param
   pSocAddr    specifies a pointer to the socket address structure
\param
   socAddrLen  length of the socket address structure


\return
   IFX_SUCCESS if the connection has been establieshed, else
   IFX_ERROR   if the operation fails.
*/ 
IFX_int_t IFXOS_SocketConnect(
                  IFXOS_socket_t    socFd, 
                  IFXOS_sockAddr_t  *pSocAddr,
                  IFX_int_t         socAddrLen);

/**
   This function converts a network address to dotted decimal notation.

\param
   pSocAddr    specifies a pointer to the IFXOS internal address structure
\param
   pBuffer     where to return ASCII string. pBuf must have size
               IFXOS_SOC_ADDR_LEN_BYTE

\return
   None
*/ 
IFX_void_t IFXOS_SocketNtoa(
                  IFXOS_sockAddr_t  *pSocAddr, 
                  IFX_char_t        *pBuffer);

/**
   This function converts dotted decimal notation to a network address.

\param
   pBufAddr    specifies a pointer to the ASCII string. pBuf must have size
               IFXOS_SOC_ADDR_LEN_BYTE
\param
   pSocAddr    where to return the IFXOS internal address structure

\return
   None
*/ 
IFX_int_t IFXOS_SocketAton(
                  const IFX_char_t  *pBufAddr,
                  IFXOS_sockAddr_t  *pSocAddr);

/**
   Mark a descriptor in use.

\param
   socFd       soccket file descriptor which will be set.
\param
   pSocFdSet   points to the set mask where the given socFd will be set.

\return
   NONE
*/
IFX_void_t IFXOS_SocFdSet(
               IFXOS_socket_t    socFd, 
               IFXOS_socFd_set_t *pSocFdSet);

/**
   Clear a given descriptor.

\param
   socFd       soccket file descriptor which will be cleared.
\param
   pSocFdSet   points to the set mask where the given socFd will be cleared.

\return
   NONE
*/
IFX_void_t IFXOS_SocFdClr(
               IFXOS_socket_t    socFd, 
               IFXOS_socFd_set_t *pSocFdSet);

/**
   Check if a descriptor is set.

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
               const IFXOS_socFd_set_t *pSocFdSet);

/**
   Clear a descriptor mask.

\param
   pSocFdSet   points to the set mask.
*/
IFX_void_t IFXOS_SocFdZero(
               IFXOS_socFd_set_t *pSocFdSet);

#endif

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_SOCKET_H */

