#ifndef _IFXOS_VXWORKS_SOCKET_H
#define _IFXOS_VXWORKS_SOCKET_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/


#ifdef VXWORKS

/** \file
   This file contains VxWorks definitions for Device Access.
*/

/** \defgroup IFXOS_SOCKET_VXWORKS Socket (VxWorks)

   This Group contains the VxWorks Socket definitions and function. 


\ingroup IFXOS_LAYER_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include <vxWorks.h>
#include <sockLib.h>
#include <inetLib.h>
#include <selectLib.h>

#include "ifx_types.h"

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - User support "Socket" */
#ifndef IFXOS_HAVE_SOCKET
#  define IFXOS_HAVE_SOCKET                           1
#endif

/** IFX VxWorks adaptation - User support "Socket Shutdown" */
#if defined(IFXOS_HAVE_SOCKET) && (IFXOS_HAVE_SOCKET == 1)
#  ifndef IFXOS_HAVE_SOCKET_SHUTDOWN
#     define IFXOS_HAVE_SOCKET_SHUTDOWN               1
#  endif
#else
#  ifdef IFXOS_HAVE_SOCKET_SHUTDOWN
#     undef IFXOS_HAVE_SOCKET_SHUTDOWN
#  endif
#  define IFXOS_HAVE_SOCKET_SHUTDOWN                  0
#endif

/* ============================================================================
   IFX VxWorks adaptation - types and defines
   ========================================================================= */
/** identify an invalid socket */
#define IFXOS_SOCKET_INVALID              -1

/** wrap the address length */
#define IFXOS_SOC_ADDR_LEN_BYTE           INET_ADDR_LEN 

#define IFXOS_SOC_INADDR_ANY              INADDR_ANY
#define IFXOS_SOC_WAIT_FOREVER            ((int) -1)
#define IFXOS_SOC_NO_WAIT                 ((int) 0)

#define IFXOS_SOC_AF_INET                 AF_INET

#define IFXOS_SOCKET_SHUTDOWN_RD          0
#define IFXOS_SOCKET_SHUTDOWN_WR          1
#define IFXOS_SOCKET_SHUTDOWN_RDWR        2

/** Return the 'Port' - value of the IFXOS_sockAddr_t parameter */
#define IFXOS_SOC_ADDR_PORT_GET(a)           (((IFXOS_sockAddr_t*)(a))->sin_port)

/** Set the 'port' in the 'IFXOS_sockAddr_t' - structure */
#define IFXOS_SOC_ADDR_PORT_SET(a, port)     (((IFXOS_sockAddr_t*)a)->sin_port = port)

/** Set the IP address in the 'IFXOS_sockAddr_t' - structure*/
#define IFXOS_SOC_ADDR_SET(a, ip)            (((IFXOS_sockAddr_t*)a)->sin_addr.s_addr = ip)

/** Set the 'family' in the 'IFXOS_sockAddr_t' - structure */
#define IFXOS_SOC_ADDR_FAMILY_SET(a, family) (((IFXOS_sockAddr_t*)a)->sin_family = family)


/** Wrap the socket types */
typedef enum
{
   /** For TCP connection*/
   IFXOS_SOC_TYPE_STREAM = SOCK_STREAM,
   /** For UDP connection*/
   IFXOS_SOC_TYPE_DGRAM  = SOCK_DGRAM
} IFXOS_socketType_t;

/** Wrap the socket fd */
typedef int                   IFXOS_socket_t;

/** Wrap the socket address type */
typedef struct sockaddr_in    IFXOS_sockAddr_t;

/** Wrap the fd_set for socket handling */
typedef fd_set                IFXOS_socFd_set_t;

/** Wrap max fd for sockets */
typedef int                   IFXOS_socFd_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_SOCKET_H */


