#ifndef _IFXOS_RTEMS_SOCKET_H
#define _IFXOS_RTEMS_SOCKET_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/


#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for Device Access.
*/

/** \defgroup IFXOS_SOCKET_RTEMS Socket (Generic OS)

   This Group contains the Generic OS Socket definitions and function.


\ingroup IFXOS_LAYER_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - User support "Socket" */
#ifndef IFXOS_HAVE_SOCKET
#define IFXOS_HAVE_SOCKET                           1
#endif

/* ============================================================================
   RTEMS adaptation - types and defines
   ========================================================================= */
/** identify an invalid socket */
#define IFXOS_SOCKET_INVALID              -1

/** wrap the address length */
#define IFXOS_SOC_ADDR_LEN_BYTE           18


#define IFXOS_SOC_INADDR_ANY              0x00000000
#define IFXOS_SOC_WAIT_FOREVER            ((int) -1)
#define IFXOS_SOC_NO_WAIT                 ((int) 0)


/** Return the 'Port' - value of the IFXOS_sockAddr_t parameter */
#define IFXOS_SOC_ADDR_PORT_GET(a)        (((IFXOS_sockAddr_t*)(a))->sin_port)

/** Set the 'port' in the 'IFXOS_sockAddr_t' - structure */
#define IFXOS_SOC_ADDR_PORT_SET(a, port)  (((IFXOS_sockAddr_t*)a)->sin_port = port)

/** Set the IP address in the 'IFXOS_sockAddr_t' - structure*/
#define IFXOS_SOC_ADDR_SET(a, ip)         (((IFXOS_sockAddr_t*)a)->sin_addr.s_addr = ip)


/** Wrap the socket types */
typedef enum
{
   /** For TCP connection*/
   IFXOS_SOC_TYPE_STREAM = 1,
   /** For UDP connection*/
   IFXOS_SOC_TYPE_DGRAM  = 2
} IFXOS_socketType_t;

/** Wrap the socket fd */
typedef int                   IFXOS_socket_t;

struct in_addr {
	IFX_uint32_t   s_addr;
};

/*
 * Socket address, internet style.
 */
struct sockaddr_in {
	IFX_uint8_t    sin_len;
	IFX_uint8_t	   sin_family;
	IFX_uint16_t	sin_port;
	struct in_addr sin_addr;
	IFX_char_t     sin_zero[8];
};

/** Wrap the socket address type */
typedef struct sockaddr_in    IFXOS_sockAddr_t;

/** Wrap the fd_set for socket handling */
typedef IFX_uint32_t          IFXOS_socFd_set_t;

/** Wrap max fd for sockets */
typedef int                   IFXOS_socFd_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_SOCKET_H */


