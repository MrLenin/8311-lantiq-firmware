#ifndef DEV_IO_H
#define DEV_IO_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#include "ifx_types.h"

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
/*!
 * \defgroup DEVIO_DEVICE_IO_LAYER DEVIO Layer - IO sub system
 */

/* ============================================================================
   Device IO - Basic and global defines
   ========================================================================= */
/** \addtogroup DEVIO_DEVICE_IO_LAYER
@{ */

/** Maximum device name length. */
#ifndef DEVIO_MAXDEVNAME
#define DEVIO_MAXDEVNAME       (64)
#endif

/** Maximum number of drivers supported by LIB_IO extension. */
#ifndef DEVIO_MAXDRIVERS
#define DEVIO_MAXDRIVERS       (6)
#endif

/** Maximum number of devices supported by LIB_IO extension. */
#ifndef DEVIO_MAXDEVICES
#define DEVIO_MAXDEVICES       (108)
#endif

/** Maximum number of device descriptors supported by LIB_IO extension. */
#ifndef DEVIO_MAXFDS
#define DEVIO_MAXFDS           (108)
#endif


/** Polling time (msec) for DEVIO_select() implementation. */
#ifndef DEVIO_SELECT_POLLING_TIME
#define DEVIO_SELECT_POLLING_TIME 	(100)
#endif

/** @} */

/* ============================================================================
   Device IO - Device and driver interface function types
   ========================================================================= */
/** \addtogroup DEVIO_DEVICE_IO_LAYER
@{ */

/** Driver open interface. */
typedef IFX_long_t ( *DEVIO_device_open ) ( void *device, const IFX_char_t *appendix );

/** Driver close interface. */
typedef IFX_int_t ( *DEVIO_device_close ) ( void *pprivate );

/** Driver ioctl interface. */
typedef IFX_int_t ( *DEVIO_device_ioctl ) ( void *pprivate, IFX_uint_t cmd, IFX_ulong_t arg );

/** Driver read interface. */
typedef IFX_int_t ( *DEVIO_device_read ) ( void *pprivate, IFX_char_t *buf, const IFX_int_t len );

/** Driver write interface. */
typedef IFX_int_t ( *DEVIO_device_write ) ( void *pprivate, const IFX_char_t *buf, const IFX_int_t len );

/** Driver poll interface. */
typedef IFX_int_t ( *DEVIO_device_poll ) ( void *pprivate );

/** @} */

/* ============================================================================
   Device IO - Device and Driver control functions
   ========================================================================= */
/** \addtogroup DEVIO_DEVICE_IO_LAYER
@{ */

/**
   Install a driver with given callbacks. 
   
   \return
   - -1 in case of error
   - positive value less then DEVIO_MAXDRIVERS
*/
IFX_uint_t DEVIO_driver_install ( DEVIO_device_open,
                                   DEVIO_device_close,
                                   DEVIO_device_read, DEVIO_device_write, DEVIO_device_ioctl,
                                   DEVIO_device_poll );

/**
   Remove a driver from the sub system. 

   \param driver_num    driver number   
   \param force         force operation even if the driver is used
*/
void DEVIO_driver_remove ( unsigned int driver_num, int force );

/**
   Add a device to the IO sub system. 

   \param device        device pointer   
   \param name          device name
   \param mode          not used
*/
IFX_uint_t DEVIO_device_add ( void *device, const char *name, unsigned int mode );

/**
   Remove a device from the IO sub system. 

   \param device        device pointer   
*/
void DEVIO_device_delete ( void *device );

/** @} */

/* ============================================================================
   Device IO - Device interface functions
   ========================================================================= */
/** \addtogroup DEVIO_DEVICE_IO_LAYER
@{ */

/**
   Open a device
   
   \param name    device name
   
   \return
   - -1 in case of a failure
   - any other positive value less then DEVIO_MAXDEVICES
*/
IFX_int_t DEVIO_open ( const char *name );

/**
   Close the device.
   
   \param fd   device descriptor, returned by DEVIO_open() call
*/
IFX_int_t DEVIO_close ( const IFX_int_t fd );

/**
   Write to the device.
   
   \param fd      device descriptor, returned by DEVIO_open() call
   \param pData   data pointer
   \param nSize   data size

   \return 
   device specific
*/
IFX_int_t DEVIO_write ( const IFX_int_t fd, const void *pData, const unsigned int nSize );

/**
   Read from the specified device.
   
   \param fd   device descriptor, returned by DEVIO_open() call
   \param pData   data pointer
   \param nSize   maximum data size
   
   \return 
   - device specific
*/
IFX_int_t DEVIO_read ( const IFX_int_t fd, void *pData, const unsigned int nSize );

/**
   Control the specified device.
   
   \param fd      device descriptor, returned by DEVIO_open() call
   \param cmd     command to be executed
   \param param   optional parameter

   \return 
   - device specific
*/
IFX_int_t DEVIO_ioctl ( const IFX_int_t fd, const unsigned int cmd, IFX_ulong_t param );

/** @} */

/* ============================================================================
   Device IO - Device IO Layer Select Handling.
   ========================================================================= */
/** \addtogroup DEVIO_DEVICE_IO_LAYER
@{ */

/**
 * Device descriptor structure. Used by DEVIO_select() call .
 */
typedef struct
{
   /**
    * - set to 1 if device is marked
    * - set to 0 if device is not selected
    */
   unsigned int fds[DEVIO_MAXFDS];
} DEVIO_fd_set_t;

/**
   Set the descriptor in the set structure indicated by the fd parameter.
   
   \param fd   descriptor, returned by \ref DEVIO_open [I]
   \param set  pointer to the descriptor set [IO]
*/
void DEVIO_fd_set(const unsigned int  fd, DEVIO_fd_set_t *set);

/**
   Check if the descriptor in the set structure is enabled.   
   \param fd   descriptor, returned by \ref DEVIO_open [I]
   \param set  pointer to the descriptor set [I]
*/
int DEVIO_fd_isset(const unsigned int  fd, const DEVIO_fd_set_t *set);

/**
   Clear the descriptor in the set structure.   
   \param fd   descriptor, returned by \ref DEVIO_open [I]
   \param set  pointer to the descriptor set [IO]
*/
void DEVIO_fd_clear(const unsigned int  fd, DEVIO_fd_set_t *set);

/**
   Zero the descriptor set structure.   
   \param fd   descriptor, returned by \ref DEVIO_open [I]
   \param set  pointer to the descriptor set [IO]
*/
void DEVIO_fd_zero(DEVIO_fd_set_t *set);

/**
	Emulation of the select() call.

	All devices marked in the read_fd_in structure will be polled. The polling
	granularity is defined by DEVIO_SELECT_POLLING_TIME .
*/
int DEVIO_select ( const unsigned int max_fd, const DEVIO_fd_set_t * read_fd_in,
                  DEVIO_fd_set_t * read_fd_out, const unsigned int timeout_msec );

/** @} */

/* ============================================================================
   Device IO - Device IO Layer control functions
   ========================================================================= */
/** \addtogroup DEVIO_DEVICE_IO_LAYER
@{ */

/** Initialize io layer */
void DEVIO_initialize(void);

/** Shutdown io layer */
void DEVIO_shutdown(void);

/** @} */

#endif      /* #if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1)) */

#ifdef __cplusplus
}
#endif

#endif /* DEV_IO_H */
