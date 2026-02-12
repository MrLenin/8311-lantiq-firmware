/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_omu_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, OMU block.
*/
#ifndef _drv_optic_omu_interface_h_
#define _drv_optic_omu_interface_h_

#include "drv_optic_std_defs.h"


#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__        /* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI Optical Interface API Reference
   @{
*/

/** \defgroup OPTIC_OMU Optical Module Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface for OMU configuration.
   @{
*/


/** GPON optical layer hardware configuration.
    Used by \ref FIO_OMU_CFG_SET and \ref FIO_OMU_CFG_GET.
*/
struct optic_omu_config {
	/** Indicate if the "signal detect" status signal is available. */
	bool signal_detect_avail;
	/** GPIO port used as "signal detect" input
	\todo Define the GPIO numbering scheme.*/
	uint8_t signal_detect_port;
	/** Loss of lock alarm threshold 1 (set alarm), in % */
	uint8_t threshold_lol_set;
	/** Loss of lock alarm threshold 2 (clear alarm), in % */
	uint8_t threshold_lol_clear;
	/** Laser enable signal mode selection. The control signal can be
	single-ended (CMOS) or differential (PECL).
	- true: single-ended laser enable signal
	- false: differential laser enable signal */
	bool laser_enable_single_ended;
} __PACKED__;

/** OMU receiver status information.
    Used by \ref FIO_OMU_RX_STATUS_GET.
*/
struct optic_omu_rx_status_get {
	/** Receiver enable,
	indicates if the optical receiver has been enabled by
	\ref FIO_OMU_RX_ENABLE.
	This status information is also available in \ref FIO_GOI_STATUS_GET. */
	bool rx_enable;
	/** Loss of signal,
	the optical signal is insufficient, indicated by the optical module's
	"signal detect" line. */
	bool loss_of_signal;
	/** Loss of lock,
	the on-chip clock and data recovery (CDR) has lost synchronization. */
	bool loss_of_lock;
} __PACKED__ ;

/** OMU transmit status information.
    Used by \ref FIO_OMU_TX_STATUS_GET.
*/
struct optic_omu_tx_status_get {
   /** Transmitter enable, indicates if the optical transmitter has been
   enabled by \ref FIO_OMU_TX_ENABLE. This status information is also available
   in \ref FIO_GOI_STATUS_GET. */
	bool tx_enable;
} __PACKED__ ;

/** OMU alarm status information. Used by \ref FIO_OMU_ALARM_STATUS_GET.
   Alarm indications are set true if an alarm has been detected since the
   last call to \ref FIO_OMU_ALARM_STATUS_CLEAR. */
struct optic_omu_alarm {
  	/** LOS (loss of signal). */
	bool loss_of_signal;
	/** LOL (loss of lock). */
	bool loss_of_lock;
} __PACKED__;


/* IOCTL Command Declaration - GOI OMU (Optical Module)
   ==================================================== */

/**
   Set the configuration for the OMU interface. It defines the handling of the
   "signal detect" control signal and the thresholds to declare/release the
   "loss of frequency/phase lock" (LOL) alarm.

   \param optic_omu_config Pointer to \ref optic_omu_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_CFG_SET _IOW(OPTIC_OMU_MAGIC, 0, struct optic_omu_config)

/**
   Read back the OMU configuration. This function returns the values that have
   been set by the \ref FIO_OMU_CFG_SET command.

   \param optic_omu_config Pointer to \ref optic_omu_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_CFG_GET _IOR(OPTIC_OMU_MAGIC, 1, struct optic_omu_config)

/**
   Enable the Optical Module receiver input.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_RX_ENABLE _IO(OPTIC_OMU_MAGIC, 2)

/**
   Disable the Optical Module receiver input.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_RX_DISABLE _IO(OPTIC_OMU_MAGIC, 3)

/**
   Enable the Optical Module laser transmitter output.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_TX_ENABLE _IO(OPTIC_OMU_MAGIC, 4)

/**
   Disable the Optical Module laser transmitter output.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_TX_DISABLE _IO(OPTIC_OMU_MAGIC, 5)

/**
   Read the OMU's receiver status. To check for receiver problems that might
   have occurred but are not persistent, use the \ref FIO_OMU_ALARM_STATUS_GET
   function.

   \param optic_omu_rx_status_get Pointer to \ref optic_omu_rx_status_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_RX_STATUS_GET _IOR(OPTIC_OMU_MAGIC, 6, struct optic_omu_rx_status_get)

/**
   Read the OMU's transmitter status (if enabled or not).

   \param optic_omu_tx_status_get Pointer to \ref optic_omu_tx_status_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_TX_STATUS_GET _IOR(OPTIC_OMU_MAGIC, 7, struct optic_omu_tx_status_get)

/**
   Read the OMU's alarm status. Alarm indications since the most recent call
   of this function are stored and indicated by this function. To check if an
   indicated alarm persists, check the \ref FIO_OMU_RX_STATUS_GET function.

   \param optic_omu_alarm Pointer to \ref optic_omu_alarm.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_ALARM_STATUS_GET _IOR(OPTIC_GOI_MAGIC, 8, optic_omu_alarm)

/**
   Clear the OMU's alarm status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_OMU_ALARM_STATUS_CLEAR _IO(OPTIC_GOI_MAGIC, 9)

#define OPTIC_OMU_MAX                              10


/*! @} */

/*! @} */

EXTERN_C_END

#ifdef __PACKED_DEFINED__
#  if !defined (__GNUC__) && !defined (__GNUG__)
#    pragma pack()
#  endif
#  undef __PACKED_DEFINED__
#  undef __PACKED__
#endif
#endif                          /* _drv_optic_omu_interface_h_ */
