/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_bosa_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, BOSA block.
*/
#ifndef _drv_optic_bosa_interface_h_
#define _drv_optic_bosa_interface_h_

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

/** \defgroup GPON_BOSA BOSA Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface for BOSA configuration.
   @{
*/

/** This enumeration defines the selectable BOSA loop control modes. */
enum optic_bosa_loop_mode {
	/** Same as open loop. */
	OPTIC_BOSA_NOLOOP,
	/** Neither bias nor modulation transmit current level are automatically
	    controlled by hardware, both values are set by software. */
	OPTIC_BOSA_OPENLOOP,
	/** Both bias and modulation transmit current level are automatically
	    controlled by hardware. */
	OPTIC_BOSA_DUALLOOP,
	/** Only the transmit modulation current level is automatically
	    controlled by hardware, the bias current is set by software. */
	OPTIC_BOSA_COMBILOOP
};

/** GPON optical layer hardware receiver configuration.
    Used by \ref FIO_BOSA_RX_CFG_SET and \ref FIO_BOSA_RX_CFG_GET.
    The parameters are application-specific and may be changed during operation.
*/
struct optic_bosa_rx_config {
	/** CDR dead zone elimination mode.
		- false: off
		- true:  on */
	bool dead_zone_elimination;
	/** Loss of lock alarm threshold 1 (set alarm), in % */
	uint8_t threshold_lol_set;
	/** Loss of lock alarm threshold 2 (clear alarm), in % */
	uint8_t threshold_lol_clear;
	/** Loss of signal threshold: [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t threshold_los;
	/** Receiver overload threshold: [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t threshold_rx_overload;
} __PACKED__;

/** GPON optical layer hardware transmitter configuration.
    Used by \ref FIO_BOSA_TX_CFG_SET and \ref FIO_BOSA_TX_CFG_GET.
    The parameters are application-specific and may be changed during operation.
*/
struct optic_bosa_tx_config {
	/** Bosa loop mode */
	enum optic_bosa_loop_mode loop_mode;
	/** Bias/Modulation integration coefficient (initial value). */
	uint8_t intcoeff_init[2];
	/** Threshold for update current bias/modulation in [%]. */
	uint8_t updatethreshold[2];
	/** Threshold for learning current bias/modulation in [%]. */
	uint8_t learnthreshold[2];
	/** Threshold for stable current bias/modulation
	    in [% difference from average codeword] */
	uint8_t stablethreshold[2];
	/** Threshold for reset bias/modulation
	    in [% difference from initializaiton codeword] */
	uint8_t resetthreshold[2];
	/** Phase interpolator setting, controls the phase between modulation
	    output and complement output. The optimum value depends on the
	    external application, details are t.b.d. */
	uint32_t pi_control;
	/** Low power level at reference [-3dB, -6dB] transmit power [uW]. */
	int16_t p0[3];
	/** High power level at reference [-3dB, -6dB] transmit power [uW]. */
	int16_t p1[3];
	/** Optical transmit power at laser threshold [uW]. */
	int16_t pth;
} __PACKED__;

/** BOSA power level set/get parameter.
    Dedicated power levels can be selected through an enum variable:
    enum optic_powerlevel
	 - OPTIC_POWERLEVEL_0: Normal (highest) power level.
	 - OPTIC_POWERLEVEL_1: Normal power level - 3 dB.
	 - OPTIC_POWERLEVEL_2: Normal power level - 6 dB.

     Used by \ref FIO_BOSA_POWERLEVEL_SET.
     Used by \ref FIO_BOSA_POWERLEVEL_GET.
     */
struct optic_bosa_powerlevel {
	enum optic_powerlevel powerlevel;
} __PACKED__;

/** BOSA dual-loop enable switch. */
/** BOSA transmit laser dual-loop enable status.
    Used by \ref FIO_BOSA_DUALLOOP_STATUS_GET
*/
struct optic_bosa_loopmode {
   /** Bias and modulation current control loop selection. */
	enum optic_bosa_loop_mode loop_mode;
} __PACKED__;

/** GPON optical layer hardware receiver status information.
    Used by \ref FIO_BOSA_RX_STATUS_GET.
*/
struct optic_bosa_rx_status {
	/** Receiver enable,
	    indicates if the optical transmitter has been enabled by
	    \ref FIO_BOSA_RX_ENABLE. */
	bool rx_enable;
	/** Measured RSSI 1490 receive power ->  [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t meas_power_1490_rssi;
	/** Measured RSSI 1490 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t meas_voltage_1490_rssi;
	/** Measured RSSI 1490 current -> for receive power calculation [mA]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t meas_current_1490_rssi;
	bool meas_current_1490_rssi_is_positive;
	/** Measured RF 1550 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t meas_voltage_1550_rf;
	/** Measured RSSI 1550 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t meas_voltage_1550_rssi;
	/** Loss of signal,
	    the optical signal is insufficient, detected by the on-chip
	    optical receiver. */
	bool loss_of_signal;
	/** Receive CDR status (Clock and Data Recovery),
		- false: The CDR is locked.
		- true:  The CDR is unlocked. */
	bool loss_of_lock;
} __PACKED__;

/** GPON optical layer hardware transmit status information.
    Used by \ref FIO_BOSA_TX_STATUS_GET.
*/
struct optic_bosa_tx_status {
	/** Transmitter enable,
	    indicates if the optical transmitter has been enabled by
	    \ref FIO_BOSA_TX_ENABLE. */
	bool tx_enable;
	/** Actual transmit laser bias current,
	    [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT.
	    This status information is also available in
	    \ref FIO_GOI_STATUS_GET. */
	uint16_t bias_current;
	/** Actual transmit laser modulation current,
	    [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT.
	    This status information is also available in
	    \ref FIO_GOI_STATUS_GET. */
	uint16_t modulation_current;
	/** Transmit laser threshold current (Ith),
	    [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t laser_threshold;
	/** Transmit laser Slope Efficiency,
	    [uW/mA] << OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY. */
	uint16_t slope_efficiency;
} __PACKED__;

/** BOSA alarm status information. Used by \ref FIO_BOSA_ALARM_STATUS_GET.
    Alarm indications are set true if alarm has been detected since the
    last call to \ref FIO_BOSA_ALARM_STATUS_CLEAR. */
struct optic_bosa_alarm {
	/** LOS (loss of signal). */
	bool loss_of_signal;
	/** LOL (loss of lock). */
	bool loss_of_lock;
	/** Receiver overload. */
	bool rx_overload;
	/** Bias over-current. */
	bool bias_overload;
	/** Modulation over-current. */
	bool modulation_overload;
	/** Laser current over-current (sum of bias and modulation current. )*/
	bool laser_overload;
	/** Rogue P0 alarm (invalid signal detected during level 0
	    transmission). */
	bool rogue_p0;
	/** Rogue P1 alarm (invalid signal detected during level 1
	    transmission). */
	bool rogue_p1;
} __PACKED__;

/** Integration coefficient for bias and modulation current integration.
    Used by \ref FIO_BOSA_INT_COEFF_GET.
*/
struct optic_int_coeff {
	/** Bias/Modulation integration coefficient (current value). */
	uint8_t intcoeff[2];
} __PACKED__;

/** Stability attribute of the bias and modulation current control.
    Used by \ref FIO_BOSA_STABLE_GET.
*/
struct optic_stable {
	/** Bias/Modulation stable attribute. */
	bool stable[2];
} __PACKED__;

/**
   Set the BOSA receiver configuration.

   \param optic_bosa_rx_config Pointer to \ref optic_bosa_rx_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_RX_CFG_SET _IOW(OPTIC_BOSA_MAGIC, 0, struct optic_bosa_rx_config)

/**
   Read back the BOSA receiver configuration.

   \param optic_bosa_rx_config Pointer to \ref optic_bosa_rx_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_RX_CFG_GET _IOR(OPTIC_BOSA_MAGIC, 1, struct optic_bosa_rx_config)

/**
   Set the BOSA transmitter configuration.

   \param optic_bosa_tx_config Pointer to \ref optic_bosa_tx_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_TX_CFG_SET _IOW(OPTIC_BOSA_MAGIC, 2, struct optic_bosa_tx_config)

/**
   Read back the BOSA transmitter configuration.

   \param optic_bosa_tx_config Pointer to \ref optic_bosa_tx_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_TX_CFG_GET _IOR(OPTIC_BOSA_MAGIC, 3, struct optic_bosa_tx_config)

/**
   Enable the BOSA receiver input.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_RX_ENABLE _IO(OPTIC_BOSA_MAGIC, 4)

/**
   Disable the BOSA laser receiver input.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_RX_DISABLE _IO(OPTIC_BOSA_MAGIC, 5)

/**
   Enable the BOSA laser transmitter output.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_TX_ENABLE _IO(OPTIC_BOSA_MAGIC, 6)

/**
   Disable the BOSA laser transmitter output.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_TX_DISABLE _IO(OPTIC_BOSA_MAGIC, 7)

/**
   Set the power level.

   \param optic_bosa_powerlevel Pointer to \ref optic_bosa_powerlevel.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_POWERLEVEL_SET _IOW(OPTIC_BOSA_MAGIC, 8, struct optic_bosa_powerlevel)

/**
   Read the power level.

   \param optic_bosa_powerlevel Pointer to \ref optic_bosa_powerlevel.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_POWERLEVEL_GET _IOR(OPTIC_BOSA_MAGIC, 9, struct optic_bosa_powerlevel)

/**
   Sets the bosa loop mode.

   \param optic_bosa_loopmode Pointer to \ref optic_bosa_loopmode.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_LOOPMODE_SET _IOW(OPTIC_BOSA_MAGIC, 10, struct optic_bosa_loopmode)

/**
  Reads the BOSA loop mode.

   \param optic_bosa_loopmode Pointer to \ref optic_bosa_loopmode.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_LOOPMODE_GET _IOR(OPTIC_BOSA_MAGIC, 11, struct optic_bosa_loopmode)


/**
   Read the BOSA's receiver status.

   \param optic_bosa_rx_status Pointer to \ref optic_bosa_rx_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_RX_STATUS_GET _IOR(OPTIC_BOSA_MAGIC, 12, struct optic_bosa_rx_status)

/**
   Read the BOSA's transmitter status.

   \param optic_bosa_tx_status Pointer to \ref optic_bosa_tx_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_TX_STATUS_GET _IOR(OPTIC_BOSA_MAGIC, 13, struct optic_bosa_tx_status)

/**
   Read the BOSA's alarm status.

   \param optic_bosa_alarm Pointer to \ref optic_bosa_alarm.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_ALARM_STATUS_GET _IOR(OPTIC_BOSA_MAGIC, 14, struct optic_bosa_alarm)

/**
   Clear the BOSA's alarm status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_ALARM_STATUS_CLEAR _IO(OPTIC_BOSA_MAGIC, 15)


/**
   Reads BOSA integration coefficients for Bias and Modulation.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_INT_COEFF_GET _IOR(OPTIC_BOSA_MAGIC, 16, struct optic_int_coeff)

/**
   Reads stable attribute for Bias and Modulation.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BOSA_STABLE_GET _IOR(OPTIC_BOSA_MAGIC, 17, struct optic_stable)

#define OPTIC_BOSA_MAX                              18



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
#endif                          /* _drv_optic_bosa_interface_h_ */
