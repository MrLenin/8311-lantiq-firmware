/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/**
   \file drv_optic_error.h
   This file contains the error code definitions
   used by the FALC(tm) ON Optic Driver.
*/
#ifndef _drv_optic_error_h_
#define _drv_optic_error_h_

#include "drv_optic_std_defs.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI Optical Interface API Reference
   @{
*/

/** \defgroup OPTIC_ERROR Optical Interface Error Codes

    This chapter describes the error codes of the optical device driver.
   @{
*/


/** Enumeration for function status return.
    The upper four bits are reserved for error classification.
*/

enum optic_errorcode {
	/* Common error codes */
	/** No error */
	OPTIC_STATUS_OK = 0,
	/** Generic or unknown warning occurred */
	OPTIC_STATUS_WRN = 1,
	/** Generic or unknown error occurred */
	OPTIC_STATUS_ERR = -1,
	/** Not supported by software yet */
	OPTIC_STATUS_NOT_IMPLEMENTED = -4000,
	/** Parameter Out Of Range */
	OPTIC_STATUS_POOR = -4001,
	/** Init failure */
	OPTIC_STATUS_INIT_FAIL = -4002,
	/** Memory Allocation error */
	OPTIC_STATUS_ALLOC_ERR = -4003,
	/** Threshold Crossing Alarm */
	OPTIC_STATUS_TCA = 4004,
	/** State change not allowed */
	OPTIC_STATUS_NO_STATECHANGE = 4005,
	/** Measured internal temperature is out of configured range */
	OPTIC_STATUS_INTTEMP_UNDERRUN = -4006,
	/** Measured internal temperature is out of configured range */
	OPTIC_STATUS_INTTEMP_OVERFLOW = -4007,
	/** Measured external temperature is out of configured range */
	OPTIC_STATUS_EXTTEMP_UNDERRUN = -4008,
	/** Measured external temperature is out of configured range */
	OPTIC_STATUS_EXTTEMP_OVERFLOW = -4009,
	/** Requested temperature table is not (yet) initialized */
	OPTIC_STATUS_TABLE_UNINIT = -4010,
	/** More table entries found as memory was allocated,
	    not all found entries are returned */
	OPTIC_STATUS_MORE_ENTRIES = 4011,
	/** No valid calculation, but gain selector was adapted */
	OPTIC_STATUS_GAIN_SELECTOR_UPDATED = 4012,
	/** Mode switching currently not possible, try again */
	OPTIC_STATUS_MODESET_FAIL = -4013,
	/** Parameter invalid */
	OPTIC_STATUS_INVAL = -4014,
	/** Driver is not in the correct state */
	OPTIC_STATUS_WRONG_STATE = -4015,
	/** Parameter for overcurrent invalid, = 0 or exceed bias or imod max */
	OPTIC_STATUS_INVAL_OCTHR = -4016,
	/** No action was needed the calling function may continue */
	OPTIC_STATUS_IGNORE = 4017,

	/* FCSI register hardware access */
	/** FCSIC timeout read */
	OPTIC_STATUS_FCSI_READTIMEOUT = -4101,
	/** FCSIC timeout write */
	OPTIC_STATUS_FCSI_WRITETIMEOUT = -4102,

	/* PLL error codes */
	/** PLL timeout wait for locking */
	OPTIC_STATUS_PLL_LOCKTIMEOUT = -4201,
	/** PLL locked */
	OPTIC_STATUS_PLL_LOCKED = 4202,
	/** PLL not locked */
	OPTIC_STATUS_PLL_NOTLOCKED = 4203,

	/* MPD error codes */
	/** Level/offset DAC saturation */
	OPTIC_STATUS_MPD_SATURATION = -4301,
	/** Comparator didn't react */
	OPTIC_STATUS_MPD_COMPTIMEOUT = -4302,
	/** The dual loop either on P0 or on P1 is still
	    active for the level search */
	OPTIC_STATUS_MPD_ACTIVE_DL = -4303,
	/** MPD stable criteria still adds values for average */
	OPTIC_STATUS_MPD_AVERAGE_NOT_COMPLETE = 4304,
	/** Update of bias/mod value not performed because of update
	    threshold */
	OPTIC_STATUS_MPD_UPDATE_THRES_NOT_REACHED = 4305,
	/** Update counter timeout */
	OPTIC_STATUS_MPD_NOUPDATE_TIMEOUT = 4306,

	/** P0, P1 coarse and fine dac value share sign -> should never differ */
	OPTIC_STATUS_DAC_SIGN_CONFLICT = -4307,
	/** Coarse and fine level search type seems not to be aligned */
	OPTIC_STATUS_LEVELSEARCH_TYPE_CONFLICT = -4308,

	/** APD ragne error */
	OPTIC_STATUS_RANGE_APD = -4309,
	/** APD polarity error */
	OPTIC_STATUS_IPOL_APD = -4310,
	/** APD table error */
	OPTIC_STATUS_APD_TBL = -4311,
	/** APD regulation error */
	OPTIC_STATUS_REGULATION = -4312,


	/** Level/offset DAC saturation */
	OPTIC_STATUS_RXDAC_SATURATION = -4401,

	/** DCDC APD sw ramp needed */
	OPTIC_STATUS_DCDC_APD_RAMP = 4501,
	/** DCDC APD target voltage reached */
	OPTIC_STATUS_DCDC_APD_CHANGE= 4502,
	/** DCDC APD target voltage wait for ramp step */
	OPTIC_STATUS_DCDC_APD_RAMP_WAIT = 4503,


#if 0
   /* GOI specific errors */
   /** Invalid function parameter */
   OPTIC_STATUS_INVALID_CTL
   /** The operation is not supported by hardware */
   OPTIC_STATUS_NO_SUPPORT
   /** Timeout */
   OPTIC_STATUS_TIMEOUT
   /** Counter overflow */
   OPTIC_STATUS_COUNTER_ERR
   /** Resource not available */
   OPTIC_STATUS_NOT_AVAILABLE
   /** Self-test failure or similar */
   OPTIC_STATUS_SELF_TEST_FAIL
   /** Self-test failure or similar */
   OPTIC_STATUS_CALIBRATION_FAIL
#endif

};

/*! @} */

/*! @} */

EXTERN_C_END

#endif /* _drv_optic_error_h_ */
