/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/**
   \file drv_onu_error.h
   This file holds the error code definitions.
*/
#ifndef _drv_onu_error_h_
#define _drv_onu_error_h_

#include "drv_onu_std_defs.h"

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/
/** \defgroup ONU_ERROR Error Codes

    This chapter describes the error codes of the ONU device driver.
   @{
*/
/** Enumeration for function status return.
    The upper four bits are reserved for error classification.
*/
enum onu_errorcode {
	/* Common error codes */
	/** Not supported by software yet */
	ONU_STATUS_NOT_IMPLEMENTED = 0,
	/** GPE is not initialized */
	ONU_STATUS_GPE_NOT_INITIALIZED = -4,
	/** No IOCTL found error */
	ONU_STATUS_IOCTL_NOT_FOUND_ERR = -3,
	/** Operation is not supported for this chip */
	ONU_STATUS_CHIP_NOT_SUPPORTED = -2,
	/** Generic or unknown error occurred */
	ONU_STATUS_ERR = -1,
	/** No error */
	ONU_STATUS_OK = 0,

	/** Threshold Crossing Alarm */
	ONU_STATUS_TCA = 1,

	/* GTC specific warnings */
	/** Warning: GEM Port in use. */
	GTC_STATUS_VALUE_PORT_IN_USE = 1009,
	/** Warning: Value is out of range.
	    Value was set to predefined value. */
	GTC_STATUS_VALUE_RANGE_WARN = 1008,

	/** Resource exists */
	GPE_STATUS_EXISTS = 3011,

	/** Memory Allocation error */
	ONU_STATUS_ALLOC_ERR = -2,

	/** Firmware Load failed */
	ONU_STATUS_FW_LOAD_ERR = -100,

	/** Firmware initialization failed */
	ONU_STATUS_FW_INIT_ERR = -101,

	/** Coprocessor initialization failed */
	ONU_STATUS_COP_INIT_ERR = -102,

	/** Merger initialization failed */
	ONU_STATUS_MRG_INIT_ERR = -103,

	/** Firmware Binary request failed */
	ONU_STATUS_FW_REQUEST_ERR = -104,
	/** Setting Firmware packet mode failed */
	ONU_STATUS_FW_PACKET_ERR = -105,
	/** Firmware tables initialization failed */
	ONU_STATUS_FW_TABLES_INIT_ERR = -106,
	/* GTC specific errors */
	/** Invalid function parameter */
	GTC_STATUS_INVALID_CTL = -1005,
	/** The operation is not supported by hardware */
	GTC_STATUS_NO_SUPPORT = -1006,
	/** Timeout */
	GTC_STATUS_TIMEOUT = -1007,
	/** At least one value is out of range */
	GTC_STATUS_VALUE_RANGE_ERR = -1008,
	/** Counter overflow */
	GTC_STATUS_COUNTER_ERR = -1010,
	/** Resource not available */
	GTC_STATUS_NOT_AVAILABLE = -1011,
	/** Unspecified GTC failure */
	GTC_STATUS_ERR = -1099,

	/* EIM specific errors */
	/** Invalid function parameter */
	EIM_STATUS_INVALID_CTL = -2005,
	/** The operation is not supported by hardware */
	EIM_STATUS_NO_SUPPORT = -2006,
	/** Timeout */
	EIM_STATUS_TIMEOUT = -2007,
	/** At least one value is out of range */
	EIM_STATUS_VALUE_RANGE_ERR = -2008,
	/** Counter overflow */
	EIM_STATUS_COUNTER_ERR = -2010,
	/** Resource not available */
	EIM_STATUS_NOT_AVAILABLE = -2011,
	/** Unspecified EIM failure */
	EIM_STATUS_ERR = -2099,

	/* GPE specific errors */
	/** Invalid function parameter */
	GPE_STATUS_INVALID_CTL = -3005,
	/** The operation is not supported by hardware */
	GPE_STATUS_NO_SUPPORT = -3006,
	/** Timeout */
	GPE_STATUS_TIMEOUT = -3007,
	/** At least one value is out of range */
	GPE_STATUS_VALUE_RANGE_ERR = -3008,
	/** Low Level modules enable failed */
	GPE_STATUS_VALUE_LL_MODULE_ENABLE_ERR = -3009,
	/** Counter overflow */
	GPE_STATUS_COUNTER_ERR = -3010,
	/** Resource not available */
	GPE_STATUS_NOT_AVAILABLE = -3011,
	/** Configuration mismatch */
	GPE_STATUS_CONFIG_MISMATCH = -3012,
	/** Unspecified GPE failure */
	GPE_STATUS_ERR = -3099,
	/** Some of the configuration parameters are ignored*/
	GPE_STATUS_CONFIG_PARAM_IGNORED = 3000,

	/* GPE COP specific errors */
	/** INDEX points beyond table size or was invalid, for example after
	   INDEX = AUX.*/
	GPE_STATUS_COP_INVALID_INDEX = -4001,
	/** A sequential search has hit the end of table without having
	   found a match */
	GPE_STATUS_COP_END_OF_TABLE = -4002,
	/** An ADD command to an LLIST failed because the free list was
	   empty (invalid AUX pointer) */
	GPE_STATUS_COP_OUT_OF_MEMORY = -4003,
	/** An ADD command with OV=0 to a LIST or LLIST failed because there
	   is already an entry with the same key */
	GPE_STATUS_COP_ENTRY_EXISTS = -4004,
	/** Controlled by External_0 */
	GPE_STATUS_COP_ERROR_DISCARD_FRAME = -4005,
	/** Controlled by Microcode */
	GPE_STATUS_COP_SOFT_ERR_1 = -4006,
	/** Controlled by Microcode */
	GPE_STATUS_COP_SOFT_ERR_2 = -4007,
	/** Generic or unknown hardware coprocessor error occurred */
	GPE_STATUS_COP_ERR = -4016,
	/* No response during a COP read command */
	/** Hardware coprocessor time-out. */
	GPE_STATUS_COP_TIMEOUT = -4032,
	/** Hardware coprocessor error. */
	/* a receive flush error */
	GPE_STATUS_COP_FLUSH = -4064,
	/** COP table entry not found */
	GPE_STATUS_COP_ENTRY_NOT_FOUND = -4128,

	/* GPE SCE specific errors */
	/** PE operation timeout error */
	GPE_STATUS_PE_TIMEOUT = -5001,

	/** Generic or unknown PE error occurred */
	GPE_STATUS_PE_ERR = -5002,

	/* LAN interface specific errors */
	/** Invalid function parameter */
	LAN_STATUS_INVALID_CTL = -6005,
	/** The operation is not supported by hardware */
	LAN_STATUS_NO_SUPPORT = -6006,
	/** Timeout */
	LAN_STATUS_TIMEOUT = -6007,
	/** At least one value is out of range */
	LAN_STATUS_VALUE_RANGE_ERR = -6008,
	/** Counter overflow */
	LAN_STATUS_COUNTER_ERR = -6010,
	/** Resource not available */
	LAN_STATUS_NOT_AVAILABLE = -6011,
	/** Common LAN interface configuration is not available */
	LAN_STATUS_NOT_INITIALIZED = -6012,
	/** Common LAN interface configuration already in place */
	LAN_STATUS_ALREADY_INITIALIZED = -6013,
	/** Traffic stuck */
	LAN_STATUS_TRAFFIC_STUCK = -6014,
	/** Unspecified LAN failure */
	LAN_STATUS_ERR = -6099
};

/*! @} */

/*! @} */

EXTERN_C_END
#endif				/* _drv_onu_error_h_ */
