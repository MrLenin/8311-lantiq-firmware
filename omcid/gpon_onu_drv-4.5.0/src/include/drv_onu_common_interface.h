/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_common_interface.h
   This is a common header file,
   used for debug purposes and direct register access.
*/
#ifndef _drv_onu_common_interface_h
#define _drv_onu_common_interface_h

#include "drv_onu_std_defs.h"

#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__	/* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/
/** \defgroup ONU_COMMON Common Driver Interface

   The common driver interface.
   @{
*/

/** device specific buffer size used for ioctl() */
#define ONU_IO_BUF_SIZE                (4096 * 2)

#define ONU_TESTMODE_RAW_KEY 		"raw_mode"
#define ONU_TESTMODE_IOCTL_TRACE_KEY 	"ioctl_trace_mode"

/** Data exchange structure for all ioctl() calls.
*/
struct fio_exchange {
	/** Error code.*/
	int error;
	/** Length of data in bytes.
	    The caller has to provide the length of pData.
	    The ioctl call will return the size or zero in case of failure.*/
	uint32_t length;
	/** Pointer to source/destination data.*/
	void *p_data;
} __PACKED__;

/** Structure for debug level manipulation.
    Used by \ref FIO_ONU_DEBUG_LEVEL_SET and \ref FIO_ONU_DEBUG_LEVEL_GET.
*/
struct onu_dbg_level {
	/** Debug level. Widened from uint8_t in v7.5.1. */
	uint32_t level;
} __PACKED__;

/** Structure for test mode setting.
    Used by \ref FIO_ONU_TEST_MODE_SET.
*/
struct onu_test_mode {
	/** Test mode string, depending on drivers implementation.*/
	char mode[32];
} __PACKED__;

/** Structure for counters configuration options.
*/
struct onu_cnt_cfg {
	/** Disable counters update.*/
	uint32_t disable_update;
} __PACKED__;

/** Structure for counters reset options.
*/
struct onu_cnt_reset {
	/** Select the counter type:
    0: reset 15-min counters
    1: reset current counter **/
	uint32_t curr;
} __PACKED__;

/** Structure to read version string.
    The string is available as 'what string' within the binary.
*/
struct onu_version_string {
	/** Version string.*/
	char onu_version[80];
	/** PE firmware version */
	char fw_version[80];
	/** COP version */
	char cop_version[80];
	/** SCE interface version */
	char sce_interface_version[80];
	/** Chip id */
	char chip_id[80];
	/** Device type string (e.g., "PSB98030"). Added in v7.5.1. */
	char device_type[80];
} __PACKED__;

/** Structure for register access.
    Used by \ref  FIO_ONU_REGISTER_GET.
*/
struct onu_reg_addr {
	/** 8, 16, 32 bit access. Widened from uint8_t in v7.5.1. */
	uint32_t form;
	/** Register address.*/
	ulong_t address;
} __PACKED__;

/** Structure specifies HW register value.
*/
struct onu_reg_val {
	/** 8, 16, 32 bit access. Widened from uint8_t in v7.5.1. */
	uint32_t form;
	/** Register value.*/
	uint32_t value;
} __PACKED__;

/** Union to retrieve HW register content.
    Used by \ref FIO_ONU_REGISTER_GET.
*/
union onu_register_get_u {
	/** Specified register address.*/
	struct onu_reg_addr in;
	/** Retrieved register.*/
	struct onu_reg_val out;
};

/** Structure for register access (Write access).
*/
struct onu_reg_addr_val {
	/** 8, 16, 32 bit access. Widened from uint8_t in v7.5.1. */
	uint32_t form;
	/** Register address.*/
	ulong_t address;
	/** Register value.*/
	uint32_t value;
} __PACKED__;

/** Structure for controlling onu counters intervals switch time.
*/
struct onu_sync_time {
	/** Enable intervals switching.*/
	uint32_t interval_enable;
	/** Enable external interval supervision.*/
	uint32_t interval_supervision_ext;
} __PACKED__;

/** magic number
*/
#define ONU_MAGIC                            1

/**
   Register Set

   \param onu_reg_addr_val Pointer to \ref onu_reg_addr_val.

*/
#define FIO_ONU_REGISTER_SET   _IOW(ONU_MAGIC, 0, struct onu_reg_addr_val)

/** Register Get

   \param onu_reg Pointer to \ref onu_register_get_u.

*/
#define FIO_ONU_REGISTER_GET   _IOWR(ONU_MAGIC, 1, union onu_register_get_u)

/**
   Specify the level of debug outputs.

   \param onu_dbg_level Pointer to \ref onu_dbg_level.

*/
#define FIO_ONU_DEBUG_LEVEL_SET   _IOW(ONU_MAGIC, 2, struct onu_dbg_level)

/**
   Reads the level of debug outputs.

   \param onu_dbg_level Pointer to \ref onu_dbg_level.

*/
#define FIO_ONU_DEBUG_LEVEL_GET   _IOR(ONU_MAGIC, 3, struct onu_dbg_level)

/**
   Return the version information

   \param onu_version_string Pointer to \ref onu_version_string.

*/
#define FIO_ONU_VERSION_GET   _IOR(ONU_MAGIC, 4, struct onu_version_string)

/**
   Initialize the GPON-PLOAM message handler and the GTC harware module.

   \param No parameter is used, set to 0.

*/
#define FIO_ONU_INIT   _IO(ONU_MAGIC, 5)

/**
   Reset GPON-PLOAM and GTC

   \param No parameter is used, set to 0.

*/
#define FIO_ONU_RESET   _IO(ONU_MAGIC, 6)

/**
   Enable/disable automatic FSM state changes

   \param onu_enable Pointer to \ref onu_enable.

*/
#define FIO_ONU_LINE_ENABLE_SET   _IOW(ONU_MAGIC, 7, struct onu_enable)

/**
   Enable/disable automatic FSM state changes

   \param onu_enable Pointer to \ref onu_enable.

*/
#define FIO_ONU_LINE_ENABLE_GET   _IOR(ONU_MAGIC, 8, struct onu_enable)

/**
   Synchronize 15 min interval. If executed:
   - The current counter values are stored in the previous counter values.
   - Counter alarm values are reset.
   - Threshold crossing alarms are reset.

   \param onu_enable Pointer to \ref onu_enable.

*/
#define FIO_ONU_SYNC_TIME_SET   _IOW(ONU_MAGIC, 9, struct onu_sync_time)

/**
   Check if 15 min counter supervision interval is enabled.

   \param onu_enable Pointer to \ref onu_enable.

*/
#define FIO_ONU_SYNC_TIME_GET   _IOR(ONU_MAGIC, 10, struct onu_sync_time)

/**
   Set test modes.

   \param onu_test_mode Pointer to \ref onu_test_mode.

*/
#define FIO_ONU_TEST_MODE_SET _IOW(ONU_MAGIC, 11, struct onu_test_mode)

/**
   Set counters handling configuration.

   \param onu_cnt_cfg Pointer to \ref onu_cnt_cfg.

*/
#define FIO_ONU_COUNTERS_CFG_SET _IOW(ONU_MAGIC, 12, struct onu_cnt_cfg)

/**
   Get counters handling configuration.

   \param onu_cnt_cfg Pointer to \ref onu_cnt_cfg.

*/
#define FIO_ONU_COUNTERS_CFG_GET _IOR(ONU_MAGIC, 13, struct onu_cnt_cfg)

/**
   Reset counters covered by the PM implementation.

   \param onu_cnt_reset Pointer to \ref onu_cnt_reset.

*/
#define FIO_ONU_COUNTERS_RESET _IOW(ONU_MAGIC, 14, struct onu_cnt_reset)

/**
   Reset counters covered by the PM implementation.

   \param onu_cnt_reset Pointer to \ref onu_cnt_reset.

*/
#define FIO_ONU_COUNTERS_RESET _IOW(ONU_MAGIC, 14, struct onu_cnt_reset)

/**
   v7.5.1: Retrieve the LAN port-to-UNI mapping from the kernel.

   Returns a 12-byte structure:
     byte 0:   number of defined LAN ports (count)
     bytes 1+: UNI ID for each LAN port index (count entries)

   The kernel provides the hardware-specific mapping between GPE LAN port
   indices and OMCI UNI ME instance IDs. This replaced the v4.5.0 file-based
   uni2lan mapping (the -u command line option).
*/
#define FIO_ONU_LAN_PORTMAP_GET _IOR(ONU_MAGIC, 0x11, char[12])

/**
   CLI access

   \param No parameter is used, set to 0.
*/
#define FIO_ONU_CLI _IO(ONU_MAGIC, 100)

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
#endif
