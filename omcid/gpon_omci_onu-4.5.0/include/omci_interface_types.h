/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_interface_types_h
#define _omci_interface_types_h

#if defined(HAVE_SYS_CDEFS_H) && (HAVE_SYS_CDEFS_H == 1)
#  include <sys/cdefs.h>
#else
#  ifdef __cplusplus
#     ifndef __BEGIN_DECLS
#        define __BEGIN_DECLS extern "C" {
#     endif
#     ifndef __END_DECLS
#        define __END_DECLS   }
#     endif
#  else
#     ifndef __BEGIN_DECLS
#        define __BEGIN_DECLS
#     endif
#     ifndef __END_DECLS
#        define __END_DECLS
#     endif
#  endif
#endif

__BEGIN_DECLS

#if defined(__GNUC__) || defined(__GNUG__)
#  define __PACKED__ __attribute__ ((packed))
#else
#  if defined(WIN32)
#    pragma warning(disable: 4103)
#    pragma pack(1)
#    define __PACKED__
#  else
#    define __PACKED__
#  endif
#endif

#if defined(HAVE_STDINT_H) && (HAVE_STDINT_H == 1)
#  include <stdint.h>
#else
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned uint32_t;

#  ifndef SWIG
#     if defined(__WORDSIZE) && (__WORDSIZE == 64)
typedef unsigned long int uint64_t;
#     else
#        if !defined(HAVE_LONG_LONG_INT) || (HAVE_LONG_LONG_INT == 0)
#           error "Your compiler doesn't support long long int type!"
#        endif
typedef unsigned long long int uint64_t;
#     endif
#  endif
#endif

#ifdef INCLUDE_PM
#  ifndef SWIG
#     if !(defined(SIZEOF_LONG_LONG_INT) && (SIZEOF_LONG_LONG_INT == 8))
#        error "sizeof(long long int) != 8"
#     endif
#  endif
#endif

#if defined(HAVE_STDBOOL_H) && (HAVE_STDBOOL_H == 1)
#  if !(defined(SIZEOF__BOOL) && (SIZEOF__BOOL == 1))
#     error "sizeof(_Bool) > 1 or _Bool is not supported (while stdbool.h exist)"
#  endif

#  include <stdbool.h>
#else
#  ifndef SWIG
#     ifdef HAVE__BOOL
#        if !(defined(SIZEOF__BOOL) && (SIZEOF__BOOL == 1))
#           error "sizeof(_Bool) > 1"
#        endif
typedef _Bool bool;
#     else
typedef unsigned char bool;

#        define _Bool bool
#     endif

#     ifndef true
#        define true 1
#     endif
#     ifndef false
#        define false 0
#     endif
#  endif
#endif

/** \addtogroup OMCI_API

   @{
*/

/** Maximum size of Managed Entity attributes data (in bytes)

    This value is checked during MIB classes correctness check. If some
    attribute size is greater than this constant OMCI SW will not start and
    assertion failed message will be printed. Please update the following
    value to the real maximum if needed and recompile this software.
*/
#define OMCI_ME_DATA_SIZE_MAX			376

/** Number of attributes

    This defines the number of attributes that are supported. */
#define OMCI_ATTRIBUTES_NUM			16

/** Number of supported alarms (as defined in ITU G.984.4) */
#define OMCI_ALARMS_NUM				224

/** Size of bitmap table in bytes */
#define OMCI_ALARM_BITMAP_SIZE			(OMCI_ALARMS_NUM / 8)

#ifdef INCLUDE_PM
#  ifdef INCLUDE_OMCI_ONU_VOIP
/** Number of supported PM Managed Entities */
#    define OMCI_ME_PM_CLASS_NUM			18
#  else
/** Number of supported PM Managed Entities */
#    define OMCI_ME_PM_CLASS_NUM			14
#  endif
#else
/** Number of supported PM Managed Entities */
#  define OMCI_ME_PM_CLASS_NUM			0
#endif

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
/** Number of supported Self description Managed Entities */
#  define OMCI_ME_SD_CLASS_NUM			3
#else
/** Number of supported Self description Managed Entities */
#  define OMCI_ME_SD_CLASS_NUM			0
#endif

#ifdef INCLUDE_CLI_SUPPORT
/** Number of Managed Entities that require CLI support */
#  define OMCI_ME_CLI_CLASS_NUM			1
#else
/** Number of Managed Entities that require CLI support */
#  define OMCI_ME_CLI_CLASS_NUM			0
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
/** Number of supported VoIP Managed Entities */
#  define OMCI_ME_VOIP_CLASS_NUM		9
#else
/** Number of supported VoIP Managed Entities */
#  define OMCI_ME_VOIP_CLASS_NUM		0
#endif

/** Number of base (required) Managed Entities */
#define OMCI_ME_BASE_CLASS_NUM			64

/** Number of customer Managed Entities */
#define OMCI_ME_CUSTOMER_CLASS_NUM		7

/** Number of supported Managed Entity classes.
   \note This is a number of items in the me_def_class_array
   (omci_me_def.c) */
#define OMCI_ME_CLASS_NUM			(OMCI_ME_BASE_CLASS_NUM \
						 + OMCI_ME_CLI_CLASS_NUM \
						 + OMCI_ME_PM_CLASS_NUM \
						 + OMCI_ME_VOIP_CLASS_NUM \
						 + OMCI_ME_SD_CLASS_NUM \
						 + OMCI_ME_CUSTOMER_CLASS_NUM)

/** Please refer to ONU_OMCI_Context */
struct omci_context;

/** Error codes */
enum omci_error {
	/** OMCI messages FIFO is full */
	OMCI_ERROR_MSG_FIFO_FULL = -15,

	/** Invalid attribute value */
	OMCI_ERROR_INVALID_VAL = -14,

	/** Driver request was not executed */
	OMCI_ERROR_DRV = -13,

	/** Invalid Managed Entity ID */
	OMCI_ERROR_INVALID_ME_ID = -12,

	/** Managed Entity was not found */
	OMCI_ERROR_ME_NOT_FOUND = -11,

	/** Managed Entity already exists */
	OMCI_ERROR_ME_EXISTS = -10,

	/** This error is returned by the OMCI action handler when received OMCI
	   message was not properly handled.  It doesn't mean that there is any
	   outstanding error, it only means that action was not executed (due
	   to some errors in the received OMCI message). For the list of errors
	   that can emit this error please refer to ITU-T G.984.4 II.1.3 */
	OMCI_ERROR_ACTION = -9,

	/** Managed Entity class is not supported */
	OMCI_ERROR_ME_NOT_SUPPORTED = -8,

	/** Managed Entity attribute position is out of range or invalid */
	OMCI_ERROR_INVALID_ME_ATTR = -7,

	/** Managed Entity action is out of range or not supported */
	OMCI_ERROR_INVALID_ME_ACTION = -6,

	/** Lock init/get/release error */
	OMCI_ERROR_LOCK = -5,

	/** Memory allocation error */
	OMCI_ERROR_MEMORY = -4,

	/** Invalid pointer */
	OMCI_ERROR_INVALID_PTR = -3,

	/** Bounds check caused an error */
	OMCI_ERROR_BOUNDS = -2,

	/** Error */
	OMCI_ERROR = -1,

	/** Success */
	OMCI_SUCCESS = 0
};

/** Managed Entity attribute properties */
enum omci_attr_prop {
	/** This attribute is not defined by the ITU (for non-supported optional
	   attributes the \ref OMCI_ATTR_PROP_NOT_SUPPORTED is used) */
	OMCI_ATTR_PROP_NONE = 0x0000,

	/** This attribute is readable by the OLT */
	OMCI_ATTR_PROP_RD = 0x0001,

	/** This attribute is writable by the OLT */
	OMCI_ATTR_PROP_WR = 0x0002,

	/** This attribute is Set-by-create */
	OMCI_ATTR_PROP_SBC = 0x0004,

	/** This attribute may generate AVC (Attribute Value Change).
	    This property is used for:
	    - automatic generation of AVC table for OMCI Self Description
	    - automatic sending of AVC messages on attribute change */
	OMCI_ATTR_PROP_AVC = 0x0008,

	/** This attribute is optional */
	OMCI_ATTR_PROP_OPTIONAL = 0x0010,

	/** This attribute is not included in the MIB upload */
	OMCI_ATTR_PROP_NO_UPLOAD = 0x0020,

	/** This is an attribute whose size might be larger than OMCI message
	   (table attribute).
	   Get next message is used to retrieve such attributes */
	OMCI_ATTR_PROP_TABLE = 0x0040,

	/** This attribute data should not be swapped before placing in the OMCI
	   message

	  \note This is for Little Endian machines only!
	*/
	OMCI_ATTR_PROP_NO_SWAP = 0x0080,

	/** This attribute not supported by current implementation */
	OMCI_ATTR_PROP_NOT_SUPPORTED = 0x0100,

	/** This attribute is implemented as template only. */
	OMCI_ATTR_PROP_TEMPLATE = 0x0200,

	/** This attribute is partly implemented only. */
	OMCI_ATTR_PROP_PARTLY = 0x0400
};

/** Managed Entity class properties */
enum omci_me_prop {
	/** Default properties (empty) */
	OMCI_ME_PROP_NONE = 0x0000,

	/** Don't include whole Managed Entity in the MIB upload */
	OMCI_ME_PROP_NO_UPLOAD = 0x0001,

	/** Managed Entity can generate alarms

	   Alarm bitmap will be allocated for such Managed Entities on create */
	OMCI_ME_PROP_HAS_ALARMS = 0x0002,

	/** Managed Entity supports ARC

	   ARC context will be allocated for such Managed Entities on create */
	OMCI_ME_PROP_HAS_ARC = 0x0004,

	/** PM Managed Entity

	   \note PM Managed Entities are not included in the MIB upload
	   \note PM Managed Entities always have alarms bitmap (for TCAs)
	*/
	OMCI_ME_PROP_PM = 0x0008,

	/** PM Managed Entity that is handled internally */
	OMCI_ME_PROP_PM_INTERNAL = 0x0010,

	/** review flag */
	OMCI_ME_PROP_REVIEW = 0x8000,
};

/** The format of the attribute (please refer to ITU-T G.984.4 9.12.10) */
enum omci_attr_type {
	/** Unknown (non-ITU definition) */
	OMCI_ATTR_TYPE_UNKNOWN = 0,

	/** Pointer */
	OMCI_ATTR_TYPE_PTR = 1,

	/** Bit field */
	OMCI_ATTR_TYPE_BF = 2,

	/** Signed integer */
	OMCI_ATTR_TYPE_INT = 3,

	/** Unsigned integer */
	OMCI_ATTR_TYPE_UINT = 4,

	/** String */
	OMCI_ATTR_TYPE_STR = 5,

	/** Enumeration */
	OMCI_ATTR_TYPE_ENUM = 6,

	/** Table */
	OMCI_ATTR_TYPE_TBL = 7
};

/** Debug Levels */
enum omci_dbg {
	/** Verbose outputs */
	OMCI_DBG_MSG = 0,

	/** Prints */
	OMCI_DBG_PRN = 1,

	/** Warnings */
	OMCI_DBG_WRN = 2,

	/** Errors */
	OMCI_DBG_ERR = 3,

	/** No output */
	OMCI_DBG_OFF = 4,

	OMCI_DBG_LVL_MIN = OMCI_DBG_MSG,
	OMCI_DBG_LVL_MAX = OMCI_DBG_OFF,
	OMCI_DBG_LVL_NUM = OMCI_DBG_LVL_MAX + 1
};

/** Debug Modules */
enum omci_dbg_module {
	/** Debug printouts not related to any module; should not be printed */
	OMCI_DBG_MODULE_NO = 0,

	/** Core module */
	OMCI_DBG_MODULE_CORE = 1,

	/** API module */
	OMCI_DBG_MODULE_API = 2,

	/** MIB module */
	OMCI_DBG_MODULE_MIB = 3,

	/** Managed Entity module */
	OMCI_DBG_MODULE_ME = 4,

	/** OMCI messages dump */
	OMCI_DBG_MODULE_MSG_DUMP = 5,

	/** PM module */
	OMCI_DBG_MODULE_PM = 6,

	/** MIB reset module (disable verbose messages on MIB reset) */
	OMCI_DBG_MODULE_MIB_RESET = 7,

	/** IFXOS module */
	OMCI_DBG_MODULE_IFXOS = 8,

	/** VoIP module */
	OMCI_DBG_MODULE_VOIP = 9,

	/** Multicast Control module */
	OMCI_DBG_MODULE_MCC = 10,

	OMCI_DBG_MODULE_MIN = OMCI_DBG_MODULE_NO,
	OMCI_DBG_MODULE_MAX = OMCI_DBG_MODULE_MCC,
	OMCI_DBG_MODULE_NUM = OMCI_DBG_MODULE_MAX + 1
};

/** Known OLT types */
enum omci_olt {
	/** Unrecognized OLT */
	OMCI_OLT_UNKNOWN = 0,

	/** NSN OLT */
	OMCI_OLT_NSN = 1,

	/** Motorola OLT */
	OMCI_OLT_MOTO = 2,

	/** OpenCon OLT */
	OMCI_OLT_OPENCON = 3
};

/** PM interval */
enum omci_pm_interval {
	/** Current interval */
	OMCI_PM_INTERVAL_CURR = 0,
	/** History interval */
	OMCI_PM_INTERVAL_HIST = 1,
	/** Absolute counters value */
	OMCI_PM_INTERVAL_ABS = 2,
	/** Maximum number of history intervals (for internal management,
	    never appears in the me_counters_get handler) */
	OMCI_PM_INTERVAL_MAX,
	/** Sentinel value which indicates the end of the 15-min interval */
	OMCI_PM_INTERVAL_END
};

/** @} */

__END_DECLS

#endif
