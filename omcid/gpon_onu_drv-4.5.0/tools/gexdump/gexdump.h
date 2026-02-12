/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __gexdump_h
#define __gexdump_h

#ifdef HAVE_CONFIG_H
#  include "drv_onu_config.h"
#endif

#include "include/drv_onu_resource.h"
#include "include/drv_onu_interface.h"
#include "include/drv_onu_common_interface.h"
#include "include/drv_onu_gpe_interface.h"
#include "include/drv_onu_gpe_tables_interface.h"

/** ONU device path */
#define ONU_DEVICE_PATH "/dev/onu0"

#define EX_DUMP_VERSION "0.0.6"

/** version string */
#define EX_DUMP_WHAT_STR "@(#)GPON Exception Dump Tool, version " \
			 EX_DUMP_VERSION " " ONU_COPYRIGHT

#define ARRAY_SIZE(array) (sizeof(array)/sizeof((array)[0]))

/** Netdev interface name for WAN/LAN exception packets*/
#define EX_DUMP_EXCEPTION_IF_NAME	"exc"

/** Egreess Queue ID for exception packets*/
#define EX_DUMP_EXCEPTION_QID		0xb0

#define EX_DUMP_HEX_BYTES_PER_LINE	16
#define EX_DUMP_HEX_CHARS_PER_BYTE	3
#define EX_DUMP_HEX_CHARS_PER_LINE	(EX_DUMP_HEX_BYTES_PER_LINE * \
						EX_DUMP_HEX_CHARS_PER_BYTE + 1)

#define EX_DUMP_LOG_FILE_MAX_PATH	256


/** Enumeration specifies exception direction
*/
enum ex_direction {
	/** Upstream */
	EX_DIR_UPSTREAM = 0,
	/** Downstream */
	EX_DIR_DOWNSTREAM = 1,
	/** Delimeter*/
	EX_DIR_LAST
};

/** Enumeration specifies action for an egress exception packets
*/
enum ex_action {
	/** Passthrough egress exception packets */
	EX_ACTION_PASS = 0,
	/** Drop egress exception packets */
	EX_ACTION_DROP = 1,
	/** Delimeter */
	EX_ACTION_LAST
};

/** Enumeration specifies format for an exception packets dump
*/
enum ex_format {
	/** Dump exception packet header */
	EX_FORMAT_HDR = 0,
	/** Dump packet info */
	EX_FORMAT_INFO = 1,
	/** Additional HEX dump*/
	EX_FORMAT_HEX = 2,
	/** Delimeter */
	EX_FORMAT_LAST
};

#endif

