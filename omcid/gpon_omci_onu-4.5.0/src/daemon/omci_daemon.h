/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_daemon_h
#define _omci_daemon_h

#ifdef HAVE_GETOPT_H
#  include "getopt.h"
#else

#  ifndef no_argument
/** getopt_long no argument */
#     define no_argument          0
#  endif

#  ifndef required_argument
/** getopt_long required argument */
#     define required_argument    1
#  endif

#  ifndef optional_argument
/** getopt_long optional argument */
#     define optional_argument    2
#  endif

#  include "ifx_getopt.h"
#endif

#include <stddef.h>
#include <signal.h>
#include "omci_interface.h"

#define omci_malloc IFXOS_MemAlloc
#define omci_free IFXOS_MemFree
#define omci_fgets IFXOS_FGets
#define omci_fopen IFXOS_FOpen
#define omci_fclose IFXOS_FClose

#define OMCID "[omcid] "

#define OMCID_WHAT_STR "@(#)OMCI daemon, version " PACKAGE_VERSION \
			" (c) Copyright 2012, Lantiq Deutschland GmbH"

#ifdef INCLUDE_CLI_SUPPORT
#include "ifxos_common.h"
#include "ifx_types.h"

#include "omci_core.h"

#include "lib_cli_config.h"
#include "lib_cli_core.h"
#include "lib_cli_console.h"
#ifdef INCLUDE_CLI_PIPE_SUPPORT
#  include "lib_cli_pipe.h"
#endif

#ifdef INCLUDE_CLI_PIPE_SUPPORT
#  ifndef OMCI_MAX_CLI_PIPES
#    define OMCI_MAX_CLI_PIPES                         1
#  endif
#   define OMCI_PIPE_NAME                        "omci"
#endif
#endif

/** \defgroup OMCI_DAEMON Optical Network Unit - Daemon
   @{
*/

/** This structure represents OMCI initial configuration data */
struct omci_config {
	/** Default MIB */
	enum omci_olt mib;

	/** MIB Config path (specified via command argument) */
	char *mib_config_path;

	/** OMCC version byte (default 0xA0 = G.988 baseline) */
	uint8_t omcc_version;

	/** IOP (Interoperability Option) mask */
	uint32_t iop_mask;

	/** LCT port number (1-4, 9; 0xFF = not configured) */
	uint8_t lct_port;

	IFXOS_File_t *debug_file;

	#ifdef INCLUDE_CLI_SUPPORT
	/** Start console? */
	bool start_console;

	/** Console context */
	struct omci_console_context *console_context;
	#endif
};


extern struct omci_config omci_config;

/** Create required Managed Entities

   \param[in] context ONU OMCI context pointer
*/
enum omci_error mib_on_reset(struct omci_context *context);

/** Parse a single MIB-format line to create an ME with attributes

   \param[in] context OMCI context pointer
   \param[in] line    Line number (for error messages only)
   \param[in] buff    MIB line: "class_id instance_id [attr1 attr2 ...]"
*/
enum omci_error mib_line_parse(struct omci_context *context,
			       unsigned int line, char *buff);

/** @} */

#endif
