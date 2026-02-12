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

	/** Remote ONU IP Address */
	char *remote_ip;

	/** OMCI PPTP Ethernet UNI port ID mapping to LAN port index.
	    (optional, specified via command argument)*/
	char *uni2lan_path;

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

/** @} */

#endif
