/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_time.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_std_defs.h"
#include "ifxos_file_access.h"
#include "ifxos_version.h"

#ifdef INCLUDE_IFXOS_SYSOBJ_SUPPORT
#include "ifxos_sys_show_interface.h"
#endif

#include "daemon/omci_daemon.h"

#ifdef INCLUDE_CLI_SUPPORT
static struct cli_core_context_s *cli_core_ctx = IFX_NULL;
# if defined(INCLUDE_CLI_PIPE_SUPPORT)
static struct cli_pipe_context_s *cli_pipe_ctx = IFX_NULL;
# endif

extern int cli_access_commands_register(struct cli_core_context_s *p_core_ctx);
extern int cli_autogen_commands_register(struct cli_core_context_s *p_core_ctx);

cli_cmd_register__file my_cli_cmds[] = {
	cli_access_commands_register,
	cli_autogen_commands_register,
	IFX_NULL
};
#else
bool g_run = false;
#endif

/** \addtogroup OMCI_DAEMON
   @{
*/

const char omcid_whatversion[] = OMCID_WHAT_STR;

struct omci_config omci_config;

/** Help */
static const char *help =
	"\nOptions:"
	"\n-l, --log                            Specify log file"
	"\n-m, --mib                            Select default MIB"
	"\n-p, --config-path                    Specify custom config path"
#ifdef INCLUDE_CLI_SUPPORT
	"\n-c, --console                        Start console"
#endif
	"\n-t, --trace-ioctl                    Trace onu driver ioctls"
#ifndef OMCI_DEBUG_DISABLE
	"\n-d, --debug_level <number>           Default debug level for all modules"
	"\n                                     (%u - max level .. %u - no output)"
#endif
#if defined(INCLUDE_REMOTE_ONU)
	"\n"
	"\n-r, --remote_dti_agent <ip>[:<port>] Connect to remote ONU with given "
	"\n                                     IP address and optional port"
#endif
	"\n-u, --uni2lan-path                   Specify UNI to LAN mapping path"
	"\n-h, --help                           Print help (this message) and exit"
	"\n-v, --version                        Print version information and exit"
	"\n";

/** Print help

   \param[in] app_name Application executable name
*/
static void omci_help(char *app_name)
{
	omci_printf("OMCI daemon v" PACKAGE_VERSION
		    " (compiled on " __DATE__ " " __TIME__ ")\n");

	if (strlen(app_name) != 0)
		omci_printf( "Usage: %s [options]\n",
			      app_name);
	else
		omci_printf( "Usage: [options]\n");

	omci_printf(help
#ifndef OMCI_DEBUG_DISABLE
		    , OMCI_DBG_LVL_MIN, OMCI_DBG_LVL_MAX
#endif
		   );
}

/** Supported options */
static struct option opt_string[] = {
	{"mib", required_argument, 0, 'm'},
	{"config-path", required_argument, 0, 'p'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
#ifdef INCLUDE_CLI_SUPPORT
	{"console", no_argument, 0, 'c'},
#endif
#if defined(INCLUDE_REMOTE_ONU)
	{"remote_dti_agent", required_argument, 0, 'r'},
#endif
	{"trace-ioctl", no_argument, 0, 't'},
	{"log", required_argument, 0, 'l'},
	{"debug_level", required_argument, 0, 'd'},
	{"uni2lan-path", required_argument, 0, 'u'},
};

/** Options string */
static const char long_opts[] =
	"hvm:p:"
#ifdef INCLUDE_CLI_SUPPORT
	"c"
#endif
	"r:tl:d:u:";

/** Parse command-line arguments

   \param[in] argc Arguments count
   \param[in] argv Array of arguments
*/
static int omci_arg_parse(int argc, char *argv[])
{
	int c;
	int index;

#ifndef OMCI_DEBUG_DISABLE
	int dbg_lvl;
#endif
	int ret;
#define ARG_PARSE_BUFSZ 1024
	char buff[ARG_PARSE_BUFSZ];

	int error = 0;

	do {
		c = getopt_long(argc, argv, long_opts, opt_string, &index);

		if (c == -1)
			return 0;

		switch (c) {
		case 'h':
			omci_help(argv[0]);
			error = 1;
			break;

		case 'v':
			omci_printf( OMCID "OMCI daemon v"
				      PACKAGE_VERSION " (compiled on " __DATE__
				      " " __TIME__ ")\n");
			error = 1;
			break;

#ifdef INCLUDE_CLI_SUPPORT
		case 'c':
			omci_config.start_console = true;
			break;
#endif
		case 'r':
#if defined(INCLUDE_REMOTE_ONU)
			if (optarg == NULL) {
				omci_printfe("Missing value for argument "
					     "'-r'\n");
				error = 1;
				break;
			}
			if (omci_config.remote_ip) {
				omci_free(omci_config.remote_ip);
				omci_config.remote_ip = NULL;
			}
			omci_config.remote_ip = omci_malloc(strlen(optarg) + 1);
			if (omci_config.remote_ip == NULL) {
				omci_printfe("Memory allocation error!\n");
				error = 1;
				break;
			}
			strcpy(omci_config.remote_ip, optarg);
#endif
			break;

		case 'd':
#ifndef OMCI_DEBUG_DISABLE
			if (optarg == NULL) {
				omci_printfe("Missing value for argument "
					     "'-d'\n");
				error = 1;
				break;
			}
			ret = sscanf(optarg, "%d", &dbg_lvl);
			if (!ret) {
				omci_printfe("Invalid value for argument "
					     "'-d'\n");
				error = 1;
				break;
			}
			(void) omci_dbg_level_set((enum omci_dbg) dbg_lvl);
#endif
			break;

		case 'l':
#ifndef OMCI_DEBUG_DISABLE
			if (optarg == NULL) {
				omci_printfe("Missing value for argument "
					     "'-l'\n");
				error = 1;
				break;
			}
			ret = sscanf(optarg, "%" _MKSTR(ARG_PARSE_BUFSZ) "s",
				     buff);
			if (!ret) {
				omci_printfe("Invalid value for argument "
					     "'-l'\n");
				error = 1;
				break;
			}

			if (omci_config.debug_file)
				omci_fclose(omci_config.debug_file);

			omci_config.debug_file =
				omci_fopen(buff, IFXOS_OPEN_MODE_WRITE);
			if (!omci_config.debug_file) {
				omci_printfe("Can't open log file '%s'\n",
					      buff);

				error = 1;
				break;
			}
#endif
			break;
		case 'm':
			if (optarg == NULL) {
				omci_printfe("Missing value for argument "
					     "'-m'\n");
				error = 1;
				break;
			}
			{
				int tmp = 0;
				ret = sscanf(optarg, "%d", &tmp);
				if (!ret) {
					omci_printfe("Invalid value for "
						     "argument '-m'\n");

					error = 1;
					break;
				}
				omci_config.mib = tmp;
			}
			break;

		case 'p':
			if (optarg == NULL) {
				omci_printfe("Missing value for argument "
					     "'-p'\n");
				error = 1;
				break;
			}
			ret = sscanf(optarg, "%" _MKSTR(ARG_PARSE_BUFSZ) "s",
				     buff);
			if (!ret) {
				omci_printfe("Invalid value for argument "
					     "'-p'\n");
				error = 1;
				break;
			}

			if (omci_config.mib_config_path) {
				omci_free(omci_config.mib_config_path);
				omci_config.mib_config_path = NULL;
			}

			omci_config.mib_config_path =
						  omci_malloc(strlen(buff) + 1);
			if (omci_config.mib_config_path == NULL) {
				omci_printfe("Memory allocation error!\n");
				error = 1;
				break;
			}
			strcpy(omci_config.mib_config_path, buff);
			break;

		case 'u':
			if (optarg == NULL) {
				omci_printfe("Missing value for argument "
					     "'-u'\n");
				error = 1;
				break;
			}
			ret = sscanf(optarg, "%" _MKSTR(ARG_PARSE_BUFSZ) "s",
				     buff);
			if (!ret) {
				omci_printfe("Invalid value for argument "
					     "'-u'\n");
				error = 1;
				break;
			}

			if (omci_config.uni2lan_path) {
				omci_free(omci_config.uni2lan_path);
				omci_config.uni2lan_path = NULL;
			}

			omci_config.uni2lan_path =
						  omci_malloc(strlen(buff) + 1);
			if (omci_config.uni2lan_path == NULL) {
				omci_printfe("Memory allocation error!\n");
				error = 1;
				break;
			}
			strcpy(omci_config.uni2lan_path, buff);
			break;

		default:
			break;
		}
	} while (!error);

	omci_free(omci_config.remote_ip);
	omci_config.remote_ip = NULL;
	omci_free(omci_config.mib_config_path);
	omci_config.mib_config_path = NULL;
	omci_free(omci_config.uni2lan_path);
	omci_config.uni2lan_path = NULL;

	return 1;
}

#ifdef INCLUDE_CLI_SUPPORT
static int cli_start(void *usr_data, const bool console)
{
	int ret = 0;

	ret = cli_core_setup__file(&cli_core_ctx, (unsigned int)-1,
				       usr_data, my_cli_cmds);
	if (ret != 0) {
		omci_printfe(OMCID "ERROR(%d) CLI init failed\n", ret);
		return ret;
	}

#if defined(INCLUDE_CLI_PIPE_SUPPORT)
	ret = cli_pipe_init(cli_core_ctx, OMCI_MAX_CLI_PIPES,
			    OMCI_PIPE_NAME, &cli_pipe_ctx);
	if (ret != 0) {
		omci_printfe(OMCID "ERROR(%d) Pipe init failed\n", ret);
		return ret;
	}
#endif

	if (console == true) {
		/* run console */
		ret = cli_console_run(cli_core_ctx, IFX_NULL, IFX_NULL); 
		if (ret != 0) {
			omci_printfe(OMCID"ERROR(%d) CLI Console init failed\n",
									   ret);
			return ret;
		}
	} else {
		/* start dummy interface to wait for quit */
		ret = cli_dummy_if_start(cli_core_ctx, 1000);
		if (ret != 0) {
			omci_printfe(
				OMCID"ERROR(%d) dummy CLI start failed\n", ret);
			return ret;
		}
	}

	return ret;
}

static int cli_stop(void)
{
	int ret = 0;
#ifdef INCLUDE_CLI_PIPE_SUPPORT
	if (cli_core_ctx && cli_pipe_ctx) {
		ret = cli_pipe_release(cli_core_ctx, &cli_pipe_ctx);
		if (ret != 0) {
			omci_printfe(OMCID"ERROR(%d) CLI pipe release failed\n",
					ret);
			return ret;
		}
	}
#endif

	if (cli_core_ctx) {
		ret = cli_core_release(&cli_core_ctx,
				       cli_cmd_core_out_mode_file);
		if (ret != 0) {
			omci_printfe(OMCID"ERROR(%d) CLI core release failed\n",
					ret);
			return ret;
		}
	}

	return ret;
}

static enum omci_error cli_cmd_execute(struct omci_context *context, char *cmd,
				       char *arg, IFXOS_File_t *out)
{
	if (cli_core_cmd_arg_exec__file(cli_core_ctx,
					cmd, arg, (clios_file_t*)out) != 0)
		return OMCI_ERROR;

	return OMCI_SUCCESS;
}
#endif

/** Termination handler

   \param[in] sig Signal
*/
static void shutdown(int sig)
{
#ifdef INCLUDE_CLI_SUPPORT
	char cmd[] = "quit";
#endif

	/* ignore the signal, we'll handle by ourself */
	signal (sig, SIG_IGN);

#ifdef INCLUDE_CLI_SUPPORT
	(void)cli_core_cmd_arg_exec__file(cli_core_ctx, cmd, NULL, stdout);
#else
	g_run = false;
#endif
}

/** Daemon main

   \param[in] argc Arguments count
   \param[in] argv Array of arguments
*/
int main(int argc, char *argv[])
{
	enum omci_error ret = OMCI_SUCCESS;
	struct omci_context *context;
#ifdef INCLUDE_CLI_SUPPORT
	omci_cli_on_exec *cli_cb = cli_cmd_execute;
#else
	omci_cli_on_exec *cli_cb = NULL;
#endif

#ifdef INCLUDE_IFXOS_SYSOBJ_SUPPORT
	IFXOS_SysObject_Setup(0);
#endif

	signal(SIGINT, shutdown);
	signal(SIGTERM, shutdown);

	memset(&omci_config, 0, sizeof(struct omci_config));

	/* default values */
	omci_config.mib = OMCI_OLT_UNKNOWN;

	/* parse command arguments */
	if (omci_arg_parse(argc, argv)) {
		/* return with OK if need to print help or version */
		goto free_args;
	}

#ifndef OMCI_DEBUG_DISABLE
	if (omci_config.debug_file)
		(void)omci_dbg_file_set(omci_config.debug_file);
#endif

	/* read initial config data */
	/* todo: use UCI access functions to read values */
	omci_handler_install();

	/* initialize OMCI stack */
	omci_printf(OMCID "Initialize OMCI daemon " PACKAGE_VERSION
		    " (compiled on " __DATE__ " " __TIME__ ")" "...\n");
	context = NULL;

	ret = omci_init(&context, mib_on_reset, cli_cb,
			omci_config.mib, omci_config.remote_ip,
			omci_config.uni2lan_path);
	if (ret != OMCI_SUCCESS) {
		omci_printfe(OMCID "ERROR(%d) OMCI daemon initialize failed\n",
			     ret);

		goto do_omci_shutdown;
	}

	omci_printf(OMCID "OMCI daemon initialized\n");

#ifdef INCLUDE_CLI_SUPPORT
	ret = cli_start((void*)context, omci_config.start_console);
	if (ret != OMCI_SUCCESS)
		omci_printfe(OMCID "ERROR(%d) CLI start failed\n", ret);

	(void)cli_stop();
#else
	g_run = true;
	/* endless loop without console */
	while (g_run) {
		IFXOS_SecSleep(1);
	}
#endif /* #ifdef INCLUDE_CLI_SUPPORT*/

do_omci_shutdown:
	(void)omci_shutdown(context);

	omci_printf(OMCID "finished\n");

free_args:
	omci_free(omci_config.remote_ip);
	omci_free(omci_config.mib_config_path);

#ifdef INCLUDE_IFXOS_SYSOBJ_SUPPORT
	IFXOS_SysObject_ShowAll(IFXOS_SYS_OBJECT_MEM_ALLOC);
	IFXOS_SysObject_Cleanup();
#endif

#ifndef OMCI_DEBUG_DISABLE
	if (omci_config.debug_file)
		omci_fclose(omci_config.debug_file);
#endif

	return (int)ret;
}

/** @} */
