/******************************************************************************
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 ******************************************************************************/
#ifndef _LIB_CLI_CORE_H
#define _LIB_CLI_CORE_H

/**
   \file lib_cli_core.h
   Command Line Interface - core defines
*/

/** \defgroup LIB_CLI Lantiq Command Line Interface (CLI)
   Provides a generic library for setup a CLI.
  @{ */

/** \defgroup LIB_CLI_CORE CLI Core Functionality

   The CLI Library provides a generic functionality to setup a user CLI.
   Therefore the user only has to register its own user specific CLI functions
   in a corresponding way. The CLI takes over the organisation und execution
   of the user CLI commands.

   The CLI Library supports 2 kinds of CLI function formats which are related to the
   OS environment and the use case:
   - Printout via buffer.
   - Printout via file functions.

   To setup a user CLI the following steps are necessary:
   - Create the CLI core (\ref cli_core_init), here the CLI context will be allocated
     and initialized. After the creation the CLI core is in the "counting" mode.
   - Register all built-in and user commands for counting. Here the required memory space
     for the binary search tree is calculated.
   - Switch to registration mode. Here the memory for the binary search tree is allocates.
   - Register all commands (built-in and user commands) a second time, here the
     binary search tree will be setup.
   - Activate CLI Core

   The CLI Core provides the \ref cli_core_setup__file (for file printout) setup
   function which wraps all above mentioned steps. The CLI commands for the setup
   are provided within a corresponding array (see below).

\attention
   For setup the search tree the CLI Core calculates the number of required nodes and
   allocates the required memory at once. Out form this, it will be not possible to
   register CLI commands after the search tree has been created.

   All CLI command functions must have the form \ref cli_cmd_user_fct_file_t (for
   file printout) or \ref cli_cmd_user_fct_buf_t (for buffer printout).
   The generation of the user CLI Function is not part of the LIB CLI, it is done
   by the user project in a manual or generic way (via swig and XML parsing).
   At the end all user commands are collected in one function which does the registration.

   Depending on the user application you can have several such register functions - at least
   one with the generic generated functions and one with the manual CLI commands.

   For the setup all these register functions are collected within one null-terminated array
   and are provided to the above mentioned \ref cli_core_setup__file .

*/


/** \defgroup LIB_CLI_CORE_FILE_OUT CLI Function - Printout via File Descriptor

   Here the user CLI functions returns the result (string) of the CLI via standard
   file printout functions (like fprintf).
   For printouts to the console, the standard "stdout" or "stderr" can be used.
   For printouts into a user given buffer it is enough to setup a so called memory
   mapped file.
   It is in the responsibilty of the user to provide a corresponding valid file descriptor.

\remarks
   It is not necessary to support a complete file system, it is enough to support the
   corresponding file access and print functions.
*/

/** \defgroup LIB_CLI_CORE_BUF_OUT CLI Function - Printout via Buffer

   Here the user CLI functions returns the result (string) of the CLI via a buffer.
   This kind of CLI functions can be used within an environment without file system support
   (like within a driver environment).
   It is in the responsibility of the user to provide the buffer.
*/


/** \defgroup LIB_CLI_CORE_GROUP CLI Core - CLI Groups

   With the CLI group extention the user have the possibility to group the CLI commands.
   Here the CLI Core assigns the commands depenting on the long name to a corresponding
   group. Therefore the user has to provide the requried group setup:
   - List of all group description (description)
   - List of all search keys + group assignment
*/

/** @} */

#ifdef __cplusplus
extern "C" {
#endif

/** Current CLI Core interface version:
    Version <undefined>: before interface header cleanup
    Version 2: header clean-up, core context struct removed from the interface
*/
#define CLI_CORE_INTERFACE_VERSION		2

/** this version supports grouping of the commands (see cli_core_group_setup__file) */
#define CLI_HAVE_GROUP_SUPPORT	1

/** this version supports multiple instance support (see cli_core_clone) */
#define CLI_HAVE_MULTIPLE_INSTANCE_SUPPORT	1


/** empty command name */
#define CLI_EMPTY_CMD		" "
/** help for empry command */
#define CLI_EMPTY_CMD_HELP	"n/a"

/** User selection mask all - allows to group commands from user side */
#define CLI_USER_MASK_ALL	0x0000FFFF

/** Register build-in command "Help" */
#define CLI_BUILDIN_REG_HELP	0x00000001
/** Register build-in command "Quit" */
#define CLI_BUILDIN_REG_QUIT	0x00000002
/** Register build-in command "What" */
#define CLI_BUILDIN_REG_WHAT	0x00000004

/** Forward declaration, file IO */
typedef void clios_file_io_t;

#if defined(CLI_SPECIAL_IO_FILE_TYPE) && (CLI_SPECIAL_IO_FILE_TYPE == 1)
/** Special IO file type */
struct cli_spec_file_io_s
{
   /** a regular IO file*/
   clios_file_io_t *p_file;
   /** memory buffer*/
   char *p_buffer;
   /** memory buffer size*/
   unsigned int buffer_size;
};
#endif

/** Forward declaration, command node element for binary tree */
struct cli_cmd_node_s;

/** Forward declaration, CLI core context */
struct cli_core_context_s;

/** implementation dependend declarations */
enum cli_cmd_status_e
{
	/** command node valid */
	e_cli_status_ok,
	/** command node memory */
	e_cli_status_mem_exhausted,
	/** command node key duplicate */
	e_cli_status_duplicate_key,
	/** command node key not found */
	e_cli_status_key_not_found,
	/** command node key invalid */
	e_cli_status_key_invalid
};

/** states of the cli command register process */
enum cli_cmd_core_state_e {
	/** CLI cmd core state - memory count mode */
	e_cli_cmd_core_count,
	/** CLI cmd core state - mem allocated, cmd register mode */
	e_cli_cmd_core_allocate,
	/** CLI cmd core state - active, ready for operation */
	e_cli_cmd_core_active,
	/** CLI cmd core state - delete, release binary tree */
	e_cli_cmd_core_delete
};

/** output mode for the CLI command user function */
enum cli_cmd_core_out_mode_e {
	/** printout to buffer */
	cli_cmd_core_out_mode_buffer,
	/** printout to file */
	cli_cmd_core_out_mode_file
};

/** Group key entry to assign a search key to a group */
struct cli_group_key_entry_s
{
	/** group search key used to sort the CLI commands (long name) */
	char const *p_search_key;
	/** assignes the search key to a group */
	unsigned char group_num;
};

/** Buffer printout, user CLI function type
   For the buffer printout a user CLI function must have this form.

\param
   p_user_data  pointer the the user specific data. The pointer has been set while
                setup and the CLI provides this pointer to each user CLI function call.
\param
   p_cmd  points to the user CLI command (string) to be executed. Therefore the
          CLI core separates the command form the arguments and searchs for the
          command within the search tree.
\param
   out_buf_size  size of the user printout buffer.
\param
   p_out_buf  points to the user buffer for the result printout.

\return
   Number of printed bytes.

*/
typedef int (*cli_cmd_user_fct_buf_t)(
	void *p_user_data,
	const char *p_cmd,
	const unsigned int out_buf_size,
	char *p_out_buf);

/** File printout, user CLI function type
   For the file printout a user CLI function must have this form.

\param
   p_user_data  pointer the the user specific data. The pointer has been set while
                setup and the CLI provides this pointer to each user CLI function call.
\param
   p_cmd  points to the user CLI command (string) to be executed. Therefore the
          CLI core separates the command form the arguments and searchs for the
          command within the search tree.
\param
   p_out_file  points to printout file (can be stdout, stderr, user given file).

\return
   Number of printed bytes.

*/
typedef int (*cli_cmd_user_fct_file_t)(
	void *p_user_data,
	const char *p_cmd,
	clios_file_io_t *p_out_file);

/** Exit callback with private pointer. */
typedef int (*cli_exit_callback) (void *);

/** Event callback with private pointer and text of decoded event */
typedef int (*cli_event_callback) (void *, char *);

/** Message dump callback with private pointer and text of decoded event */
typedef int (*cli_dump_callback) (void *, char *);


/** CLI context to control several CLI's */
struct cli_user_context_s
{
	/** points to the next user CLI */
	struct cli_user_context_s *p_next;
	/** points to the user data for callback handling */
	void *p_user_data;
	/** callback function - on exit */
	cli_exit_callback exit_cb_fct;
	/** callback function - on event */
	cli_event_callback event_cb_fct;
	/** callback function - on dump */
	cli_dump_callback dump_cb_fct;
};

/**
   User command register function type.

   All user CLI commands are collected at the end in one functions which does
   the registration. This function will be used for the setup process.

*/
typedef int (*cli_cmd_register__file) (struct cli_core_context_s *);

/** contains the CLI version string */
extern const char g_cli_version_what[];

/** Own implementation of the sscanf functions with additional format characters */
extern int cli_sscanf(const char *buf, char const *fmt, ...);

/** Shutdown the CLI core, release the binary search tree for the selected mode.

\param
   p_core_ctx points the the CLI context
\param
   out_mode selects the output mode (buffer/file printout)

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_core_cfg_cmd_shutdown(
	struct cli_core_context_s *p_core_ctx,
	enum cli_cmd_core_out_mode_e out_mode);


/** Switch the CLI to registration mode.
   While counting mode the CLI counts all registration calles. This function
   allocates the required memeory and switch over the registration mode.

\param
   p_core_ctx points the the CLI context

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_core_cfg_mode_cmd_reg(
	struct cli_core_context_s *p_core_ctx);


/** Activate the CLI.
   After counting, memory allocation and registration the CLI is ready for use.

\param
   p_core_ctx points the the CLI context

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.
*/
extern int cli_core_cfg_mode_active(
	struct cli_core_context_s *p_core_ctx);

/** Shutdown and release the CLI.

\param
   pp_core_ctx  contains the CLI context pointer
\param
   out_mode selects the output mode (buffer/file printout)

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_core_release(
	struct cli_core_context_s **pp_core_ctx,
	enum cli_cmd_core_out_mode_e out_mode);


/** Create and setup a CLI.

\param
   pp_core_ctx  returns the created CLI context pointer.
\param
   out_mode selects the output mode (buffer/file printout)
\param
   p_cli_fct_data pointer the the user data, provided with each CLI call.

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_core_init(
	struct cli_core_context_s **pp_core_ctx,
	enum cli_cmd_core_out_mode_e out_mode,
	void *p_cli_fct_data);

/** Setup the group handling within the CLI.

\param
   p_core_ctx  CLI context pointer.
\param
   p_group_list  null-terminated list of groups (description)
\param
   p_key_entries  null-terminated list of key entries (\ref cli_group_key_entry_s)
      - search key which is compared with the CLI command long name
      - assignment to a group (must match with the group list).

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_GROUP
*/
extern int cli_core_user_group_init(
	struct cli_core_context_s *p_core_ctx,
	char const *p_group_list[],
	struct cli_group_key_entry_s const *p_key_entries);


/** Register the built-in CLI commands.
   Therefore the commands are selected via a mask.

\param
   p_core_ctx  CLI context pointer.
\param
   select_mask mask to select the built-in commands
      (see \ref CLI_USER_MASK_ALL to get all).

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_core_buildin_register(
	struct cli_core_context_s *p_core_ctx,
	unsigned int select_mask);


/** Check the given command if the help output is requested.
   (If the help is requested return the usage-string)

\param
   p_cmd  points to the command.
\param
   p_usage points to the usage-string
\param
   bufsize_max size of the user printout buffer
\param
   p_out points to user printout buffer

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_BUF_OUT
*/
extern int cli_check_help__buffer(
	const char *p_cmd,
	const char *p_usage,
	const unsigned int bufsize_max,
	char *p_out);

/** Check the given command if the help output is requested.
   (If the help is requested return the usage-string)

\param
   p_cmd  points to the command.
\param
   p_usage points to the usage-string
\param
   p_file_io points to used file descriptor for printout

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_FILE_OUT
*/
extern int cli_check_help__file(
	const char *p_cmd,
	const char *p_usage,
	clios_file_io_t *p_file_io);

/** Command Registration - add a CLI command.

\param
   p_core_ctx  CLI context pointer.
\param
   group_mask  user given group assignment.
\param
   p_short_name  points to the short CLI Command name.
\param
   p_long_name  points to the long CLI Command name.
\param
   cli_cmd_user_fct_buf  points to the CLI function to execute (buffer printout)

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_BUF_OUT
*/
extern int cli_core_key_add__buffer(
	struct cli_core_context_s *p_core_ctx,
	unsigned int group_mask,
	char const *p_short_name,
	char const *p_long_name,
	cli_cmd_user_fct_buf_t cli_cmd_user_fct_buf);

/** Command Registration - add a CLI command.

\param
   p_core_ctx  CLI context pointer.
\param
   group_mask  user given group assignment.
\param
   p_short_name  points to the short CLI Command name.
\param
   p_long_name  points to the long CLI Command name.
\param
   cli_cmd_user_fct_file  points to the CLI function to execute (file printout)

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_FILE_OUT
*/
extern int cli_core_key_add__file(
	struct cli_core_context_s *p_core_ctx,
	unsigned int group_mask,
	char const *p_short_name,
	char const *p_long_name,
	cli_cmd_user_fct_file_t cli_cmd_user_fct_file);

/** Command Execution - executes a CLI command.

\param
   p_core_ctx  CLI context pointer.
\param
   p_cmd_arg_buf  points to the user buffer which contains the command (+ args)
      and which is also  used to return the result string.
\param
   buffer_size  size of the user buffer.

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_BUF_OUT
*/
extern int cli_core_cmd_exec__buffer(
	struct cli_core_context_s *p_core_ctx,
	char *p_cmd_arg_buf,
	const unsigned int buffer_size);

/** Command Execution - executes a CLI command.

\param
   p_core_ctx  CLI context pointer.
\param
   p_cmd_arg_buf  points to the user buffer which contains the command (+ args).
\param
   p_file_io points to used file descriptor for printout

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_FILE_OUT
*/
extern int cli_core_cmd_exec__file(
	struct cli_core_context_s *p_core_ctx,
	char *p_cmd_arg_buf,
	clios_file_io_t *p_file_io);

/** Command Execution - executes a CLI command.
   CLI command and command arguments are already seperated.

\param
   p_core_ctx  CLI context pointer.
\param
   p_cmd  points to the CLI command only.
\param
   p_arg  points to the CLI arguments.
\param
   p_file_io points to used file descriptor for printout

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_FILE_OUT
*/
extern int cli_core_cmd_arg_exec__file(
	struct cli_core_context_s *p_core_ctx,
	char *p_cmd,
	char *p_arg,
	clios_file_io_t *p_file_io);


/** CLI Setup - setup a CLI interface with given user functions.

\param
   pp_core_ctx  returns the CLI context.
\param
   builtin_selmask  mask to select the built-in commands.
\param
   p_user_fct_data  pointer the the user data, provided with each CLI call.
\param
   cmd_reg_list  null-terminated list of register functions.

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_FILE_OUT
*/
extern int cli_core_setup__file(
	struct cli_core_context_s **pp_core_ctx,
	unsigned int builtin_selmask,
	void *p_user_fct_data,
	const cli_cmd_register__file cmd_reg_list[]);

/** CLI Setup - setup a CLI interface, based on the given already existing CLI Core:

\remarks
   Take over the command search tree and group config from the parent CLI core - no mem alloc.

\param
   p_core_ctx_parent  points to the parent (reference) CLI Core.
\param
   pp_core_ctx  returns the CLI context.
\param
   instance_num  instance number of this core.
\param
   p_user_fct_data  pointer the the user data, provided with each CLI call.

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_FILE_OUT
*/
extern int cli_core_clone(
	struct cli_core_context_s *p_core_ctx_parent,
	struct cli_core_context_s **pp_core_ctx,
	unsigned int instance_num,
	void *p_user_fct_data);


/** CLI Setup - setup a CLI interface with given user functions and group handling.

\param
   pp_core_ctx  returns the CLI context.
\param
   builtin_selmask  mask to select the built-in commands.
\param
   p_user_fct_data  pointer the the user data, provided with each CLI call.
\param
   cmd_reg_list  null-terminated list of register functions.
\param
   p_group_list  null-terminated list of groups (description)
\param
   p_key_entries  null-terminated list of key entries (\ref cli_group_key_entry_s)
      - search key which is compared with the CLI command long name
      - assignment to a group (must match with the group list).

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE_FILE_OUT
*/
extern int cli_core_group_setup__file(
	struct cli_core_context_s **pp_core_ctx,
	unsigned int builtin_selmask,
	void *p_user_fct_data,
	const cli_cmd_register__file cmd_reg_list[],
	char const *p_group_list[],
	struct cli_group_key_entry_s const *p_key_entries);

/** Registers an user interface within the CLI core.
   For normal or special event handling (autonomous messages, exit, message dumps)
   The CLI must be able to distribute this autonomoues information to all running
   user interfaces. Therefore the user interfaces must be registered.

\param
   p_core_ctx  CLI context pointer.
\param
   p_cb_data  points to data provided to a callback function call.
\param
   exit_cb_fct  points to the callback function called on exit.
\param
   event_cb_fct  points to the callback function called on events.
\param
   dump_cb_fct  points to the callback function called on message dump.
\param
   pp_user_ctx  returns the context of the created user interface
      (required for unregistration).

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_user_if_register(
	struct cli_core_context_s *p_core_ctx,
	void *p_cb_data,
	cli_exit_callback exit_cb_fct,
	cli_event_callback event_cb_fct,
	cli_dump_callback dump_cb_fct,
	struct cli_user_context_s **pp_user_ctx);

/** Registers an user interface within the CLI core.
   For normal or special event handling (autonomous messages, exit, message dumps)
   The CLI must be able to distribute this autonomoues information to all running
   user interfaces. Therefore the user interfaces must be registered.

\param
   p_core_ctx  CLI context pointer.
\param
   pp_user_ctx  contains the user interface context.

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_user_if_unregister(
	struct cli_core_context_s *p_core_ctx,
	struct cli_user_context_s **pp_user_ctx);


/** Starts a dummy interface.
   This function can be used to wait for the termination / shutdown.

\remarks
   The application has been setup and for the control a pipe interface is used.
   The main program simple enters a dummy interface and so the main function
   simple waits until the application will be shutdown via the pipe interface.
   The "quit" command from the pipe interface will also shutdown the dummy interface
   and the function returns.

\param
   p_core_ctx  CLI context pointer.
\param
   sleep_ms  sleep time [ms].

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_dummy_if_start(
	struct cli_core_context_s *p_core_ctx,
	unsigned int sleep_ms);

/** Get name of the command that is being executed.

\remarks
   The only valid context in which it's allowed to call this routine is the
   CLI command handler itself, so it may be used by the command handler
   to get the name of the command that's being executed in case when the same
   handler has been registered for different commands.

\param
   p_core_ctx  CLI context pointer.

\return
   NULL - failed
   non-NULL - const char pointer containing name of the command; this pointer
              becomes invalid as soon as execution of the handler ends
              (use strdup if you need to preserve it for some reason).

\ingroup LIB_CLI_CORE
*/
extern const char *cli_cmd_name_get(struct cli_core_context_s *p_core_ctx);


/** Returns the instance number of the given CLI Core.

\param
   p_core_ctx  CLI context pointer.

\return
   instance number
   IFX_ERROR if the core context is not valid.

\ingroup LIB_CLI_CORE
*/
extern int cli_core_inst_num_get(struct cli_core_context_s *p_core_ctx);


/** Returns the number of existing clones attached to the given CLI Core (reference core).

\param
   p_core_ctx  CLI context pointer.

\return
   number of attached clones.
   IFX_ERROR if the core context is not valid.

\ingroup LIB_CLI_CORE
*/
extern int cli_core_num_of_clones_get(struct cli_core_context_s *p_core_ctx);


/** Iterate over all registered CLI commands

\param
   p_core_ctx  CLI context pointer
\param
   hander  Handler which is called for each command
\param
   user_data  Data passed to handler

\return
   none
*/
extern void cli_traverse(struct cli_core_context_s *p_core_ctx,
		int (*handler)(const char *s, void *user_data),
		void *user_data);


/** Issues the event callback for all registered user interfaces.

\param
   p_core_ctx  CLI context pointer.
\param
   p_event  points to event's text.

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_user_if_event(
	struct cli_core_context_s *p_core_ctx,
	char *p_event
);

/** Issues the dump callback for all registered user interfaces.

\param
   p_core_ctx  CLI context pointer.
\param
   p_dump  points to dump.

\return
   IFX_SUCCESS - operation done
   IFX_ERROR - failed.

\ingroup LIB_CLI_CORE
*/
extern int cli_user_if_dump(
	struct cli_core_context_s *p_core_ctx,
	char *p_dump
);

#ifdef __cplusplus
}
#endif

#endif  /* _LIB_CLI_CORE_H */




