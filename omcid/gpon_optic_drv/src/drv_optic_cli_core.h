/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_cli_core.h
   Device Driver, Command Line Interface
*/
#ifndef _optic_cli_h
#define _optic_cli_h

#include "drv_optic_std_defs.h"
#include "drv_optic_common.h"

EXTERN_C_BEGIN

#ifdef INCLUDE_CLI_SUPPORT

/** @defgroup CLI_INTERFACE Command Line Interface
 *  This file contains the informations to access the device driver.
 *  @{
 */

/** empty command name */
#define CLI_EMPTY_CMD		" "
/** help for empry command */
#define CLI_EMPTY_CMD_HELP	"n/a"

/**
   Initialize the command line interface.

   \return
   - 0       on success
   - -1    on failure
*/
int optic_cli_init ( void );

/**
   Clean command  list.

   \return
   - 0 successful operation
*/
int optic_cli_shutdown ( void );

typedef int (*optic_cli_entry) ( struct optic_device *p_dev,
				 const char *p_cmds,
				 const uint32_t bufsize_max,
				 char *p_out );

/**
   Add a command to the list.

   \param short_name short command name
   \param long_name  long command name
   \param func       command entry point

   \return
   - -1 no more space left in command table
   - 0 command added to the command table
*/
int optic_cli_command_add ( char const *short_name,
			    char const *long_name,
			    optic_cli_entry cli_entry );

/**
   Execute CLI command.

   \param devCtx   device context
   \param buffer   command string buffer (in & out)
   \param size     maximum size of the buffer

   \return
   - number of bytes in return buffer on success
   - -1 on failure
*/
int optic_cli_command_execute ( struct optic_device *p_dev,
			        char *buffer,
			        const uint32_t size );

/**
   Register the non-generated commands.
*/
void optic_cli_misc_register ( void );

/**
   Register the generated commands.
*/
void optic_cli_autogen_register ( void );

/**
   sscanf implementation with uint8 support.
*/
int32_t optic_cli_sscanf ( const char *buf, char const *fmt,...);

/** @} */

#endif                          /* INCLUDE_CLI_SUPPORT */

EXTERN_C_END

#endif                          /* _optic_cli_h */
