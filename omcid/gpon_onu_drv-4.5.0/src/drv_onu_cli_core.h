/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_cli_core.h
   Device Driver, Command Line Interface
*/
#ifndef _onu_cli_h
#define _onu_cli_h

#include "drv_onu_std_defs.h"

EXTERN_C_BEGIN
#ifdef INCLUDE_CLI_SUPPORT

#if defined(LINUX) && defined(__KERNEL__)
long onu_strtol(const char *cp, char **endp, unsigned int base);
long long onu_strtoll(const char *cp, char **endp, unsigned int base);
unsigned long onu_strtoul(const char *cp, char **endp, unsigned int base);
unsigned long long onu_strtoull(const char *cp, char **endp, unsigned int base);
#else

#ifdef WIN32
	#if _MSC_VER < 1300
		#define strtoll(p, e, b) ((*(e) = (char*)(p) + (((b) == 10) ? strspn((p), "0123456789") : 0)), _atoi64(p))
	#else
		#define strtoll(p, e, b) _strtoi64(p, e, b)
		#define strtoull(p, e, b) _strtoui64(p, e, b)
	#endif
#endif

#define onu_strtol strtol
#define onu_strtoll strtoll
#define onu_strtoul strtoul
#define onu_strtoull strtoull
#endif

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
int onu_cli_init(void);

/**
   Clean command  list.

   \return
   - 0 successful operation
*/
int onu_cli_shutdown(void);

typedef int (*onu_cli_entry_t) (struct onu_device *, const char *commands,
			        const uint32_t max_buf_size, char *out);

/**
   Add a command to the list.

   \param short_name short command name
   \param long_name  long command name
   \param func       command entry point

   \return
   - -1 no more space left in command table
   - 0 command added to the command table
*/
int onu_cli_command_add(char const *short_name, char const *long_name,
			onu_cli_entry_t cliEntry);

/**
   Execute CLI command.

   \param dev_ctx   device context
   \param buffer   command string buffer (in & out)
   \param size     maximum size of the buffer

   \return
   - number of bytes in return buffer on success
   - -1 on failure
*/
int onu_cli_command_execute(struct onu_device *dev_ctx, char *buffer,
			    const uint32_t size);

/**
   Register the generated commands.
*/
void onu_cli_autogen_register(void);

/**
   Register the misc commands.
*/
void onu_cli_misc_register(void);

/**
   sscanf implementation with uint8 support.
*/
int32_t onu_cli_sscanf(const char *buf, char const *fmt, ...);

/** @} */

#endif				/* INCLUDE_CLI_SUPPORT */

EXTERN_C_END
#endif				/* _onu_cli_h */
