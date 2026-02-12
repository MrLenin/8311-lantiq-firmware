/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _LIB_CLI_PIPE_H
#define _LIB_CLI_PIPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lib_cli_config.h"
#include "lib_cli_core.h"

#include "ifx_types.h"
#include "ifxos_lock.h"
#include "ifxos_thread.h"
#include "ifx_fifo.h"
#include "ifxos_event.h"

#ifndef CLI_PIPE_NAME_FORMAT
	/** defines the pipe name <name>_<num>_<type> ("myname_0_cmd")*/
#	define CLI_PIPE_NAME_FORMAT	"%s_%u_"
#endif

#ifndef PIPE_DEBUG
#	define PIPE_DEBUG   0
#endif

/* forward declaration */
struct cli_pipe_env_s;

/** CLI Pipe Context */
struct cli_pipe_context_s
{
	IFXOS_lock_t lock_cb;

	/** Thread control of the log thread */
	IFXOS_ThreadCtrl_t thr_ctrl_log;

	/** Log thread - FIFO memory */
	unsigned long *p_fifo_mem;
	/** Log thread - FIFO */
	IFX_VFIFO log_fifo;
	/** Log thread - FIFO event to wakeup processing */
	IFXOS_event_t event_fifo;

	/** number of used pipes */
	unsigned short n_pipes;
	/** pipe interface memory */
	struct cli_pipe_env_s *p_pipe_env_mem;
	/** collect available pipe interfaces */
	struct cli_pipe_env_s *p_cli_pipe_env[MAX_CLI_PIPES];
};

extern int cli_pipe_init(
	struct cli_core_context_s *p_cli_core_ctx,
	unsigned short n_pipes,
	char const *p_pipe_name,
	struct cli_pipe_context_s **pp_cli_pipe_context);

extern int cli_single_pipe_init(
	struct cli_core_context_s *p_cli_core_ctx,
	unsigned short pipe_num,
	char const *p_pipe_name,
	struct cli_pipe_context_s **pp_cli_pipe_context);

extern int cli_pipe_release(
	struct cli_core_context_s *p_cli_core_ctx,
	struct cli_pipe_context_s **pp_cli_pipe_context);


#ifdef __cplusplus
}
#endif

#endif	/* #ifndef _LIB_CLI_PIPE_H */

