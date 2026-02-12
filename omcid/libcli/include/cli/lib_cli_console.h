/******************************************************************************
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 ******************************************************************************/
#ifndef _LIB_CLI_CONSOLE_H
#define _LIB_CLI_CONSOLE_H

/**
   \file lib_cli_console.h
   Command Line Interface - Console defines
*/

#include "lib_cli_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Prompt set feature available */
#define CLI_CONSOLE_HAVE_PROMPT_SET	1

/** Console non blocking mode featuer available
   Currently suppoerted for the following OS:
   - Linux
   - VxWorks
*/
#define CLI_CONSOLE_HAVE_NON_BLOCKING_MODE	1


/** console non blocking mode - wait forever for input */
#define CLIOS_IO_WAIT_FOREVER	((unsigned int) -1)
/** console non blocking mode - no wait for input */
#define CLIOS_IO_NO_WAIT	((unsigned int) 0)


/* forward declaration */
struct cli_console_context_s;



/** User function to read a character from the input

\param
   p_console_ctx points to the console context
\param
   p_in  points to the input stream from which the char is read
\param
   p_b_eof  return pointer, points to eof indication flag
\param
   p_c  return pointer, points to the character to read in

\returns
   1: success, number of characters are returned, char and b_eof are set.
   0: nothing read (non-blocking mode)
   < 0 --> error
*/
typedef int (*cli_console_char_read_fct) (
	struct cli_console_context_s *p_console_ctx,
	clios_file_io_t *p_in_io,
	int *p_b_eof,
	char *p_c);


/** \addtogroup LIB_CLI
   @{
*/

/** \defgroup LIB_CLI_CONSOLE CLI Console
   @{
*/

/** Defines the prompt of the CLI Console.

\remarks
   If this function is set the console prompt will be generated with this function.

\param
   p_console_ctx  CLI Console context pointer.

\return
   Number of printed bytes.

*/
typedef const char *(*cli_console_prompt_fct_t)(
	struct cli_console_context_s *p_console_ctx);

/**
   Initialize the console.

   \param[in]  p_cli_core_ctx  CLI core context pointer.
   \param[in]  p_in   Pointer to stdin descriptor.
   \param[in]  p_out  Pointer to stdout descriptor.
   \param[out] pp_console_ctx  returns the console context.

   \return
   - IFX_ERROR On error
   - IFX_SUCCESS On success
*/
extern int cli_console_init(
	struct cli_core_context_s *p_cli_core_ctx,
	clios_file_io_t *p_in_io,
	clios_file_io_t *p_out_io,
	struct cli_console_context_s **pp_console_ctx);

/**
   Shutdown and release the console

   \param[in]  p_cli_core_ctx  CLI core context pointer.
   \param[out] pp_console_ctx  contains the console context.

   \return
   - IFX_ERROR On error
   - IFX_SUCCESS On success
*/
extern int cli_console_release(
	struct cli_core_context_s *p_cli_core_ctx,
	struct cli_console_context_s **pp_console_ctx);

/**
   This function collects single key input and handles execution of commands.


   \param[out] p_console_ctx  points to the console context.

   \return
   - IFX_SUCCESS if a command was completely entered and successful
                           executed
   - IFX_ERROR if an error occurred or the command "quit" was entered
*/
extern int cli_console_handle(
	struct cli_console_context_s *p_console_ctx);

/** Handle console init non-blocking mode

\param[in]
   p_console_ctx Console context pointer
\param[in]
   non_blocking_enable
\param[in]
   non_blocking_enable

\return
   0 if success
   <0 in case of error
*/
extern int cli_console_init_nb(
	struct cli_console_context_s *p_console_ctx,
	int non_blocking_enable,
	unsigned int cycle_time_ms);

/** Handle console input (non-blocking)

\param[in]
   p_console_ctx Console context pointer
\param[in]
   timeout_ms
*/
extern int cli_console_handle_nb(
	struct cli_console_context_s *p_console_ctx,
	unsigned int *p_timeout_ms);

/** Setup and run a console with the given CLI core.

   \param[in]  p_cli_core_ctx  CLI core context pointer.
   \param[in]  p_in_io   Pointer to stdin descriptor.
   \param[in]  p_out_io  Pointer to stdout descriptor.

   \return
   - IFX_ERROR On error
   - IFX_SUCCESS On success
*/
extern int cli_console_run(
	struct cli_core_context_s *p_cli_core_ctx,
	clios_file_io_t *p_in_io,
	clios_file_io_t *p_out_io);

/** Check if the current console instance is running.

   \param[in]  points to the console context.

   \return
   - 0x1 console is running
   - 0x0 console is not running
*/
extern unsigned int cli_console_is_running(
	struct cli_console_context_s *p_console_ctx);

/**
   This function sets console prompt handler.

   \param[in] p_console_ctx   points to the console context.
   \param[in] console_prompt  console prompt handler.

   \return
   - IFX_ERROR On error
   - IFX_SUCCESS On success
*/
extern int cli_console_prompt_fct_set(
	struct cli_console_context_s *p_console_ctx,
	const cli_console_prompt_fct_t f_cons_prompt);

/**
   This function sets the internal console prompt.

   \param[in] p_console_ctx   points to the console context.
   \param[in] p_new_prompt  points to the new prompt string.

   \return
   - IFX_ERROR On error
   - IFX_SUCCESS On success
*/

extern int cli_console_default_prompt_set(
	struct cli_console_context_s *p_console_ctx,
	const char *p_new_prompt);

/**
   This function sets the char read function for the console.

   This allows to register a user char read function within the console.

\remarks
   Call this function without a function (NULL ptr) to set the internal read
   function again.

\param[in]
   p_console_ctx   points to the console context.
\param[in]
   f_char_read  user character read function.

\return
   - IFX_ERROR On error
   - IFX_SUCCESS On success
*/
extern int cli_console_char_read_fct_set(
	struct cli_console_context_s *p_console_ctx,
	const cli_console_char_read_fct f_char_read);



/** @} */

/** @} */

#ifdef __cplusplus
}
#endif

#endif	/* #ifndef _LIB_CLI_CONSOLE_H */

