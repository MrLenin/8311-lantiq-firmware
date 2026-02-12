#ifndef _IFXOS_GENERIC_OS_FILE_ACCESS_H
#define _IFXOS_GENERIC_OS_FILE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains Generic OS definitions for File Access.
*/

/** \defgroup IFXOS_FILE_ACCESS_GENERIC_OS_APPL File Access (Generic OS)

   This Group contains the Generic OS File Access definitions and function. 

   To access a file the standard C-lib functions for file handling are wrapped.

   Further a file type is provided which is used for further access destinations
   (streams) like files, pipes, stdin, stdout.

\ingroup IFXOS_LAYER_GENERIC_OS
*/

/** \defgroup IFXOS_MEM_FILE_GENERIC_OS Memory File (Generic OS)

   This Group contains the Generic OS Memory File definitions and function. 

   The memory file feature provides the possibility to map a memory to a file.
   This allows to use the standard file operation on the memory block.

\ingroup IFXOS_LAYER_GENERIC_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Generic OS adaptation - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"

/* ============================================================================
   IFX Generic OS adaptation - supported features
   ========================================================================= */

/** IFX Generic OS adaptation - User support "file access" */
#define IFXOS_HAVE_FILE_ACCESS                     1
/** IFX Generic OS adaptation - User support "file system" */
#define IFXOS_HAVE_FILESYSTEM                      1
/** IFX Generic OS adaptation - User support "memory file" */
#define IFXOS_HAVE_MEMORY_FILE                     1

/* ============================================================================
   IFX Generic OS adaptation - defines, types
   ========================================================================= */

/** IFX Generic OS adaptation - Rebuild the missing "fmemopen" */
#ifndef IFXOS_ADD_LOCAL_FMEMOPEN
#  define IFXOS_ADD_LOCAL_FMEMOPEN                 1
#endif

/** IFX Generic OS adaptation - User support "static memory file" 
   No standard file system calls are required.

\attention 
   For private memory file support you have to use the corresponding
   IFXOS_FMemClose function.
*/
#ifndef IFXOS_ADD_STATIC_MEMORY_FILE
#  define IFXOS_ADD_STATIC_MEMORY_FILE             0
#endif

/** max number of supported private memory files */
#define IFXOS_MAX_NUM_OF_STATIC_MEMFILES           3

/** Generic OS User - file access, type FILE for stream handling */
typedef struct {
   IFX_int_t   dummy_stat;
} IFXOS_File_t;

extern IFXOS_File_t *ifx_stderr;
extern IFXOS_File_t *ifx_stdout;
extern IFXOS_File_t *ifx_stdin;

/** Generic OS User - map to stderr */
#define IFXOS_STDERR          ifx_stderr
/** Generic OS User - map to stdout */
#define IFXOS_STDOUT          ifx_stdout
/** Generic OS User - map to stdin */
#define IFXOS_STDIN           ifx_stdin

/** Generic OS User - Open  text  file  for  reading.  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ              "r"
/** Generic OS User - Open  text  file  for  reading (binary).  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ_BIN          "rb"

/** Generic OS User - Truncate  file  to  zero length or create text file for writing.
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE             "w"
/** Generic OS User - Truncate  file  to  zero length or create text file for writing (binary).
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE_BIN         "wb"

/** Generic OS User - Open for appending (writing at end of file).  
         The file  is  created  if it does not exist.  The stream is positioned 
         at the end of the file. */
#define IFXOS_OPEN_MODE_APPEND            "a"
/** Generic OS User - Open for reading and appending (writing at end  of  file).   
         The file is created if it does not exist.  The initial file position 
         for reading is at the beginning  of  the  file,  but  output  is always 
         appended to the end of the file */
#define IFXOS_OPEN_MODE_READ_APPEND       "a+"


/** Generic OS User - file access, type struct stat */
typedef struct IFXOS_stat_s
{
   IFX_int_t   dummy_stat;
   IFX_int_t   st_size;
} IFXOS_stat_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_FILE_ACCESS_H */

