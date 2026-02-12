#ifndef _IFXOS_SUN_OS_FILE_ACCESS_H
#define _IFXOS_SUN_OS_FILE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(SUN_OS)

/** \file
   This file contains Sun OS definitions for File Access.
*/

/** \defgroup IFXOS_FILE_ACCESS_SUN_OS_APPL File Access (Sun OS User Space)

   This Group contains the Sun OS File Access definitions and function. 

   To access a file the standard C-lib functions for file handling are wrapped.

   Further a file type is provided which is used for further access destinations
   (stream) like files, pipes, stdin, stdout.

\ingroup IFXOS_LAYER_SUN_OS
*/

/** \defgroup IFXOS_MEM_FILE_SUN_OS_APPL Memory File (Sun OS User Space)

   This Group contains the Sun OS Memory File definitions and function. 

   The memory file feature provides the possibility to map a memory to a file.
   This allows to use the standard file operation on the memory block.

\ingroup IFXOS_LAYER_SUN_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Sun OS adaptation - Includes
   ========================================================================= */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ============================================================================
   IFX Sun OS adaptation - supported features
   ========================================================================= */

/** IFX Sun OS adaptation - User support "file access" */
#ifndef IFXOS_HAVE_FILE_ACCESS
#  define IFXOS_HAVE_FILE_ACCESS                  1
#endif

/** IFX Sun OS adaptation - User support "file system" */
#ifndef IFXOS_HAVE_FILESYSTEM
#  define IFXOS_HAVE_FILESYSTEM                   1
#endif

/** IFX Sun OS adaptation - User support "memory file" */
#ifndef IFXOS_HAVE_MEMORY_FILE
#  define IFXOS_HAVE_MEMORY_FILE                  0
#endif

/* ============================================================================
   IFX Sun OS adaptation - define, types
   ========================================================================= */

/** Sun OS User - map to stderr */
#define IFXOS_STDERR                      stderr
/** Sun OS User - map to stdout */
#define IFXOS_STDOUT                      stdout
/** Sun OS User - map to stdin */
#define IFXOS_STDIN                       stdin

/** Sun OS User - Open  text  file  for  reading.  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ              "r"
/** Sun OS User - Open  text  file  for  reading (binary).  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ_BIN          "rb"

/** Sun OS User - Truncate  file  to  zero length or create text file for writing.
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE             "w"
/** Sun OS User - Truncate  file  to  zero length or create text file for writing (binary).
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE_BIN         "wb"

/** Sun OS User - Open for appending (writing at end of file).  
         The file  is  created  if it does not exist.  The stream is positioned 
         at the end of the file. */
#define IFXOS_OPEN_MODE_APPEND            "a"
/** Sun OS User - Open for reading and appending (writing at end  of  file).   
         The file is created if it does not exist.  The initial file position 
         for reading is at the beginning  of  the  file,  but  output  is always 
         appended to the end of the file */
#define IFXOS_OPEN_MODE_READ_APPEND       "a+"


/** Sun OS User - file access, type FILE for stream handling */
typedef FILE            IFXOS_File_t;

/** Sun OS User - file access, type struct stat */
typedef struct stat     IFXOS_stat_t;

#ifdef __cplusplus
}
#endif
#endif      /* #if defined(SUN_OS) */
#endif      /* #ifndef _IFXOS_SUN_OS_FILE_ACCESS_H */


