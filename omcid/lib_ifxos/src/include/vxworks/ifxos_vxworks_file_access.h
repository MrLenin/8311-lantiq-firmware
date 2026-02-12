#ifndef _IFXOS_VXWORKS_FILE_ACCESS_H
#define _IFXOS_VXWORKS_FILE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains VxWorks definitions for File Access.
*/

/** \defgroup IFXOS_FILE_ACCESS_VXWORKS_APPL File Access (VxWorks)

   This Group contains the VxWorks File Access definitions and function. 

   To access a file the standard C-lib functions for file handling are wrapped.

   Further a file type is provided which is used for further access destinations
   (streams) like files, pipes, stdin, stdout.

\ingroup IFXOS_LAYER_VXWORKS
*/

/** \defgroup IFXOS_MEM_FILE_VXWORKS Memory File (VxWorks)

   This Group contains the VxWorks Memory File definitions and function. 

   The memory file feature provides the possibility to map a memory to a file.
   This allows to use the standard file operation on the memory block.

\ingroup IFXOS_LAYER_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include <vxWorks.h>
#include <stdio.h>
#include <sys/stat.h> /* stat */
#include <unistd.h>

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - User support "file access" */
#ifndef IFXOS_HAVE_FILE_ACCESS
#  define IFXOS_HAVE_FILE_ACCESS                   1
#endif

/** IFX VxWorks adaptation - User support "file system" */
#ifndef IFXOS_HAVE_FILESYSTEM
#  define IFXOS_HAVE_FILESYSTEM                    1
#endif

/** IFX VxWorks adaptation - User support "memory file" */
#ifndef IFXOS_HAVE_MEMORY_FILE
#  define IFXOS_HAVE_MEMORY_FILE                   1
#endif

/* ============================================================================
   IFX VxWorks adaptation - defines, types
   ========================================================================= */

/** IFX VxWorks adaptation - Rebuild the missing "fmemopen" */
#ifndef IFXOS_ADD_LOCAL_FMEMOPEN
#  define IFXOS_ADD_LOCAL_FMEMOPEN                 1
#endif

/** IFX VxWorks adaptation - User support "static memory file" 
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

/** VxWorks User - map to stderr */
#define IFXOS_STDERR          stderr
/** VxWorks User - map to stdout */
#define IFXOS_STDOUT          stdout
/** VxWorks User - map to stdin */
#define IFXOS_STDIN           stdin

/** VxWorks User - Open  text  file  for  reading.  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ              "r"
/** VxWorks User - Open  text  file  for  reading (binary).  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ_BIN          "rb"

/** VxWorks User - Truncate  file  to  zero length or create text file for writing.
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE             "w"
/** VxWorks User - Truncate  file  to  zero length or create text file for writing (binary).
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE_BIN         "wb"

/** VxWorks User - Open for appending (writing at end of file).  
         The file  is  created  if it does not exist.  The stream is positioned 
         at the end of the file. */
#define IFXOS_OPEN_MODE_APPEND            "a"
/** VxWorks User - Open for reading and appending (writing at end  of  file).   
         The file is created if it does not exist.  The initial file position 
         for reading is at the beginning  of  the  file,  but  output  is always 
         appended to the end of the file */
#define IFXOS_OPEN_MODE_READ_APPEND       "a+"

/** VxWorks User - file access, type FILE for stream handling */
typedef FILE                  IFXOS_File_t;

/** VxWorks User - file access, type struct stat */
typedef struct stat           IFXOS_stat_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_FILE_ACCESS_H */

