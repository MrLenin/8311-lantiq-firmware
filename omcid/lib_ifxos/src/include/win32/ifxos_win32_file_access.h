#ifndef _IFXOS_WIN32_FILE_ACCESS_H
#define _IFXOS_WIN32_FILE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains VxWorks definitions for File Access.
*/

/** \defgroup IFXOS_FILE_ACCESS_WIN32_APPL File Access (Win32)

   This Group contains the Win32 File Access definitions and function. 

   To access a file the standard C-lib functions for file handling are wrapped.

   Further a file type is provided which is used for further access destinations
   (streams) like files, pipes, stdin, stdout.

\ingroup IFXOS_LAYER_WIN32
*/

/** \defgroup IFXOS_MEM_FILE_WIN32 Memory File (Win32)

   This Group contains the Win32 Memory File definitions and function. 

   The memory file feature provides the possibility to map a memory to a file.
   This allows to use the standard file operation on the memory block.

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#include <stdio.h>
#include <sys/stat.h>

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - User support "file access" */
#ifndef IFXOS_HAVE_FILE_ACCESS
#  define IFXOS_HAVE_FILE_ACCESS                   1
#endif

/** IFX Win32 adaptation - User support "file system" */
#ifndef IFXOS_HAVE_FILESYSTEM
#  define IFXOS_HAVE_FILESYSTEM                    1
#endif

/** IFX Win32 adaptation - User support "memory file" */
#ifndef IFXOS_HAVE_MEMORY_FILE
#  define IFXOS_HAVE_MEMORY_FILE                   1
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */

/** \addtogroup IFXOS_FILE_ACCESS_WIN32_APPL
@{ */

/** IFX Win32 adaptation - User support "static memory file" 
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

/** Win32 User - map to stderr */
#define IFXOS_STDERR          stderr
/** Win32 User - map to stdout */
#define IFXOS_STDOUT          stdout
/** Win32 User - map to stdin */
#define IFXOS_STDIN           stdin

/** Win32 User - Open  text  file  for  reading.  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ              "r"
/** Win32 User - Open  text  file  for  reading (binary).  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ_BIN          "rb"

/** Win32 User - Truncate  file  to  zero length or create text file for writing.
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE             "w"
/** Win32 User - Truncate  file  to  zero length or create text file for writing (binary).
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE_BIN         "wb"

/** Win32 User - Open for appending (writing at end of file).  
         The file  is  created  if it does not exist.  The stream is positioned 
         at the end of the file. */
#define IFXOS_OPEN_MODE_APPEND            "a"
/** Win32 User - Open for reading and appending (writing at end  of  file).   
         The file is created if it does not exist.  The initial file position 
         for reading is at the beginning  of  the  file,  but  output  is always 
         appended to the end of the file */
#define IFXOS_OPEN_MODE_READ_APPEND       "a+"

/** Win32 User - file access, type FILE for stream handling */
typedef FILE                  IFXOS_File_t;

/** Win32 User - file access, type struct stat */
typedef struct stat           IFXOS_stat_t;

#if ( defined(IFXOS_ADD_STATIC_MEMORY_FILE) && (IFXOS_ADD_STATIC_MEMORY_FILE == 1) )

/**
   Control struct to handle private memory files
*/
typedef struct
{
   /* points to the user given memfile buffer */
   IFX_char_t  *pBuffer;
   /* contains the buffer size */
   IFX_uint_t  bufSize;
   /* contains the current write position */
   IFX_uint_t  currPos;
} IFXOS_staticMemoryFile_t;

/* export control struct */
extern IFXOS_staticMemoryFile_t IFXOS_privatMemoryFiles[];

#endif


/** @} */
#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_XXX_WIN32_H */

