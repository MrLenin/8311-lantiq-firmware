#ifndef _IFXOS_ECOS_FILE_ACCESS_H
#define _IFXOS_ECOS_FILE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for File Access.
*/

/** \defgroup IFXOS_FILE_ACCESS_ECOS_APPL File Access (eCos)

   This Group contains the eCos File Access definitions and function. 

   To access a file the standard C-lib functions for file handling are wrapped.

   Further a file type is provided which is used for further access destinations
   (streams) like files, pipes, stdin, stdout.

\ingroup IFXOS_LAYER_ECOS
*/

/** \defgroup IFXOS_MEM_FILE_ECOS Memory File (eCos)

   This Group contains the eCos Memory File definitions and function. 

   The memory file feature provides the possibility to map a memory to a file.
   This allows to use the standard file operation on the memory block.

\ingroup IFXOS_LAYER_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */

#include <pkgconf/system.h>
#include <stdio.h>               /* FILE */
#if defined(CYGONCE_LIBC_STDIO_STDIO_H)
#  include <sys/stat.h>          /* stat */
#endif

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

#ifndef IFXOS_HAVE_FILE_TYPE
#  if defined(CYGONCE_LIBC_STDIO_STDIO_H)
#    define IFXOS_HAVE_FILE_TYPE                   1
#  else
#    define IFXOS_HAVE_FILE_TYPE                   0
#  endif
#endif

/** IFX eCos adaptation - User support "file access" */
#ifndef IFXOS_HAVE_FILE_ACCESS
#  if IFXOS_HAVE_FILE_TYPE == 1
#    define IFXOS_HAVE_FILE_ACCESS                   1
#  else
#    define IFXOS_HAVE_FILE_ACCESS                   0
#  endif
#endif

/** IFX eCos adaptation - User support "file system" */
#ifndef IFXOS_HAVE_FILESYSTEM
#  if defined(CYGPKG_IO_FILEIO)
#    define IFXOS_HAVE_FILESYSTEM                    1
#  else
#    define IFXOS_HAVE_FILESYSTEM                    0
#  endif
#endif

/** IFX eCos adaptation - User support "memory file" */
#ifndef IFXOS_HAVE_MEMORY_FILE
#  if IFXOS_HAVE_FILE_TYPE == 1
#     define IFXOS_HAVE_MEMORY_FILE                      1
#  else
#     define IFXOS_HAVE_MEMORY_FILE                      0
#  endif
#endif


/* ============================================================================
   IFX eCos adaptation - defines, types
   ========================================================================= */

/** IFX eCos adaptation - Rebuild the missing "fmemopen" */
#ifndef IFXOS_ADD_LOCAL_FMEMOPEN
#  define IFXOS_ADD_LOCAL_FMEMOPEN                 0
#endif

/** IFX eCos adaptation - User support "static memory file" 
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

#if ( defined(IFXOS_HAVE_FILE_ACCESS) && (IFXOS_HAVE_FILE_ACCESS == 1) )


/** eCos User - Open  text  file  for  reading.  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ              "r"
/** eCos User - Open  text  file  for  reading (binary).  
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ_BIN          "rb"

/** eCos User - Truncate  file  to  zero length or create text file for writing.
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE             "w"
/** eCos User - Truncate  file  to  zero length or create text file for writing (binary).
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE_BIN         "wb"

/** eCos User - Open for appending (writing at end of file).  
         The file  is  created  if it does not exist.  The stream is positioned 
         at the end of the file. */
#define IFXOS_OPEN_MODE_APPEND            "a"
/** eCos User - Open for reading and appending (writing at end  of  file).   
         The file is created if it does not exist.  The initial file position 
         for reading is at the beginning  of  the  file,  but  output  is always 
         appended to the end of the file */
#define IFXOS_OPEN_MODE_READ_APPEND       "a+"

#endif

#if ( defined(IFXOS_HAVE_FILE_TYPE) && (IFXOS_HAVE_FILE_TYPE == 1) )

/** eCos User - map to stderr */
#define IFXOS_STDERR          stderr
/** eCos User - map to stdout */
#define IFXOS_STDOUT          stdout
/** eCos User - map to stdin */
#define IFXOS_STDIN           stdin

/** eCos User - file access, type FILE for stream handling */
typedef FILE                  IFXOS_File_t;

/** eCos User - file access, type struct stat */
typedef struct stat           IFXOS_stat_t;

#endif

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

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_FILE_ACCESS_H */

