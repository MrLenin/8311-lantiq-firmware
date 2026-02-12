#ifndef _IFXOS_RTEMS_FILE_ACCESS_H
#define _IFXOS_RTEMS_FILE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains RTEMS definitions for File Access.
*/

/** \defgroup IFXOS_FILE_ACCESS_RTEMS_APPL File Access (RTEMS)

   This Group contains the RTEMS File Access definitions and function.

   To access a file the standard C-lib functions for file handling are wrapped.

   Further a file type is provided which is used for further access destinations
   (streams) like files, pipes, stdin, stdout.

\ingroup IFXOS_LAYER_RTEMS
*/

/** \defgroup IFXOS_MEM_FILE_RTEMS Memory File (RTEMS)

   This Group contains the RTEMS Memory File definitions and function.

   The memory file feature provides the possibility to map a memory to a file.
   This allows to use the standard file operation on the memory block.

\ingroup IFXOS_LAYER_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - User support "file access" */
#define IFXOS_HAVE_FILE_ACCESS                  1
/** RTEMS adaptation - User support "file system" */
#define IFXOS_HAVE_FILESYSTEM                   1
/** RTEMS adaptation - User support "memory file" */
#define IFXOS_HAVE_MEMORY_FILE                  1

/* ============================================================================
   RTEMS adaptation - defines, types
   ========================================================================= */

/** RTEMS adaptation - Rebuild the missing "fmemopen" */
#define IFXOS_ADD_LOCAL_FMEMOPEN                1


/** RTEMS User - map to stderr */
#define IFXOS_STDERR          0
/** RTEMS User - map to stdout */
#define IFXOS_STDOUT          1
/** RTEMS User - map to stdin */
#define IFXOS_STDIN           2

/** RTEMS User - Open  text  file  for  reading.
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ              "r"
/** RTEMS User - Open  text  file  for  reading (binary).
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_READ_BIN          "rb"

/** RTEMS User - Truncate  file  to  zero length or create text file for writing.
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE             "w"
/** RTEMS User - Truncate  file  to  zero length or create text file for writing (binary).
         The stream is positioned at the beginning of the file. */
#define IFXOS_OPEN_MODE_WRITE_BIN         "wb"

/** RTEMS User - Open for appending (writing at end of file).
         The file  is  created  if it does not exist.  The stream is positioned
         at the end of the file. */
#define IFXOS_OPEN_MODE_APPEND            "a"
/** RTEMS User - Open for reading and appending (writing at end  of  file).
         The file is created if it does not exist.  The initial file position
         for reading is at the beginning  of  the  file,  but  output  is always
         appended to the end of the file */
#define IFXOS_OPEN_MODE_READ_APPEND       "a+"

/** RTEMS User - file access, type FILE for stream handling */
typedef IFX_int_t    IFXOS_File_t;

/** RTEMS User - file access, type struct stat */
typedef struct IFXOS_stat_s
{
   IFX_int_t   dummy_stat;
   IFX_int_t   st_size;
} IFXOS_stat_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_FILE_ACCESS_H */

