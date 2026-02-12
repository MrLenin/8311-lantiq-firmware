/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __optic_top_h
#define __optic_top_h

#include "include/drv_optic_interface.h"

#define OPTIC_TOP_VERSION	"3.0.18"

/** version string */
#define OPTIC_TOP_WHAT_STR "@(#)GPON Optic top, version "OPTIC_TOP_VERSION" " \
		      OPTIC_COPYRIGHT

/** Device descriptor */
extern int fd_dev;

/** Get counters table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
typedef void (tableentry_get) ( int entry, char *text );

/** Get complete counters table from device to application's memory

   \return Number of entries in the table
*/
typedef int ( table_get) ( void );

/** Read file contents into shared buffer

   \param[in] nFiles Number of files
   \param[in] ...    File names

   \return Number of lines in file
*/
int file_read ( int files, ...);

/** Get line from shared buffer

   \param[in] nLine Line number

   \return Pointer to string data
*/
char *file_line_get ( int line );

#endif
