/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __gtop_h
#define __gtop_h

#include "drv_onu_interface.h"
#include "drv_onu_gpe_interface.h"

#ifdef HAVE_CONFIG_H
#include "drv_onu_config.h"
#endif

#define GTOP_VERSION		"1.0.7"
/** version string */
#define GTOP_WHAT_STR "@(#)GPON ONU top, version " GTOP_VERSION " " \
			 ONU_COPYRIGHT

/** Driver capabilities */
extern struct gpe_capability g_capability;

/** Device descriptor */
extern int g_dev_fd;

/** Get counters table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text

   \return - NULL - means that data in text
           - non-NULL - print returned pointer
*/
typedef char *(table_entry_get_t) (const int entry, char *text);

/** Get complete counters table from device to application's memory

   \param[in] name of the file to be used

   \return Number of entries in the table
*/
typedef int (table_get_t) (const int fd, const char *input_file_name);

/** Enter counters page */
typedef void (table_enter_t) (void);

/** Leave counters page */
typedef void (table_leave_t) (void);

/** Read file contents into shared buffer

   \param[in] files Number of files
   \param[in] ...    File names

   \return Number of lines in file
*/
int file_read(const char *name);

/** Get line from shared buffer

   \param[in] line Line number

   \return Pointer to string data
*/
char *file_line_get(int line);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array)/sizeof((array)[0]))
#endif

#ifndef offsetof
#define offsetof(STRUCT, MEMBER) \
   /*lint -save -e(413) -e(507) -e(831) */ \
   ((size_t) &((STRUCT *) 0)->MEMBER ) \
				/*lint -restore */
#endif

#define MAX_PATH 256

extern char g_remote[MAX_PATH];

/** Maximum line length for table/dump data */
#define LINE_LEN 1000

/** Maximum amount of lines for table/dump data */
#define LINE_MAX 25000

extern char g_shared_buff[LINE_MAX][LINE_LEN];

#endif
