/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __dump_h
#define __dump_h

/** Get dump

   \return Number of entries (lines) in the dump
*/
int dump_get(const int fd, const char *input_file_name);

/** Get dump entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *dump_entry_get(const int entry, char *text);

#endif
