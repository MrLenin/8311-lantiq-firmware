/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __sce_counter_h
#define __sce_counter_h

/** Get FW perfmeter counters table

   \return Number of entries in the table
*/
int fw_perfmeter_table_get(const int fd, const char *dummy);

/** Get FW perfmeter table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *fw_perfmeter_entry_get(int entry, char *text);

/** Enter FW perfmeter page */
void fw_perfmeter_on_enter(void);

/** Leave FW perfmeter page */
void fw_perfmeter_on_leave(void);

/** Get FW status table

   \return Number of entries in the table
*/
int fw_status_table_get(const int fd, const char *dummy);

/** Get FW status table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *fw_status_entry_get(int entry, char *text);

/** Get FW status table

   \return Number of entries in the table
*/
int fw_detailed_status_table_get(const int fd, const char *dummy);

/** Get FW status table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *fw_detailed_status_entry_get(int entry, char *text);

#endif
