/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __gtc_counter_h
#define __gtc_counter_h

/** Initialize/shutdown GTC group

   \param[in] init true - initialize group, otherwise shutdown
*/
void gtc_group_init(bool init);

/** Get status table

   \return Number of entries in the table
*/
int status_table_get(const int fd, const char *);

/** Get status table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *status_table_entry_get(const int entry, char *text);

/** Get configuration table

   \return Number of entries in the table
*/
int cfg_table_get(const int fd, const char *);

/** Get configuration table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *cfg_table_entry_get(const int entry, char *text);

/** Get GTC alarms

   \return Number of entries in the table
*/
int gtc_alarms_table_get(const int fd, const char *);

/** Get GTC alarms entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *gtc_alarms_table_entry_get(const int entry, char *text);

/** Get BWM trace

   \return Number of entries in the table
*/
int gtc_bwmtrace_table_get(const int fd, const char *dummy);

/** Get BWM trace entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *gtc_bwmtrace_table_entry_get(const int entry, char *text);

/** Get GTC counters

   \return Number of entries in the table
*/
int gtc_counters_table_get(const int fd, const char *);

/** Get GTC counters entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *gtc_counters_table_entry_get(const int entry, char *text);

#endif
