/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __gpe_counter_h
#define __gpe_counter_h

/** Initialize/shutdown GPE group

   \param[in] init true - initialize group, otherwise shutdown
*/
void gpe_group_init(bool init);

/** Get GPE counters table

   \return Number of entries in the table
*/
int gpe_table_get(const int fd, const char*);

/** Get GPE capability table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *gpe_capability_entry_get(const int entry, char *text);

/** Get GPE capability table

   \return Number of entries in the table
*/
int gpe_capability_table_get(const int fd, const char *dummy);

/** Get GPE counters table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *gpe_table_entry_get(int entry, char *text);

/** Get GEM port counter table

   \return Number of entries in the table
*/
int gpem_port_table_get(const int fd, const char *);

/** Get alloc id table

   \return Number of entries in the table
*/
int alloc_id_table_get(const int fd, const char *);

/** Get GEM port counters table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *gem_port_entry_get(const int entry, char *text);

/** Get Alloc ID table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *alloc_id_entry_get(const int entry, char *text);

/** Read upstream flow table

   \return Number of entries in the table
*/
int us_flow_table_get(const int fd, const char *dummy);

/** Get upstream flow table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *us_flow_entry_get(const int entry, char *text);

/** Read bridge port counter table

   \return Number of entries in the table
*/
int bridge_port_counter_table_get(const int fd, const char *dummy);

/** Get bridge port counter table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *bridge_port_counter_entry_get(const int entry, char *text);

/** Read Token Bucket Meter

   \return Number of entries in the table
*/
int meter_table_get(const int fd, const char *dummy);

/** Get bridge port counter table entry

   \param[in]  entry Table entry number; -1 for header
   \param[out] text  Table entry text
*/
char *meter_entry_get(const int entry, char *text);

#endif
