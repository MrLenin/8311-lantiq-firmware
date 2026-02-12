/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __dump_h
#define __dump_h

/** Get version/status dump

   \return Number of entries (lines) in the dump
*/
int table_get_version ( void );

/** Get version/status dump entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_version ( int entry, char *text );


/** Get configuration table

   \return Number of entries in the table
*/
int table_get_config ( void );

/** Get configuration table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_config ( int entry, char *text );

/** Get range table

   \return Number of entries in the table
*/
int table_get_ranges ( void );

/** Get range table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_ranges ( int entry, char *text );


/** Get temperature table

   \return Number of entries in the table
*/
int table_get_temperature ( void );

/** Get temperature table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_temperature ( int entry, char *text );

/** Get temperature translation table

   \return Number of entries in the table
*/
int table_get_temptrans ( void );

/** Get temperature translation table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_temptrans ( int entry, char *text );

/** Get gain table

   \return Number of entries in the table
*/
int table_get_gain ( void );

/** Get gain table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_gain ( int entry, char *text );

/** Get monitor table

   \return Number of entries in the table
*/
int table_get_monitor ( void );

/** Get monitor table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_monitor ( int entry, char *text );

/** Get fusing registers

   \return Number of entries in the table
*/
int table_get_fuses ( void );

/** Get fusing register entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_fuses ( int entry, char *text );

/** Get status table

   \return Number of entries in the table
*/
int table_get_status ( void );

/** Get status table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_status ( int entry, char *text );

/** Get alarm table

   \return Number of entries in the table
*/
int table_get_alarm ( void );

/** Get status table entry

   \param[in]  nEntry Table entry number; -1 for header
   \param[out] pText  Table entry text
*/
void table_entry_get_alarm ( int entry, char *text );

#endif
