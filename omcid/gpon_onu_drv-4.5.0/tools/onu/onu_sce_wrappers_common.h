/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef __sce_wrappers_common_h
#define __sce_wrappers_common_h

#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#ifdef HAVE_CONFIG_H
#  include "drv_onu_config.h"
#endif

#include "drv_onu_std_defs.h"
#include "drv_onu_interface.h"
#include "drv_onu_resource.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_gpe_tables.h"
#include "drv_onu_gpe_tables_interface.h"

#include"onu_sce_wrappers_misc.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array)/sizeof((array)[0]))
#endif

#ifndef offsetof
#define offsetof(STRUCT, MEMBER) \
   /*lint -save -e(413) -e(507) -e(831) */ \
   ((size_t) &((STRUCT *) 0)->MEMBER ) \
				/*lint -restore */
#endif

#define TABLE_ENTRY_SIZE(ENTRY) \
	(offsetof(struct gpe_table_entry, data) + sizeof(ENTRY))

int onu_iocmd(const int fd, const unsigned int cmd, void *data, const unsigned int size);
int table_read(int onu_fd, uint32_t id, size_t size, uint32_t instance, uint32_t index, struct gpe_table_entry *entry);

void wrapper_begin(enum output_type type, FILE *f, const char *name);
void wrapper_end(enum output_type type, FILE *f);
void wrapper_entry_begin(enum output_type type, FILE *f, uint32_t index);
void wrapper_entry_end(enum output_type type, FILE *f);
void wrapper_field(enum output_type type, FILE *f, bool first, const char *name, const char *value_type, uint32_t value);

#endif
