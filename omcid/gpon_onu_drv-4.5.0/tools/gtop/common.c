/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "gtop.h"
#include "common.h"
#include <stdio.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include "drv_onu_resource.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_gpe_tables_interface.h"

int table_read(int fd,
		const uint32_t id,
		const uint16_t idx,
		const uint32_t size,
		struct gpe_table_entry *entry)
{
	int ret;
	memset(entry, 0x00, size);
	entry->id = id;
	if(GPE_IS_PE_TABLE(id))
		entry->instance = 0x1;
	else
		entry->instance = 0;
	entry->index = idx;
	ret = onu_iocmd(fd, FIO_GPE_TABLE_ENTRY_GET, entry,
		    offsetof(struct gpe_table_entry, data) + size);
	return ret;
}
