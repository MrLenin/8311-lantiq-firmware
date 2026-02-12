/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __common_h
#define __common_h

#include "onu_control.h"

/** Read a generic table entry

   \return 0 in case of success
*/
int table_read(int fd,
		const uint32_t id,
		const uint16_t idx,
		const uint32_t size,
		struct gpe_table_entry *entry);

#endif
