/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "dump.h"
#include "gtop.h"
#include <stdio.h>
#include <string.h>

#ifdef INCLUDE_REMOTE_ONU
int remote_file_read(const int fd, const char *name, void *p_data, const unsigned int line_max,  const unsigned int line_len);
#endif

#ifdef INCLUDE_PROCFS_SUPPORT
int dump_get(const int fd, const char *name)
{
	char tmp[256];

#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0]) {
		return remote_file_read(fd, name, g_shared_buff, LINE_MAX, LINE_LEN);
	} else
#endif	
	{
		snprintf(tmp, sizeof(tmp), "/proc/driver/onu/%s", name);
		return file_read(tmp);
	}
}
#endif

char *dump_entry_get(const int entry, char *text)
{
	if (entry != -1)
		return file_line_get(entry);
	return NULL;
}
