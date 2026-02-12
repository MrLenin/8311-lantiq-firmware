/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "onu_control.h"
#include "onu_control_config.h"

#ifdef INCLUDE_REMOTE_ONU
#include "dti_rpc.h"

extern char g_remote[MAX_PATH];
#endif

static int onu_iocmd_local(const int fd, const unsigned int cmd, void *data, const unsigned int size)
{
	struct fio_exchange ex;
	int err;

	ex.p_data = data;
	ex.length = size;
	ex.error = 0;

	if((err = ioctl(fd, cmd, (long)&ex)) == 0) {
		if (ex.error == 0)
			return 0;
		else {
			if (cmd == FIO_ONU_EVENT_FIFO && ex.error == 1) {
				fprintf(stderr, "WARN: fifo overflow\n");
				return 0;
			}

			return ex.error;
		}
	}
	else
		fprintf(stderr, "ERROR: ioctl.err = %i, ex.error = %i\n", err, ex.error);

	return -1;
}

int onu_open(const char *name)
{
#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0])
	{
		return remote_device_open(name);
	} else
#endif
	{
		return open(name, O_RDWR, 0644);
	}
}

int onu_close(const int fd)
{
#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0])
	{
		return remote_device_close(fd);
	} else
#endif
	{
		return close(fd);
	}
}

int onu_iocmd(const int fd, const unsigned int cmd, void *data, const unsigned int size)
{
#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0])
	{
		return remote_dev_ctl(fd, cmd, data, size);
	} else
#endif
	{
		return onu_iocmd_local(fd, cmd, data, size);
	}
}

