/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifdef HAVE_CONFIG_H
#include "drv_optic_config.h"
#endif
#ifdef LINUX
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <linux/types.h>
#include <unistd.h>
#include <arpa/inet.h> 
#endif /* LINUX */

#include "drv_optic_std_defs.h"
#include "optic_control.h"
#include "drv_optic_interface.h"

#ifdef INCLUDE_REMOTE_ONU
#include "dti_client_lib.h"

#ifndef MAX_PATH
#define MAX_PATH 256
#endif
extern char g_remote[MAX_PATH];

#define MAX_CONNECTIONS 2
static struct dti_ctx dti_ctx[MAX_CONNECTIONS];

int remote_notification_read(const int fd, void *p_data, const unsigned int max_sz);

int remote_init(const char *remote_ip)
{
	int ret, i;
	unsigned int udp_port = 9000;
	char buf[DTI_IP_ADDR_SIZE];

	ret = sscanf(remote_ip, "%[^:]:%u", buf, &udp_port);
	if (ret < 1) {
		return -1;
	}
	printf("remote connection %s %d\n", buf, udp_port);
	for (i = 0; i < MAX_CONNECTIONS; i++) {
		memset(&dti_ctx[i], 0x00, sizeof(struct dti_ctx));
		dti_ctx[i].channel = 1;
		dti_ctx[i].udp_port = udp_port + i;
		strcpy(dti_ctx[i].ip_addr, buf);
		dti_ctx[i].tan = 1;
		dti_ctx[i].client = -1;
	}

	return 0;
}

int remote_shutdown(void)
{
	return 0;
}

int remote_device_open(const char *dev_name_str)
{
	int ret, i;
	(void) dev_name_str;

	for (i = 0; i < MAX_CONNECTIONS; i++) {
		if(dti_ctx[i].client == -1)
			break;
	}

	if(i == MAX_CONNECTIONS)
		return -1;
	ret = dti_client_session_start(&dti_ctx[i]);
	if (ret < 0) {
		dti_client_session_stop(&dti_ctx[i]);
		return -1;
	}

	return i;
}

int remote_device_close(const int fd)
{
	if(fd < MAX_CONNECTIONS)
		dti_client_session_stop(&dti_ctx[fd]);

	return 0;
}

int remote_device_event_wait(const int fd, void *data, const unsigned int max_size)
{
	int ret;
	fd_set rfds;
	struct timeval tv;

	if(fd >= MAX_CONNECTIONS || fd < 0)
		return -1;
	if (dti_ctx[fd].client == -1)
		return -2;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(dti_ctx[fd].client, &rfds);
	ret = select(dti_ctx[fd].client + 1, &rfds, NULL, NULL, &tv);
	if (ret == -1) {
		fprintf(stderr, "[opticd] ERROR: select error.\n");
		return -1;
	}
	if (ret == 0)
		/* no data within timeout */
		return 1;
	if (FD_ISSET(dti_ctx[fd].client, &rfds) == 0) {
		/* not for us */
		printf("*");
		return 1;
	}
	ret = remote_notification_read(fd, data, max_size);
	if (ret != 0) {
		fprintf(stderr,
			"[opticd] ERROR: can't read from device.\n");
		return -1;
	}
	return 0;
}

int remote_dev_ctl(const int fd,
		  const unsigned int cmd, void *p_data, unsigned int size)
{
	int ret = 0;
	uint8_t tx_buf[8];
	unsigned int rx_len = 0;

	if(fd >= MAX_CONNECTIONS || fd < 0)
		return -1;

	if (dti_ctx[fd].client == -1)
		return -1;

	/* fill ioctl cmd and expected data size */
	*((uint32_t *)&tx_buf[0]) = htonl(cmd);
	*((uint32_t *)&tx_buf[4]) = htonl(size);

	ret = dti_packet(&dti_ctx[fd], DTI_PACKET_TYPE_MESSAGE, DTI_8BIT,
			 &tx_buf[0], 8,
			 p_data, size,
			 &dti_ctx[fd].rx[0], DTI_TMP_BUF_SIZE, &rx_len);
	if (ret < 0) {
		return ret;
	}
	if (rx_len < 4) {
		return -2;
	}
	rx_len -= 4;
	/* copy result data */
	if (rx_len > size)
		rx_len = size;
	memcpy(p_data, &dti_ctx[fd].rx[4], rx_len);

	return 0;
}

int remote_notification_read(const int fd, void *p_data,
			    const unsigned int max_sz)
{
	int ret = 0;
	unsigned int rx_len = 0;
	unsigned int tan=0, type=0, opt=0;

	if(fd >= MAX_CONNECTIONS || fd < 0)
		return -1;

	if (dti_ctx[fd].client == -1)
		return -1;

	ret =
	    dti_packet_receive(&dti_ctx[fd], &type, &opt, &tan, p_data,
			       max_sz, &rx_len, NULL);
	if (ret < 0)
		return ret;

	if (type != DTI_PACKET_TYPE_MESSAGE)
		return -1;

	return 0;
}

#define MAX_RX_BUFFER 4096
char file_buf[MAX_RX_BUFFER];

int remote_file_read(const int fd, const char *name, void *p_data, const unsigned int line_max,  const unsigned int line_len)
{
	char *line = p_data;
	char *ptr;
	unsigned int i=0;

	if(fd >= MAX_CONNECTIONS || fd < 0)
		return -1;

	if (dti_ctx[fd].client == -1)
		return -1;

	printf("read file: %s\n", name);
	if(dti_client_cli_execute(&dti_ctx[fd], name, &file_buf[0], MAX_RX_BUFFER) >= 0) {
		ptr = strtok(&file_buf[0], "\n");
		for(i=0;ptr && i<line_max;i++, line+=line_len) {
			strncpy(line, ptr, line_len - 2);
			line[line_len - 1] = 0;
			ptr = strtok(NULL, "\n");
		}
	}

	return i;
}

#endif /* INCLUDE_REMOTE_ONU */

static int optic_iocmd_local(const int fd, const unsigned int cmd, void *data, const unsigned int size)
{
#ifndef WIN32
	struct optic_exchange ex;
	int err;

	ex.p_data = data;
	ex.length = size;
	ex.error = 0;

	if((err = ioctl(fd, cmd, (long)&ex)) == 0) {
		if (ex.error == 0)
			return 0;
		else {
			/*
			if (cmd == FIO_ONU_EVENT_FIFO && ex.error == 1) {
				fprintf(stderr, "WARN: fifo overflow\n");
				return 0;
			}*/
			fprintf(stderr, "ERROR: ex.error = %i\n", ex.error);
		}
	}
	else
		fprintf(stderr, "ERROR: ioctl.err = %i, ex.error = %i\n", err, ex.error);
#endif
	return -1;
}

int optic_open(const char *name)
{
#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0])
	{
		return remote_device_open(name);
	} else
#endif
	{
#ifdef WIN32
		return -1;
#else
		return open(name, O_RDWR, 0644);
#endif
	}
}

int optic_close(const int fd)
{
#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0])
	{
		return remote_device_close(fd);
	} else
#endif
	{
#ifdef WIN32
		return 0;
#else
		return close(fd);
#endif
	}
}

int optic_iocmd(const int fd, const unsigned int cmd, void *data, const unsigned int size)
{
#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0])
	{
		return remote_dev_ctl(fd, cmd, data, size);
	} else
#endif
	{
		return optic_iocmd_local(fd, cmd, data, size);
	}
}

