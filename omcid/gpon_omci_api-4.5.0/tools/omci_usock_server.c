/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <stdbool.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "omci_api_usock.h"
#include "omci_usock_server.h"

const char omci_usock_what_version[] = OMCI_USOCK_WHAT_STR;

unsigned int g_run = 1;

/** Termination handler

   \param[in] sig Signal
*/
static void on_term(int sig)
{
	/* ignore the signal, we'll handle by ourself */
	signal (sig, SIG_IGN);
	g_run = 0;
}

static int usock_client_process(int s)
{
	int ret;
	struct usock_msg msg;

	ret = recv(s, &msg.hdr, sizeof(msg.hdr), 0);
	if (ret < (int)sizeof(msg.hdr))
		return -1;

	if (msg.hdr.len > sizeof(msg.data)) {
		printf(OMCI_USOCK_PRN_PREFIX
			"msg length is too big, msg_id=0x%X, msg_len=%u\n",
			msg.hdr.msg_id, msg.hdr.len);
		return -1;
	}

	ret = recv(s, msg.data, msg.hdr.len, 0);
	if (ret != (int)msg.hdr.len)
		return -1;

	switch (msg.hdr.msg_id) {
	case OMCI_API_USOCK_MSG_ID_SYSCMD:
		ret = system((char*)msg.data);
		break;
	default:
		ret = -1;
		break;
	}

	msg.hdr.len = 0;
	msg.hdr.op_code = OMCI_API_USOCK_OP_CODE_SUCCESS;
	if (ret < 0) {
		printf(OMCI_USOCK_PRN_PREFIX
			"msg process failed, msg_id=0x%X\n", msg.hdr.msg_id);
		msg.hdr.op_code = OMCI_API_USOCK_OP_CODE_ERROR;
	}

	if (send(s, &msg, sizeof(msg.hdr), 0) == -1)
		printf(OMCI_USOCK_PRN_PREFIX
			"msg ack failed, msg_id=0x%X\n", msg.hdr.msg_id);

	return ret;
}

/* Entry point

   \param[in] argc Arguments count
   \param[in] argv Array of arguments
*/
int main(int argc, char *argv[])
{
	int s, s2, len, sretval;
	unsigned int t = sizeof(struct sockaddr_un);
	struct sockaddr_un local, remote;
	fd_set rfds;
	struct timeval tv;

	signal(SIGINT, on_term);
	signal(SIGTERM, on_term);

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		printf(OMCI_USOCK_PRN_PREFIX"sock create failed!\n");
		return -1;
	}

	if (fcntl(s, F_SETFD, FD_CLOEXEC) == -1) {
		printf(OMCI_USOCK_PRN_PREFIX"sock flags set failed!\n");
		goto on_exit;
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, OMCI_API_USOCK_SOCK_PATH);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(s, (struct sockaddr *)&local, len) == -1) {
		printf(OMCI_USOCK_PRN_PREFIX"sock bind failed!\n");
		goto on_exit;
	}

	if (listen(s, 10) == -1) {
		printf(OMCI_USOCK_PRN_PREFIX"sock listen failed!\n");
		goto on_exit;
	}

	printf(OMCI_USOCK_PRN_PREFIX"OMCI Usock Server v%s started...\n",
		OMCI_USOCK_VERSION);

	while (g_run) {

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);

		sretval = select(s + 1, &rfds, NULL, NULL, &tv);
		if (sretval <= 0)
			continue;

		s2 = accept(s, (struct sockaddr *)&remote, &t);
		if (s2 == -1) {
			printf(OMCI_USOCK_PRN_PREFIX"sock accept failed!\n");
			goto on_exit;
		}

		fcntl(s2, F_SETFD, FD_CLOEXEC);

		if (usock_client_process(s2) < 0)
			printf(OMCI_USOCK_PRN_PREFIX"client process failed!\n");

		close(s2);
	}

on_exit:
	close(s);
	unlink(local.sun_path);
	return 0;
}

