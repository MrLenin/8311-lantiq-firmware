/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "omci_api_usock.h"

/** \addtogroup OMCI_API_USOCK

   @{
*/

enum omci_api_return
omci_api_usock_msg_send(struct omci_api_ctx *ctx, struct usock_msg *msg)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	int32_t s, t, len;
	struct sockaddr_un remote;

	/* currently not used*/
	(void)ctx;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   msg=%p\n", __FUNCTION__, msg));

	if (!ctx || !msg)
		return OMCI_API_ERROR;

	if (msg->hdr.len > sizeof(msg->data))
		return OMCI_API_ERROR;

	if (msg->hdr.msg_id != OMCI_API_USOCK_MSG_ID_SYSCMD)
		return OMCI_API_ERROR;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s == -1) {
		DBG(OMCI_API_ERR, ("socket create failed\n"));
		return OMCI_API_ERROR;
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, OMCI_API_USOCK_SOCK_PATH);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		DBG(OMCI_API_ERR, ("socket connect failed\n"));
		close(s);
		return OMCI_API_ERROR;
	}

	len = send(s, msg, sizeof(msg->hdr) + msg->hdr.len, 0);
        if (len == -1) {
		DBG(OMCI_API_ERR, ("socket send failed\n"));
		close(s);
		return OMCI_API_ERROR;
        }

	if (recv(s, msg, sizeof(msg->hdr), 0) != sizeof(msg->hdr)) {
		ret = OMCI_API_ERROR;
	} else {
		if (msg->hdr.op_code != OMCI_API_USOCK_OP_CODE_SUCCESS) {
			DBG(OMCI_API_ERR, ("msg ack, msg_id=0x%x op_code=%d\n",
					msg->hdr.msg_id, msg->hdr.op_code));
			ret = OMCI_API_ERROR;
		}
	}

	close(s);
	return ret;
}

enum omci_api_return
omci_api_scmd_run(struct omci_api_ctx *ctx, const char *cmd)
{
	struct usock_msg msg;
	uint32_t len = strlen(cmd) + 1;

	if (len > sizeof(msg.data))
		return OMCI_API_ERROR;

	msg.hdr.msg_id = OMCI_API_USOCK_MSG_ID_SYSCMD;
	msg.hdr.len = len;

	memcpy(msg.data, cmd, len);

	if (omci_api_usock_msg_send(ctx, &msg) != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

/** @} */

#endif /* LINUX */
