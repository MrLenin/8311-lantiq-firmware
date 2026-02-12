/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_usock_h
#define _omci_api_usock_h

#include "omci_api.h"

__BEGIN_DECLS


/** \defgroup OMCI_API_USOCK uSock

   @{
*/

/** Unix domain socket path */
#define OMCI_API_USOCK_SOCK_PATH		"/tmp/omci_usock"
/** Usock message data length max (bytes) */
#define OMCI_API_USOCK_MSG_DATA_SIZE_MAX	256

#define OMCI_API_USOCK_MSG_ID_SYSCMD		0x00000001

#define OMCI_API_USOCK_OP_CODE_SUCCESS		(0)
#define OMCI_API_USOCK_OP_CODE_ERROR		(-1)

/** Usock Message header
*/
struct usock_msg_hdr {
	/** Message ID*/
	uint32_t msg_id;
	/** Message data length in bytes*/
	uint32_t len;
	/** Optional op code */
	int32_t op_code;
};

/** Usock message
*/
struct usock_msg {
	/** Header*/
	struct usock_msg_hdr hdr;
	/** Data*/
	uint8_t data[OMCI_API_USOCK_MSG_DATA_SIZE_MAX];
};

/** Send Unix domain socket message

   \param[in] ctx                   OMCI API context pointer
   \param[in] msg                   Message
*/
enum omci_api_return
omci_api_usock_msg_send(struct omci_api_ctx *ctx, struct usock_msg *msg);

/** Run shell command using send of Unix domain socket message

   \param[in] ctx                   OMCI API context pointer
   \param[in] cmd                   Shell command string
*/
enum omci_api_return
omci_api_scmd_run(struct omci_api_ctx *ctx, const char *cmd);


/** @} */

__END_DECLS

#endif
