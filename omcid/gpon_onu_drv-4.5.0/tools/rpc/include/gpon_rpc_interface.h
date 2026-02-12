#ifndef _gpon_rpc_interface_h
#define _gpon_rpc_interface_h

#include "dti_client_lib.h"

#define MAX_RX_BUFFER 4096

struct onu_rctx
{
	struct dti_ctx dti;
	char buffer[MAX_RX_BUFFER];
	unsigned int len;
};

#endif
