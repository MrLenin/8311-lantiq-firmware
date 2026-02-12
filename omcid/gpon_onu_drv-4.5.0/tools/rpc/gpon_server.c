#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include "dti_socket_lib.h"
#include "gpon_rpc_interface.h" /* dti_xxx() */
#include "gpon_client_rpc_interface.h" /* onu_xxx() */

static void handler_info(struct dti_ctx *ctx, void *data, const uint32_t len)
{
	char *ptr = data;

	strcpy(ptr, "error=0 rpc_server=1\n");
	dti_packet_send(ctx,
		DTI_PACKET_TYPE_CLI_INFO,
		DTI_8BIT,
		ctx->rx_header.tan,
		ptr,
		strlen(ptr),
		NULL,
		0);
}

static void handler_cli(struct dti_ctx *ctx, void *data, const uint32_t len)
{
	char *ptr = data;

	printf("server: %s\n", ptr);
	if(ctx->rx_header.channel == 0)
		strcpy(ptr, "error=0 device=0 version=42\n");
	else
		strcpy(ptr, "error=0 device=1 version=42\n");
	dti_packet_send(ctx,
		DTI_PACKET_TYPE_CLI_INFO,
		DTI_8BIT,
		ctx->rx_header.tan,
		ptr,
		strlen(ptr),
		NULL,
		0);
}

static void handler_ioctl(struct dti_ctx *ctx, void *data, const uint32_t len, const uint32_t cmd)
{
	int tx_len=0;
	unsigned char *ptr = data;
	struct onu_version_string ovs = {"1", "2", "3", "4", "5"};

	printf("server: message received... ");
	switch(cmd) {
		case FIO_ONU_VERSION_GET:
		printf("FIO_ONU_VERSION_GET\n");
		memset(ptr, 0, 4);
		memcpy(ptr + 4, &ovs, sizeof(ovs));
		tx_len = sizeof(ovs) + 4;
		break;

		default:
		memset(ptr, 0xff, 4);
		tx_len = 4;
		printf("unknown\n");
		break;
	}
	dti_packet_send(ctx,
		DTI_PACKET_TYPE_MESSAGE,
		DTI_8BIT,
		ctx->rx_header.tan,
		data,
		tx_len,
		NULL,
		0);
}

int main(int argc, char* argv[])
{
	int ret, i, silent=0, len, error;
	unsigned int rx_tan = 0;
	unsigned int type;
	unsigned int opt;
	struct onu_rctx ctx;
	dti_socket server;
	dti_socket client;
	uint32_t cmd;

	/* Prepare the default dti parameters. */
	memset(&ctx, 0x00, sizeof(struct onu_rctx));
	ctx.dti.udp_port = 9000;
	strcpy(ctx.dti.ip_addr, "127.0.0.1");
	ctx.dti.tan = 1;

	/* Update the dti parameters, if required. */
	for(i=1;i<argc;i++) {
		if(argv[i][0] != '-')
			continue;
		if(argv[i][1] == 'p') {
			ctx.dti.udp_port = atoi((char *)&argv[i][2]);
			printf("Port: %d\n", ctx.dti.udp_port);
			continue;
		}
		if(argv[i][1] == 's') {
			silent=1;
			printf("Silent: enabled\n");
			continue;
		}
	}

	ret = dti_server_start(&ctx.dti);
	if(ret != 0)
		return -1;

	for(;;) {
		printf("wait for incomming connection\n");
		ret = dti_server_connect(&ctx.dti);
		if(ret == -1)
			break;
		printf("accept\n");
		for(;;) {
			len = 0;
			error = 0;
			type = 0;
			opt = 0;
			ret = dti_packet_receive(&ctx.dti, &type, &opt, &rx_tan, &ctx.buffer[0], MAX_RX_BUFFER, &len, &error);
			if(ret < 0)
				break;
			switch(ctx.dti.rx_header.type) {
				case DTI_PACKET_TYPE_CLI_INFO:
				handler_info(&ctx.dti, &ctx.buffer[0], len);
				break;
				case DTI_PACKET_TYPE_CLI_STRING:
				handler_cli(&ctx.dti, &ctx.buffer[0], len);
				break;
				case DTI_PACKET_TYPE_MESSAGE:
				handler_ioctl(&ctx.dti, &ctx.buffer[0], len, error);
				break;
			}
		}
		ret = dti_server_disconnect(&ctx.dti);
	}
	dti_server_stop(&ctx.dti);

	return 0;
}
