#include <stdio.h>
#include <string.h> /* strlen */
#include "gpon_rpc_interface.h" /* dti_xxx() */
#include "gpon_client_rpc_interface.h" /* onu_xxx() */

/* Read the software version information from FALC ON.
   It defines a dedicated function, directly callable by the software.
   This would be needed for each function that is used. */
static void version_dump(struct dti_ctx *ctx,
							unsigned char *buf,
							const unsigned int len,
							const unsigned int silent,
							const unsigned int channel)
{
	dti_channel_set(ctx, channel);
	/* Select the command to be performed:
	    Here: vig = version_information_get */
	if(dti_client_cli_execute(ctx, "vig", buf, len) >= 0) {
		if(silent == 0) {
			printf(buf);
		}
	} else {
		printf("ERROR: can't execute CLI command vig.\n");
	}
}

int main(int argc, char* argv[])
{
	int ret=0, cnt=1, i, ioctl_test=0, silent=0;
	struct onu_rctx ctx;

	/* Define the parameter structure for "version get",
	   use a union to cover different parameter definitions in a single memory space
	   if multiple functions shall be implemented. */
	struct onu_version_string param;

	/* Define the command to be given and th error code to be returned. */
	char *cmd = "vig";
	enum onu_errorcode err;

	/* Prepare the default dti parameters. */
	memset(&ctx, 0x00, sizeof(struct onu_rctx));
	ctx.dti.udp_port = 9000;
	strcpy(ctx.dti.ip_addr, "127.0.0.1");
	ctx.dti.tan = 1;

	/* Update the dti parameters, if required. */
	for(i=1;i<argc;i++) {
		if(argv[i][0] != '-')
			continue;
		if(argv[i][1] == 'c') {
			cnt = atoi(&argv[i][2]);
			if(cnt > 100000U)
				cnt = 0;
			printf("Count: %d\n", cnt);
			continue;
		}
		if(argv[i][1] == 'p') {
			ctx.dti.udp_port = atoi((char *)&argv[i][2]);
			printf("Port: %d\n", ctx.dti.udp_port);
			continue;
		}
		if(argv[i][1] == 'r') {
			strcpy(ctx.dti.ip_addr, &argv[i][2]);
			printf("IP: %s\n", ctx.dti.ip_addr);
			continue;
		}
		if(argv[i][1] == 'm') {
			cmd =(char *) &argv[i][2];
			printf("Cmd: %s\n", cmd);
			continue;
		}
		if(argv[i][1] == 'l') {
			ioctl_test=1;
			printf("IOCTL test: enabled\n");
			continue;
		}
		if(argv[i][1] == 's') {
			silent=1;
			printf("Silent: enabled\n");
			continue;
		}
	}

	/* Start the dti session and prepare the context. */
	ret = dti_client_session_start(&ctx.dti);
	if(ret < 0) {
		return -1;
	}

#if 0
	/* Just for information ... */
	if(dti_client_info_get(&ctx.dti, &ctx.buffer[0], MAX_RX_BUFFER) >= 0) {
		printf("info: %s\n", ctx.buffer);
	} else {
		printf("ERROR: can't execute info command.\n");
	}

	/* Call the dedicated function. */
	version_dump(&ctx.dti, &ctx.buffer[0], MAX_RX_BUFFER, silent, 1);
	version_dump(&ctx.dti, &ctx.buffer[0], MAX_RX_BUFFER, silent, 0);
#endif

	while(cnt--) {
		if(ioctl_test) {
			/* test the ioctl mapping */
			/* Be aware of the return value endianess. */
			err = onu_version_get(&ctx, &param);
			if(err == ONU_STATUS_OK) {
				if(silent == 0) {
					printf("driver version: %s\n", param.onu_version);
					printf("fw version:     %s\n", param.fw_version);
					printf("cop version:    %s\n", param.cop_version);
					printf("sce version:    %s\n", param.sce_interface_version);
					printf("chip id:        %s\n", param.chip_id);
				}
			} else {
				printf("ERROR: can't execute binary command.\n");
			}
		} else {
			/* Alternatively use the CLI method. */
			if(dti_client_cli_execute(&ctx.dti, cmd, &ctx.buffer[0], MAX_RX_BUFFER) >= 0) {
				if(silent == 0) {
					printf(ctx.buffer);
				}
			} else {
				printf("ERROR: can't execute CLI command.\n");
			}
		}
	}

	/* Terminate the dti session, when done. */
	ret = dti_client_session_stop(&ctx.dti);
	if(ret < 0) {
		return -1;
	}

	return 0;
}
