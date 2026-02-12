#ifdef LINUX

#include "onu_control.h"
#include "onu_control_config.h"

#ifndef INCLUDE_CLI_SUPPORT
#include <stdarg.h>
#include <stdlib.h>

/**
   Command handler type definition.
*/
typedef int (*cmd_handler)(int fd, char *str_param);

/**
   Wrapper for FIO_GPE_INIT IOCTL call via ONU options.
*/
static int gpe_init(int fd, char *str_param);
/**
   Wrapper for FIO_PLOAM_INIT IOCTL call via ONU options.
*/
static int ploam_init(int fd, char *str_param);
/**
   Wrapper for FIO_GTC_INIT IOCTL call via ONU options.
*/
static int gtc_init(int fd, char *str_param);
/**
   Wrapper for FIO_GTC_SERIAL_NUMBER_SET IOCTL call via ONU options.
*/
static int gtc_serial_number_set(int fd, char *str_param);
/**
   Wrapper for FIO_GTC_CFG_SET IOCTL call via ONU options.
*/
static int gtc_cfg_set(int fd, char *str_param);
/**
   Wrapper for FIO_GTC_POWER_SAVING_MODE_SET IOCTL call via ONU options.
*/
static int gtc_power_saving_mode_set(int fd, char *str_param);
/**
   Wrapper for FIO_ONU_LINE_ENABLE_SET IOCTL call via ONU options.
*/
static int onu_line_enable_set(int fd, char *str_param);
/**
   Wrapper for FIO_LAN_INIT IOCTL call via ONU options.
*/
static int lan_init(int fd, char *str_param);
/**
   Wrapper for FIO_LAN_GPHY_FIRMWARE_DOWNLOAD IOCTL call via ONU options.
*/
static int lan_gphy_firmware_download(int fd, char *str_param);
/**
   Wrapper for FIO_LAN_CFG_SET IOCTL call via ONU options.
*/
static int lan_cfg_set(int fd, char *str_param);
/**
   Wrapper for FIO_LAN_PORT_CFG_SET IOCTL call via ONU options.
*/
static int lan_port_cfg_set(int fd, char *str_param);
/**
   Wrapper for FIO_LAN_EXCEPTION_CFG_SET IOCTL call via ONU options.
*/
static int gpe_lan_exception_cfg_set(int fd, char *str_param);
/**
   Wrapper for FIO_EXCEPTION_QUEUE_CFG_SET IOCTL call via ONU options.
*/
static int gpe_exception_queue_cfg_set(int fd, char *str_param);
/**
   Wrapper for FIO_GPE_SCE_MAC_SET IOCTL call via ONU options.
*/
static int gpe_sce_mac_set(int fd, char *str_param);

/**
   Command type definition.
*/
struct command {
	char *name;
	char *long_name;
	cmd_handler handler;
};

/**
   Supported commands list definition.
*/
struct command command_list[] = {
	{"gpei", "gpe_init", gpe_init},
	{"ploami", "ploam_init", ploam_init},
	{"gtci", "gtc_init", gtc_init},
	{"gtcsns", "gtc_serial_number_set", gtc_serial_number_set},
	{"gtccs", "gtc_cfg_set", gtc_cfg_set},
	{"gtcpsms", "gtc_power_saving_mode_set", gtc_power_saving_mode_set},
	{"onules", "onu_line_enable_set", onu_line_enable_set},
	{"lani", "lan_init", lan_init},
	{"langfd", "lan_gphy_firmware_download", lan_gphy_firmware_download},
	{"lancs", "lan_cfg_set", lan_cfg_set},
	{"lanpcs", "lan_port_cfg_set", lan_port_cfg_set},
	{"gpelecs", "gpe_lan_exception_cfg_set", gpe_lan_exception_cfg_set},
	{" ", "gpe_exception_queue_cfg_set", gpe_exception_queue_cfg_set},
	{"gpesms", "gpe_sce_mac_set", gpe_sce_mac_set},
};

static int gpe_init(int fd, char *str_param)
{
	int ret = 0;
	struct gpe_init_data param;

	ret = sscanf(str_param,
		     "%s %u "
		     "%u %u "
		     "%u %u %u %u "
		     "%u %u %u %u "
		     "%u %u %i %u",
		     &param.fw_name[0], &param.ll_mod_sel.fsqm,
		     &param.ll_mod_sel.iqm, &param.ll_mod_sel.tmu,
		     &param.ll_mod_sel.ictrll[0],
		     &param.ll_mod_sel.ictrll[1],
		     &param.ll_mod_sel.ictrll[2],
		     &param.ll_mod_sel.ictrll[3],
		     &param.ll_mod_sel.octrll[0],
		     &param.ll_mod_sel.octrll[1],
		     &param.ll_mod_sel.octrll[2],
		     &param.ll_mod_sel.octrll[3],
		     &param.ll_mod_sel.ictrlg, &param.ll_mod_sel.octrlg,
		     &param.arb_mode,
		     &param.num_pe);
	if (ret != 16) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_GPE_INIT, &param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int ploam_init(int fd, char *str_param)
{
	int ret = 0;

	ret = onu_iocmd(fd, FIO_PLOAM_INIT, NULL, 0);
	printf("errorcode=%d\n", ret);
	return ret;
}

static int gtc_init(int fd, char *str_param)
{
	int ret = 0;
	struct gtc_init_data param;

	ret = sscanf(str_param, "%u %u %u %u %u %u %u %u",
		     &param.dlos.dlos_enable, &param.dlos.dlos_inversion,
		     &param.dlos.dlos_window_size,
		     &param.dlos.dlos_trigger_threshold,
		     &param.laser_gap, &param.laser_offset,
		     &param.laser_en_end_ext, &param.laser_en_start_ext);
	if (ret != 8) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_GTC_INIT, &param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int gtc_serial_number_set(int fd, char *str_param)
{
	int ret = 0;
	struct gtc_serial_num param;

	ret = sscanf(str_param, "%hhi %hhi %hhi %hhi %hhi %hhi %hhi %hhi",
		     &param.serial_number[0],
		     &param.serial_number[1],
		     &param.serial_number[2],
		     &param.serial_number[3],
		     &param.serial_number[4],
		     &param.serial_number[5],
		     &param.serial_number[6],
		     &param.serial_number[7]);
	if (ret != 8) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_GTC_SERIAL_NUMBER_SET, &param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int gtc_cfg_set(int fd, char *str_param)
{
	int ret = 0;
	struct gtc_cfg param;

	ret = sscanf(str_param, "%u %u %u %u %u %u %u %u %u %u %u "
		     "%hhi %hhi %hhi %hhi %hhi %hhi %hhi %hhi %hhi %hhi",
		     &param.bip_error_interval, &param.sf_threshold,
		     &param.sd_threshold, &param.onu_response_time,
		     &param.serial_number_request_threshold,
		     &param.rogue_msg_id, &param.rogue_msg_rpt,
		     &param.rogue_msg_enable, &param.ploam_timeout_1,
		     &param.ploam_timeout_2, &param.emergency_stop_state,
		     &param.password[0],
		     &param.password[1],
		     &param.password[2],
		     &param.password[3],
		     &param.password[4],
		     &param.password[5],
		     &param.password[6],
		     &param.password[7],
		     &param.password[8],
		     &param.password[9]);
	if (ret != 21) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_GTC_CFG_SET, &param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int gtc_power_saving_mode_set(int fd, char *str_param)
{
	int ret = 0;
	struct gtc_op_mode param;

	ret = sscanf(str_param, "%i", &param.gpon_op_mode);
	if (ret != 1) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_GTC_POWER_SAVING_MODE_SET,
			&param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int onu_line_enable_set(int fd, char *str_param)
{
	int ret = 0;
	struct onu_enable param;

	ret = sscanf(str_param, "%u", &param.enable);
	if (ret != 1) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_ONU_LINE_ENABLE_SET, &param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int lan_init(int fd, char *str_param)
{
	int ret = 0;

	ret = onu_iocmd(fd, FIO_LAN_INIT, NULL, 0);
	printf("errorcode=%d\n", ret);
	return ret;
}

static int lan_gphy_firmware_download(int fd, char *str_param)
{
	int ret = 0;
	struct lan_gphy_fw param;

	ret = sscanf(str_param, "%s", &param.fw_name[0]);
	if (ret != 1) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_LAN_GPHY_FIRMWARE_DOWNLOAD,
			&param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int lan_cfg_set(int fd, char *str_param)
{
	int ret = 0;
	struct lan_cfg param;

	ret = sscanf(str_param, "%i "
		     "%hhi %hhi %hhi %hhi "
		     "%i %u %u",
		     &param.mux_mode,
		     &param.mdio_dev_addr[0],
		     &param.mdio_dev_addr[1],
		     &param.mdio_dev_addr[2],
		     &param.mdio_dev_addr[3],
		     &param.mdio_data_rate, &param.mdio_short_preamble_en,
		     &param.mdio_en);
	if (ret != 8) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_LAN_CFG_SET, &param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int lan_port_cfg_set(int fd, char *str_param)
{
	int ret = 0;
	struct lan_port_cfg param;

	ret = sscanf(str_param, "%u %u %i %i %i %i %hhu %hhu %hu %u %i",
		     &param.index, &param.uni_port_en, &param.mode,
		     &param.duplex_mode, &param.flow_control_mode,
		     &param.speed_mode, &param.tx_clk_dly,
		     &param.rx_clk_dly, &param.max_frame_size,
		     &param.lpi_enable, &param.autoneg_mode);
	if (ret != 11) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_LAN_PORT_CFG_SET, &param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

#define pr

static int gpe_lan_exception_cfg_set(int fd, char *str_param)
{
	int ret = 0;
	struct gpe_lan_exception_cfg param;

	ret = sscanf(str_param, "%u %u %u %u %u %u",
		     &param.lan_port_index,
		     &param.exception_profile,
		     &param.exception_meter_id,
		     &param.exception_meter_enable,
		     &param.igmp_meter_id,
		     &param.igmp_meter_enable);
	if (ret != 6) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_GPE_LAN_EXCEPTION_CFG_SET, &param,
			sizeof(param));

	printf("errorcode=%d\n", ret);
	return ret;
}

static int gpe_exception_queue_cfg_set(int fd, char *str_param)
{
	int ret = 0;
	struct gpe_exception_queue_cfg param;

	ret = sscanf(str_param, "%u %u %u",
		     &param.exception_index, &param.exception_queue,
		     &param.snooping_enable);
	if (ret != 3) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_GPE_EXCEPTION_QUEUE_CFG_SET, &param,
			sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int gpe_sce_mac_set(int fd, char *str_param)
{
	int ret = 0;
	struct gpe_sce_mac param;

	ret = sscanf(str_param, "%hhi %hhi %hhi %hhi %hhi %hhi",
		     &param.local_cpu_mac[0],
		     &param.local_cpu_mac[1],
		     &param.local_cpu_mac[2],
		     &param.local_cpu_mac[3],
		     &param.local_cpu_mac[4],
		     &param.local_cpu_mac[5]);
	if (ret != 6) {
		return -1;
	}

	ret = onu_iocmd(fd, FIO_GPE_SCE_MAC_SET, &param, sizeof(param));
	printf("errorcode=%d\n", ret);
	return ret;
}

static int onu_cli(int argc, char *argv[])
{
	int fd, i, ret = -1;
	unsigned int len;

	fd = onu_open(ONU_DEVICE_PATH);
	if (fd < 0) {
		printf("oops fd %d (errno=%d)\n", fd, errno);
		fprintf(stderr,
			"ERROR: can't open device " ONU_DEVICE_PATH ".\n");
		return ret;
	}

	buf[0] = 0;
	len = 0;
	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			len += (strlen(argv[i])+1);
			if(len < (sizeof(buf)-1)) {
				strcat(buf, argv[i]);
				strcat(buf, " ");
			}
		}
	} else {
		strcat(buf, "help");
	}

	if ((ret = onu_iocmd(fd, FIO_ONU_CLI, &buf[0], strlen(buf))) == 0) {
		if(strncmp(buf, "errorcode=0", 11))
			ret = -1;
		/*if(!g_silence) */ {
			len = strlen(buf);
			len = len < sizeof(buf) ? len : (sizeof(buf)-1);
			buf[len] = 0;
			fprintf(stdout, "%s", &buf[0]);
			if(buf[len-1] != '\n')
				fprintf(stdout, "\n");
		}
	} else {
		fprintf(stderr, "ERROR: can't execute command.\n");
	}
	onu_close(fd);

	return ret;
}

/**
   Handle configuration commands in the case of disabled CLI.
*/
int onu_cfg(int argc, char *argv[])
{
	int fd, i, j, ret;
	unsigned int cmd_num, len;

	fd = onu_open(ONU_DEVICE_PATH);
	if (fd < 0) {
		printf("oops fd %d (errno=%d)\n", fd, errno);
		fprintf(stderr,
			"ERROR: can't open device " ONU_DEVICE_PATH ".\n");
		return -1;
	}

	cmd_num = sizeof(command_list) / sizeof(command_list[0]);
	for (i = 0; i < cmd_num; i++) {
		if ((strcmp(command_list[i].name, argv[1]) == 0) ||
		    (strcmp(command_list[i].long_name, argv[1]) == 0)) {
			buf[0] = 0;
			len = 0;
			for (j = 2; j < argc; j++) {
				len += strlen(argv[j]) + 1;
				if (len < sizeof(buf) - 1) {
					strcat(buf, argv[j]);
					strcat(buf, " ");
				}
			}
			ret = command_list[i].handler(fd, buf);
			if (ret)
				fprintf(stderr,
					"ERROR: %s execution error %d\n",
					argv[1], ret);

			onu_close(fd);
			return ret;
		}
	}

	fprintf(stderr, "ERROR: command %s not found\n", argv[1]);

	onu_close(fd);
	return -1;
}
#endif

#endif				/* LINUX */
