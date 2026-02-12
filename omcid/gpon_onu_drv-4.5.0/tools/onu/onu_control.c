#ifdef LINUX

#include "onu_control.h"
#include "onu_control_config.h"

#ifndef INCLUDE_CLI_SUPPORT
#include <stdarg.h>
#include <stdlib.h>
#endif

#ifdef ONU_SCE_TABLES_WRAPPERS
#include "onu_sce_xml_wrappers.h"
#include "onu_sce_json_wrappers.h"
#include "onu_sce_wrappers_misc.h"
#endif

#ifdef INCLUDE_REMOTE_ONU
#include "dti_rpc.h"
#endif

/** what string support */
const char ctrl_whatversion[] = CTRL_WHAT_STR;

char buf[ONU_IO_BUF_SIZE];

static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{"daemon", 0, 0, 'd'},
	{"log-file", 1, 0, 'f'},
	{"silence", 0, 0, 's'},
	{"times-tamp", 0, 0, 't'},
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	{"ioctl-dump", 0, 0, 'i'},
#endif
#ifdef INCLUDE_REMOTE_ONU
	{"remote", 1, 0, 'r'},
#endif
	{NULL, 0, 0, 0}
};

/* 1 colon means there is a required parameter */
/* 2 colons means there is an optional parameter */
static const char getopt_long_optstring[] = 
	"hvdf:st"
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	"i"
#endif
#ifdef INCLUDE_REMOTE_ONU
	"r:"
#endif
	;

/**
   description of command line options
*/
static char *description[] = {
	"help screen",
	"version",
	"daemon",
	"write log to specified file",
	"no output",
	"enable the timestamp",
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	"dump ioctl as CLI command",
#endif
#ifdef INCLUDE_REMOTE_ONU
	"remote ONU access",
#endif
};

static int g_help;
static int g_version;
static int g_daemon;
static char g_log_file[MAX_PATH];
static int g_silence;
static int g_time_stamp;
#ifdef INCLUDE_CLI_DUMP_SUPPORT
static int g_ioctl_dump;
#endif
#ifdef INCLUDE_REMOTE_ONU
char g_remote[MAX_PATH];
#endif

/**
   Parse all arguments and enable requested features.

   \param argc number of parameters
   \param argv array of parameter strings

   \return
   - 0 if all parameters decoded
   - -1 if not all parameters could be decoded
*/
static int onu_args_parse(char argc, char *argv[])
{
	int option_index = 0;

	if(argc > 1 && argv[1][0] != '-')
		return 0;

	while (1) {
		int c;

		/* 1 colon means there is a required parameter */
		/* 2 colons means there is an optional parameter */
		c = getopt_long(argc, argv, getopt_long_optstring, long_options,
				&option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			g_help = 1;
			break;
		case 'v':
			g_version = 1;
			break;
		case 'd':
			g_daemon = 1;
			break;
		case 'f':
			if(optarg && (strlen(optarg)<(MAX_PATH-1))) {
				strcpy(g_log_file, optarg);
				printf("using log file %s\n", g_log_file);
			} else {
				printf("missig log file name\n");
			}
			break;
		case 's':
			g_silence = 1;
			break;
#ifdef INCLUDE_CLI_DUMP_SUPPORT
		case 'i':
			g_ioctl_dump = 1;
			break;
#endif
		case 't':
			g_time_stamp = 1;
			break;
#ifdef INCLUDE_REMOTE_ONU
		case 'r':
			if(optarg && (strlen(optarg)<(MAX_PATH-1))) {
				strcpy(g_remote, optarg);
			}
			break;
#endif
		default:
			return 0;
		}
	}
	return 0;
}

/**
   Print the help text to the terminal.

   \return
   - 0
   - -1
*/
static int onu_usage(const char *pAppName)
{
	struct option *ptr;
	char **desc = &description[0];
	uint32_t len = 0, fillLen = 0;
	static const char *fill = "             ";

	ptr = long_options;

	fprintf(stdout, "usage: %s [options] | <cli command>\n", pAppName);
	fprintf(stdout, "example: %s vig\n", pAppName);
#ifdef ONU_SCE_TABLES_WRAPPERS
	fprintf(stdout, "\nto dump SCE table use: "
		"%s <format> <table> <index>\n", pAppName);
	fprintf(stdout, "where format is 'xml_table', 'json_table', "
		"'xml_wrapper' or 'json_wrapper' "
		"and index can be -1 to dump all entries\n\n");
#endif

	while (ptr->name) {
		len = strlen(ptr->name);
		fillLen = strlen(fill);
		if (fillLen > 1)
			fillLen = (int)(fillLen - 1);
		if (len > fillLen)
			len = fillLen;
		fprintf(stdout, " --%s%s(-%c)\t- %s\n", ptr->name, &fill[len],
			ptr->val, *desc);
		ptr++;
		desc++;
	}

	return 0;
}

/**
   Print the version info to the terminal.

   \return
   - 0
   - -1
*/
static int onu_version(void)
{
	int fd, ret = -1;
	struct onu_version_string data;

	fd = onu_open(ONU_DEVICE_PATH);

	if (fd >= 0) {
		if ((ret = onu_iocmd(fd, FIO_ONU_VERSION_GET, &data, sizeof(data))) == 0) {
			fprintf(stdout, "driver version: %s\n", data.onu_version);
			fprintf(stdout, "fw version:     %s\n", data.fw_version);
			fprintf(stdout, "cop version:    %s\n", data.cop_version);
			fprintf(stdout, "sce version:    %s\n", data.sce_interface_version);
			fprintf(stdout, "chip id:        %s\n", data.chip_id);
		} else {
			fprintf(stderr,
				"ERROR: can't read version from device.\n");
		}
		onu_close(fd);
	} else {
		fprintf(stderr,
			"ERROR: can't open device " ONU_DEVICE_PATH ".\n");
	}

	return ret;
}

const char *onu_msg_id_ds_string(uint8_t msg_id)
{
	if (msg_id == PLOAM_DN_UPSTREAM_OVERHEAD)
		return "UpstreamOverhead";
	else if (msg_id == PLOAM_DN_SERIAL_NUM_MASK)
		return "SerialNumMask";
	else if (msg_id == PLOAM_DN_ASSIGN_ONU_ID)
		return "AssignOnuId";
	else if (msg_id == PLOAM_DN_RANGING_TIME)
		return "RangingTime";
	else if (msg_id == PLOAM_DN_DEACTIVE_ONU_ID)
		return "DeactiveOnuId";
	else if (msg_id == PLOAM_DN_DISABLE_SERIAL_NUM)
		return "DisableSerialNum";
	else if (msg_id == PLOAM_DN_CONFIGURE_VP_VC)
		return "ConfigureVpVc";
	else if (msg_id == PLOAM_DN_ENCRYPTED_PORTID)
		return "EncryptedPortId";
	else if (msg_id == PLOAM_DN_REQUEST_PASSWORD)
		return "RequestPassword";
	else if (msg_id == PLOAM_DN_ASSIGN_ALLOC_ID)
		return "AssignAllocId";
	else if (msg_id == PLOAM_DN_NO_MESSAGE)
		return "NoMessage";
	else if (msg_id == PLOAM_DN_POPUP)
		return "Popup";
	else if (msg_id == PLOAM_DN_REQUEST_KEY)
		return "RequestKey";
	else if (msg_id == PLOAM_DN_CONFIGURE_PORT_ID)
		return "ConfigurePortId";
	else if (msg_id == PLOAM_DN_PHY_EQUIPMENT_ERR)
		return "PhyEquipmentErr";
	else if (msg_id == PLOAM_DN_CHANGE_POWER_LEVEL)
		return "ChangePowerLevel";
	else if (msg_id == PLOAM_DN_PST)
		return "Pst";
	else if (msg_id == PLOAM_DN_BER_INTERVAL)
		return "BerInterval";
	else if (msg_id == PLOAM_DN_KEY_SWITCHING_TIME)
		return "KeySwitchingTime";
	else if (msg_id == PLOAM_DN_EXTENDED_BURST_LEN)
		return "ExtendedBurstLen";
	else if (msg_id == PLOAM_DN_PON_ID)
		return "PonID";
	else {
		return "unknown";
	};
}

const char *onu_msg_id_us_string(uint8_t msg_id)
{
	if (msg_id == PLOAM_UP_SERIAL_NUMBER_ONU)
		return "serial number";
	else if (msg_id == PLOAM_UP_PASSWORD)
		return "password";
	else if (msg_id == PLOAM_UP_DYING_GASP)
		return "dying gasp";
	else if (msg_id == PLOAM_UP_NO_MESSAGE)
		return "no message";
	else if (msg_id == PLOAM_UP_ENCRYPTION_KEY)
		return "encryption key";
	else if (msg_id == PLOAM_UP_PHY_EQUIPMENT_ERR)
		return "phy error";
	else if (msg_id == PLOAM_UP_PST)
		return "pst";
	else if (msg_id == PLOAM_UP_REI)
		return "rei";
	else if (msg_id == PLOAM_UP_ACKNOWLEDGE)
		return "ack";
	else {
		return "unknown";
	};
}

void onu_time_stamp(FILE * file, struct tm *tm)
{
	char s[100];

	if (!tm)
		return;

	sprintf(s, "%4d-%2d-%2d %2d:%2d:%2d",
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
	if (tm->tm_mon < 9)
		s[5] = '0';
	if (tm->tm_mday < 10)
		s[8] = '0';
	if (tm->tm_hour < 10)
		s[11] = '0';
	if (tm->tm_min < 10)
		s[14] = '0';
	if (tm->tm_sec < 10)
		s[17] = '0';

	fprintf(file, "%s ", s);
}

static void onu_termination_handler(int sig)
{
	/* ignore the signal, we'll handle by ourself */
	signal (sig, SIG_IGN);

	if (sig == SIGINT || sig == SIGTERM) {
		printf("\nBye from the ONU Control Application\n");
		g_daemon = 0;
	}
}

const char *omci_msg_type[] = {
"", "", "", "", "create", "", "delete", "", "set", "get",
"", "get", "get", "mib upload", "mib upload next", "mib reset",
"alarm notification", "attribute value change", "test request",
"start software download", "download section", "end software download",
"activate software", "commit software", "synchronize time", "reboot",
"get next", "test result", "get current data", "set table"
};

static void onu_dump_omci( FILE * fd,
				const unsigned int event,
				const unsigned int length,
				const unsigned char *data)
{
	struct omci_msg *msg = (struct omci_msg *)data;
	struct omci_msg_rsp *rsp = (struct omci_msg_rsp *)data;
	unsigned int i;

	fprintf( fd, "%s: %u@%u",
			event == ONU_EVENT_OMCI_RECEIVE ? "rx" : "tx",
			msg->header.class_id,
			msg->header.instance_id);
	if(msg->header.type & (1 << 6)) fprintf( fd, ", AR");
	if(msg->header.type & (1 << 5)) fprintf( fd, ", AK");
	if((msg->header.type & 0x1f) < 30)
		fprintf( fd, ", %s, %s",
			omci_msg_type[msg->header.type & 0x1f],
			msg->header.tci & 0x8000 ? "high" : "low");
	fprintf( fd, "\n");
	fprintf( fd, "%s|%04x|%02x|%02x|%04x|%04x|%02x|",
			event == ONU_EVENT_OMCI_RECEIVE ? "rx" : "tx",
			msg->header.tci,
			msg->header.type,
			msg->header.dev_id,
			msg->header.class_id,
			msg->header.instance_id,
			event == ONU_EVENT_OMCI_RECEIVE ? 0 : rsp->result);

	if (g_log_file[0] != 0) {
		for (i = 0; i < length; i++)
			fprintf( fd, "%02x ", data[i]);
	}
	fprintf(fd, "\n");
}

static void onu_dump_ploam( FILE * fd,
				const unsigned int event,
				const struct ploam_msg *msg)
{
	unsigned int i;

	fprintf( fd, "ploam %s: onu id - %d / %s\n",
		event == ONU_EVENT_PLOAM_US ? "us" : "ds",
		(int)msg->onu_id,
		event == ONU_EVENT_PLOAM_US ? 
		   onu_msg_id_us_string(msg->msg_id) :
		   onu_msg_id_ds_string(msg->msg_id));

	fprintf( fd, "%s|%02x %02x ",
				 event == ONU_EVENT_PLOAM_US ? "ploam us" : "ploam ds",
				 msg->onu_id,
				 msg->msg_id);

	if (g_log_file[0] != 0) {
		for (i = 0; i < 10; i++)
			fprintf( fd, "%02x ", msg->content[i]);
	}

	fprintf(fd, "\n");
}

static int onu_event_wait_local(int fd, struct onu_fifo_data *fifo_data)
{
	int ret;
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	ret = select(fd + 1, &rfds, NULL, NULL, &tv);
	if (ret == -1) {
		fprintf(stderr, "[onud] ERROR: select error.\n");
		return -1;
	}
	if (ret == 0)
		/* no data within timeout */
		return 1;

	if (FD_ISSET(fd, &rfds) == 0) {
		/* not for us */
		printf("*");
		return 1;
	}
	ret = onu_iocmd(fd, FIO_ONU_EVENT_FIFO, fifo_data, sizeof(struct onu_fifo_data));
	if (ret != 0) {
		fprintf(stderr,
			"[onud] ERROR: can't read from device.\n");
		return -1;
	}

	return 0;
}

static int onu_daemon(void)
{
	int fd, ret = -1;
	struct onu_fifo_data fifo_data;
	struct onu_event_mask fifo_mask;
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	struct onu_test_mode test_mode;
#endif
	FILE *log_file = stdout;

	signal(SIGINT, onu_termination_handler);
	signal(SIGTERM, onu_termination_handler);

	fd = onu_open(ONU_DEVICE_PATH);

	if (fd < 0) {
		fprintf(stderr,
			"[onud] ERROR: can't open device " ONU_DEVICE_PATH
			".\n");
		return ret;
	}

	if (g_log_file[0] != 0)
		log_file = fopen(g_log_file, "w");

	if (!log_file) {
		fprintf(stderr, "[onud] ERROR: can't open log file.\n");
		onu_close(fd);
		return -1;
	}

#ifdef INCLUDE_CLI_DUMP_SUPPORT
	if (g_ioctl_dump) {
		strcpy(test_mode.mode, ONU_TESTMODE_IOCTL_TRACE_KEY"=1");
		onu_iocmd(fd, FIO_ONU_TEST_MODE_SET, &test_mode, sizeof(test_mode));
	}
#endif

	fifo_mask.val = 0xFFFFFFFF;

	ret = onu_iocmd(fd, FIO_ONU_EVENT_ENABLE_SET, &fifo_mask, sizeof(fifo_mask));
	if (ret != 0)
		fprintf(stderr, "[onud] ERROR: can't enable event FIFO\n");

	while (g_daemon) {
		if (g_log_file[0] != 0)
			fflush(log_file);

#ifdef INCLUDE_REMOTE_ONU
		if(g_remote[0])
		{
			ret = remote_device_event_read(fd, &fifo_data, sizeof(fifo_data));
		} else
#endif
		{
			ret = onu_event_wait_local(fd, &fifo_data);
		}
		if(ret < 0)
			break;
		if(ret > 0)
			continue;

#ifdef INCLUDE_CLI_DUMP_SUPPORT
		if (g_log_file[0] == 0) {
			if(fifo_data.header.id != ONU_EVENT_IOCTL_TRACE ||
				(fifo_data.header.id == ONU_EVENT_IOCTL_TRACE &&
				g_ioctl_dump))
			fprintf(log_file, "[onud] ");
		}
#endif

		if(g_time_stamp == 1) {
			time_t itime = time(0);
			onu_time_stamp(log_file, localtime(&itime));
		}

		switch (fifo_data.header.id) {
		case ONU_EVENT_HARDWARE:
			fprintf(log_file, "hardware event\n");
			break;

		case ONU_EVENT_PLOAM_US:
		case ONU_EVENT_PLOAM_DS:
			onu_dump_ploam(log_file, fifo_data.header.id, &fifo_data.data.ploam_message);
			break;

		case ONU_EVENT_STATE_CHANGE:
			fprintf(log_file, "state change: new %d, old %d\n",
				(int)fifo_data.data.state.curr_state,
				(int)fifo_data.data.state.
				previous_state);
			break;

		case ONU_EVENT_GTC_STATUS_CHANGE:
			fprintf(log_file, "GTC status change:\n");
			fprintf(log_file, "ONU ID %d\n",
				fifo_data.data.status.onu_id);
			fprintf(log_file,
				"Downstream FEC enable status %d\n",
				fifo_data.data.status.ds_fec_enable);
			fprintf(log_file,
				"Upstream FEC enable status %d\n",
				fifo_data.data.status.us_fec_enable);
			fprintf(log_file,
				"PLOAMd message waiting in buffer %d\n",
				fifo_data.data.status.ds_ploam_waiting);
			fprintf(log_file,
				"PLOAMd message buffer overflow %d\n",
				fifo_data.data.status.ds_ploam_overflow);
			fprintf(log_file,
				"Receive state machine status %d\n",
				fifo_data.data.status.ds_state);
			fprintf(log_file,
				"Receive superframe state machine "
				"status %d\n",
				fifo_data.data.status.ds_sf_state);
			fprintf(log_file,
				"Physical Equipment Error (PEE) %d\n",
				fifo_data.data.status.
				ds_physical_equipment_error);
			break;

		case ONU_EVENT_OMCI_RECEIVE:
			onu_dump_omci(log_file,
				fifo_data.header.id,
				fifo_data.data.omci_message.length,
				&fifo_data.data.omci_message.message[0]);
			break;

		case ONU_EVENT_OMCI_SENT:
			onu_dump_omci(log_file,
				fifo_data.header.id,
				fifo_data.data.omci_message.length,
				&fifo_data.data.omci_message.message[0]);
			break;
#ifdef INCLUDE_CLI_DUMP_SUPPORT
		case ONU_EVENT_IOCTL_TRACE:
			if(g_ioctl_dump) {
				fprintf(log_file, "onu %s",
					fifo_data.data.onu_ioctl_trace);
			}
			break;
#endif
		case ONU_EVENT_BWMAP_TRACE:
			fprintf(log_file,
				"bwmap trace stopped (bwmstat 0x%x)\n",
				(int)fifo_data.data.val32);
			break;

		case ONU_EVENT_SCE_BP_REACHED:
			fprintf(log_file, "breakpoint hit\n");
			break;

		case ONU_EVENT_GTC_TCA:
			fprintf(log_file, "threshold crossing alarm\n");
			break;

		case ONU_EVENT_LINK_STATE_CHANGE:
			fprintf(log_file, "port %u state changed to %s "
				"(was %s)\n",
				fifo_data.data.link_state.port,
				fifo_data.data.link_state.new ? "on" : "off",
				fifo_data.data.link_state.old ? "on" : "off");
			break;

		case ONU_EVENT_15MIN_INTERVAL_END:
			fprintf(log_file, "15min interval\n");
			break;

		default:
			fprintf(log_file, "unknown event %d\n",
				fifo_data.header.id);
			break;
		}
	}
	onu_close(fd);

	if (g_log_file[0] != 0)
		fclose(log_file);

	return ret;
}

#ifdef INCLUDE_CLI_SUPPORT
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
		if(!g_silence) {
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
#endif

#ifdef ONU_SCE_TABLES_WRAPPERS
static int onu_sce_wrappers(int argc, char *argv[])
{
	int fd, ret = 0;

	fd = onu_open(ONU_DEVICE_PATH);
	if (fd < 0) {
		printf("oops fd %d (errno=%d)\n", fd, errno);
		fprintf(stderr,
			"ERROR: can't open device " ONU_DEVICE_PATH ".\n");

		ret = 1;
		goto exit;
	}

	if (argc >= 4 && strcmp(argv[1], "xml_table") == 0) {
		xml_table_by_name_get(stdout, argv[2], fd, 1, atoi(argv[3]));

		ret = 1;
		goto exit;
	}

	if (argc >= 4 && strcmp(argv[1], "json_table") == 0) {
		json_table_by_name_get(stdout, argv[2], fd, 1, atoi(argv[3]));

		ret = 1;
		goto exit;
	}

	if (argc >= 4 && strcmp(argv[1], "xml_wrapper") == 0) {
		wrapper_by_name_get(stdout, argv[2], fd, OUTPUT_XML, atoi(argv[3]));

		ret = 1;
		goto exit;
	}

	if (argc >= 4 && strcmp(argv[1], "json_wrapper") == 0) {
		wrapper_by_name_get(stdout, argv[2], fd, OUTPUT_JSON, atoi(argv[3]));

		ret = 1;
		goto exit;
	}

exit:
	onu_close(fd);
	return ret;
}
#endif

int main(int argc, char *argv[])
{
	g_help = -1;
	g_version = -1;
	g_daemon = -1;
	g_log_file[0] = 0;
	g_silence = 0;
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	g_ioctl_dump = 0;
#endif
#ifdef INCLUDE_REMOTE_ONU
	g_remote[0] = 0;
#endif

	if (onu_args_parse(argc, argv) != 0)
		return -1;

	if (g_help == 1)
		return onu_usage(argv[0]);

#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0])
		remote_init(&g_remote[0], 2);
#endif

	if (g_version == 1)
		return onu_version();

	if (g_daemon == 1)
		return onu_daemon();

#ifdef ONU_SCE_TABLES_WRAPPERS
	if (onu_sce_wrappers(argc, argv))
		return 0;
#endif

#ifdef INCLUDE_CLI_SUPPORT
	return onu_cli(argc, argv);
#else
	return onu_cfg(argc, argv);
#endif

}

#endif				/* LINUX */
