/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

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

#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <linux/sockios.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>

#include "gexdump.h"

const char dummy[] = "1";
/** what string support */
const char ex_dump_whatversion[] = EX_DUMP_WHAT_STR;

int g_socket = -1;

unsigned char g_buf[2048];
char g_log_file[256] = {0};

unsigned int g_run = 1;
unsigned int g_time_stamp = 0;
unsigned int g_ex_gpix = 0;
unsigned int g_ex_lpix = 0;
unsigned int g_ex_mask = 0;
unsigned int g_verbose = 0;
unsigned int g_help = 0;
unsigned int g_ver = 0;
unsigned int g_timeout = 0;
unsigned int g_count = 0;
enum ex_direction g_ex_dir = EX_DIR_UPSTREAM;
enum ex_action g_ex_act = EX_ACTION_PASS;
enum ex_format g_ex_format = EX_FORMAT_HDR;
struct gpe_capability g_capability;

static inline char *basename(char *s)
{
	return s;
}

/** Print help */
static void help_print(char const *name)
{
	printf("%s V" EX_DUMP_VERSION " (compiled on "
	       __DATE__ " " __TIME__ ")\n", name);

	printf(	"Usage: %s [options]"
		"\n\n"
		"Options:\n"
		"\t-m, --mask <VAL>        VAL used as an exception mask, mandatory option\n"
		"\t-g, --gpix <GPIX>       sets GEM port index to GPIX (default 0)\n"
		"\t-l, --lpix <LPIX>       sets LAN port index to LPIX (default 0)\n"
		"\t-d, --dir <DIR>         specifies excpetion direction by DIR:\n"
		"\t                           0 - UPSTREAM\n"
		"\t                           1 - DOWNSTREAM\n"
		"\t-a, --action <ACTION>   sets ACTION to be performed on an excpetion packets\n"
		"\t                           0 - passthrough (default)\n"
		"\t                           1 - drop\n"
		"\t-t, --timestamp         include timestamp\n"
		"\t-o, --option <FORMAT>   set dump option to specified FORMAT\n"
		"\t                           0 - exception header (default)\n"
		"\t                           1 - eth packet info\n"
		"\t                           2 - packet hex dump\n"
		"\t-f, --file <FILE>       log packet dump to a FILE\n"
		"\t-T, --timeout <VAL>     sets timeout in seconds for capturing\n"
		"\t-C, --count <VAL>       sets the number of packets for capturing \n",
		name);
	printf("\n"
		"\t-e, --verbose           Verbose mode\n"
		"\t-h, --help              Print help (this message)\n"
		"\t-v, --version           Print version information\n");
}

/** Parse command line arguments

   \param[in] argc Arguments count
   \param[in] argv Array of arguments
*/
static int arg_parse(int argc, char *argv[])
{
	int c;
	int option;

	static struct option opt_str[] = {
		{ "help", no_argument, 0, 'h' },
		{ "verbose", no_argument, 0, 'e' },
		{ "version", no_argument, 0, 'v' },
		{ "mask", required_argument, 0, 'm' },
		{ "gpix", required_argument, 0, 'g' },
		{ "lpix", required_argument, 0, 'l' },
		{ "dir", required_argument, 0, 'd' },
		{ "action", required_argument, 0, 'a' },
		{ "timestamp", no_argument, 0, 't' },
		{ "option", required_argument, 0, 'o' },
		{ "file", required_argument, 0, 'f' },
		{ "timeout", required_argument, 0, 'T' },
		{ "count", required_argument, 0, 'C' },
		{ NULL, no_argument, 0, 'n' }
	};

	static const char long_opts[] = "hvm:g:l:d:a:to:f:T:C:e";

	do {
		c = getopt_long(argc, argv, long_opts, opt_str, &option);

		if (c == -1)
			return 0;

		switch (c) {
		case 'h':
			g_help = 1;
			return 0;
		case 'v':
			g_ver = 1;
			return 0;
		case 'm':
			g_ex_mask = (unsigned int)atoi(optarg);
			break;
		case 'g':
			g_ex_gpix = (unsigned int)atoi(optarg);
			if (g_ex_gpix >= g_capability.max_gpix)
				return 1;
			break;
		case 'l':
			g_ex_lpix = (unsigned int)atoi(optarg);
			if (g_ex_lpix >= g_capability.max_eth_uni) {
				printf("wrong LAN port index %u, max is %u\n",
						g_ex_lpix,
						g_capability.max_eth_uni - 1);
				return 1;
			}
			break;
		case 'd':
			g_ex_dir = (enum ex_direction)atoi(optarg);
			if (g_ex_dir >= EX_DIR_LAST)
				return 1;
			break;
		case 'a':
			g_ex_act = (enum ex_action)atoi(optarg);
			if (g_ex_act >= EX_ACTION_LAST)
				return 1;
			break;
		case 't':
			g_time_stamp = 1;
			break;
		case 'o':
			g_ex_format = (enum ex_format)atoi(optarg);
			if (g_ex_format >= EX_FORMAT_LAST)
				return 1;
			break;
		case 'f':
			if (optarg && (strlen(optarg) <
					(EX_DUMP_LOG_FILE_MAX_PATH - 1))) {
				strcpy(g_log_file, optarg);
			} else {
				printf("missig log file name\n");
				return 1;
			}
			break;
		case 'T':
			g_timeout = (unsigned int)atoi(optarg);
			break;
		case 'C':
			g_count = (unsigned int)atoi(optarg);
			break;
		case 'e':
			g_verbose = 1;
			return 0;
		default:
			return 1;
		}
	} while (1);

	return 0;
}

/** Termination handler

   \param[in] sig Signal
*/
static void termination_handler(int sig)
{
	/* ignore the signal, we'll handle by ourself */
	signal (sig, SIG_IGN);

	g_run = 0;
}

static int iocmd(const int fd,  const unsigned int cmd,  void *data,
		 const unsigned int size)
{
	struct fio_exchange ex;
	int err;

	ex.p_data = data;
	ex.length = size;
	ex.error = 0;

	if((err = ioctl(fd, cmd, (long)&ex)) != 0)
		return -1;

	if (ex.error == 0)
		return 0;

	return ex.error;
}

static int ex_socket_open(const char *if_name, struct sockaddr_ll *sll)
{
	int s;
	struct ifreq ifr;

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(s < 0)
		return s;

	bzero(&ifr, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "[%s] ioctl SIOCGIFFLAGS failed\n", if_name);
		goto on_error;
	}

	if (!((ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING))) {
		fprintf(stderr, "[%s] the device is not up\n", if_name);
		goto on_error;
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "[%s] ioctl SIOCGIFFLAGS failed\n", if_name);
		goto on_error;
	}

	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
		fprintf(stderr, "[%s] ioctl SIOCGIFINDEX failed\n", if_name);
		goto on_error;
	}

	memset(sll, 0xff, sizeof(*sll));
	sll->sll_family = AF_PACKET;
	sll->sll_protocol = htons(ETH_P_ALL);
	sll->sll_ifindex = ifr.ifr_ifindex;
	sll->sll_hatype = 1;
	sll->sll_halen = ETH_ALEN;
	if (bind(s, (struct sockaddr*)sll,sizeof(*sll)) < 0) {
		fprintf(stderr, "[%s] bind error\n", if_name);
		goto on_error;
	}

	return s;
on_error:
	close(s);
	return -1;
}

static void ex_socket_close(const int s)
{
	struct ifreq ifr;

	if (s >= 0) {
		ioctl(s, SIOCGIFFLAGS, &ifr);
		ifr.ifr_flags &= ~IFF_PROMISC;
		ioctl(s, SIOCSIFFLAGS, &ifr);
	
		close(s);
	}
}

static int ex_cfg_set(const unsigned int gpix,
		      const unsigned int lpix,
		      const unsigned int mask,
		      enum ex_direction dir,
		      enum ex_action act)
{
	struct gpe_lan_exception_cfg lan_cfg;
	struct gpe_ani_exception_cfg ani_cfg;
	struct gpe_exception_queue_cfg queue_cfg;
	struct gpe_exception_profile_cfg profile[2];
	unsigned int i;
	int fd, ret = 0;

	/* Open onu device*/
	fd = open(ONU_DEVICE_PATH, O_RDWR, 0644);
	if (fd < 0) {
		fprintf(stderr, "can't open device " ONU_DEVICE_PATH "\n");
		return -1;
	}

	memset(&lan_cfg, 0x0, sizeof(lan_cfg));
	memset(&ani_cfg, 0x0, sizeof(ani_cfg));
	memset(profile, 0x0, sizeof(profile));

	if (dir == EX_DIR_UPSTREAM) {
		profile[0].exception_profile = 0;
		profile[0].ingress_exception_mask =
					act == EX_ACTION_DROP ? mask : 0;
		profile[0].egress_exception_mask = 0;

		profile[1].exception_profile = 0;
		profile[1].ingress_exception_mask = 0x0;
		profile[1].egress_exception_mask = mask;
	} else {
		profile[0].exception_profile = 0;
		profile[0].ingress_exception_mask = 0x0;
		profile[0].egress_exception_mask = mask;

		profile[1].exception_profile = 0;
		profile[1].ingress_exception_mask =
					act == EX_ACTION_DROP ? mask : 0;
		profile[1].egress_exception_mask = 0;
	}


	for (i = 0; i < sizeof(profile)/sizeof(profile[0]); i++) {
		if (iocmd(fd, FIO_GPE_EXCEPTION_PROFILE_CFG_SET, &profile[i],
			  sizeof(profile[i])) != 0) {
			ret = -1;
		}

	}

	lan_cfg.lan_port_index = (uint8_t)lpix;
	ani_cfg.gem_port_index = (uint8_t)gpix;

	lan_cfg.exception_profile = 0;
	ani_cfg.ds_exception_profile = 1;
	ani_cfg.us_exception_profile = 1;

	if (iocmd(fd, FIO_GPE_LAN_EXCEPTION_CFG_SET, &lan_cfg,
		  sizeof(lan_cfg)) != 0) {
		ret = -1;
	}

	if (iocmd(fd, FIO_GPE_ANI_EXCEPTION_CFG_SET, &ani_cfg,
		  sizeof(ani_cfg)) != 0) {
		ret = -1;
	}

	for (i = 0; i < 32; i++) {
		if (ret != 0)
			break;

		if (!(mask & (1 << i)))
			continue;
		
		queue_cfg.exception_index = i;
		queue_cfg.exception_queue = EX_DUMP_EXCEPTION_QID;

		if (iocmd(fd, FIO_GPE_EXCEPTION_QUEUE_CFG_SET, &queue_cfg,
			  sizeof(queue_cfg)) != 0) {
			ret = -1;
		}
	}

	if (fd >= 0)
		close(fd);

	return ret;
}

static void ex_time_stamp(FILE * file, struct tm *tm)
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

static int ex_packet_filter(const unsigned char *pkt,
			    const unsigned int gpix,
			    const unsigned int lpix,
			    enum ex_direction dir)
{
	union u_onu_exception_pkt_hdr *hdr =
		(union u_onu_exception_pkt_hdr *)pkt;

	if (dir == EX_DIR_UPSTREAM) {
		if (hdr->ext.ex_side == hdr->ext.ex_dir) {
			if (hdr->ext.lan_port_idx != lpix)
				/* filter packet*/
				return 1;
		} else {
			/* filter packet*/
			return 1;
		}
	} else {
		if (hdr->ext.ex_dir == !hdr->ext.ex_side) {
			if (hdr->ext.gpix != gpix)
				/* filter packet*/
				return 1;
		} else {
			/* filter packet*/
			return 1;
		}
	}
	
	return 0;
}

static void ex_packet_hdr_dump(FILE *out, const unsigned char *pkt, int len)
{
	int c = 0;
	char misc[128];
	union u_onu_exception_pkt_hdr *hdr =
		(union u_onu_exception_pkt_hdr *)pkt;

	/* only valid for WAN ingress or LAN egress*/
	if (hdr->ext.ex_dir == !hdr->ext.ex_side)
		c = sprintf(&misc[c], "GPIX(0x%02X)", hdr->ext.gpix);
	/* only valid for WAN egress or LAN ingress*/
	if (hdr->ext.ex_dir == hdr->ext.ex_side)
		c = sprintf(&misc[c], "LAN(0x%1X), FID(0x%02X)",
					hdr->ext.lan_port_idx, hdr->ext.fid);

	/* only valid for WAN/LAN egress*/
	if (!hdr->ext.ex_dir)
		c = sprintf(&misc[c], ", QID(0x%02X)", hdr->byte.egress_qid);
	if (hdr->ext.ext_bytes)
		c = sprintf(&misc[c], ", EXT[0x%02X 0x%02X 0x%02X 0x%02X]",
					hdr->raw.e[0], hdr->raw.e[1],
					hdr->raw.e[2], hdr->raw.e[3]);

	fprintf(out, "[%s] exception (%02u) from %s %s, %s, pkt_len=%d\n",
				EX_DUMP_EXCEPTION_IF_NAME,
				hdr->ext.ex_idx,
				hdr->ext.ex_dir ? "ingress" : "egress",
				hdr->ext.ex_side ? "LAN" : "WAN",
				misc, len);
}

static void ex_packet_info_dump(FILE *out, const unsigned char *pkt, int len)
{
	(void)out;
	(void)pkt;
}

static void ex_packet_hex_dump(FILE *out, const unsigned char *pkt, int len)
{
	int i = 0, bytes = len, stamp = 0;
	char line[EX_DUMP_HEX_CHARS_PER_LINE], *s;

	s = line;
	while (--bytes >= 0) {
		snprintf(s, EX_DUMP_HEX_CHARS_PER_BYTE + 1, " %02X", *pkt++);
		s += EX_DUMP_HEX_CHARS_PER_BYTE;
		i++;
		if (i >= EX_DUMP_HEX_BYTES_PER_LINE) {
			fprintf(out, "\t0x%04X: %s\n", stamp, line);
			i = 0;
			s = line;
			stamp += EX_DUMP_HEX_BYTES_PER_LINE;
		}
	}
	if (i) {
		*s = '\0';
		fprintf(out, "\t0x%04X: %s\n", stamp, line);
	}
}

static int capability_get(void)
{
	int fd, ret = 0;

	fd = open(ONU_DEVICE_PATH, O_RDWR, 0644);
	if (fd < 0) {
		fprintf(stderr, "can't open device " ONU_DEVICE_PATH "\n");
		return -1;
	}

	if (iocmd(fd, FIO_GPE_CAPABILITY_GET, &g_capability,
		  sizeof(g_capability)) != 0) {
		ret = -1;
	}

	if (fd >= 0)
		close(fd);

	return ret;
}

/** Entry point

   \param[in] argc Arguments count
   \param[in] argv Array of arguments
*/
int main(int argc, char *argv[])
{
	int sretval, len;
	fd_set rfds;
	struct timeval tv, stv, ctv;
	struct sockaddr_ll sll;
	unsigned int pkt_count = 0, t_diff;
	union u_onu_exception_pkt_hdr *hdr =
		(union u_onu_exception_pkt_hdr *)g_buf;
	FILE *log = stdout;

	signal(SIGINT, termination_handler);
	signal(SIGTERM, termination_handler);

	if (capability_get() < 0) {
		fprintf(stderr, "Can't get device capability!\n");
		goto on_exit;
	}

	if (arg_parse(argc, argv) != 0) {
		help_print((char *)basename(argv[0]));
		return 1;
	}

	if (g_help) {
		help_print((char *)basename(argv[0]));
		return 0;
	}

	if (g_ver) {
		printf("%s\n", ex_dump_whatversion);
		return 0;
	}

	if (g_ex_mask == 0) {
		help_print((char *)basename(argv[0]));
		return 1;
	}
	/* Open log file if specified*/
	if (g_log_file[0] != 0) {
		log = fopen(g_log_file, "w");
		if (!log) {
			fprintf(stderr, "can't open log file %s\n", g_log_file);
			return 1;
		}
	}

	if (g_timeout && g_count) {
		fprintf(stderr, "-C option ignored\n");
		g_count = 0;
	}

	/* Open RAW socket for exception packets */
	g_socket = ex_socket_open(EX_DUMP_EXCEPTION_IF_NAME, &sll);
	if (g_socket < 0) {
		fprintf(stderr, "socket open failed!\n");
		goto on_exit;
	}
	/* Configure exceptions. Note that the flat egress path should be
	   created beforehand (currently created by the OMCI API) */
	if (ex_cfg_set(g_ex_gpix, g_ex_lpix, g_ex_mask, g_ex_dir, g_ex_act) < 0) {
		fprintf(stderr, "%s exception config failed!\n",
				g_ex_dir == EX_DIR_UPSTREAM ? "US" : "DS");
		goto on_exit;
	}

	gettimeofday(&stv, 0);

	while (g_run) {
		FD_ZERO(&rfds);
		FD_SET(g_socket, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		sretval = select(g_socket + 1, &rfds, NULL, NULL, &tv);

		gettimeofday(&ctv, 0);
		t_diff = ctv.tv_sec - stv.tv_sec +
				(ctv.tv_usec - stv.tv_usec)/1000000;

		if (g_timeout && t_diff >= g_timeout)
			break;

		if (sretval <= 0)
			continue;

		/* Receive exception packet*/
		len = recvfrom(g_socket, g_buf, sizeof(g_buf), 0, NULL, NULL);
		if (len <= 0)
			continue;

		/* Ignore exception packets which are not targeted to
		   this instance of application */
		if (ex_packet_filter(g_buf, g_ex_gpix, g_ex_lpix, g_ex_dir)) {
			if(g_verbose) {
				fprintf(log, "[%s] ignore packet\n", EX_DUMP_EXCEPTION_IF_NAME);
				goto DUMP_PACKET;
			}
			continue;
		}

		if ((unsigned int)len < sizeof(*hdr)) {
			fprintf(stderr, "[%s] wrong packet size %d!\n",
				g_ex_dir == EX_DIR_UPSTREAM ? "US" : "DS", len);
				continue;
		}

		/* Passthrough only egress exception packet if specified*/
		if (g_ex_act == EX_ACTION_PASS && hdr->ext.ex_dir == 0) {
			len = sendto(g_socket, g_buf, len, 0,
					(struct sockaddr *)&sll, sizeof(sll));
			if (len <= 0)
				fprintf(stderr, "[%s] packet pass failed!\n",
						 g_ex_dir == EX_DIR_UPSTREAM ?
							"us" : "ds");
		}

DUMP_PACKET:
		/* Dump packet */
		if(g_time_stamp) {
			time_t itime = time(0);
			ex_time_stamp(log, localtime(&itime));
		}

		ex_packet_hdr_dump(log, g_buf, len);
		if (g_ex_format >= EX_FORMAT_INFO)
			ex_packet_info_dump(log, g_buf, len);
		if (g_ex_format >= EX_FORMAT_HEX)
			ex_packet_hex_dump(log, g_buf, len);

		pkt_count++;
		if (g_count && pkt_count >= g_count)
			break;
	}

on_exit:
	if (ex_cfg_set(g_ex_gpix, g_ex_lpix, 0, g_ex_dir, g_ex_act) < 0)
		fprintf(stderr,
			"%s exception config clear failed, GPIX=%u, LPIX=%u!\n",
			g_ex_dir == EX_DIR_UPSTREAM ? "US" : "DS",
			g_ex_gpix, g_ex_lpix);

	if (g_log_file[0] != 0)
		fclose(log);

	ex_socket_close(g_socket);

	fprintf(stdout, "\npkt_count=%u\n", pkt_count);

	return 0;
}
