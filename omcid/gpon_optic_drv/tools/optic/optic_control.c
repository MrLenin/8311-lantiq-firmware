#ifdef HAVE_CONFIG_H
#include "drv_optic_config.h"
#endif
#include "drv_optic_std_defs.h"
#ifdef WIN32
#define OPTIC_SIMULATION
#include "drv_optic_devio.h"
#undef OPTIC_SIMULATION
#include <winsock2.h>
#endif
#include "optic_control.h"
#include "ifxos_std_defs.h"

#ifdef LINUX
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <linux/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
#  include <stdint.h>
#  include <stdbool.h>
#endif
#endif /* LINUX */

#include <string.h>
#include <math.h>

#ifdef WIN32
#include "ifx_getopt.h"
#endif

#include "drv_optic_std_defs.h"
#include "drv_optic_interface.h"
#include "drv_optic_event_interface.h"
#include "drv_optic_goi_interface.h"
#include "drv_optic_fcsi_interface.h"
#include "drv_optic_mm_interface.h"
#include "drv_optic_mpd_interface.h"
#include "drv_optic_omu_interface.h"
#include "drv_optic_bosa_interface.h"
#include "drv_optic_dcdc_apd_interface.h"
#include "drv_optic_dcdc_core_interface.h"
#include "drv_optic_dcdc_ddr_interface.h"

#ifdef INCLUDE_REMOTE_ONU
#include "optic_control_rpc.h"
#endif

/** version string */
#define CTRL_WHAT_STR "@(#)GPON Optic Control, version " OPTIC_VER_STR " " OPTIC_COPYRIGHT

union table_ref {
	void *p;
	struct table_factor *f;
	struct table_laserref *lr;
	struct table_temptrans *tt;
	struct table_ibiasimod *bm;
};

/** what string support */
const char ctrl_whatversion[] = CTRL_WHAT_STR;

static char buf[4096];

static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{"daemon", 0, 0, 'd'},
#ifdef INCLUDE_REMOTE_ONU
	{"remote", 1, 0, 'r'},
#endif
	{NULL, 0, 0, 0}
};

/* 1 colon means there is a required parameter */
/* 2 colons means there is an optional parameter */
static const char getopt_long_optstring[] = "hvd"
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
#ifdef INCLUDE_REMOTE_ONU
	"remote"
#endif
};

static int g_help;
static int g_version;
static int g_daemon;
#ifdef INCLUDE_REMOTE_ONU
#ifndef MAX_PATH
#define MAX_PATH 256
#endif
char g_remote[MAX_PATH];
#endif

#ifdef WIN32
int round(float f)
{
	return (int)(f + 0.5);
}
#endif

/**
   Parse all arguments and enable requested features.

   \param argc number of parameters
   \param argv array of parameter strings

   \return
   - 0 if all parameters decoded
   - -1 if not all parameters could be decoded
*/
static int optic_args_parse ( char argc, char *argv[] )
{
	int option_index = 0;

	if (argc == 1)
		return 0;

	/* no optional parameter */
	if ((argc > 1) && (argv[1][0] != '-'))
		return 0;

	while (1) {
		int c;

		/* 1 colon means there is a required parameter */
		/* 2 colons means there is an optional parameter */
		c = getopt_long(argc, argv, getopt_long_optstring, long_options,
				&option_index);
		if (c == -1 || c == 0)
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
#ifdef INCLUDE_REMOTE_ONU
		case 'r':
			if(optarg && (strlen(optarg)<(MAX_PATH-1))) {
				strcpy(g_remote, optarg);
			}
			break;
#endif
		default:
			fprintf(stderr,
				"Sorry, there is an unrecognized option\n");
			return -1;
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
static int optic_usage ( const char *p_name )
{
	struct option *ptr;
	char **desc = &description[0];
	uint32_t len = 0, fill_len = 0;
	static const char *fill = "             ";

	ptr = long_options;

	fprintf(stdout, "%s\n", &ctrl_whatversion[4]);
	fprintf(stdout, "usage: %s [options] | <cli command>\n", p_name);
	fprintf(stdout, "example: %s vg\n", p_name);

	while (ptr->name) {
		len = strlen(ptr->name);
		fill_len = strlen(fill);
		if (fill_len > 1)
			fill_len = (int)(fill_len - 1);
		if (len > fill_len)
			len = fill_len;
		fprintf(stdout, " --%s%s(-%c)\t- %s\n", ptr->name,
			&fill[len], ptr->val, *desc);
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
static int optic_version ( void )
{
	int fd, ret = -1;
	struct optic_versionstring data;
	struct optic_ext_status param;
	memset(&param, 0x00, sizeof(param));

#ifdef OPTIC_SIMULATION
	fprintf(stderr, "OPTIC_SIMULATION");
	fprintf(stdout, "\nuse IFXOS_open for automatic switching between linux "
		"and simulation...\n");
	return ret;
#endif

	fd = optic_open(OPTIC_DEVICE_PATH);

	if (fd >= 0) {
		ret = optic_iocmd(fd, FIO_OPTIC_VERSION_GET, &data, sizeof(data));
		if (ret == 0)
			fprintf(stdout, "%s\n", data.version);
		ret = optic_iocmd (fd, FIO_GOI_EXT_STATUS_GET,
			&param, sizeof(struct optic_ext_status));
		if (ret == 0)
			printf("\bchip=%hu fuse_format=%u state_history=\"%u %u %u %u %u %u %u %u %u %u\" table_read=\"%u %u %u %u %u %u %u %u %u\" config_read=\"%u %u %u %u %u %u %u %u %u %u %u\" mode=%u rx_offset=%hd mod_max=%hu bias_max=%hu rx_enable=%u tx_enable=%u bias_current=%hu modulation_current=%hu meas_power_1490_rssi=%hu meas_power_1550_rssi=%hu meas_power_1550_rf=%hu meas_voltage_1490_rssi=%hu meas_current_1490_rssi=%hu meas_voltage_1550_rf=%hu meas_voltage_1550_rssi=%hu pll_lock_status=%u loss_of_signal=%u loss_of_lock=%u temp_alarm_yellow=%u temp_alarm_red=%u\n",
			ntohs(param.chip), param.fuse_format, param.state_history[0], param.state_history[1], param.state_history[2], param.state_history[3], param.state_history[4], param.state_history[5], param.state_history[6], param.state_history[7], param.state_history[8], param.state_history[9], param.table_read[0], param.table_read[1], param.table_read[2], param.table_read[3], param.table_read[4], param.table_read[5], param.table_read[6], param.table_read[7], param.table_read[8], param.config_read[0], param.config_read[1], param.config_read[2], param.config_read[3], param.config_read[4], param.config_read[5], param.config_read[6], param.config_read[7], param.config_read[8], param.config_read[9], param.config_read[10], param.mode, param.rx_offset, param.mod_max, param.bias_max, param.rx_enable, param.tx_enable, param.bias_current, param.modulation_current, param.meas_power_1490_rssi, param.meas_power_1550_rssi, param.meas_power_1550_rf, param.meas_voltage_1490_rssi, param.meas_current_1490_rssi, param.meas_voltage_1550_rf, param.meas_voltage_1550_rssi, param.pll_lock_status, param.loss_of_signal, param.loss_of_lock, param.temp_alarm_yellow, param.temp_alarm_red);

		optic_close(fd);
	} else {
		fprintf(stderr,
			"ERROR: can't open device " OPTIC_DEVICE_PATH ".\n");
	}

	return ret;
}

static int optic_daemon ( void )
{
	int fd, ret = -1;
	struct optic_fifo_data fifo_data;
	enum optic_activation fifo_mode;
#ifndef WIN32
	fd_set rfds;
	struct timeval tv;
#endif
	fd = optic_open(OPTIC_DEVICE_PATH);

	if (fd < 0) {
		fprintf(stderr, "ERROR: can't open device " OPTIC_DEVICE_PATH ".\n");
		return ret;
	}

	fifo_mode = OPTIC_ENABLE;

	ret = optic_iocmd (fd, FIO_OPTIC_EVENT_SET, &fifo_mode, sizeof(fifo_mode));
	if (ret != 0) {
		fprintf(stderr, "ERROR: can't enable event FIFO\n");
	}

	while(1) {
#ifdef INCLUDE_REMOTE_ONU
		if (g_remote[0]) {
			ret = remote_device_event_wait(fd, &fifo_data, sizeof(fifo_data));
		}
		else
#endif
#ifndef WIN32
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		ret = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (ret == -1) {
			fprintf(stderr, "ERROR: select error.\n");
			break;
		}
		if (ret == 0) {
			/* no data within timeout */
			continue;
		}
		if(FD_ISSET(fd, &rfds) == 0) {
			/* not for us */
			printf("*");
			continue;
		}
#endif
		ret = optic_iocmd (fd, FIO_OPTIC_EVENT_FIFO, &fifo_data,
			sizeof(fifo_data));
		if (ret == 0) {
			switch(fifo_data.header.id) {
			case OPTIC_FIFO_STATE_CHANGE:
				fprintf(stdout,
					"OPTIC_STATE_CHANGE: state = %d\n",
                       			(int)fifo_data.data.state);
				break;
			case OPTIC_FIFO_TABLE_REQUEST:
				fprintf(stdout,
					"OPTIC_FIFO_TABLE_REQUEST: table = %d\n",
					(int)fifo_data.data.table);
				break;
			case OPTIC_FIFO_ALARM:
				fprintf(stdout,
					"OPTIC_ALARM: alarm = %d\n",
                       			(int)fifo_data.data.alarm);
				break;
			case OPTIC_FIFO_TIMESTAMP:
				fprintf(stdout,
					"OPTIC_TIMESTAMP: time = %d\n",
                       			(unsigned int)fifo_data.data.time);
				break;
			default:
				break;
			}
		}
	}
	optic_close(fd);

	return ret;
}

static int read_tableval ( enum optic_tabletype type,
			   char *line,
			   uint16_t temp_min,
			   uint16_t temp_max,
			   union table_ref *p_dest,
			   uint16_t *temp_low,
			   uint16_t *temp_high )
{
	int ret;

	/* static uint16_t factor = 2 << OPTIC_TABLE_FLOAT2INT_SHIFT; */
	uint16_t temp, t;
	float read_f[4];

	if ((temp_low == NULL) || (temp_high == NULL))
		return -1;

	if ((temp_min == 0) || (temp_max == 0))
		return -1;

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		ret = sscanf(line, "%f;%f",&read_f[0], &read_f[1]);
		if (ret == EOF)
			return 0;

		if (ret != 2) {
			fprintf(stderr, "read problem in: %s (%d)\n",
					line, ret);
			return 0;
		}
		break;
	case OPTIC_TABLETYPE_LASERREF:
		ret = sscanf(line, "%f;%f;%f;%f",&read_f[0], &read_f[1],
			  			 &read_f[2], &read_f[3]);
		if (ret == EOF)
			return 0;

		if (ret != 4) {
			fprintf(stderr, "read problem in: %s (%d)\n",
					line, ret);
			return 0;
		}
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		ret = sscanf(line, "%f;%f",&read_f[0], &read_f[1]);
		if (ret == EOF)
			return 0;

		if (ret != 2) {
			fprintf(stderr, "read problem in: %s (%d)\n",
					line, ret);
			return 0;
		}
		break;
	default:
		return -1;
	}

	temp = (uint16_t) read_f[0];
	if ((temp < temp_min) || (temp > temp_max))
		return -1;

	if (temp < *temp_low)
		*temp_low = temp;
	if (temp > *temp_high)
		*temp_high = temp;

	t = temp - temp_min;

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		if ((read_f[1] <= FACTOR_MIN) || (read_f[1] >= FACTOR_MAX))
			read_f[1] = FACTOR_DEFAULT;

		p_dest->f[t].corr_factor = read_f[1];
		p_dest->f[t].quality = OPTIC_TABLEQUAL_STORE;
		p_dest->f[t].valid = true;
		break;
	case OPTIC_TABLETYPE_LASERREF:
		p_dest->lr[t].ith = read_f[1];
		p_dest->lr[t].se = read_f[2];
		p_dest->lr[t].age = (uint32_t) read_f[3];
		p_dest->lr[t].quality = OPTIC_TABLEQUAL_STORE;
		p_dest->lr[t].valid = true;
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		p_dest->tt[t].temp_corr = read_f[1];
		p_dest->tt[t].quality = OPTIC_TABLEQUAL_STORE;
		p_dest->tt[t].valid = true;
		break;
	default:
		return -1;
	}
	return 0;
}

static int write_tableval ( enum optic_tabletype type,
			    void *src,
			    uint16_t temp_min,
			    uint16_t temp_max,
			    uint16_t temp,
			    char *line )
{
	struct table_factor *f = (struct table_factor *) src;
	struct table_laserref *lr = (struct table_laserref *) src;
	struct table_temptrans *tt = (struct table_temptrans *) src;
	int ret;
	uint16_t t = temp - temp_min;

	if (src == NULL)
		return -1;

	if ((temp_min > temp) || (temp_max < temp))
		return -1;

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		if (f[t].valid == true)
			ret = sprintf (line, "%d;%.3f\n",
					temp, f[t].corr_factor);
		else
			ret = 0;
		break;
	case OPTIC_TABLETYPE_LASERREF:
		if (lr[t].valid == true)
			ret = sprintf (line, "%d;%.3f;%.3f;%d\n",
					temp, lr[t].ith, lr[t].se, lr[t].age);
		else
			ret = 0;
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		if (tt[t].valid == true)
			ret = sprintf (line, "%d;%d\n",
					temp, tt[t].temp_corr);
		else
			ret = 0;
		break;
	default:
		return -1;
	}

	return ret;
}

static int interpolate_table ( enum optic_tabletype type,
			       uint16_t temp_min,
			       uint16_t temp_max,
			       uint16_t temp_low,
			       uint16_t temp_high,
			       union table_ref *p_dest )
{
	uint16_t temp, next, last = temp_low;
	uint8_t i;
	float z;

	if (p_dest == NULL)
		return -1;

	if ((temp_low < temp_min) || (temp_high < temp_min) ||
	    (temp_high > temp_max))
		return -1;

	switch (type) {
	case OPTIC_TABLETYPE_LASERREF:
		for (temp=temp_low; temp<=temp_high; temp++) {
			if (p_dest->lr[temp - temp_min].valid == true) {
				last = temp;
				continue;
			}
			/* search for next defined value */
			next = temp;
			do {
				next++;
			} while ((next <= temp_max) &&
			         (p_dest->lr[next - temp_min].valid == false));

			if (next >= temp_max)
				break;

			/* interpolate lineary */
			z = p_dest->lr[next - temp_min].ith -
				p_dest->lr[last - temp_min].ith;
			z = z / (next - last);
			z = z * (temp - last);
			p_dest->lr[temp - temp_min].ith = z +
				p_dest->lr[last - temp_min].ith;

			z = p_dest->lr[next - temp_min].se -
				p_dest->lr[last - temp_min].se;
			z = z / (next - last);
			z = z * (temp - last);
			p_dest->lr[temp - temp_min].se = z +
				p_dest->lr[last - temp_min].se;

			p_dest->lr[temp - temp_min].age = 0;
			p_dest->lr[temp - temp_min].quality =
				OPTIC_TABLEQUAL_INTERP;
			p_dest->lr[temp - temp_min].valid = true;
		}
		break;
/* just from the past...*/
	case OPTIC_TABLETYPE_IBIASIMOD:
		for (temp=temp_low; temp<=temp_high; temp++) {
			if (p_dest->bm[temp - temp_min].valid == true) {
				last = temp;
				continue;
			}
			/* search for next defined value */
			next = temp;
			do {
				next++;
			} while ((next <= temp_max) &&
			         (p_dest->bm[next - temp_min].valid == false));

			if (next >= temp_max)
				break;

			/* interpolate lineary */
			for (i=0; i<3; i++) {
				z = p_dest->bm[next - temp_min].ibias[i] -
				    p_dest->bm[last - temp_min].ibias[i];
				z = z / (next - last);
				z = z * (temp - last);
				z = z + p_dest->bm[last - temp_min].ibias[i];
				p_dest->bm[temp - temp_min].ibias[i] =
							(uint16_t) (z + 0.5);

				z = p_dest->bm[next - temp_min].imod[i] -
				    p_dest->bm[last - temp_min].imod[i];
				z = z / (next - last);
				z = z * (temp - last);
				z = z + p_dest->bm[last - temp_min].imod[i];
				p_dest->bm[temp - temp_min].imod[i] =
							(uint16_t) (z + 0.5);
			}

			p_dest->bm[temp - temp_min].age = 0;
			p_dest->bm[temp - temp_min].quality =
				OPTIC_TABLEQUAL_INTERP;
			p_dest->bm[temp - temp_min].valid = true;
		}
		break;
	default:
		fprintf(stderr, "table type %d not supported\n", type);
		return -1;
	}
	return 0;
}

static int extrapolate_table_laserref ( uint16_t temp_min,
					uint16_t temp_max,
					struct table_laserref *lr,
					uint16_t temp_low,
					uint16_t temp_high,
					int16_t tc_ith_low,
					int16_t tc_ith_high,
					int16_t tc_se_low,
					int16_t tc_se_high )
{
	uint16_t temp;
	float ith, se;
	int16_t td;
	float z;

	if (lr == NULL)
		return -1;

	if ((temp_low == 0) || (temp_high == 0) ||
	    (tc_ith_low == 0) || (tc_ith_high == 0) ||
	    (tc_se_low == 0) || (tc_se_high == 0)) {
		fprintf(stderr, "extrapolation params not defined");
		return -1;
	}

	/* extrapolate lower band */
	ith = lr[temp_low - temp_min].ith;
	se = lr[temp_low - temp_min].se;
	for (temp=temp_min; temp < temp_low; temp ++) {
		td = (temp - temp_low);
		/* Ith(x) = Ith(temp_low)*e^((x-temp_low) / tc_ith_low) */
		z = td;
		z = z / tc_ith_low;
		lr[temp - temp_min].ith = ith * exp(z);

		/* SE(x) = SE(temp_low)*e^((x-temp_low) / tc_se_low) */
		z = td;
		z = z / tc_se_low;
		lr[temp - temp_min].se = se * exp(z);

		lr[temp - temp_min].age = 0;
		lr[temp - temp_min].quality = OPTIC_TABLEQUAL_EXTRAP;
		lr[temp - temp_min].valid = true;
	}

	/* extrapolate upper band */
	ith = lr[temp_high - temp_min].ith;
	se = lr[temp_high - temp_min].se;
	for (temp=temp_max; temp > temp_high; temp --) {
		td = (temp - temp_high);
		/* Ith(x) = Ith(temp_high)*e^((x-temp_high) / tc_ith_high) */
		z = td;
		z = z / tc_ith_high;
		lr[temp - temp_min].ith = ith * exp(z);

		/* SE(x) = SE(temp_high)*e^((x-temp_high) / tc_se_high) */
		z = td;
		z = z / tc_se_high;
		lr[temp - temp_min].se = se * exp(z);

		lr[temp - temp_min].age = 0;
		lr[temp - temp_min].quality = OPTIC_TABLEQUAL_EXTRAP;
		lr[temp - temp_min].valid = true;
	}

	return 0;
}

static int fill_table_factor ( uint16_t temp_min,
			       uint16_t temp_max,
			       struct table_factor *t_factor )
{
	uint16_t t;

	if (t_factor == NULL)
		return -1;

	for (t=0; t<=temp_max-temp_min; t++)
		if ((t_factor[t].valid == false) ||
		    (t_factor[t].corr_factor <= FACTOR_MIN) ||
		    (t_factor[t].corr_factor >= FACTOR_MAX)) {
			t_factor[t].corr_factor = FACTOR_DEFAULT;
			t_factor[t].quality = OPTIC_TABLEQUAL_FIXSET;
			t_factor[t].valid = true;
		}

	return 0;
}

static int fill_table_laserref ( uint16_t temp_min,
				 uint16_t temp_max,
				 struct table_laserref *lr,
				 uint16_t temp_low,
				 uint16_t temp_high,
				 int16_t tci_ith_low,
				 int16_t tci_ith_high,
				 int16_t tci_se_low,
				 int16_t tci_se_high,
				 uint8_t tcd_ith_low,
				 uint8_t tcd_ith_high,
				 uint8_t tcd_se_low,
				 uint8_t tcd_se_high )
{
	int16_t tc_ith_low, tc_ith_high;
	int16_t tc_se_low, tc_se_high;
	float i1, i2, z;
	int ret =0;
	union table_ref tref;

	if (lr == NULL)
		return -1;

	if ((temp_low == 0) || (temp_high == 0)) {
		fprintf(stderr, "interpolation params not defined");
		return -1;
	}
	tref.lr = lr;
	/* interpolate gaps between valid entries */
	ret = interpolate_table ( OPTIC_TABLETYPE_LASERREF, temp_min, temp_max,
	                          temp_low, temp_high, &tref);

	if ((tci_ith_low == 0) || (tci_ith_high == 0) ||
	    (tcd_ith_low == 0) || (tcd_ith_high == 0)) {
		fprintf(stderr, "extrapolation params for Ith not defined");
		return -1;
	}
	if ((tci_se_low == 0) || (tci_se_high == 0) ||
	    (tcd_se_low == 0) || (tcd_se_high == 0)) {
		fprintf(stderr, "extrapolation params for SE not defined");
		return -1;
	}

	/* Ith[temp_low + tcd_ith_low] defined? -> calculate tc_ith_low */
	if (((temp_low + tcd_ith_low) >= temp_min) &&
	    ((temp_low + tcd_ith_low) <= temp_max) &&
	    (lr[temp_low + tcd_ith_low - temp_min].valid == true)) {
		i1 = lr[temp_low + tcd_ith_low - temp_min].ith;
		i2 = lr[temp_low - temp_min].ith;
		z = tcd_ith_low / log ( i1 / i2 );
		if (z > TCD_MAX)
			z = TCD_MAX;
		if (z < TCD_MIN)
			z = TCD_MIN;
		tc_ith_low = (int16_t) round(z);

	} else {
		tc_ith_low = tci_ith_low;
	}

	/* Ith[temp_high - tcd_ith_high] defined? -> calculate tc_ith_high */
	if (((temp_high - tcd_ith_high) >= temp_min) &&
	    ((temp_high - tcd_ith_high) <= temp_max) &&
            (lr[temp_high - tcd_ith_high - temp_min].valid == true)) {
		i1 = lr[temp_high - temp_min].ith;
		i2 = lr[temp_high - tcd_ith_high - temp_min].ith;
		z = tcd_ith_high / log ( i1 / i2 );
		if (z > TCD_MAX)
			z = TCD_MAX;
		if (z < TCD_MIN)
			z = TCD_MIN;
		tc_ith_high = (int16_t) round(z);
	} else {
		tc_ith_high = tci_ith_high;
	}

	/* SE[temp_low + tcd_se_low] defined? -> calculate tc_se_low */
	if (((temp_low + tcd_se_low) >= temp_min) &&
	    ((temp_low + tcd_se_low) <= temp_max) &&
	    (lr[temp_low + tcd_se_low - temp_min].valid == true)) {
		i1 = lr[temp_low + tcd_se_low - temp_min].se;
		i2 = lr[temp_low - temp_min].se;
		z = tcd_se_low / log ( i1 / i2 );
		if (z > TCD_MAX)
			z = TCD_MAX;
		if (z < TCD_MIN)
			z = TCD_MIN;
		tc_se_low = (int16_t) round(z);
	} else {
		tc_se_low = tci_se_low;
	}

	/* SE[temp_high - tcd_se_high] defined? -> calculate tc_se_high */
	if (((temp_high - tcd_se_high) >= temp_min) &&
	    ((temp_high - tcd_se_high) <= temp_max) &&
            (lr[temp_high - tcd_se_high - temp_min].valid == true)) {
		i1 = lr[temp_high - temp_min].se;
		i2 = lr[temp_high - tcd_se_high - temp_min].se;
		z = tcd_se_high / log ( i1 / i2 );
		if (z > TCD_MAX)
			z = TCD_MAX;
		if (z < TCD_MIN)
			z = TCD_MIN;
		tc_se_high = (int16_t) round(z);
	} else {
		tc_se_high = tci_se_high;
	}

	/* extrapolate gaps at borders */
	ret = extrapolate_table_laserref ( temp_min, temp_max, lr,
				           temp_low, temp_high,
				           tc_ith_low, tc_ith_high,
				           tc_se_low, tc_se_high );

	if (ret != 0)
		return ret;


	return ret;
}

static int fill_table_temptrans ( uint16_t temp_min,
			          uint16_t temp_max,
			          struct table_temptrans *temptrans )
{
	uint16_t t;

	if (temptrans == NULL)
		return -1;

	for (t=0; t<=temp_max-temp_min; t++)
		if (temptrans[t].valid == false){
			temptrans[t].temp_corr = t + temp_min;
			temptrans[t].quality = OPTIC_TABLEQUAL_FIXSET;
			temptrans[t].valid = true;
		}

	return 0;
}

static int read_table ( enum optic_tabletype type,
			char *table_name,
			uint16_t temp_min,
			uint16_t temp_max,
			union table_ref *p_dest,
			uint16_t *temp_low,
			uint16_t *temp_high )
{
	FILE *fp = NULL;
	char type_str[32], buf[128], line[128];
	char file_name[32+TABLE_NAME_LENGTH] = OPTIC_CONFIG_TABLE_PATH;
	uint32_t i;
	uint16_t t;
	bool type_known = false;
	int ret = 0;

	if ((temp_low == NULL) || (temp_high == NULL))
		return -1;

	*temp_low = temp_max;
	*temp_high = temp_min;

	strncat(file_name, table_name, TABLE_NAME_LENGTH);
	fp = fopen( file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "config table %s not found\n", file_name);
		return -1;
	}

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		p_dest->p = malloc (sizeof(struct table_factor) *
				 (temp_max - temp_min + 1 ));
		if (p_dest->p == NULL) {
			ret = -1;
			goto end_read_table;
		}
		for (t=0; t<=temp_max-temp_min; t++)
			p_dest->f[t].valid = false;

		switch (type) {
		case OPTIC_TABLETYPE_PTH:
			strncpy ( type_str, TYPE_PTH_CORR, sizeof(type_str));
			break;
		case OPTIC_TABLETYPE_MPDRESP:
			strncpy ( type_str, TYPE_MPD_RESP_CORR,
				  sizeof(type_str));
			break;
		case OPTIC_TABLETYPE_RSSI1490:
			strncpy ( type_str, TYPE_RSSI_1490_CORR,
			          sizeof(type_str));
			break;
		case OPTIC_TABLETYPE_RSSI1550:
			strncpy ( type_str, TYPE_RSSI_1550_CORR,
				  sizeof(type_str));
			break;
		case OPTIC_TABLETYPE_RF1550:
			strncpy ( type_str, TYPE_RF_1550_CORR,
				  sizeof(type_str));
			break;
		default:
			break;
		}
		break;
	case OPTIC_TABLETYPE_LASERREF:
		p_dest->p = malloc (sizeof(struct table_laserref) *
				 (temp_max - temp_min + 1 ));
		if (p_dest->p == NULL) {
			ret = -1;
			goto end_read_table;
		}
		for (t=0; t<=temp_max-temp_min; t++)
			p_dest->lr[t].valid = false;
		strncpy ( type_str, TYPE_LASER_REF, sizeof(type_str));
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		p_dest->p = malloc (sizeof(struct table_temptrans) *
				 (temp_max - temp_min + 1 ));
		if (p_dest->p == NULL) {
			ret = -1;
			goto end_read_table;
		}
		for (t=0; t<=temp_max-temp_min; t++)
			p_dest->tt[t].valid = false;
		strncpy ( type_str, TYPE_TEMP_TRANS, sizeof(type_str));
		break;
	default:
		fprintf(stderr, "table type %d not supported\n", type);
		ret = -1;
		goto end_read_table;
	}

	while ((ret == 0) && (fgets(buf, sizeof(buf), fp))) {
		i = strcspn(buf, COMMENT);
		if (i == 0)
			continue;

		if (i> (sizeof(line) -2)) {
			fprintf(stderr, "read line too long\n");
			ret = -1;
		} else {
			strncpy (line, buf, i);
 			line[i] = '\0';
		}

		/* doublecheck type */
		if ((ret == 0) && (type_known == false) &&
		    (strstr(line, TYPE))) {
			if (strstr(line, type_str)) {
				type_known = true;
				continue;
			} else {
				fprintf(stderr, "table type: %s expect: %s \n",
					line, type_str);
				ret = -1;
			}
		}
		/* read data */
		if (ret == 0)
			ret = read_tableval ( type, line, temp_min, temp_max,
					      p_dest, temp_low, temp_high );
/*
		fputs(line, stderr);
*/
	}

end_read_table:

	if (fp != NULL) {
		fflush (fp);
		fclose (fp);
	}
	return ret;
}

static int write_table ( enum optic_tabletype type,
			 char *table_name,
			 void *src,
			 uint16_t temp_min,
			 uint16_t temp_max,
			 uint16_t temp_low,
			 uint16_t temp_high )
{
	struct table_factor *f;
	struct table_laserref *lr;
	struct table_temptrans *tt;
	FILE *fp = NULL;
	FILE *fp_ = NULL;
	char type_str[32], buf[256], line[128];
	char table_name_[6+TABLE_NAME_LENGTH] = "temp_";
	char file_name[32+TABLE_NAME_LENGTH] = OPTIC_CONFIG_TABLE_PATH;
	char file_name_[32+6+TABLE_NAME_LENGTH] = OPTIC_CONFIG_TABLE_PATH;
	uint32_t i;
	uint16_t t;
	bool type_known = false;
	int ret = 0;

	strncat(table_name_, table_name, TABLE_NAME_LENGTH);
	strncat(file_name, table_name, TABLE_NAME_LENGTH);
	strncat(file_name_, table_name_, TABLE_NAME_LENGTH);

	rename( file_name , file_name_ );

	fp_ = fopen( file_name_, "r");
	fp = fopen( file_name, "w");

	if (fp_ == NULL) {
		fprintf(stderr, "config table %s not found\n", file_name_);
		ret = -1;
		goto end_write_table;
	}
	if (fp == NULL) {
		fprintf(stderr, "config table %s not found\n", file_name);
		ret = -1;
		goto end_write_table;
	}

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		f = (struct table_factor *) src;
		if (f == NULL) {
			ret = -1;
			goto end_write_table;
		}
		switch (type) {
		case OPTIC_TABLETYPE_PTH:
			strncpy ( type_str, TYPE_PTH_CORR, sizeof(type_str));
			break;
		case OPTIC_TABLETYPE_MPDRESP:
			strncpy ( type_str, TYPE_MPD_RESP_CORR,
				  sizeof(type_str));
			break;
		case OPTIC_TABLETYPE_RSSI1490:
			strncpy ( type_str, TYPE_RSSI_1490_CORR,
			          sizeof(type_str));
			break;
		case OPTIC_TABLETYPE_RSSI1550:
			strncpy ( type_str, TYPE_RSSI_1550_CORR,
				  sizeof(type_str));
			break;
		case OPTIC_TABLETYPE_RF1550:
			strncpy ( type_str, TYPE_RF_1550_CORR,
				  sizeof(type_str));
			break;
		default:
			break;
		}
		break;
	case OPTIC_TABLETYPE_LASERREF:
		lr = (struct table_laserref *) src;
		if (lr == NULL) {
			ret = -1;
			goto end_write_table;
		}
		strncpy ( type_str, TYPE_LASER_REF, sizeof(type_str));
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		tt = (struct table_temptrans *) src;
		if (tt == NULL) {
			ret = -1;
			goto end_write_table;
		}
		strncpy ( type_str, TYPE_TEMP_TRANS, sizeof(type_str));
		break;
	default:
		fprintf(stderr, "table type %d not supported\n", type);
		ret = -1;
		goto end_write_table;
	}

	while ((ret == 0) && (fgets(buf, sizeof(buf), fp_))) {
		i = strcspn(buf, COMMENT);
		if (i == 0) {
			fputs(buf, fp);
			continue;
		}

		if (i> (sizeof(line) -2)) {
			fprintf(stderr, "read line too long\n");
			ret = -1;
		} else {
			strncpy (line, buf, i);
 			line[i] = '\0';
		}

		/* doublecheck type */
		if ((ret == 0) && (type_known == false) &&
		    (strstr(line, TYPE))) {
			if (strstr(line, type_str)) {
				fputs(buf, fp);
				type_known = true;
				continue;
			} else {
				fprintf(stderr, "table type: %s expect: %s \n",
					line, type_str);
				ret = -1;
			}
		}
		/* read data -> break;*/
		if (ret == 0)
			fseek ( fp_, 0, SEEK_END);
	}

	/* write data */
	for (t=temp_low; t<=temp_high; t++) {
		if (write_tableval ( type, src, temp_min, temp_max, t,
				     line ) > 0)
			fputs ( line, fp );
	}

end_write_table:

	if (fp_ != NULL) {
		fflush (fp_);
		fclose (fp_);
		remove (file_name_);
	}
	if (fp != NULL) {
		fflush (fp);
		fclose (fp);
	}
	return ret;
}

static int update_table ( enum optic_tabletype type,
			  void *table_base,
			  void *table,
			  uint16_t temp_min,
			  uint16_t temp_max )
{
	struct table_laserref *lr_new = (struct table_laserref *) table;
	struct table_laserref *lr_base = (struct table_laserref *) table_base;
	uint16_t t;

	if (table == NULL)
		return -1;

	/* first transfer: transfer all (valid) entries */
	if (table_base == NULL)
		return 0;

	/* only update: search differences */
	switch (type) {
	case OPTIC_TABLETYPE_LASERREF:
		for (t=0; t <= temp_max-temp_min ; t ++) {
			if (lr_new[t].valid == false)
				continue;

			if (lr_new[t].quality == OPTIC_TABLEQUAL_MEAS)
				lr_new[t].quality = OPTIC_TABLEQUAL_STORE;

			if (lr_base[t].valid == true)
				continue;


			lr_base[t].ith = lr_new[t].ith;
			lr_base[t].se = lr_new[t].se;
			lr_base[t].age = lr_new[t].age;
			lr_base[t].quality = lr_new[t].quality;

			lr_base[t].valid = true;
			}
		break;
	default:
		fprintf(stderr, "table type %d not supported\n", type);
		return -1;
	}
	return 0;
}

static int update_table_transfer ( enum optic_tabletype type,
				   void *table_new,
				   void *table_old,
				   uint16_t temp_min,
				   uint16_t temp_max )
{
	struct table_ibiasimod *bm_n =(struct table_ibiasimod *) table_new;
	struct table_ibiasimod *bm_o = (struct table_ibiasimod *) table_old;
	struct table_laserref *lr_n = (struct table_laserref *) table_new;
	struct table_laserref *lr_o = (struct table_laserref *) table_old;
	uint16_t t;
	uint8_t i;
	bool update;

	if (table_new == NULL)
		return -1;

	/* first transfer: transfer all (valid) entries */
	if (table_old == NULL)
		return 0;

	/* only update: search differences */
	switch (type) {
	case OPTIC_TABLETYPE_LASERREF:
		for (t=0; t <= temp_max-temp_min ; t ++) {
			if (lr_n[t].valid == false)
				continue;
			/* no difference -> no transfer */
			update = false;
			if (round(lr_n[t].ith * INTFACTOR_ITH) !=
			    round(lr_o[t].ith * INTFACTOR_ITH)) {
				update = true;
				continue;
			}
			if (round(lr_n[t].se * INTFACTOR_SE) !=
			    round(lr_o[t].se * INTFACTOR_SE)) {
				update = true;
				continue;
			}
			if (update == false)
				lr_n[t].valid = false;
		}
		break;
	case OPTIC_TABLETYPE_IBIASIMOD:
		for (t=0; t <= temp_max-temp_min ; t ++) {
			if (bm_n[t].valid == false)
				continue;
			/* no difference -> no transfer */
			update = false;
			for (i=0; i<3; i++) {
				if (bm_n[t].ibias[i] != bm_o[t].ibias[i]) {
					update = true;
					continue;
				}
				if (bm_n[t].imod[i] != bm_o[t].imod[i]) {
					update = true;
					continue;
				}
			}

			if (update == false)
				bm_n[t].valid = false;
		}
		break;
	default:
		fprintf(stderr, "table type %d not supported\n", type);
		return -1;
	}
	return 0;
}


static int compress_table ( enum optic_tabletype type,
			    void *src_table,
			    uint16_t temp_min,
			    uint16_t temp_max,
			    void **p_transfer,
			    uint16_t *depth )
{
	struct table_factor *f= (struct table_factor *) src_table;
	struct table_laserref *lr= (struct table_laserref *) src_table;
	struct table_ibiasimod *bm= (struct table_ibiasimod *) src_table;
	struct table_vapd *v= (struct table_vapd *) src_table;
	struct table_temptrans *tt= (struct table_temptrans *) src_table;
	struct optic_tt_factor *trans_f;
	struct optic_tt_laserref *trans_lr;
	struct optic_tt_ibiasimod *trans_bm;
	struct optic_tt_vapd *trans_v;
	struct optic_tt_temptrans *trans_tt;
	uint16_t factor_corr = 1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR;
	uint16_t factor_ith = 1 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint16_t factor_se = 1 << OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY;
	uint16_t temp, t, i=0;
	uint8_t j;

	if ((src_table == NULL) || (depth == NULL))
		return -1;

	if (*p_transfer != NULL)
		free(*p_transfer);

	*depth = 0;

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		/* count temerature entries to transfer */
		for (temp=temp_min; temp<=temp_max; temp++)
			if (f[temp - temp_min].valid == true)
				(*depth) ++;

		*p_transfer = malloc ( sizeof(struct optic_tt_factor) *
		                      (*depth) );
		trans_f = (struct optic_tt_factor *) *p_transfer;
		if (trans_f == NULL)
			return -1;

		for (temp=temp_min; temp<=temp_max; temp++) {
			t = temp - temp_min;
			if (f[t].valid == false)
				continue;

			trans_f[i].temp = temp;
			trans_f[i].corr_factor = (uint16_t)
					round( f[t].corr_factor * factor_corr );
			trans_f[i].quality = f[t].quality;
			i++;
		}
		break;
	case OPTIC_TABLETYPE_LASERREF:
		/* count temerature entries to transfer */
		for (temp=temp_min; temp<=temp_max; temp++)
			if (lr[temp - temp_min].valid == true)
				(*depth) ++;

		*p_transfer = malloc ( sizeof(struct optic_tt_laserref) *
		                       (*depth) );
		trans_lr = (struct optic_tt_laserref *) *p_transfer;
		if (trans_lr == NULL)
			return -1;

		for (temp=temp_min; temp<=temp_max; temp++) {
			t = temp - temp_min;
			if (lr[t].valid == false)
				continue;

			trans_lr[i].temp = temp;
			trans_lr[i].ith = (uint16_t) round( lr[t].ith *
			                                    factor_ith );
			trans_lr[i].se = (uint16_t) round( lr[t].se *
			                                   factor_se );
			trans_lr[i].age = lr[t].age;
			trans_lr[i].quality = lr[t].quality;

			i++;
		}
		break;
	case OPTIC_TABLETYPE_IBIASIMOD:
		/* count temerature entries to transfer */
		for (temp=temp_min; temp<=temp_max; temp++)
			if (bm[temp - temp_min].valid == true)
				(*depth) ++;

		*p_transfer = malloc ( sizeof(struct optic_tt_ibiasimod) *
				       (*depth) );
		trans_bm = (struct optic_tt_ibiasimod *) *p_transfer;
		if (trans_bm == NULL)
			return -1;

		for (temp=temp_min; temp<=temp_max; temp++) {
			t = temp - temp_min;
			if (bm[t].valid == false)
				continue;

			trans_bm[i].temp = temp;
			for (j=0; j<3; j++) {
				trans_bm[i].ibias[j] = bm[t].ibias[j];
				trans_bm[i].imod[j] = bm[t].imod[j];
			}
			trans_bm[i].age = bm[t].age;
			trans_bm[i].quality = bm[t].quality;
			i++;
		}
		break;
	case OPTIC_TABLETYPE_VAPD:
		/* count temerature entries to transfer */
		for (temp=temp_min; temp<=temp_max; temp++)
			if (v[temp - temp_min].valid == true)
				(*depth) ++;

		*p_transfer = malloc ( sizeof(struct optic_tt_vapd) *
				       (*depth) );
		trans_v = (struct optic_tt_vapd *) *p_transfer;
		if (trans_v == NULL)
			return -1;

		for (temp=temp_min; temp<=temp_max; temp++) {
			t = temp - temp_min;
			if (v[t].valid == false)
				continue;

			trans_v[i].temp = temp;
			trans_v[i].vref = v[t].vref;
			trans_v[i].sat = v[t].sat;
			trans_v[i].quality = v[t].quality;
			i++;
		}
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		/* count temerature entries to transfer */
		for (temp=temp_min; temp<=temp_max; temp++)
			if (tt[temp - temp_min].valid == true)
				(*depth) ++;

		*p_transfer = malloc ( sizeof(struct optic_tt_temptrans) *
				       (*depth) );
		trans_tt = (struct optic_tt_temptrans *) *p_transfer;
		if (trans_tt == NULL)
			return -1;

		for (temp=temp_min; temp<=temp_max; temp++) {
			t = temp - temp_min;
			if (tt[t].valid == false)
				continue;

			trans_tt[i].temp = temp;
			trans_tt[i].temp_corr = tt[t].temp_corr;
			trans_tt[i].quality = tt[t].quality;;
			i++;
		}
		break;
	default:
		fprintf(stderr, "table type %d not supported\n", type);
		return -1;
	}

	return 0;
}

static int extract_table ( enum optic_tabletype type,
			   uint16_t tabledepth,
			   void *p_transfer,
			   uint16_t tabletemp_min,
			   uint16_t tabletemp_max,
			   void *dest_table,
			   uint16_t *valuetemp_min,
			   uint16_t *valuetemp_max )
{
	uint16_t i, temp;
	uint8_t pl;
	struct optic_tt_factor *p_factor = NULL;
	struct optic_tt_laserref *p_laserref = NULL;
	struct optic_tt_ibiasimod *p_ibiasimod = NULL;
	struct optic_tt_vapd *p_vapd = NULL;
	struct optic_tt_temptrans *p_temptrans = NULL;
	struct table_factor *factor= (struct table_factor *) dest_table;
	struct table_laserref *lr= (struct table_laserref *) dest_table;
	struct table_ibiasimod *bm= (struct table_ibiasimod *) dest_table;
	struct table_vapd *v= (struct table_vapd *) dest_table;
	struct table_temptrans *tt= (struct table_temptrans *) dest_table;
	uint16_t factor_corr = 1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR;
	uint16_t factor_ith = 1 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint16_t factor_se = 1 << OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY;
	float f;

	if ((p_transfer == NULL) || (dest_table == NULL))
		return -1;

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		p_factor = (struct optic_tt_factor *) p_transfer;
		break;
	case OPTIC_TABLETYPE_LASERREF:
		p_laserref = (struct optic_tt_laserref *) p_transfer;
		break;
	case OPTIC_TABLETYPE_IBIASIMOD:
		p_ibiasimod = (struct optic_tt_ibiasimod *) p_transfer;
		break;
	case OPTIC_TABLETYPE_VAPD:
		p_vapd = (struct optic_tt_vapd *) p_transfer;
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		p_temptrans = (struct optic_tt_temptrans *) p_transfer;
		break;
	default:
		fprintf(stderr, "table type %d not supported\n", type);
		return -1;
	}


	for (i=0; i<tabledepth; i++) {
		switch (type) {
		case OPTIC_TABLETYPE_PTH:
		case OPTIC_TABLETYPE_MPDRESP:
		case OPTIC_TABLETYPE_RSSI1490:
		case OPTIC_TABLETYPE_RSSI1550:
		case OPTIC_TABLETYPE_RF1550:
			temp = p_factor[i].temp;
			break;
		case OPTIC_TABLETYPE_LASERREF:
			temp = p_laserref[i].temp;
			break;
		case OPTIC_TABLETYPE_IBIASIMOD:
			temp = p_ibiasimod[i].temp;
			break;
		case OPTIC_TABLETYPE_VAPD:
			temp = p_vapd[i].temp;
			break;
		case OPTIC_TABLETYPE_TEMPTRANS:
			temp = p_temptrans[i].temp;
			break;
		default:
			fprintf(stderr, "table type %d not supported\n", type);
			return -1;
		}

		/* ignore all temp values outside the temperature table */
		if ((temp < tabletemp_min) || (temp > tabletemp_max))
			continue;

		/* note min/max defined temperature for upper/lower gap */
		if (temp < *valuetemp_min)
			*valuetemp_min = temp;
		if (temp > *valuetemp_max)
			*valuetemp_max = temp;

		temp -= tabletemp_min;
		/* set value and note quality */
		switch (type) {
		case OPTIC_TABLETYPE_PTH:
		case OPTIC_TABLETYPE_MPDRESP:
		case OPTIC_TABLETYPE_RSSI1490:
		case OPTIC_TABLETYPE_RSSI1550:
		case OPTIC_TABLETYPE_RF1550:
			f = p_factor[i].corr_factor;
			factor[temp].corr_factor = f / factor_corr;
			factor[temp].quality = p_factor[i].quality;
			factor[temp].valid = true;
			break;
		case OPTIC_TABLETYPE_LASERREF:
			f = p_laserref[i].ith;
			lr[temp].ith = f / factor_ith;
			f = p_laserref[i].se;
			lr[temp].se = f / factor_se;
			lr[temp].age = p_laserref[i].age;
			lr[temp].quality = p_laserref[i].quality;
			lr[temp].valid = true;
			break;
		case OPTIC_TABLETYPE_IBIASIMOD:
			for (pl=0; pl<3; pl++) {
				bm[temp].ibias[pl] = p_ibiasimod[i].ibias[pl];
				bm[temp].imod[pl] = p_ibiasimod[i].imod[pl];
			}
			bm[temp].age = p_ibiasimod[i].age;
			bm[temp].quality = p_ibiasimod[i].quality;
			bm[temp].valid = true;
			break;
		case OPTIC_TABLETYPE_VAPD:
			v[temp].vref = p_vapd[i].vref;
			v[temp].sat = p_vapd[i].sat;
			v[temp].quality = p_vapd[i].quality;;
			v[temp].valid = true;
			break;
		case OPTIC_TABLETYPE_TEMPTRANS:
			tt[temp].temp_corr = p_temptrans[i].temp_corr;
			tt[temp].quality = p_temptrans[i].quality;
			tt[temp].valid = true;
			break;
		default:
			fprintf(stderr, "table type %d not supported\n", type);
			return -1;
		}
	}

	return 0;
}

static int calc_table_ibiasimod ( uint16_t temp_min,
				  uint16_t temp_max,
				  float p0[3],
				  float p1[3],
				  float pth_ref,
				  float ibias_max,
				  float imod_max,
				  float ibiasimod_max,
				  struct table_factor *t_pth,
				  struct table_laserref *t_laserref,
				  struct table_ibiasimod **pt_biasmod )
{
	uint16_t factor_ibias = 1 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint16_t factor_imod = 1 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint16_t t;
	int ret =0;
	uint8_t i;
	float pth, ith, se, z1, z2;

	if ((t_pth == NULL) || (t_laserref == NULL))
		return -1;

	if ((temp_min == 0) || (temp_max == 0) || (temp_min >= temp_max))
		return -1;

	*pt_biasmod = malloc ( sizeof (struct table_ibiasimod) *
			       (temp_max - temp_min + 1) );
	if (*pt_biasmod == NULL)
		return -1;

	/* calculate directly */
	for (t=0; t<=temp_max-temp_min; t++) {
		if ((t_pth[t].valid == false) ||
		    (t_laserref[t].valid == false)) {
			(*pt_biasmod)[t].valid = false;
			continue;
		}

		pth = pth_ref * t_pth[t].corr_factor;
		ith = t_laserref[t].ith;
		se = t_laserref[t].se;
		(*pt_biasmod)[t].valid = true;

		for (i=0; i<3; i++) {
			if ((p0[i] <= pth) || (p1[i] <= p0[i])) {
				(*pt_biasmod)[t].valid = false;
				break;
			}

			/* ibias = ith + (p0-pth)/SE */
			z1 = ith + ((p0[i] - pth) / se);
			if (z1 > ibias_max)
				z1 = ibias_max;

			/* imod = (p1-p0)/SE */
			z2 = (p1[i] - p0[i]) / se;
			if (z2 > imod_max)
				z2 = imod_max;

			while (ibiasimod_max < (z1 + z2)) {
				z1 = z1 * 0.9;
				z2 = z2 * 0.9;
			}

			/* [ << OPTIC_FLOAT2INTSHIFT_CURRENT] */
			(*pt_biasmod)[t].ibias[i] =
					(uint16_t) round(z1 * factor_ibias);

			/* [ << OPTIC_FLOAT2INTSHIFT_CURRENT] */
			(*pt_biasmod)[t].imod[i] =
					(uint16_t) round(z2 * factor_imod);
		}

		if ((*pt_biasmod)[t].valid == true) {
			(*pt_biasmod)[t].age = t_laserref[t].age;
			(*pt_biasmod)[t].quality = t_laserref[t].quality;
		}
	}

	return ret;
}


/** duty cycle saturation min/max=
    = SQRT(2*nCurrentLimit[mA]*nTargetVoltage[V]/(nEta[%]/100*nExtL[uVs/A]*nSwitchingFrequency[1/s])) *nExtL[uVs/A]/nExtVoltage[V]*nSwitchingFrequency[1/s]*255
    = SQRT(2*nCurrentLimit[mA]*100.000*nTargetVoltage[V]/(nEta[%]*nExtL[mVs/A]*nSwitchingFrequency[1/s])) *nExtL[Vs/A]/nExtVoltage[V]*nSwitchingFrequency[1/s]*255 /1.000.000
    = SQRT(20*nCurrentLimit[mA]*nTargetVoltage[V]/(nEta[%]*nExtL[mVs/A]*nSwitchingFrequency[1/s])) *nExtL[Vs/A]/nExtVoltage[V]*nSwitchingFrequency[1/s]*255 /10.000
*/
static uint8_t calc_sat ( float vapd,
		          float curr_limit,
		          float ext_supply,
		          float efficiency,
		          float ext_inductivity,
		          float switching_frequency )
{
	double temp, n, z;

	z = 20 * curr_limit * vapd;
	n = efficiency * ext_inductivity * switching_frequency;

	temp = sqrt ( z / n );

	z = temp * ext_inductivity * switching_frequency * 255;
	n = ext_supply * 10000;

	return ((uint8_t) round ( z / n ));
}



static int calc_table_vapd ( uint16_t temp_min,
			     uint16_t temp_max,
			     float temp_ref,
			     float vapd_bd_ref,
			     float vapd_offset,
			     float vapd_scal_ref,
			     float vapd_min,
			     float vapd_max,
			     float vapd_curr_limit,
			     float vapd_ext_supply,
			     float vapd_efficiency,
			     float vapd_ext_inductivity,
			     float vapd_switching_frequency,
			     struct table_vapd ** p_vapd_tab )
{
	uint16_t factor_vref = 1 << OPTIC_FLOAT2INTSHIFT_VOLTAGE;
	float temp, z;
	uint16_t t;
	int ret = 0;

	if ((temp_min == 0) || (temp_max == 0) || (temp_min >= temp_max))
		return -1;

	*p_vapd_tab = malloc ( sizeof (struct table_vapd) *
	                       (temp_max - temp_min + 1) );
	if (*p_vapd_tab == NULL)
		return -1;

	/* calculate directly */
	for (t=0; t<=temp_max-temp_min; t++) {
		temp = t + temp_min - temp_ref;
		/* vapd = vapd_bd_ref + vapd_scal_ref * (temp - temp_ref)
		                   - vapd_offset                       */
		z = vapd_bd_ref + (vapd_scal_ref * temp) - vapd_offset;

		if (z < vapd_min)
			z = vapd_min;
		if (z > vapd_max)
			z = vapd_max;

		(*p_vapd_tab)[t].vref = (uint16_t) (round(z * factor_vref));
		(*p_vapd_tab)[t].sat = calc_sat ( z, vapd_curr_limit,
						  vapd_ext_supply,
						  vapd_efficiency,
						  vapd_ext_inductivity,
				 		  vapd_switching_frequency );
		(*p_vapd_tab)[t].quality = OPTIC_TABLEQUAL_CALC;
		(*p_vapd_tab)[t].valid = true;
	}

	return ret;
}

static void strtostr ( char *name, uint16_t bufsize,  char **p_str )
{
	uint8_t cnt = 0;
	char temp[32];

	if (*p_str == NULL)
		return;

	if (bufsize < 32)
		return;

	while ((*p_str != NULL) && ((*p_str)[cnt] == ' '))
		cnt ++;

	if ((cnt>0) && (sscanf(*p_str,"%32s", temp ) == 1)) {
		strncpy(name,temp, bufsize);
		*p_str =  (char *) ((ulong_t) *p_str + strlen(temp) + cnt);
	}
}

#ifndef INCLUDE_CLI_SUPPORT
static int optic_mode_set (char *p_next, int fd)
{
	int ret = 0;
	struct optic_mode mode;

	mode.mode = (int) strtod ( p_next, &p_next );

	ret = optic_iocmd(fd, FIO_OPTIC_MODE_SET, &mode, sizeof(mode));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_optic_mode_set ioctl access \n");
	}

	return ret;
}
#endif

static int config_goi ( char *p_next, int fd )
{
	int ret = 0;
	struct optic_goi_config cfg;

	cfg.temperature_check_time =    (uint16_t) strtod ( p_next, &p_next );
	cfg.temperature_thres_mpdcorr = (uint8_t)  strtod ( p_next, &p_next );

	cfg.update_laser_age =          (uint16_t) strtod ( p_next, &p_next );
	cfg.laser_age =                 (uint32_t) strtod ( p_next, &p_next );

	cfg.rx_polarity_regular =       (bool)     strtod ( p_next, &p_next );
	cfg.bias_polarity_regular =     (bool)     strtod ( p_next, &p_next );
	cfg.mod_polarity_regular =      (bool)     strtod ( p_next, &p_next );

	cfg.temp_alarm_yellow_set =     (uint16_t) strtod ( p_next, &p_next );
	cfg.temp_alarm_yellow_clear =   (uint16_t) strtod ( p_next, &p_next );
	cfg.temp_alarm_red_set =        (uint16_t) strtod ( p_next, &p_next );
	cfg.temp_alarm_red_clear =      (uint16_t) strtod ( p_next, &p_next );

	cfg.delay_tx_enable =           (uint16_t) strtod ( p_next, &p_next );
	cfg.delay_tx_disable =          (uint16_t) strtod ( p_next, &p_next );
	cfg.size_tx_fifo =              (uint16_t) strtod ( p_next, &p_next );

	cfg.temp_ref =                  (uint16_t) strtod ( p_next, &p_next );

	ret = optic_iocmd (fd, FIO_GOI_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_cfg_set ioctl access \n");
	}

	return ret;
}

static int config_ranges ( char *p_next, int fd )
{
	int ret = 0;
	struct optic_range_config cfg;
	uint16_t factor_ibias = 1 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint16_t factor_imod = 1 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint16_t factor_ibiasimod = 1 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint16_t factor_v = 1 << OPTIC_FLOAT2INTSHIFT_VOLTAGE;
	float vapd_min, vapd_max, vapd_curr_limit, vapd_ext_supply,
	      vapd_efficiency, vapd_ext_inductivity, vapd_switching_frequency;

	cfg.tabletemp_extcorr_min =    (uint16_t)  strtod ( p_next, &p_next );
	cfg.tabletemp_extcorr_max =    (uint16_t)  strtod ( p_next, &p_next );
	cfg.tabletemp_extnom_min =     (uint16_t)  strtod ( p_next, &p_next );
	cfg.tabletemp_extnom_max =     (uint16_t)  strtod ( p_next, &p_next );
	cfg.tabletemp_intcorr_min =    (uint16_t)  strtod ( p_next, &p_next );
	cfg.tabletemp_intcorr_max =    (uint16_t)  strtod ( p_next, &p_next );
	cfg.tabletemp_intnom_min =     (uint16_t)  strtod ( p_next, &p_next );
	cfg.tabletemp_intnom_max =     (uint16_t)  strtod ( p_next, &p_next );
	cfg.ibias_max =                (uint16_t) (strtod ( p_next, &p_next ) *
					  	   factor_ibias);
	cfg.imod_max =                 (uint16_t) (strtod ( p_next, &p_next ) *
						   factor_imod);
	cfg.ibiasimod_max =            (uint16_t) (strtod ( p_next, &p_next ) *
						   factor_ibiasimod);
	cfg.intcoeff_max[OPTIC_BIAS] = (uint8_t)   strtod ( p_next, &p_next );
	cfg.intcoeff_max[OPTIC_MOD] =  (uint8_t)   strtod ( p_next, &p_next );

	vapd_min =                                 strtod ( p_next, &p_next );
	vapd_max =                                 strtod ( p_next, &p_next );

	cfg.vcore_min =                (uint16_t) (strtod ( p_next, &p_next ) *
						   factor_v);
	cfg.vcore_max =                (uint16_t) (strtod ( p_next, &p_next ) *
						   factor_v);
	cfg.vddr_min =                 (uint16_t) (strtod ( p_next, &p_next ) *
						   factor_v);
	cfg.vddr_max =                 (uint16_t) (strtod ( p_next, &p_next ) *
						   factor_v);

	vapd_ext_inductivity =                     strtod ( p_next, &p_next );
	vapd_ext_supply =                          strtod ( p_next, &p_next );
	vapd_efficiency =                          strtod ( p_next, &p_next );
	vapd_curr_limit =                          strtod ( p_next, &p_next );
	vapd_switching_frequency =                 strtod ( p_next, &p_next );
	cfg.oc_ibias_thr =              (uint16_t) strtod ( p_next, &p_next );
	cfg.oc_imod_thr =               (uint16_t) strtod ( p_next, &p_next );
	cfg.oc_ibias_imod_thr =		(uint16_t) strtod ( p_next, &p_next );

	cfg.vapd_min =                 (uint16_t) (vapd_min * factor_v);
	cfg.vapd_max =                 (uint16_t) (vapd_max * factor_v);

	cfg.sat_min = calc_sat ( vapd_min, vapd_curr_limit, vapd_ext_supply,
				 vapd_efficiency, vapd_ext_inductivity,
				 vapd_switching_frequency );
	cfg.sat_max = calc_sat ( vapd_max, vapd_curr_limit, vapd_ext_supply,
				 vapd_efficiency, vapd_ext_inductivity,
				 vapd_switching_frequency );

	ret = optic_iocmd(fd, FIO_GOI_RANGE_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_range_def_set ioctl access \n");
	}

	return ret;
}

static int config_fcsi ( char *p_next, int fd )
{
	int ret = 0;
	struct optic_fcsi_config cfg;

	cfg.gvs = (uint16_t) strtod ( p_next, &p_next );

	ret = optic_iocmd(fd, FIO_FCSI_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: fcsi_cfg_set ioctl access \n");
	}

	return ret;

}

static int config_measure ( char *p_next, int fd )
{
	int ret = 0;
	struct optic_mm_config cfg;
	uint16_t factor_tscal_ref = 1 << OPTIC_FLOAT2INTSHIFT_TSCALREF;
	uint16_t factor_pscal_ref = 1 << OPTIC_FLOAT2INTSHIFT_PSCALREF;
	uint16_t factor_r = 1 << OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE;
	uint16_t factor_corr = 1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR;

	cfg.tscal_ref =           (uint16_t)        (strtod ( p_next, &p_next )
							* factor_tscal_ref);
	cfg.pn_r =                (uint16_t)        (strtod ( p_next, &p_next )
							* factor_r);
	cfg.pn_iref =             (enum optic_iref) strtod ( p_next, &p_next );
	cfg.rssi_1490_mode =      (enum optic_rssi_1490_mode)
						    strtod ( p_next, &p_next );
	cfg.rssi_1490_dark_corr = (uint16_t)        (strtod ( p_next, &p_next )
							* factor_corr);
	cfg.rssi_1490_shunt_res = (uint16_t)        strtod ( p_next, &p_next );
	cfg.rssi_1550_vref =      (enum optic_vref) strtod ( p_next, &p_next );
	cfg.rf_1550_vref =        (enum optic_vref) strtod ( p_next, &p_next );

	cfg.rssi_1490_scal_ref =  (uint16_t)        (strtod ( p_next, &p_next )
							* factor_pscal_ref);
	cfg.rssi_1550_scal_ref =  (uint16_t)        (strtod ( p_next, &p_next )
							* factor_pscal_ref);
	cfg.rf_1550_scal_ref =    (uint16_t)        (strtod ( p_next, &p_next )
							* factor_pscal_ref);
	cfg.rssi_1490_parabolic_ref =  (uint16_t)        (strtod ( p_next, &p_next )
								* factor_pscal_ref);
	cfg.rssi_1490_dark_ref =  (uint16_t)        (strtod ( p_next, &p_next )
							* factor_pscal_ref);

	cfg.RSSI_autolevel =  (bool)     strtod ( p_next, &p_next );
	cfg.RSSI_1490threshold_low =  (uint16_t)        strtod ( p_next, &p_next );
	cfg.RSSI_1490threshold_high =  (uint16_t)        strtod ( p_next, &p_next );

	ret = optic_iocmd(fd, FIO_MM_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: mm_cfg_set ioctl access \n");
	}

	return ret;
}

static int config_mpd ( char *p_next, int fd )
{
	int ret = 0;
	int i;
	struct optic_mpd_config cfg;
	uint32_t factor_dref = 1 << OPTIC_FLOAT2INTSHIFT_DREF;
	uint32_t factor_corr = 1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR;
	uint32_t factor_ratio = 1 << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO;

	for (i=0; i<4; i++)
		cfg.tia_gain_selector[i] = (uint8_t) strtod ( p_next, &p_next );
	for (i=0; i<4; i++)
		cfg.cal_current[i] = (uint8_t)  strtod ( p_next, &p_next );

	for (i=0; i<3; i++) {
		cfg.scalefactor_mod[i] = (uint32_t) round( factor_corr *
						strtod ( p_next, &p_next ) );
	}

	for (i=0; i<3; i++) {
		cfg.dcal_ref_p0[i] = (uint32_t) round( factor_dref *
						strtod ( p_next, &p_next ) );
		cfg.dcal_ref_p1[i] = (uint32_t) round( factor_dref *
						strtod ( p_next, &p_next ) );
	}
	for (i=0; i<3; i++) {
		cfg.dref_p0[i] =     (uint32_t) round( factor_dref *
						strtod ( p_next, &p_next ) );
		cfg.dref_p1[i] =     (uint32_t) round( factor_dref *
						strtod ( p_next, &p_next ) );
	}

	cfg.ratio_coarse_fine = (uint16_t) round( factor_ratio *
					   strtod ( p_next, &p_next ) );
	cfg.powersave =        (enum optic_activation)
					  strtod ( p_next, &p_next );

	cfg.cid_size_p0 =      (uint8_t)  strtod ( p_next, &p_next );
	cfg.cid_size_p1 =      (uint8_t)  strtod ( p_next, &p_next );
	cfg.cid_match_all_p0 = (bool)     strtod ( p_next, &p_next );
	cfg.cid_match_all_p1 = (bool)     strtod ( p_next, &p_next );
	cfg.cid_mask_p0 =      (uint16_t) strtod ( p_next, &p_next );
	cfg.cid_mask_p1 =      (uint16_t) strtod ( p_next, &p_next );
	cfg.rogue_interburst = (uint16_t) strtod ( p_next, &p_next );

	ret = optic_iocmd(fd, FIO_MPD_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: config_mpd ioctl access \n");
	}

	return ret;
}

static int config_omu ( char *p_next, int fd )
{
	int ret = 0;
	struct optic_omu_config cfg;

	cfg.signal_detect_avail =       (bool)     strtod ( p_next, &p_next );
	cfg.signal_detect_port =        (uint8_t)  strtod ( p_next, &p_next );
	cfg.threshold_lol_set =         (uint8_t)  strtod ( p_next, &p_next );
	cfg.threshold_lol_clear =       (uint8_t)  strtod ( p_next, &p_next );
	cfg.laser_enable_single_ended = (bool)     strtod ( p_next, &p_next );

	ret = optic_iocmd(fd, FIO_OMU_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: omu_cfg_set ioctl access \n");
	}

	return ret;
}

static int config_bosa ( char *p_next, int fd )
{
	int ret = 0;
	int B = OPTIC_BIAS, M = OPTIC_MOD;
	struct optic_bosa_rx_config rx_cfg;
	struct optic_bosa_tx_config tx_cfg;
	uint32_t factor_power = 1 << OPTIC_FLOAT2INTSHIFT_POWER;
	uint8_t i;

	tx_cfg.loop_mode =             (enum optic_bosa_loop_mode)
						     strtod ( p_next, &p_next );

	rx_cfg.dead_zone_elimination = (bool)     strtod ( p_next, &p_next );
	rx_cfg.threshold_lol_set =     (uint8_t)  strtod ( p_next, &p_next );
	rx_cfg.threshold_lol_clear =   (uint8_t)  strtod ( p_next, &p_next );
	rx_cfg.threshold_los =         (uint16_t) (strtod ( p_next, &p_next )
	                                             * factor_power);
	rx_cfg.threshold_rx_overload = (uint16_t) (strtod ( p_next, &p_next )
						     * factor_power);

	tx_cfg.intcoeff_init[B] =      (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.intcoeff_init[M] =      (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.pi_control =            (uint32_t) strtod ( p_next, &p_next );

	tx_cfg.updatethreshold[B] =    (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.updatethreshold[M] =    (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.learnthreshold[B] =     (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.learnthreshold[M] =     (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.stablethreshold[B] =    (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.stablethreshold[M] =    (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.resetthreshold[B] =     (uint8_t)  strtod ( p_next, &p_next );
	tx_cfg.resetthreshold[M] =     (uint8_t)  strtod ( p_next, &p_next );

	for (i=0; i<3; i++)
		tx_cfg.p0[i] =         (int16_t) strtod ( p_next, &p_next );

	for (i=0; i<3; i++)
		tx_cfg.p1[i] =         (int16_t) strtod ( p_next, &p_next );

	tx_cfg.pth =                   (uint16_t) strtod ( p_next, &p_next );

	ret = optic_iocmd(fd, FIO_BOSA_RX_CFG_SET, &rx_cfg, sizeof(rx_cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: bosa_rx_cfg_set ioctl access \n");
	}

	ret = optic_iocmd(fd, FIO_BOSA_TX_CFG_SET, &tx_cfg, sizeof(tx_cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: bosa_tx_cfg_set ioctl access \n");
	}

	return ret;
}

static int config_dcdc_apd ( char *p_next, int fd )
{
	int ret = 0;
	struct optic_dcdc_apd_config cfg;
	float VAPD_ext_supply;
	uint32_t factor_voltage = 1 << OPTIC_FLOAT2INTSHIFT_VOLTAGE;

	cfg.r_diff[0] =    (uint32_t)    strtod ( p_next, &p_next );
	cfg.r_diff[1] =    (uint32_t)    strtod ( p_next, &p_next );
	VAPD_ext_supply = strtod ( p_next, &p_next );

	cfg.v_ext = VAPD_ext_supply * factor_voltage;

	ret = optic_iocmd(fd, FIO_DCDC_APD_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: dcdc_apd_cfg_set ioctl access \n");
	}

	return ret;
}

static int config_dcdc_core ( char *p_next, int fd )
{
	int ret = 0;
	struct optic_dcdc_core_config cfg;
	float r[2], i[2];
	uint32_t temp;
	uint32_t factor_voltage = 1 << OPTIC_FLOAT2INTSHIFT_VOLTAGE;

	r[0] = strtod ( p_next, &p_next );
	r[1] = strtod ( p_next, &p_next );
	i[0] = strtod ( p_next, &p_next );
	i[1] = strtod ( p_next, &p_next );

	cfg.v_tolerance_input =    (uint8_t)    strtod ( p_next, &p_next );
	cfg.v_tolerance_target =   (uint8_t)    strtod ( p_next, &p_next );

	cfg.pmos_on_delay =    (uint8_t)    strtod ( p_next, &p_next );
	cfg.nmos_on_delay =    (uint8_t)    strtod ( p_next, &p_next );

	temp = r[0] * i[0] * factor_voltage;
	temp += 500;
	cfg.v_min = (uint16_t) (temp / 1000);

	temp = r[1] * i[1] * factor_voltage;
	temp += 500;
	cfg.v_max = (uint16_t) (temp / 1000);

	ret = optic_iocmd(fd, FIO_DCDC_CORE_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: dcdc_core_cfg_set ioctl access \n");
	}

	return ret;
}

static int config_dcdc_ddr ( char *p_next, int fd )
{
	int ret = 0;
	struct optic_dcdc_ddr_config cfg;
	float r[2], i[2];
	uint32_t temp;
	uint32_t factor_voltage = 1 << OPTIC_FLOAT2INTSHIFT_VOLTAGE;

	r[0] = strtod ( p_next, &p_next );
	r[1] = strtod ( p_next, &p_next );
	i[0] = strtod ( p_next, &p_next );
	i[1] = strtod ( p_next, &p_next );

	cfg.v_tolerance_input =    (uint8_t)    strtod ( p_next, &p_next );
	cfg.v_tolerance_target =   (uint8_t)    strtod ( p_next, &p_next );

	cfg.pmos_on_delay =    (uint8_t)    strtod ( p_next, &p_next );
	cfg.nmos_on_delay =    (uint8_t)    strtod ( p_next, &p_next );

	temp = r[0] * i[0] * factor_voltage;
	temp += 500;
	cfg.v_min = (uint16_t) (temp / 1000);

	temp = r[1] * i[1] * factor_voltage;
	temp += 500;
	cfg.v_max = (uint16_t) (temp / 1000);

	ret = optic_iocmd(fd, FIO_DCDC_DDR_CFG_SET, &cfg, sizeof(cfg));
	if (ret != 0) {
		fprintf(stderr, "ERROR: dcdc_ddr_cfg_set ioctl access \n");
	}

	return ret;
}

static int read_table_factor ( enum optic_tabletype type,
			       char *p_next, int fd )
{
	int ret = -1;
	uint16_t temp_min, temp_max, temp_low, temp_high;
	union table_ref tref;
	char table_name[TABLE_NAME_LENGTH];
	/* table set */
	void *p_transfer = NULL;
	uint16_t tabledepth;
	struct optic_transfer_table_set transfer_table;
	enum optic_tabletype types[3];
	uint8_t table_cnt, types_index = 0;

	temp_min = (uint16_t)  strtod(p_next, &p_next);
	temp_max = (uint16_t)  strtod(p_next, &p_next);

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
		table_cnt = 1;
		types[0] = type;
		break;
	case OPTIC_TABLETYPE_POWER:
		table_cnt = 3;
		types[0] = OPTIC_TABLETYPE_RSSI1490;
		types[1] = OPTIC_TABLETYPE_RSSI1550;
		types[2] = OPTIC_TABLETYPE_RF1550;
		break;
	default:
		fprintf(stderr, "ERROR: read_table_factor doesn't support table type %d \n", type);
		table_cnt = 0;
		break;
	}

	tref.p = NULL;
	while (table_cnt) {
		/* read table name & parse + complete table */
		strtostr(table_name, TABLE_NAME_LENGTH, &p_next);

		if (read_table ( types[types_index], table_name, temp_min,
				 temp_max, &tref, &temp_low,
				 &temp_high ) < 0)
			goto end_read_table_factor;

		if (fill_table_factor ( temp_min, temp_max, tref.f ) < 0)
			goto end_read_table_factor;

		if (compress_table ( types[types_index], (void*) tref.f,
				     temp_min, temp_max, &p_transfer,
				     &tabledepth ) < 0)
			goto end_read_table_factor;

		transfer_table.table_type = types[types_index];
		transfer_table.table_depth = tabledepth;
		transfer_table.p_data = (void*) p_transfer;

		ret = optic_iocmd(fd, FIO_GOI_TABLE_SET, &transfer_table, sizeof(transfer_table));
		if (ret != 0) {
			fprintf(stderr, "ERROR: goi_table_set ioctl access \n");
		}

		free(tref.f);
		tref.f = NULL;

		free(p_transfer);
		p_transfer = NULL;

		table_cnt --;
		types_index ++;
	}

end_read_table_factor:
	if (tref.f != NULL)
		free(tref.f);

	if (p_transfer != NULL)
		free(p_transfer);

	return ret;
}

static int read_table_laserref ( char *p_next, int fd )
{
	int ret = -1;
	uint16_t temp_min, temp_max, temp_low, temp_high;
	int16_t tci_ith_low, tci_ith_high, tci_se_low, tci_se_high;
	uint8_t tcd_ith_low, tcd_ith_high, tcd_se_low, tcd_se_high;
	union table_ref tref;
	char table_name[TABLE_NAME_LENGTH];
	/* table set */
	void *p_transfer = NULL;
	uint16_t tabledepth;
	struct optic_transfer_table_set transfer_table;

	temp_min = (uint16_t)  strtod(p_next, &p_next);
	temp_max = (uint16_t)  strtod(p_next, &p_next);

	tci_ith_low =  (int16_t)  strtod(p_next, &p_next);
	tci_ith_high = (int16_t)  strtod(p_next, &p_next);
	tci_se_low =   (int16_t)  strtod(p_next, &p_next);
	tci_se_high =  (int16_t)  strtod(p_next, &p_next);
	tcd_ith_low =  (uint8_t)  strtod(p_next, &p_next);
	tcd_ith_high = (uint8_t)  strtod(p_next, &p_next);
	tcd_se_low =   (uint8_t)  strtod(p_next, &p_next);
	tcd_se_high =  (uint8_t)  strtod(p_next, &p_next);

	/* read table name & parse + complete table */
	strtostr(table_name, TABLE_NAME_LENGTH, &p_next);
	if (read_table ( OPTIC_TABLETYPE_LASERREF, table_name,
	                 temp_min, temp_max, &tref,
	                 &temp_low, &temp_high ) < 0)
		goto end_read_table_laserref;

	if (fill_table_laserref ( temp_min, temp_max, tref.lr,
				  temp_low, temp_high,
				  tci_ith_low, tci_ith_high,
				  tci_se_low, tci_se_high,
				  tcd_ith_low, tcd_ith_high,
				  tcd_se_low, tcd_se_high ) < 0)
		goto end_read_table_laserref;

	if (compress_table ( OPTIC_TABLETYPE_LASERREF, (void*) tref.lr,
			     temp_min, temp_max, &p_transfer, &tabledepth ) < 0)
		goto end_read_table_laserref;

	transfer_table.table_type = OPTIC_TABLETYPE_LASERREF;
	transfer_table.table_depth = tabledepth;
	transfer_table.p_data = (void*) p_transfer;

	ret = optic_iocmd(fd, FIO_GOI_TABLE_SET, &transfer_table,
		sizeof(transfer_table));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_table_set ioctl access \n");
	}

end_read_table_laserref:
	if (tref.lr != NULL)
		free(tref.lr);

	if (p_transfer != NULL)
		free(p_transfer);

	return ret;
}

static int write_table_laserref ( char *p_next, int fd )
{
	int ret = -1;
	uint16_t temp_min, temp_max, temp_low, temp_high, temp_low_, temp_high_;
	int16_t tci_ith_low, tci_ith_high, tci_se_low, tci_se_high;
	uint8_t tcd_ith_low, tcd_ith_high, tcd_se_low, tcd_se_high;
	union table_ref tref, trefbase;
	char table_name[TABLE_NAME_LENGTH];
	char table_name_base[TABLE_NAME_LENGTH];
	/* table set */
	void *p_transfer = NULL;
	uint16_t tabledepth;
	union optic_transfer_table_get transfer_table_get;
	struct optic_transfer_table_set transfer_table_set;

	temp_min = (uint16_t)  strtod(p_next, &p_next);
	temp_max = (uint16_t)  strtod(p_next, &p_next);

	tci_ith_low =  (int16_t)  strtod(p_next, &p_next);
	tci_ith_high = (int16_t)  strtod(p_next, &p_next);
	tci_se_low =   (int16_t)  strtod(p_next, &p_next);
	tci_se_high =  (int16_t)  strtod(p_next, &p_next);
	tcd_ith_low =  (uint8_t)  strtod(p_next, &p_next);
	tcd_ith_high = (uint8_t)  strtod(p_next, &p_next);
	tcd_se_low =   (uint8_t)  strtod(p_next, &p_next);
	tcd_se_high =  (uint8_t)  strtod(p_next, &p_next);

	/* read table name & parse + complete table */
	strtostr(table_name, TABLE_NAME_LENGTH, &p_next);
	strtostr(table_name_base, TABLE_NAME_LENGTH, &p_next);
	tref.p = NULL;
	trefbase.p = NULL;
	if (read_table ( OPTIC_TABLETYPE_LASERREF, table_name,
	                 temp_min, temp_max, &tref,
	                 &temp_low, &temp_high ) < 0)
		goto end_write_table_laserref;

	tabledepth = temp_max - temp_min + 1;
	p_transfer = malloc ( sizeof(struct optic_tt_laserref) * tabledepth );

	transfer_table_get.in.table_type = OPTIC_TABLETYPE_LASERREF;
	transfer_table_get.in.table_depth = tabledepth;
	transfer_table_get.in.quality = OPTIC_TABLEQUAL_MEAS;	/* /todo: OPTIC_TABLEQUAL_MEAS */
	transfer_table_get.in.p_data = (void*) p_transfer;

	ret = optic_iocmd(fd, FIO_GOI_TABLE_GET, &transfer_table_get,
		sizeof(transfer_table_get));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_table_set ioctl access \n");
	}

	tabledepth = transfer_table_get.out.table_depth;

	if (extract_table ( OPTIC_TABLETYPE_LASERREF, tabledepth, p_transfer,
			    temp_min, temp_max, (void *) tref.lr,
			    &temp_low, &temp_high ) < 0)
		goto end_write_table_laserref;

	if (write_table ( OPTIC_TABLETYPE_LASERREF, table_name,
	                  (void *) tref.lr, temp_min, temp_max,
	                  temp_low, temp_high ) < 0)
		goto end_write_table_laserref;

	/* read base file */
	if (read_table ( OPTIC_TABLETYPE_LASERREF, table_name_base,
	                 temp_min, temp_max,
	                 &trefbase,
	                 &temp_low_, &temp_high_ ) < 0)
		goto end_write_table_laserref;

	if (update_table ( OPTIC_TABLETYPE_LASERREF,
	                   (void *) trefbase.lr,
	                   (void *) tref.lr,
	                   temp_min, temp_max) < 0)
		goto end_write_table_laserref;

	if (temp_low < temp_low_)
		temp_low_ = temp_low;
	if (temp_high > temp_high_)
		temp_high_ = temp_high;

	if (write_table ( OPTIC_TABLETYPE_LASERREF, table_name_base,
	                  (void *) trefbase.lr, temp_min, temp_max,
	                  temp_low_, temp_high_ ) < 0)
		goto end_write_table_laserref;

	/* new inter/extrapolation */
	/* complete table */
	if (fill_table_laserref ( temp_min, temp_max, tref.lr,
				  temp_low, temp_high,
				  tci_ith_low, tci_ith_high,
				  tci_se_low, tci_se_high,
				  tcd_ith_low, tcd_ith_high,
				  tcd_se_low, tcd_se_high ) < 0)
		goto end_write_table_laserref;

	if (compress_table ( OPTIC_TABLETYPE_LASERREF, (void*) tref.lr,
			     temp_min, temp_max, &p_transfer, &tabledepth ) < 0)
		goto end_write_table_laserref;

	transfer_table_set.table_type = OPTIC_TABLETYPE_LASERREF;
	transfer_table_set.table_depth = tabledepth;
	transfer_table_set.p_data = (void*) p_transfer;

	ret = optic_iocmd(fd, FIO_GOI_TABLE_SET, &transfer_table_set,
		sizeof(transfer_table_set));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_table_set ioctl access \n");
	}


end_write_table_laserref:
	if (tref.lr != NULL)
		free(tref.lr);

	if (trefbase.lr != NULL)
		free(trefbase.lr);

	if (p_transfer != NULL)
		free(p_transfer);

	return ret;
}

static int read_table_ibiasimod ( char *p_next, int fd )
{
	int ret = -1;
	uint16_t temp_min, temp_max, temp_low, temp_high;
	int16_t tci_ith_low, tci_ith_high, tci_se_low, tci_se_high;
	uint8_t tcd_ith_low, tcd_ith_high, tcd_se_low, tcd_se_high;
	float p0[3], p1[3], pth_ref;
	float ibias_max, imod_max, ibiasimod_max;
	char table_name[TABLE_NAME_LENGTH];
	union table_ref tref, tref_pth;
	struct table_ibiasimod *t_ibiasimod = NULL;
	/* table set */
	void *p_transfer = NULL;
	uint16_t tabledepth;
	struct optic_transfer_table_set transfer_table;

	temp_min = (uint16_t)  strtod(p_next, &p_next);
	temp_max = (uint16_t)  strtod(p_next, &p_next);

	p0[0] = strtod(p_next, &p_next);
	p0[1] = strtod(p_next, &p_next);
	p0[2] = strtod(p_next, &p_next);
	p1[0] = strtod(p_next, &p_next);
	p1[1] = strtod(p_next, &p_next);
	p1[2] = strtod(p_next, &p_next);
	pth_ref = strtod(p_next, &p_next);

	tci_ith_low =  (int16_t)  strtod(p_next, &p_next);
	tci_ith_high = (int16_t)  strtod(p_next, &p_next);
	tci_se_low =   (int16_t)  strtod(p_next, &p_next);
	tci_se_high =  (int16_t)  strtod(p_next, &p_next);
	tcd_ith_low =  (uint8_t)  strtod(p_next, &p_next);
	tcd_ith_high = (uint8_t)  strtod(p_next, &p_next);
	tcd_se_low =   (uint8_t)  strtod(p_next, &p_next);
	tcd_se_high =  (uint8_t)  strtod(p_next, &p_next);

	ibias_max =     strtod(p_next, &p_next);
	imod_max =      strtod(p_next, &p_next);
	ibiasimod_max = strtod(p_next, &p_next);

	/* read table name & parse + complete table */
	strtostr(table_name, TABLE_NAME_LENGTH, &p_next);
	if (read_table ( OPTIC_TABLETYPE_PTH, table_name, temp_min, temp_max,
			 &tref_pth, &temp_low, &temp_high ) < 0)
		goto end_read_table_ibiasimod;

	if (fill_table_factor ( temp_min, temp_max, tref_pth.f ) < 0)
		goto end_read_table_ibiasimod;

	/* read table name & parse + complete table */
	strtostr(table_name, TABLE_NAME_LENGTH, &p_next);
	if (read_table ( OPTIC_TABLETYPE_LASERREF, table_name,
	                 temp_min, temp_max, &tref,
	                 &temp_low, &temp_high ) < 0)
		goto end_read_table_ibiasimod;

	if (fill_table_laserref ( temp_min, temp_max, tref.lr,
				  temp_low, temp_high,
				  tci_ith_low, tci_ith_high,
				  tci_se_low, tci_se_high,
				  tcd_ith_low, tcd_ith_high,
				  tcd_se_low, tcd_se_high ) < 0)
		goto end_read_table_ibiasimod;

	/* create ibias/imod table */
	if (calc_table_ibiasimod ( temp_min, temp_max, p0, p1, pth_ref,
				   ibias_max, imod_max, ibiasimod_max,
				   tref_pth.f, tref.lr,
				   &t_ibiasimod ) < 0)
		goto end_read_table_ibiasimod;

	/* used for updates: to hide all unchanged entries */
	if (update_table_transfer ( OPTIC_TABLETYPE_IBIASIMOD,
				    (void**) &t_ibiasimod, NULL,
				    temp_min, temp_max) < 0)
		goto end_read_table_ibiasimod;

	if (compress_table ( OPTIC_TABLETYPE_IBIASIMOD, (void*) t_ibiasimod,
			     temp_min, temp_max, &p_transfer, &tabledepth ) < 0)
		goto end_read_table_ibiasimod;

	transfer_table.table_type = OPTIC_TABLETYPE_IBIASIMOD;
	transfer_table.table_depth = tabledepth;
	transfer_table.p_data = (void*) p_transfer;

	ret = optic_iocmd(fd, FIO_GOI_TABLE_SET, &transfer_table,
		sizeof(transfer_table));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_table_set ioctl access \n");
	}

end_read_table_ibiasimod:
	if (tref_pth.p != NULL)
		free(tref_pth.p);
	if (tref.p != NULL)
		free(tref.p);
	if (t_ibiasimod != NULL)
		free(t_ibiasimod);

	if (p_transfer != NULL)
		free(p_transfer);

	return ret;
}

static int read_table_vapd ( char *p_next, int fd )
{
	int ret = -1;
	uint16_t temp_min, temp_max;

	float temp_ref, vapd_bd_ref, vapd_offset, vapd_scal_ref;
	float vapd_min, vapd_max;
	float vapd_curr_limit, vapd_ext_supply, vapd_efficiency,
	      vapd_ext_inductivity, vapd_switching_frequency;

	struct table_vapd *t_vapd = NULL;

	/* table set */
	void *p_transfer = NULL;
	uint16_t tabledepth;
	struct optic_transfer_table_set transfer_table;

	temp_min =       (uint16_t) strtod(p_next, &p_next);
	temp_max =       (uint16_t) strtod(p_next, &p_next);

	temp_ref =                  strtod(p_next, &p_next);
	vapd_bd_ref =               strtod(p_next, &p_next);
	vapd_offset =               strtod(p_next, &p_next);
	vapd_scal_ref =             strtod(p_next, &p_next);

	vapd_min =                  strtod(p_next, &p_next);
	vapd_max =                  strtod(p_next, &p_next);

	vapd_ext_inductivity =      strtod(p_next, &p_next);
	vapd_ext_supply =           strtod(p_next, &p_next);
	vapd_efficiency =           strtod(p_next, &p_next);
	vapd_curr_limit =           strtod(p_next, &p_next);
	vapd_switching_frequency =  strtod(p_next, &p_next);

	/* create ibias/imod table */
	if (calc_table_vapd ( temp_min, temp_max, temp_ref, vapd_bd_ref,
			      vapd_offset, vapd_scal_ref, vapd_min, vapd_max,
			      vapd_curr_limit, vapd_ext_supply, vapd_efficiency,
			      vapd_ext_inductivity, vapd_switching_frequency,
			      &t_vapd ) < 0)
		goto end_read_table_vapd;

	if (compress_table ( OPTIC_TABLETYPE_VAPD, (void*) t_vapd,
			     temp_min, temp_max, &p_transfer, &tabledepth ) < 0)
		goto end_read_table_vapd;

	transfer_table.table_type = OPTIC_TABLETYPE_VAPD;
	transfer_table.table_depth = tabledepth;
	transfer_table.p_data = (void*) p_transfer;

	ret = optic_iocmd(fd, FIO_GOI_TABLE_SET, &transfer_table,
		sizeof(transfer_table));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_table_set ioctl access \n");
	}

end_read_table_vapd:
	if (t_vapd != NULL)
		free(t_vapd);

	if (p_transfer != NULL)
		free(p_transfer);

	return ret;
}

static int read_table_temptrans ( char *p_next, int fd )
{
	int ret = -1;
	uint16_t temp_min, temp_max, temp_low, temp_high;
	char table_name[TABLE_NAME_LENGTH];
	union table_ref tref;

	/* table set */
	void *p_transfer = NULL;
	uint16_t tabledepth;
	struct optic_transfer_table_set transfer_table;

	temp_min = (uint16_t)  strtod(p_next, &p_next);
	temp_max = (uint16_t)  strtod(p_next, &p_next);

	/* read table name & parse + complete table */
	strtostr(table_name, TABLE_NAME_LENGTH, &p_next);
	if (read_table ( OPTIC_TABLETYPE_TEMPTRANS, table_name,
			 temp_min, temp_max, &tref,
			 &temp_low, &temp_high ) < 0)
		goto end_read_table_temptrans;

	if (fill_table_temptrans ( temp_min, temp_max, tref.tt) < 0)
		goto end_read_table_temptrans;

	if (compress_table ( OPTIC_TABLETYPE_TEMPTRANS,
	                     (void*) tref.tt, temp_min, temp_max,
	                     &p_transfer, &tabledepth ) < 0)
		goto end_read_table_temptrans;

	transfer_table.table_type = OPTIC_TABLETYPE_TEMPTRANS;
	transfer_table.table_depth = tabledepth;
	transfer_table.p_data = (void*) p_transfer;

	ret = optic_iocmd(fd, FIO_GOI_TABLE_SET, &transfer_table,
		sizeof(transfer_table));
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_table_set ioctl access \n");
	}

end_read_table_temptrans:
	if (tref.p != NULL)
		free(tref.p);

	if (p_transfer != NULL)
		free(p_transfer);

	return ret;
}

static int goi_init ( char *p_next, int fd )
{
	int ret = 0;
	(void) p_next;

	ret = optic_iocmd(fd, FIO_GOI_INIT, NULL, 0);
	if (ret != 0) {
		fprintf(stderr, "ERROR: goi_init ioctl access \n");
	}

	return ret;
}


static int optic_send (unsigned int argc, char *argv[])
{
	int fd, params, ret = -1;
	unsigned char idx=1;
	int c;
	unsigned int i;

	fd = optic_open(OPTIC_DEVICE_PATH);
	if (fd < 0) {
		printf("oops fd %d (errno=%d)\n", fd, errno);
		fprintf(stderr, "ERROR: can't open device "
				OPTIC_DEVICE_PATH ".\n");
		return ret;
	}

	if (argc > 1) {
		do {
			c = -1;
			/* filter out the additional options */
			if(argv[idx][0] == '-')	{
				c = (int)argv[idx][1];
				for (i=0; i < strlen (getopt_long_optstring);
				     i++) {
					if(getopt_long_optstring[i] == ':')
						continue;
					if(getopt_long_optstring[i] == c) {
						/* option found */
						ret = c;
						if (argv[idx][2] == 0)
							optarg= &argv[idx+1][0];
						else
							optarg= &argv[idx][2];
						idx++;
						break;
					}
				}
			}
			if (c == -1 || c == 0)
				break;
			idx++;
		} while (c > 0);
	}

	buf[0] = 0;
	if (argc - idx > 0) {

		strcat(buf, argv[idx]);
		strcat(buf, " ");
		params = strlen(buf);
		for (i = 1 + idx; i < argc; i++) {
			strcat(buf, argv[i]);
			strcat(buf, " ");
		}

#ifndef INCLUDE_CLI_SUPPORT
		/*
		  Add here handling for required commands (e.g. configuration
		  commands) in the case of disabled CLI support.
		*/
		if (!strcmp(argv[idx], "optic_mode_set")) {
			ret = optic_mode_set (&buf[params], fd);
			goto end;
		} else
#endif
		if (!strcmp(argv[idx], "config_goi")) {
			ret = config_goi (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_ranges")) {
			ret = config_ranges (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_fcsi")) {
			ret = config_fcsi (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_measure")) {
			ret = config_measure (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_mpd")) {
			ret = config_mpd (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_omu")) {
			ret = config_omu (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_bosa")) {
			ret = config_bosa (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_dcdc_apd")) {
			ret = config_dcdc_apd (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_dcdc_core")) {
			ret = config_dcdc_core (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "config_dcdc_ddr")) {
			ret = config_dcdc_ddr (&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "read_table_pth")) {
			ret = read_table_factor( OPTIC_TABLETYPE_PTH,
						 &buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "read_table_laserref")) {
			ret = read_table_laserref(&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "write_table_laserref")) {
			ret = write_table_laserref(&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "read_table_ibiasimod")) {
			ret = read_table_ibiasimod(&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "read_table_vapd")) {
			ret = read_table_vapd(&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "read_table_mpdresp")) {
			ret = read_table_factor( OPTIC_TABLETYPE_MPDRESP,
						 &buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "read_table_temptrans")) {
			ret = read_table_temptrans(&buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "read_table_power")) {
			ret = read_table_factor( OPTIC_TABLETYPE_POWER,
						 &buf[params], fd);
			goto end;
		} else
		if (!strcmp(argv[idx], "goi_init")) {
			ret = goi_init(&buf[params], fd);
			goto end;
		}

	} else {
		strcat(buf, "help");
	}

#ifdef INCLUDE_CLI_SUPPORT
	ret = optic_iocmd(fd, FIO_OPTIC_CLI, &buf, strlen(buf));
	if (ret == 0) {
		fprintf(stdout, "%s\n", &buf[0]);
	} else {
		fprintf(stderr, "ERROR: can't cli from device.\n");
	}
#endif

end:
	optic_close(fd);

	return ret;
}


int main ( int argc, char *argv[] )
{
	g_help = -1;
	g_version = -1;
	g_daemon = -1;

#ifdef INCLUDE_REMOTE_ONU
	g_remote[0] = 0;
#endif
	if (optic_args_parse(argc, argv) != 0)
		return -1;

	if (g_help == 1)
		return optic_usage(argv[0]);

#ifdef INCLUDE_REMOTE_ONU
	if(g_remote[0])
		remote_init(&g_remote[0]);
#endif
	if (g_version == 1)
		return optic_version();

	if (g_daemon == 1)
		return optic_daemon();

	return optic_send ((unsigned int)argc, argv);
}
