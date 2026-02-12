   /******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "gtop.h"
#include "gtc_counter.h"

#include <stdio.h>
#include <sys/time.h>

#include <sys/ioctl.h>
#include "drv_onu_resource.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_reg_gtc.h"
#include "common.h"

static struct gtc_status gtc_status;
static struct ploam_state_data_get ploam_state;
static struct lan_port_status *lan_port_status;
static struct wol_status *wol_status;

static struct gtc_cfg gtc_cfg;
static struct gpe_cfg gpe_cfg;
static struct lan_cfg lan_cfg;
static struct lan_port_cfg *lan_port_cfg;

void gtc_group_init(bool init)
{
	if (init) {
		lan_port_status = malloc(sizeof(*lan_port_status) *
					 g_capability.max_eth_uni);

		wol_status = malloc(sizeof(*wol_status) *
				    g_capability.max_eth_uni);

		lan_port_cfg = malloc(sizeof(*lan_port_cfg) *
				      g_capability.max_eth_uni);

		if (!lan_port_status || !wol_status || !lan_port_cfg) {
			fprintf(stderr, "No free memory\n");
			exit(2);
		}
	} else {
		free(lan_port_status);
		free(wol_status);
		free(lan_port_cfg);
	}
}

int status_table_get(const int fd, const char *dummy)
{
	unsigned int i;

	if (onu_iocmd(fd, FIO_PLOAM_STATE_GET, &ploam_state,  sizeof(ploam_state)) != 0)
		memset(&ploam_state, 0, sizeof(ploam_state));

	if (onu_iocmd(fd, FIO_GTC_STATUS_GET, &gtc_status, sizeof(gtc_status)) != 0)
		memset(&gtc_status, 0, sizeof(gtc_status));

	/* get struct lan_port_status & wol_status */
	for (i = 0; i < g_capability.max_eth_uni; i++) {
		lan_port_status[i].index = i;
		if (onu_iocmd(fd, FIO_LAN_PORT_STATUS_GET,
			&lan_port_status[i], sizeof(lan_port_status[i])) != 0)
			memset(&lan_port_status[i], 0, sizeof(lan_port_status[i]));

		wol_status[i].index = i;
		if (onu_iocmd(fd, FIO_WOL_STATUS_GET,
			&wol_status[i], sizeof(wol_status[i])) != 0)
			memset(&wol_status[i], 0, sizeof(wol_status[i]));
	}

	return 1 + 8 + 7 + g_capability.max_eth_uni * 4 + 1;
}

char *status_table_entry_get(const int num, char *text)
{
	int entry = num;

	if (entry == -1) {
		sprintf(text, "%-50s %s", "OPTION", "VALUE");
	} else if (entry >= 0 && entry <= 8) {
		switch (entry) {
		case 0:
			sprintf(text, "%-50s %u", "PLOAM state",
				ploam_state.curr_state);
			break;

		case 1:
			sprintf(text, "%-50s %s", "Downstream FEC enable",
				(gtc_status.ds_fec_enable) ? "yes" : "no");
			break;

		case 2:
			sprintf(text, "%-50s %s", "Upstream FEC enable",
				(gtc_status.us_fec_enable) ? "yes" : "no");
			break;

		case 3:
			sprintf(text, "%-50s %s", "PLOAMd message waiting in buffer",
				(gtc_status.ds_ploam_waiting) ? "yes" : "no");
			break;

		case 4:
			sprintf(text, "%-50s %s", "PLOAMd message buffer overflow",
				(gtc_status.ds_ploam_overflow) ? "yes" : "no");
			break;

		case 5:
			sprintf(text, "%-50s %s", "Receive state machine status",
				(gtc_status.ds_state == GPON_STATE_HUNT) ? "hunt" :
				(gtc_status.ds_state == GPON_STATE_PRESYNC) ? "presync" :
				"sync");
			break;

		case 6:
			sprintf(text, "%-50s %s", "Receive superframe state machine status",
				(gtc_status.ds_sf_state == GPON_SF_STATE_HUNT) ? "hunt" :
				(gtc_status.ds_sf_state == GPON_SF_STATE_PRESYNC) ? "presync" :
				"sync");
			break;

		case 7:
			sprintf(text, "%-50s %s", "PEE received",
				(gtc_status.ds_physical_equipment_error) ? "yes" : "no");
			break;

		case 8:
			sprintf(text, "%-50s %u", "ONU ID",
				gtc_status.onu_id);
			break;

		}

	} else if (entry - 9 >= 0 && entry - 9 < (int)g_capability.max_eth_uni * 4) {
		entry = entry - 9;
		uint8_t port_idx = entry / 4;

		switch (entry % 4) {
		case 0:
			sprintf(text, "[%u] %-46s %u",
				port_idx,
				"Interface mode",
				lan_port_status[port_idx].mode);
			break;

		case 1:
			sprintf(text, "[%u] %-46s %u",
				port_idx,
				"PHY status",
				lan_port_status[port_idx].link_status);
			break;

		case 2:
			sprintf(text, "[%u] %-46s %u",
				port_idx,
				"PHY duplex",
				lan_port_status[port_idx].phy_duplex);
			break;

		case 3:
			sprintf(text, "[%u] %-46s %u",
				port_idx,
				"WOL status",
				wol_status[port_idx].wol_sts);
			break;
		}

	} else {
		text[0] = 0;
	}

	return NULL;
}

int cfg_table_get(const int fd, const char *dummy)
{
	unsigned int i;

	if (onu_iocmd(fd, FIO_GTC_CFG_GET, &gtc_cfg, sizeof(gtc_cfg)) != 0)
		memset(&gtc_cfg, 0, sizeof(gtc_cfg));
	if (onu_iocmd(fd, FIO_GPE_CFG_GET, &gpe_cfg, sizeof(gpe_cfg)) != 0)
		memset(&gpe_cfg, 0, sizeof(gpe_cfg));
	if (onu_iocmd(fd, FIO_LAN_CFG_GET, &lan_cfg, sizeof(lan_cfg)) != 0)
		memset(&lan_cfg, 0, sizeof(lan_cfg));
	/* get struct lan_port_cfg */
	for (i = 0; i < g_capability.max_eth_uni; i++) {
		lan_port_cfg[i].index = i;
		if (onu_iocmd(fd, FIO_LAN_PORT_CFG_GET,
			&lan_port_cfg[i], sizeof(lan_port_cfg[i])) != 0)
			memset(&lan_port_cfg[i], 0, sizeof(lan_port_cfg[i]));
	}

	return 11 + g_capability.max_eth_uni * 2;
}

char *cfg_table_entry_get(const int num, char *text)
{
	int entry = num;

	if (entry == -1) {
		sprintf(text, "%-50s %s", "OPTION", "VALUE");
	} else if (entry >= 0 && entry <= 10) {

		switch (entry) {
		case 0:
			sprintf(text, "%-50s %u", "BIP error interval",
				gtc_cfg.bip_error_interval);
			break;

		case 1:
			sprintf(text, "%-50s %u", "Signal Fail threshold",
				gtc_cfg.sf_threshold);
			break;

		case 2:
			sprintf(text, "%-50s %u", "Signal Degrade threshold",
				gtc_cfg.sd_threshold);
			break;

		case 3:
			sprintf(text, "%-50s %u", "ONU response time",
				gtc_cfg.onu_response_time);
			break;

		case 4:
			sprintf(text, "%-50s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				"PLOAM password",
				gtc_cfg.password[0],
				gtc_cfg.password[1],
				gtc_cfg.password[2],
				gtc_cfg.password[3],
				gtc_cfg.password[4],
				gtc_cfg.password[5],
				gtc_cfg.password[6],
				gtc_cfg.password[7],
				gtc_cfg.password[8],
				gtc_cfg.password[9]);
			break;

		case 5:
			sprintf(text, "%-50s %u", "GEM block length",
				gpe_cfg.gem_blk_len);
			break;

		case 6:
			sprintf(text, "%-50s %u", "Maximum GEM payload size US",
				gpe_cfg.gem_payload_size_max);
			break;

		case 7:
			sprintf(text, "%-50s ETH:0x%04x OMCI:0x%04x IP:0x%04x MPLS:0x%04x",
				"Maximum PDU size DS",
				gpe_cfg.pdu_size_max_eth,
				gpe_cfg.pdu_size_max_omci,
				gpe_cfg.pdu_size_max_ip,
				gpe_cfg.pdu_size_max_mpls);
			break;

		case 8:
			sprintf(text, "%-50s %u",
				"LAN port operation mode",
				lan_cfg.mux_mode);
			break;

		case 9:
			sprintf(text, "%-50s %d", "MDIO data rate",
				lan_cfg.mdio_data_rate);
			break;

		case 10:
			sprintf(text, "%-50s %s", "MDIO interface enable",
				(lan_cfg.mdio_en) ? "yes" : "no");
			break;

		}

	} else if (entry - 11 >= 0 && entry - 11 < (int)g_capability.max_eth_uni * 2) {
		entry = entry - 11;
		uint8_t port_idx = entry / 2;

		switch (entry % 2) {
		case 0:
			sprintf(text, "[%u] %-46s %s",
				port_idx,
				"LAN port enable",
				lan_port_cfg[port_idx].uni_port_en ? "yes" : "no");
			break;

		case 1:
			sprintf(text, "[%u] %-46s %u",
				port_idx,
				"LAN port PHY MDIO device address",
				lan_cfg.mdio_dev_addr[port_idx]);
			break;

		}

	} else {
		text[0] = 0;
	}

	return NULL;
}

static struct gtc_alarm gtc_alarm;

int gtc_alarms_table_get(const int fd, const char *dummy)
{
	if (onu_iocmd(fd, FIO_GTC_ALARM_GET, &gtc_alarm, sizeof(gtc_alarm)) != 0)
		memset(&gtc_alarm, 0, sizeof(gtc_alarm));

	return 14 + 1;
}

char *gtc_alarms_table_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text, "%-50s %s", "OPTION", "VALUE");

	} else {
		switch (entry) {
		case 0:
			sprintf(text, "%-50s %d", "Signal fail",
				gtc_alarm.sig_fail);

			break;
		case 1:
			sprintf(text, "%-50s %d", "Signal degrade",
				gtc_alarm.sig_degrade);

			break;
		case 2:
			sprintf(text, "%-50s %d", "Loss of Signal",
				gtc_alarm.loss_of_signal);

			break;
		case 3:
			sprintf(text, "%-50s %d", "Loss of GEM frame",
				gtc_alarm.loss_of_gem_frame);

			break;
		case 4:
			sprintf(text, "%-50s %d", "GEM frame starvation",
				gtc_alarm.gem_frame_starvation);

			break;
		case 5:
			sprintf(text, "%-50s %d", "Loss of GTC frame",
				gtc_alarm.loss_of_gtc_frame);

			break;
		case 6:
			sprintf(text, "%-50s %d", "Loss of GTC superframe",
				gtc_alarm.loss_of_gtc_superframe);

			break;
		case 7:
			sprintf(text, "%-50s %d", "PLOAM receive error",
				gtc_alarm.ploam_rx_error);

			break;
		case 8:
			sprintf(text, "%-50s %d", "PLOAM receive buffer error",
				gtc_alarm.ploam_rx_buffer_error);

			break;
		case 9:
			sprintf(text, "%-50s %d", "PLOAM transmit buffer error",
				gtc_alarm.ploam_tx_buffer_error);

			break;
		case 10:
			sprintf(text, "%-50s %d", "Counter overflow",
				gtc_alarm.counter_overflow);

			break;
		case 11:
			sprintf(text, "%-50s %d", "Plen reception warning",
				gtc_alarm.plen_warning);

			break;
		case 12:
			sprintf(text, "%-50s %d", "Plen reception error",
				gtc_alarm.plen_error);

			break;
		case 13:
			sprintf(text, "%-50s %d", "Physical Equipment Error received from OLT",
				gtc_alarm.physical_equipment_error);

			break;
		case 14:
#define BWMBIT(BIT, IF_SET) ((gtc_alarm.loss_of_allocation & (BIT)) ? IF_SET : "")
			sprintf(text, "%-50s %d %s%s%s%s%s%s%s%s%s%s", "Loss of allocation",
				gtc_alarm.loss_of_allocation,
				BWMBIT(GTC_BWMSTAT_OVH_SZ, "OVH_SZ"),
				BWMBIT(GTC_BWMSTAT_DAT_SZ, "DAT_SZ "),
				BWMBIT(GTC_BWMSTAT_PAR_SZ, "PAR_SZ "),
				BWMBIT(GTC_BWMSTAT_START, "START "),
				BWMBIT(GTC_BWMSTAT_STOP, "STOP "),
				BWMBIT(GTC_BWMSTAT_MIN_TC, "MIN_TC "),
				BWMBIT(GTC_BWMSTAT_PLOGAP, "PLOGAP "),
				BWMBIT(GTC_BWMSTAT_TCOVLP, "TCOVLP "),
				BWMBIT(GTC_BWMSTAT_NO_GEM, "NO_GEM "),
				BWMBIT(GTC_BWMSTAT_SWT, "SWT ")
				);
#undef BWMBIT
			break;

		default:
			sprintf(text, "???");
			break;
		}
	}

	return NULL;
}

static struct gtc_bwmt_status gtc_bwmt_status;
static struct gtc_bwmt_cfg gtc_bwmt_cfg;

int gtc_bwmtrace_table_get(const int fd, const char *dummy)
{
	if (onu_iocmd(fd, FIO_GTC_BWMT_STATUS_GET, &gtc_bwmt_status,
		      sizeof(gtc_bwmt_status)) != 0)
		memset(&gtc_bwmt_status, 0, sizeof(gtc_bwmt_status));

	if (onu_iocmd(fd, FIO_GTC_BWMT_CFG_GET, &gtc_bwmt_cfg,
		      sizeof(gtc_bwmt_cfg)) != 0)
		memset(&gtc_bwmt_cfg, 0, sizeof(gtc_bwmt_cfg));

	return 20 + 1;
}

char *gtc_bwmtrace_table_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text, "%-50s %s", "OPTION", "VALUE");

	} else {
		switch (entry) {
		case 0:
			sprintf(text, "%-50s %d", "BWM trace enable",
				gtc_bwmt_cfg.trace_enable);
			break;
		case 1:
			sprintf(text, "%-50s %d", "BWMSTAT: GTC overhead size trigger",
				gtc_bwmt_status.overhead_size_enable);
			break;
		case 2:
			sprintf(text, "%-50s %d", "BWMSTAT: GTC data size trigger",
				gtc_bwmt_status.data_size_enable);
			break;
		case 3:
			sprintf(text, "%-50s %d", "BWMSTAT: FEC parity size trigger",
				gtc_bwmt_status.parity_size_enable);
			break;
		case 4:
			sprintf(text, "%-50s %d", "BWMSTAT: Start time trigger",
				gtc_bwmt_status.start_time_enable);
			break;
		case 5:
			sprintf(text, "%-50s %d", "BWMSTAT: Stop time trigger",
				gtc_bwmt_status.stop_time_enable);
			break;
		case 6:
			sprintf(text, "%-50s %d", "BWMSTAT: Start/stop trigger",
				gtc_bwmt_status.start_stop_enable);
			break;
		case 7:
			sprintf(text, "%-50s %d", "BWMSTAT: PLOu size trigger",
				gtc_bwmt_status.plou_enable);
			break;
		case 8:
			sprintf(text, "%-50s %d", "BWMSTAT: T-CONT overlap trigger",
				gtc_bwmt_status.overlap_enable);
			break;
		case 9:
			sprintf(text, "%-50s %d", "BWMSTAT: No GEM data trigger",
				gtc_bwmt_status.no_gem_enable);
			break;
		case 10:
			sprintf(text, "%-50s %d", "BWMSTAT: Software trigger enable",
				gtc_bwmt_status.sw_trigger);
			break;
		case 11:
			sprintf(text, "%-50s %d", "BWMTMASK: GTC overhead size trigger",
				gtc_bwmt_cfg.overhead_size_enable);
			break;
		case 12:
			sprintf(text, "%-50s %d", "BWMTMASK: GTC data size trigger",
				gtc_bwmt_cfg.data_size_enable);
			break;
		case 13:
			sprintf(text, "%-50s %d", "BWMTMASK: FEC parity size trigger",
				gtc_bwmt_cfg.parity_size_enable);
			break;
		case 14:
			sprintf(text, "%-50s %d", "BWMTMASK: Start time trigger",
				gtc_bwmt_cfg.start_time_enable);
			break;
		case 15:
			sprintf(text, "%-50s %d", "BWMTMASK: Stop time trigger",
				gtc_bwmt_cfg.stop_time_enable);
			break;
		case 16:
			sprintf(text, "%-50s %d", "BWMTMASK: Start/stop trigger",
				gtc_bwmt_cfg.start_stop_enable);
			break;
		case 17:
			sprintf(text, "%-50s %d", "BWMTMASK: PLOu size trigger",
				gtc_bwmt_cfg.plou_enable);
			break;
		case 18:
			sprintf(text, "%-50s %d", "BWMTMASK: T-CONT overlap trigger",
				gtc_bwmt_cfg.overlap_enable);
			break;
		case 19:
			sprintf(text, "%-50s %d", "BWMTMASK: No GEM data trigger",
				gtc_bwmt_cfg.no_gem_enable);
			break;
		case 20:
			sprintf(text, "%-50s %d", "BWMTMASK: Software trigger enable",
				gtc_bwmt_cfg.sw_trigger);
			break;
		default:
			sprintf(text, "???");
			break;
		}
	}

	return NULL;
}

static union gtc_counter_get_u gtc_counter;

int gtc_counters_table_get(const int fd, const char *dummy)
{
	gtc_counter.in.reset_mask = 0;
	gtc_counter.in.curr = 1;

	if (onu_iocmd(fd, FIO_GTC_COUNTER_GET, &gtc_counter, sizeof(gtc_counter)) != 0)
		memset(&gtc_counter, 0, sizeof(gtc_counter));

	return 20;
}

char *gtc_counters_table_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text, "%-50s %s", "OPTION", "VALUE");

	} else {
		switch (entry) {
		case 0:
			sprintf(text, "%-50s %llu", "Received BIP errors",
				gtc_counter.out.val.bip);

			break;
		case 1:
			sprintf(text, "%-50s %llu", "Received correctable HEC errors",
				gtc_counter.out.val.hec_error_corr);
			break;
		case 2:
			sprintf(text, "%-50s %llu", "Received uncorrectable HEC errors",
				gtc_counter.out.val.hec_error_uncorr);
			break;
		case 3:
			sprintf(text, "%-50s %llu", "Received correctable bandwidth map errors",
				gtc_counter.out.val.bwmap_error_corr);
			break;
		case 4:
			sprintf(text, "%-50s %llu", "Received uncorrectable bandwidth map errors",
				gtc_counter.out.val.bwmap_error_uncorr);
			break;
		case 5:
			sprintf(text, "%-50s %llu", "Number of corrected FEC bytes",
				gtc_counter.out.val.fec_error_corr);
			break;
		case 6:
			sprintf(text, "%-50s %llu", "Number of corrected FEC code words",
				gtc_counter.out.val.fec_words_corr);
			break;
		case 7:
			sprintf(text, "%-50s %llu", "Number of uncorrectable FEC code words",
				gtc_counter.out.val.fec_words_uncorr);
			break;
		case 8:
			sprintf(text, "%-50s %llu", "Total number of received FEC code words",
				gtc_counter.out.val.fec_words_total);
			break;
		case 9:
			sprintf(text, "%-50s %llu", "Total number of transmitted GEM frames",
				gtc_counter.out.val.tx_gem_frames_total);
			break;
		case 10:
			sprintf(text, "%-50s %llu", "Total number of transmitted GEM payload bytes",
				gtc_counter.out.val.tx_gem_bytes_total);
			break;
		case 11:
			sprintf(text, "%-50s %llu", "Total number of transmitted GEM Idle Frames",
				gtc_counter.out.val.tx_gem_idle_frames_total);
			break;
		case 12:
			sprintf(text, "%-50s %llu", "Received GEM frames/packets",
				gtc_counter.out.val.rx_gem_frames_total);
			break;
		case 13:
			sprintf(text, "%-50s %llu", "Received GEM payload bytes",
				gtc_counter.out.val.rx_gem_bytes_total);
			break;
		case 14:
			sprintf(text, "%-50s %llu", "dropped GEM frames",
				gtc_counter.out.val.rx_gem_frames_dropped);
			break;
		case 15:
			sprintf(text, "%-50s %llu", "Dropped bad OMCI frames/packets",
				gtc_counter.out.val.omci_drop);
			break;
		case 16:
			sprintf(text, "%-50s %llu", "All dropped frames/packets",
				gtc_counter.out.val.drop);
			break;
		case 17:
			sprintf(text, "%-50s %llu", "Oversized frames/packets",
				gtc_counter.out.val.rx_oversized_frames);
			break;
		case 18:
			sprintf(text, "%-50s %llu", "Count all TCONTs of this ONU",
				gtc_counter.out.val.allocations_total);
			break;
		case 19:
			sprintf(text, "%-50s %llu", "GTC Rejected TCONT Counter",
				gtc_counter.out.val.allocations_lost);
			break;
		default:
			sprintf(text, "???");
			break;

		}
	}

	return NULL;
}
