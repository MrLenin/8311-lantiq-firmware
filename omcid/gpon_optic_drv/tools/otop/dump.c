/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "drv_optic_config.h"
#endif

#include "dump.h"
#include "optic_top.h"

#include "drv_optic_interface.h"
#include "drv_optic_goi_interface.h"
#include "drv_optic_fcsi_interface.h"
#include "drv_optic_mm_interface.h"
#include "drv_optic_mpd_interface.h"
#include "drv_optic_omu_interface.h"
#include "drv_optic_bosa_interface.h"
#include "drv_optic_cal_interface.h"
#include "drv_optic_dcdc_apd_interface.h"
#include "drv_optic_dcdc_core_interface.h"
#include "drv_optic_dcdc_ddr_interface.h"
#include "drv_optic_ldo_interface.h"

#ifdef LINUX

#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>




static void optic_float2int ( int32_t float_val,
			      uint8_t shift,
			      uint16_t dec_factor,
			      uint16_t *ib,
			      uint16_t *fb,
			      bool *sign )
{
	uint32_t temp;

	if ((ib == NULL) || (fb == NULL))
		return;

	temp = abs(float_val);
	*ib = (temp >> shift);

	if (sign != NULL) {
		if (float_val < abs(float_val))
			*sign = true;
		else
			*sign = false;
	}

	*fb = (temp & ((1<<shift) -1));

	temp = (*fb * dec_factor) + (1<<(shift-1));
	*fb = (temp >> shift);

	if (*fb >= dec_factor) {
		(*ib) ++;
		(*fb) -= dec_factor;
	}
#if 0
	/* will not work for *ib == 0 */
	if (sign == true)
		(*ib) *= -1;
#endif
}

static void optic_float2uint ( int32_t float_val,
			       uint8_t shift,
			       uint16_t dec_factor,
			       uint16_t *ib,
			       uint16_t *fb )
{
	optic_float2int ( float_val, shift, dec_factor, ib, fb, NULL );
}


int table_get_version ( void )
{
	return file_read(2, "/proc/driver/optic/version",
			    "/proc/driver/optic/status");
}

void table_entry_get_version ( int entry, char *text )
{
	if (entry == -1)
		sprintf(text, "Version & status information");
	else
		strcpy(text, file_line_get(entry));
}


static struct optic_goi_config goi_cfg;
static struct optic_mm_config mm_cfg;
static struct optic_mpd_config mpd_cfg;
static struct optic_omu_config omu_cfg;
static struct optic_bosa_rx_config bosa_rx_cfg;
static struct optic_bosa_tx_config bosa_tx_cfg;
static struct optic_dcdc_apd_config apd_cfg;
static struct optic_dcdc_core_config core_cfg;

int table_get_config(void)
{
	struct optic_exchange ex;

	/* get optic_goi_config */
	ex.error = 0;
	ex.length = sizeof(goi_cfg);
	ex.p_data = (void *)&goi_cfg;

	if (ioctl(fd_dev, FIO_GOI_CFG_GET, &ex) < 0)
	memset(&goi_cfg, 0, sizeof(goi_cfg));

	/* get optic_mm_config */
	ex.error = 0;
	ex.length = sizeof(mm_cfg);
	ex.p_data = (void *)&mm_cfg;

	if (ioctl(fd_dev, FIO_MM_CFG_GET, &ex) < 0)
		memset(&mm_cfg, 0, sizeof(mm_cfg));

	/* get optic_mpd_config */
	ex.error = 0;
	ex.length = sizeof(mpd_cfg);
	ex.p_data = (void *)&mpd_cfg;

	if (ioctl(fd_dev, FIO_MPD_CFG_GET, &ex) < 0)
		memset(&mpd_cfg, 0, sizeof(mpd_cfg));

	/* get optic_omu_config */
	ex.error = 0;
	ex.length = sizeof(omu_cfg);
	ex.p_data = (void *)&omu_cfg;

	if (ioctl(fd_dev, FIO_OMU_CFG_GET, &ex) < 0)
		memset(&omu_cfg, 0, sizeof(omu_cfg));

	/* get optic_bosa_config */
	ex.error = 0;
	ex.length = sizeof(bosa_rx_cfg);
	ex.p_data = (void *)&bosa_rx_cfg;

	if (ioctl(fd_dev, FIO_BOSA_RX_CFG_GET, &ex) < 0)
		memset(&bosa_rx_cfg, 0, sizeof(bosa_rx_cfg));

	ex.error = 0;
	ex.length = sizeof(bosa_tx_cfg);
	ex.p_data = (void *)&bosa_tx_cfg;

	if (ioctl(fd_dev, FIO_BOSA_TX_CFG_GET, &ex) < 0)
		memset(&bosa_tx_cfg, 0, sizeof(bosa_tx_cfg));

	/* get optic_dcdc_apd_config */
	ex.error = 0;
	ex.length = sizeof(apd_cfg);
	ex.p_data = (void *)&apd_cfg;

	if (ioctl(fd_dev, FIO_DCDC_APD_CFG_GET, &ex) < 0)
	memset(&apd_cfg, 0, sizeof(apd_cfg));

	/* get optic_dcdc_core_config */
	ex.error = 0;
	ex.length = sizeof(core_cfg);
	ex.p_data = (void *)&core_cfg;

	if (ioctl(fd_dev, FIO_DCDC_CORE_CFG_GET, &ex) < 0)
	memset(&core_cfg, 0, sizeof(core_cfg));


	return 31;
}

void table_entry_get_config ( int entry, char *text )
{
	uint16_t r_low, tscal_ref_low, scal_ref_low[3], dark_corr_low, low[2],
	         p_low[2];
	uint16_t r_high, tscal_ref_high, scal_ref_high[3], dark_corr_high,
	         high[2], p_high[2];
	char str[6], str_[6];

	switch (entry) {
	case -1:
		sprintf(text, "%-50s %s", "OPTION", "VALUE");
		break;
	case 0:
		sprintf(text, "%-50s %dms", "temperature monitor interval",
			goi_cfg.temperature_check_time);
		break;
	case 1:
		sprintf(text, "%-50s %dK", "temperature threshold for MPD (re)correction",
			goi_cfg.temperature_thres_mpdcorr);
		break;
	case 2:
		sprintf(text, "%-50s %ds", "update cycle of laser age",
			goi_cfg.update_laser_age);
		break;
	case 3:
		sprintf(text, "%-50s %dK  %dK", "yellow temperature alarm (set/clear)",
			goi_cfg.temp_alarm_yellow_set,
			goi_cfg.temp_alarm_yellow_clear);
		break;
	case 4:
		sprintf(text, "%-50s %dK  %dK", "red temperature alarm (set/clear)",
			goi_cfg.temp_alarm_red_set,
			goi_cfg.temp_alarm_red_clear);
		break;
	case 5:
		sprintf(text, "%-50s %s  %s  %s", "polarity [rx, bias, modulation]",
			(goi_cfg.rx_polarity_regular == true) ?
			"regular" : "inverse",
			(goi_cfg.bias_polarity_regular == true) ?
			"regular" : "inverse",
			(goi_cfg.mod_polarity_regular == true) ?
			"regular" : "inverse");
		break;
	case 6:
		sprintf(text, "%-50s %dbit  %dbit  %dbit",
			"FIFO: enable delay, disable~, fifo size",
			goi_cfg.delay_tx_enable, goi_cfg.delay_tx_disable,
			goi_cfg.size_tx_fifo);
		break;
	case 7:
		optic_float2uint ( mm_cfg.tscal_ref,
		                  OPTIC_FLOAT2INTSHIFT_TSCALREF,
				  100, &tscal_ref_high, &tscal_ref_low );

		optic_float2uint ( mm_cfg.pn_r,
		                  OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE,
				  100, &r_high, &r_low );

		switch (mm_cfg.pn_iref) {
		case OPTIC_IREF_20UA:
			sprintf(str, "20uA");
			break;
		case OPTIC_IREF_100UA:
			sprintf(str, "100uA");
			break;
		case OPTIC_IREF_400UA:
			sprintf(str, "400uA");
			break;
		default:
			break;
		}

		sprintf(text, "%-50s %d.%02dK/mV  %d.%02dV/A  %s", "MM: tscal_ref, pn_r, pn_iref",
			tscal_ref_high, tscal_ref_low,
			r_high, r_low, str);
		break;
	case 8:
		optic_float2uint ( mm_cfg.rssi_1490_dark_corr,
		                  OPTIC_FLOAT2INTSHIFT_PSCALREF,
				  100, &dark_corr_high, &dark_corr_low );

		sprintf(text, "%-50s %s  %dV/A  %d.%02d",
			"MM: RSSI 1490 mode, shunt resistor, dark corr",
			(mm_cfg.rssi_1490_mode == OPTIC_RSSI_1490_DIFFERENTIAL)
			? "differential" : "single-ended",
			mm_cfg.rssi_1490_shunt_res,
			dark_corr_high, dark_corr_low);
		break;
	case 9:
		switch (mm_cfg.rssi_1550_vref) {
		case OPTIC_VREF_500MV:
			sprintf(str, "0.5V");
			break;
		case OPTIC_VREF_1000MV:
			sprintf(str, "1.0V");
			break;
		case OPTIC_VREF_1500MV:
			sprintf(str, "1.5V");
			break;
		default:
			sprintf(str, "n/a");
			break;
		}

		switch (mm_cfg.rf_1550_vref) {
		case OPTIC_VREF_500MV:
			sprintf(str_, "0.5V");
			break;
		case OPTIC_VREF_1000MV:
			sprintf(str_, "1.0V");
			break;
		case OPTIC_VREF_1500MV:
			sprintf(str_, "1.5V");
			break;
		default:
			sprintf(str_, "n/a");
			break;
		}

		sprintf(text, "%-50s %s  %s", "MM: vref [RSSI 1550, RF 1550]",
			str, str_);
		break;
	case 10:
		optic_float2uint ( mm_cfg.rssi_1490_scal_ref,
		                  OPTIC_FLOAT2INTSHIFT_PSCALREF,
				  1000, &scal_ref_high[0], &scal_ref_low[0] );
		optic_float2uint ( mm_cfg.rssi_1550_scal_ref,
		                  OPTIC_FLOAT2INTSHIFT_PSCALREF,
				  1000, &scal_ref_high[1], &scal_ref_low[1] );
		optic_float2uint ( mm_cfg.rf_1550_scal_ref,
		                  OPTIC_FLOAT2INTSHIFT_PSCALREF,
				  1000, &scal_ref_high[2], &scal_ref_low[2] );

		sprintf(text, "%-50s %d.%03dV  %d.%03dmA  %d.%03dmA ",
			"MM: scal_ref [RSSI 1490, RSSI 1550, RF 1550]",
			scal_ref_high[0], scal_ref_low[0],
			scal_ref_high[1], scal_ref_low[1] ,
			scal_ref_high[2], scal_ref_low[2]  );
		break;
	case 11:
		sprintf(text, "%-50s %d  0x%X  %s",
			"MPD: CID P0 size, mask, match-all",
			mpd_cfg.cid_size_p0, mpd_cfg.cid_mask_p0,
			(mpd_cfg.cid_match_all_p0)? "yes" : "no");
		break;
	case 12:
		sprintf(text, "%-50s %d  0x%X  %s",
			"MPD: CID P1 size, mask, match-all",
			mpd_cfg.cid_size_p1, mpd_cfg.cid_mask_p1,
			(mpd_cfg.cid_match_all_p1)? "yes" : "no");
		break;
	case 13:
		sprintf(text, "%-50s %s",
			"MPD: power save mode",
			(mpd_cfg.powersave == OPTIC_ENABLE)?
			"active  " : "inactive");
		break;
	case 14:
		sprintf(text, "%-50s %s  %d",
			"OMU: signal detect available, ~ port",
			(omu_cfg.signal_detect_avail)? "yes" : "no",
			omu_cfg.signal_detect_port);
		break;
	case 15:
		sprintf(text, "%-50s %d%s  %d%s",
			"OMU: threshold LOL set, clear",
			omu_cfg.threshold_lol_set,"%%",
			omu_cfg.threshold_lol_clear,"%%");
		break;
	case 16:
		sprintf(text, "%-50s %s",
			"OMU: laser enable signal",
			(omu_cfg.laser_enable_single_ended)? "single-ended" :
			"differential");
		break;
	case 17:
		sprintf(text, "%-50s %d%s  %d%s",
			"BOSA: threshold_lol_set, ~clear",
			bosa_rx_cfg.threshold_lol_set,"%%",
			bosa_rx_cfg.threshold_lol_clear,"%%");
		break;
	case 18:
		optic_float2uint ( bosa_rx_cfg.threshold_los,
		                  OPTIC_FLOAT2INTSHIFT_POWER,
				  1000, &p_high[0], &p_low[0] );

		optic_float2uint ( bosa_rx_cfg.threshold_rx_overload,
		                  OPTIC_FLOAT2INTSHIFT_POWER,
				  1000, &p_high[1], &p_low[1] );

		sprintf(text, "%-50s %d.%03dmW  %d.%03dmW",
			"BOSA: threshold LOS, threshold overload",
			p_high[0], p_low[0],
			p_high[1], p_low[1] );
		break;
	case 19:
		sprintf(text, "%-50s %s  0x%08X",
			"BOSA: dead zone elimination, pi control",
			(bosa_rx_cfg.dead_zone_elimination)? "yes" : "no",
			bosa_tx_cfg.pi_control);
		break;
	case 20:
		sprintf(text, "%-50s %1d  %1d",
			"BOSA: init integr.coeff. bias, modulation",
			bosa_tx_cfg.intcoeff_init[OPTIC_BIAS],
			bosa_tx_cfg.intcoeff_init[OPTIC_MOD]);
		break;
	case 21:
		sprintf(text, "%-50s %d%s  %d%s",
			"BOSA: update threshold bias, modulation",
			bosa_tx_cfg.updatethreshold[OPTIC_BIAS], "%%",
			bosa_tx_cfg.updatethreshold[OPTIC_MOD], "%%");
		break;
	case 22:
		sprintf(text, "%-50s %d%s  %d%s",
			"BOSA: learn threshold bias, modulation",
			bosa_tx_cfg.learnthreshold[OPTIC_BIAS], "%%",
			bosa_tx_cfg.learnthreshold[OPTIC_MOD], "%%");
		break;
	case 23:
		sprintf(text, "%-50s %d%s  %d%s",
			"BOSA: stable threshold (vs. average) bias, mod",
			bosa_tx_cfg.stablethreshold[OPTIC_BIAS], "%%",
			bosa_tx_cfg.stablethreshold[OPTIC_MOD], "%%");
		break;
	case 24:
		sprintf(text, "%-50s %d%s  %d%s",
			"BOSA: reset threshold (vs. init) bias, mod",
			bosa_tx_cfg.resetthreshold[OPTIC_BIAS], "%%",
			bosa_tx_cfg.resetthreshold[OPTIC_MOD], "%%");
		break;
	case 25:
		sprintf(text, "%-50s %4duW  %4duW  %4duW",
			"BOSA: P0 [ref, -3dB, -6dB]",
			bosa_tx_cfg.p0[0],
			bosa_tx_cfg.p0[1],
			bosa_tx_cfg.p0[2]);
		break;
	case 26:
		sprintf(text, "%-50s %4duW  %4duW  %4duW",
			"BOSA: P1 [ref, -3dB, -6dB]",
			bosa_tx_cfg.p1[0],
			bosa_tx_cfg.p1[1],
			bosa_tx_cfg.p1[2]);
		break;
	case 27:
		sprintf(text, "%-50s %4duW",
			"BOSA: Pth",
			bosa_tx_cfg.pth);
		break;
	case 28:
		sprintf(text, "%-50s %dV/A  %dV/A", "DCDC APD: r_diff low, high",
			apd_cfg.r_diff[0], apd_cfg.r_diff[1]);
		break;
	case 29:
		optic_float2uint ( core_cfg.v_min,
		                  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  1000, &high[0], &low[0] );

		optic_float2uint ( core_cfg.v_max,
		                  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  1000, &high[1], &low[1] );


		sprintf(text, "%-50s %d.%03dV  %d.%03dV", "DCDC Core: voltage min, max",
			high[0], low[0], high[1], low[1]);
		break;
	case 30:
		sprintf(text, "%-50s %d%s  %d%s", "DCDC Core: input voltage tolerance, target~",
			core_cfg.v_tolerance_input, "%%",
			core_cfg.v_tolerance_input, "%%");
		break;
	default:
		text[0] = 0;
		break;
	}
}


static struct optic_range_config range;
int table_get_ranges(void)
{
	struct optic_exchange ex;

	/* get OPTIC_cfgParam_t */
	ex.error = 0;
	ex.length = sizeof(range);
	ex.p_data = (void *)&range;

	if (ioctl(fd_dev, FIO_GOI_RANGE_CFG_GET, &ex) < 0)
		memset(&range, 0, sizeof(range));

	return 12;
}

void table_entry_get_ranges ( int entry, char *text )
{
	uint16_t ibias_max_high, imod_max_high, ibiasimod_max_high,
	         v_min_high, v_max_high;
	uint16_t ibias_max_low, imod_max_low, ibiasimod_max_low,
	         v_min_low, v_max_low;

	switch (entry) {
	case -1:
		sprintf(text, "%-50s %s", "OPTION", "VALUE");
		break;
	case 0:
		sprintf(text, " ");
		break;
	case 1:
		sprintf(text, "%-50s %dK / %dK", "min/max corrected external temperature",
			range.tabletemp_extcorr_min,
			range.tabletemp_extcorr_max);
		break;
	case 2:
		sprintf(text, "%-50s %dK / %dK", "min/max nominal external temperature",
			range.tabletemp_extnom_min,
			range.tabletemp_extnom_max);
		break;
	case 3:
		sprintf(text, "%-50s %dK / %dK", "min/max corrected internal temperature",
			range.tabletemp_intcorr_min,
			range.tabletemp_intcorr_max);
		break;
	case 4:
		sprintf(text, "%-50s %dK / %dK", "min/max nominal internal temperature",
			range.tabletemp_intnom_min,
			range.tabletemp_intnom_max);
		break;
	case 5:
		optic_float2uint ( range.ibias_max, OPTIC_FLOAT2INTSHIFT_CURRENT,
				  100, &ibias_max_high, &ibias_max_low );

		optic_float2uint ( range.imod_max, OPTIC_FLOAT2INTSHIFT_CURRENT,
				  100, &imod_max_high, &imod_max_low );

		optic_float2uint ( range.ibiasimod_max,
			          OPTIC_FLOAT2INTSHIFT_CURRENT, 100,
			          &ibiasimod_max_high, &ibiasimod_max_low );

		sprintf(text, "%-50s %2d.%02dmA  %2d.%02dmA  %2d.%02dmA", "maximum ibias, imod, ibias+imod",
			ibias_max_high, ibias_max_low,
			imod_max_high, imod_max_low,
			ibiasimod_max_high, ibiasimod_max_low);
		break;
	case 6:
		sprintf(text, "%-50s %1d / %1d", "max integration coeeficient Bias/Modulation",
			range.intcoeff_max[OPTIC_BIAS],
			range.intcoeff_max[OPTIC_MOD]);
		break;
	case 7:
		optic_float2uint ( range.vapd_min, OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &v_min_high, &v_min_low );

		optic_float2uint ( range.vapd_max, OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &v_max_high, &v_max_low );

		sprintf(text, "%-50s %d.%02dV / %d.%02dV", "min/max DCDC APD voltage",
			v_min_high, v_min_low,
			v_max_high, v_max_low );
		break;
	case 8:
		sprintf(text, "%-50s %d / %d", "min/max DCDC APD saturation",
			range.sat_min, range.sat_max );
		break;
	case 9:
		optic_float2uint ( range.vcore_min, OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &v_min_high, &v_min_low );

		optic_float2uint ( range.vcore_max, OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &v_max_high, &v_max_low );

		sprintf(text, "%-50s %d.%02dV / %d.%02dV", "min/max DCDC CORE voltage",
			v_min_high, v_min_low,
			v_max_high, v_max_low );
		break;
	case 10:
		optic_float2uint ( range.vddr_min, OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &v_min_high, &v_min_low );

		optic_float2uint ( range.vddr_max, OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &v_max_high, &v_max_low );

		sprintf(text, "%-50s %d.%02dV / %d.%02dV", "min/max DCDC DDR voltage",
			v_min_high, v_min_low,
			v_max_high, v_max_low );
		break;
        default:
		text[0] = 0;
		break;
	}
}



int table_get_temperature ( void )
{
	int line = file_read(1, "/proc/driver/optic/temptable");

	if (line != 0)
		line += 1;

	return line;
}

void table_entry_get_temperature (int entry , char *text )
{
	if (entry == -1) {
		sprintf(text, "temperature tables");
	} else
	if (entry == 0) {
		sprintf(text, " ");
	} else
	if ((entry > 0) && (entry < table_get_temperature())) {
		strcpy(text, file_line_get(entry-1));
	}
}

int table_get_temptrans ( void )
{
	int line = file_read(1, "/proc/driver/optic/temptrans");

	if (line != 0)
		line += 1;

	return line;
}

void table_entry_get_temptrans (int entry , char *text )
{
	if (entry == -1) {
		sprintf(text, "temperature translation table");
	} else
	if (entry == 0) {
		sprintf(text, " ");
	} else
	if ((entry > 0) && (entry < table_get_temptrans())) {
		strcpy(text, file_line_get(entry-1));
	}
}


int table_get_gain(void)
{
	int line = file_read(1, "/proc/driver/optic/gainset");

	if (line != 0)
		line += 1;

	return line;
}

void table_entry_get_gain ( int entry, char *text )
{
	if (entry == -1) {
		sprintf(text, "gain settings");
	} else
	if (entry == 0) {
		sprintf(text, " ");
	} else
	if ((entry > 0) && (entry < table_get_gain())) {
		strcpy(text, file_line_get(entry-1));
	}
}

static struct optic_fcsi_config fcsi_cfg;
static struct optic_fcsi_predriver fcsi_predriver;
static struct optic_debug_status dbg_status;
static union optic_gain_get mpd_gain[OPTIC_GAINBANK_MAX];
static union optic_cal_get mpd_cal[OPTIC_GAINBANK_MAX];
static struct optic_dbg_gain mpd_dbg_gain;
static struct optic_dbg_cal mpd_dbg_cal;
static struct optic_mpd_config mpd_cfg;
static union optic_refcw_get mpd_refcw[OPTIC_POWERLEVEL_MAX];
static struct optic_dbg_refcw mpd_dbg_refcw;
static union optic_tia_offset_get mpd_tia_offset[OPTIC_GAINBANK_MAX];
static struct optic_dbg_tia_offset mpd_dbg_tia_offset;
static struct optic_cfratio mpd_cfratio;
static struct optic_bosa_powerlevel bosa_powerlevel;

int table_get_monitor(void)
{
	uint8_t i;
	struct optic_exchange ex;

	ex.error = 0;
	ex.length = sizeof(struct optic_debug_status);
	ex.p_data = (void *)&dbg_status;

	if (ioctl(fd_dev, FIO_CAL_DEBUG_STATUS_GET, &ex) < 0)
		memset(&dbg_status, 0, sizeof(dbg_status));

	/* fcsi */
	ex.error = 0;
	ex.length = sizeof(struct optic_fcsi_config);
	ex.p_data = (void *)&fcsi_cfg;

	if (ioctl(fd_dev, FIO_FCSI_CFG_GET, &ex) < 0)
		memset(&fcsi_cfg, 0, sizeof(fcsi_cfg));

	ex.error = 0;
	ex.length = sizeof(struct optic_fcsi_predriver);
	ex.p_data = (void *)&fcsi_predriver;

	if (ioctl(fd_dev, FIO_CAL_FCSI_PREDRIVER_GET, &ex) < 0)
		memset(&fcsi_predriver, 0, sizeof(fcsi_predriver));


	/* gain */
	for (i=OPTIC_GAINBANK_PL0; i<OPTIC_GAINBANK_MAX; i++) {
		ex.error = 0;
		ex.length = sizeof(union optic_gain_get);
		ex.p_data = (void *)&(mpd_gain[i]);

		mpd_gain[i].in.gainbank = i;

		if (ioctl(fd_dev, FIO_CAL_MPD_GAIN_GET, &ex) < 0)
			memset(&(mpd_gain[i]), 0, sizeof(mpd_gain[i]));
	}

	/* cal */
	for (i=OPTIC_GAINBANK_PL0; i<OPTIC_GAINBANK_MAX; i++) {
		ex.error = 0;
		ex.length = sizeof(union optic_cal_get);
		ex.p_data = (void *)&(mpd_cal[i]);

		mpd_cal[i].in.gainbank = i;

		if (ioctl(fd_dev, FIO_CAL_MPD_CAL_CURRENT_GET, &ex) < 0)
			memset(&(mpd_cal[i]), 0, sizeof(mpd_cal[i]));
	}


	/* dbg gain */
	ex.error = 0;
	ex.length = sizeof(struct optic_dbg_gain);
	ex.p_data = (void *)&mpd_dbg_gain;

	if (ioctl(fd_dev, FIO_CAL_MPD_DBG_GAIN_GET, &ex) < 0)
		memset(&mpd_dbg_gain, 0, sizeof(mpd_dbg_gain));

	/* dbg cal */
	ex.error = 0;
	ex.length = sizeof(struct optic_dbg_cal);
	ex.p_data = (void *)&mpd_dbg_cal;

	if (ioctl(fd_dev, FIO_CAL_MPD_DBG_CAL_CURRENT_GET, &ex) < 0)
		memset(&mpd_dbg_cal, 0, sizeof(mpd_dbg_cal));

	/* mpd cfg */
	ex.error = 0;
	ex.length = sizeof(struct optic_mpd_config);
	ex.p_data = (void *)&mpd_cfg;

	if (ioctl(fd_dev, FIO_MPD_CFG_GET, &ex) < 0)
		memset(&mpd_cfg, 0, sizeof(mpd_cfg));

	/* ref_codeword */
	for (i=OPTIC_POWERLEVEL_0; i<OPTIC_POWERLEVEL_MAX; i++) {
		ex.error = 0;
		ex.length = sizeof(union optic_refcw_get);
		ex.p_data = (void *)&(mpd_refcw[i]);

		mpd_refcw[i].in.powerlevel = i;

		if (ioctl(fd_dev, FIO_CAL_MPD_REF_CODEWORD_GET, &ex) < 0)
			memset(&(mpd_refcw[i]), 0, sizeof(mpd_refcw[i]));
	}

	ex.error = 0;
	ex.length = sizeof(struct optic_dbg_refcw);
	ex.p_data = (void *)&mpd_dbg_refcw;

	if (ioctl(fd_dev, FIO_CAL_MPD_DBG_REF_CODEWORD_GET, &ex) < 0)
		memset(&mpd_dbg_refcw, 0, sizeof(mpd_dbg_refcw));

	/* offset */
	for (i=OPTIC_GAINBANK_PL0; i<OPTIC_GAINBANK_MAX; i++) {
		ex.error = 0;
		ex.length = sizeof(union optic_tia_offset_get);
		ex.p_data = (void *)&(mpd_tia_offset[i]);

		mpd_tia_offset[i].in.gainbank = i;

		if (ioctl(fd_dev, FIO_CAL_MPD_TIA_OFFSET_GET, &ex) < 0)
			memset(&(mpd_tia_offset[i]), 0, sizeof(mpd_tia_offset[i]));
	}

	ex.error = 0;
	ex.length = sizeof(struct optic_dbg_tia_offset);
	ex.p_data = (void *)&mpd_dbg_tia_offset;

	if (ioctl(fd_dev, FIO_CAL_MPD_DBG_TIA_OFFSET_GET, &ex) < 0)
		memset(&mpd_dbg_tia_offset, 0, sizeof(mpd_dbg_tia_offset));

	/* coarse-fine ratio */
	ex.error = 0;
	ex.length = sizeof(struct optic_cfratio);
	ex.p_data = (void *)&mpd_cfratio;

	if (ioctl(fd_dev, FIO_CAL_MPD_CFRATIO_GET, &ex) < 0)
		memset(&mpd_cfratio, 0, sizeof(mpd_cfratio));

	/* powerlevel */
	ex.error = 0;
	ex.length = sizeof(struct optic_bosa_powerlevel);
	ex.p_data = (void *)&bosa_powerlevel;

	if (ioctl(fd_dev, FIO_BOSA_POWERLEVEL_GET, &ex) < 0)
		memset(&bosa_powerlevel, 0, sizeof(bosa_powerlevel));



	return 13;
}

void table_entry_get_monitor ( int entry, char *text )
{
	uint8_t pl, gb, t;
	bool sign[OPTIC_POWERLEVEL_MAX];
	bool sign2;
	uint16_t scal_high[OPTIC_POWERLEVEL_MAX],
	         dcal_ref_p0_high[OPTIC_POWERLEVEL_MAX], dbg_dcal_ref_p0_high,
		 dcal_ref_p1_high[OPTIC_POWERLEVEL_MAX], dbg_dcal_ref_p1_high,
		 dref_p0_high[OPTIC_POWERLEVEL_MAX], dbg_dref_p0_high,
		 dref_p1_high[OPTIC_POWERLEVEL_MAX], dbg_dref_p1_high,
		 ratio_p0_high, ratio_p1_high;
	uint16_t scal_low[OPTIC_POWERLEVEL_MAX],
	         dcal_ref_p0_low[OPTIC_POWERLEVEL_MAX], dbg_dcal_ref_p0_low,
		 dcal_ref_p1_low[OPTIC_POWERLEVEL_MAX], dbg_dcal_ref_p1_low,
		 dref_p0_low[OPTIC_POWERLEVEL_MAX], dbg_dref_p0_low,
		 dref_p1_low[OPTIC_POWERLEVEL_MAX], dbg_dref_p1_low,
 		 ratio_p0_low, ratio_p1_low;

	switch (entry) {
	case -1:
		sprintf(text, "monitor calibrated settings");
		break;
	case 0:
		sprintf(text, " ");
		break;
	case 1:
		sprintf(text, "                            ref.       -3dB       -6dB       global    cal/dbg");
		break;
	case 2:
		sprintf(text, " tia gain sel (0x%04X):       %1d          %1d          %1d          %1d          %1d",
			fcsi_cfg.gvs,
			mpd_gain[OPTIC_GAINBANK_PL0].out.tia_gain_selector,
			mpd_gain[OPTIC_GAINBANK_PL1].out.tia_gain_selector,
			mpd_gain[OPTIC_GAINBANK_PL2].out.tia_gain_selector,
			mpd_gain[OPTIC_GAINBANK_GLOBAL].out.tia_gain_selector,
			mpd_dbg_gain.tia_gain_selector);
		break;
	case 3:
		t = sprintf(text, " MPD calibrat. current:");
		for (gb=OPTIC_GAINBANK_PL0; gb<OPTIC_GAINBANK_MAX; gb++) {
			switch (mpd_cal[gb].out.cal_current) {
				case OPTIC_CAL_OFF:
					t += sprintf(text + t, "      off  ");
					break;
				case OPTIC_CAL_OPEN:
					t += sprintf(text + t, "     open  ");
					break;
				case OPTIC_CAL_100UA:
					t += sprintf(text + t, "     100uA ");
					break;
				case OPTIC_CAL_1MA:
					t += sprintf(text + t, "      1mA  ");
					break;
				default:
					t += sprintf(text + t, "       -   ");
					break;
			}
		}
		switch (mpd_dbg_cal.cal_current) {
			case OPTIC_CAL_OFF:
				t += sprintf(text + t, "      off  ");
				break;
			case OPTIC_CAL_OPEN:
				t += sprintf(text + t, "     open  ");
				break;
			case OPTIC_CAL_100UA:
				t += sprintf(text + t, "     100uA ");
				break;
			case OPTIC_CAL_1MA:
				t += sprintf(text + t, "      1mA  ");
				break;
			default:
				t += sprintf(text + t, "       -   ");
				break;
		}
		break;
	case 4:
		for (pl=OPTIC_POWERLEVEL_0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
			optic_float2uint ( mpd_cfg.scalefactor_mod[pl],
		                	  OPTIC_FLOAT2INTSHIFT_CORRFACTOR,
		                	  1000, &(scal_high[pl]),
		                	  &(scal_low[pl]) );
		}

		sprintf(text, " scale factor Imod:         %1d.%03d      %1d.%03d      %1d.%03d",
			scal_high[OPTIC_POWERLEVEL_0],
			scal_low[OPTIC_POWERLEVEL_0],
			scal_high[OPTIC_POWERLEVEL_1],
			scal_low[OPTIC_POWERLEVEL_1],
			scal_high[OPTIC_POWERLEVEL_2],
			scal_low[OPTIC_POWERLEVEL_2]);

		break;
	case 5:
		for (pl=OPTIC_POWERLEVEL_0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
			optic_float2int ( mpd_refcw[pl].out.dcal_ref_p0,
		                	  OPTIC_FLOAT2INTSHIFT_DREF,
		                	  10, &(dcal_ref_p0_high[pl]),
		                	  &(dcal_ref_p0_low[pl]), &sign[pl] );
		}
		optic_float2int ( mpd_dbg_refcw.dcal_ref_p0,
		                  OPTIC_FLOAT2INTSHIFT_DREF, 10,
		                  &(dbg_dcal_ref_p0_high),
		                  &(dbg_dcal_ref_p0_low), &sign2 );
		sprintf(text, " P0 Dcal_ref:            %s%4d.%01d   %s%4d.%01d   %s%4d.%01d              %s%4d.%01d",
			(sign[OPTIC_POWERLEVEL_0] == true)? "-":"+",
			dcal_ref_p0_high[OPTIC_POWERLEVEL_0],
			dcal_ref_p0_low[OPTIC_POWERLEVEL_0],
			(sign[OPTIC_POWERLEVEL_1] == true)? "-":"+",
			dcal_ref_p0_high[OPTIC_POWERLEVEL_1],
			dcal_ref_p0_low[OPTIC_POWERLEVEL_1],
			(sign[OPTIC_POWERLEVEL_2] == true)? "-":"+",
			dcal_ref_p0_high[OPTIC_POWERLEVEL_2],
			dcal_ref_p0_low[OPTIC_POWERLEVEL_2],
			(sign2 == true)? "-":"+",
			dbg_dcal_ref_p0_high, dbg_dcal_ref_p0_low);
		break;
	case 6:
		for (pl=OPTIC_POWERLEVEL_0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
			optic_float2int ( mpd_refcw[pl].out.dcal_ref_p1,
		                	  OPTIC_FLOAT2INTSHIFT_DREF,
		                	  10, &(dcal_ref_p1_high[pl]),
		                	  &(dcal_ref_p1_low[pl]), &sign[pl] );
		}
		optic_float2int ( mpd_dbg_refcw.dcal_ref_p1,
		                  OPTIC_FLOAT2INTSHIFT_DREF, 10,
		                  &(dbg_dcal_ref_p1_high),
		                  &(dbg_dcal_ref_p1_low), &sign2 );
		sprintf(text, " P1 Dcal_ref:            %s%4d.%01d   %s%4d.%01d   %s%4d.%01d              %s%4d.%01d",
			(sign[OPTIC_POWERLEVEL_0] == true)? "-":"+",
			dcal_ref_p1_high[OPTIC_POWERLEVEL_0],
			dcal_ref_p1_low[OPTIC_POWERLEVEL_0],
			(sign[OPTIC_POWERLEVEL_1] == true)? "-":"+",
			dcal_ref_p1_high[OPTIC_POWERLEVEL_1],
			dcal_ref_p1_low[OPTIC_POWERLEVEL_1],
			(sign[OPTIC_POWERLEVEL_2] == true)? "-":"+",
			dcal_ref_p1_high[OPTIC_POWERLEVEL_2],
			dcal_ref_p1_low[OPTIC_POWERLEVEL_2],
			(sign2 == true)? "-":"+",
			dbg_dcal_ref_p1_high, dbg_dcal_ref_p1_low);
		break;
	case 7:
		for (pl=OPTIC_POWERLEVEL_0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
			optic_float2int ( mpd_refcw[pl].out.dref_p0,
		                	  OPTIC_FLOAT2INTSHIFT_DREF,
		                	  10, &(dref_p0_high[pl]),
		                	  &(dref_p0_low[pl]), &sign[pl] );
		}
		optic_float2int ( mpd_dbg_refcw.dref_p0,
		                  OPTIC_FLOAT2INTSHIFT_DREF, 10,
		                  &(dbg_dref_p0_high),
		                  &(dbg_dref_p0_low),  &sign2 );
		sprintf(text, " P0 Dref:                %s%4d.%01d   %s%4d.%01d   %s%4d.%01d              %s%4d.%01d",
			(sign[OPTIC_POWERLEVEL_0] == true)? "-":"+",
			dref_p0_high[OPTIC_POWERLEVEL_0],
			dref_p0_low[OPTIC_POWERLEVEL_0],
			(sign[OPTIC_POWERLEVEL_1] == true)? "-":"+",
			dref_p0_high[OPTIC_POWERLEVEL_1],
			dref_p0_low[OPTIC_POWERLEVEL_1],
			(sign[OPTIC_POWERLEVEL_2] == true)? "-":"+",
			dref_p0_high[OPTIC_POWERLEVEL_2],
			dref_p0_low[OPTIC_POWERLEVEL_2],
			(sign2 == true)? "-":"+",
			dbg_dref_p0_high, dbg_dref_p0_low);

		break;
	case 8:
		for (pl=OPTIC_POWERLEVEL_0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
			optic_float2int ( mpd_refcw[pl].out.dref_p1,
		                	  OPTIC_FLOAT2INTSHIFT_DREF,
		                	  10, &(dref_p1_high[pl]),
		                	  &(dref_p1_low[pl]), &sign[pl] );
		}
		optic_float2int ( mpd_dbg_refcw.dref_p1,
		                  OPTIC_FLOAT2INTSHIFT_DREF, 10,
		                  &(dbg_dref_p1_high),
		                  &(dbg_dref_p1_low),  &sign2 );
		sprintf(text, " P1 Dref:                %s%4d.%01d   %s%4d.%01d   %s%4d.%01d              %s%4d.%01d",
			(sign[OPTIC_POWERLEVEL_0] == true)? "-":"+",
			dref_p1_high[OPTIC_POWERLEVEL_0],
			dref_p1_low[OPTIC_POWERLEVEL_0],
			(sign[OPTIC_POWERLEVEL_1] == true)? "-":"+",
			dref_p1_high[OPTIC_POWERLEVEL_1],
			dref_p1_low[OPTIC_POWERLEVEL_1],
			(sign[OPTIC_POWERLEVEL_2] == true)? "-":"+",
			dref_p1_high[OPTIC_POWERLEVEL_2],
			dref_p1_low[OPTIC_POWERLEVEL_2],
			(sign2 == true)? "-":"+",
			dbg_dref_p1_high, dbg_dref_p1_low);
		break;
	case 9:
		sprintf(text, " tia offset c/f:           %3d/%-4d   %3d/%-4d   %3d/%-4d   %3d/%-4d   %3d/%-4d",
			mpd_tia_offset[OPTIC_GAINBANK_PL0].out.tia_offset_coarse,
			mpd_tia_offset[OPTIC_GAINBANK_PL0].out.tia_offset_fine,
			mpd_tia_offset[OPTIC_GAINBANK_PL1].out.tia_offset_coarse,
			mpd_tia_offset[OPTIC_GAINBANK_PL1].out.tia_offset_fine,
			mpd_tia_offset[OPTIC_GAINBANK_PL2].out.tia_offset_coarse,
			mpd_tia_offset[OPTIC_GAINBANK_PL2].out.tia_offset_fine,
			mpd_tia_offset[OPTIC_GAINBANK_GLOBAL].out.tia_offset_coarse,
			mpd_tia_offset[OPTIC_GAINBANK_GLOBAL].out.tia_offset_fine,
			mpd_dbg_tia_offset.tia_offset_coarse,
			mpd_dbg_tia_offset.tia_offset_fine);
		break;
	case 10:
		sprintf(text, " P1 delta offset c/f:      %3d/%-4d   %3d/%-4d   %3d/%-4d   %3d/%-4d   %3d/%-4d",
			mpd_tia_offset[OPTIC_GAINBANK_PL0].out.tia_offset_p1_coarse,
			mpd_tia_offset[OPTIC_GAINBANK_PL0].out.tia_offset_p1_fine,
			mpd_tia_offset[OPTIC_GAINBANK_PL1].out.tia_offset_p1_coarse,
			mpd_tia_offset[OPTIC_GAINBANK_PL1].out.tia_offset_p1_fine,
			mpd_tia_offset[OPTIC_GAINBANK_PL2].out.tia_offset_p1_coarse,
			mpd_tia_offset[OPTIC_GAINBANK_PL2].out.tia_offset_p1_fine,
			mpd_tia_offset[OPTIC_GAINBANK_GLOBAL].out.tia_offset_p1_coarse,
			mpd_tia_offset[OPTIC_GAINBANK_GLOBAL].out.tia_offset_p1_fine,
			mpd_dbg_tia_offset.tia_offset_p1_coarse,
			mpd_dbg_tia_offset.tia_offset_p1_fine);
		break;
	case 11:
		optic_float2uint ( mpd_cfratio.ratio_p0,
				  OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO, 100,
				  &(ratio_p0_high), &(ratio_p0_low) );

		sprintf(text, " coarse/fine ratio P0:                                                ");

		if (dbg_status.debug_enable)
			t = 28 + 4 * 11;
		else
			t = 28 + 3 * 11;

		sprintf(text + t, "%2d.%02d", ratio_p0_high, ratio_p0_low);
		break;
	case 12:
		optic_float2uint ( mpd_cfratio.ratio_p1,
				  OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO, 100,
				  &(ratio_p1_high), &(ratio_p1_low) );

		sprintf(text, " coarse/fine ratio P1:                                                ");

		if (dbg_status.debug_enable)
			t = 28 + 4 * 11;
		else
			t = 28 + 3 * 11;

		sprintf(text + t, "%2d.%02d", ratio_p1_high, ratio_p1_low);
		break;

	default:
	/*
if ((entry > 0) && (entry < table_get_monitor())) {
	strcpy(text, file_line_get(entry-12));
}
*/
		break;
	}
}

static struct optic_fusing fusing;

int table_get_fuses ( void )
{
	struct optic_exchange ex;

	ex.error = 0;
	ex.length = sizeof(struct optic_fusing);
	ex.p_data = (void *)&fusing;

	if (ioctl(fd_dev, FIO_CAL_FUSES_GET, &ex) < 0)
		memset(&fusing, 0, sizeof(fusing));

	return 9;
}

void table_entry_get_fuses (int entry, char *text )
{
	switch (entry) {
	case -1:
		sprintf(text, "%s ", "fusing register overview");
		break;
	case 0:
		sprintf(text, " ");
		break;
	case 1:
		sprintf(text, "%-50s %d",
			"fusing format:",
			fusing.format);
		break;
	case 2:
		sprintf(text, "%-50s %d  %d  %d   ",
			"VCALMM20, VCALMM100, VCALMM400:",
			fusing.vcal_mm20,
			fusing.vcal_mm100,
			fusing.vcal_mm400);
		break;
	case 3:
		sprintf(text, "%-50s %d  %d   ",
			"RCALMM, TEMPMM:",
			fusing.rcal_mm,
			fusing.temp_mm);
		break;
	case 4:
		sprintf(text, "%-50s %d  %d  %d   ",
			"TBGP, VBGP, IREFBGP:",
			fusing.tbgp,
			fusing.vbgp,
			fusing.irefbgp);
		break;
	case 5:
		sprintf(text, "%-50s %d  %d   ",
			"GAINDRIVEDAC, GAINBIASDAC:",
			fusing.gain_dac_drive,
			fusing.gain_dac_bias);
		break;
	case 6:
		sprintf(text, "%-50s %d  %d   ",
			"OFFSETDDRDCDC, GAINDDRDCDC:",
			fusing.offset_dcdc_ddr,
			fusing.gain_dcdc_ddr);
		break;
	case 7:
		sprintf(text, "%-50s %d  %d   ",
			"OFFSET1V0DCDC, GAIN1V0DCDC:",
			fusing.offset_dcdc_core,
			fusing.gain_dcdc_core);
		break;
	case 8:
		sprintf(text, "%-50s %d  %d   ",
			"OFFSETAPDDCDC, GAINAPDDCDC:",
			fusing.offset_dcdc_apd,
			fusing.gain_dcdc_apd);
		break;
	default:
		break;
	}
}

static struct optic_versionstring version;
static struct optic_ext_status status;
static struct optic_bosa_powerlevel powerlevel;
static struct optic_debug_status debug_status;
static struct optic_bosa_loopmode loopmode;
static struct optic_temperature temperature_laser;
static struct optic_temperature temperature_die;
static struct optic_timestamp timestamp;
static struct optic_dcdc_apd_status apd_status;
static struct optic_dcdc_core_status core_status;
static struct optic_dcdc_ddr_status ddr_status;
static struct optic_ldo_status ldo_status;
static struct optic_laserdelay laserdelay;
static struct optic_stable stable;
static struct optic_int_coeff int_coeff;
static union optic_level_get mpd_level[2];
static union optic_ibiasimod_get ibiasimod;
static struct optic_current_fine current_offset;
static union optic_vapd_get vapd;

int table_get_status ( void )
{
	struct optic_exchange ex;
	uint8_t i;

	ex.error = 0;
	ex.length = sizeof(struct optic_versionstring);
	ex.p_data = (void *)&version;

	if (ioctl(fd_dev, FIO_OPTIC_VERSION_GET, &ex) < 0)
		memset(&version, 0, sizeof(version));

	ex.error = 0;
	ex.length = sizeof(struct optic_ext_status);
	ex.p_data = (void *)&status;

	if (ioctl(fd_dev, FIO_GOI_EXT_STATUS_GET, &ex) < 0)
		memset(&status, 0, sizeof(status));

	ex.error = 0;
	ex.length = sizeof(struct optic_debug_status);
	ex.p_data = (void *)&debug_status;

	if (ioctl(fd_dev, FIO_CAL_DEBUG_STATUS_GET, &ex) < 0)
		memset(&debug_status, 0, sizeof(debug_status));

	ex.error = 0;
	ex.length = sizeof(struct optic_bosa_powerlevel);
	ex.p_data = (void *)&powerlevel;

	if (ioctl(fd_dev, FIO_BOSA_POWERLEVEL_GET, &ex) < 0)
		memset(&powerlevel, 0, sizeof(struct optic_bosa_powerlevel));

	ex.error = 0;
	ex.length = sizeof(struct optic_bosa_loopmode);
	ex.p_data = (void *)&loopmode;


	if (ioctl(fd_dev, FIO_BOSA_LOOPMODE_GET, &ex) < 0)
		memset(&loopmode, 0, sizeof(loopmode));

	ex.error = 0;
	ex.length = sizeof(struct optic_temperature);
	ex.p_data = (void *)&temperature_laser;

	if (ioctl(fd_dev, FIO_MM_LASER_TEMPERATURE_GET, &ex) < 0)
		memset(&temperature_laser, 0, sizeof(struct optic_temperature));

	ex.error = 0;
	ex.length = sizeof(struct optic_temperature);
	ex.p_data = (void *)&temperature_die;

	if (ioctl(fd_dev, FIO_MM_DIE_TEMPERATURE_GET, &ex) < 0)
		memset(&temperature_die, 0, sizeof(struct optic_temperature));

	ex.error = 0;
	ex.length = sizeof(struct optic_timestamp);
	ex.p_data = (void *)&timestamp;

	if (ioctl(fd_dev, FIO_CAL_LASER_AGE_GET, &ex) < 0)
		memset(&timestamp, 0, sizeof(struct optic_timestamp));

	ex.error = 0;
	ex.length = sizeof(union optic_ibiasimod_get);
	ibiasimod.in.temperature = temperature_laser.temperature;
	ibiasimod.in.powerlevel = powerlevel.powerlevel;
	ex.p_data = (void *)&ibiasimod;

	if (ioctl(fd_dev, FIO_CAL_IBIASIMOD_TABLE_GET, &ex) < 0)
		memset(&ibiasimod, 0, sizeof(union optic_ibiasimod_get));

	ex.error = 0;
	ex.length = sizeof(struct optic_stable);
	ex.p_data = (void *)&stable;

	if (ioctl(fd_dev, FIO_BOSA_STABLE_GET, &ex) < 0)
		memset(&stable, 0, sizeof(struct optic_stable));

	ex.error = 0;
	ex.length = sizeof(struct optic_int_coeff);
	ex.p_data = (void *)&int_coeff;

	if (ioctl(fd_dev, FIO_BOSA_INT_COEFF_GET, &ex) < 0)
		memset(&int_coeff, 0, sizeof(struct optic_int_coeff));

	/* dac levels */
	for (i=0; i<2; i++) {
		ex.error = 0;
		ex.length = sizeof(union optic_level_get);
		ex.p_data = (void *)&(mpd_level[i]);

		mpd_level[i].in.level_select = i;

		if (ioctl(fd_dev, FIO_CAL_MPD_LEVEL_GET, &ex) < 0)
			memset(&(mpd_level[i]), 0, sizeof(mpd_level[i]));
	}

	ex.error = 0;
	ex.length = sizeof(struct optic_current_fine);
	ex.p_data = (void *)&current_offset;

	if (ioctl(fd_dev, FIO_CAL_CURRENT_OFFSET_GET, &ex) < 0)
		memset(&current_offset, 0, sizeof(struct optic_current_fine));

	ex.error = 0;
	ex.length = sizeof(union optic_vapd_get);
	vapd.in.temperature = temperature_laser.temperature;
	ex.p_data = (void *)&vapd;

	if (ioctl(fd_dev, FIO_CAL_VAPD_TABLE_GET, &ex) < 0)
		memset(&vapd, 0, sizeof(union optic_vapd_get));

	ex.error = 0;
	ex.length = sizeof(struct optic_dcdc_apd_status);
	ex.p_data = (void *)&apd_status;

	if (ioctl(fd_dev, FIO_DCDC_APD_STATUS_GET, &ex) < 0)
		memset(&apd_status, 0, sizeof(struct optic_dcdc_apd_status));

	ex.error = 0;
	ex.length = sizeof(struct optic_dcdc_core_status);
	ex.p_data = (void *)&core_status;

	if (ioctl(fd_dev, FIO_DCDC_CORE_STATUS_GET, &ex) < 0)
		memset(&core_status, 0, sizeof(struct optic_dcdc_core_status));

	ex.error = 0;
	ex.length = sizeof(struct optic_dcdc_ddr_status);
	ex.p_data = (void *)&ddr_status;

	if (ioctl(fd_dev, FIO_DCDC_DDR_STATUS_GET, &ex) < 0)
		memset(&ddr_status, 0, sizeof(struct optic_dcdc_ddr_status));

	ex.error = 0;
	ex.length = sizeof(struct optic_ldo_status);
	ex.p_data = (void *)&ldo_status;

	if (ioctl(fd_dev, FIO_LDO_STATUS_GET, &ex) < 0)
		memset(&ldo_status, 0, sizeof(struct optic_ldo_status));

	ex.error = 0;
	ex.length = sizeof(struct optic_laserdelay);
	ex.p_data = (void *)&laserdelay;

	if (ioctl(fd_dev, FIO_CAL_LASERDELAY_GET, &ex) < 0)
		memset(&laserdelay, 0, sizeof(struct optic_laserdelay));

	return 35;
}

void table_entry_get_status (int entry, char *text )
{
	int32_t temp;
	uint16_t high[2];
	uint16_t low[2];
	bool sign, sign2;
	int i, t;
	char mode[4][6] = { " --- ", "OMU  ", "BOSA ", "BOSA2" };

	switch (entry) {
	case -1:
		sprintf(text, "%s ", "status overview");
		break;
	case 0:
		sprintf(text, " ");
		break;
	case 1:
		sprintf(text, "%-50s %X  (%d)", "chip version (fuse format):",
			status.chip, status.fuse_format);
		break;
	case 2:
		sprintf(text, "%-50s %s  (%s)", "driver version (otop version):",
			version.version, OPTIC_TOP_VERSION);
		break;
	case 3:
		t = sprintf(text, "%-50s ", "state history:");
		for (i=0; i<OPTIC_STATE_HISTORY_DEPTH; i++)
			t += sprintf( text + t, "%d ",
				      status.state_history[i]);
		break;
	case 4:
		t = sprintf(text, "%-50s ", "config reads:");
		for (i=0; i<OPTIC_CONFIGREAD_MAX; i++)
			t += sprintf( text + t, "%s ",
				      (status.config_read[i]) ? "+" : "-");
		break;
	case 5:
		t = sprintf(text, "%-50s ", "table reads:");
		for (i=0; i<OPTIC_TABLEREAD_MAX; i++)
			t += sprintf( text + t, "%s ",
				      (status.table_read[i]) ? "+" : "-");
		break;
	case 6:
		sprintf(text, "%-50s %s", "PLL lock status:",
			(status.pll_lock_status == true)?
			"locked    " : "not locked");
		break;
	case 7:
		sprintf(text, "%-50s %s  %s", "Signal detect, Lock on Signal:",
			(status.loss_of_signal == false)?
			"true " : "false",
			(status.loss_of_lock == false)?
			"true " : "false");
		break;
	case 8:
		sprintf(text, "%-50s %s (%d)", "manage mode (OMU/BOSA/BOSA2), powerlevel:",
			mode[(int)status.mode], powerlevel.powerlevel );
		break;
	case 9:
		sprintf(text, "%-50s %s  %s", "debug mode, bosa loop mode:",
			(debug_status.debug_enable == true)?
			"on " : "off",
			(loopmode.loop_mode == OPTIC_BOSA_DUALLOOP)?
			"dual-loop" :
			(loopmode.loop_mode == OPTIC_BOSA_OPENLOOP)?
			"open-loop": " no-loop ");
		break;
	case 10:
		sprintf(text, "%-50s %d:%02d:%02d", "laser age (active time):",
			timestamp.seconds / 3600,
			(timestamp.seconds / 60) % 60,
			timestamp.seconds % 60);
		break;
	case 11:
		t = sprintf(text, "%-50s ", "laser temperature (ext corr):");
		if (temperature_laser.temperature == 0xFFFF)
			sprintf(text + t, "not valid");
		else
			sprintf(text + t, "%dK     ",
				temperature_laser.temperature);
		break;
	case 12:
		t = sprintf(text, "%-50s ", "die temperature (int corr):");
		if (temperature_die.temperature == 0xFFFF)
			sprintf(text + t, "not valid");
		else
			sprintf(text + t, "%dK     ",
				temperature_die.temperature);
		break;
	case 13:
		sprintf(text, "%-50s %d", "rx offset correction:",
			status.rx_offset);
		break;
	case 14:
		optic_float2uint ( status.bias_max,
				  OPTIC_FLOAT2INTSHIFT_CURRENT,
				  100, &high[0], &low[0] );
		optic_float2uint ( status.mod_max,
				  OPTIC_FLOAT2INTSHIFT_CURRENT,
				  100, &high[1], &low[1] );
		sprintf(text, "%-50s %d.%02dmA / %d.%02dmA   ",
			"maximum bias / modulation current (chip):",
			high[0], low[0], high[1], low[1]);
		break;
	case 15:
		optic_float2uint ( ibiasimod.out.ibias,
				  OPTIC_FLOAT2INTSHIFT_CURRENT,
				  100, &high[0], &low[0] );
		optic_float2uint ( ibiasimod.out.imod,
				  OPTIC_FLOAT2INTSHIFT_CURRENT,
				  100, &high[1], &low[1] );
		sprintf(text, "%-50s %d.%02dmA / %d.%02dmA (%d)   ",
			"precalc. bias / modulation current:",
			high[0], low[0], high[1], low[1],
			ibiasimod.out.quality);
		break;
	case 16:
		optic_float2uint ( status.bias_current,
				  OPTIC_FLOAT2INTSHIFT_CURRENT,
				  100, &high[0], &low[0] );
		optic_float2uint ( status.modulation_current,
				  OPTIC_FLOAT2INTSHIFT_CURRENT,
				  100, &high[1], &low[1] );
		sprintf(text, "%-50s %d.%02dmA / %d.%02dmA   ",
			"actual bias / modulation current:",
			high[0], low[0], high[1], low[1]);
		break;
	case 17:
		if(loopmode.loop_mode == OPTIC_BOSA_OPENLOOP) {
			sprintf(text, "%-50s %s     ",
					"bias / modulation change:",
					"n/a");
		} else
		{
			sprintf(text, "%-50s %s / %s    ",
					"bias / modulation change:",
					(stable.stable[0] == true) ? "stable" : "unstable",
					(stable.stable[1] == true) ? "stable" : "unstable");
		}
		break;
	case 18:
		sprintf(text, "%-50s %d / %d   ",
			"integration coefficient bias / modulation:",
			int_coeff.intcoeff[0], int_coeff.intcoeff[1]);
		break;
	case 19:
		optic_float2uint ( mpd_level[0].out.gain_correction,
				  OPTIC_FLOAT2INTSHIFT_CORRFACTOR, 100,
				  &(high[0]), &(low[0]) );
		optic_float2uint ( mpd_level[1].out.gain_correction,
				  OPTIC_FLOAT2INTSHIFT_CORRFACTOR, 100,
				  &(high[1]), &(low[1]) );

		sprintf(text, "%-50s %d.%02d / %d.%02d   ",
			"gain correction factor P0 / P1:",
			high[0], low[0], high[1], low[1]);
		break;
	case 20:
		optic_float2int ( mpd_level[0].out.level_value,
				  OPTIC_FLOAT2INTSHIFT_DREF, 10,
				  &(high[0]), &(low[0]), &sign);


		optic_float2int ( mpd_level[1].out.level_value,
				  OPTIC_FLOAT2INTSHIFT_DREF, 10,
				  &(high[1]), &(low[1]), &sign2);

		sprintf(text, "%-50s %s%d.%01d / %s%d.%01d     ",
			"digital codeword P0 / P1:",
			(sign == true)? "-":"+",
			 high[0], low[0],
			 (sign2 == true)? "-":"+",
			 high[1], low[1]);
		break;
	case 21:
		temp = current_offset.current_fine_val * 1000;
		optic_float2uint ( temp, OPTIC_FLOAT2INTSHIFT_CURRENT_FINE, 100,
				  &high[0], &low[0] );

		sprintf(text, "%-50s %d.%02duA     ",
			"current offset:", high[0], low[0]);
		break;
	case 22:
		temp = status.meas_voltage_1490_rssi * 1000;
		optic_float2uint ( temp, OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE,
				  100, &high[0], &low[0] );
		temp = status.meas_current_1490_rssi * 1000;
		optic_float2uint ( temp, OPTIC_FLOAT2INTSHIFT_CURRENT_FINE,
				  100, &high[1], &low[1] );
				  
		sign = status.meas_current_1490_rssi_is_positive;
		sprintf(text, "%-50s %d.%02dmV   %s%d.%02duA   ",
				"RSSI 1490 voltage, current:",
				high[0], low[0], (sign == true)? "+":"-", high[1], low[1]);
		break;
	case 23:
		temp = status.meas_voltage_1550_rssi * 1000;
		optic_float2uint ( temp, OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE,
				  100, &high[0], &low[0] );
		sprintf(text, "%-50s %d.%02dmV   ", "RSSI 1550 voltage:",
			high[0], low[0]);
		break;

	case 24:
		temp = status.meas_voltage_1550_rf * 1000;
		optic_float2uint ( temp, OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE,
				  100, &high[0], &low[0] );
		sprintf(text, "%-50s %d.%02dmV   ", "RF 1550 voltage:",
			high[0], low[0]);
		break;
	case 25:
		temp = status.meas_power_1490_rssi * 1000;
		optic_float2uint ( temp, OPTIC_FLOAT2INTSHIFT_POWER,
				  100, &high[0], &low[0] );
		sprintf(text, "%-50s %d.%02duW   ",
			"RSSI 1490 power:",
			high[0], low[0]);
		break;
	case 26:
		temp = status.meas_power_1550_rssi * 1000;
		optic_float2uint ( temp, OPTIC_FLOAT2INTSHIFT_POWER,
				  100, &high[0], &low[0] );
		sprintf(text, "%-50s %d.%02duW   ",
			"RSSI 1550 power:",
			high[0], low[0]);
		break;
	case 27:
		temp = status.meas_power_1550_rf * 1000;
		optic_float2uint ( temp, OPTIC_FLOAT2INTSHIFT_POWER,
				  100, &high[0], &low[0] );
		sprintf(text, "%-50s %d.%02duW   ",
			"RF 1550 power:",
			high[0], low[0]);
		break;
	case 28:
		optic_float2uint ( vapd.out.vref,
				  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &high[0], &low[0] );

		sprintf(text, "%-50s %d.%02dV %d (%d)   ",
			"precalc. dcdc apd voltage, saturation:",
			high[0], low[0], vapd.out.sat,
			vapd.out.quality);
		break;
	case 29:
		optic_float2uint ( apd_status.target_voltage,
				  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &high[0], &low[0] );

		sprintf(text, "%-50s %d.%02dV (%s)   ",
			"DCDC APD target voltage (active/inactive)",
			high[0], low[0], (apd_status.enable == true)?
			"active" : "inactive" );
		break;

	case 30:
		optic_float2uint ( apd_status.voltage,
				  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &high[0], &low[0] );
		optic_float2int ( apd_status.regulation_error,
				  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &high[1], &low[1], &sign );

		sprintf(text, "%-50s %d.%02dV (%s%d.%02dV) %d   ",
			"DCDC APD voltage (regulation error), saturation:",
			high[0], low[0], (sign == true)? "-":"+", high[1],
			low[1], apd_status.saturation );
		break;
	case 31:
		optic_float2uint ( core_status.voltage,
				  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &high[0], &low[0] );

		sprintf(text, "%-50s %d.%02dV (%s)   ",
			"DCDC CORE voltage (active/inactive):",
			high[0], low[0],
			(core_status.enable == true)? "active" : "inactive" );
		break;
	case 32:
		optic_float2uint ( ddr_status.voltage,
				  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				  100, &high[0], &low[0] );

		sprintf(text, "%-50s %d.%02dV (%s)   ",
			"DCDC DDR voltage (active/inactive):",
			high[0], low[0],
			(ddr_status.enable == true)? "active" : "inactive" );
		break;
	case 33:
		sprintf(text, "%-50s (%s)   ",
			"linear LDO converter (active/inactive):",
			(ldo_status.enable == true)? "active" : "inactive" );
		break;
	case 34:
		sprintf(text, "%-50s %d   ", "laser bitdelay:",
			laserdelay.bitdelay);
		break;
	default:
		break;
	}
}

static struct optic_ext_status status;
static struct optic_bosa_alarm alarm;

int table_get_alarm ( void )
{
	struct optic_exchange ex;

	ex.error = 0;
	ex.length = sizeof(struct optic_ext_status);
	ex.p_data = (void *)&status;

	if (ioctl(fd_dev, FIO_GOI_EXT_STATUS_GET, &ex) < 0)
		memset(&status, 0, sizeof(status));

	ex.error = 0;
	ex.length = sizeof(struct optic_bosa_alarm);
	ex.p_data = (void *)&alarm;

	if (ioctl(fd_dev, FIO_BOSA_ALARM_STATUS_GET, &ex) < 0)
		memset(&alarm, 0, sizeof(alarm));

	return 14;
}

void table_entry_get_alarm (int entry, char *text )
{

	switch (entry) {
	case -1:
		sprintf(text, "%s ", "alarm overview");
		break;
	case 0:
		sprintf(text, " ");
		break;

	case 1:
		sprintf(text, "%-50s %s ", "PLL lock:",
			(status.pll_lock_status == true) ? "X" : "-");
		break;
	case 2:
		sprintf(text, "%-50s %s ", "loss of signal:",
			(status.loss_of_signal == true) ? "X" : "-");
		break;
	case 3:
		sprintf(text, "%-50s %s ", "loss of lock:",
			(status.loss_of_lock == true) ? "X" : "-");
		break;
	case 4:
		sprintf(text, " ");
		break;
	case 5:
		sprintf(text, "%-50s %s ", "temperature yellow alarm:",
			(status.temp_alarm_yellow == true) ? "X" : "-");
		break;
	case 6:
		sprintf(text, "%-50s %s ", "temperature red alarm:",
			(status.temp_alarm_red == true) ? "X" : "-");
		break;
	case 7:
		sprintf(text, " ");
		break;
	case 8:
		sprintf(text, "%-50s %s ", "signal overload (RX):",
			(alarm.rx_overload == true) ? "X" : "-");
		break;
	case 9:
		sprintf(text, "%-50s %s ", "Overcurrent, Bias+Modulation (TX):",
			(alarm.laser_overload == true) ? "X" : "-");
		break;
	case 10:
		sprintf(text, "%-50s %s ", "Bias overload (TX):",
			(alarm.bias_overload == true) ? "X" : "-");
		break;
	case 11:
		sprintf(text, "%-50s %s ", "Modulation overload (TX):",
			(alarm.modulation_overload == true) ? "X" : "-");
		break;
	case 12:
		sprintf(text, "%-50s %s ", "Rogue ONT P0 alarm (TX):",
			(alarm.rogue_p0 == true) ? "X" : "-");
		break;
	case 13:
		sprintf(text, "%-50s %s ", "Rogue ONT P1 alarm (TX):",
			(alarm.rogue_p1 == true) ? "X" : "-");
		break;
	default:
		break;
	}
}

#endif


