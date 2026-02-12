/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_optic_api.h"
#include "drv_optic_cli_core.h"
#include "drv_optic_timer.h"
#include "drv_optic_interface.h"
#include "drv_optic_common.h"
#include "drv_optic_calc.h"
#include "drv_optic_mpd.h"
#include "drv_optic_mm.h"
#include "drv_optic_dcdc_apd.h"
#include "drv_optic_register.h"
#include "drv_optic_event_interface.h"
#include "drv_optic_bosa.h"
#include "drv_optic_ll_fcsi.h"
#include "drv_optic_ll_mm.h"
#include "drv_optic_ll_mpd.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_ll_octrlg.h"
#include "drv_optic_ll_gpio.h"
#include "drv_optic_ll_int.h"
#include "drv_optic_ll_dcdc_apd.h"
#include "drv_optic_ll_rx.h"
#include "drv_optic_reg_base.h"

#include "drv_optic_ll_pll.h"
#include "drv_optic_ll_sys_gpon.h"
#include "drv_optic_ll_status.h"
#ifdef OPTIC_LIBRARY
extern void octrlg_laser_ageupdate ( uint8_t *seconds );
#endif

/** chip version, used by is_falcon_chip_a1x/a2x() */
enum optic_chip chip_version;

static enum optic_errorcode optic_increase_age (struct optic_control *p_ctrl);
static void dualloop ( struct optic_control *p_ctrl, const bool reset_states );

#ifdef INCLUDE_DEBUG_SUPPORT
#  if defined(__GNUC__)
#     if defined(__KERNEL__)
const char *optic_dbg_str[] = { KERN_INFO, KERN_WARNING , KERN_ERR, "" };
#     else
const char *optic_dbg_str[] = { " msg - ", " wrn - ", " err - ", "" };
#     endif


int optic_debug_print ( const enum optic_debug_levels level,
                        const char *format, ... )
{
	int ret = 0;
	va_list ap;

	if ((level < OPTIC_DBG_OFF) && (level >= optic_debug_level)) {
		va_start(ap, format);
#     if defined(__KERNEL__)
		ret = printk("%s" DEBUG_PREFIX " ", optic_dbg_str[level]);
		ret = vprintk(format, ap);
		ret = printk(OPTIC_CRLF);
#     else
		ret = printf(DEBUG_PREFIX "%s", optic_dbg_str[level]);
		ret = vprintf(format, ap);
		ret = printf(OPTIC_CRLF);
#     endif
		va_end(ap);
	}
	return ret;
}
#  else
int optic_debug_print_err ( const char *format, ... )
{
	va_list ap;
	int ret = 0;

	va_start(ap, format);
	ret = fprintf(stdout, DEBUG_PREFIX " err - ");
	ret = vfprintf(stdout, format, ap);
	ret = fprintf(stdout, OPTIC_CRLF);
	va_end(ap);

	return ret;
}

int optic_debug_print_wrn ( const char *format, ... )
{
	va_list ap;
	int ret = 0;

	va_start(ap, format);
	ret = fprintf(stdout, DEBUG_PREFIX " wrn - ");
	ret = vfprintf(stdout, format, ap);
	ret = fprintf(stdout, OPTIC_CRLF);
	va_end(ap);

	return ret;
}

int optic_debug_print_msg ( const char *format, ... )
{
	va_list ap;
	int ret = 0;

	va_start(ap, format);
	ret = fprintf(stdout, DEBUG_PREFIX " msg - ");
	ret = vfprintf(stdout, format, ap);
	ret = fprintf(stdout, OPTIC_CRLF);
	va_end(ap);

	return ret;
}
#  endif
#endif

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_COMMON_INTERNAL Optic Common Driver Interface - Internal
   @{
*/

/** what string support, driver version string */
const char optic_whatversion[] = OPTIC_WHAT_STR;

/** pointer to control structures. */
struct optic_control optic_ctrl[OPTIC_INSTANCES_MAX];



enum optic_errorcode optic_temptrans_size_get ( const enum optic_tabletype
						type,
						uint8_t *size )
{
	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		*size = sizeof(struct optic_tt_factor);
		break;
	case OPTIC_TABLETYPE_LASERREF:
		*size = sizeof(struct optic_tt_laserref);
		break;
	case OPTIC_TABLETYPE_IBIASIMOD:
		*size = sizeof(struct optic_tt_ibiasimod);
		break;
	case OPTIC_TABLETYPE_VAPD:
		*size = sizeof(struct optic_tt_vapd);
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		*size = sizeof(struct optic_tt_temptrans);
		break;
	default:
		OPTIC_DEBUG_ERR("unsupported tabletype %d", type);
		return OPTIC_STATUS_POOR;
	}
	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_table_completion ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t tabletemp_min, tabletemp_max;

	tabletemp_min = p_ctrl->config.range.tabletemp_extcorr_min;
	tabletemp_max = p_ctrl->config.range.tabletemp_extcorr_max;

	if (p_ctrl->state.current_state != OPTIC_STATE_TABLE_INIT)
		return OPTIC_STATUS_ERR;

	ret = optic_check_age ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;


	if (IFXOS_MutexGet(&p_ctrl->access.table_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;

	ret = optic_calc_ibiasimod ( p_ctrl );
	if (ret != OPTIC_STATUS_OK) {
		IFXOS_MutexRelease(&p_ctrl->access.table_lock);
		OPTIC_DEBUG_ERR("optic_calc_ibiasimod(): %d", ret);
			return ret;
	}

	ret = optic_complete_table ( p_ctrl, OPTIC_TABLETYPE_IBIASIMOD,
					   tabletemp_min, tabletemp_max );

	IFXOS_MutexRelease(&p_ctrl->access.table_lock);

	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_complete_table(): %d", ret);
		return ret;
	}

	/* mark table as read */
	p_ctrl->state.table_read[OPTIC_TABLETYPE_IBIASIMOD -
	                         OPTIC_TABLETYPE_INTERN_MIN] = true;

	optic_state_set(p_ctrl, OPTIC_STATE_TABLE_CALC);

	return ret;
}


enum optic_errorcode optic_init_temptable ( struct optic_control *p_ctrl,
                                            const enum optic_tabletype type )
{
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;
	uint16_t i, tabletemp_min, tabletemp_max, fkt, ith, se, age,
	         ibias, imod, vapd, sat;
	uint8_t pl, t;
	enum optic_tableval_quality init;
	struct optic_factor *tfact;

/** \todo cleanup start without tables */
#ifndef OPTIC_LIBRARY
	fkt = 0;
	ith = 0;
	se = 0;
	age = 0;
	ibias = 0;
	imod = 0;
	vapd = 0;
	sat = 0;
	init = OPTIC_TABLEQUAL_INITIAL;
#else
	/*330K: Ibias/Imod [ref|-3dB|-6dB]:    5.69/29.79    5.11/14.69    4.70/ 6.85 (6)
      	Pth factor, Ith/SE, age:       1.000 (2)     4.17/121.17 (4)     0:00:00
      	MPDrespCorr factor, Vapd/sat:  1.000 (2)    45.10/112 (6)
      	factor [RX1490|RX1550|RF1550]: 1.000 (2)     1.000 (2)     1.000 (2) */
	fkt = 1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR;
	ith = 4 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	se = 121 << OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY;
	age = 0;
	ibias = 6 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	imod = 30 << OPTIC_FLOAT2INTSHIFT_CURRENT;
	vapd = 45 << OPTIC_FLOAT2INTSHIFT_VOLTAGE;
	sat = 112;
	init = OPTIC_TABLEQUAL_FIXSET;
#endif

	if ((type >= OPTIC_TABLETYPE_TEMP_CORR_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_CORR_MAX)) {
	    	t = type - OPTIC_TABLETYPE_TEMP_CORR_MIN;
	    	tabletemp_min = p_ctrl->config.range.tabletemp_extcorr_min;
	    	tabletemp_max = p_ctrl->config.range.tabletemp_extcorr_max;
	    	table_corr = p_ctrl->table_temperature_corr;
	} else
	if ((type >= OPTIC_TABLETYPE_TEMP_NOM_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_NOM_MAX)) {
	    	t = type - OPTIC_TABLETYPE_TEMP_NOM_MIN;
	    	tabletemp_min = p_ctrl->config.range.tabletemp_extnom_min;
	    	tabletemp_max = p_ctrl->config.range.tabletemp_extnom_max;
	    	table_nom = p_ctrl->table_temperature_nom;
	} else
		return OPTIC_STATUS_POOR;

	if (tabletemp_min >= tabletemp_max)
		return OPTIC_STATUS_ERR;

	for (i=0; i<=tabletemp_max-tabletemp_min; i++) {
		switch (type) {
		case OPTIC_TABLETYPE_PTH:
		case OPTIC_TABLETYPE_MPDRESP:
		case OPTIC_TABLETYPE_RSSI1490:
		case OPTIC_TABLETYPE_RSSI1550:
		case OPTIC_TABLETYPE_RF1550:
			if (table_corr == NULL)
				return OPTIC_STATUS_ERR;
			tfact = table_corr[i].factor;
			switch (type) {
			case OPTIC_TABLETYPE_PTH:
				tfact[OPTIC_CFACTOR_PTH].corr_factor = fkt;
				break;
			case OPTIC_TABLETYPE_MPDRESP:
				tfact[OPTIC_CFACTOR_MPDRESP].corr_factor = fkt;
				break;
			case OPTIC_TABLETYPE_RSSI1490:
				tfact[OPTIC_CFACTOR_RSSI1490].corr_factor = fkt;
				break;
			case OPTIC_TABLETYPE_RSSI1550:
				tfact[OPTIC_CFACTOR_RSSI1550].corr_factor = fkt;
				break;
			case OPTIC_TABLETYPE_RF1550:
				tfact[OPTIC_CFACTOR_RF1550].corr_factor = fkt;
				break;
			default:
				break;
			}
			break;
		case OPTIC_TABLETYPE_LASERREF:
			if (table_corr == NULL)
				return OPTIC_STATUS_ERR;
			table_corr[i].laserref.ith = ith;
			table_corr[i].laserref.se = se;
			table_corr[i].laserref.age = age;
			break;
		case OPTIC_TABLETYPE_IBIASIMOD:
			if (table_corr == NULL)
				return OPTIC_STATUS_ERR;
			for (pl = OPTIC_POWERLEVEL_0;
			     pl <= OPTIC_POWERLEVEL_2; pl++) {
				table_corr[i].ibiasimod.ibias[pl] = ibias;
				table_corr[i].ibiasimod.imod[pl] = imod;
			}
			break;
		case OPTIC_TABLETYPE_VAPD:
			if (table_corr == NULL)
				return OPTIC_STATUS_ERR;
			table_corr[i].vapd.vref = vapd;
			table_corr[i].vapd.sat = sat;
			break;
		case OPTIC_TABLETYPE_TEMPTRANS:
			if (table_nom == NULL)
				return OPTIC_STATUS_ERR;
/** \todo cleanup start without tables */
#ifndef OPTIC_LIBRARY
			table_nom[i].temptrans.temp_corr = 0;
#else
			table_nom[i].temptrans.temp_corr = tabletemp_min + i;
#endif
			break;
		default:
			OPTIC_DEBUG_ERR("unsupported tabletype %d", type);
			return OPTIC_STATUS_POOR;
		}

		if (table_corr != NULL)
			table_corr[i].quality[t] = init;

		if (table_nom != NULL)
			table_nom[i].quality[t] = init;
	}

	p_ctrl->state.table_read[t] = false;

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_write_temptable ( struct optic_control *p_ctrl,
                                             const enum optic_tabletype type,
                                             const uint16_t tabledepth,
                                             const void *p_transfertable,
                                             uint16_t *valuetemp_min,
                                             uint16_t *valuetemp_max,
                                             bool *complete )
{
	uint16_t pl;
	uint16_t i;
	uint8_t t;
	uint16_t temp, tabletemp_min, tabletemp_max;
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;
	struct optic_tt_factor *p_factor = NULL;
	struct optic_tt_laserref *p_laserref = NULL;
	struct optic_tt_ibiasimod *p_ibiasimod = NULL;
	struct optic_tt_vapd *p_vapd = NULL;
	struct optic_tt_temptrans *p_temptrans = NULL;
	struct optic_factor *tfact;

	if ((valuetemp_min == NULL) || (valuetemp_max == NULL) ||
	    (complete == NULL))
		return OPTIC_STATUS_ERR;

	if (p_transfertable == NULL)
		return OPTIC_STATUS_ERR;

	if ((type >= OPTIC_TABLETYPE_TEMP_CORR_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_CORR_MAX)) {
	    	t = type - OPTIC_TABLETYPE_TEMP_CORR_MIN;
		tabletemp_min = p_ctrl->config.range.tabletemp_extcorr_min;
		tabletemp_max = p_ctrl->config.range.tabletemp_extcorr_max;
	    	table_corr = p_ctrl->table_temperature_corr;
	} else
	if ((type >= OPTIC_TABLETYPE_TEMP_NOM_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_NOM_MAX)) {
	    	t = type - OPTIC_TABLETYPE_TEMP_NOM_MIN;
		tabletemp_min = p_ctrl->config.range.tabletemp_extnom_min;
		tabletemp_max = p_ctrl->config.range.tabletemp_extnom_max;
	    	table_nom = p_ctrl->table_temperature_nom;
	} else
		return OPTIC_STATUS_POOR;

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		p_factor = (struct optic_tt_factor *) p_transfertable;
		break;
	case OPTIC_TABLETYPE_LASERREF:
		p_laserref = (struct optic_tt_laserref *) p_transfertable;
		break;
	case OPTIC_TABLETYPE_IBIASIMOD:
		p_ibiasimod = (struct optic_tt_ibiasimod *) p_transfertable;
		break;
	case OPTIC_TABLETYPE_VAPD:
		p_vapd = (struct optic_tt_vapd *) p_transfertable;
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		p_temptrans = (struct optic_tt_temptrans *) p_transfertable;
		break;
	default:
		OPTIC_DEBUG_ERR("unsupported tabletype %d", type);
		return OPTIC_STATUS_POOR;
	}

	*valuetemp_min = tabletemp_max;
	*valuetemp_max = tabletemp_min;

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
			OPTIC_DEBUG_ERR("unsupported tabletype %d", type);
			return OPTIC_STATUS_POOR;
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
			tfact = table_corr[temp].factor;
			switch (type) {
			case OPTIC_TABLETYPE_PTH:
				tfact[OPTIC_CFACTOR_PTH].corr_factor =
							p_factor[i].corr_factor;
				break;
			case OPTIC_TABLETYPE_MPDRESP:
				tfact[OPTIC_CFACTOR_MPDRESP].corr_factor =
							p_factor[i].corr_factor;
				break;
			case OPTIC_TABLETYPE_RSSI1490:
				tfact[OPTIC_CFACTOR_RSSI1490].corr_factor =
							p_factor[i].corr_factor;
				break;
			case OPTIC_TABLETYPE_RSSI1550:
				tfact[OPTIC_CFACTOR_RSSI1550].corr_factor =
							p_factor[i].corr_factor;
				break;
			case OPTIC_TABLETYPE_RF1550:
				tfact[OPTIC_CFACTOR_RF1550].corr_factor =
							p_factor[i].corr_factor;
				break;
			default:
				break;
			}
			table_corr[temp].quality[t] = p_factor[i].quality;
			break;
		case OPTIC_TABLETYPE_LASERREF:
			table_corr[temp].laserref.ith = p_laserref[i].ith;
			table_corr[temp].laserref.se = p_laserref[i].se;
			table_corr[temp].laserref.age = p_laserref[i].age;
			table_corr[temp].quality[t] = p_laserref[i].quality;
			break;
		case OPTIC_TABLETYPE_IBIASIMOD:
			for (pl=0; pl<3; pl++) {
				table_corr[temp].ibiasimod.ibias[pl] =
						p_ibiasimod[i].ibias[pl];
				table_corr[temp].ibiasimod.imod[pl] =
						p_ibiasimod[i].imod[pl];
			}
			/* old measured value? mark as "old" stored one -
			   to differ from new measurement */
			if (p_ibiasimod[i].quality == OPTIC_TABLEQUAL_MEAS)
			     	table_corr[temp].quality[t] =
			     				OPTIC_TABLEQUAL_STORE;
			else
				table_corr[temp].quality[t] =
							p_ibiasimod[i].quality;
			break;
		case OPTIC_TABLETYPE_VAPD:
			table_corr[temp].vapd.vref = p_vapd[i].vref;
			table_corr[temp].vapd.sat = p_vapd[i].sat;
			table_corr[temp].quality[t] = p_vapd[i].quality;;
			break;
		case OPTIC_TABLETYPE_TEMPTRANS:
			table_nom[temp].temptrans.temp_corr =
						p_temptrans[i].temp_corr;
			table_nom[temp].quality[t] = p_temptrans[i].quality;
			break;
		default:
			OPTIC_DEBUG_ERR("unsupported type %d", type);
			return OPTIC_STATUS_POOR;
		}
	}

	/* search for gaps, if table is filled completly */
	*complete = true;
	for (i=0; i<=tabletemp_max-tabletemp_min; i++) {
		if ((table_corr != NULL) &&
		    (table_corr[i].quality[t] == OPTIC_TABLEQUAL_INITIAL)) {
		    	*complete = false;
		    	break;
		}
		if ((table_nom != NULL) &&
		    (table_nom[i].quality[t] == OPTIC_TABLEQUAL_INITIAL)) {
		    	*complete = false;
		    	break;
		}
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_read_temptable ( struct optic_control *p_ctrl,
                                            const enum optic_tabletype type,
                                            const uint16_t tabledepth_max,
                                            void *p_transfertable,
                                            enum optic_tableval_quality quality,
                                            uint16_t *tabledepth )
{
	enum optic_powerlevel pl = p_ctrl->calibrate.powerlevel;
	uint8_t t;
	uint16_t temp, temp_index, tabletemp_min, tabletemp_max;
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;
	struct optic_tt_factor *p_factor = NULL;
	struct optic_tt_laserref *p_laserref = NULL;
	struct optic_tt_ibiasimod *p_ibiasimod = NULL;
	struct optic_tt_vapd *p_vapd = NULL;
	struct optic_tt_temptrans *p_temptrans = NULL;
	struct optic_factor *tfact;

	if ((p_transfertable == NULL) || (tabledepth == NULL))
		return OPTIC_STATUS_ERR;

	*tabledepth = 0;

	if ((type >= OPTIC_TABLETYPE_TEMP_CORR_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_CORR_MAX)) {
	    	t = type - OPTIC_TABLETYPE_TEMP_CORR_MIN;
		tabletemp_min = p_ctrl->config.range.tabletemp_extcorr_min;
		tabletemp_max = p_ctrl->config.range.tabletemp_extcorr_max;
	    	table_corr = p_ctrl->table_temperature_corr;
	} else
	if ((type >= OPTIC_TABLETYPE_TEMP_NOM_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_NOM_MAX)) {
	    	t = type - OPTIC_TABLETYPE_TEMP_NOM_MIN;
		tabletemp_min = p_ctrl->config.range.tabletemp_extnom_min;
		tabletemp_max = p_ctrl->config.range.tabletemp_extnom_max;
	    	table_nom = p_ctrl->table_temperature_nom;
	} else
		return OPTIC_STATUS_POOR;

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		p_factor = (struct optic_tt_factor *) p_transfertable;
		break;
	case OPTIC_TABLETYPE_LASERREF:
		p_laserref = (struct optic_tt_laserref *) p_transfertable;
		break;
	case OPTIC_TABLETYPE_IBIASIMOD:
		p_ibiasimod = (struct optic_tt_ibiasimod *) p_transfertable;
		break;
	case OPTIC_TABLETYPE_VAPD:
		p_vapd = (struct optic_tt_vapd *) p_transfertable;
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		p_temptrans = (struct optic_tt_temptrans *) p_transfertable;
		break;
	default:
		OPTIC_DEBUG_ERR("unsupported tabletype %d", type);
		return OPTIC_STATUS_POOR;
	}

	for (temp=tabletemp_min; temp<=tabletemp_max; temp++) {

		if (*tabledepth >= tabledepth_max)
			return OPTIC_STATUS_MORE_ENTRIES;

		temp_index = temp - tabletemp_min;

/* /todo: < quality ! */
		if ((table_corr != NULL) &&
		    (table_corr[temp_index].quality[t] != quality))
			continue;
		if ((table_nom != NULL) &&
		    (table_nom[temp_index].quality[t] != quality))
			continue;

		switch (type) {
		case OPTIC_TABLETYPE_PTH:
		case OPTIC_TABLETYPE_MPDRESP:
		case OPTIC_TABLETYPE_RSSI1490:
		case OPTIC_TABLETYPE_RSSI1550:
		case OPTIC_TABLETYPE_RF1550:
			if (table_corr == NULL)
				return OPTIC_STATUS_ERR;

			tfact = table_corr[temp_index].factor;
			p_factor[*tabledepth].temp = temp;

			switch (type) {
			case OPTIC_TABLETYPE_PTH:
				p_factor[*tabledepth].corr_factor =
					tfact[OPTIC_CFACTOR_PTH].corr_factor;
				break;
			case OPTIC_TABLETYPE_MPDRESP:
				p_factor[*tabledepth].corr_factor =
				    tfact[OPTIC_CFACTOR_MPDRESP].corr_factor;
				break;
			case OPTIC_TABLETYPE_RSSI1490:
				p_factor[*tabledepth].corr_factor =
				   tfact[OPTIC_CFACTOR_RSSI1490].corr_factor;
				break;
			case OPTIC_TABLETYPE_RSSI1550:
				p_factor[*tabledepth].corr_factor =
				   tfact[OPTIC_CFACTOR_RSSI1550].corr_factor;
				break;
			case OPTIC_TABLETYPE_RF1550:
				p_factor[*tabledepth].corr_factor =
				     tfact[OPTIC_CFACTOR_RF1550].corr_factor;
				break;
			default:
				break;
			}

			p_factor[*tabledepth].quality =
					table_corr[temp_index].quality[t];
			break;
		case OPTIC_TABLETYPE_LASERREF:
			if (table_corr == NULL)
				return OPTIC_STATUS_ERR;
			p_laserref[*tabledepth].temp = temp;
			p_laserref[*tabledepth].ith =
					table_corr[temp_index].laserref.ith;
			p_laserref[*tabledepth].se =
					table_corr[temp_index].laserref.se;
			p_laserref[*tabledepth].age =
					table_corr[temp_index].laserref.age;
			p_laserref[*tabledepth].quality =
					table_corr[temp_index].quality[t];
			break;
		case OPTIC_TABLETYPE_IBIASIMOD:
			if (table_corr == NULL)
				return OPTIC_STATUS_ERR;
			p_ibiasimod[*tabledepth].temp = temp;
			for (pl=0; pl<3; pl++) {
				p_ibiasimod[*tabledepth].ibias[pl] =
				    table_corr[temp_index].ibiasimod.ibias[pl];
				p_ibiasimod[*tabledepth].imod[pl] =
				    table_corr[temp_index].ibiasimod.imod[pl];
			}
			p_ibiasimod[*tabledepth].quality =
					table_corr[temp_index].quality[t];
			break;
		case OPTIC_TABLETYPE_VAPD:
			if (table_corr == NULL)
				return OPTIC_STATUS_ERR;
			p_vapd[*tabledepth].temp = temp;
			p_vapd[*tabledepth].vref =
					table_corr[temp_index].vapd.vref;
			p_vapd[*tabledepth].sat =
					table_corr[temp_index].vapd.sat;
			p_vapd[*tabledepth].quality =
					table_corr[temp_index].quality[t];
			break;
		case OPTIC_TABLETYPE_TEMPTRANS:
			if (table_nom == NULL)
				return OPTIC_STATUS_ERR;
			p_temptrans[*tabledepth].temp = temp;
			p_temptrans[*tabledepth].temp_corr =
				table_nom[temp_index].temptrans.temp_corr;
			p_temptrans[*tabledepth].quality =
					table_nom[temp_index].quality[t];
			break;
		default:
			OPTIC_DEBUG_ERR("unsupported tabletype %d", type);
			return OPTIC_STATUS_POOR;
		}

		(*tabledepth) ++;
	}
	return OPTIC_STATUS_OK;
}



enum optic_errorcode optic_complete_table ( struct optic_control *p_ctrl,
                                            const enum optic_tabletype type,
                                            const uint16_t valuetemp_min,
                                            const uint16_t valuetemp_max )
{
	enum optic_errorcode ret;
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;
	uint16_t tabletemp_min, tabletemp_max, min, max;
	struct optic_factor *t_factor;

	uint16_t offset;
	uint8_t size, pl;

	if ((type >= OPTIC_TABLETYPE_TEMP_CORR_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_CORR_MAX)) {
		tabletemp_min = p_ctrl->config.range.tabletemp_extcorr_min;
		tabletemp_max = p_ctrl->config.range.tabletemp_extcorr_max;
	    	table_corr = p_ctrl->table_temperature_corr;
	} else
	if ((type >= OPTIC_TABLETYPE_TEMP_NOM_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_NOM_MAX)) {
		tabletemp_min = p_ctrl->config.range.tabletemp_extnom_min;
		tabletemp_max = p_ctrl->config.range.tabletemp_extnom_max;
	    	table_nom = p_ctrl->table_temperature_nom;
	} else
		return OPTIC_STATUS_POOR;


	if ((tabletemp_min > tabletemp_max) ||
	     (valuetemp_min > valuetemp_max)) {
		OPTIC_DEBUG_ERR("min > max temperature error");
		return OPTIC_STATUS_POOR;
	}
	if ((valuetemp_min < tabletemp_min) ||
	    (valuetemp_max > tabletemp_max)) {
		OPTIC_DEBUG_ERR("interpol block is out of temp table range");
		return OPTIC_STATUS_POOR;
	}

	min = valuetemp_min - tabletemp_min;
	max = valuetemp_max - tabletemp_min;

	switch (type) {
	case OPTIC_TABLETYPE_PTH:
	case OPTIC_TABLETYPE_MPDRESP:
	case OPTIC_TABLETYPE_RSSI1490:
	case OPTIC_TABLETYPE_RSSI1550:
	case OPTIC_TABLETYPE_RF1550:
		t_factor = table_corr[0].factor;
		switch (type) {
		case OPTIC_TABLETYPE_PTH:
			offset = offsetof ( struct optic_table_temperature_corr,
				     factor[OPTIC_CFACTOR_PTH].corr_factor );
			size = sizeof (t_factor[OPTIC_CFACTOR_PTH].corr_factor);
			break;
		case OPTIC_TABLETYPE_MPDRESP:
			offset = offsetof ( struct optic_table_temperature_corr,
				 factor[OPTIC_CFACTOR_MPDRESP].corr_factor );
			size =
			   sizeof (t_factor[OPTIC_CFACTOR_MPDRESP].corr_factor);
			break;
		case OPTIC_TABLETYPE_RSSI1490:
			offset = offsetof ( struct optic_table_temperature_corr,
				 factor[OPTIC_CFACTOR_RSSI1490].corr_factor );
			size =
			  sizeof (t_factor[OPTIC_CFACTOR_RSSI1490].corr_factor);
			break;
		case OPTIC_TABLETYPE_RSSI1550:
			offset = offsetof ( struct optic_table_temperature_corr,
				 factor[OPTIC_CFACTOR_RSSI1550].corr_factor );
			size =
			  sizeof (t_factor[OPTIC_CFACTOR_RSSI1550].corr_factor);
			break;
		case OPTIC_TABLETYPE_RF1550:
			offset = offsetof ( struct optic_table_temperature_corr,
				 factor[OPTIC_CFACTOR_RF1550].corr_factor );
			size =
			  sizeof (t_factor[OPTIC_CFACTOR_RF1550].corr_factor);
			break;
		default:
			return OPTIC_STATUS_ERR;
		}
		ret = optic_fill_table_const ( p_ctrl, type, offset, size,
					1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		break;
	case OPTIC_TABLETYPE_LASERREF:
		/* Ith */
		offset = offsetof ( struct optic_table_temperature_corr,
				    laserref.ith );
		size = sizeof(table_corr[0].laserref.ith);
		ret = optic_fill_table_ipol ( p_ctrl, type, offset, size,
						    min, max );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		/* SE */
		offset = offsetof ( struct optic_table_temperature_corr,
				    laserref.se );
		size = sizeof(table_corr[0].laserref.se);
		ret = optic_fill_table_ipol ( p_ctrl, type, offset, size,
						    min, max );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		break;
	case OPTIC_TABLETYPE_IBIASIMOD:
		for (pl = OPTIC_POWERLEVEL_0; pl <= OPTIC_POWERLEVEL_2;
		     pl ++)  {
			/* Ibias */
			offset = offsetof ( struct optic_table_temperature_corr,
					    ibiasimod.ibias[pl] );
			size = sizeof(table_corr[0].ibiasimod.ibias[pl]);
			ret = optic_fill_table_ipol ( p_ctrl, type,
							    offset, size,
							    min, max );
			if (ret != OPTIC_STATUS_OK)
				return ret;

			/* Imod */
			offset = offsetof ( struct optic_table_temperature_corr,
					    ibiasimod.imod[pl] );
			size = sizeof(table_corr[0].ibiasimod.imod[pl]);
			ret = optic_fill_table_ipol ( p_ctrl, type,
							    offset, size,
							    min, max );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		}
		break;
	case OPTIC_TABLETYPE_VAPD:
		/* vref */
		offset = offsetof ( struct optic_table_temperature_corr,
				    vapd.vref );
		size = sizeof(table_corr[0].vapd.vref);
		ret = optic_fill_table_ipol ( p_ctrl, type, offset, size,
					            min, max );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		/* sat */
		offset = offsetof ( struct optic_table_temperature_corr,
				    vapd.sat );
		size = sizeof(table_corr[0].vapd.sat);
		ret = optic_fill_table_ipol ( p_ctrl, type, offset, size,
					            min, max );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		offset = offsetof ( struct optic_table_temperature_nom,
				    temptrans.temp_corr );
		size = sizeof(table_nom[0].temptrans.temp_corr);
		ret = optic_fill_table_ipol ( p_ctrl, type, offset, size,
						    min, max );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		break;
	default:
		OPTIC_DEBUG_ERR("table type not supported %d", type);
		return OPTIC_STATUS_ERR;
	}

   return ret;
}

enum optic_errorcode optic_cfactor_table_set ( struct optic_control *p_ctrl,
					       const enum optic_cfactor type,
					       const uint16_t temperature,
					       const uint16_t corr_factor )
{
	uint16_t temp;
	struct optic_table_temperature_corr *tcorr;
	struct optic_config_range *range;
	uint16_t min = (1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR) / 10;   /* 0.1 */
	uint16_t max = (1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR) * 10;   /* 10. */
	uint8_t t;

	if (p_ctrl == NULL)
		return OPTIC_STATUS_ERR;

	tcorr = p_ctrl->table_temperature_corr;
	range = &(p_ctrl->config.range);

	if ((temperature < range->tabletemp_extcorr_min) ||
	    (temperature > range->tabletemp_extcorr_max))
	    	return OPTIC_STATUS_POOR;

	if ((corr_factor < min) || (corr_factor > max))
	    	return OPTIC_STATUS_POOR;

	temp = temperature - range->tabletemp_extcorr_min;
	tcorr[temp].factor[type].corr_factor = corr_factor;

	switch (type) {
	case OPTIC_CFACTOR_MPDRESP:
		t = OPTIC_TABLETYPE_MPDRESP;
		break;
	case OPTIC_CFACTOR_RSSI1490:
		t = OPTIC_TABLETYPE_RSSI1490;
		break;
	case OPTIC_CFACTOR_RSSI1550:
		t = OPTIC_TABLETYPE_RSSI1550;
		break;
	case OPTIC_CFACTOR_RF1550:
		t = OPTIC_TABLETYPE_RF1550;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	t -= OPTIC_TABLETYPE_TEMP_CORR_MIN;
	tcorr[temp].quality[t] = OPTIC_TABLEQUAL_FIXSET;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_cfactor_table_get ( struct optic_control *p_ctrl,
					       const enum optic_cfactor type,
					       const uint16_t temperature,
					       uint16_t *corr_factor,
					       enum optic_tableval_quality
					       *quality )
{
	uint16_t temp;
	struct optic_table_temperature_corr *tcorr;
	struct optic_config_range *range;
	uint8_t t;

	if ((p_ctrl == NULL) || (corr_factor == NULL))
		return OPTIC_STATUS_ERR;

	tcorr = p_ctrl->table_temperature_corr;
	range = &(p_ctrl->config.range);

	if ((temperature < range->tabletemp_extcorr_min) ||
	    (temperature > range->tabletemp_extcorr_max))
	    	return OPTIC_STATUS_POOR;

	temp = temperature - range->tabletemp_extcorr_min;
	*corr_factor = tcorr[temp].factor[type].corr_factor;

	if (quality != NULL) {
		switch (type) {
		case OPTIC_CFACTOR_MPDRESP:
			t = OPTIC_TABLETYPE_MPDRESP;
			break;
		case OPTIC_CFACTOR_RSSI1490:
			t = OPTIC_TABLETYPE_RSSI1490;
			break;
		case OPTIC_CFACTOR_RSSI1550:
			t = OPTIC_TABLETYPE_RSSI1550;
			break;
		case OPTIC_CFACTOR_RF1550:
			t = OPTIC_TABLETYPE_RF1550;
			break;
		default:
			return OPTIC_STATUS_POOR;
		}

		t -= OPTIC_TABLETYPE_TEMP_CORR_MIN;

		*quality = tcorr[temp].quality[t];
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_powersave_set ( struct optic_control *p_ctrl )
{
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);
	enum optic_errorcode ret;

	ret = optic_ll_mpd_powersave_set ( monitor->powersave );
	if (ret !=  OPTIC_STATUS_OK)
		return ret;

	optic_ll_tx_powersave_set (monitor->powersave);

	ret = optic_ll_fcsi_powersave_set ( monitor->powersave );
	if (ret !=  OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode optic_fifo_init ( struct optic_fifo *p_fifo,
				       const char *name )
{
#ifndef OPTIC_LIBRARY
	strcpy ( p_fifo->name, name );
	p_fifo->enable = false;

	if (IFX_Var_Fifo_Init ( &p_fifo->data, (ulong_t *) & p_fifo->buf[0],
				(ulong_t *) & (p_fifo->buf[OPTIC_FIFO_SIZE]),
			        OPTIC_FIFO_SIZE) != IFX_SUCCESS) {
		OPTIC_DEBUG_ERR("Can't initialize fifo %s.", name);
		return OPTIC_STATUS_ERR;
	}

	if (optic_spinlock_init(&p_fifo->lock, name) != 0) {
		return OPTIC_STATUS_ERR;
	}
#endif
	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_fifo_delete ( struct optic_fifo *p_fifo )
{
#ifndef OPTIC_LIBRARY
	if (optic_spinlock_delete ( &p_fifo->lock ) != 0) {
		return OPTIC_STATUS_ERR;
	}
#endif
	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_fifo_cloneentry ( struct optic_fifo *p_fifo,
					     const void *buf,
					     const uint32_t len )
{
#ifndef OPTIC_LIBRARY
	void *p_data;
	unsigned long flags = 0;

	optic_spinlock_get ( &p_fifo->lock, &flags );
	p_data = IFX_Var_Fifo_writeElement ( &p_fifo->data, len );
	if (p_data) {
		memcpy(p_data, buf, len);
	} else {
		p_fifo->lost++;
	}
	optic_spinlock_release ( &p_fifo->lock, flags );
	return p_data ? OPTIC_STATUS_OK : OPTIC_STATUS_ERR;
#else
	return OPTIC_STATUS_ERR;
#endif
}

enum optic_errorcode optic_fifo_write ( IFXOS_event_t *wakeup_event,
					struct optic_fifo *p_fifo,
				        const uint32_t control,
				        const void *buf,
				        const uint32_t len )
{
#ifndef OPTIC_LIBRARY
	uint8_t *p_data, *p_buffer;
	unsigned long flags = 0;

	optic_spinlock_get ( &p_fifo->lock, &flags );
	p_data = (uint8_t *) IFX_Var_Fifo_writeElement(&p_fifo->data,
					sizeof(struct optic_fifo_header) + len);
	if (p_data) {
		((struct optic_fifo_header *)p_data)->id = control;
		((struct optic_fifo_header *)p_data)->len = len;
		if (len) {
			p_buffer = p_data + sizeof(struct optic_fifo_header);
			memcpy(&p_buffer[0], buf, len);
		}
	} else {
		p_fifo->lost++;
	}
	optic_spinlock_release ( &p_fifo->lock, flags );
	IFXOS_EventWakeUp ( wakeup_event );

	return p_data ? OPTIC_STATUS_OK : OPTIC_STATUS_ERR;
#else
	return OPTIC_STATUS_ERR;
#endif
}

enum optic_errorcode optic_fifo_writevalue ( IFXOS_event_t *wakeup_event,
					     struct optic_fifo *p_fifo,
					     const uint32_t control,
					     const uint32_t value )
{
#ifndef OPTIC_LIBRARY
	uint8_t *p_data, *p_buffer;
	unsigned long flags = 0;

	optic_spinlock_get ( &p_fifo->lock, &flags );
	p_data = (uint8_t *)IFX_Var_Fifo_writeElement(&p_fifo->data,
					sizeof(struct optic_fifo_header) + 4);
	if (p_data) {
		((struct optic_fifo_header *)p_data)->id = control;
		((struct optic_fifo_header *)p_data)->len = 4;
		p_buffer = p_data + sizeof(struct optic_fifo_header);
		*((uint32_t *)p_buffer) = value;
	} else {
		p_fifo->lost++;
	}
	optic_spinlock_release ( &p_fifo->lock, flags );
	IFXOS_EventWakeUp ( wakeup_event );

	return p_data ? OPTIC_STATUS_OK : OPTIC_STATUS_ERR;
#else
	return OPTIC_STATUS_ERR;
#endif
}

enum optic_errorcode optic_fifo_read ( struct optic_fifo *p_fifo,
				       void *buf,
				       uint32_t *len )
{
#ifndef OPTIC_LIBRARY
	void *ptr;
	unsigned long flags = 0;

	optic_spinlock_get ( &p_fifo->lock, &flags );
	ptr = (struct optic_fifo_header *)
		IFX_Var_Fifo_readElement(&p_fifo->data, len);
	if ((ptr != NULL) && (buf != NULL) && (*len != 0)) {
		memcpy(buf, ptr, *len);
	}
	optic_spinlock_release ( &p_fifo->lock, flags );

	return ptr ? OPTIC_STATUS_OK : OPTIC_STATUS_ERR;
#else
	return OPTIC_STATUS_ERR;
#endif
}

static enum optic_errorcode optic_increase_age ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	static uint8_t cycle_cnt = 0;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_config *conf = &(p_ctrl->config);
	uint8_t sec;

	if (++cycle_cnt < (OPTIC_LASERAGE_UPDATE/conf->temperature_check_time))
		return ret;

	cycle_cnt = 0;

#ifdef OPTIC_LIBRARY
	octrlg_laser_ageupdate (&sec);
#else
	optic_ll_octrlg_ageupdate ( &sec );
#endif

	cal->timestamp += sec;

	if (((cal->timestamp - sec) / conf->update_laser_age) <
	     (cal->timestamp / conf->update_laser_age)) {
#ifndef OPTIC_LIBRARY
		optic_fifo_write ( &(p_ctrl->event_worker),
				   &p_ctrl->fifo_worker,
			   	   OPTIC_FIFO_TIMESTAMP,
			   	   (void*) &(cal->timestamp),
			   	   sizeof(cal->timestamp));
#endif
	}

	return ret;
}

int32_t optic_thread_measure ( IFXOS_ThreadParams_t *param )
{
	struct optic_control *p_ctrl = (struct optic_control *) param->nArg1;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	static uint8_t cnt_temp = 0;
	uint8_t i;
	uint16_t check_time = p_ctrl->config.temperature_check_time;
	uint16_t saturation;
	static uint16_t loop_mode_old = OPTIC_BOSA_OPENLOOP;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_measurement *meas = &(cal->measurement);


#ifdef OPTIC_LIBRARY
	do {
#else
	while (p_ctrl->measure_run == true) {
		if (optic_signal_pending ( current ))
			break;

		/* wait for Activating */
		if (IFXOS_EventWait ( &p_ctrl->event_measure, 10000, NULL )
		    != IFX_SUCCESS)
		    	continue;

		/* waked up by event */

		/* easiest way to kill the measurement thread */
		if (p_ctrl->measure_run == false)
			return 0;

		/* recover PLL in case of LOL, required in BOSA and OMU mode */
		optic_ll_rx_dsm_reset (p_ctrl->config.bosa.threshold_lol_set,
				p_ctrl->config.bosa.threshold_lol_clear);
#endif
#if ((OPTIC_BOSA_IRQ == ACTIVE) && ( OPTIC_BOSA_IRQ_THRESHOLD_CHECK == ACTIVE))
		if ((p_ctrl->config.mode == OPTIC_BOSA) ||
			(p_ctrl->config.mode == OPTIC_BOSA_2)) {
		    	ret = optic_ll_int_poll
		    			( &(p_ctrl->state.interrupts) );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("optic_ll_int_set(): %d",
						ret);
				continue;
			}
		}
#endif

		check_time = p_ctrl->config.temperature_check_time;

		if (p_ctrl->state.current_state == OPTIC_STATE_RUN) {
			cnt_temp++;
		} else {
			/* preparation next cycle -> temperature measurement */
			cnt_temp = (check_time / p_ctrl->mm_interval) - 1;
		}
		/* temperature measurement ? */
		if (cnt_temp < (check_time / p_ctrl->mm_interval)) {
			/* no temperature calculation -> measure all channels */
			ret = optic_mm_control ( p_ctrl );

			if (ret != OPTIC_STATUS_OK)
				continue;
		} else {
			/* temperature calculation (default all second) */
			cnt_temp = 0;

			ret = optic_increase_age ( p_ctrl );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR(" age incr ;(" );
				continue;
			}

			/* get (new) internal temperature */
			ret = optic_mm_temp_int_get ( p_ctrl );
#if (OPTIC_INT_TEMP_REACTION == ACTIVE)
			if (ret == OPTIC_STATUS_INTTEMP_OVERFLOW) {

				ret = optic_ll_dcdc_apd_set (OPTIC_DISABLE);
				continue;
			}
#endif
			/* get external temperature */
			ret = optic_mm_temp_ext_get ( p_ctrl );
#if (OPTIC_EXT_TEMP_REACTION == ACTIVE)
			if (ret == OPTIC_STATUS_EXTTEMP_OVERFLOW) {
				OPTIC_DEBUG_ERR("eTemp overflow");
				continue;
			}
#endif
			ret = optic_temperature_store ( p_ctrl );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("temperature store error" );
				continue;
			}

#if (OPTIC_TEMPERATURE_ALARM == ACTIVE)
			ret = optic_check_temperature_alarm ( p_ctrl );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("temperature alarm check" );
				continue;
			}
#endif
			if ((p_ctrl->config.mode != OPTIC_BOSA) &&
			    (p_ctrl->config.mode != OPTIC_BOSA_2))
				continue;

			/* following functions are not applicable
			   without external temperature */
			ret = optic_mm_power_get ( p_ctrl );
			if (ret < OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("power measurement: %d", ret);
			}

#if (OPTIC_DCDC_APD_UPDATE == ACTIVE)
			/* temp -> VAPD, duty cycle saturation -> config apd */
			ret = optic_dcdc_apd_update ( p_ctrl );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("optic_dcdc_apd_update(): %d",
						ret);
				continue;
			}

			ret = optic_calc_offset_and_thresh ( p_ctrl );
			if (ret != OPTIC_STATUS_OK) {
	 			OPTIC_DEBUG_ERR("optic_calc_current_thresh(): %d",
	 					ret);
				continue;
			}

#endif
			/** update LOS, RX Overload thresholds */
			ret = optic_mm_thresh_calc ( p_ctrl );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("optic_mm_thresh_calc(): %d",
						ret);
				continue;
			}
			/* GPONSW-588: LOS interrupt and RSSI1490 in differential mode */
			if (abs(meas->average[OPTIC_MEASURE_POWER_RSSI_1490]) >
					cal->thresh_codeword_ovl) {
				p_ctrl->state.interrupts.signal_overload = true;
			} else {
				p_ctrl->state.interrupts.signal_overload = false;
			}
			if (abs(meas->average[OPTIC_MEASURE_POWER_RSSI_1490]) <
				cal->thresh_codeword_los) {
				p_ctrl->state.interrupts.signal_lost = true;
			} else {
				p_ctrl->state.interrupts.signal_lost = false;
			}

			/** debug mode? stop processing */
			if ((p_ctrl->calibrate.temperature_ext == 0) ||
			    (p_ctrl->config.debug_mode == true))
				continue;

			/** read abias / amod for average */
			for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) {
				ret = optic_mpd_biasmod_average( p_ctrl, i );
				if (ret != OPTIC_STATUS_OK)
					continue;
			}

			if (p_ctrl->config.bosa.loop_mode ==
			    OPTIC_BOSA_OPENLOOP) {

				/* GPONSW-998: automatic smooth power scaling */
				if(p_ctrl->config.measurement.RSSI_autolevel == true) {
		
					if( p_ctrl->calibrate.meas_power_1490_rssi <
					     p_ctrl->config.measurement.RSSI_1490threshold_low ) {
						/* switch from powerlevel P1 to P0 */
						optic_bosa_powerlevel_set(p_ctrl,
								OPTIC_POWERLEVEL_0);
					}
		
					if(p_ctrl->calibrate.meas_power_1490_rssi >
					     p_ctrl->config.measurement.RSSI_1490threshold_high ) {
						/* switch from powerlevel P0 to P1 */
						optic_bosa_powerlevel_set(p_ctrl,
								OPTIC_POWERLEVEL_1);
					}
				}
				/* work around in case that a dual loop was active and
				 * optic ocalodi is issued. In the integrator hardware,
				 * the c_int is not handled in a correct way
				 */
				if ((p_ctrl->calibrate.intcoeff[0] != 0)||
						(p_ctrl->calibrate.intcoeff[1] != 0)){
					saturation = 1 << (7 - p_ctrl->calibrate.intcoeff[0]);
					if (saturation > 32)
						saturation = 32;
					ret = optic_ll_mpd_cint_set ( OPTIC_BIAS,
							p_ctrl->calibrate.intcoeff[0], saturation );
					saturation = 1 << (7 - p_ctrl->calibrate.intcoeff[1]);
					if (saturation > 32)
						saturation = 32;
					ret = optic_ll_mpd_cint_set ( OPTIC_MOD,
							p_ctrl->calibrate.intcoeff[1], saturation );
				}

				for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) {
				 	/* TRY to update (if update threshold
				 	   exceeded)
				 	   Abias/Amod <-> LUT
				 	   (update -> Ibias/Imod) */
					ret = optic_mpd_biasmod_update
								( p_ctrl, i );
				}
				loop_mode_old = OPTIC_BOSA_OPENLOOP;
				continue;
			}

			if (p_ctrl->config.bosa.loop_mode !=
			    OPTIC_BOSA_DUALLOOP)
			    	continue;

#ifdef OPTIC_LIBRARY
			if ((p_ctrl->config.bosa.loop_mode == OPTIC_BOSA_DUALLOOP) &&
					(loop_mode_old == OPTIC_BOSA_OPENLOOP))
				dualloop ( p_ctrl, true );
			else
				dualloop ( p_ctrl, false );
#else
			if ((p_ctrl->config.bosa.loop_mode == OPTIC_BOSA_DUALLOOP) &&
					(loop_mode_old == OPTIC_BOSA_OPENLOOP))
			{
				ret = optic_fifo_write ( &(p_ctrl->event_worker),
						 &(p_ctrl->fifo_worker),
						 OPTIC_FIFO_BOSA_DUALLOOP_TRUE,
						 NULL, 0 );
			} else {
				ret = optic_fifo_write ( &(p_ctrl->event_worker),
					 &(p_ctrl->fifo_worker),
					 OPTIC_FIFO_BOSA_DUALLOOP,
					 NULL, 0 );
			}
#endif
			loop_mode_old = OPTIC_BOSA_DUALLOOP;

			if (ret != OPTIC_STATUS_OK)
				continue;
		}
	}
#ifdef OPTIC_LIBRARY
	while (0);
#endif
	return 0;
}

static void dualloop ( struct optic_control *p_ctrl, const bool reset_states )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	static bool first_entry = true;
	bool update[2];
	bool learn[2] = {false, false};
	bool reset[2] = { false, false };
	static bool reset_bias_low = false;
	uint8_t i;
	static uint8_t cnt_first_entry = 0;
	enum optic_current_type type;
	uint16_t temp_thresh = p_ctrl->config.temperature_thres_mpdcorr <<
			       OPTIC_FLOAT2INTSHIFT_TEMPERATURE;
	uint16_t temp_int = p_ctrl->calibrate.temperature_int;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);
	static uint16_t temp_int_old = 0;
	static uint16_t average[2] = {0, 0};
	int16_t dac_coarse[2], dac_fine[2];
	bool calibrate[2];
	uint16_t temp_index = p_ctrl->config.temp_ref -
			      p_ctrl->config.range.tabletemp_extnom_min;

	if (reset_states == true) {
		first_entry = true;
		cnt_first_entry = 0;
		temp_int_old = 0;
		average[0] = 0;
		average[1] = 0;
		return;
	}

	/* GPONSW-663: stop dualloop regulation upon rogue interrupt */
	if(p_ctrl->state.interrupts.tx_p0_interburst_alarm)
		return;

	/** init Ibias/Imod with the first "regular" temperature */
	if (first_entry == true) {
		for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) {
			type = (enum optic_current_type) i;
			/* Abias/Amod <-> LUT
			(update -> Ibias/Imod) */
			ret = optic_mpd_biasmod_update ( p_ctrl, type );
		}

		/* bias/mod is set after few time: this loop is for avoiding
		   "reset" bias/mod */
		ret = optic_ll_mpd_bias_check ( &update[OPTIC_BIAS] );
		ret = optic_ll_mpd_mod_check ( &update[OPTIC_MOD] );

		if ((update[OPTIC_BIAS] == true) &&
		    (update[OPTIC_MOD] == true) && (++cnt_first_entry > 1)) {
			first_entry = false;
		} else {
			return;
		}
	}

	/** Tbosa > dTcal -> MPD calibration */
	/** \todo move to measurement_thread to avoid fifo overload */
	if ((abs(temp_int - temp_int_old) >= temp_thresh) ||
	    (p_ctrl->calibrate.dualloop_control == 0)) {
		temp_int_old = temp_int;

		/* update the bias low saturation value */
		if (is_falcon_chip_a2x()) {
			/* GPONSW-927: get the index based on the actual temperature */
			temp_index = (temp_int >> OPTIC_FLOAT2INTSHIFT_TEMPERATURE) -
								p_ctrl->config.range.tabletemp_extnom_min;
			/* init to 0 */
			ret = optic_mpd_biaslowsat_set ( p_ctrl, 0 );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("dualloop: %d",
						ret);
			}
		}


		/* either toggling between P0/P1 control or both in parallel */
		switch(p_ctrl->calibrate.dualloop_control) {
		case 0:
			/* for optic calibration (used by cal_mpd_level_find) */
			p_ctrl->calibrate.dualloop_control = 1;
			calibrate[0] = false;
			calibrate[1] = true;
			break;
		case 1:
			/* for optic calibration (used by cal_mpd_level_find) */
			p_ctrl->calibrate.dualloop_control = 0;
			calibrate[0] = true;
			calibrate[1] = false;
			break;
		default:
			/* standard flow: MPD calibration for P0 and P1 */
			calibrate[0] = OPTIC_MPD_CALIBRATE_P0;
			calibrate[1] = OPTIC_MPD_CALIBRATE_P1;
			break;
		}

		/* gain correction with offset cancellation */
		ret = optic_mpd_calibrate_level ( p_ctrl, 
			OPTIC_MPD_CALIBRATE_OFFSET, calibrate,
			dac_coarse, dac_fine);

		if (ret != OPTIC_STATUS_OK)
			return;

		ret = optic_mpd_codeword_calc ( p_ctrl, calibrate,
						OPTIC_MPD_CALIBRATE_OFFSET,
						dac_coarse, dac_fine );
		if (ret != OPTIC_STATUS_OK)
			return;

		return;
	}

	if (p_ctrl->calibrate.temperature_ext == 0)
		return;



	/** dual loop regulation - independent of external temperature */
	for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) {
		type = (enum optic_current_type) i;

		/* for Bias/Mod: read CID counters, read Abias/Amod -> average */
		/* note, optic_mpd_regulation_get can throw
			OPTIC_STATUS_MPD_UPDATE_THRES_NOT_REACHED */
		ret = optic_mpd_regulation_get ( p_ctrl, type,
						 &(update[i]),
						 &(average[i]),
						 &reset_bias_low);
		if (ret < OPTIC_STATUS_OK)
			continue;

		/** bias/mod average update */
		if ((update[i] == true) && ((type!=OPTIC_BIAS) ||
				(reset_bias_low == false))){
			ret = optic_mpd_stable_get ( p_ctrl, type,
						     average[i],
						     &(reset[i]));
			if (ret != OPTIC_STATUS_OK)
				continue;
		}

		/** average not ready -> update = false +
				OPTIC_STATUS_MPD_UPDATE_THRES_NOT_REACHED */
		if (((update[i] == false) &&
		    ((ret == OPTIC_STATUS_MPD_NOUPDATE_TIMEOUT))) ||
		    ((reset[i] == true) && reset_bias_low == false)) {
			/** Abias/Amod <-> LUT  (update -> Ibias/Imod) */

			/** note, update can throw
			    OPTIC_STATUS_MPD_UPDATE_THRES_NOT_REACHED */
			ret = optic_mpd_biasmod_update ( p_ctrl, type );
			if (ret != OPTIC_STATUS_OK)
				continue;

			ret = optic_mpd_cint_set ( p_ctrl, i,
						   bosa->intcoeff_init[i] );
			if (ret != OPTIC_STATUS_OK)
				continue;

			continue;
		}

		/** GPONSW-593 */
		/* the trigger for this condition is processed
		 * in optic_mpd_regulation_get() function */
		if ((update[i] == true) && (type == OPTIC_BIAS) &&
			(reset_bias_low == true)) {
			ret = optic_mpd_p0_correct ( p_ctrl);
			if (ret != OPTIC_STATUS_OK)
				continue;

			/* update criteria is valid for 1s only */
			update[i] = false;
			continue;
		}
		/** GPONSW-593 end */

		if ((update[i] == true) && (reset[i] == false)) {
			if (p_ctrl->calibrate.stable[i] == true) {
				/* integration coefficient increasable ? */
				if (p_ctrl->calibrate.intcoeff[i] <
				    p_ctrl->config.range.intcoeff_max[i]) {
					ret = optic_mpd_cint_set ( p_ctrl, type,
					      p_ctrl->calibrate.intcoeff[i]+1 );
					if (ret != OPTIC_STATUS_OK)
						continue;
				} else {
					/* Abias/Amod <-> LUT  (learn -> LUT)
					   TRY to learn (if learn thresholds
					   exceeded) */
					ret = optic_mpd_biasmod_learn ( p_ctrl,
							type, &learn[i] );
					if (ret != OPTIC_STATUS_OK)
						continue;
				}
			} else {
				/* integration coefficient increasable ? */
				if (p_ctrl->calibrate.intcoeff[i] >
				    bosa->intcoeff_init[i]) {

					ret = optic_mpd_cint_set ( p_ctrl, type,
					      p_ctrl->calibrate.intcoeff[i]-1 );
					if (ret != OPTIC_STATUS_OK)
						continue;
				}
			}
		}
	} /* end for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) */
	/* both (bias & mod) are stable -> learning criteria .. */
	if ((p_ctrl->config.bosa.stablethreshold[OPTIC_BIAS] == false) ||
	    (p_ctrl->config.bosa.stablethreshold[OPTIC_MOD] == false))
		return;

#if (OPTIC_MPD_LEARNING == ACTIVE)
	/* backcalculation of Ith/SE -> new calculation of all 3 (powerlevel)
	   ibias/imod - no setting! */
	if ((learn[OPTIC_BIAS] == true) || (learn[OPTIC_MOD] == true)) {
		ret = optic_calc_ith_se ( p_ctrl );
		if (ret != OPTIC_STATUS_OK)
			return;

		ret = optic_calc_ibiasimod ( p_ctrl );
		if (ret != OPTIC_STATUS_OK)
			return;

		/** \todo check, if necessary */
#if (OPTIC_DIRECT_TABLE_UPDATE == ACTIVE)
#ifndef OPTIC_LIBRARY
		/* tell the application: new ith/se values to store */
		optic_fifo_write ( &(p_ctrl->event_worker),
				   &p_ctrl->fifo_worker,
			   	   OPTIC_FIFO_TIMESTAMP,
			   	   (void*) &(p_ctrl->calibrate.timestamp),
			   	   sizeof(p_ctrl->calibrate.timestamp));
#endif
#endif
	}
#endif

	return;
}

#ifndef OPTIC_LIBRARY
int32_t optic_thread_worker ( IFXOS_ThreadParams_t *param )
{
	struct optic_control *p_ctrl = (struct optic_control *) param->nArg1;
	struct optic_device *p_dev;
	struct optic_fifo_data *p_src;
	uint32_t len = 0;

	while (p_ctrl->worker_run == true) {
		if (optic_signal_pending ( current ))
			break;
		/* wait for Activating */
		if (IFX_Var_Fifo_isEmpty (&p_ctrl->fifo_worker.data))
			if (IFXOS_EventWait (&p_ctrl->event_worker, 1000, NULL)
							!= IFX_SUCCESS) {
				continue;
			}
		len = 0;
		p_src = (struct optic_fifo_data *)
			IFX_Var_Fifo_peekElement ( &p_ctrl->fifo_worker.data,
						   &len );
		if (p_src == NULL)
			continue;

		if ((p_src->header.id == OPTIC_FIFO_EXIT) &&
		    (p_ctrl->worker_run == false))
		    	return 0;

		/* special handling for OPTIC_FIFO_BOSA_DUALLOOP: BOSA/dualloop */
		if (p_src->header.id == OPTIC_FIFO_BOSA_DUALLOOP) {
			dualloop ( p_ctrl, false );
		}
		if (p_src->header.id == OPTIC_FIFO_BOSA_DUALLOOP_TRUE) {
			dualloop ( p_ctrl, true );
		}
		/* special handling for OPTIC_FIFO_STATE_CHANGE: HotPlug/LED */
		if (p_src->header.id == OPTIC_FIFO_STATE_CHANGE) {
#ifdef OPTIC_STATE_HOTPLUG_EVENT
			optic_hotplug_state ( p_src->data.state );
#endif
			/* state machine */
			switch (p_src->data.state) {
			case OPTIC_STATE_CONFIG:
/** \todo cleanup start without tables */
#ifndef OPTIC_LIBRARY
				optic_state_set ( p_ctrl, OPTIC_STATE_TABLE_INIT );
				break;
			case OPTIC_STATE_TABLE_INIT:
				optic_table_completion ( p_ctrl );
#else
				optic_state_set ( p_ctrl,
						  OPTIC_STATE_TABLE_CALC);
#endif
				break;
			case OPTIC_STATE_TABLE_CALC:
				goi_init_ctrl ( p_ctrl );
				break;
			default:
				break;
			}
		}
		/* special handling for OPTIC_FIFO_TIMESTAMP: HotPlug/LED */
		if (p_src->header.id == OPTIC_FIFO_TIMESTAMP) {
			optic_hotplug_timestamp ( p_src->data.time );
		}

		if (p_ctrl->p_dev_head == NULL) {
			optic_fifo_read ( &p_ctrl->fifo_worker, NULL, &len );
			continue;
		}
		if (IFXOS_MutexGet(&p_ctrl->list_lock) != IFX_SUCCESS)
			continue;

		p_dev = p_ctrl->p_dev_head;
		while (p_dev) {
			if ((p_dev->fifo_nfc.enable) && (optic_fifo_cloneentry
			    (&p_dev->fifo_nfc, p_src, len )
			     == OPTIC_STATUS_OK)) {
				IFXOS_DrvSelectQueueWakeUp(&p_dev->select_queue,
						IFXOS_DRV_SEL_WAKEUP_TYPE_RD);
			}
			p_dev = p_dev->p_next;
		}
		IFXOS_MutexRelease(&p_ctrl->list_lock);

		optic_fifo_read ( &p_ctrl->fifo_worker, NULL, &len );
	}
	return 0;
}
#endif

enum optic_errorcode optic_devicelist_add ( struct optic_control *p_ctrl,
                                            struct optic_device *p_dev )
{
	struct optic_device *p_old;

	if (IFXOS_MutexGet(&p_ctrl->list_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;

   	if (p_ctrl->p_dev_head == NULL) {
		p_ctrl->p_dev_head = p_dev;
	} else {
		p_old = p_ctrl->p_dev_head;

		while (p_old->p_next != NULL) {
			p_old = p_old->p_next;
		}
		p_old->p_next = p_dev;
		p_dev->p_prev = p_old;
	}
	IFXOS_MutexRelease(&p_ctrl->list_lock);
	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_devicelist_delete ( struct optic_control *p_ctrl,
                                               struct optic_device *p_dev )
{
	if (IFXOS_MutexGet(&p_ctrl->list_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;

	if ((p_dev->p_prev != NULL) && (p_dev->p_next != NULL)) {
		p_dev->p_prev->p_next = p_dev->p_next;
		p_dev->p_next->p_prev = p_dev->p_prev;
	} else
	if ((p_dev->p_prev != NULL) && (p_dev->p_next == NULL)) {
		p_dev->p_prev->p_next = NULL;
	} else
	if ((p_dev->p_prev == NULL) && (p_dev->p_next != NULL)) {
		p_dev->p_next->p_prev = NULL;
		p_ctrl->p_dev_head = p_dev->p_next;
	} else {
		p_ctrl->p_dev_head = NULL;
	}

	IFXOS_MutexRelease(&p_ctrl->list_lock);
	return OPTIC_STATUS_OK;
}



enum optic_errorcode optic_device_open ( struct optic_control *p_ctrl,
                                         struct optic_device *p_dev )
{
	if (p_dev == NULL)
		return OPTIC_STATUS_ERR;

	memset(p_dev, 0x00, sizeof(struct optic_device));
#ifndef OPTIC_LIBRARY
	if (optic_fifo_init ( &p_dev->fifo_nfc, "device" ) != OPTIC_STATUS_OK)
		return OPTIC_STATUS_ERR;

	IFXOS_DrvSelectQueueInit ( &p_dev->select_queue );

	p_dev->p_ctrl = p_ctrl;

	if (optic_devicelist_add ( p_ctrl, p_dev ) != OPTIC_STATUS_OK)
		return OPTIC_STATUS_ERR;
#else
	p_dev->p_ctrl = p_ctrl;
	p_ctrl->p_dev_head = p_dev;
#endif
	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_device_close ( struct optic_device *p_dev )
{
	if (p_dev == NULL)
		return OPTIC_STATUS_ERR;
#ifndef OPTIC_LIBRARY
	optic_fifo_delete ( &p_dev->fifo_nfc );
	IFXOS_MemFree ( p_dev );
#endif
	return OPTIC_STATUS_OK;
}

#ifdef INCLUDE_DEBUG_SUPPORT
enum optic_errorcode optic_debuglevel_set ( struct optic_device *p_dev,
                                            const struct optic_debuglevel
                                            *param )
{
	(void) p_dev;

	optic_debug_level = param->level;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_debuglevel_get ( struct optic_device *p_dev,
                                            struct optic_debuglevel *param )
{
	(void) p_dev;

	param->level = optic_debug_level;

	return OPTIC_STATUS_OK;
}
#endif

enum optic_errorcode optic_version_get ( struct optic_device *p_dev,
                                         struct optic_versionstring *param )
{
	(void) p_dev;

	if (memcpy((char *)param->version, OPTIC_VER_STR,
	    strlen(OPTIC_VER_STR) +1) == NULL)
		return OPTIC_STATUS_ERR;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_reset ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	ret = optic_ctrl_reset ( p_ctrl, false );

	return ret;
}


enum optic_errorcode optic_reconfig ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	/*OPTIC_DEBUG_ERR("optic_reconfig calls optic_ctrl_reset !");*/

	ret = optic_ctrl_reset ( p_ctrl, true );

	return ret;
}

/**
   Write to hardware register.

   \param p_dev     device structure
   \param param_in  register structure

   \return
   OPTIC_STATUS_OK    Success
   OPTIC_STATUS_ERR   in case of error
*/
enum optic_errorcode optic_register_set ( struct optic_device *p_dev,
                                          const struct optic_reg_set
                                          *param_in )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	(void) p_dev;

	ret = optic_register_write ( param_in->form,
				     (uint32_t *) param_in->address,
				     param_in->value );
	return ret;
}

/**
   Read hardware register.

   \param p_dev     device structure
   \param param_in  register structure
   \param param_out register structure

   \return
   OPTIC_STATUS_OK    Success
   OPTIC_STATUS_ERR   in case of error
*/
enum optic_errorcode optic_register_get ( struct optic_device *p_dev,
                                          const struct optic_reg_get_in
                                          *param_in,
                                          struct optic_reg_get_out *param_out)
{
	(void) p_dev;

	param_out->form = param_in->form;
	param_out->value = optic_register_read ( param_in->form,
				    (uint32_t*)param_in->address);
	return OPTIC_STATUS_OK;
}

#ifdef INCLUDE_CLI_SUPPORT
enum optic_errorcode optic_cli ( struct optic_device *p_dev,
                                 char *param )
{
	return optic_cli_command_execute ( p_dev, param, OPTIC_IO_BUF_SIZE );
}
#endif


enum optic_errorcode optic_state_set ( struct optic_control *p_ctrl,
                                       const enum optic_statetype state )
{
	uint8_t i;

	if ((p_ctrl->state.current_state==OPTIC_STATE_PLL_ERROR) && (state != OPTIC_STATE_INIT))
		return OPTIC_STATUS_NO_STATECHANGE;

	/* state change allowed? */
	switch (state) {
	case OPTIC_STATE_CONFIG:
		for (i=0; i<OPTIC_CONFIGTYPE_MAX; i++)
			if (p_ctrl->state.config_read[i] == false)
				return OPTIC_STATUS_NO_STATECHANGE;
		break;
	case OPTIC_STATE_TABLE_INIT:
		for (i=OPTIC_TABLETYPE_INTERN_MIN;
		     i<=OPTIC_TABLETYPE_INTERN_MAX; i++)
			if ((i != OPTIC_TABLETYPE_IBIASIMOD) &&
			    (p_ctrl->state.table_read[i -
			     OPTIC_TABLETYPE_INTERN_MIN] == false))
				return OPTIC_STATUS_NO_STATECHANGE;
		break;
	case OPTIC_STATE_TABLE_CALC:
		i = OPTIC_TABLETYPE_IBIASIMOD;
		if (p_ctrl->state.config_read[i] == false)
			return OPTIC_STATUS_NO_STATECHANGE;
		break;
	case OPTIC_STATE_MODECHANGE:
		if ((p_ctrl->state.current_state != OPTIC_STATE_NOMODE) &&
		    (p_ctrl->state.current_state != OPTIC_STATE_RESET) &&
		    (p_ctrl->state.current_state != OPTIC_STATE_CALIBRATE) &&
		    (p_ctrl->state.current_state != OPTIC_STATE_RUN))
			return OPTIC_STATUS_NO_STATECHANGE;
		break;
	case OPTIC_STATE_CALIBRATE:
		/* initialize the measurement */
		p_ctrl->calibrate.measurement.mode = OPTIC_MEASUREMODE_INIT;
		break;
	default:
		break;
	}
#ifdef EVENT_LOGGER_DEBUG
	{
		char s[30];
		sprintf(s, "optic_state_set: %d -> %d",
			p_ctrl->state.current_state,
			state);
		EL_LOG_EVENT_USER_STR(1, 0, 0, s);
	}
#endif

#ifdef OPTIC_LIBRARY
	if (state == OPTIC_STATE_CONFIG) {
		/** \todo come up without tables as workaround now,
		should be programmed from host once the
		network is available */
		p_ctrl->state.current_state = OPTIC_STATE_TABLE_CALC;
	}
	else
	/* call to goi_init must be done manually later */
#endif
	p_ctrl->state.current_state = state;

	if ((state == OPTIC_STATE_BOOT) ||
	    ((p_ctrl->state.index_buffer +1) == OPTIC_STATE_HISTORY_DEPTH))
		p_ctrl->state.index_buffer = 0;
	else
		p_ctrl->state.index_buffer ++;

	p_ctrl->state.buffer[p_ctrl->state.index_buffer] =
						p_ctrl->state.current_state;


#ifndef OPTIC_LIBRARY
	/* state machine logic in worker thread */
	optic_fifo_write ( &(p_ctrl->event_worker), &p_ctrl->fifo_worker,
			   OPTIC_FIFO_STATE_CHANGE, (void*) &state,
			   sizeof(enum optic_statetype));
#endif

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_state_get ( struct optic_control *p_ctrl,
                                       enum optic_statetype
                                       state[OPTIC_STATE_HISTORY_DEPTH] )
{
	uint8_t i, j;

	if (state == NULL)
		return OPTIC_STATUS_ERR;

	i = 0;
	j = p_ctrl->state.index_buffer;
	do {
		state[i] = p_ctrl->state.buffer[j];
		if (j!=0) {
			j--;
		} else {
			if (state[i] != OPTIC_STATE_BOOT)
				j = OPTIC_STATE_HISTORY_DEPTH-1;
		}
	} while (++i < OPTIC_STATE_HISTORY_DEPTH);

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_mode_set ( struct optic_device *p_dev,
	                              const struct optic_mode *param )
{
	enum optic_errorcode ret;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
#ifdef INCLUDE_DEBUG_SUPPORT
	enum optic_debug_levels temp = optic_debug_level;
#endif/* INCLUDE_DEBUG_SUPPORT */

	if ((p_ctrl->state.current_state != OPTIC_STATE_BOOT) &&
	    (p_ctrl->state.current_state != OPTIC_STATE_RUN)) {
		OPTIC_DEBUG_ERR("optic driver not in switchable mode "
				"-OPTIC_STATE_RUN-");
		return OPTIC_STATUS_MODESET_FAIL;
	}

	p_ctrl->config.mode = param->mode;

#ifdef INCLUDE_DEBUG_SUPPORT
	/* force printout of mode */
	optic_debug_level = OPTIC_DBG_MSG;
	if (param->mode != OPTIC_NOMODE)
		OPTIC_DEBUG_MSG ("%s mode activated",
				(param->mode == OPTIC_OMU)? "OMU" : "BOSA");
	else
		OPTIC_DEBUG_MSG ("no mode selected - use optic_mode_set");
	optic_debug_level = temp;
#endif/* INCLUDE_DEBUG_SUPPORT */

	ret = optic_ctrl_reset ( p_ctrl, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (p_ctrl->state.current_state != OPTIC_STATE_BOOT) {
		ret = optic_state_set ( p_ctrl, OPTIC_STATE_MODECHANGE );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		OPTIC_DEBUG_MSG("optic_goi_init for activation called "
				"automatically");
		ret = goi_init_ctrl ( p_ctrl );
	}

	return ret;
}

enum optic_errorcode optic_isr_register ( struct optic_device *p_dev,
	                                  const struct optic_register *param )
{
	struct optic_control *p_ctrl;
	uint8_t i;

	if (p_dev == NULL) {
		for (i=0; i<OPTIC_INSTANCES_MAX; i++) {
			p_ctrl = &optic_ctrl[i];
			p_ctrl->config.callback_isr = param->callback_isr;
		}
	} else {
		p_ctrl = p_dev->p_ctrl;
		p_ctrl->config.callback_isr = param->callback_isr;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ctrl_reset ( struct optic_control *p_ctrl,
					const bool init )
{
	uint8_t i;
	enum optic_errorcode ret;
	static bool first_start = true;
	static enum optic_manage_mode mode_old = OPTIC_NOMODE;

	if (init == true)
		first_start = true;


	optic_timer_stop (OPTIC_TIMER_ID_MEASURE);
	if (mode_old == OPTIC_OMU) {
		/* cleanup omu stuff */
		if (p_ctrl->config.omu.signal_detect_avail == true) {
			i = p_ctrl->config.omu.signal_detect_port;
#ifndef OPTIC_LIBRARY
			ret = optic_ll_gpio_exit ( i );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("optic_ll_gpio_exit: %d",
						ret);
			}
#endif
		}
	}

	if ((mode_old == OPTIC_BOSA) || (mode_old == OPTIC_BOSA_2)) {
		/* cleanup bosa stuff */
		ret = optic_ll_mpd_exit ( );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_mpd_exit: %d", ret);
		}

		ret = optic_ll_int_all_set ( OPTIC_DISABLE );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_int_all_set: %d", ret);
		}

		ret = optic_ll_dcdc_apd_set ( OPTIC_DISABLE );
		if (ret != OPTIC_STATUS_OK) {
	 		OPTIC_DEBUG_ERR("optic_ll_dcdc_apd_set: %d", ret);
		}

		/* reset dual loop regulation -> MPD calibration */
		dualloop ( p_ctrl, true );
	}

	p_ctrl->calibrate.measurement.mode = OPTIC_MEASUREMODE_INIT;
	p_ctrl->config.run_mode = OPTIC_RUNMODE;
	p_ctrl->config.debug_mode = false;

	p_ctrl->config.callback_isr = NULL;

	p_ctrl->calibrate.powerlevel = OPTIC_POWERLEVEL_0;
	p_ctrl->calibrate.auto_powerlevel = OPTIC_POWERLEVEL_0;

	p_ctrl->calibrate.stable[0]              = false;
	p_ctrl->calibrate.stable[1]              = false;
	p_ctrl->calibrate.gain_correct_p0        = 
		(1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR);
	p_ctrl->calibrate.gain_correct_p1        = 
		(1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR);
	p_ctrl->calibrate.digit_codeword_p0      = 0;
	p_ctrl->calibrate.digit_codeword_p1      = 0;
	p_ctrl->calibrate.dbias                  = 0;
	p_ctrl->calibrate.dmod                   = 0;
	p_ctrl->calibrate.vapd_target            = 0;
	p_ctrl->calibrate.thresh_current_los     = 0;
	p_ctrl->calibrate.thresh_current_ovl     = 0;
	p_ctrl->calibrate.thresh_voltage_los     = 0;
	p_ctrl->calibrate.thresh_voltage_ovl     = 0;

	p_ctrl->calibrate.abias_average          = 0;
	p_ctrl->calibrate.amod_average           = 0;

	p_ctrl->calibrate.meas_voltage_1490_rssi = 0;
	p_ctrl->calibrate.meas_current_1490_rssi = 0;
	p_ctrl->calibrate.meas_voltage_1550_rf   = 0;
	p_ctrl->calibrate.meas_voltage_1550_rssi = 0;

	p_ctrl->calibrate.meas_power_1490_rssi   = 0;

	p_ctrl->calibrate.dualloop_control =       2; /* P0 + P1 in parallel */

	if (first_start == true) {
		for (i=0; i<OPTIC_CONFIGTYPE_MAX; i++)
			p_ctrl->state.config_read[i] = false;
		for (i=OPTIC_TABLETYPE_INTERN_MIN;
		     i<=OPTIC_TABLETYPE_INTERN_MAX; i++)
			p_ctrl->state.table_read[i-OPTIC_TABLETYPE_INTERN_MIN] =
									false;
		for (i=0; i<OPTIC_TEMPERATURE_HISTORY_DEPTH; i++) {
			p_ctrl->state.temperatures[i].timestamp = 0;
		}
		p_ctrl->state.index_temperature = 0;

		/* timestamp offset configured by goi_cfg_set and doublechecked
		   against ibias/imod table age values */
		p_ctrl->calibrate.timestamp = 0;
		p_ctrl->config.fcsi.gvs = 0;               /* use reset value */
		p_ctrl->calibrate.rx_offset = 0;

		for (i=OPTIC_POWERLEVEL_0; i<OPTIC_POWERLEVEL_MAX; i++) {
			/* set to 0 to use reset value -
			   if no fcsi config follows */
			p_ctrl->config.fcsi.dd_loadn[i] = 0;
			p_ctrl->config.fcsi.dd_bias_en[i] = 0;
			p_ctrl->config.fcsi.dd_loadp[i] = 0;
			p_ctrl->config.fcsi.dd_cm_load[i] = 0;
			p_ctrl->config.fcsi.bd_loadn[i] = 0;
			p_ctrl->config.fcsi.bd_bias_en[i] = 0;
			p_ctrl->config.fcsi.bd_loadp[i] = 0;
			p_ctrl->config.fcsi.bd_cm_load[i] = 0;
		}

		/** pre init */

		/* deactivate clocks, debug why this does stall!! */
		/*
		ret = optic_ll_sys_gpon_clockdisable();
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_sys_gpon_clockenable: %d",
					ret);
		}
		*/
		/* start pll */
		ret = optic_ll_pll_calibrate();
		if (ret != OPTIC_STATUS_PLL_LOCKED) {
			OPTIC_DEBUG_ERR(" PLL not locked, error code = %d",
					ret);
		}

		/* read chip version */
		ret = optic_ll_status_chip_get ( &chip_version );
		if (ret != OPTIC_STATUS_OK) {
		 	OPTIC_DEBUG_ERR("optic_ctrl_reset/optic_ll_status_chip_get: %d",
		 			ret);
			return OPTIC_STATUS_INIT_FAIL;
		}
	}

	if (mode_old != OPTIC_NOMODE) {
		optic_irq_set ( mode_old, OPTIC_DISABLE );

		/* init FCSI */
		ret = optic_ll_fcsi_init ( OPTIC_NOMODE );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_fcsi_init: %d",
					ret);
		}
	}

	/* activate PLL OMU/BOSA */
	ret = optic_ll_pll_start( p_ctrl->config.mode );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_pll_start: %d",
				ret);
	}

	/* init FCSI */
	ret = optic_ll_fcsi_init ( p_ctrl->config.mode );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_fcsi_init: %d",
				ret);
	}

	/* first call */
	if (first_start == true) {
		/* activate clocks */
		ret = optic_ll_sys_gpon_clockenable();
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_sys_gpon_clockenable: %d",
					ret);
		}

		ret = optic_state_set ( p_ctrl, OPTIC_STATE_INIT );
		if (ret != OPTIC_STATUS_OK)
			OPTIC_DEBUG_ERR("optic_state_set: %d", ret);

		first_start = false;
	} else {

		ret = optic_state_set ( p_ctrl, OPTIC_STATE_RESET );
		if (ret != OPTIC_STATUS_OK)
			OPTIC_DEBUG_ERR("optic_state_set: %d", ret);
	}

	mode_old = p_ctrl->config.mode;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_interrupt ( struct optic_control *p_ctrl )
{
	(void) p_ctrl;
	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_temperature_store ( struct optic_control *p_ctrl )
{
	uint8_t index = p_ctrl->state.index_temperature;

	if (index >= OPTIC_TEMPERATURE_HISTORY_DEPTH)
		index = 0;

#if defined(LINUX) && defined (__KERNEL__) && !defined(OPTIC_SIMULATION)
	p_ctrl->state.temperatures[index].timestamp = jiffies;
#else
	p_ctrl->state.temperatures[index].timestamp =
						p_ctrl->calibrate.timestamp;
#endif
	p_ctrl->state.temperatures[index].temp_int =
		optic_shift_temp_back (p_ctrl->calibrate.temperature_int);
	p_ctrl->state.temperatures[index].temp_ext =
		optic_shift_temp_back (p_ctrl->calibrate.temperature_ext);

	p_ctrl->state.index_temperature = index+1;

	return OPTIC_STATUS_OK;
}

void optic_timer_measure ( struct optic_control *p_ctrl )
{
#ifdef OPTIC_LIBRARY
	IFXOS_ThreadParams_t param;

	/* poll measurements threads */
	param.nArg1 = (int)p_ctrl;
	optic_thread_measure (&param);
#else
	IFXOS_EventWakeUp ( &p_ctrl->event_measure );
#endif
	/* reload timer */
	if (p_ctrl->state.current_state == OPTIC_STATE_CALIBRATE)
		optic_timer_start ( OPTIC_TIMER_ID_MEASURE,
				    OPTIC_TIMER_MEASURE_CALIBRATION);
	else
		optic_timer_start ( OPTIC_TIMER_ID_MEASURE,
				    p_ctrl->mm_interval);
}

int optic_context_init ( void *ctrl, uint8_t nr )
{
	struct optic_control *p_ctrl = (struct optic_control *) ctrl;
	char buffer[8];

	if (IFXOS_MutexInit ( &p_ctrl->list_lock ) != IFX_SUCCESS) {
		OPTIC_DEBUG_ERR("can't init list_lock mutex %d", nr);
		return -1;
	}

	/* init worker thread */
	sprintf(buffer, "ow/%d",nr);
	p_ctrl->worker_run = true;
	p_ctrl->config.mode = OPTIC_NOMODE;
	p_ctrl->mm_interval = OPTIC_TIMER_MEASURE;
#ifndef OPTIC_LIBRARY
	if ((IFXOS_EventInit ( &p_ctrl->event_worker) != IFX_SUCCESS ) ||
	    (IFXOS_ThreadInit ( &p_ctrl->thread_ctx_worker, buffer,
			        optic_thread_worker,
				OPTIC_WORKER_THREAD_STACK_SIZE,
				OPTIC_WORKER_THREAD_PRIO,
				(ulong_t) p_ctrl, 0 ) != IFX_SUCCESS)) {
		OPTIC_DEBUG_ERR("can't start worker thread %s", buffer);
		return -1;
	}

	/* init worker thread message fifo */
	sprintf(buffer, "of/%d", nr);
	if (optic_fifo_init ( &p_ctrl->fifo_worker, buffer ) != 0) {
		OPTIC_DEBUG_ERR("can't init fifo %s", buffer);
		return -1;
	}
	p_ctrl->fifo_worker.enable = true;

	/* init measurement wake up event and measure thread */
	sprintf(buffer, "om/%d", nr);
	p_ctrl->measure_run = true;

	if ((IFXOS_EventInit ( &p_ctrl->event_measure ) != IFX_SUCCESS ) ||
	    (IFXOS_ThreadInit ( &p_ctrl->thread_ctx_measure, buffer,
				optic_thread_measure,
				OPTIC_MEASURE_THREAD_STACK_SIZE,
				OPTIC_MEASURE_THREAD_PRIO,
				(ulong_t) p_ctrl, 0 ) != IFX_SUCCESS)) {
		OPTIC_DEBUG_ERR("can't start measurement thread %s", buffer);
		return -1;
	}
	if (IFXOS_MutexInit ( &p_ctrl->access.dac_lock ) != IFX_SUCCESS) {
		OPTIC_DEBUG_ERR("can't init dac_lock mutex %d", nr);
		return -1;
	}
	if (IFXOS_MutexInit ( &p_ctrl->access.table_lock ) != IFX_SUCCESS) {
		OPTIC_DEBUG_ERR("can't init table_lock mutex %d", nr);
		return -1;
	}
#endif
	return 0;
}

/*
   see header
*/
int optic_context_free ( void *ctrl )
{
	struct optic_control *p_ctrl = (struct optic_control *) ctrl;
#ifndef OPTIC_LIBRARY
	struct optic_device *p_dev, *p_delete;
	if (p_ctrl->config.omu.signal_detect_avail == true)
		optic_ll_gpio_exit ( p_ctrl->config.omu.signal_detect_port );

	optic_ll_int_all_set ( OPTIC_DISABLE );

	optic_irq_set ( p_ctrl->config.mode, OPTIC_DISABLE );
#endif

	/* create temperature table */
	if (p_ctrl->table_temperature_corr != NULL)
		IFXOS_MemFree(p_ctrl->table_temperature_corr);
	if (p_ctrl->table_temperature_nom != NULL)
		IFXOS_MemFree(p_ctrl->table_temperature_nom);

#ifndef OPTIC_LIBRARY
	/* delete measurement timer */
	optic_timer_stop (OPTIC_TIMER_ID_MEASURE);
	/* delete apd adaption timer */
	optic_timer_stop (OPTIC_TIMER_ID_APD_ADAPT);

	/* delete worker thread */
	p_ctrl->worker_run = false;
	optic_fifo_write ( &(p_ctrl->event_worker), &(p_ctrl->fifo_worker),
	                   OPTIC_FIFO_EXIT, NULL, 0 );
	IFXOS_ThreadDelete ( &p_ctrl->thread_ctx_worker, 1000 );
	IFXOS_EventDelete ( &p_ctrl->event_worker );

	/* delete worker thread message fifo */
	optic_fifo_delete ( &p_ctrl->fifo_worker );

	/* delete measurement wake up event and measure thread */
	p_ctrl->measure_run = false;
	IFXOS_EventWakeUp ( &p_ctrl->event_measure );
	IFXOS_ThreadDelete ( &p_ctrl->thread_ctx_measure, 1000 );
	IFXOS_EventDelete ( &p_ctrl->event_measure );

	IFXOS_EventDelete ( &p_ctrl->calibrate.measurement.ocal.event_measure );

	if (IFXOS_MutexGet(&p_ctrl->list_lock) == IFX_SUCCESS) {
		p_dev = p_ctrl->p_dev_head;
		while (p_dev) {
			p_delete = p_dev;
			p_dev = p_dev->p_next;
			optic_device_close ( p_delete );
		}
		IFXOS_MutexRelease ( &p_ctrl->list_lock );
	}

	IFXOS_MutexDelete ( &p_ctrl->list_lock );
	IFXOS_MutexDelete ( &p_ctrl->access.dac_lock );
	IFXOS_MutexDelete ( &p_ctrl->access.table_lock );
#endif
	return 0;
}

/******************************************************************************/

const struct optic_entry optic_function_table[OPTIC_MAX] = {
/*  0 */  TE1in  (FIO_OPTIC_REGISTER_SET,       sizeof(struct optic_reg_set),
						optic_register_set),
/*  1 */  TE2    (FIO_OPTIC_REGISTER_GET,       sizeof(struct optic_reg_get_in),
					        sizeof(struct optic_reg_get_out),
					    	optic_register_get),
#ifdef INCLUDE_DEBUG_SUPPORT
/*  2 */  TE1in  (FIO_OPTIC_DEBUGLEVEL_SET,     sizeof(struct optic_debuglevel),
						optic_debuglevel_set),
/*  3 */  TE1out (FIO_OPTIC_DEBUGLEVEL_GET,     sizeof(struct optic_debuglevel),
						optic_debuglevel_get),
#else
/*  2 */  TE0    (FIO_OPTIC_DEBUGLEVEL_SET,     NULL),
/*  3 */  TE0    (FIO_OPTIC_DEBUGLEVEL_GET,     NULL),
#endif
/*  4 */  TE1out (FIO_OPTIC_VERSION_GET,        sizeof(struct optic_versionstring),
 						optic_version_get),
/*  5 */  TE0    (FIO_OPTIC_RESET,              optic_reset),
/*  6 */  TE0    (FIO_OPTIC_RECONFIG,           optic_reconfig),
/*  7 */  TE1in  (FIO_OPTIC_MODE_SET,           sizeof(struct optic_mode),
						optic_mode_set),
/*  8 */  TE1in  (FIO_OPTIC_ISR_REGISTER,       sizeof(struct optic_register),
						optic_isr_register)
};

/*! @} */

/*! @} */
