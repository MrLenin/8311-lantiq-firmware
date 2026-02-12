/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/


#include "drv_optic_calc.h"
#include "drv_optic_reg_base.h"
#include "drv_optic_dcdc_apd.h"


/* 640uA a 4 slices = 2.56 mA << OPTIC_FLOAT2INTSHIFT_CURRENT
 * -> measurement in the lab = 2.84 mA
 * */
#define LD_MOD_DAC_OFFSET 	727
/* 560uA a 4 slices = 2.24 mA << OPTIC_FLOAT2INTSHIFT_CURRENT
 * -> measurement in the lab = 2.55 mA
 * */
#define LD_BIAS_DAC_OFFSET	653


/** \addtogroup MAPI_REFERENCE_INTERNAL Management API Reference - Internals
	@{
*/

/** \addtogroup OPTIC_COMMON_INTERNAL Optic Common Driver Interface - Internal
   @{
*/


static enum optic_errorcode optic_calc_table_get ( struct optic_control *p_ctrl,
                                       	           const enum optic_tabletype
                                       	           type,
                                	     	   uint16_t *tabledepth,
                                	     	   uint8_t *type_index,
						   struct
						   optic_table_temperature_corr
						   **table_corr,
						   struct
						   optic_table_temperature_nom
						   **table_nom );

static enum optic_errorcode optic_calc_table_addr ( struct optic_control
 						    *p_ctrl,
 						    const enum optic_tabletype
 						    type,
						    const uint16_t temp_index,
						    const uint16_t offset,
					            ulong_t *addr );
static bool optic_calc_interpolation_need ( struct optic_control *p_ctrl,
					    const enum optic_tabletype type,
					    const uint16_t temp_index );
static bool optic_calc_fixsetting_need ( struct optic_control *p_ctrl,
					 const enum optic_tabletype type,
					 const uint16_t temp_index );
static enum optic_errorcode optic_calc_write ( uint8_t size,
					       ulong_t addr_dest,
					       ulong_t addr_src,
					       int32_t offset );
static enum optic_errorcode optic_calc_ipol ( uint8_t size,
					      ulong_t addr_last,
					      ulong_t addr_next,
					      uint16_t index,
					      uint16_t index_last,
					      uint16_t index_next,
					      int32_t *diff );
static enum optic_errorcode optic_fill_table_border (
					struct optic_control *p_ctrl,
					const enum optic_tabletype type,
					const uint16_t temp_index,
					const uint8_t size,
					ulong_t addr_dest,
					ulong_t addr_ref );


int optic_in_range (void *ptr, ulong_t start, ulong_t end )
{
	ulong_t addr = (ulong_t)ptr & ~KSEG1;
	start &= ~KSEG1;
	end &= ~KSEG1;

	if ((addr >= start) && (addr <= end))
		return 1;
	return 0;
}

uint32_t optic_uint_div_rounded ( uint32_t divident, uint32_t divisor )
{
	/* round compensation */
	divident += (divisor / 2);
	return (divident / divisor);
}

int32_t optic_int_div_rounded ( int32_t divident, int32_t divisor )
{
	/* round compensation */
	if (divident > 0)
		divident += (abs(divisor) / 2);
	else
		divident -= (abs(divisor) / 2);

	return (divident / divisor);
}

uint16_t optic_shift_temp_back ( const uint16_t temperature )
{
	/* round compensation */
	uint16_t temp = temperature +
	                (1 << (OPTIC_FLOAT2INTSHIFT_TEMPERATURE-1));

	return (temp >> OPTIC_FLOAT2INTSHIFT_TEMPERATURE);
}

enum optic_errorcode optic_float2int ( int32_t float_val,
				       uint8_t shift,
                                       uint16_t dec_factor,
                                       int16_t *ib,
                                       uint16_t *fb )
{
	uint32_t temp;
	bool sign;

	if ((ib == NULL) || (fb == NULL))
		return OPTIC_STATUS_ERR;

	temp = abs(float_val);
	*ib = (temp >> shift);
	if (float_val < abs(float_val))
		sign = true;
	else
		sign = false;

	*fb = (temp & ((1<<shift) -1));

	temp = (*fb * dec_factor) + (1<<(shift-1));
	*fb = (temp >> shift);

	if (*fb >= dec_factor) {
		(*ib) ++;
		(*fb) -= dec_factor;
	}

	if (sign == true)
		(*ib) *= -1;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_powerlevel2gainbank ( const enum optic_powerlevel
						 powerlevel,
			              		 enum optic_gainbank *gainbank )
{
	if (gainbank == NULL)
		return OPTIC_STATUS_ERR;

	switch (powerlevel) {
	case OPTIC_POWERLEVEL_0:
		*gainbank = OPTIC_GAINBANK_PL0;
		break;
	case OPTIC_POWERLEVEL_1:
		*gainbank = OPTIC_GAINBANK_PL1;
		break;
	case OPTIC_POWERLEVEL_2:
		*gainbank = OPTIC_GAINBANK_PL2;
		break;
	default:
		return OPTIC_STATUS_ERR;
		break;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_rangecheck_dcdc ( const struct optic_config_range
					     *range,
					     const enum optic_dcdc_type type,
					     const uint16_t dcdc_voltage )
{
	uint16_t min, max;

	switch (type) {
	case OPTIC_DCDC_APD:
		min = range->vapd_min;
		max = range->vapd_max;
		break;
	case OPTIC_DCDC_CORE:
		min = range->vcore_min;
		max = range->vcore_max;
		break;
	case OPTIC_DCDC_DDR:
		min = range->vddr_min;
		max = range->vddr_max;
		break;
	default:
		return OPTIC_STATUS_ERR;
	}

	if (dcdc_voltage < min)
		return OPTIC_STATUS_POOR;

	if (dcdc_voltage > max)
		return OPTIC_STATUS_POOR;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_rangecheck_itemp_nom ( const struct
						  optic_config_range *range,
					          const uint16_t itemp_nom )
{
	uint16_t itemp_nom_min = range->tabletemp_intnom_min <<
	                         OPTIC_FLOAT2INTSHIFT_TEMPERATURE;
	uint16_t itemp_nom_max = range->tabletemp_intnom_max <<
	                         OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

	if (itemp_nom < itemp_nom_min)
	     	return OPTIC_STATUS_INTTEMP_UNDERRUN;

	if (itemp_nom > itemp_nom_max)
	     	return OPTIC_STATUS_INTTEMP_OVERFLOW;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_rangecheck_itemp_corr ( const struct
						   optic_config_range *range,
					           const uint16_t itemp_corr )
{
	uint16_t itemp_corr_min = range->tabletemp_intcorr_min <<
	                         OPTIC_FLOAT2INTSHIFT_TEMPERATURE;
	uint16_t itemp_corr_max = range->tabletemp_intcorr_max <<
	                         OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

	if (itemp_corr < itemp_corr_min)
	     	return OPTIC_STATUS_INTTEMP_UNDERRUN;

	if (itemp_corr > itemp_corr_max)
	     	return OPTIC_STATUS_INTTEMP_OVERFLOW;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_rangecheck_etemp_nom ( const struct
						  optic_config_range *range,
					          const uint16_t etemp_nom,
					          uint16_t *temp_index )
{
	uint16_t etemp_nom_min = range->tabletemp_extnom_min <<
	                         OPTIC_FLOAT2INTSHIFT_TEMPERATURE;
	uint16_t etemp_nom_max = range->tabletemp_extnom_max <<
	                         OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

	if (etemp_nom < etemp_nom_min)
	     	return OPTIC_STATUS_EXTTEMP_UNDERRUN;

	if (etemp_nom > etemp_nom_max)
	     	return OPTIC_STATUS_EXTTEMP_OVERFLOW;

	if (temp_index != NULL) {
		*temp_index = optic_shift_temp_back ( etemp_nom ) -
			      range->tabletemp_extnom_min;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_rangecheck_etemp_corr ( const struct
						   optic_config_range *range,
					           const uint16_t etemp_corr,
					           uint16_t *temp_index )
{
	uint16_t etemp_corr_min = range->tabletemp_extcorr_min <<
	                          OPTIC_FLOAT2INTSHIFT_TEMPERATURE;
	uint16_t etemp_corr_max = range->tabletemp_extcorr_max <<
	                          OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

	if (etemp_corr < etemp_corr_min)
	     	return OPTIC_STATUS_EXTTEMP_UNDERRUN;

	if (etemp_corr > etemp_corr_max)
	     	return OPTIC_STATUS_EXTTEMP_OVERFLOW;

	if (temp_index != NULL) {
		*temp_index = optic_shift_temp_back ( etemp_corr ) -
			      range->tabletemp_extcorr_min;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_pn_gain_sel ( struct optic_control *p_ctrl )
{
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_config *config = &(p_ctrl->config);
	struct optic_measurement *measure = &(cal->measurement);
	uint8_t shift, i;
	uint32_t temp;
	int16_t um_max;

	/** Um_max [mV] = pnR[Ohm] * pnISrc[mA] + Temp_max_nom(K) / TScalref (K/mV)
                        = pnR >> OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE * pnISrc[uA]/1000
                          + Temp_max_nom / TScalref >> OPTIC_FLOAT2INTSHIFT_TSCALREF
	    Um_max [mV] = pnR * pnISrc [uA]/1000 >> OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE
	                  + Temp_max_nom << OPTIC_FLOAT2INTSHIFT_TSCALREF / TScalref

	    store Um_max[V] with << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE

	    shift: OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE - OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE
	    Um_max [V] = pnR * pnISrc [uA]/1000 << shift / 1000
	                  + Temp_max_nom << (OPTIC_FLOAT2INTSHIFT_TSCALREF+OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE)/1000 / (TScalref)

  	*/
	temp = config->measurement.pn_r;

	switch (config->measurement.pn_iref) {
	case OPTIC_IREF_20UA:
		temp *= 20;
		break;
	case OPTIC_IREF_100UA:
		temp *= 100;
		break;
	case OPTIC_IREF_400UA:
		temp *= 400;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE -
	        OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE;
	/* -> mV */
	temp = optic_uint_div_rounded ( temp, 1000 );
	/*  -> V */
	temp = optic_uint_div_rounded ( temp * (1 << shift), 1000 );

	measure->voltage_offset_pn = temp;

	/*  -> V */
	temp = optic_uint_div_rounded ( config->range.tabletemp_extnom_max *
			(1 << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE), 1000 );

	temp = temp * (1 << OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE);

	temp = optic_uint_div_rounded ( temp, config->measurement.tscal_ref );

	um_max = measure->voltage_offset_pn + temp;

	/** Um_max * gain_factor < 0,5 V
            Um_max [V] * gain_factor [/4] < 2 V << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE */
        i = OPTIC_GAIN_SELECTOR_MAX-1;

        while ((i > 0) && ((um_max * measure->gain[i].factor) >=
                           (2 << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE))) {
		i --;
	}
	measure->gain_selector_pn = i;

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode optic_calc_table_get ( struct optic_control *p_ctrl,
                                       	           const enum optic_tabletype
                                       	           type,
                                	     	   uint16_t *tabledepth,
                                	     	   uint8_t *type_index,
						   struct
						   optic_table_temperature_corr
						   **table_corr,
						   struct
						   optic_table_temperature_nom
						   **table_nom )
{
	struct optic_config_range *range = &(p_ctrl->config.range);

	if ((type >= OPTIC_TABLETYPE_TEMP_CORR_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_CORR_MAX)) {
	    	if (type_index != NULL)
	    		*type_index = type - OPTIC_TABLETYPE_TEMP_CORR_MIN;
	    	if (tabledepth != NULL)
			*tabledepth = range->tabletemp_extcorr_max + 1 -
				      range->tabletemp_extcorr_min;
	    	if (table_corr != NULL)
			*table_corr = p_ctrl->table_temperature_corr;
	    	if (table_nom != NULL)
	    		*table_nom = NULL;
	} else
	if ((type >= OPTIC_TABLETYPE_TEMP_NOM_MIN) &&
	    (type <= OPTIC_TABLETYPE_TEMP_NOM_MAX)) {
	    	if (type_index != NULL)
	    		*type_index = type - OPTIC_TABLETYPE_TEMP_NOM_MIN;
	    	if (tabledepth != NULL)
			*tabledepth = range->tabletemp_extnom_max + 1 -
				      range->tabletemp_extnom_min;
	    	if (table_corr != NULL)
			*table_corr = NULL;
	    	if (table_nom != NULL)
	    		*table_nom = p_ctrl->table_temperature_nom;
	} else
		return OPTIC_STATUS_POOR;

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode optic_calc_table_addr ( struct optic_control
						    *p_ctrl,
						    const  enum optic_tabletype
						    type,
						    const uint16_t temp_index,
						    const uint16_t offset,
					            ulong_t *addr )
{
	struct optic_config_range *range = &(p_ctrl->config.range);
	if (addr == NULL)
		return OPTIC_STATUS_ERR;

	switch (type) {
	case OPTIC_TABLETYPE_IBIASIMOD:
	case OPTIC_TABLETYPE_VAPD:
	case OPTIC_TABLETYPE_MPDRESP:
		if (temp_index > (range->tabletemp_extcorr_max -
		                  range->tabletemp_extcorr_min))
			return OPTIC_STATUS_POOR;
		*addr = (ulong_t) &(p_ctrl->table_temperature_corr[temp_index])
		        + offset;
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		if (temp_index > (range->tabletemp_extnom_max -
		                  range->tabletemp_extnom_min))
			return OPTIC_STATUS_POOR;
		*addr = (ulong_t) &(p_ctrl->table_temperature_nom[temp_index])
		        + offset;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

static bool optic_calc_interpolation_need ( struct optic_control *p_ctrl,
					    const enum optic_tabletype type,
					    const uint16_t temp_index )
{
	uint16_t tabledepth;
	uint8_t type_index;
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;

	switch (type) {
	case OPTIC_TABLETYPE_IBIASIMOD:
	case OPTIC_TABLETYPE_VAPD:
	case OPTIC_TABLETYPE_TEMPTRANS:
		if (optic_calc_table_get ( p_ctrl, type, &tabledepth,
					   &type_index, &table_corr,
					   &table_nom ) != OPTIC_STATUS_OK)
			return false;

		if (temp_index >= tabledepth)
			return false;

		if (table_corr != NULL) {
			if (table_corr[temp_index].quality[type_index]
			    == OPTIC_TABLEQUAL_INITIAL)
				return true;
			if (table_corr[temp_index].quality[type_index]
			    == OPTIC_TABLEQUAL_INTERP)
				return true;
		}

		if (table_nom != NULL) {
			if (table_nom[temp_index].quality[type_index]
			    == OPTIC_TABLEQUAL_INITIAL)
				return true;
			if (table_nom[temp_index].quality[type_index]
			    == OPTIC_TABLEQUAL_INTERP)
				return true;
		}

		break;
	default:
		return false;
	}

	return false;
}

static bool optic_calc_fixsetting_need ( struct optic_control *p_ctrl,
					 const enum optic_tabletype type,
					 const uint16_t temp_index )
{
	uint16_t tabledepth;
	uint8_t type_index;
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;

	switch (type) {
	case OPTIC_TABLETYPE_MPDRESP:
		if (optic_calc_table_get ( p_ctrl, type, &tabledepth,
					   &type_index, &table_corr,
					   &table_nom ) != OPTIC_STATUS_OK)
			return false;

		if (temp_index >= tabledepth)
			return false;

		if (table_corr != NULL) {
			if (table_corr[temp_index].quality[type_index]
			    == OPTIC_TABLEQUAL_INITIAL)
				return true;
		}
	default:
		return false;
	}

	return false;
}

static enum optic_errorcode optic_calc_write ( uint8_t size,
					       ulong_t addr_dest,
					       ulong_t addr_src,
					       int32_t offset )
{
	uint32_t base = 0;

	if (addr_src != 0) {
		switch (size) {
		case 1:
			base = *((uint8_t*) addr_src);
			break;
		case 2:
			base = *((uint16_t*) addr_src);
			break;
		case 4:
			base = *((uint32_t*) addr_src);
			break;
		default:
			OPTIC_DEBUG_ERR("size not supported: %d", size);
			return OPTIC_STATUS_POOR;
		}
	}

	switch (size) {
	case 1:
		if (addr_src == 0)
		*((uint8_t*) addr_dest) = (uint8_t) (base + offset);
		break;
	case 2:
		*((uint16_t*) addr_dest) = (uint16_t) (base + offset);
		break;
	case 4:
		*((uint32_t*) addr_dest) = (uint32_t) (base + offset);
		break;
	default:
		OPTIC_DEBUG_ERR("size not supported: %d", size);
		return OPTIC_STATUS_POOR;
	}
	return OPTIC_STATUS_OK;
}


static enum optic_errorcode optic_calc_ipol ( uint8_t size,
					      ulong_t addr_last,
					      ulong_t addr_next,
					      uint16_t index,
					      uint16_t index_last,
					      uint16_t index_next,
					      int32_t *diff )
{
	int32_t ipol_d, ipol_r;
	uint16_t index_diff = index_next - index_last;

	if (diff == NULL)
		return OPTIC_STATUS_ERR;

	if ((addr_last == 0) || (addr_next == 0))
		return OPTIC_STATUS_ERR;

	if ((index_last >= index) || (index >= index_next)) {
		OPTIC_DEBUG_ERR("index_last=%d, index=%d, index_next=%d",
		  		index_last, index, index_next);
		return OPTIC_STATUS_POOR;
	}

	switch (size) {
	case 1:
		ipol_d = (*((uint8_t*) addr_next) -
		          *((uint8_t*) addr_last)) / (index_diff);
		ipol_r = (*((uint8_t*) addr_next) -
		          *((uint8_t*) addr_last)) % (index_diff);
		break;
	case 2:
		ipol_d = (*((uint16_t*) addr_next) -
		          *((uint16_t*) addr_last)) / (index_diff);
		ipol_r = (*((uint16_t*) addr_next) -
		          *((uint16_t*) addr_last)) % (index_diff);
		break;
	case 4:
		ipol_d = (*((uint32_t*) addr_next) -
		          *((uint32_t*) addr_last)) / (index_diff);
		ipol_r = (*((uint32_t*) addr_next) -
		          *((uint32_t*) addr_last)) % (index_diff);
		break;
	default:
		OPTIC_DEBUG_ERR("size not supported: %d", size);
		return OPTIC_STATUS_POOR;
	}

	if ((ipol_d < 0) || (ipol_r < 0)) {
		*diff = ipol_d * (index-index_last) -
			ipol_r * (index-index_last) / (index_diff);
		if (abs(ipol_r) * 2 >= (index_diff))
			(*diff) --;
	} else {
		*diff = ipol_d * (index-index_last) +
		        ipol_r * (index-index_last) / (index_diff);
		if (abs(ipol_r) * 2 >= (index_diff))
			(*diff) ++;
	}

	return OPTIC_STATUS_OK;
}


static enum optic_errorcode optic_fill_table_border (
					struct optic_control *p_ctrl,
					const enum optic_tabletype type,
					const uint16_t temp_index,
					const uint8_t size,
					ulong_t addr_dest,
					ulong_t addr_ref )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t tabledepth;
	uint8_t type_index;
	struct optic_config_range *range = &(p_ctrl->config.range);
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;

	if (addr_dest == 0)
		return OPTIC_STATUS_ERR;

	ret = optic_calc_table_get ( p_ctrl, type, &tabledepth,
					   &type_index, &table_corr,
					   &table_nom );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (temp_index >= tabledepth)
		return OPTIC_STATUS_POOR;

	switch (type) {
	case OPTIC_TABLETYPE_IBIASIMOD:
	case OPTIC_TABLETYPE_VAPD:
		ret = optic_calc_write ( size, addr_dest, addr_ref, 0 );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if (table_corr != NULL)
			table_corr[temp_index].quality[type_index] =
							OPTIC_TABLEQUAL_BORDER;
		break;
	case OPTIC_TABLETYPE_TEMPTRANS:
		ret = optic_calc_write ( size, addr_dest, 0, temp_index +
					       range->tabletemp_extnom_min );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if (table_nom != NULL)
			table_nom[temp_index].quality[type_index] =
							OPTIC_TABLEQUAL_FIXSET;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return ret;
}

/**
	Fill gaps in temperature table by interpolation and
	reusing border values.

	/param ipol_lb   lower border value: lowest defined value
	/param ipol_ub   upper border value: highest defined value

*/
enum optic_errorcode optic_fill_table_ipol ( struct optic_control *p_ctrl,
                                       	     const enum optic_tabletype type,
                                	     const uint16_t offset,
                                	     const uint8_t size,
                                	     const uint16_t ipol_lb,
                                	     const uint16_t ipol_ub )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;
	uint16_t i, tabledepth, last=0, next=0;
	ulong_t addr_lb, addr_ub, addr_last = 0, addr_next = 0, addr;
	int32_t diff;
	uint8_t type_index;

	ret = optic_calc_table_get ( p_ctrl, type, &tabledepth,
					   &type_index, &table_corr,
					   &table_nom );
	if (ret != OPTIC_STATUS_OK)
		return ret;


	if (optic_calc_interpolation_need ( p_ctrl, type, ipol_lb ) == true) {
		OPTIC_DEBUG_ERR("low-temp value not measured/*polated (%d)",
				type);
		return OPTIC_STATUS_ERR;
	}

	if (optic_calc_interpolation_need (p_ctrl, type, ipol_ub ) == true) {
		OPTIC_DEBUG_ERR("high-temp  value not measured/*polated (%d %d)",
				 type, ipol_ub);
		return OPTIC_STATUS_ERR;
	}

	/* ipol_lb / ipol_ub really defined? */
	ret = optic_calc_table_addr ( p_ctrl, type, ipol_lb, offset,
	                                    &addr_lb );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_calc_table_addr ( p_ctrl, type, ipol_ub, offset,
	                                    &addr_ub);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	for (i=0; i<tabledepth; i++) {
		ret = optic_calc_table_addr ( p_ctrl, type, i, offset,
	                                    	    &addr);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if (i < ipol_lb) {
			/* fill lower undefined band */
			ret = optic_fill_table_border ( p_ctrl, type, i,
							size, addr, addr_lb );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		} else
		if (i > ipol_ub) {
			/* fill upper undefined band */
			ret = optic_fill_table_border ( p_ctrl, type, i,
							size, addr, addr_ub );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		} else {
			/* search for gaps and interpolate lineary */
			if (optic_calc_interpolation_need ( p_ctrl, type, i )) {
				/* search for next defined value */
				next = i;
				do {
					next++;
				}
				while (optic_calc_interpolation_need ( p_ctrl,
								type, next ));

				ret = optic_calc_table_addr ( p_ctrl,
						type, next, offset, &addr_next);
				if (ret != OPTIC_STATUS_OK)
					return ret;

				/* interpolate lineary */
				ret = optic_calc_ipol ( size, addr_last,
					    addr_next, i, last, next, &diff );
				if (ret != OPTIC_STATUS_OK)
					return ret;

				/* set value */
				ret = optic_calc_write ( size, addr,
							addr_last, diff );
				if (ret != OPTIC_STATUS_OK)
					return ret;

				if (table_corr != NULL)
					table_corr[i].quality[type_index] =
							OPTIC_TABLEQUAL_INTERP;
				if (table_nom != NULL)
					table_nom[i].quality[type_index] =
							OPTIC_TABLEQUAL_INTERP;
			}
			else {
				addr_last = addr;
				last = i;
			}
		}
	}
	return ret;
}

/**
	Fill gaps in temperature table with constant values.
*/
enum optic_errorcode optic_fill_table_const ( struct optic_control *p_ctrl,
                                       	      const enum optic_tabletype type,
                                	      uint16_t offset,
                                	      uint8_t size,
                                	      int32_t val )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_table_temperature_corr *table_corr = NULL;
	struct optic_table_temperature_nom *table_nom = NULL;
	ulong_t addr;
	uint16_t i, tabledepth;
	uint8_t type_index;

	ret = optic_calc_table_get ( p_ctrl, type, &tabledepth,
					   &type_index, &table_corr,
					   &table_nom );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	for (i=0; i<tabledepth; i++) {
		ret = optic_calc_table_addr ( p_ctrl, type, i, offset,
	                                    	    &addr);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		/* search for gaps and set fix value */
		if (optic_calc_fixsetting_need ( p_ctrl, type, i )) {
			/* set value */
			ret = optic_calc_write ( size, addr, 0, val );
			if (ret != OPTIC_STATUS_OK)
				return ret;

			if (table_corr != NULL)
				table_corr[i].quality[type_index] =
							OPTIC_TABLEQUAL_FIXSET;
			if (table_nom != NULL)
				table_nom[i].quality[type_index] =
							OPTIC_TABLEQUAL_FIXSET;
		}
	}

	return ret;
}

enum optic_errorcode optic_calc_ibiasimod ( struct optic_control *p_ctrl )
{
	int32_t p0[OPTIC_POWERLEVEL_MAX], p1[OPTIC_POWERLEVEL_MAX], pth,
	         pth_ref, temp;
	uint16_t i, tabletemp_min, tabletemp_max, temp_index;
	uint8_t pl;
	uint8_t shift = OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY +
	                OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint8_t t = OPTIC_TABLETYPE_IBIASIMOD -
	            OPTIC_TABLETYPE_TEMP_CORR_MIN;
	struct optic_ibiasimod *p_ibiasimod;
	struct optic_laserref *p_laserref;
	struct optic_factor *p_factor;
	struct optic_config_range *range = &(p_ctrl->config.range);
	struct optic_table_temperature_corr *table =
						p_ctrl->table_temperature_corr;

   	tabletemp_min = range->tabletemp_extcorr_min;
    	tabletemp_max = range->tabletemp_extcorr_max;

	/**
		p0, p1: [<<0}
		pth = pth_ref * corr_factor [<<OPTIC_FLOAT2INTSHIFT_CORRFACTOR]
		SE: [<<OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY]
		ibias, imod, ith; [<<OPTIC_FLOAT2INTSHIFT_CURRENT]

		shift = OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY + OPTIC_FLOAT2INTSHIFT_CURRENT

	                      ((p0 << shift) - (pth << (shift - OPTIC_FLOAT2INTSHIFT_CORRFACTOR)))
		ibias = ith + --------------------------------------------------------------------
				                        SE

			(p1 << shift) - (p0 << shift)
		imod = -------------------------------
                                     SE
	*/

	/* pth [ << shift - OPTIC_FLOAT2INTSHIFT_CORRFACTOR] */
	pth_ref = p_ctrl->config.bosa.pth <<
		(shift - OPTIC_FLOAT2INTSHIFT_CORRFACTOR);

	for (pl=OPTIC_POWERLEVEL_0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
		/* p0, p1 [ << shift] */
		p0[pl] = (p_ctrl->config.bosa.p0[pl] << shift);
		p1[pl] = (p_ctrl->config.bosa.p1[pl] << shift);
	}

	for (i=tabletemp_min; i<=tabletemp_max; i++) {
		temp_index = i - tabletemp_min;

		p_ibiasimod = &(table[temp_index].ibiasimod);
		p_laserref = &(table[temp_index].laserref);
		p_factor = &(table[temp_index].factor[OPTIC_CFACTOR_PTH]);

		pth = pth_ref * p_factor->corr_factor;

		if (table[temp_index].quality[OPTIC_TABLETYPE_LASERREF -
	            OPTIC_TABLETYPE_TEMP_CORR_MIN] == OPTIC_TABLEQUAL_MEAS)
	            	table[temp_index].quality[t] = OPTIC_TABLEQUAL_MEAS;
		else
			table[temp_index].quality[t] = OPTIC_TABLEQUAL_CALC;

		for (pl=OPTIC_POWERLEVEL_0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
			if (p0[pl] > pth || p0[pl] < 0) {
				/* ibias = ith + (p0-pth)/SE */
				temp = p0[pl] - pth;
				temp = optic_int_div_rounded
						( temp, p_laserref->se );
				temp += p_laserref->ith;

				if (temp > range->ibias_max)
					temp = range->ibias_max;

				if(temp < 0)
					p_ibiasimod->ibias[pl] = 0;
				else
					p_ibiasimod->ibias[pl] = (uint16_t) (temp);
			} else
				table[temp_index].quality[t] =
							OPTIC_TABLEQUAL_UNKNOWN;

			if (p1[pl] > p0[pl]) {
				/* imod = (p1-p0)/SE */
				temp = p1[pl] - p0[pl];

				temp = optic_int_div_rounded
						( temp, p_laserref->se );

				if (temp > range->imod_max)
					temp = range->imod_max;

				if(temp < 0)
					p_ibiasimod->imod[pl] = 0;
				else
					p_ibiasimod->imod[pl] = (uint16_t) (temp);

			} else
				table[temp_index].quality[t] =
							OPTIC_TABLEQUAL_UNKNOWN;

			if ((p_ibiasimod->ibias[pl] + p_ibiasimod->imod[pl]) >
			     range->ibiasimod_max) {
				p_ibiasimod->imod[pl] = range->ibiasimod_max -
							p_ibiasimod->ibias[pl];
			}
		}
	}

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_calc_ith_se ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t temp_index, ibias, imod;
	uint32_t p0, p1, pth, temp;
	uint8_t shift = OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY +
	                OPTIC_FLOAT2INTSHIFT_CURRENT;
	uint8_t t = OPTIC_TABLETYPE_LASERREF -
	            OPTIC_TABLETYPE_TEMP_CORR_MIN;
	enum optic_powerlevel pl = p_ctrl->calibrate.powerlevel;
	struct optic_laserref *p_laserref;
	struct optic_factor *p_factor;
	struct optic_table_temperature_corr *table =
						p_ctrl->table_temperature_corr;

	ibias = p_ctrl->calibrate.abias_average;
	imod = p_ctrl->calibrate.amod_average;

	if ((ibias == 0) || (imod == 0)) {
		OPTIC_DEBUG_WRN("optic_calc_ith_se: rangecheck "
				"(abias=%d, amod=%d)", ibias, imod);
            	return OPTIC_STATUS_POOR;
	}

	ret = optic_rangecheck_etemp_corr ( &(p_ctrl->config.range),
					    p_ctrl->calibrate.temperature_ext,
					    &temp_index );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	p_laserref = &(table[temp_index].laserref);
	p_factor = &(table[temp_index].factor[OPTIC_CFACTOR_PTH]);

	/**
		p0, p1: [<<0}
		pth = pth_ref * corr_factor [<<OPTIC_FLOAT2INTSHIFT_CORRFACTOR]
		SE: [<<OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY]
		ibias, imod, ith; [<<OPTIC_FLOAT2INTSHIFT_CURRENT]

		shift = OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY + OPTIC_FLOAT2INTSHIFT_CURRENT

	                      ((p0 << shift) - (pth << (shift - OPTIC_FLOAT2INTSHIFT_CORRFACTOR)))
		ibias = ith + --------------------------------------------------------------------
				                        SE

			(p1 << shift) - (p0 << shift)
		imod = -------------------------------
                                     SE


			(p1 << shift) - (p0 << shift)
		SE = -------------------------------
				imod

				((p0 << shift) - (pth << (shift - OPTIC_FLOAT2INTSHIFT_CORRFACTOR)))
		ith = ibias - --------------------------------------------------------------------
				                        SE


	*/

	/* pth [ << shift - OPTIC_FLOAT2INTSHIFT_CORRFACTOR] */
	pth = p_ctrl->config.bosa.pth <<
		(shift - OPTIC_FLOAT2INTSHIFT_CORRFACTOR);
	pth = pth * p_factor->corr_factor;

	/* p0, p1 [ << shift] */
	p0 = (p_ctrl->config.bosa.p0[pl] << shift);
	p1 = (p_ctrl->config.bosa.p1[pl] << shift);

	if (p1 > p0) {
		/* SE = (p1-p0)/imod */

		temp = p1 - p0;
		p_laserref->se = (uint16_t) optic_uint_div_rounded
								( temp, imod );

	} else {
		OPTIC_DEBUG_WRN("optic_calc_ith_se: p1 > p0 rangecheck");
		return OPTIC_STATUS_POOR;
	}

	if (p0 > pth) {
		/* ith = ibias - (p0-pth)/se */
		temp = p0 - pth;
		temp = optic_uint_div_rounded ( temp, p_laserref->se );

		if (ibias < temp)
			return OPTIC_STATUS_POOR;

		p_laserref->ith = (uint16_t) (ibias - temp);

	} else {
		OPTIC_DEBUG_WRN("optic_calc_ith_se: p0 > pth rangecheck");
		return OPTIC_STATUS_POOR;
	}

	p_laserref->age = p_ctrl->calibrate.timestamp;
	table[temp_index].quality[t] = OPTIC_TABLEQUAL_MEAS;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_temperature_nom2corr ( const struct
						  optic_config_range *range,
						  const struct
						  optic_table_temperature_nom
						  *table_temperature_nom,
						  const uint16_t temp_nom,
					          uint16_t *temp_corr )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t temp_index;

	if ((range == NULL) || (table_temperature_nom == NULL) ||
	    (temp_corr == NULL))
		return OPTIC_STATUS_ERR;

	ret = optic_rangecheck_etemp_nom ( range, temp_nom, &temp_index );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	*temp_corr = table_temperature_nom[temp_index].temptrans.temp_corr
	             << OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

      	return ret;
}

enum optic_errorcode optic_fusecorrect_temp ( struct optic_fuses *fuses,
					      uint16_t temp_nom,
					      uint16_t *temp_corr )
{
	if (temp_corr == NULL)
		return OPTIC_STATUS_ERR;

	*temp_corr = temp_nom + (fuses->temp_mm <<
				 OPTIC_FLOAT2INTSHIFT_TEMPERATURE);
	if (fuses->temp_mm & 0x20)
		*temp_corr -= (64 << OPTIC_FLOAT2INTSHIFT_TEMPERATURE);

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_check_age ( struct optic_control *p_ctrl )
{
	uint16_t temp, temp_index, tabletemp_min, tabletemp_max;
	struct optic_laserref *p_lr;

	if (p_ctrl == NULL)
		return OPTIC_STATUS_ERR;

	tabletemp_min = p_ctrl->config.range.tabletemp_extcorr_min;
	tabletemp_max = p_ctrl->config.range.tabletemp_extcorr_max;

	for (temp=tabletemp_min; temp<=tabletemp_max; temp++) {
		temp_index = temp - tabletemp_min;
		p_lr = &(p_ctrl->table_temperature_corr[temp_index].laserref);

		if (p_lr->age > p_ctrl->calibrate.timestamp) {
		    	p_ctrl->calibrate.timestamp = p_lr->age;
		}
	}

	return OPTIC_STATUS_OK;
}
#if (OPTIC_FCSI_PREDRIVER_RANGECHECK == ACTIVE)
enum optic_errorcode optic_check_predriver ( uint8_t dd_loadn,
					     uint8_t dd_bias_en,
					     uint8_t dd_loadp,
					     uint8_t dd_cm_load,
					     uint8_t bd_loadn,
					     uint8_t bd_bias_en,
					     uint8_t bd_loadp,
					     uint8_t bd_cm_load )
{
	uint8_t i = 0;
	uint16_t loadn[2];
	uint16_t bias_en[2];
	uint16_t loadp[2];
	uint16_t cm_load[2];
	uint32_t temp;

	uint8_t *p_dd_load[2] = { &dd_loadn, &dd_loadp };
	uint8_t *p_bd_load[2] = { &bd_loadn, &bd_loadp };
	uint16_t *p_loadx_0[2] = { &(loadn[0]), &(loadp[0]) };
	uint16_t *p_loadx_1[2] = { &(loadn[1]), &(loadp[1]) };

	/* interpret dd loadn/loadp [Ohm*10] */
	for (i=0; i<2; i++) {
		switch (*p_dd_load[i]) {
			case 0x00: *(p_loadx_0[i]) = 4000; break;
			case 0x01: *(p_loadx_0[i]) = 3000; break;
			case 0x02: *(p_loadx_0[i]) = 2400; break;
			case 0x03: *(p_loadx_0[i]) = 2000; break;
			case 0x04: *(p_loadx_0[i]) = 1714; break;
			case 0x05: *(p_loadx_0[i]) = 1500; break;
			case 0x06: *(p_loadx_0[i]) = 1333; break;
			case 0x07: *(p_loadx_0[i]) = 1200; break;
			case 0x08: *(p_loadx_0[i]) = 1091; break;
			case 0x09: *(p_loadx_0[i]) = 1000; break;
			case 0x0A: *(p_loadx_0[i]) =  923; break;
			case 0x0B: *(p_loadx_0[i]) =  857; break;
			case 0x0C: *(p_loadx_0[i]) =  800; break;
			case 0x0D: *(p_loadx_0[i]) =  750; break;
			case 0x0E: *(p_loadx_0[i]) =  706; break;
			case 0x0F: *(p_loadx_0[i]) =  667; break;
			case 0x10: *(p_loadx_0[i]) =  632; break;
			case 0x11: *(p_loadx_0[i]) =  600; break;
			case 0x12: *(p_loadx_0[i]) =  571; break;
			case 0x13: *(p_loadx_0[i]) =  545; break;
			case 0x14: *(p_loadx_0[i]) =  525; break;
			case 0x15: *(p_loadx_0[i]) =  500; break;
			case 0x16: *(p_loadx_0[i]) =  480; break;
			case 0x17: *(p_loadx_0[i]) =  462; break;
			case 0x18: *(p_loadx_0[i]) =  444; break;
			case 0x19: *(p_loadx_0[i]) =  429; break;
			case 0x1A: *(p_loadx_0[i]) =  414; break;
			case 0x1B: *(p_loadx_0[i]) =  400; break;
			case 0x1C: *(p_loadx_0[i]) =  387; break;
			case 0x1D: *(p_loadx_0[i]) =  375; break;
			case 0x1E: *(p_loadx_0[i]) =  364; break;
			case 0x1F: *(p_loadx_0[i]) =  353; break;
			default: return OPTIC_STATUS_POOR;
		}
	}

	/* interpret dd bias_en [mA*10] */
	if (dd_bias_en > 0x0F)
		return OPTIC_STATUS_POOR;
	bias_en[0] = 32 * dd_bias_en;

	/* interpret dd cm_load [Ohm*10] */
	switch (dd_cm_load) {
		case 0x00: cm_load[0] = 2000; break;
		case 0x01: cm_load[0] = 1500; break;
		case 0x02: cm_load[0] = 1200; break;
		case 0x03: cm_load[0] = 1000; break;
		case 0x04: cm_load[0] =  857; break;
		case 0x05: cm_load[0] =  750; break;
		case 0x06: cm_load[0] =  667; break;
		case 0x07: cm_load[0] =  600; break;
		case 0x08: cm_load[0] =  546; break;
		case 0x09: cm_load[0] =  500; break;
		case 0x0A: cm_load[0] =  462; break;
		case 0x0B: cm_load[0] =  429; break;
		case 0x0C: cm_load[0] =  400; break;
		case 0x0D: cm_load[0] =  375; break;
		case 0x0E: cm_load[0] =  353; break;
		case 0x0F: cm_load[0] =  333; break;
		case 0x10: cm_load[0] =  316; break;
		case 0x11: cm_load[0] =  300; break;
		case 0x12: cm_load[0] =  286; break;
		case 0x13: cm_load[0] =  273; break;
		case 0x14: cm_load[0] =  261; break;
		case 0x15: cm_load[0] =  250; break;
		case 0x16: cm_load[0] =  240; break;
		case 0x17: cm_load[0] =  231; break;
		case 0x18: cm_load[0] =  222; break;
		case 0x19: cm_load[0] =  214; break;
		case 0x1A: cm_load[0] =  207; break;
		case 0x1B: cm_load[0] =  200; break;
		case 0x1C: cm_load[0] =  194; break;
		case 0x1D: cm_load[0] =  188; break;
		case 0x1E: cm_load[0] =  181; break;
		case 0x1F: cm_load[0] =  177; break;
		default: return OPTIC_STATUS_POOR;
	}

	/* interpret bd loadn/loadp [Ohm*10] */
	for (i=0; i<2; i++) {
		switch (*p_bd_load[i]) {
			case 0x00: *(p_loadx_1[i]) = 8000; break;
			case 0x01: *(p_loadx_1[i]) = 6857; break;
			case 0x02: *(p_loadx_1[i]) = 6000; break;
			case 0x03: *(p_loadx_1[i]) = 5333; break;
			case 0x04: *(p_loadx_1[i]) = 4800; break;
			case 0x05: *(p_loadx_1[i]) = 4364; break;
			case 0x06: *(p_loadx_1[i]) = 4000; break;
			case 0x07: *(p_loadx_1[i]) = 3692; break;
			case 0x08: *(p_loadx_1[i]) = 3429; break;
			case 0x09: *(p_loadx_1[i]) = 3200; break;
			case 0x0A: *(p_loadx_1[i]) = 3000; break;
			case 0x0B: *(p_loadx_1[i]) = 2824; break;
			case 0x0C: *(p_loadx_1[i]) = 2667; break;
			case 0x0D: *(p_loadx_1[i]) = 2526; break;
			case 0x0E: *(p_loadx_1[i]) = 2400; break;
			case 0x0F: *(p_loadx_1[i]) = 2286; break;
			case 0x10: *(p_loadx_1[i]) = 2182; break;
			case 0x11: *(p_loadx_1[i]) = 2087; break;
			case 0x12: *(p_loadx_1[i]) = 2000; break;
			case 0x13: *(p_loadx_1[i]) = 1920; break;
			case 0x14: *(p_loadx_1[i]) = 1846; break;
			case 0x15: *(p_loadx_1[i]) = 1778; break;
			case 0x16: *(p_loadx_1[i]) = 1714; break;
			case 0x17: *(p_loadx_1[i]) = 1655; break;
			case 0x18: *(p_loadx_1[i]) = 1600; break;
			case 0x19: *(p_loadx_1[i]) = 1548; break;
			case 0x1A: *(p_loadx_1[i]) = 1500; break;
			case 0x1B: *(p_loadx_1[i]) = 1455; break;
			case 0x1C: *(p_loadx_1[i]) = 1412; break;
			case 0x1D: *(p_loadx_1[i]) = 1371; break;
			case 0x1E: *(p_loadx_1[i]) = 1333; break;
			case 0x1F: *(p_loadx_1[i]) = 1297; break;
			default: return OPTIC_STATUS_POOR;
		}
	}

	/* interpret bd bias_en [mA*10] */
	if (bd_bias_en > 0x0F)
		return OPTIC_STATUS_POOR;
	bias_en[1] = 4 * bd_bias_en;

	/* interpret bd cm_load [Ohm*10] */
	switch (bd_cm_load) {
		case 0x00: cm_load[1] = 4000; break;
		case 0x01: cm_load[1] = 3429; break;
		case 0x02: cm_load[1] = 3000; break;
		case 0x03: cm_load[1] = 2667; break;
		case 0x04: cm_load[1] = 2400; break;
		case 0x05: cm_load[1] = 2182; break;
		case 0x06: cm_load[1] = 2000; break;
		case 0x07: cm_load[1] = 1846; break;
		case 0x08: cm_load[1] = 1714; break;
		case 0x09: cm_load[1] = 1600; break;
		case 0x0A: cm_load[1] = 1500; break;
		case 0x0B: cm_load[1] = 1412; break;
		case 0x0C: cm_load[1] = 1333; break;
		case 0x0D: cm_load[1] = 1263; break;
		case 0x0E: cm_load[1] = 1200; break;
		case 0x0F: cm_load[1] = 1143; break;
		case 0x10: cm_load[1] = 1091; break;
		case 0x11: cm_load[1] = 1043; break;
		case 0x12: cm_load[1] = 1000; break;
		case 0x13: cm_load[1] =  960; break;
		case 0x14: cm_load[1] =  923; break;
		case 0x15: cm_load[1] =  889; break;
		case 0x16: cm_load[1] =  857; break;
		case 0x17: cm_load[1] =  828; break;
		case 0x18: cm_load[1] =  800; break;
		case 0x19: cm_load[1] =  774; break;
		case 0x1A: cm_load[1] =  750; break;
		case 0x1B: cm_load[1] =  727; break;
		case 0x1C: cm_load[1] =  706; break;
		case 0x1D: cm_load[1] =  686; break;
		case 0x1E: cm_load[1] =  667; break;
		case 0x1F: cm_load[1] =  649; break;
		default: return OPTIC_STATUS_POOR;
	}

	/**
	Vgate = 3.3V ??? I(bias_en) * R(cm_load); must be equal or less than 2.0V
	Error:  200000 [mV *100] < 330000 [mV *100] - bias_en [mA * 10] * cm_load [Ohm *10]
		bias_en [mA * 100] * cm_load [Ohm *10] < 130000 [mV *100]


	Vgate = 3.3V ??? I(bias_en) * [R(cm_load) + R(loadn/p)]; must be equal or greater than 0.3V
	Error:  30000 [mV *100] > 330000 [mV *100] - bias_en [mA * 10] * (cm_load [Ohm *10] + loadx [Ohm *10])
		bias_en [mA * 100] * (cm_load [Ohm *10] + loadx [Ohm *10]) > 300000 [mV *100]

	*/

	for (i=0; i<2; i++) {
		temp = bias_en[i] * cm_load[i];
		if (temp < 130000) {
			OPTIC_DEBUG_WRN("bias_en(%d) * cm_load(%d) < 130.000",
					bias_en[i], cm_load[i]);
			return OPTIC_STATUS_POOR;
		}

		temp = cm_load[i] + loadn[i];
		temp = bias_en[i] * temp;
		if (temp > 300000) {
			OPTIC_DEBUG_WRN("bias_en(%d) * (cm_load(%d)+loadn(%d)) > 300.000",
					bias_en[i], cm_load[i], loadn[i]);
			return OPTIC_STATUS_POOR;
		}

		temp = cm_load[i] + loadp[i];
		temp = bias_en[i] * temp;
		if (temp > 300000) {
			OPTIC_DEBUG_WRN("bias_en(%d) * (cm_load(%d)+loadp(%d)) > 300.000",
					bias_en[i], cm_load[i], loadp[i]);
			return OPTIC_STATUS_POOR;
		}
	}

	return OPTIC_STATUS_OK;
}
#endif

enum optic_errorcode optic_check_temperature_alarm ( struct optic_control
						     *p_ctrl )
{
	struct optic_interrupts *irq = &(p_ctrl->state.interrupts);
	uint16_t temp_int = optic_shift_temp_back (p_ctrl->calibrate.
					           temperature_int);
	enum optic_irq alarm = OPTIC_IRQ_NONE;


	if ((irq->temp_alarm_yellow == false) &&
	    (temp_int >= p_ctrl->config.temp_alarm_yellow_set)) {
	    	irq->temp_alarm_yellow = true;

		alarm = OPTIC_IRQ_TEMPALARM_YELLOW_SET;
	}
	if ((irq->temp_alarm_yellow == true) &&
	    (temp_int <= p_ctrl->config.temp_alarm_yellow_clear)) {
	    	irq->temp_alarm_yellow = false;

		alarm = OPTIC_IRQ_TEMPALARM_YELLOW_CLEAR;
	}

	if ((irq->temp_alarm_red == false) &&
	    (temp_int >= p_ctrl->config.temp_alarm_red_set)) {
	    	irq->temp_alarm_red = true;

		alarm = OPTIC_IRQ_TEMPALARM_RED_SET;
	}

	if ((irq->temp_alarm_red == true) &&
	    (temp_int <= p_ctrl->config.temp_alarm_red_clear)) {
	    	irq->temp_alarm_red = false;

		alarm = OPTIC_IRQ_TEMPALARM_RED_CLEAR;
	}

	if (alarm != OPTIC_IRQ_NONE) {
		if (p_ctrl->config.callback_isr != NULL) {
			p_ctrl->config.callback_isr ( alarm );
		} else {
#ifndef OPTIC_LIBRARY
			optic_fifo_write ( &(p_ctrl->event_worker),
					   &(p_ctrl->fifo_worker),
					   OPTIC_FIFO_ALARM, (void*) &alarm,
			  		   sizeof(enum optic_irq));
#endif
			OPTIC_DEBUG_MSG("signal: temperature alarm %d",
					alarm);
		}
	}

	return OPTIC_STATUS_OK;
}

/**
	calculates gain correction.
*/
enum optic_errorcode optic_calc_gain_correct ( struct optic_control *p_ctrl,
					       const bool p0,
					       const int16_t dac_coarse,
					       const int16_t dac_fine,
					       uint16_t *gain_correct )

{
	int32_t temp;
	int32_t dcal_ref;
	int16_t shift = OPTIC_FLOAT2INTSHIFT_CORRFACTOR -
		        OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO;
	enum optic_powerlevel pl = p_ctrl->calibrate.powerlevel;

	if (gain_correct == NULL)
		return OPTIC_STATUS_ERR;

	if (p0 == true)
		temp = p_ctrl->calibrate.ratio_p0 * ( 1 << shift);
	else
		temp = p_ctrl->calibrate.ratio_p1 * ( 1 << shift);

	if (p_ctrl->config.debug_mode == true) {
		if (p0 == true)
			dcal_ref = p_ctrl->config.debug.dcal_ref_p0;
		else
			dcal_ref = p_ctrl->config.debug.dcal_ref_p1;
	} else {
		if (p0 == true)
			dcal_ref = p_ctrl->config.monitor.dcal_ref_p0[pl];
		else
			dcal_ref = p_ctrl->config.monitor.dcal_ref_p1[pl];
	}

	/**
			coarse * ratio + fine
	gain_correct = -----------------------
		    	      Dcalref

	coarse * ratio + fine => 14 bit , + OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO = 25
	ratio: << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO
	Dcalref: << OPTIC_FLOAT2INTSHIFT_DREF
	gain_correct: << OPTIC_FLOAT2INTSHIFT_CORRFACTOR

			coarse * ratio >> OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO + fine
	gain_correct = -------------------------------------------------------------- << OPTIC_FLOAT2INTSHIFT_CORRFACTOR
		    	      Dcalref >> OPTIC_FLOAT2INTSHIFT_DREF

	shift = OPTIC_FLOAT2INTSHIFT_CORRFACTOR - OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO;

			coarse * (ratio << shift) + (fine << OPTIC_FLOAT2INTSHIFT_CORRFACTOR)
	gain_correct = --------------------------------------------------------------------------
		    	      Dcalref >> OPTIC_FLOAT2INTSHIFT_DREF

			(coarse * (ratio << shift) + (fine << OPTIC_FLOAT2INTSHIFT_CORRFACTOR)) << OPTIC_FLOAT2INTSHIFT_DREF
	gain_correct = -----------------------------------------------------------------------------------------------------
		    	      		Dcalref
	*/


	temp = (abs(dac_coarse) * temp) +
		(abs(dac_fine) * (1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR));

	temp *= (1 << OPTIC_FLOAT2INTSHIFT_DREF);

	*gain_correct = (uint16_t) optic_int_div_rounded ( temp, dcal_ref );

	return OPTIC_STATUS_OK;
}

/**
	calculates gain correction.
*/
enum optic_errorcode optic_calc_codeword ( struct optic_control *p_ctrl,
					   const bool p0,
					   const uint16_t temp_ext_corr,
					   const int16_t gain_correct,
				           int32_t *codeword )
{
	uint32_t temp;
	int32_t dref;
	struct optic_table_temperature_corr *table_corr;
	uint16_t temp_index = temp_ext_corr -
			      p_ctrl->config.range.tabletemp_extcorr_min;
	int16_t shift = OPTIC_FLOAT2INTSHIFT_CORRFACTOR +
		        OPTIC_FLOAT2INTSHIFT_CORRFACTOR -
		        OPTIC_FLOAT2INTSHIFT_MPDRESPCORRGAINCORR;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;

	if (codeword == NULL)
		return OPTIC_STATUS_ERR;

	if (p_ctrl->config.debug_mode == true) {
		if (p0 == true)
			dref = p_ctrl->config.debug.dref_p0;
		else
			dref = p_ctrl->config.debug.dref_p1;
	} else {
		if (p0 == true)
			dref = p_ctrl->config.monitor.dref_p0[powerlevel];
		else
			dref = p_ctrl->config.monitor.dref_p1[powerlevel];
	}

	/**

	D = MPD_resp_corr[Tbosa] * gain_correct * Dref
	       temp = MPD_resp_corr[Tbosa] * gain_correct
	MPD_resp_corr: << OPTIC_FLOAT2INTSHIFT_CORRFACTOR
	gain_correct: << OPTIC_FLOAT2INTSHIFT_CORRFACTOR
	Dref: << OPTIC_FLOAT2INTSHIFT_DREF:    4 + 14
	Dref: OPTIC_USEDBITS_DREF (18)
	temp: 6 + 8 = 14	+ Dref: 4 + 14 		= 32

	1) temp = (MPD_resp_corr[Tbosa] * gain_correct) >> (OPTIC_FLOAT2INTSHIFT_CORRFACTOR + OPTIC_FLOAT2INTSHIFT_CORRFACTOR)
	   temp [<<OPTIC_FLOAT2INTSHIFT_MPDRESPCORRGAINCORR]

	   shift = OPTIC_FLOAT2INTSHIFT_CORRFACTOR + OPTIC_FLOAT2INTSHIFT_CORRFACTOR - OPTIC_FLOAT2INTSHIFT_MPDRESPCORRGAINCORR
	   temp = (MPD_resp_corr[Tbosa] * gain_correct) >> shift

	2) D = temp * Dref
	   temp: << OPTIC_FLOAT2INTSHIFT_MPDRESPCORRGAINCORR
	   Dref: << OPTIC_FLOAT2INTSHIFT_DREF
	   D: << OPTIC_FLOAT2INTSHIFT_DREF

	   D = (temp * Dref) >> OPTIC_FLOAT2INTSHIFT_MPDRESPCORRGAINCORR

	*/

	table_corr = &(p_ctrl->table_temperature_corr[temp_index]);
	temp = (table_corr->factor[OPTIC_CFACTOR_MPDRESP].corr_factor *
	        gain_correct);

	temp = optic_uint_div_rounded ( temp, 1 << shift );

	*codeword = optic_int_div_rounded ( temp * dref,
				1 << OPTIC_FLOAT2INTSHIFT_MPDRESPCORRGAINCORR );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_bias2reg ( const uint8_t gain_dac_bias,
					   const uint8_t bias_max,
                       const uint16_t ibias,
					   uint16_t *dbias )
{
	uint32_t ibias_int;
	uint32_t ibias_without_offset = ibias;
	uint8_t shift = 11-OPTIC_FLOAT2INTSHIFT_CURRENT;

	if (dbias == NULL)
		return OPTIC_STATUS_ERR;

	/**

	GPONSW-802: consider offset for A21 and A22:
	===========================================================

    First of all, the biasing offset of 2.8mA (mod) or 2.5mA (bias) has to be subtracted.
    The remaining value has to be corrected and written in the register

	ibias = (ibias - offset)	//used in formula below

	ibias_int is the digital value of the current
	The fuses correspond to a deviation that has to be compensated.
	For example, if the fuses is 23d=-8.8%, we have to generate a correction factor of 1.088

		            gainbiasdac                             gainbiasdac + 64
	ibias_int = ( ----------- * 0,4 + 0,8 ) * ibias  = ( ----------------- ) * ibias
	                  32                                       80

	dbias     ibias_int >> OPTIC_FLOAT2INTSHIFT_CURRENT
	------   = -------------------------------------
	1 << 11            DEFAULT_A12_BIASMAX

	dbias = (ibias_int << (11-OPTIC_FLOAT2INTSHIFT_CURRENT)) / DEFAULT_A12_BIASMAX


	*/

	if(is_falcon_chip_a2x()) {
		if (ibias >= LD_BIAS_DAC_OFFSET)
			ibias_without_offset = ibias - LD_BIAS_DAC_OFFSET;
		else /* we can not produce currents below bias offset value */
			ibias_without_offset = 0;

		ibias_int = optic_uint_div_rounded (
				(gain_dac_bias + 64) * ibias_without_offset, 80);
	}
	else { /* A12 calculates with 4 bit only */
		ibias_int = optic_uint_div_rounded (
				(gain_dac_bias + 152) * ibias, 160 );
	}

	if (bias_max == 0)
		return OPTIC_STATUS_ERR;

	*dbias = (uint16_t) optic_uint_div_rounded ( ibias_int << shift,
						     bias_max );

	/* !! never set 0 into register, this is a meta value, set by hardware
	      after DAC update !! */
	if (*dbias == 0)
		*dbias = 1;
	if (*dbias > 0x7FF)
		*dbias = 0x7FF;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_reg2bias ( const uint8_t gain_dac_bias,
					   const uint8_t bias_max,
                       const uint16_t dbias,
					   uint16_t *bias )
{
	uint32_t bias_int;
	uint8_t shift = 11-OPTIC_FLOAT2INTSHIFT_CURRENT;

	if (bias == NULL)
		return OPTIC_STATUS_ERR;

	/**

	dbias       bias_c >> OPTIC_FLOAT2INTSHIFT_CURRENT
	------   = -------------------------------------
	1 << 11               DEFAULT_A12_BIASMAX

	bias_int = (dbias * DEFAULT_A12_BIASMAX) >> (11-OPTIC_FLOAT2INTSHIFT_CURRENT)

	           gainbiasdac                            gainbiasdac + 64
	bias_int = ( ----------- * 0,4 + 0,8 ) * bias  = ( ----------------- ) * bias
	               32                                       80

	bias = (bias_c * 80) / (gainbiasdac + 64)

	GPONSW-802: consider offset for A21:
	===========================================================
	bias = bias + offset 	//used in above formula

	*/

	bias_int = optic_uint_div_rounded ( dbias * bias_max, 1 << shift );

	if(is_falcon_chip_a2x()) {
		*bias = (uint16_t) optic_uint_div_rounded ( bias_int * 80,
				gain_dac_bias + 64 );

		*bias += LD_BIAS_DAC_OFFSET;
	}
	else { /* A12 calculates with 4 bit only */
		*bias = (uint16_t) optic_uint_div_rounded ( bias_int * 160,
			    gain_dac_bias + 152 );
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_mod2reg ( const uint8_t gain_dac_drive,
					  const uint16_t scalefactor_mod,
					  const uint8_t mod_max,
                      const uint16_t imod,
					  uint16_t *dmod )
{
	uint32_t imod_int;
	uint32_t imod_without_offset = imod;
	uint8_t shift = OPTIC_FLOAT2INTSHIFT_CORRFACTOR +
	                OPTIC_FLOAT2INTSHIFT_CURRENT - 11;

	if (dmod == NULL)
		return OPTIC_STATUS_ERR;

	/**
	            gaindrivedac                            gaindrivedac + 64
	imod_int = ( ------------- * 0,4 + 0,8 ) * imod  = ( ------------------ ) * imod
	                  32                                       80

	dmod        imod_int >> OPTIC_FLOAT2INTSHIFT_CURRENT
	------   = -------------------------------------     * scalefactor_mod[pl] >> OPTIC_FLOAT2INTSHIFT_CORRFACTOR
	1 << 11               DEFAULT_A12_MODMAX

	dmod = imod_int * scalefactor_mod[pl] / (DEFAULT_A12_MODMAX << (OPTIC_FLOAT2INTSHIFT_CORRFACTOR + OPTIC_FLOAT2INTSHIFT_CURRENT -11))

	GPONSW-777: A21 scaling adaptation:
	===========================================================
	scaling adaptation is done inherently with new max value !!!

	GPONSW-802: consider offset for A21:
	===========================================================
	imod = imod - offset	//used in above formula

	*/

	if(is_falcon_chip_a2x()) {
		if (imod >= LD_MOD_DAC_OFFSET)
			imod_without_offset = imod - LD_MOD_DAC_OFFSET;
		else
			imod_without_offset = 0;

		imod_int = optic_uint_div_rounded (
				(gain_dac_drive + 64) * imod_without_offset, 80 );
	}
	else {
		imod_int = optic_uint_div_rounded ( 
			(gain_dac_drive + 152) * imod, 160 );
	}


	if (mod_max == 0)
		return OPTIC_STATUS_ERR;

	*dmod = (uint16_t) optic_uint_div_rounded ( imod_int * scalefactor_mod,
						    mod_max << shift );

	/* !! never set 0 into register, this is a meta value, set by hardware
	      after DAC update !! */
	if (*dmod == 0)
		*dmod = 1;
	if (*dmod > 0x7FF)
		*dmod = 0x7FF;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_reg2mod ( const uint8_t gain_dac_drive,
					  const uint16_t scalefactor_mod,
					  const uint8_t mod_max,
                      const uint16_t dmod,
					  uint16_t *mod )
{
	uint32_t temp, mod_int;
	uint8_t shift = OPTIC_FLOAT2INTSHIFT_CORRFACTOR +
	                OPTIC_FLOAT2INTSHIFT_CURRENT - 11;

	if (mod == NULL)
		return OPTIC_STATUS_ERR;

	/**

	dmod        mod_int >> OPTIC_FLOAT2INTSHIFT_CURRENT
	------   = -----------------------------------  * scalefactor_mod[pl] >> OPTIC_FLOAT2INTSHIFT_CORRFACTOR
	1 << 11             DEFAULT_A12_MODMAX

		(dmod * DEFAULT_A12_MODMAX) << (OPTIC_FLOAT2INTSHIFT_CORRFACTOR + OPTIC_FLOAT2INTSHIFT_CURRENT -11)
	mod_int = ------------------------------------------------------------------------------------
				scalefactor_mod[pl]

		  	  gaindrivedac                           gaindrivedac + 64
	mod_c = ( ------------ * 0,4 + 0,8 ) * mod  = ( ------------------ ) * mod
	               32                                       80

	mod = (mod_c * 80) / (gaindrivedac + 64)

	GPONSW-777: A21 scaling adaptation:
	========================================================
	scaling adaptation is done inherently with new max value !!!

	GPONSW-802: consider offset for A21:
	===========================================================
	mod = mode + offset	//in above formula

	*/

	temp = (dmod * mod_max) << shift;

 	if (scalefactor_mod == 0)
		return OPTIC_STATUS_ERR;

 	mod_int = optic_uint_div_rounded ( temp, scalefactor_mod );

	if(is_falcon_chip_a2x()) {
		*mod = (uint16_t) optic_uint_div_rounded ( mod_int * 80,
				gain_dac_drive + 64 );
	
		*mod += LD_MOD_DAC_OFFSET;
	}
	else {
		*mod = (uint16_t) optic_uint_div_rounded ( mod_int * 160,
				gain_dac_drive + 152 );
	}

	return OPTIC_STATUS_OK;
}

/**
	/note: OPTIC_STATUS_GAIN_SELECTOR_UPDATED ->
		+ measure->measure_index[type] = 0; / ocal->measure_index = 0;
		+ optic_mm_prepare ( p_ctrl, type );
*/
enum optic_errorcode optic_calc_voltage ( const enum optic_measure_type type,
					  const enum optic_vref vref,
					  const struct optic_table_mm_gain
					  *gain,
					  const int16_t reg_value,
					  uint8_t *gain_selector,
					  uint16_t *voltage )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint32_t factor;
	int32_t temp;
	uint8_t shift;

	if ((gain_selector == NULL) || (voltage == NULL))
		return OPTIC_STATUS_ERR;

	*voltage = 0;

	/* automatic gain correction */
	switch (type) {
	case OPTIC_MEASURE_POWER_RSSI_1490:
	case OPTIC_MEASURE_POWER_RF_1550:
	case OPTIC_MEASURE_POWER_RSSI_1550:
		/** automatic gain correction */
		if ((abs(reg_value) > ((4<<15)/5)) &&  (*gain_selector > 0)) {
			*gain_selector -= 1;
		} else
		if ((abs(reg_value) < ((1<<15)/5)) && (*gain_selector < 5)) {
			*gain_selector += 1;
		} else
			break;

		return OPTIC_STATUS_GAIN_SELECTOR_UPDATED;
	default:
		break;
	}

	/**
	     (read_data - offset[]) * gain_correction[]
	U = --------------------------------------------  + Vref
			2^16 * gain_factor[]

	we use scaled values (integer):
	Vref * 2 = 1, 2, 3
	gain_factor = < <<2 >      1..64    gain_factor[2] = 4
	gain_correction =  < <<OPTIC_FLOAT2INTSHIFT_CORRFACTOR > ...
				~1*2^OPTIC_FLOAT2INTSHIFT_CORRFACTOR

	     (read_data - offset[]) * gain_correction[]
	U = --------------------------------------------  + Vref
			2^16 * gain_factor[]


	  (read_data - offset[]) * gain_correction[] >> OPTIC_FLOAT2INTSHIFT_CORRFACTOR
	= ------------------------------------------------------------------------------  + Vref >> 1
				2^16 * gain_factor[] >> 2

	save voltages with << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE
	shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE - OPTIC_FLOAT2INTSHIFT_CORRFACTOR    .. 3

	     (read_data - offset[]) * gain_correction[]
	U = ------------------------------------------- + Vref << (OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE-1)
			gain_factor[] << (14-shift)


	      (read_data - offset[2]) * gain_correction[2]
	VDD = -------------------------------------------- + Vref << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE
			gain_factor[2] << (13 - shift)

		     (read_data - offset[2]) * gain_correction[2]
	VBE1, VBE2 = -------------------------------------------- + Vref << (OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE-1)
				gain_factor[2] << (14 - shift )


	          (read_data - offset[]) * gain_correction[]
	U_corr = -------------------------------------------- + Vref << (OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE-1)
			gain_factor[] << (14 - shift)

	*/
	/*if(type == OPTIC_MEASURE_VOLTAGE_PN)
		OPTIC_DEBUG_ERR("avg: %d, off: %d, corr: %d, factor: %d",
				reg_value,
				gain->offset,
				gain->correction,
				gain->factor);
	*/
	temp = (reg_value - gain->offset) * gain->correction;
	if (type == OPTIC_MEASURE_VDD_HALF) {
		shift = 13 + OPTIC_FLOAT2INTSHIFT_CORRFACTOR -
			OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE;
	} else {
		shift = 14 + OPTIC_FLOAT2INTSHIFT_CORRFACTOR -
			OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE;
	}

	factor = gain->factor << shift;
	temp = optic_int_div_rounded ( temp, (uint32_t) factor );

	if (type == OPTIC_MEASURE_VDD_HALF) {
		temp += (vref << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE);
	}
	else {
		if (vref > OPTIC_VREF_0MV)
			temp += (vref <<
				(OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE - 1));
	}
	*voltage = (uint16_t) abs(temp);

	return ret;
}

enum optic_errorcode optic_calc_digitword ( const enum optic_vref vref,
					    const struct optic_table_mm_gain
					    *gain,
					    const uint16_t voltage,
					    uint16_t *digitword )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint8_t shift = 14 + OPTIC_FLOAT2INTSHIFT_CORRFACTOR -
		             OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE;
	int32_t temp;

	if (digitword == NULL)
		return OPTIC_STATUS_ERR;

	/**
	     (read_data - offset[]) * gain_correction[]
	U = --------------------------------------------  + Vref
			2^16 * gain_factor[]

	read_data = digitword

		    (U - Vref) * 2^16 * gain_factor[]
	digitword = --------------------------------- + offset[]
			   gain_correction[]

	we use scaled values (integer):
	Vref * 2 = 1, 2, 3
	gain_factor = < <<2 >      1..64    gain_factor[2] = 4
	gain_correction =  < <<OPTIC_FLOAT2INTSHIFT_CORRFACTOR > ...
				~1*2^OPTIC_FLOAT2INTSHIFT_CORRFACTOR


		    (U >> OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE - Vref >> 1) * 2^16 * gain_factor[] >> 2
	digitword = -------------------------------------------------------------------------------- + offset[]
			   gain_correction[] >> OPTIC_FLOAT2INTSHIFT_CORRFACTOR

	  (U >> OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE - Vref >> 1) * gain_factor[] << 14
	= -------------------------------------------------------------------------- + offset[]
			gain_correction[] >> OPTIC_FLOAT2INTSHIFT_CORRFACTOR

	shift = 14 + OPTIC_FLOAT2INTSHIFT_CORRFACTOR - OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE    .. 11


	  	    (U << shift - Vref << (13 + OPTIC_FLOAT2INTSHIFT_CORRFACTOR)) * gain_factor[]
	digitword= ------------------------------------------------------------------------------ + offset[]
					gain_correction[]
	*/

	temp = voltage * (1 << shift);
	temp += (vref << (13 + OPTIC_FLOAT2INTSHIFT_CORRFACTOR));

	temp = temp * gain->factor;

	temp = optic_int_div_rounded ( temp, (uint32_t) gain->correction );

	if ((temp + gain->offset) > 0xFFFF) {
		OPTIC_DEBUG_MSG ("threshold range overrun: voltage %dmV -> 0x%X",
				 (voltage*1000) >>
				 OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE,
				 temp + gain->offset);
		*digitword = 0xFFFF;
	} else
		*digitword = (uint16_t) temp + gain->offset;

	return ret;
}


enum optic_errorcode optic_calc_temperature_int ( const uint16_t voltage_vdd,
					          const uint16_t voltage_vbe1,
					          const uint16_t voltage_vbe2,
	                                          uint16_t *t_nom )
{
	int8_t shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE -
		       OPTIC_FLOAT2INTSHIFT_LOG -
		       OPTIC_FLOAT2INTSHIFT_TEMPERATURE;
	uint32_t z, n, diff;

	if (t_nom == NULL)
		return OPTIC_STATUS_ERR;

	/** Temperature calculation

	      q      VBE2 - VBE1             q           VBE2 - VBE1
	T = ----- * -------------------  = ----- * -------------------------
	    n * k            VDD-VBE2      n * k                  VDD-VBE2
		    ln (80 * -------- )            ln (80) + ln ( -------- )
			     VDD-VBE1                             VDD-VBE1

	q = 1,602177 e-19
	n = 1,011
	k = 1,380658 e-23

	we use scaled values (integer):
	q / n / k =  < *100 > = 1147819
	ln (80) = < <<OPTIC_FLOAT2INTSHIFT_LOG > = 4487
	VDD, VBE1, VBE2 = < <<OPTIC_FLOAT2INTSHIFT_VOLTAGE > = int 16
	ln (x<<OPTIC_FLOAT2INTSHIFT_LOG) = < <<OPTIC_FLOAT2INTSHIFT_LOG >

		1147819 / 100 * (VBE2 - VBE1) >> OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE
	T = -----------------------------------------------------------------------------------------------------------------------------------------------
					            (VDD-VBE2) >> OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE << OPTIC_FLOAT2INTSHIFT_LOG
	    4487 >> OPTIC_FLOAT2INTSHIFT_LOG + ln ( ----------------------------------------------------------------------------- ) >> OPTIC_FLOAT2INTSHIFT_LOG
						    (VDD-VBE1) >> OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE

	save T with << OPTIC_FLOAT2INTSHIFT_TEMPERATURE [K]
	shift = (OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE - OPTIC_FLOAT2INTSHIFT_LOG) - OPTIC_FLOAT2INTSHIFT_TEMPERATURE ... 0

			1147819 * (VBE2 - VBE1)
	T = -------------------------------------------------------------
			  (VDD-VBE2) << OPTIC_FLOAT2INTSHIFT_LOG
	    ( 4487 + ln ( -------------------------------------- ) )* 100 << shift
					VDD-VBE1
	*/
	/* per design: vdd > vbe2, vbe2 > vbe1
	OPTIC_ASSERT_RETURN (voltage_vbe2 > voltage_vbe1, OPTIC_STATUS_ERR);
	OPTIC_ASSERT_RETURN (voltage_vdd >= voltage_vbe2, OPTIC_STATUS_ERR);
	*/
	diff = voltage_vdd - voltage_vbe2;
	n = diff * (1 << OPTIC_FLOAT2INTSHIFT_LOG);

	diff = voltage_vdd - voltage_vbe1;
	n = optic_uint_div_rounded ( n, diff );
	n = optic_ln_lookuptable( abs(n) ) + 4487;
	n = (n * 100) * (1 << shift);

	diff = voltage_vbe2 - voltage_vbe1;
	z = diff * 1147819;

	*t_nom = (uint16_t) abs( optic_uint_div_rounded ( z, n ) );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_temperature_ext ( const uint16_t
						  voltage_offset_pn,
					          const uint16_t tscal_ref,
						  const uint16_t voltage,
						  uint16_t *t_nom )
{
	uint16_t u_corr;
	int32_t temp;
	uint8_t shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE -
		        OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

	if (t_nom == NULL)
		return OPTIC_STATUS_ERR;

	/**
	temperature(nominal) = (1200 [mV] - (U_corr [mv] - offset[mV])) * tscal_ref [K/mV] >> OPTIC_FLOAT2INTSHIFT_TSCALREF
	V = (1200 [mV] - (U_corr [mv] - offset[mV])) / 1000 << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE
	temperature(nominal) = V >> OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE * tscal_ref [K/mV] *1000 >> OPTIC_FLOAT2INTSHIFT_TSCALREF

	temperature stored as << OPTIC_FLOAT2INTSHIFT_TEMPERATURE
	shift = (OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE + OPTIC_FLOAT2INTSHIFT_TSCALREF) - OPTIC_FLOAT2INTSHIFT_TEMPERATURE
	temperature(nominal) = V * tscal_ref [K/mV] * 1000 >> shift */

	u_corr = voltage - voltage_offset_pn;

	temp = (1200 << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE);
	temp = optic_int_div_rounded ( temp, 1000 );

	temp = (temp - u_corr) * tscal_ref;

	temp = optic_int_div_rounded ( temp,
				       1 << OPTIC_FLOAT2INTSHIFT_TSCALREF );

	*t_nom = (uint16_t) abs( optic_int_div_rounded ( temp * 1000,
							 1 << shift ));

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_search_apd_saturation ( struct optic_control *p_ctrl,
			                           const uint16_t vapd,
			                           uint8_t *sat )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t index_low, index_high, index_center;
	ulong_t p_sat_last, p_sat_next;
	uint16_t *p_vapd_last, *p_vapd_next;
	int32_t diff;
	struct optic_table_temperature_corr *table =
						p_ctrl->table_temperature_corr;

	if (sat == NULL)
		return OPTIC_STATUS_ERR;
#ifndef OPTIC_LIBRARY
	if (p_ctrl->state.table_read[OPTIC_TABLETYPE_VAPD-
	                             OPTIC_TABLETYPE_INTERN_MIN] == false)
		return OPTIC_STATUS_APD_TBL;
#endif
	ret = optic_rangecheck_dcdc ( &(p_ctrl->config.range),
					OPTIC_DCDC_APD, vapd );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("vapd_min %d, vapd %d, vapd_max %d",
				p_ctrl->config.range.vapd_min,
				vapd,
				p_ctrl->config.range.vapd_max);
		return OPTIC_STATUS_RANGE_APD;
	}

	index_low = 0;
	index_high = p_ctrl->config.range.tabletemp_extcorr_max -
	             p_ctrl->config.range.tabletemp_extcorr_min;

	/* simple cases */
	if (vapd == table[index_low].vapd.vref) {
		*sat = table[index_low].vapd.sat;
		return OPTIC_STATUS_OK;
	}
	if (vapd == table[index_high].vapd.vref) {
		*sat = table[index_high].vapd.sat;
		return OPTIC_STATUS_OK;
	}
	if (vapd == p_ctrl->config.range.vapd_min) {
		*sat = p_ctrl->config.range.sat_min;
		return OPTIC_STATUS_OK;
	}
	if (vapd == p_ctrl->config.range.vapd_max) {
		*sat = p_ctrl->config.range.sat_max;
		return OPTIC_STATUS_OK;
	}

	/* lower than measured vapds? */
	if ( vapd < table[index_low].vapd.vref ) {
		/* interpolate between minimum sat and minimal calculated sat */
		p_sat_last = (ulong_t) &(p_ctrl->config.range.sat_min);
		p_sat_next = (ulong_t) &(table[index_low].vapd.sat);
		p_vapd_last = &(p_ctrl->config.range.vapd_min);
		p_vapd_next = &(table[index_low].vapd.vref);
	} else
	/* higher than measured vapds? */
	if ( vapd > table[index_high].vapd.vref ) {
		/* interpolate between maximum sat and maximal calculated sat */
		p_sat_last = (ulong_t) &(table[index_high].vapd.sat);
		p_sat_next = (ulong_t) &(p_ctrl->config.range.sat_max);
		p_vapd_last = &(table[index_high].vapd.vref);
		p_vapd_next = &(p_ctrl->config.range.vapd_max);
	} else {
		/* binary search */
		while (index_high - index_low > 1) {
			index_center = index_low +
			               ((index_high - index_low) / 2);

			if (vapd < table[index_center].vapd.vref)
				index_high = index_center;
			else if (vapd > table[index_center].vapd.vref)
				index_low = index_center;
			else {
				*sat = table[index_center].vapd.sat;
				return OPTIC_STATUS_OK;
			}
		}

		/* interpolate between two nearest sat values */
		p_sat_last = (ulong_t) &(table[index_low].vapd.sat);
		p_sat_next = (ulong_t) &(table[index_high].vapd.sat);
		p_vapd_last = &(table[index_low].vapd.vref);
		p_vapd_next = &(table[index_high].vapd.vref);
	}

	ret = optic_calc_ipol ( 1, p_sat_last, p_sat_next, vapd,
				      *p_vapd_last, *p_vapd_next, &diff );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_calc_ipol(): %d", ret);
		return OPTIC_STATUS_IPOL_APD;
	}

	*sat = *((uint8_t *) p_sat_last) + diff;
	return ret;
}

enum optic_errorcode optic_calc_duty_cycle ( struct optic_control *p_ctrl,
					     const enum optic_dcdc_type type,
			                     const uint16_t voltage,
			                     uint8_t *duty_cycle_min,
			                     uint8_t *duty_cycle_max )
{
	uint8_t i;
    	uint32_t temp[2];
    	uint32_t diff[2];
    	uint8_t *duty_cycle[2] = {duty_cycle_min, duty_cycle_max};
	struct optic_config_dcdc *dcdc;

    	if ((duty_cycle[0] == NULL) || (duty_cycle[1] == NULL))
    		return OPTIC_STATUS_ERR;

    	switch (type) {
	case OPTIC_DCDC_CORE:
		dcdc = &(p_ctrl->config.dcdc_core);
		break;
	case OPTIC_DCDC_DDR:
		dcdc = &(p_ctrl->config.dcdc_ddr);
		break;
	default:
		return OPTIC_STATUS_POOR;
    	}

    	/**
    			  (V * (1 - y/100) + Vmin) * 256
    	duty_cycle_min = --------------------------------
    				3,3 * (1 + x/100)

	V: [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE

    			  (V * 100 - y) + Vmin * 100) * 256
    	duty_cycle_min = ---------------------------------------
			 330 << OPTIC_FLOAT2INTSHIFT_VOLTAGE + x

    			  (V * 100 + y) + Vmax * 100) * 256
    	duty_cycle_max = ---------------------------------------
			 330 << OPTIC_FLOAT2INTSHIFT_VOLTAGE - x
	*/


	for (i=0; i<2; i++) {
		temp[i] = voltage * 100;
		diff[i] = 330 << OPTIC_FLOAT2INTSHIFT_VOLTAGE;
	}

	temp[0] = temp[0] - dcdc->v_tolerance_target + dcdc->v_min;
	temp[1] = temp[1] + dcdc->v_tolerance_target + dcdc->v_max;

	diff[0] += dcdc->v_tolerance_input;
	diff[1] -= dcdc->v_tolerance_input;

	for (i=0; i<2; i++) {
		*(duty_cycle[i]) = (uint8_t) optic_uint_div_rounded
						( temp[i] * 256, diff[i] );
	}

    	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_rssi_1490_dark_corr ( const uint16_t
						      meas_voltage_1490_rssi,
                                                      const uint16_t ext_att,
						      const uint16_t
						      vapd_target,
                                                      const uint32_t *r_diff,
                                                      const uint16_t
                                                      rssi_1490_shunt_res,
                                                      uint16_t
                                                      *rssi_1490_dark_corr )
{
	uint32_t temp;
	int8_t shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE +
		       OPTIC_FLOAT2INTSHIFT_EXTATT -
	 	       OPTIC_FLOAT2INTSHIFT_VOLTAGE -
		       OPTIC_FLOAT2INTSHIFT_CORRFACTOR;

	if (shift < 1)
		return OPTIC_STATUS_ERR;

	if (rssi_1490_dark_corr == NULL)
		return OPTIC_STATUS_ERR;

	/**
	                       meas_voltage_rx1490 * ext_att
	                       -----------------------------
	                             rssi_1490_shunt_res
	rssi_1490_dark_corr = --------------------------------
						vapd
			       ---------------------------------------------
			      (rssi_1490_shunt_res + r_diff_low + r_diff_high)


	                       meas_voltage_rx1490 * ext_att * (rssi_1490_shunt_res + r_diff_low + r_diff_high)
	rssi_1490_dark_corr =  ---------------------------------------------------------------------------------
					rssi_1490_shunt_res * vapd

	rssi_1490_dark_corr: << OPTIC_FLOAT2INTSHIFT_CORRFACTOR
	meas_voltage_rx1490: [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE
	ext_att: << OPTIC_FLOAT2INTSHIFT_EXTATT
	vapd: [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE

	                       meas_voltage_rx1490 * ext_att        (rssi_1490_shunt_res + r_diff_low + r_diff_high)
	rssi_1490_dark_corr =  ------------------------------  *    ---------------------------------------------------
					   vapd                           rssi_1490_shunt_res << shift

	shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE + OPTIC_FLOAT2INTSHIFT_EXTATT - OPTIC_FLOAT2INTSHIFT_VOLTAGE - OPTIC_FLOAT2INTSHIFT_CORRFACTOR


	*/

	temp = meas_voltage_1490_rssi * ext_att;
	temp = optic_uint_div_rounded ( temp, vapd_target );

	temp = temp * (r_diff[0] + r_diff[1] + rssi_1490_shunt_res);

	temp = optic_uint_div_rounded ( temp, (rssi_1490_shunt_res << shift) );

	*rssi_1490_dark_corr = (uint16_t) temp;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_current_offset ( const uint16_t
						 rssi_1490_dark_corr,
						 const uint16_t vapd_target,
						 const uint32_t *r_diff,
						 const uint16_t
						 rssi_1490_shunt_res,
						 uint16_t *current_offset )
{
	uint32_t temp, diff;
	int8_t shift = OPTIC_FLOAT2INTSHIFT_CORRFACTOR +
		       OPTIC_FLOAT2INTSHIFT_VOLTAGE -
		       OPTIC_FLOAT2INTSHIFT_CURRENT_FINE;

	if (shift < 1)
		return OPTIC_STATUS_ERR;

	if (current_offset == NULL)
		return OPTIC_STATUS_ERR;

	/**
			RSSI1490dark_corr * Vapd
	Ioffset = -----------------------------------------------
		  (R_diff_low + R_diff_high + rssi_1490_shunt_res)

	RSSI1490dark_corr [<<OPTIC_FLOAT2INTSHIFT_CORRFACTOR]
	VAPD: V [<<OPTIC_FLOAT2INTSHIFT_VOLTAGE]
	R_diff_low, R_diff_high, rssi_1490_shunt_res: Ohm
	Ioffset: mA [<<OPTIC_FLOAT2INTSHIFT_CURRENT_FINE]

	shift = OPTIC_FLOAT2INTSHIFT_CORRFACTOR + OPTIC_FLOAT2INTSHIFT_VOLTAGE
	 	- OPTIC_FLOAT2INTSHIFT_CURRENT_FINE

			RSSI1490dark_corr * Vapd * 1000
	Ioffset = --------------------------------------------------------
		  (R_diff_low + R_diff_high + rssi_1490_shunt_res) << shift
	*/

	temp = rssi_1490_dark_corr * vapd_target;

	diff = r_diff[0] + r_diff[1] + rssi_1490_shunt_res;

	temp = optic_uint_div_rounded ( temp, diff );

	temp = optic_uint_div_rounded ( temp * 1000, (1 << shift) );

	*current_offset = (uint16_t) (temp);

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_calc_current_1490 ( const enum optic_rssi_1490_mode
					       rssi_1490_mode,
                           const uint16_t voltage_1490,
					       const uint16_t ext_att,
					       const uint16_t rssi_1490_shunt_res,
					       const uint16_t current_offset,
					       struct optic_fuses *fuses,
					       uint16_t *current_1490,
					       bool *is_positive )
{
	uint32_t temp;
	int8_t shift;

	if (current_1490 == NULL)
		return OPTIC_STATUS_ERR;

	switch (rssi_1490_mode) {
	case OPTIC_RSSI_1490_DIFFERENTIAL:
		/**
				      	  	  	 meas_voltage_rx1490 * ext_att
		meas_current_rx1490 = ----------------------------   - current_offset
				          	  	  rssi_1490_shunt_res

		meas_voltage_rx1490: [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE
		meas_current_rx1490, current_offset: [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE
		ext_att: << OPTIC_FLOAT2INTSHIFT_EXTATT

		shift = OPTIC_FLOAT2INTSHIFT_CURRENT_FINE - OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE

				       	   	   meas_voltage_rx1490 << shift * 1000 * ext_att
		meas_current_rx1490 = ---------------------------------------------------  - current_offset
				       	   	   rssi_1490_shunt_res << OPTIC_FLOAT2INTSHIFT_EXTATT
		*/

		shift = OPTIC_FLOAT2INTSHIFT_CURRENT_FINE -
		        OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE;
		temp = (voltage_1490 << shift) * ext_att;

		temp = optic_uint_div_rounded ( temp, rssi_1490_shunt_res);

		temp = temp * 1000;
		temp += (1 << (OPTIC_FLOAT2INTSHIFT_EXTATT - 1));
		temp = (temp >> OPTIC_FLOAT2INTSHIFT_EXTATT);

		if (temp > current_offset) {
			*current_1490 = (uint16_t) (temp - current_offset);
			*is_positive = true;
		} else {
			*current_1490 = (uint16_t) (current_offset -
						    (uint16_t) temp);
			*is_positive = false;
		}

		break;

	case OPTIC_RSSI_1490_SINGLE_ENDED:
		/**
					  meas_voltage_rx1490
		meas_current_rx1490 = --------------------------
				      (700 + RCALMM / 2^7 * 300)

		meas_voltage_rx1490: [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE
		meas_current_rx1490: [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE

		shift = 7 + OPTIC_FLOAT2INTSHIFT_CURRENT_FINE - OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE

				       meas_voltage_rx1490 << shift * 1000
		meas_current_rx1490 = ------------------------------------
					(700*128 + RCALMM * 300)
		*/

		shift = 7 + OPTIC_FLOAT2INTSHIFT_CURRENT_FINE -
	                    OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE;
		temp = (voltage_1490 << shift) * 1000;

		temp = optic_uint_div_rounded ( temp,
						(700 * 128) +
						       (fuses->rcal_mm * 300) );

		*current_1490 = (uint16_t) temp;
		*is_positive = true;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

/**
	/note: meas_value is current for RSSI_1490
		and voltage for RF_1550 and RSSI 1550
*/
enum optic_errorcode optic_calc_power ( const enum optic_cfactor factor_index,
					const struct optic_config_range *range,
					const uint16_t temperature_ext,
					struct optic_table_temperature_corr
					*t_corr,
					const uint16_t scal_ref,
					const uint16_t meas_value,
					uint16_t *power,
					const uint16_t parabolic_ref,
					const uint16_t dark_curr)
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint32_t temp, temp2;
	uint16_t temp3;
	uint16_t temp_index;
	int8_t shift;

	if (factor_index == OPTIC_CFACTOR_RSSI1490) {
		shift = OPTIC_FLOAT2INTSHIFT_CURRENT_FINE +
		        OPTIC_FLOAT2INTSHIFT_PSCALREF -
		        OPTIC_FLOAT2INTSHIFT_POWER;
	}
	else {
		shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE +
		        OPTIC_FLOAT2INTSHIFT_PSCALREF -
		        OPTIC_FLOAT2INTSHIFT_POWER;
	}

	if (power == NULL)
		return OPTIC_STATUS_ERR;

	ret = optic_rangecheck_etemp_corr ( range, temperature_ext,
						  &temp_index );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/**
	meas_power_1490_rssi = meas_current_1490_rssi * rssi_1490_scal_ref

	meas_current_1490_rssi: [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE
	rssi_1490_scal_ref: [mW/mA] << OPTIC_FLOAT2INTSHIFT_PSCALREF
	meas_power_1490_rssi: [mW] << OPTIC_FLOAT2INTSHIFT_POWER

	shift =  OPTIC_FLOAT2INTSHIFT_CURRENT_FINE + OPTIC_FLOAT2INTSHIFT_PSCALREF - OPTIC_FLOAT2INTSHIFT_POWER

	meas_power_1490_rssi = meas_current_1490_rssi * rssi_1490_scal_ref >> shift

	GPONSW-747:
	RSSI1490 parabolic correction

	rssi1490_parab_ref: [mW/mA^2] << OPTIC_FLOAT2INTSHIFT_PSCALREF
	rssi1490_dark_ref: [mA] << OPTIC_FLOAT2INTSHIFT_PSCALREF

	RSSI1490 = RSSI1490scal * (RSSI1490current - RSSI1490dark_ref) +
					RSSI1490parab_ref * (RSSI1490current - RSSI1490dark_ref)^2


 	temp = (meas_current_1490_rssi - rssi1490_dark_ref)
	meas_power_1490_rssi = temp * rssi_1490_scal_ref >> shift
							+ temp^2 * rssi1490_parab_ref >> (shift+OPTIC_FLOAT2INTSHIFT_CURRENT_FINE)

	*/

	/**
	meas_power_1550_x = meas_voltage_1550_x * x_1550_scal_ref

	meas_voltage_1550_x: [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE
	x_1550_scal_ref: [mW/V] << OPTIC_FLOAT2INTSHIFT_PSCALREF
	meas_power_1550_x: [mW] << OPTIC_FLOAT2INTSHIFT_POWER

	shift =  OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE + OPTIC_FLOAT2INTSHIFT_PSCALREF - OPTIC_FLOAT2INTSHIFT_POWER

	meas_power_1550_x = meas_voltage_1550_x * x_1550_scal_ref >> shift

	*/

	temp3 = (meas_value-dark_curr);

	temp = temp3 * scal_ref;
	temp = optic_uint_div_rounded ( temp, 1 << shift );

	if(factor_index == OPTIC_CFACTOR_RSSI1490 ) {
		/* temp^2 * rssi1490_parab_ref >> shift2 */
		temp2 = temp3 * parabolic_ref;
		temp2 = optic_uint_div_rounded ( temp2, 1 << shift );
		temp2 = temp2 * temp3;
		temp2 = optic_uint_div_rounded ( temp2, 1 << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE );

		temp += temp2;
	}

	/**
	corr_power_1490_rssi = meas_power_1490_rssi * corr_factor
	corr_factor: << OPTIC_FLOAT2INTSHIFT_CORRFACTOR
	*/
	temp *= t_corr[temp_index].factor[factor_index].corr_factor;
	temp = optic_uint_div_rounded ( temp, 1 << shift );

	*power = (uint16_t) temp;

	return ret;
}

enum optic_errorcode optic_calc_thresh_current ( const uint16_t
						 rssi_1490_scal_ref,
						 const uint16_t threshold,
						 uint16_t *thresh_current )
{
	uint32_t temp;
	uint8_t shift;

	/**
	I = Power_threshold / rssi_1490_scal_ref

	power_threshold: [mW] << OPTIC_FLOAT2INTSHIFT_POWER
	rssi_1490_scal_ref: [mW/mA] << OPTIC_FLOAT2INTSHIFT_PSCALREF
	I: [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE
	*/

	shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE +
		OPTIC_FLOAT2INTSHIFT_PSCALREF -
		OPTIC_FLOAT2INTSHIFT_POWER;

	temp = threshold << shift;

	temp = optic_uint_div_rounded ( temp, rssi_1490_scal_ref );

	if (thresh_current != NULL)
		*thresh_current = (uint16_t) temp;

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_calc_thresh_voltage_1490 ( const enum
						      optic_rssi_1490_mode
						      rssi_1490_mode,
						      const uint16_t
						      thresh_current,
					       	      const uint16_t ext_att,
					       	      const uint16_t
						      rssi_1490_shunt_res,
					       	      const uint16_t
					       	      current_offset,
						      struct optic_fuses *fuses,
						      const bool force,
						      uint16_t *thresh_voltage )
{
	uint32_t temp;
	uint32_t rcal;
	uint8_t shift;

	if (thresh_voltage == NULL)
		return OPTIC_STATUS_ERR;

	if ((rssi_1490_mode == OPTIC_RSSI_1490_SINGLE_ENDED) &&
	    (force == false) && (*thresh_voltage != 0))
	    	return OPTIC_STATUS_OK;

	temp = thresh_current;

	switch (rssi_1490_mode) {
	case OPTIC_RSSI_1490_DIFFERENTIAL:
		/**
				      meas_voltage_rx1490 * ext_att
		meas_current_rx1490 = ----------------------------   - current_offset
				          rssi_1490_shunt_res

				     power_threshold                         rssi_1490_shunt_res
		thresh_voltage =  ( ------------------- + current_offset ) * -------------------
				     rssi_1490_scal_ref                           ext_att

		power_threshold: [mW] << OPTIC_FLOAT2INTSHIFT_POWER
		current_offset: [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE
		rssi_1490_scal_ref: [mW/mA] << OPTIC_FLOAT2INTSHIFT_PSCALREF
		ext_att: << OPTIC_FLOAT2INTSHIFT_EXTATT
		thresh_voltage: [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE

		shift_pow = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE + OPTIC_FLOAT2INTSHIFT_PSCALREF - OPTIC_FLOAT2INTSHIFT_POWER
		shift_off = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE - OPTIC_FLOAT2INTSHIFT_CURRENT_FINE

				     power_threshold << shift_pow                                   rssi_1490_shunt_res << OPTIC_FLOAT2INTSHIFT_EXTATT
		thresh_voltage =  ( ------------------------------ + current_offset << shift_off ) * ---------------------------------------------------
				         rssi_1490_scal_ref                                               1000 * ext_att
		*/


		shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE -
			OPTIC_FLOAT2INTSHIFT_CURRENT_FINE;

		temp += (current_offset << shift);
		temp = (temp * rssi_1490_shunt_res);

		temp = optic_uint_div_rounded ( temp, 1000 );

		temp = (temp << OPTIC_FLOAT2INTSHIFT_EXTATT);

		temp = optic_uint_div_rounded ( temp, ext_att );
		break;
	case OPTIC_RSSI_1490_SINGLE_ENDED:
		/**
					  meas_voltage_rx1490
		meas_current_rx1490 = --------------------------
				      (700 + RCALMM / 2^7 * 300)

				     power_threshold        (700 + RCALMM / 2^7 * 300)
		thresh_voltage =    -------------------  *  --------------------------
				     rssi_1490_scal_ref                1000

		power_threshold: [mW] << OPTIC_FLOAT2INTSHIFT_POWER
		rssi_1490_scal_ref: [mW/mA] << OPTIC_FLOAT2INTSHIFT_PSCALREF
		thresh_voltage: [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE

		shift_pow = OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE + OPTIC_FLOAT2INTSHIFT_PSCALREF - OPTIC_FLOAT2INTSHIFT_POWER

				     power_threshold << shift_pow      (700 * 128 + RCALMM * 300)
		thresh_voltage =  ( ------------------------------  * ----------------------------
				         rssi_1490_scal_ref                  1000 << 7
		*/

		rcal = (700 * 128) + (fuses->rcal_mm * 300);

		temp = temp * rcal;

		temp = optic_uint_div_rounded ( temp, 1000 << 7 );

		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	*thresh_voltage = (uint16_t) temp;

	return OPTIC_STATUS_OK;
}

/**
	calculate current offset, and threshold voltage for los and ovl

	- optic_calc_current_offset
	- optic_calc_thresh_voltage_1490 ( los )
	- optic_calc_thresh_voltage_1490 ( ovl )

*/
enum optic_errorcode optic_calc_offset_and_thresh ( struct optic_control
						    *p_ctrl )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t vapd;
	int16_t regulation_error;

	if(dcdc_apd_disabled()) {
		/* GPONSW-686: read back VAPD voltage before calculation */
		ret = optic_dcdc_apd_voltage_get ( p_ctrl, &vapd, &regulation_error);
		if (ret != OPTIC_STATUS_OK)
			return ret;
	} else {
		vapd = p_ctrl->calibrate.vapd_target;
	}

	ret = optic_calc_current_offset (
				p_ctrl->config.measurement.rssi_1490_dark_corr,
				vapd,
				p_ctrl->config.dcdc_apd.r_diff,
				p_ctrl->config.measurement.rssi_1490_shunt_res,
				&(p_ctrl->calibrate.current_offset) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_calc_thresh_voltage_1490 (
				p_ctrl->config.measurement.rssi_1490_mode,
				p_ctrl->calibrate.thresh_current_los,
				p_ctrl->config.dcdc_apd.ext_att,
				p_ctrl->config.measurement.rssi_1490_shunt_res,
				p_ctrl->calibrate.current_offset,
				&(p_ctrl->config.fuses), false,
				&(p_ctrl->calibrate.thresh_voltage_los) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_calc_thresh_voltage_1490 (
				p_ctrl->config.measurement.rssi_1490_mode,
				p_ctrl->calibrate.thresh_current_ovl,
				p_ctrl->config.dcdc_apd.ext_att,
				p_ctrl->config.measurement.rssi_1490_shunt_res,
				p_ctrl->calibrate.current_offset,
				&(p_ctrl->config.fuses), false,
				&(p_ctrl->calibrate.thresh_voltage_ovl) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/*
 * This function is required by
 *  - optic_ll_rx_dsm_reset()
 *  - optic_thread_measure()
 */
enum optic_errorcode optic_calc_lol_thresh ( const uint32_t base,
					     const uint8_t limit_low,
					     const uint8_t limit_high,
					     int32_t *low_tresh,
					     int32_t *high_tresh)
{
	int32_t low, high, temp;

	temp = base;
	/* calculate twos complement */
	/* check for 24 bit twos complement value? */
	if (temp & 0x800000)
		temp -= (1<<24);

	low  = abs(temp) * limit_low;
	high = abs(temp) * limit_high;

	/* set lower limit */
	*low_tresh = temp - optic_int_div_rounded ( low, 100 );

	/* set upper limit */
	*high_tresh = temp + optic_int_div_rounded ( high, 100 );

	return OPTIC_STATUS_OK;
}

uint32_t optic_ln2_arithmentic ( void )
{
	const uint32_t ln2 = 744261118 >> (30-OPTIC_LOG_GRANULARITY);

	return ln2;
}

uint32_t optic_ld_arithmentic ( uint32_t value )
{
	uint32_t border = 2 << OPTIC_LOG_GRANULARITY;
	uint8_t i = 0;
	uint32_t ld = 0;

	while (value >= border) {
		i++;
		value >>= 1;
	}

	ld = i << OPTIC_LOG_GRANULARITY;

	if (value) {
		for (i=OPTIC_LOG_GRANULARITY; i; i--) {
			value *= value;
			if (value >= border) {
				ld += (1 << (i-1));
				value >>= 1;
			}
			value >>= OPTIC_LOG_GRANULARITY;
		}
	}

	return ld;
}

uint32_t optic_ln_arithmentic (uint32_t value )
{
	uint32_t temp = optic_ld_arithmentic(value) * optic_ln2_arithmentic();

	return optic_uint_div_rounded ( temp, 1 << OPTIC_LOG_GRANULARITY );
}

/**

	\param value   input is shifted to the left by
	               OPTIC_TABLE_FLOAT2INT_SHIFT

	\return        output is shifted to the left by
	               OPTIC_TABLE_FLOAT2INT_SHIFT
*/
int32_t optic_ln_lookuptable ( uint32_t value )
{
#define OPTIC_LN_LOOKUP_MAX 6
/* for OPTIC_LN_LOOKUP_GRANULARIRY=4: 1/2^4,  steps = 0,0625 (decimal) */
#define OPTIC_LN_LOOKUP_GRANULARITY 4

#define OPTIC_LN_LOOKUP_SHIFT (OPTIC_FLOAT2INTSHIFT_LOG - OPTIC_LN_LOOKUP_GRANULARITY)
#define OPTIC_LN_LOOKUP_VALUES (OPTIC_LN_LOOKUP_MAX << OPTIC_LN_LOOKUP_GRANULARITY)

	int8_t i;
	int32_t split;
	int32_t ret;
	static uint8_t step = 1 << OPTIC_LN_LOOKUP_SHIFT;

#if (OPTIC_FLOAT2INTSHIFT_LOG == 10)
	/* calculated for OPTIC_FLOAT2INTSHIFT_LOG = 10 */
	static int LN[OPTIC_LN_LOOKUP_VALUES] = {
	-2839, -2129, -1714, -1420, -1191, -1004,  -847,  -710,
	 -589,  -481,  -384,  -295,  -213,  -137,   -66,     0, /* .. 1,00 */
	   62,   121,   176,   228,   278,   326,   372,   415,
	  457,   497,   536,   573,   609,   644,   677,   710, /* .. 2,00 */
	  741,   772,   802,   830,   858,   886,   912,   938,
	  964,   988,  1012,  1036,  1059,  1081,  1103,  1125, /* .. 3,00 */
	 1146,  1167,  1187,  1207,  1226,  1246,  1264,  1283,
	 1301,  1319,  1336,  1353,  1370,  1387,  1403,  1420, /* .. 4,00 */
	 1435,  1451,  1466,  1482,  1497,  1511,  1526,  1540,
	 1554,  1568,  1582,  1596,  1609,  1622,  1635,  1648, /* .. 5,00 */
	 1661,  1673,  1686,  1698,  1710,  1722,  1734,  1746,
	 1757,  1769,  1780,  1791,  1802,  1813,  1824,  1835  /* .. 6,00 */
	};
#else
	#error RECALCULATE ln lookuptable !!!
#endif

	i = value >> OPTIC_LN_LOOKUP_SHIFT;
	if ((i) && (i < OPTIC_LN_LOOKUP_VALUES)) {
		ret = (int32_t) LN[i-1];
		split = value - (i<<OPTIC_LN_LOOKUP_SHIFT);
		return ret +
		       optic_int_div_rounded (split * (LN[i] - LN[i-1]), step);
	}

	return 0xFFFFFFFF;
}



/*! @} */

/*! @} */
