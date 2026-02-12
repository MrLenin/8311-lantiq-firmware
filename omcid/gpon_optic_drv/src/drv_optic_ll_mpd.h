
/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_mpd.h
*/
#ifndef _drv_optic_ll_mpd_h
#define _drv_optic_ll_mpd_h

#ifndef SYSTEM_SIMULATION
#include "drv_optic_api.h"
#include "drv_optic_common.h"
#else
#include "drv_optic_simu.h"
#endif


EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_MPD_INTERNAL MPD Interface - Internal
   @{
*/

#define P0_DUAL_LOOP_RESET                  0x0FE008C0
#define P1_DUAL_LOOP_RESET                  0x0FE008C0
#define LOOP_REGULATION_BIAS_RESET          0x42002080
#define LOOP_REGULATION_MODULATION_RESET    0x42002080



enum optic_dac_type {
	OPTIC_DAC_TIA_OFFSET,
	OPTIC_DAC_P0_LEVEL,
	OPTIC_DAC_P1_LEVEL,
	OPTIC_DAC_MAX
};

enum optic_p_type {
	OPTIC_P0,
	OPTIC_P1
};

enum optic_errorcode optic_ll_mpd_init ( const struct optic_config_monitor
					 *monitor,
					 const enum optic_bosa_loop_mode
					 loop_mode );
enum optic_errorcode optic_ll_mpd_exit ( void );
enum optic_errorcode optic_ll_mpd_level_set ( const enum optic_search_type type,
					      const int16_t level );
#if 0
enum optic_errorcode optic_ll_mpd_level_get ( const enum optic_search_type type,
					      int16_t *level );
#endif
enum optic_errorcode optic_ll_mpd_disable_powersave(void);
enum optic_errorcode optic_ll_mpd_level_find ( const enum optic_loop_mode burstmode, const enum optic_search_type
					       type,
					       const bool read_p0,
					       int32_t gain,
					       int16_t *level,
					       int16_t *level_c);
enum optic_errorcode optic_ll_mpd_loop_set ( const struct optic_config_monitor
					     *monitor,
					     enum optic_loop_mode *loopmode,
					     const enum optic_loop_mode
					     loopmode_p0,
					     const enum optic_loop_mode
					     loopmode_p1 );
enum optic_errorcode optic_ll_mpd_cint_set ( const enum optic_current_type
                                             type,
                                             const uint8_t intcoeff,
                                             const uint16_t saturation );
enum optic_errorcode optic_ll_mpd_dac_set ( enum optic_dac_type dac,
                                            const int16_t coarse,
					    const int16_t fine );
enum optic_errorcode optic_ll_mpd_dac_get ( enum optic_dac_type dac,
                                            int16_t *off_c,
					    int16_t *off_f );
enum optic_errorcode optic_ll_mpd_trace_get ( uint16_t *correlator_trace_p0,
					      uint16_t *correlator_trace_p1,
					      uint16_t *trace_pattern_p0,
					      uint16_t *trace_pattern_p1 );
enum optic_errorcode optic_ll_mpd_update_get ( const enum optic_current_type
					       type,
					       const uint8_t int_coeff,
					       bool *update );
enum optic_errorcode optic_ll_mpd_saturation_write ( const uint16_t bias_sat,
					             const uint16_t mod_sat );
enum optic_errorcode optic_ll_mpd_saturation_read ( uint16_t *bias_sat,
					            uint16_t *mod_sat );
enum optic_errorcode optic_ll_mpd_bias_write ( const uint16_t dbias );
enum optic_errorcode optic_ll_mpd_biaslowsat_write ( const uint16_t dbias );
enum optic_errorcode optic_ll_mpd_bias_read ( uint16_t *dbias );
#if 0
enum optic_errorcode optic_ll_mpd_gain_toggle (void);
#endif
enum optic_errorcode optic_ll_mpd_bias_check ( bool *update );
enum optic_errorcode optic_ll_mpd_mod_write ( const uint16_t dmod );
enum optic_errorcode optic_ll_mpd_mod_read ( uint16_t *dmod );
enum optic_errorcode optic_ll_mpd_mod_check ( bool *update );
enum optic_errorcode optic_ll_mpd_compstatus_get ( uint16_t *p0_cnt,
					           uint16_t *p1_cnt );
enum optic_errorcode optic_ll_mpd_powersave_set ( const enum optic_activation
                                                  powerdown );
enum optic_errorcode optic_ll_mpd_powersave_get ( enum optic_activation
						  *powerdown );
enum optic_errorcode optic_ll_mpd_gainctrl_set ( const uint8_t
						 tia_gain_selector,
                                                 const uint8_t
                                                 calibration_current );
void optic_ll_mpd_az_delay_set (uint8_t p0_az, uint8_t p1_az);
enum optic_errorcode optic_ll_mpd_az_delay_get (uint8_t *p0_az,
	uint8_t *p1_az);
void optic_ll_mpd_rogue_int_set ( const enum optic_activation iba_mode,
	const enum optic_activation ba_mode);
void optic_ll_mpd_ib_handle (uint32_t *ib_check_old, bool rw);
void optic_ll_mpd_p0cnt_get (uint32_t *p0_cnt);

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_MPD == ACTIVE))
enum optic_errorcode optic_ll_mpd_dump ( void );
#endif

/*! @} */

/*! @} */

EXTERN_C_END

#endif

