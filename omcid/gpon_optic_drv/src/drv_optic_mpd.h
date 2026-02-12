/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_mpd.h
*/
#ifndef _drv_optic_mpd_h
#define _drv_optic_mpd_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_MPD_INTERNAL MPD Module - Internal
   @{
*/
enum optic_errorcode optic_mpd_init ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mpd_level_search ( struct optic_control *p_ctrl,
					      const enum optic_search_type
					      type,
					      int16_t *level ,int16_t *level_c );
enum optic_errorcode optic_mpd_offset_cancel ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mpd_ratio_measure ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mpd_calibrate_level ( struct optic_control *p_ctrl,
					         const bool offset_cancel,
					         const bool calibrate[2],
					         int16_t dac_coarse[2],
					         int16_t dac_fine[2] );
enum optic_errorcode optic_mpd_dac_level_search ( struct optic_control *p_ctrl,
						  const bool offset_calibration,
                                                  const uint8_t type_coarse,
						  const uint8_t type_fine,
						  int16_t *dac_coarse,
		                                  int16_t *dac_fine );
enum optic_errorcode optic_mpd_codeword_calc ( struct optic_control *p_ctrl,
					       const bool calibrate[2],
					       const bool offset_cancellation,
					       const int16_t dac_coarse[2],
					       const int16_t dac_fine[2] );
enum optic_errorcode optic_mpd_codeword_set ( struct optic_control *p_ctrl,
                                              bool p0 );
enum optic_errorcode optic_mpd_biasmod_average ( struct optic_control *p_ctrl,
					         const enum optic_current_type
					         type );
enum optic_errorcode optic_mpd_regulation_get ( struct optic_control *p_ctrl,
						const enum optic_current_type type,
						bool *update,
 						uint16_t *average,
 						bool *reset_bias_low);
enum optic_errorcode optic_mpd_stable_get ( struct optic_control *p_ctrl,
					    const enum optic_current_type type,
					    const uint16_t average,
					    bool *reset);
enum optic_errorcode optic_mpd_biasmod_update ( struct optic_control *p_ctrl,
						const enum optic_current_type
						type );
enum optic_errorcode optic_mpd_p0_correct ( struct optic_control *p_ctrl);
enum optic_errorcode optic_mpd_biasmod_learn ( struct optic_control *p_ctrl,
					       const enum optic_current_type
					       type,
					       bool *learn );
void optic_mpd_biasmod_max_set ( uint8_t *bias_max, uint8_t *mod_max );
enum optic_errorcode optic_mpd_saturation_set ( struct optic_control *p_ctrl,
				                const uint16_t bias_sat,
				                const uint16_t mod_sat );
enum optic_errorcode optic_mpd_bias_set ( struct optic_control *p_ctrl,
					  const uint16_t ibias );
enum optic_errorcode optic_mpd_biaslowsat_set ( struct optic_control *p_ctrl,
					  const uint16_t ibias );
enum optic_errorcode optic_mpd_bias_get ( struct optic_control *p_ctrl,
					  const bool init,
					  uint16_t *bias );
enum optic_errorcode optic_mpd_mod_set ( struct optic_control *p_ctrl,
                                         const uint16_t imod );
enum optic_errorcode optic_mpd_mod_get ( struct optic_control *p_ctrl,
					 const bool init,
					 uint16_t *mod );
enum optic_errorcode optic_mpd_cint_set ( struct optic_control *p_ctrl,
					  const enum optic_current_type type,
                                          const uint8_t intcoeff );
enum optic_errorcode optic_mpd_loopmode ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mpd_gainctrl_set ( struct optic_control *p_ctrl,
                                              const enum optic_gainbank
                                              gainbank,
                                              const enum optic_cal_current
                                              cal_current );
enum optic_errorcode optic_mpd_tia_offset_set ( struct optic_control *p_ctrl,
						const enum optic_gainbank
						gainbank );

/*! @} */

/*! @} */

EXTERN_C_END

#endif
