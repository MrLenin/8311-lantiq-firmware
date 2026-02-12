/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_api_h
#define _drv_optic_api_h

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
                  Internally used functions to control the optical interface.
   @{
*/

/** \addtogroup OPTIC_COMMON_INTERNAL Optic Common Driver Interface - Internal
   @{
*/



/* exclude some parts from SWIG generation */
#ifndef SWIG

#include "drv_optic_std_defs.h"
#include "ifxos_thread.h"
#include "ifxos_event.h"
#include "ifxos_select.h"

#include "drv_optic_error.h"
#include "drv_optic_common.h"

#include "drv_optic_debug.h"

#include "drv_optic_goi_interface.h"
#include "drv_optic_fcsi_interface.h"
#include "drv_optic_mm_interface.h"
#include "drv_optic_mpd_interface.h"
#include "drv_optic_bert_interface.h"
#include "drv_optic_omu_interface.h"
#include "drv_optic_bosa_interface.h"
#include "drv_optic_cal_interface.h"
#include "drv_optic_dcdc_apd_interface.h"
#include "drv_optic_dcdc_core_interface.h"
#include "drv_optic_dcdc_ddr_interface.h"
#include "drv_optic_ldo_interface.h"

EXTERN_C_BEGIN

#endif /* SWIG */




#ifdef INCLUDE_DEBUG_SUPPORT
enum optic_errorcode optic_debuglevel_set ( struct optic_device *p_dev,
					    const struct optic_debuglevel
					    *param );
enum optic_errorcode optic_debuglevel_get ( struct optic_device *p_dev,
					    struct optic_debuglevel *param );
#endif
enum optic_errorcode optic_version_get ( struct optic_device *p_dev,
				         struct optic_versionstring *param );
enum optic_errorcode optic_register_set ( struct optic_device *p_dev,
					  const struct optic_reg_set *param );
enum optic_errorcode optic_register_get ( struct optic_device *p_dev,
					  const struct optic_reg_get_in
					  *param_in,
					  struct optic_reg_get_out
					  *param_out );
enum optic_errorcode optic_reset ( struct optic_device *p_dev );
enum optic_errorcode optic_reconfig ( struct optic_device *p_dev );
enum optic_errorcode optic_mode_set ( struct optic_device *p_dev,
                                      const struct optic_mode *param);
enum optic_errorcode optic_isr_register ( struct optic_device *p_dev,
	                                  const struct optic_register
	                                  *param );
/* GOI block -> drv_optic_goi_interface.h, drv_optic_goi.c */
enum optic_errorcode goi_init ( struct optic_device *p_dev );
enum optic_errorcode goi_init_ctrl ( struct optic_control *p_ctrl );
enum optic_errorcode goi_cfg_set ( struct optic_device *p_dev,
                                   const struct optic_goi_config *param );
enum optic_errorcode goi_cfg_get ( struct optic_device *p_dev,
				   struct optic_goi_config *param );
enum optic_errorcode goi_range_cfg_set ( struct optic_device *p_dev,
                                         const struct optic_range_config
                                         *param );
enum optic_errorcode goi_range_cfg_get ( struct optic_device *p_dev,
                                         struct optic_range_config *param );
enum optic_errorcode goi_table_set ( struct optic_device *p_dev,
				     const struct optic_transfer_table_set
				     *param );
enum optic_errorcode goi_table_get ( struct optic_device *p_dev,
				     const struct optic_transfer_table_get_in
				     *param_in,
				     struct optic_transfer_table_get_out
				     *param_out );
enum optic_errorcode goi_status_get ( struct optic_device *p_dev,
				      struct optic_status *param );
enum optic_errorcode goi_ext_status_get ( struct optic_device *p_dev,
				      struct optic_ext_status *param );
enum optic_errorcode goi_lts_cfg_set ( struct optic_device *p_dev,
				       const struct optic_lts_config *param );
enum optic_errorcode goi_lts_cfg_get ( struct optic_device *p_dev,
				       struct optic_lts_config *param );
#ifndef SWIG
enum optic_errorcode goi_lts_trigger ( void );
#endif
enum optic_errorcode goi_video_cfg_set ( struct optic_device *p_dev,
				         const struct optic_video_config
				         *param );
enum optic_errorcode goi_video_cfg_get ( struct optic_device *p_dev,
				         struct optic_video_config *param );
enum optic_errorcode goi_video_enable ( struct optic_device *p_dev );
enum optic_errorcode goi_video_disable ( struct optic_device *p_dev );
enum optic_errorcode goi_video_status_get ( struct optic_device *p_dev,
				            struct optic_video_status *param );
enum optic_errorcode goi_mm_interval_cfg_set ( struct optic_device *p_dev,
	const struct optic_mm_interval_config *param );

/* FCSI block -> drv_optic_fcsi_interface.h, drv_optic_fcsi.c */
enum optic_errorcode fcsi_cfg_set ( struct optic_device *p_dev,
				    const struct optic_fcsi_config *param );
enum optic_errorcode fcsi_cfg_get ( struct optic_device *p_dev,
				    struct optic_fcsi_config *param );

/* DCDC APD block -> drv_optic_dcdc_apd_interface.h, drv_optic_dcdc_apd.c */
enum optic_errorcode dcdc_apd_cfg_set ( struct optic_device *p_dev,
				        const struct optic_dcdc_apd_config
					*param );
enum optic_errorcode dcdc_apd_cfg_get ( struct optic_device *p_dev,
				        struct optic_dcdc_apd_config *param );
enum optic_errorcode dcdc_apd_enable ( struct optic_device *p_dev );
enum optic_errorcode dcdc_apd_disable ( struct optic_device *p_dev );
#ifndef SWIG
bool dcdc_apd_disabled (void);
#endif
enum optic_errorcode dcdc_apd_status_get ( struct optic_device *p_dev,
                                           struct optic_dcdc_apd_status
                                           *param );

/* DCDC CORE block -> drv_optic_dcdc_core_interface.h, drv_optic_dcdc_core.c */
enum optic_errorcode dcdc_core_cfg_set ( struct optic_device *p_dev,
				         const struct optic_dcdc_core_config
					 *param );
enum optic_errorcode dcdc_core_cfg_get ( struct optic_device *p_dev,
				         struct optic_dcdc_core_config *param );
enum optic_errorcode dcdc_core_enable ( struct optic_device *p_dev );
enum optic_errorcode dcdc_core_disable ( struct optic_device *p_dev );
enum optic_errorcode dcdc_core_status_get ( struct optic_device *p_dev,
                                            struct optic_dcdc_core_status
                                            *param );

/* LDO block -> drv_optic_ldo_interface.h, drv_optic_ldo.c */
enum optic_errorcode ldo_enable ( struct optic_device *p_dev );
enum optic_errorcode ldo_disable ( struct optic_device *p_dev );
enum optic_errorcode ldo_status_get ( struct optic_device *p_dev,
                                      struct optic_ldo_status *param );

/* MM block -> drv_optic_mm_interface.h, drv_optic_mm.c */
enum optic_errorcode mm_cfg_set ( struct optic_device *p_dev,
				  const struct optic_mm_config *param );
enum optic_errorcode mm_cfg_get ( struct optic_device *p_dev,
                                  struct optic_mm_config *param );
enum optic_errorcode mm_die_temperature_get ( struct optic_device *p_dev,
					      struct optic_temperature
					      *param );
enum optic_errorcode mm_laser_temperature_get ( struct optic_device *p_dev,
						struct optic_temperature
						*param );
enum optic_errorcode mm_1490_optical_voltage_get ( struct optic_device *p_dev,
					           struct optic_voltage_fine
					           *param );
enum optic_errorcode mm_1490_optical_current_get ( struct optic_device *p_dev,
					           struct optic_current_fine
					           *param );
enum optic_errorcode mm_1490_optical_power_get ( struct optic_device *p_dev,
						 struct optic_power *param );
enum optic_errorcode mm_1550_optical_voltage_get ( struct optic_device *p_dev,
					           struct optic_voltage_fine
					           *param );
enum optic_errorcode mm_1550_electrical_voltage_get ( struct optic_device
						      *p_dev,
					              struct optic_voltage_fine
					              *param );

/* MPD block -> drv_optic_mpd_interface.h, drv_optic_mpd.c */
enum optic_errorcode mpd_cfg_set ( struct optic_device *p_dev,
				   const struct optic_mpd_config *param );
enum optic_errorcode mpd_cfg_get ( struct optic_device *p_dev,
			           struct optic_mpd_config *param );
enum optic_errorcode mpd_trace_get ( struct optic_device *p_dev,
			             struct optic_mpd_trace *param );

/* BERT block -> drv_optic_bert_interface.h, drv_optic_bert.c */
enum optic_errorcode bert_cfg_set ( struct optic_device *p_dev,
                                    const struct optic_bert_cfg *param );
enum optic_errorcode bert_cfg_get ( struct optic_device *p_dev,
				    struct optic_bert_cfg *param );
enum optic_errorcode bert_enable ( struct optic_device *p_dev );
enum optic_errorcode bert_disable ( struct optic_device *p_dev );
enum optic_errorcode bert_synchronize ( struct optic_device *p_dev );
enum optic_errorcode bert_status_get ( struct optic_device *p_dev,
				       struct optic_bert_status *param );
enum optic_errorcode bert_mode_set ( struct optic_device *p_dev,
                                     const struct optic_bert_mode *param );
enum optic_errorcode bert_counter_reset ( struct optic_device *p_dev );

/* OMU block -> drv_optic_omu_interface.h, drv_optic_omu.c */
enum optic_errorcode omu_init ( struct optic_control *p_ctrl );
enum optic_errorcode omu_cfg_set ( struct optic_device *p_dev,
				   const struct optic_omu_config *param );
enum optic_errorcode omu_cfg_get ( struct optic_device *p_dev,
				   struct optic_omu_config *param );
enum optic_errorcode omu_rx_enable ( struct optic_device *p_dev );
enum optic_errorcode omu_rx_disable ( struct optic_device *p_dev );
enum optic_errorcode omu_tx_enable ( struct optic_device *p_dev );
enum optic_errorcode omu_tx_disable ( struct optic_device *p_dev );
enum optic_errorcode omu_rx_status_get ( struct optic_device *p_dev,
					 struct optic_omu_rx_status_get
					 *param );
enum optic_errorcode omu_tx_status_get ( struct optic_device *p_dev,
					 struct optic_omu_tx_status_get
					 *param );

/* BOSA block -> drv_optic_bosa_interface.h, drv_optic_bosa.c */
enum optic_errorcode bosa_rx_cfg_set ( struct optic_device *p_dev,
                                       const struct optic_bosa_rx_config
                                       *param );
enum optic_errorcode bosa_rx_cfg_get ( struct optic_device
                                       *p_dev,
                                       struct optic_bosa_rx_config *param );
enum optic_errorcode bosa_tx_cfg_set ( struct optic_device *p_dev,
                                       const struct optic_bosa_tx_config
                                       *param );
enum optic_errorcode bosa_tx_cfg_get ( struct optic_device *p_dev,
                                       struct optic_bosa_tx_config *param );
enum optic_errorcode bosa_rx_enable ( struct optic_device *p_dev );
enum optic_errorcode bosa_rx_disable ( struct optic_device *p_dev );
enum optic_errorcode bosa_tx_enable ( struct optic_device *p_dev );
enum optic_errorcode bosa_tx_disable ( struct optic_device *p_dev );
enum optic_errorcode bosa_powerlevel_set ( struct optic_device *p_dev,
					   const struct optic_bosa_powerlevel
                                           *param );
enum optic_errorcode bosa_powerlevel_get ( struct optic_device *p_dev,
                                           struct optic_bosa_powerlevel
                                           *param );
enum optic_errorcode bosa_loopmode_set ( struct optic_device *p_dev,
					 const struct optic_bosa_loopmode
					 *param);
enum optic_errorcode bosa_loopmode_get ( struct optic_device *p_dev,
					 struct optic_bosa_loopmode *param);
enum optic_errorcode bosa_rx_status_get ( struct optic_device *p_dev,
                                          struct optic_bosa_rx_status *param );
enum optic_errorcode bosa_tx_status_get ( struct optic_device *p_dev,
                                          struct optic_bosa_tx_status *param );
enum optic_errorcode bosa_alarm_status_get ( struct optic_device *p_dev,
                                             struct optic_bosa_alarm *param );
enum optic_errorcode bosa_alarm_status_clear ( struct optic_device *p_dev );
enum optic_errorcode bosa_int_coeff_get ( struct optic_device *p_dev,
					  struct optic_int_coeff *param );
enum optic_errorcode bosa_stable_get ( struct optic_device *p_dev,
				       struct optic_stable *param );

/* Calibration block -> drv_optic_cal_interface.h, drv_optic_cal.c */
enum optic_errorcode cal_debug_enable ( struct optic_device *p_dev );
enum optic_errorcode cal_debug_disable ( struct optic_device *p_dev );
enum optic_errorcode cal_mm_enable ( struct optic_device *p_dev );
enum optic_errorcode cal_mm_disable ( struct optic_device *p_dev );
enum optic_errorcode cal_debug_status_get ( struct optic_device *p_dev,
					    struct optic_debug_status *param );
enum optic_errorcode cal_laser_age_get ( struct optic_device *p_dev,
					 struct optic_timestamp *param );
enum optic_errorcode cal_ibiasimod_table_set ( struct optic_device *p_dev,
					       const struct optic_ibiasimod_set
					       *param );
enum optic_errorcode cal_ibiasimod_table_get ( struct optic_device *p_dev,
					       const struct
					       optic_ibiasimod_get_in
					       *param_in,
					       struct optic_ibiasimod_get_out
					       *param_out );
enum optic_errorcode cal_laserref_table_set ( struct optic_device *p_dev,
					      const struct optic_laserref_set
					      *param );
enum optic_errorcode cal_laserref_table_get ( struct optic_device *p_dev,
					      const struct optic_laserref_get_in
					      *param_in,
					      struct optic_laserref_get_out
					      *param_out );
enum optic_errorcode cal_vapd_table_set ( struct optic_device *p_dev,
					  const struct optic_vapd_set *param );
enum optic_errorcode cal_vapd_table_get ( struct optic_device *p_dev,
					  const struct optic_vapd_get_in
					  *param_in,
					  struct optic_vapd_get_out
					  *param_out );
enum optic_errorcode cal_corr_table_set ( struct optic_device *p_dev,
					  const struct optic_corr_set *param );
enum optic_errorcode cal_corr_table_get ( struct optic_device *p_dev,
					  const struct optic_corr_get_in
					  *param_in,
					  struct optic_corr_get_out
					  *param_out );
enum optic_errorcode cal_tcorrext_table_set ( struct optic_device *p_dev,
					      const struct optic_tcorrext_set
					      *param );
enum optic_errorcode cal_tcorrext_table_get ( struct optic_device *p_dev,
				              const struct optic_tcorrext_get_in
				              *param_in,
				              struct optic_tcorrext_get_out
				              *param_out );
enum optic_errorcode cal_init_bias_current_set ( struct optic_device *p_dev,
						 const struct optic_bias
						 *param );
enum optic_errorcode cal_init_bias_current_get ( struct optic_device *p_dev,
						 struct optic_bias *param );
enum optic_errorcode cal_init_mod_current_set ( struct optic_device *p_dev,
			 		        const struct optic_mod
			 		        *param );
enum optic_errorcode cal_init_mod_current_get ( struct optic_device *p_dev,
					        struct optic_mod *param );
enum optic_errorcode cal_actual_bias_current_get ( struct optic_device *p_dev,
					           struct optic_bias *param );
enum optic_errorcode cal_actual_mod_current_get ( struct optic_device *p_dev,
						  struct optic_mod *param );
enum optic_errorcode cal_mpd_gain_set ( struct optic_device *p_dev,
					const struct optic_gain_set *param );
enum optic_errorcode cal_mpd_gain_get ( struct optic_device *p_dev,
					const struct optic_gain_get_in
					*param_in,
					struct optic_gain_get_out *param_out );
enum optic_errorcode cal_mpd_dbg_gain_set ( struct optic_device *p_dev,
					    const struct optic_dbg_gain
					    *param );
enum optic_errorcode cal_mpd_dbg_gain_get ( struct optic_device *p_dev,
					    struct optic_dbg_gain *param );
enum optic_errorcode cal_mpd_cal_current_set ( struct optic_device *p_dev,
				               const struct optic_cal_set
				               *param );
enum optic_errorcode cal_mpd_cal_current_get ( struct optic_device *p_dev,
				               const struct optic_cal_get_in
				               *param_in,
				               struct optic_cal_get_out
				               *param_out );
enum optic_errorcode cal_mpd_dbg_cal_current_set ( struct optic_device *p_dev,
					           const struct optic_dbg_cal
					           *param );
enum optic_errorcode cal_mpd_dbg_cal_current_get ( struct optic_device *p_dev,
					           struct optic_dbg_cal
					           *param );
enum optic_errorcode cal_mpd_ref_codeword_set ( struct optic_device *p_dev,
						const struct optic_refcw_set
						*param );
enum optic_errorcode cal_mpd_ref_codeword_get ( struct optic_device *p_dev,
						const struct optic_refcw_get_in
						*param_in,
						struct optic_refcw_get_out
						*param_out );
enum optic_errorcode cal_mpd_dbg_ref_codeword_set ( struct optic_device *p_dev,
 						    const struct optic_dbg_refcw
 						    *param );
enum optic_errorcode cal_mpd_dbg_ref_codeword_get ( struct optic_device *p_dev,
 						    struct optic_dbg_refcw
						    *param );
enum optic_errorcode cal_mpd_tia_offset_set ( struct optic_device *p_dev,
					      const struct optic_tia_offset_set
					      *param );
enum optic_errorcode cal_mpd_tia_offset_get ( struct optic_device *p_dev,
					      const struct optic_tia_offset_get_in
					      *param_in,
					      struct optic_tia_offset_get_out
					      *param_out );
enum optic_errorcode cal_mpd_dbg_tia_offset_set ( struct optic_device *p_dev,
                                                  const struct optic_dbg_tia_offset
						  *param );
enum optic_errorcode cal_mpd_dbg_tia_offset_get ( struct optic_device *p_dev,
 						  struct optic_dbg_tia_offset
 						  *param );
enum optic_errorcode cal_mpd_tia_offset_find ( struct optic_device *p_dev );
enum optic_errorcode cal_mpd_level_set ( struct optic_device *p_dev,
				         const struct optic_level_set *param );
enum optic_errorcode cal_mpd_level_get ( struct optic_device *p_dev,
					 const struct optic_level_get_in
					 *param_in,
					 struct optic_level_get_out
					 *param_out );
enum optic_errorcode cal_mpd_level_find ( struct optic_device *p_dev,
				          const struct optic_level_find_in
					  *param_in,
					  struct optic_level_find_out
					  *param_out );
enum optic_errorcode cal_mpd_cfratio_set ( struct optic_device *p_dev,
					   const struct optic_cfratio
					   *param );
enum optic_errorcode cal_mpd_cfratio_get ( struct optic_device *p_dev,
					   struct optic_cfratio *param );
enum optic_errorcode cal_mpd_cfratio_find ( struct optic_device *p_dev );
enum optic_errorcode cal_mpd_powersave_set ( struct optic_device *p_dev,
					     const struct optic_powersave
					     *param );
enum optic_errorcode cal_mpd_powersave_get ( struct optic_device *p_dev,
					     struct optic_powersave *param );
enum optic_errorcode cal_fcsi_predriver_set ( struct optic_device *p_dev,
					      const struct optic_fcsi_predriver
					      *param );
enum optic_errorcode cal_fcsi_predriver_get ( struct optic_device *p_dev,
					      struct optic_fcsi_predriver
					      *param );
enum optic_errorcode cal_dcdc_apd_voltage_set ( struct optic_device *p_dev,
					        const struct optic_voltage
					        *param );
enum optic_errorcode cal_dcdc_apd_voltage_get ( struct optic_device *p_dev,
					        struct optic_voltage *param );
enum optic_errorcode cal_dcdc_core_voltage_set ( struct optic_device *p_dev,
					         const struct optic_voltage
					         *param );
enum optic_errorcode cal_dcdc_core_voltage_get ( struct optic_device *p_dev,
					         struct optic_voltage *param );
enum optic_errorcode cal_dcdc_ddr_voltage_set ( struct optic_device *p_dev,
					        const struct optic_voltage
					        *param );
enum optic_errorcode cal_dcdc_ddr_voltage_get ( struct optic_device *p_dev,
					        struct optic_voltage *param );
enum optic_errorcode cal_laser_delay_set ( struct optic_device *p_dev,
					   const struct optic_laserdelay
					   *param );
enum optic_errorcode cal_laser_delay_get ( struct optic_device *p_dev,
					   struct optic_laserdelay *param );
enum optic_errorcode cal_mm_dark_corr_set ( struct optic_device *p_dev,
					    const struct optic_rssi_1490_dark
					    *param );
enum optic_errorcode cal_mm_dark_corr_get ( struct optic_device *p_dev,
					    struct optic_rssi_1490_dark
					    *param );
enum optic_errorcode cal_mm_dark_corr_find ( struct optic_device *p_dev );
enum optic_errorcode cal_fusing_get ( struct optic_device *p_dev,
				      struct optic_fusing *param );
enum optic_errorcode cal_tscalref_set( struct optic_device *p_dev,
				       const struct optic_tscalref *param );
enum optic_errorcode cal_tscalref_get( struct optic_device *p_dev,
				       struct optic_tscalref *param );
enum optic_errorcode cal_measure_rssi_1490_get ( struct optic_device *p_dev,
				                 const struct
				                 optic_measure_rssi_1490_get_in
				                 *param_in,
				                 struct
				                 optic_measure_rssi_1490_get_out
				                 *param_out );
enum optic_errorcode cal_current_offset_get( struct optic_device *p_dev,
				             struct optic_current_fine *param );
enum optic_errorcode cal_rx_offset_set ( struct optic_device *p_dev,
					 const struct optic_rx_offset *param );
enum optic_errorcode cal_rx_offset_get ( struct optic_device *p_dev,
					 struct optic_rx_offset *param );
enum optic_errorcode cal_rx_offset_find ( struct optic_device *p_dev );



/*! @} */

/*! @} */

#ifndef SWIG
EXTERN_C_END
#endif

#endif
