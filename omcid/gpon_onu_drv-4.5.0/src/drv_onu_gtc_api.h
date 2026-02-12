/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_gtc_api.h
*/
#ifndef _drv_onu_gtc_api_h
#define _drv_onu_gtc_api_h

#include "drv_onu_std_defs.h"
#include "drv_onu_gtc_interface.h"

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/
/** \defgroup ONU_GTC_INTERNAL Transmission Convergence Layer
   @{
*/
extern const struct onu_entry gtc_func_tbl[];
extern const unsigned int gtc_func_tbl_size;

enum onu_errorcode gtc_init(struct onu_device *p_dev,
			    const struct gtc_init_data *param);

enum onu_errorcode gtc_cfg_set(struct onu_device *p_dev,
			       const struct gtc_cfg *param);

enum onu_errorcode gtc_cfg_get(struct onu_device *p_dev, struct gtc_cfg *param);

enum onu_errorcode gtc_counter_threshold_set(struct onu_device *p_dev,
					     const struct gtc_cnt_value *param);

enum onu_errorcode gtc_counter_threshold_get(struct onu_device *p_dev,
					     struct gtc_cnt_value *param);

enum onu_errorcode gtc_tca_get(struct onu_device *p_dev,
			       struct gtc_cnt_value *param);

enum onu_errorcode gtc_us_header_cfg_get(struct onu_device *p_dev,
					 struct gtc_us_header_cfg *param);

enum onu_errorcode gtc_counter_get(struct onu_device *p_dev,
				   const struct gtc_cnt_interval *in,
				   struct gtc_counters *out);

enum onu_errorcode gtc_counter_reset(struct onu_device *p_dev,
				     const struct gtc_cnt_interval *param);

enum onu_errorcode gtc_status_get(struct onu_device *p_dev,
				  struct gtc_status *param);

enum onu_errorcode gtc_alarm_get(struct onu_device *p_dev,
				 struct gtc_alarm *param);

enum onu_errorcode gtc_ranging_get(struct onu_device *p_dev,
				   struct gtc_ranging_val *param);

enum onu_errorcode gtc_dying_gasp_cfg_set(struct onu_device *p_dev,
					  const struct gtc_dgasp_msg *param);

enum onu_errorcode gtc_dying_gasp_cfg_get(struct onu_device *p_dev,
					  struct gtc_dgasp_msg *param);

enum onu_errorcode gtc_no_message_cfg_set(struct onu_device *p_dev,
					  const struct gtc_no_msg_msg *param);

enum onu_errorcode gtc_no_message_cfg_get(struct onu_device *p_dev,
					  struct gtc_no_msg_msg *param);

enum onu_errorcode gtc_power_saving_mode_set(struct onu_device *p_dev,
					     const struct gtc_op_mode *param);

enum onu_errorcode gtc_power_saving_mode_get(struct onu_device *p_dev,
					     struct gtc_op_mode *param);

enum onu_errorcode gtc_ploam_send(struct onu_device *p_dev,
				  const struct gtc_ploamu *param);

enum onu_errorcode gtc_ploam_receive(struct onu_device *p_dev,
				     struct gtc_ploamd *param);

enum onu_errorcode gtc_serial_number_set(struct onu_device *p_dev,
					 const struct gtc_serial_num *param);

enum onu_errorcode gtc_serial_number_get(struct onu_device *p_dev,
					 struct gtc_serial_num *param);

enum onu_errorcode gtc_password_set(struct onu_device *p_dev,
				    const struct gtc_password *param);

enum onu_errorcode gtc_password_get(struct onu_device *p_dev,
				    struct gtc_password *param);

enum onu_errorcode gtc_forced_alloc_set(struct onu_device *p_dev,
					const struct gtc_forced_alloc *param);

enum onu_errorcode gtc_forced_alloc_get(struct onu_device *p_dev,
					struct gtc_forced_alloc *param);

enum onu_errorcode gtc_bwmt_cfg_set(struct onu_device *p_dev,
				    const struct gtc_bwmt_cfg *param);

enum onu_errorcode gtc_bwmt_cfg_get(struct onu_device *p_dev,
				    struct gtc_bwmt_cfg *param);

enum onu_errorcode gtc_bwmt_next(struct onu_device *p_dev,
				 const struct gtc_bwmt_next_data *param);

enum onu_errorcode gtc_bwmt_status_get(struct onu_device *p_dev,
				       struct gtc_bwmt_status *param);

enum onu_errorcode gtc_last_change_time_get(struct onu_device *p_dev,
					    struct gtc_last_change_time *param);

enum onu_errorcode gtc_pon_id_get(struct onu_device *p_dev,
				  struct gtc_pon_id *param);
#ifndef SWIG
/** Update Total BERR counter
*/
void gtc_total_berr_update(struct onu_control *ctrl);

/** Get Total BERR counter
*/
uint64_t gtc_total_berr_get(struct onu_control *ctrl);

enum onu_errorcode gtc_counter_update(struct onu_control *ctrl,
				      const uint64_t reset_mask,
				      const bool curr,
				      void *data);
#endif

/*! @} */

/*! @} */

EXTERN_C_END
#endif
