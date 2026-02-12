#include <sys/ioctl.h>
#include <linux/types.h>
#include "gpon_rpc_interface.h"
#include "gpon_client_rpc_interface.h"

enum onu_errorcode gtc_init(struct onu_rctx *ctx, const struct gtc_init_data *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_INIT, param, sizeof(struct gtc_init_data), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_cfg_set(struct onu_rctx *ctx, const struct gtc_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_CFG_SET, param, sizeof(struct gtc_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_cfg_get(struct onu_rctx *ctx, struct gtc_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_CFG_GET, NULL, 0, param, sizeof(struct gtc_cfg));
   return ret;
}

enum onu_errorcode gtc_counter_threshold_set(struct onu_rctx *ctx, const struct gtc_cnt_value *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_COUNTER_THRESHOLD_SET, param, sizeof(struct gtc_cnt_value), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_counter_threshold_get(struct onu_rctx *ctx, struct gtc_cnt_value *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_COUNTER_THRESHOLD_GET, NULL, 0, param, sizeof(struct gtc_cnt_value));
   return ret;
}

enum onu_errorcode gtc_tca_get(struct onu_rctx *ctx, struct gtc_cnt_value *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_TCA_GET, NULL, 0, param, sizeof(struct gtc_cnt_value));
   return ret;
}

enum onu_errorcode gtc_us_header_cfg_get(struct onu_rctx *ctx, struct gtc_us_header_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_US_HEADER_CFG_GET, NULL, 0, param, sizeof(struct gtc_us_header_cfg));
   return ret;
}

enum onu_errorcode gtc_counter_get(struct onu_rctx *ctx, const struct gtc_cnt_interval *in, struct gtc_counters *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_COUNTER_GET, in, sizeof(struct gtc_cnt_interval), out, sizeof(struct gtc_counters));
   return ret;
}

enum onu_errorcode gtc_counter_reset(struct onu_rctx *ctx, const struct gtc_cnt_interval *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_COUNTER_RESET, param, sizeof(struct gtc_cnt_interval), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_status_get(struct onu_rctx *ctx, struct gtc_status *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_STATUS_GET, NULL, 0, param, sizeof(struct gtc_status));
   return ret;
}

enum onu_errorcode gtc_alarm_get(struct onu_rctx *ctx, struct gtc_alarm *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_ALARM_GET, NULL, 0, param, sizeof(struct gtc_alarm));
   return ret;
}

enum onu_errorcode gtc_ranging_get(struct onu_rctx *ctx, struct gtc_ranging_val *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_RANGING_GET, NULL, 0, param, sizeof(struct gtc_ranging_val));
   return ret;
}

enum onu_errorcode gtc_dying_gasp_cfg_set(struct onu_rctx *ctx, const struct gtc_dgasp_msg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_DYING_GASP_CFG_SET, param, sizeof(struct gtc_dgasp_msg), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_dying_gasp_cfg_get(struct onu_rctx *ctx, struct gtc_dgasp_msg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_DYING_GASP_CFG_GET, NULL, 0, param, sizeof(struct gtc_dgasp_msg));
   return ret;
}

enum onu_errorcode gtc_no_message_cfg_set(struct onu_rctx *ctx, const struct gtc_no_msg_msg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_NO_MESSAGE_CFG_SET, param, sizeof(struct gtc_no_msg_msg), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_no_message_cfg_get(struct onu_rctx *ctx, struct gtc_no_msg_msg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_NO_MESSAGE_CFG_GET, NULL, 0, param, sizeof(struct gtc_no_msg_msg));
   return ret;
}

enum onu_errorcode gtc_power_saving_mode_set(struct onu_rctx *ctx, const struct gtc_op_mode *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_POWER_SAVING_MODE_SET, param, sizeof(struct gtc_op_mode), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_power_saving_mode_get(struct onu_rctx *ctx, struct gtc_op_mode *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_POWER_SAVING_MODE_GET, NULL, 0, param, sizeof(struct gtc_op_mode));
   return ret;
}

enum onu_errorcode gtc_ploam_send(struct onu_rctx *ctx, const struct gtc_ploamu *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_PLOAM_SEND, param, sizeof(struct gtc_ploamu), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_ploam_receive(struct onu_rctx *ctx, struct gtc_ploamd *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_PLOAM_RECEIVE, NULL, 0, param, sizeof(struct gtc_ploamd));
   return ret;
}

enum onu_errorcode gtc_serial_number_set(struct onu_rctx *ctx, const struct gtc_serial_num *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_SERIAL_NUMBER_SET, param, sizeof(struct gtc_serial_num), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_serial_number_get(struct onu_rctx *ctx, struct gtc_serial_num *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_SERIAL_NUMBER_GET, NULL, 0, param, sizeof(struct gtc_serial_num));
   return ret;
}

enum onu_errorcode gtc_password_set(struct onu_rctx *ctx, const struct gtc_password *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_PASSWORD_SET, param, sizeof(struct gtc_password), NULL, 0);
   return ret;
}

enum onu_errorcode gtc_password_get(struct onu_rctx *ctx, struct gtc_password *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_PASSWORD_GET, NULL, 0, param, sizeof(struct gtc_password));
   return ret;
}

enum onu_errorcode gtc_last_change_time_get(struct onu_rctx *ctx, struct gtc_last_change_time *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GTC_LAST_CHANGE_TIME_GET, NULL, 0, param, sizeof(struct gtc_last_change_time));
   return ret;
}

enum onu_errorcode gpe_init(struct onu_rctx *ctx, const struct gpe_init_data *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_INIT, param, sizeof(struct gpe_init_data), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_low_level_modules_enable(struct onu_rctx *ctx, const struct gpe_ll_mod_sel *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_LOW_LEVEL_MODULES_ENABLE, param, sizeof(struct gpe_ll_mod_sel), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_cfg_set(struct onu_rctx *ctx, const struct gpe_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_CFG_SET, param, sizeof(struct gpe_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_cfg_get(struct onu_rctx *ctx, struct gpe_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_CFG_GET, NULL, 0, param, sizeof(struct gpe_cfg));
   return ret;
}

enum onu_errorcode gpe_status_get(struct onu_rctx *ctx, struct gpe_status *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_STATUS_GET, NULL, 0, param, sizeof(struct gpe_status));
   return ret;
}

enum onu_errorcode gpe_gem_port_add(struct onu_rctx *ctx, const struct gpe_gem_port *in, struct gpe_gem_port *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_PORT_ADD, in, sizeof(struct gpe_gem_port), out, sizeof(struct gpe_gem_port));
   return ret;
}

enum onu_errorcode gpe_gem_port_delete(struct onu_rctx *ctx, const struct gem_port_id *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_PORT_DELETE, param, sizeof(struct gem_port_id), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_gem_port_get(struct onu_rctx *ctx, const struct gem_port_id *in, struct gpe_gem_port *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_PORT_GET, in, sizeof(struct gem_port_id), out, sizeof(struct gpe_gem_port));
   return ret;
}

enum onu_errorcode gpe_gem_port_set(struct onu_rctx *ctx, const struct gpe_gem_port *in)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_PORT_SET, in, sizeof(struct gpe_gem_port), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_tcont_set(struct onu_rctx *ctx, const struct gpe_tcont *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TCONT_SET, param, sizeof(struct gpe_tcont), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_tcont_get(struct onu_rctx *ctx, const struct tcont_index *in, struct gpe_tcont *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TCONT_GET, in, sizeof(struct tcont_index), out, sizeof(struct gpe_tcont));
   return ret;
}

enum onu_errorcode gpe_tcont_delete(struct onu_rctx *ctx, const struct tcont_index *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TCONT_DELETE, param, sizeof(struct tcont_index), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_egress_port_create(struct onu_rctx *ctx, const struct gpe_eport_create *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_PORT_CREATE, param, sizeof(struct gpe_eport_create), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_egress_port_get(struct onu_rctx *ctx, const struct gpe_epn *in, struct gpe_eport_create *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_PORT_GET, in, sizeof(struct gpe_epn), out, sizeof(struct gpe_eport_create));
   return ret;
}

enum onu_errorcode gpe_port_index_get(struct onu_rctx *ctx, const struct gpe_egress_port *in, struct gpe_eport_create *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_PORT_INDEX_GET, in, sizeof(struct gpe_egress_port), out, sizeof(struct gpe_eport_create));
   return ret;
}

enum onu_errorcode gpe_egress_port_delete(struct onu_rctx *ctx, const struct gpe_egress_port *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_PORT_DELETE, param, sizeof(struct gpe_egress_port), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_egress_port_cfg_set(struct onu_rctx *ctx, const struct gpe_egress_port_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_PORT_CFG_SET, param, sizeof(struct gpe_egress_port_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_egress_port_cfg_get(struct onu_rctx *ctx, const struct gpe_epn *in, struct gpe_egress_port_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_PORT_CFG_GET, in, sizeof(struct gpe_epn), out, sizeof(struct gpe_egress_port_cfg));
   return ret;
}

enum onu_errorcode gpe_egress_port_status_get(struct onu_rctx *ctx, const struct gpe_epn *in, struct gpe_egress_port_status *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_PORT_STATUS_GET, in, sizeof(struct gpe_epn), param, sizeof(struct gpe_egress_port_status));
   return ret;
}

enum onu_errorcode gpe_backpressure_cfg_set(struct onu_rctx *ctx, const struct gpe_backpressure_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_BACKPRESSURE_CFG_SET, param, sizeof(struct gpe_backpressure_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_backpressure_cfg_get(struct onu_rctx *ctx, struct gpe_backpressure_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_BACKPRESSURE_CFG_GET, NULL, 0, param, sizeof(struct gpe_backpressure_cfg));
   return ret;
}

enum onu_errorcode gpe_ingress_queue_cfg_set(struct onu_rctx *ctx, const struct gpe_iqueue_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_INGRESS_QUEUE_CFG_SET, param, sizeof(struct gpe_iqueue_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_ingress_queue_cfg_get(struct onu_rctx *ctx, const struct gpe_iqueue *in, struct gpe_iqueue_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_INGRESS_QUEUE_CFG_GET, in, sizeof(struct gpe_iqueue), out, sizeof(struct gpe_iqueue_cfg));
   return ret;
}

enum onu_errorcode gpe_ingress_queue_status_get(struct onu_rctx *ctx, const struct gpe_iqueue *in, struct gpe_iqueue_status *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_INGRESS_QUEUE_STATUS_GET, in, sizeof(struct gpe_iqueue), out, sizeof(struct gpe_iqueue_status));
   return ret;
}

enum onu_errorcode gpe_egress_queue_create(struct onu_rctx *ctx, const struct gpe_equeue_create *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_QUEUE_CREATE, param, sizeof(struct gpe_equeue_create), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_egress_queue_delete(struct onu_rctx *ctx, const struct gpe_equeue *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_QUEUE_DELETE, param, sizeof(struct gpe_equeue), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_egress_queue_get(struct onu_rctx *ctx, const struct gpe_equeue *in, struct gpe_equeue_create *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_QUEUE_GET, in, sizeof(struct gpe_equeue), out, sizeof(struct gpe_equeue_create));
   return ret;
}

enum onu_errorcode gpe_egress_queue_cfg_set(struct onu_rctx *ctx, const struct gpe_equeue_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_QUEUE_CFG_SET, param, sizeof(struct gpe_equeue_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_egress_queue_cfg_get(struct onu_rctx *ctx, const struct gpe_equeue *in, struct gpe_equeue_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_QUEUE_CFG_GET, in, sizeof(struct gpe_equeue), out, sizeof(struct gpe_equeue_cfg));
   return ret;
}

enum onu_errorcode gpe_egress_queue_status_get(struct onu_rctx *ctx, const struct gpe_equeue *in, struct gpe_equeue_status *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_QUEUE_STATUS_GET, in, sizeof(struct gpe_equeue), out, sizeof(struct gpe_equeue_status));
   return ret;
}

enum onu_errorcode gpe_egress_queue_path_get(struct onu_rctx *ctx, const struct gpe_equeue *in)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EGRESS_QUEUE_PATH_GET, in, sizeof(struct gpe_equeue), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_scheduler_create(struct onu_rctx *ctx, const struct gpe_sched_create *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_SCHEDULER_CREATE, param, sizeof(struct gpe_sched_create), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_scheduler_delete(struct onu_rctx *ctx, const struct gpe_scheduler_idx *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_SCHEDULER_DELETE, param, sizeof(struct gpe_scheduler_idx), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_scheduler_get(struct onu_rctx *ctx, const struct gpe_scheduler_idx *in, struct gpe_sched_create *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_SCHEDULER_GET, in, sizeof(struct gpe_scheduler_idx), out, sizeof(struct gpe_sched_create));
   return ret;
}

enum onu_errorcode gpe_scheduler_cfg_set(struct onu_rctx *ctx, const struct gpe_scheduler_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_SCHEDULER_CFG_SET, param, sizeof(struct gpe_scheduler_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_scheduler_cfg_get(struct onu_rctx *ctx, const struct gpe_scheduler_idx *in, struct gpe_scheduler_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_SCHEDULER_CFG_GET, in, sizeof(struct gpe_scheduler_idx), out, sizeof(struct gpe_scheduler_cfg));
   return ret;
}

enum onu_errorcode gpe_scheduler_status_get(struct onu_rctx *ctx, const struct gpe_scheduler_idx *in, struct gpe_scheduler_status *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_SCHEDULER_STATUS_GET, in, sizeof(struct gpe_scheduler_idx), out, sizeof(struct gpe_scheduler_status));
   return ret;
}

enum onu_errorcode gpe_token_bucket_shaper_create(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOKEN_BUCKET_SHAPER_CREATE, param, sizeof(struct gpe_token_bucket_shaper), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_token_bucket_shaper_delete(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOKEN_BUCKET_SHAPER_DELETE, param, sizeof(struct gpe_token_bucket_shaper), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_token_bucket_shaper_get(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper_idx *in, struct gpe_token_bucket_shaper *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOKEN_BUCKET_SHAPER_GET, in, sizeof(struct gpe_token_bucket_shaper_idx), out, sizeof(struct gpe_token_bucket_shaper));
   return ret;
}

enum onu_errorcode gpe_token_bucket_shaper_cfg_set(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_SET, param, sizeof(struct gpe_token_bucket_shaper_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_token_bucket_shaper_cfg_get(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper_idx *in, struct gpe_token_bucket_shaper_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_GET, in, sizeof(struct gpe_token_bucket_shaper_idx), out, sizeof(struct gpe_token_bucket_shaper_cfg));
   return ret;
}

enum onu_errorcode gpe_token_bucket_shaper_status_get(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper_idx *in, struct gpe_token_bucket_shaper_status *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOKEN_BUCKET_SHAPER_STATUS_GET, in, sizeof(struct gpe_token_bucket_shaper_idx), out, sizeof(struct gpe_token_bucket_shaper_status));
   return ret;
}

enum onu_errorcode gpe_meter_cfg_set(struct onu_rctx *ctx, const struct gpe_meter_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_METER_CFG_SET, param, sizeof(struct gpe_meter_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_meter_cfg_get(struct onu_rctx *ctx, const struct gpe_meter *in, struct gpe_meter_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_METER_CFG_GET, in, sizeof(struct gpe_meter), out, sizeof(struct gpe_meter_cfg));
   return ret;
}

enum onu_errorcode gpe_meter_status_get(struct onu_rctx *ctx, const struct gpe_meter *in, struct gpe_meter_status *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_METER_STATUS_GET, in, sizeof(struct gpe_meter), out, sizeof(struct gpe_meter_status));
   return ret;
}

enum onu_errorcode gpe_shared_buffer_cfg_set(struct onu_rctx *ctx, const struct gpe_shared_buffer_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_SHARED_BUFFER_CFG_SET, param, sizeof(struct gpe_shared_buffer_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_shared_buffer_cfg_get(struct onu_rctx *ctx, struct gpe_shared_buffer_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_SHARED_BUFFER_CFG_GET, NULL, 0, out, sizeof(struct gpe_shared_buffer_cfg));
   return ret;
}

enum onu_errorcode gpe_bridge_counter_get(struct onu_rctx *ctx, const struct gpe_bridge_cnt_interval *in, struct gpe_bridge_counter *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_BRIDGE_COUNTER_GET, in, sizeof(struct gpe_bridge_cnt_interval), out, sizeof(struct gpe_bridge_counter));
   return ret;
}

enum onu_errorcode gpe_bridge_counter_threshold_set(struct onu_rctx *ctx, const struct gpe_cnt_bridge_threshold *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_BRIDGE_COUNTER_THRESHOLD_SET, param, sizeof(struct gpe_cnt_bridge_threshold), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_bridge_counter_threshold_get(struct onu_rctx *ctx, const struct gpe_bridge *in, struct gpe_cnt_bridge_threshold *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_BRIDGE_COUNTER_THRESHOLD_GET, in, sizeof(struct gpe_bridge), out, sizeof(struct gpe_cnt_bridge_threshold));
   return ret;
}

enum onu_errorcode gpe_bridge_tca_get(struct onu_rctx *ctx, const struct gpe_bridge *in, struct gpe_cnt_bridge_threshold *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_BRIDGE_TCA_GET, in, sizeof(struct gpe_bridge), out, sizeof(struct gpe_cnt_bridge_threshold));
   return ret;
}

enum onu_errorcode gpe_bridge_counter_reset(struct onu_rctx *ctx, const struct gpe_bridge_cnt_interval *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_BRIDGE_COUNTER_RESET, param, sizeof(struct gpe_bridge_cnt_interval), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_parser_cfg_set(struct onu_rctx *ctx, const struct gpe_parser_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_PARSER_CFG_SET, param, sizeof(struct gpe_parser_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_parser_cfg_get(struct onu_rctx *ctx, struct gpe_parser_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_PARSER_CFG_GET, NULL, 0, out, sizeof(struct gpe_parser_cfg));
   return ret;
}

enum onu_errorcode gpe_omci_send(struct onu_rctx *ctx, const struct gpe_omci_msg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_OMCI_SEND, param, sizeof(struct gpe_omci_msg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_tod_init(struct onu_rctx *ctx, const struct gpe_tod_init_data *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOD_INIT, param, sizeof(struct gpe_tod_init_data), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_tod_sync_set(struct onu_rctx *ctx, const struct gpe_tod_sync *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOD_SYNC_SET, param, sizeof(struct gpe_tod_sync), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_tod_get(struct onu_rctx *ctx, struct gpe_tod *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOD_GET, NULL, 0, param, sizeof(struct gpe_tod));
   return ret;
}

enum onu_errorcode gpe_tod_sync_get(struct onu_rctx *ctx, struct gpe_tod_sync *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TOD_SYNC_GET, NULL, 0, param, sizeof(struct gpe_tod_sync));
   return ret;
}

enum onu_errorcode gpe_iqm_global_cfg_set(struct onu_rctx *ctx, const struct gpe_iqm_global_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_IQM_GLOBAL_CFG_SET, param, sizeof(struct gpe_iqm_global_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_iqm_global_cfg_get(struct onu_rctx *ctx, struct gpe_iqm_global_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_IQM_GLOBAL_CFG_GET, NULL, 0, param, sizeof(struct gpe_iqm_global_cfg));
   return ret;
}

enum onu_errorcode gpe_iqm_global_status_get(struct onu_rctx *ctx, struct gpe_iqm_global_status *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_IQM_GLOBAL_STATUS_GET, NULL, 0, param, sizeof(struct gpe_iqm_global_status));
   return ret;
}

enum onu_errorcode gpe_tmu_global_cfg_get(struct onu_rctx *ctx, struct gpe_tmu_global_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TMU_GLOBAL_CFG_GET, NULL, 0, param, sizeof(struct gpe_tmu_global_cfg));
   return ret;
}

enum onu_errorcode gpe_tmu_global_status_get(struct onu_rctx *ctx, struct gpe_tmu_global_status *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_TMU_GLOBAL_STATUS_GET, NULL, 0, param, sizeof(struct gpe_tmu_global_status));
   return ret;
}

enum onu_errorcode gpe_gem_counter_get(struct onu_rctx *ctx, const struct gpe_gem_cnt_interval *in, struct gpe_gem_counter *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_COUNTER_GET, in, sizeof(struct gpe_gem_cnt_interval), out, sizeof(struct gpe_gem_counter));
   return ret;
}

enum onu_errorcode gpe_gem_counter_threshold_set(struct onu_rctx *ctx, const struct gpe_cnt_gem_threshold *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_COUNTER_THRESHOLD_SET, param, sizeof(struct gpe_cnt_gem_threshold), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_gem_counter_threshold_get(struct onu_rctx *ctx, const struct gem_port_index *in, struct gpe_cnt_gem_val *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_COUNTER_THRESHOLD_GET, in, sizeof(struct gem_port_index), out, sizeof(struct gpe_cnt_gem_val));
   return ret;
}

enum onu_errorcode gpe_gem_tca_get(struct onu_rctx *ctx, const struct gem_port_index *in, struct gpe_gem_tca_val *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_TCA_GET, in, sizeof(struct gem_port_index), out, sizeof(struct gpe_gem_tca_val));
   return ret;
}

enum onu_errorcode gpe_gem_counter_reset(struct onu_rctx *ctx, const struct gpe_gem_cnt_interval *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_GEM_COUNTER_RESET, param, sizeof(struct gpe_gem_cnt_interval), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_flat_egress_path_create(struct onu_rctx *ctx, const struct gpe_flat_egress_path *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_FLAT_EGRESS_PATH_CREATE, param, sizeof(struct gpe_flat_egress_path), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_cop_download(struct onu_rctx *ctx, const struct cop_download_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_COP_DOWNLOAD, param, sizeof(struct cop_download_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_lan_exception_cfg_set(struct onu_rctx *ctx, const struct gpe_lan_exception_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_LAN_EXCEPTION_CFG_SET, param, sizeof(struct gpe_lan_exception_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_lan_exception_cfg_get(struct onu_rctx *ctx, const struct gpe_lan_exception_idx *in, struct gpe_lan_exception_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_LAN_EXCEPTION_CFG_GET, in, sizeof(struct gpe_lan_exception_idx), out, sizeof(struct gpe_lan_exception_cfg));
   return ret;
}

enum onu_errorcode gpe_ani_exception_cfg_set(struct onu_rctx *ctx, const struct gpe_ani_exception_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_ANI_EXCEPTION_CFG_SET, param, sizeof(struct gpe_ani_exception_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_ani_exception_cfg_get(struct onu_rctx *ctx, const struct gpe_ani_exception_idx *in, struct gpe_ani_exception_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_ANI_EXCEPTION_CFG_GET, in, sizeof(struct gpe_ani_exception_idx), out, sizeof(struct gpe_ani_exception_cfg));
   return ret;
}

enum onu_errorcode gpe_exception_queue_cfg_set(struct onu_rctx *ctx, const struct gpe_exception_queue_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EXCEPTION_QUEUE_CFG_SET, param, sizeof(struct gpe_exception_queue_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode gpe_exception_queue_cfg_get(struct onu_rctx *ctx, const struct gpe_exception_queue_idx *in, struct gpe_exception_queue_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_EXCEPTION_QUEUE_CFG_GET, in, sizeof(struct gpe_exception_queue_idx), out, sizeof(struct gpe_exception_queue_cfg));
   return ret;
}

enum onu_errorcode gpe_capability_get(struct onu_rctx *ctx, struct gpe_capability *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_GPE_CAPABILITY_GET, NULL, 0, param, sizeof(struct gpe_capability));
   return ret;
}

enum onu_errorcode lan_gphy_firmware_download(struct onu_rctx *ctx, const struct lan_gphy_fw *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_GPHY_FIRMWARE_DOWNLOAD, param, sizeof(struct lan_gphy_fw), NULL, 0);
   return ret;
}

enum onu_errorcode lan_init(struct onu_rctx *ctx)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_INIT, NULL, 0, NULL, 0);
   return ret;
}

enum onu_errorcode lan_cfg_set(struct onu_rctx *ctx, const struct lan_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_CFG_SET, param, sizeof(struct lan_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode lan_cfg_get(struct onu_rctx *ctx, struct lan_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_CFG_GET, NULL, 0, param, sizeof(struct lan_cfg));
   return ret;
}

enum onu_errorcode lan_port_cfg_set(struct onu_rctx *ctx, const struct lan_port_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_PORT_CFG_SET, param, sizeof(struct lan_port_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode lan_port_cfg_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct lan_port_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_PORT_CFG_GET, in, sizeof(struct lan_port_index), out, sizeof(struct lan_port_cfg));
   return ret;
}

enum onu_errorcode lan_port_enable(struct onu_rctx *ctx, const struct lan_port_index *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_PORT_ENABLE, param, sizeof(struct lan_port_index), NULL, 0);
   return ret;
}

enum onu_errorcode lan_port_disable(struct onu_rctx *ctx, const struct lan_port_index *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_PORT_DISABLE, param, sizeof(struct lan_port_index), NULL, 0);
   return ret;
}

enum onu_errorcode lan_loop_cfg_set(struct onu_rctx *ctx, const struct lan_loop_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_LOOP_CFG_SET, param, sizeof(struct lan_loop_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode lan_loop_cfg_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct lan_loop_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_LOOP_CFG_GET, in, sizeof(struct lan_port_index), out, sizeof(struct lan_loop_cfg));
   return ret;
}

enum onu_errorcode lan_port_status_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct lan_port_status *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_PORT_STATUS_GET, in, sizeof(struct lan_port_index), out, sizeof(struct lan_port_status));
   return ret;
}

enum onu_errorcode lan_counter_get(struct onu_rctx *ctx, const struct lan_cnt_interval *in, struct lan_counters *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_COUNTER_GET, in, sizeof(struct lan_cnt_interval), out, sizeof(struct lan_counters));
   return ret;
}

enum onu_errorcode lan_counter_reset(struct onu_rctx *ctx, const struct lan_cnt_interval *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_COUNTER_RESET, param, sizeof(struct lan_cnt_interval), NULL, 0);
   return ret;
}

enum onu_errorcode lan_counter_threshold_set(struct onu_rctx *ctx, const struct lan_cnt_threshold *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_COUNTER_THRESHOLD_SET, param, sizeof(struct lan_cnt_threshold), NULL, 0);
   return ret;
}

enum onu_errorcode lan_counter_threshold_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct lan_cnt_threshold *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_COUNTER_THRESHOLD_GET, in, sizeof(struct lan_port_index), out, sizeof(struct lan_cnt_threshold));
   return ret;
}

enum onu_errorcode lan_tca_get(struct onu_rctx *ctx, const struct uni_port_id *in, struct lan_cnt_val *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_LAN_TCA_GET, in, sizeof(struct uni_port_id), out, sizeof(struct lan_cnt_val));
   return ret;
}

enum onu_errorcode wol_cfg_set(struct onu_rctx *ctx, const struct wol_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_WOL_CFG_SET, param, sizeof(struct wol_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode wol_cfg_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct wol_cfg *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_WOL_CFG_GET, in, sizeof(struct lan_port_index), out, sizeof(struct wol_cfg));
   return ret;
}

enum onu_errorcode wol_status_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct wol_status *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_WOL_STATUS_GET, in, sizeof(struct lan_port_index), out, sizeof(struct wol_status));
   return ret;
}

enum onu_errorcode mdio_data_read(struct onu_rctx *ctx, const struct mdio *in, struct mdio_read *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_MDIO_DATA_READ, in, sizeof(struct mdio), out, sizeof(struct mdio_read));
   return ret;
}

enum onu_errorcode mdio_data_write(struct onu_rctx *ctx, const struct mdio_write *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_MDIO_DATA_WRITE, param, sizeof(struct mdio_write), NULL, 0);
   return ret;
}

enum onu_errorcode mdio_enable(struct onu_rctx *ctx, const struct mdio_en *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_MDIO_ENABLE, param, sizeof(struct mdio_en), NULL, 0);
   return ret;
}

enum onu_errorcode mdio_disable(struct onu_rctx *ctx, const struct mdio_dis *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_MDIO_DISABLE, param, sizeof(struct mdio_dis), NULL, 0);
   return ret;
}

enum onu_errorcode mmd_data_read(struct onu_rctx *ctx, const struct mmd *in, struct mmd_read *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_MMD_DATA_READ, in, sizeof(struct mmd), out, sizeof(struct mmd_read));
   return ret;
}

enum onu_errorcode mmd_data_write(struct onu_rctx *ctx, const struct mmd_write *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_MMD_DATA_WRITE, param, sizeof(struct mmd_write), NULL, 0);
   return ret;
}

enum onu_errorcode onu_debug_level_set(struct onu_rctx *ctx, const struct onu_dbg_level *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_DEBUG_LEVEL_SET, param, sizeof(struct onu_dbg_level), NULL, 0);
   return ret;
}

enum onu_errorcode onu_debug_level_get(struct onu_rctx *ctx, struct onu_dbg_level *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_DEBUG_LEVEL_GET, NULL, 0, param, sizeof(struct onu_dbg_level));
   return ret;
}

enum onu_errorcode onu_version_get(struct onu_rctx *ctx, struct onu_version_string *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_VERSION_GET, NULL, 0, param, sizeof(struct onu_version_string));
   return ret;
}

enum onu_errorcode onu_register_set(struct onu_rctx *ctx, const struct onu_reg_addr_val *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_REGISTER_SET, param, sizeof(struct onu_reg_addr_val), NULL, 0);
   return ret;
}

enum onu_errorcode onu_register_get(struct onu_rctx *ctx, const struct onu_reg_addr *in, struct onu_reg_val *out)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_REGISTER_GET, in, sizeof(struct onu_reg_addr), out, sizeof(struct onu_reg_val));
   return ret;
}

enum onu_errorcode onu_test_mode_set(struct onu_rctx *ctx, const struct onu_test_mode *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_TEST_MODE_SET, param, sizeof(struct onu_test_mode), NULL, 0);
   return ret;
}

enum onu_errorcode onu_line_enable_set(struct onu_rctx *ctx, const struct onu_enable *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_LINE_ENABLE_SET, param, sizeof(struct onu_enable), NULL, 0);
   return ret;
}

enum onu_errorcode onu_line_enable_get(struct onu_rctx *ctx, struct onu_enable *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_LINE_ENABLE_GET, NULL, 0, param, sizeof(struct onu_enable));
   return ret;
}

enum onu_errorcode onu_sync_time_set(struct onu_rctx *ctx, const struct onu_sync_time *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_SYNC_TIME_SET, param, sizeof(struct onu_sync_time), NULL, 0);
   return ret;
}

enum onu_errorcode onu_sync_time_get(struct onu_rctx *ctx, struct onu_sync_time *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_SYNC_TIME_GET, NULL, 0, param, sizeof(struct onu_sync_time));
   return ret;
}

enum onu_errorcode onu_counters_cfg_set(struct onu_rctx *ctx, const struct onu_cnt_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_COUNTERS_CFG_SET, param, sizeof(struct onu_cnt_cfg), NULL, 0);
   return ret;
}

enum onu_errorcode onu_counters_cfg_get(struct onu_rctx *ctx, struct onu_cnt_cfg *param)
{
   int ret;
   ret = dti_client_ioctl_execute(&ctx->dti, FIO_ONU_COUNTERS_CFG_GET, NULL, 0, param, sizeof(struct onu_cnt_cfg));
   return ret;
}
