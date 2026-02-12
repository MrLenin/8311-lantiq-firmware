#ifndef _gpon_onu_rpc_interface_h
#define _gpon_onu_rpc_interface_h

#include "drv_onu_resource.h"
#include "drv_onu_error.h"
#include "drv_onu_types.h"
#include "drv_onu_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_common_interface.h"

enum onu_errorcode gtc_init(struct onu_rctx *ctx, const struct gtc_init_data *param);
enum onu_errorcode gtc_cfg_set(struct onu_rctx *ctx, const struct gtc_cfg *param);
enum onu_errorcode gtc_cfg_get(struct onu_rctx *ctx, struct gtc_cfg *param);
enum onu_errorcode gtc_counter_threshold_set(struct onu_rctx *ctx, const struct gtc_cnt_value *param);
enum onu_errorcode gtc_counter_threshold_get(struct onu_rctx *ctx, struct gtc_cnt_value *param);
enum onu_errorcode gtc_tca_get(struct onu_rctx *ctx, struct gtc_cnt_value *param);
enum onu_errorcode gtc_us_header_cfg_get(struct onu_rctx *ctx, struct gtc_us_header_cfg *param);
enum onu_errorcode gtc_counter_get(struct onu_rctx *ctx, const struct gtc_cnt_interval *in, struct gtc_counters *out);
enum onu_errorcode gtc_counter_reset(struct onu_rctx *ctx, const struct gtc_cnt_interval *param);
enum onu_errorcode gtc_status_get(struct onu_rctx *ctx, struct gtc_status *param);
enum onu_errorcode gtc_alarm_get(struct onu_rctx *ctx, struct gtc_alarm *param);
enum onu_errorcode gtc_ranging_get(struct onu_rctx *ctx, struct gtc_ranging_val *param);
enum onu_errorcode gtc_dying_gasp_cfg_set(struct onu_rctx *ctx, const struct gtc_dgasp_msg *param);
enum onu_errorcode gtc_dying_gasp_cfg_get(struct onu_rctx *ctx, struct gtc_dgasp_msg *param);
enum onu_errorcode gtc_no_message_cfg_set(struct onu_rctx *ctx, const struct gtc_no_msg_msg *param);
enum onu_errorcode gtc_no_message_cfg_get(struct onu_rctx *ctx, struct gtc_no_msg_msg *param);
enum onu_errorcode gtc_power_saving_mode_set(struct onu_rctx *ctx, const struct gtc_op_mode *param);
enum onu_errorcode gtc_power_saving_mode_get(struct onu_rctx *ctx, struct gtc_op_mode *param);
enum onu_errorcode gtc_ploam_send(struct onu_rctx *ctx, const struct gtc_ploamu *param);
enum onu_errorcode gtc_ploam_receive(struct onu_rctx *ctx, struct gtc_ploamd *param);
enum onu_errorcode gtc_serial_number_set(struct onu_rctx *ctx, const struct gtc_serial_num *param);
enum onu_errorcode gtc_serial_number_get(struct onu_rctx *ctx, struct gtc_serial_num *param);
enum onu_errorcode gtc_password_set(struct onu_rctx *ctx, const struct gtc_password *param);
enum onu_errorcode gtc_password_get(struct onu_rctx *ctx, struct gtc_password *param);
enum onu_errorcode gtc_last_change_time_get(struct onu_rctx *ctx, struct gtc_last_change_time *param);
enum onu_errorcode gpe_init(struct onu_rctx *ctx, const struct gpe_init_data *param);
enum onu_errorcode gpe_low_level_modules_enable(struct onu_rctx *ctx, const struct gpe_ll_mod_sel *param);
enum onu_errorcode gpe_cfg_set(struct onu_rctx *ctx, const struct gpe_cfg *param);
enum onu_errorcode gpe_cfg_get(struct onu_rctx *ctx, struct gpe_cfg *param);
enum onu_errorcode gpe_status_get(struct onu_rctx *ctx, struct gpe_status *param);
enum onu_errorcode gpe_gem_port_add(struct onu_rctx *ctx, const struct gpe_gem_port *in, struct gpe_gem_port *out);
enum onu_errorcode gpe_gem_port_delete(struct onu_rctx *ctx, const struct gem_port_id *param);
enum onu_errorcode gpe_gem_port_get(struct onu_rctx *ctx, const struct gem_port_id *in, struct gpe_gem_port *out);
enum onu_errorcode gpe_gem_port_set(struct onu_rctx *ctx, const struct gpe_gem_port *in);
enum onu_errorcode gpe_tcont_set(struct onu_rctx *ctx, const struct gpe_tcont *param);
enum onu_errorcode gpe_tcont_get(struct onu_rctx *ctx, const struct tcont_index *in, struct gpe_tcont *out);
enum onu_errorcode gpe_tcont_delete(struct onu_rctx *ctx, const struct tcont_index *param);
enum onu_errorcode gpe_egress_port_create(struct onu_rctx *ctx, const struct gpe_eport_create *param);
enum onu_errorcode gpe_egress_port_get(struct onu_rctx *ctx, const struct gpe_epn *in, struct gpe_eport_create *out);
enum onu_errorcode gpe_port_index_get(struct onu_rctx *ctx, const struct gpe_egress_port *in, struct gpe_eport_create *out);
enum onu_errorcode gpe_egress_port_delete(struct onu_rctx *ctx, const struct gpe_egress_port *param);
enum onu_errorcode gpe_egress_port_cfg_set(struct onu_rctx *ctx, const struct gpe_egress_port_cfg *param);
enum onu_errorcode gpe_egress_port_cfg_get(struct onu_rctx *ctx, const struct gpe_epn *in, struct gpe_egress_port_cfg *out);
enum onu_errorcode gpe_egress_port_status_get(struct onu_rctx *ctx, const struct gpe_epn *in, struct gpe_egress_port_status *param);
enum onu_errorcode gpe_backpressure_cfg_set(struct onu_rctx *ctx, const struct gpe_backpressure_cfg *param);
enum onu_errorcode gpe_backpressure_cfg_get(struct onu_rctx *ctx, struct gpe_backpressure_cfg *param);
enum onu_errorcode gpe_ingress_queue_cfg_set(struct onu_rctx *ctx, const struct gpe_iqueue_cfg *param);
enum onu_errorcode gpe_ingress_queue_cfg_get(struct onu_rctx *ctx, const struct gpe_iqueue *in, struct gpe_iqueue_cfg *out);
enum onu_errorcode gpe_ingress_queue_status_get(struct onu_rctx *ctx, const struct gpe_iqueue *in, struct gpe_iqueue_status *out);
enum onu_errorcode gpe_egress_queue_create(struct onu_rctx *ctx, const struct gpe_equeue_create *param);
enum onu_errorcode gpe_egress_queue_delete(struct onu_rctx *ctx, const struct gpe_equeue *param);
enum onu_errorcode gpe_egress_queue_get(struct onu_rctx *ctx, const struct gpe_equeue *in, struct gpe_equeue_create *out);
enum onu_errorcode gpe_egress_queue_cfg_set(struct onu_rctx *ctx, const struct gpe_equeue_cfg *param);
enum onu_errorcode gpe_egress_queue_cfg_get(struct onu_rctx *ctx, const struct gpe_equeue *in, struct gpe_equeue_cfg *out);
enum onu_errorcode gpe_egress_queue_status_get(struct onu_rctx *ctx, const struct gpe_equeue *in, struct gpe_equeue_status *out);
enum onu_errorcode gpe_egress_queue_path_get(struct onu_rctx *ctx, const struct gpe_equeue *in);
enum onu_errorcode gpe_scheduler_create(struct onu_rctx *ctx, const struct gpe_sched_create *param);
enum onu_errorcode gpe_scheduler_delete(struct onu_rctx *ctx, const struct gpe_scheduler_idx *param);
enum onu_errorcode gpe_scheduler_get(struct onu_rctx *ctx, const struct gpe_scheduler_idx *in, struct gpe_sched_create *out);
enum onu_errorcode gpe_scheduler_cfg_set(struct onu_rctx *ctx, const struct gpe_scheduler_cfg *param);
enum onu_errorcode gpe_scheduler_cfg_get(struct onu_rctx *ctx, const struct gpe_scheduler_idx *in, struct gpe_scheduler_cfg *out);
enum onu_errorcode gpe_scheduler_status_get(struct onu_rctx *ctx, const struct gpe_scheduler_idx *in, struct gpe_scheduler_status *out);
enum onu_errorcode gpe_token_bucket_shaper_create(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper *param);
enum onu_errorcode gpe_token_bucket_shaper_delete(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper *param);
enum onu_errorcode gpe_token_bucket_shaper_get(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper_idx *in, struct gpe_token_bucket_shaper *out);
enum onu_errorcode gpe_token_bucket_shaper_cfg_set(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper_cfg *param);
enum onu_errorcode gpe_token_bucket_shaper_cfg_get(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper_idx *in, struct gpe_token_bucket_shaper_cfg *out);
enum onu_errorcode gpe_token_bucket_shaper_status_get(struct onu_rctx *ctx, const struct gpe_token_bucket_shaper_idx *in, struct gpe_token_bucket_shaper_status *out);
enum onu_errorcode gpe_meter_cfg_set(struct onu_rctx *ctx, const struct gpe_meter_cfg *param);
enum onu_errorcode gpe_meter_cfg_get(struct onu_rctx *ctx, const struct gpe_meter *in, struct gpe_meter_cfg *out);
enum onu_errorcode gpe_meter_status_get(struct onu_rctx *ctx, const struct gpe_meter *in, struct gpe_meter_status *out);
enum onu_errorcode gpe_shared_buffer_cfg_set(struct onu_rctx *ctx, const struct gpe_shared_buffer_cfg *param);
enum onu_errorcode gpe_shared_buffer_cfg_get(struct onu_rctx *ctx, struct gpe_shared_buffer_cfg *out);
enum onu_errorcode gpe_bridge_counter_get(struct onu_rctx *ctx, const struct gpe_bridge_cnt_interval *in, struct gpe_bridge_counter *out);
enum onu_errorcode gpe_bridge_counter_threshold_set(struct onu_rctx *ctx, const struct gpe_cnt_bridge_threshold *param);
enum onu_errorcode gpe_bridge_counter_threshold_get(struct onu_rctx *ctx, const struct gpe_bridge *in, struct gpe_cnt_bridge_threshold *out);
enum onu_errorcode gpe_bridge_tca_get(struct onu_rctx *ctx, const struct gpe_bridge *in, struct gpe_cnt_bridge_threshold *out);
enum onu_errorcode gpe_bridge_counter_reset(struct onu_rctx *ctx, const struct gpe_bridge_cnt_interval *param);
enum onu_errorcode gpe_parser_cfg_set(struct onu_rctx *ctx, const struct gpe_parser_cfg *param);
enum onu_errorcode gpe_parser_cfg_get(struct onu_rctx *ctx, struct gpe_parser_cfg *out);
enum onu_errorcode gpe_omci_send(struct onu_rctx *ctx, const struct gpe_omci_msg *param);
enum onu_errorcode gpe_tod_init(struct onu_rctx *ctx, const struct gpe_tod_init_data *param);
enum onu_errorcode gpe_tod_sync_set(struct onu_rctx *ctx, const struct gpe_tod_sync *param);
enum onu_errorcode gpe_tod_get(struct onu_rctx *ctx, struct gpe_tod *param);
enum onu_errorcode gpe_tod_sync_get(struct onu_rctx *ctx, struct gpe_tod_sync *param);
enum onu_errorcode gpe_iqm_global_cfg_set(struct onu_rctx *ctx, const struct gpe_iqm_global_cfg *param);
enum onu_errorcode gpe_iqm_global_cfg_get(struct onu_rctx *ctx, struct gpe_iqm_global_cfg *param);
enum onu_errorcode gpe_iqm_global_status_get(struct onu_rctx *ctx, struct gpe_iqm_global_status *param);
enum onu_errorcode gpe_tmu_global_cfg_get(struct onu_rctx *ctx, struct gpe_tmu_global_cfg *param);
enum onu_errorcode gpe_tmu_global_status_get(struct onu_rctx *ctx, struct gpe_tmu_global_status *param);
enum onu_errorcode gpe_gem_counter_get(struct onu_rctx *ctx, const struct gpe_gem_cnt_interval *in, struct gpe_gem_counter *out);
enum onu_errorcode gpe_gem_counter_threshold_set(struct onu_rctx *ctx, const struct gpe_cnt_gem_threshold *param);
enum onu_errorcode gpe_gem_counter_threshold_get(struct onu_rctx *ctx, const struct gem_port_index *in, struct gpe_cnt_gem_val *out);
enum onu_errorcode gpe_gem_tca_get(struct onu_rctx *ctx, const struct gem_port_index *in, struct gpe_gem_tca_val *out);
enum onu_errorcode gpe_gem_counter_reset(struct onu_rctx *ctx, const struct gpe_gem_cnt_interval *param);
enum onu_errorcode gpe_flat_egress_path_create(struct onu_rctx *ctx, const struct gpe_flat_egress_path *param);
enum onu_errorcode gpe_cop_download(struct onu_rctx *ctx, const struct cop_download_cfg *param);
enum onu_errorcode gpe_lan_exception_cfg_set(struct onu_rctx *ctx, const struct gpe_lan_exception_cfg *param);
enum onu_errorcode gpe_lan_exception_cfg_get(struct onu_rctx *ctx, const struct gpe_lan_exception_idx *in, struct gpe_lan_exception_cfg *out);
enum onu_errorcode gpe_ani_exception_cfg_set(struct onu_rctx *ctx, const struct gpe_ani_exception_cfg *param);
enum onu_errorcode gpe_ani_exception_cfg_get(struct onu_rctx *ctx, const struct gpe_ani_exception_idx *in, struct gpe_ani_exception_cfg *out);
enum onu_errorcode gpe_exception_queue_cfg_set(struct onu_rctx *ctx, const struct gpe_exception_queue_cfg *param);
enum onu_errorcode gpe_exception_queue_cfg_get(struct onu_rctx *ctx, const struct gpe_exception_queue_idx *in, struct gpe_exception_queue_cfg *out);
enum onu_errorcode gpe_capability_get(struct onu_rctx *ctx, struct gpe_capability *param);
enum onu_errorcode lan_gphy_firmware_download(struct onu_rctx *ctx, const struct lan_gphy_fw *param);
enum onu_errorcode lan_init(struct onu_rctx *ctx);
enum onu_errorcode lan_cfg_set(struct onu_rctx *ctx, const struct lan_cfg *param);
enum onu_errorcode lan_cfg_get(struct onu_rctx *ctx, struct lan_cfg *param);
enum onu_errorcode lan_port_cfg_set(struct onu_rctx *ctx, const struct lan_port_cfg *param);
enum onu_errorcode lan_port_cfg_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct lan_port_cfg *out);
enum onu_errorcode lan_port_enable(struct onu_rctx *ctx, const struct lan_port_index *param);
enum onu_errorcode lan_port_disable(struct onu_rctx *ctx, const struct lan_port_index *param);
enum onu_errorcode lan_loop_cfg_set(struct onu_rctx *ctx, const struct lan_loop_cfg *param);
enum onu_errorcode lan_loop_cfg_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct lan_loop_cfg *out);
enum onu_errorcode lan_port_status_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct lan_port_status *out);
enum onu_errorcode lan_counter_get(struct onu_rctx *ctx, const struct lan_cnt_interval *in, struct lan_counters *out);
enum onu_errorcode lan_counter_reset(struct onu_rctx *ctx, const struct lan_cnt_interval *param);
enum onu_errorcode lan_counter_threshold_set(struct onu_rctx *ctx, const struct lan_cnt_threshold *param);
enum onu_errorcode lan_counter_threshold_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct lan_cnt_threshold *out);
enum onu_errorcode lan_tca_get(struct onu_rctx *ctx, const struct uni_port_id *in, struct lan_cnt_val *out);
enum onu_errorcode wol_cfg_set(struct onu_rctx *ctx, const struct wol_cfg *param);
enum onu_errorcode wol_cfg_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct wol_cfg *out);
enum onu_errorcode wol_status_get(struct onu_rctx *ctx, const struct lan_port_index *in, struct wol_status *out);
enum onu_errorcode mdio_data_read(struct onu_rctx *ctx, const struct mdio *in, struct mdio_read *out);
enum onu_errorcode mdio_data_write(struct onu_rctx *ctx, const struct mdio_write *param);
enum onu_errorcode mdio_enable(struct onu_rctx *ctx, const struct mdio_en *param);
enum onu_errorcode mdio_disable(struct onu_rctx *ctx, const struct mdio_dis *param);
enum onu_errorcode mmd_data_read(struct onu_rctx *ctx, const struct mmd *in, struct mmd_read *out);
enum onu_errorcode mmd_data_write(struct onu_rctx *ctx, const struct mmd_write *param);
enum onu_errorcode onu_debug_level_set(struct onu_rctx *ctx, const struct onu_dbg_level *param);
enum onu_errorcode onu_debug_level_get(struct onu_rctx *ctx, struct onu_dbg_level *param);
enum onu_errorcode onu_version_get(struct onu_rctx *ctx, struct onu_version_string *param);
enum onu_errorcode onu_register_set(struct onu_rctx *ctx, const struct onu_reg_addr_val *param);
enum onu_errorcode onu_register_get(struct onu_rctx *ctx, const struct onu_reg_addr *in, struct onu_reg_val *out);
enum onu_errorcode onu_test_mode_set(struct onu_rctx *ctx, const struct onu_test_mode *param);
enum onu_errorcode onu_line_enable_set(struct onu_rctx *ctx, const struct onu_enable *param);
enum onu_errorcode onu_line_enable_get(struct onu_rctx *ctx, struct onu_enable *param);
enum onu_errorcode onu_sync_time_set(struct onu_rctx *ctx, const struct onu_sync_time *param);
enum onu_errorcode onu_sync_time_get(struct onu_rctx *ctx, struct onu_sync_time *param);
enum onu_errorcode onu_counters_cfg_set(struct onu_rctx *ctx, const struct onu_cnt_cfg *param);
enum onu_errorcode onu_counters_cfg_get(struct onu_rctx *ctx, struct onu_cnt_cfg *param);

#endif
