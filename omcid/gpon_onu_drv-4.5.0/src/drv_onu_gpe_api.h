/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_gpe_api.h
   Device Driver, GPON Packer Engine
*/
#ifndef _drv_onu_gpe_api_h
#define _drv_onu_gpe_api_h

#include "drv_onu_std_defs.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gpe_tables.h"
#include "drv_onu_types.h"

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/
/** \defgroup ONU_GPE_INTERNAL Packet Engine - Internal

    This chapter describes the software interface to access and configure the
    GPON Packet Engine (GPE).

    @{
*/
extern const struct onu_entry gpe_function_table[];
extern const unsigned int gpe_function_table_size;

#ifndef SWIG
/** Firmware header size in bytes */
#define PE_FW_HEADER_SIZE		16

#define PE_FW_FLAG0_OFFSET_WORD		1
#define PE_FW_FLAG1_OFFSET_WORD		2
#define PE_FW_OPT_HDR_LEN_OFFSET_WORD	3

#define PE_FW_FLAG0_OPT_HEADER_MASK	0x80000000
#endif

enum onu_errorcode gpe_init(struct onu_device *p_dev,
			    const struct gpe_init_data *param);

enum onu_errorcode gpe_debug_init(struct onu_device *p_dev,
				  const struct gpe_init_data *param);

enum onu_errorcode
gpe_low_level_modules_enable(struct onu_device *p_dev,
			     const struct gpe_ll_mod_sel *param);

enum onu_errorcode gpe_cfg_set(struct onu_device *p_dev,
			       const struct gpe_cfg *param);
enum onu_errorcode gpe_cfg_get(struct onu_device *p_dev, struct gpe_cfg *param);

enum onu_errorcode gpe_status_get(struct onu_device *p_dev,
				  struct gpe_status *param);

#ifndef SWIG
enum onu_errorcode gpe_arbiter_get(struct onu_device *p_dev,
				   struct gpe_arbiter *param);
enum onu_errorcode gpe_arbiter_set(struct onu_device *p_dev,
				   const struct gpe_arbiter *param);
#endif

enum onu_errorcode gpe_gem_port_add(struct onu_device *p_dev,
				    const struct gpe_gem_port *in,
				    struct gpe_gem_port *out);
enum onu_errorcode gpe_gem_port_delete(struct onu_device *p_dev,
				       const struct gem_port_id *param);
enum onu_errorcode gpe_gem_port_get(struct onu_device *p_dev,
				    const struct gem_port_id *in,
				    struct gpe_gem_port *out);
enum onu_errorcode gpe_gem_port_set(struct onu_device *p_dev,
				    const struct gpe_gem_port *in);

enum onu_errorcode gpe_tcont_create(struct onu_device *p_dev,
				 const struct gpe_tcont_cfg *param);
enum onu_errorcode gpe_tcont_set(struct onu_device *p_dev,
				 const struct gpe_tcont *param);
enum onu_errorcode gpe_tcont_get(struct onu_device *p_dev,
				 const struct tcont_index *in,
				 struct gpe_tcont *out);
enum onu_errorcode gpe_tcont_delete(struct onu_device *p_dev,
				    const struct tcont_index *param);

enum onu_errorcode gpe_egress_port_create(struct onu_device *p_dev,
					  const struct gpe_eport_create *param);
enum onu_errorcode gpe_egress_port_get(struct onu_device *p_dev,
				       const struct gpe_epn *in,
				       struct gpe_eport_create *out);
enum onu_errorcode gpe_port_index_get(struct onu_device *p_dev,
				      const struct gpe_egress_port *in,
				      struct gpe_eport_create *out);
enum onu_errorcode gpe_egress_port_delete(struct onu_device *p_dev,
					  const struct gpe_egress_port *param);
enum onu_errorcode
gpe_egress_port_cfg_set(struct onu_device *p_dev,
			const struct gpe_egress_port_cfg *param);
enum onu_errorcode gpe_egress_port_cfg_get(struct onu_device *p_dev,
					   const struct gpe_epn *in,
					   struct gpe_egress_port_cfg *out);

enum onu_errorcode
gpe_egress_port_status_get(struct onu_device *p_dev,
			   const struct gpe_epn *in,
			   struct gpe_egress_port_status *param);

enum onu_errorcode
gpe_backpressure_cfg_set(struct onu_device *p_dev,
			 const struct gpe_backpressure_cfg *param);
enum onu_errorcode gpe_backpressure_cfg_get(struct onu_device *p_dev,
					    struct gpe_backpressure_cfg *param);

enum onu_errorcode
gpe_ingress_queue_cfg_set(struct onu_device *p_dev,
			  const struct gpe_iqueue_cfg *param);
enum onu_errorcode gpe_ingress_queue_cfg_get(struct onu_device *p_dev,
					    const struct gpe_iqueue *in,
					    struct gpe_iqueue_cfg *out);
enum onu_errorcode gpe_ingress_queue_status_get(struct onu_device *p_dev,
					    const struct gpe_iqueue *in,
					    struct gpe_iqueue_status *out);

enum onu_errorcode
gpe_egress_queue_create(struct onu_device *p_dev,
			const struct gpe_equeue_create *param);
enum onu_errorcode gpe_egress_queue_delete(struct onu_device *p_dev,
					    const struct gpe_equeue *param);
enum onu_errorcode gpe_egress_queue_get(struct onu_device *p_dev,
					const struct gpe_equeue *in,
					struct gpe_equeue_create *out);
enum onu_errorcode
gpe_egress_queue_cfg_set(struct onu_device *p_dev,
			 const struct gpe_equeue_cfg *param);
enum onu_errorcode gpe_egress_queue_cfg_get(struct onu_device *p_dev,
					    const struct gpe_equeue *in,
					    struct gpe_equeue_cfg *out);
enum onu_errorcode gpe_egress_queue_status_get(struct onu_device *p_dev,
					       const struct gpe_equeue *in,
					       struct gpe_equeue_status *out);
enum onu_errorcode gpe_egress_queue_path_get(struct onu_device *p_dev,
					     const struct gpe_equeue *in,
					     struct gpe_equeue_path *out);

enum onu_errorcode gpe_scheduler_create(struct onu_device *p_dev,
				        const struct gpe_sched_create *param);
enum onu_errorcode gpe_scheduler_delete(struct onu_device *p_dev,
				        const struct gpe_scheduler_idx *param);
enum onu_errorcode gpe_scheduler_get(struct onu_device *p_dev,
				     const struct gpe_scheduler_idx *in,
				     struct gpe_sched_create *out);
enum onu_errorcode gpe_scheduler_cfg_set(struct onu_device *p_dev,
					 const struct gpe_scheduler_cfg *param);
enum onu_errorcode gpe_scheduler_cfg_get(struct onu_device *p_dev,
					 const struct gpe_scheduler_idx *in,
					 struct gpe_scheduler_cfg *out);
enum onu_errorcode gpe_scheduler_status_get(struct onu_device *p_dev,
					    const struct gpe_scheduler_idx *in,
					    struct gpe_scheduler_status *out);

enum onu_errorcode
gpe_token_bucket_shaper_create(struct onu_device *p_dev,
			       const struct gpe_token_bucket_shaper *param);
enum onu_errorcode
gpe_token_bucket_shaper_delete(struct onu_device *p_dev,
			       const struct gpe_token_bucket_shaper *param);
enum onu_errorcode
gpe_token_bucket_shaper_get(struct onu_device *p_dev,
			    const struct gpe_token_bucket_shaper_idx *in,
			    struct gpe_token_bucket_shaper *out);
enum onu_errorcode
gpe_token_bucket_shaper_cfg_set(struct onu_device *p_dev,
			       const struct gpe_token_bucket_shaper_cfg *param);
enum onu_errorcode
gpe_token_bucket_shaper_cfg_get(struct onu_device *p_dev,
				const struct gpe_token_bucket_shaper_idx *in,
				struct gpe_token_bucket_shaper_cfg *out);
enum onu_errorcode
gpe_token_bucket_shaper_status_get(struct onu_device *p_dev,
				   const struct gpe_token_bucket_shaper_idx *in,
				   struct gpe_token_bucket_shaper_status *out);

enum onu_errorcode gpe_meter_create(struct onu_device *p_dev,
				    struct gpe_meter *param);
enum onu_errorcode gpe_meter_delete(struct onu_device *p_dev,
				    const struct gpe_meter *param);
enum onu_errorcode gpe_meter_cfg_set(struct onu_device *p_dev,
				     const struct gpe_meter_cfg *param);
enum onu_errorcode gpe_meter_cfg_get(struct onu_device *p_dev,
				     const struct gpe_meter *in,
				     struct gpe_meter_cfg *out);
enum onu_errorcode gpe_meter_status_get(struct onu_device *p_dev,
				     const struct gpe_meter *in,
				     struct gpe_meter_status *out);


enum onu_errorcode
gpe_shared_buffer_cfg_set(struct onu_device *p_dev,
			  const struct gpe_shared_buffer_cfg *param);

enum onu_errorcode gpe_shared_buffer_cfg_get(struct onu_device *p_dev,
					     struct gpe_shared_buffer_cfg *out);

enum onu_errorcode
gpe_bridge_counter_get(struct onu_device *p_dev,
		       const struct gpe_bridge_cnt_interval *in,
		       struct gpe_bridge_counter *out);
enum onu_errorcode
gpe_bridge_port_counter_get(struct onu_device *p_dev,
		       const struct gpe_bridge_port_cnt_interval *in,
		       struct gpe_bridge_port_counter *out);
enum onu_errorcode
gpe_bridge_counter_threshold_set(struct onu_device *p_dev,
				 const struct gpe_cnt_bridge_threshold *param);
enum onu_errorcode
gpe_bridge_port_counter_threshold_set(struct onu_device *p_dev,
				 const struct gpe_cnt_bridge_port_threshold *param);
enum onu_errorcode
gpe_bridge_counter_threshold_get(struct onu_device *p_dev,
				 const struct gpe_bridge *in,
				 struct gpe_cnt_bridge_threshold *out);
enum onu_errorcode
gpe_bridge_port_counter_threshold_get(struct onu_device *p_dev,
				 const struct gpe_bridge_port_index *in,
				 struct gpe_cnt_bridge_port_threshold *out);
enum onu_errorcode
gpe_bridge_tca_get(struct onu_device *p_dev,
				      const struct gpe_bridge *in,
				      struct gpe_cnt_bridge_threshold *out);
enum onu_errorcode
gpe_bridge_port_tca_get(struct onu_device *p_dev,
				      const struct gpe_bridge_port_index *in,
				      struct gpe_cnt_bridge_port_threshold *out);
enum onu_errorcode
gpe_bridge_counter_reset(struct onu_device *p_dev,
			 const struct gpe_bridge_cnt_interval *param);
enum onu_errorcode
gpe_bridge_port_counter_reset(struct onu_device *p_dev,
			 const struct gpe_bridge_port_cnt_interval *param);

#ifndef SWIG
bool
gpe_bridge_port_valid(struct onu_control *ctrl,
			   const uint32_t index);

enum onu_errorcode sce_lan_cnt_get(struct onu_control *ctrl,
				   const uint8_t uni_idx,
				   struct sce_lan_counter *cnt);
#endif

enum onu_errorcode gpe_parser_cfg_set(struct onu_device *p_dev,
				      const struct gpe_parser_cfg *param);
enum onu_errorcode gpe_parser_cfg_get(struct onu_device *p_dev,
				      struct gpe_parser_cfg *out);

enum onu_errorcode
gpe_ethertype_filter_cfg_set(struct onu_device *p_dev,
			     const struct gpe_ethertype_filter_cfg *param);

enum onu_errorcode
gpe_ethertype_filter_cfg_get(struct onu_device *p_dev,
			     const struct gpe_ethertype_filter_index *in,
			     struct gpe_ethertype_filter_cfg *out);

enum onu_errorcode gpe_omci_send(struct onu_device *p_dev,
				 const struct gpe_omci_msg *param);

enum onu_errorcode gpe_tod_init(struct onu_device *p_dev,
				const struct gpe_tod_init_data *param);
enum onu_errorcode gpe_tod_sync_set(struct onu_device *p_dev,
				    const struct gpe_tod_sync *param);
enum onu_errorcode gpe_tod_get(struct onu_device *p_dev, struct gpe_tod *param);
enum onu_errorcode gpe_tod_sync_get(struct onu_device *p_dev,
				    struct gpe_tod_sync *param);

enum onu_errorcode
gpe_iqm_global_cfg_set(struct onu_device *p_dev,
		       const struct gpe_iqm_global_cfg *param);
enum onu_errorcode gpe_iqm_global_cfg_get(struct onu_device *p_dev,
					  struct gpe_iqm_global_cfg *param);

enum onu_errorcode
gpe_iqm_global_status_get(struct onu_device *p_dev,
			  struct gpe_iqm_global_status *param);

enum onu_errorcode gpe_tmu_global_cfg_get(struct onu_device *p_dev,
					  struct gpe_tmu_global_cfg *param);

enum onu_errorcode
gpe_tmu_global_status_get(struct onu_device *p_dev,
			  struct gpe_tmu_global_status *param);

enum onu_errorcode gpe_tmu_counter_get(struct onu_device *p_dev,
				       const struct gpe_cnt_tmu_sel *in,
				       struct gpe_cnt_tmu_val *out);
enum onu_errorcode gpe_tmu_counter_reset(struct onu_device *p_dev,
					 const struct gpe_cnt_tmu_reset *param);

enum onu_errorcode gpe_sce_counter_get(struct onu_device *p_dev,
				       const struct gpe_cnt_sce_sel *in,
				       struct gpe_cnt_sce_val *out);
enum onu_errorcode gpe_sce_counter_reset(struct onu_device *p_dev,
					 const struct gpe_cnt_sce_reset *param);

enum onu_errorcode gpe_gem_counter_get(struct onu_device *p_dev,
				       const struct gpe_gem_cnt_interval *in,
				       struct gpe_gem_counter *out);
enum onu_errorcode
gpe_gem_counter_threshold_set(struct onu_device *p_dev,
			      const struct gpe_cnt_gem_threshold *param);
enum onu_errorcode
gpe_gem_counter_threshold_get(struct onu_device *p_dev,
			      const struct gem_port_index *in,
			      struct gpe_cnt_gem_val *out);
enum onu_errorcode gpe_gem_tca_get(struct onu_device *p_dev,
				   const struct gem_port_index *in,
				   struct gpe_gem_tca_val *out);
enum onu_errorcode
gpe_gem_counter_reset(struct onu_device *p_dev,
		      const struct gpe_gem_cnt_interval *param);

#if defined(INCLUDE_SCE_DEBUG)
enum onu_errorcode sce_break_set(struct onu_device *p_dev,
				 const struct sce_break_point *param);
enum onu_errorcode sce_break_autocheck_enable(struct onu_device *p_dev,
					      const bool enable);
enum onu_errorcode sce_break_get(struct onu_device *p_dev,
				 const struct sce_break_index *in,
				 struct sce_break_point *out);
enum onu_errorcode sce_break_remove(struct onu_device *p_dev,
				    const struct sce_break_point *param);
enum onu_errorcode sce_break(struct onu_device *p_dev,
			     const struct sce_thread *in,
			     struct sce_break_info *out);
enum onu_errorcode sce_single_step(struct onu_device *p_dev,
				   const struct sce_thread *in,
				   struct sce_break_info *out);
enum onu_errorcode sce_run(struct onu_device *p_dev,
			   const struct sce_thread *param);
enum onu_errorcode sce_restart_vm(struct onu_device *p_dev,
				  const struct sce_restart_cfg *param);
enum onu_errorcode sce_run_mask(struct onu_device *p_dev,
				const struct sce_thread_mask *param);
enum onu_errorcode sce_break_mask(struct onu_device *p_dev,
				  const struct sce_thread_mask *param);
enum onu_errorcode sce_status_get(struct onu_device *p_dev,
				  struct sce_status *param);
enum onu_errorcode sce_reg_set(struct onu_device *p_dev,
			       const struct sce_register_val *param);
enum onu_errorcode sce_reg_get(struct onu_device *p_dev,
			       const struct sce_register *in,
			       struct sce_register_val *out);
enum onu_errorcode sce_mem_set(struct onu_device *p_dev,
			       const struct sce_memory_val *param);
enum onu_errorcode sce_mem_get(struct onu_device *p_dev,
			       const struct sce_memory *in,
			       struct sce_memory_val *out);
#ifndef SWIG
enum onu_errorcode sce_break_check(struct onu_device *p_dev,
				   struct sce_thread_mask *out);
#endif
#endif /* defined(INCLUDE_SCE_DEBUG)*/
enum onu_errorcode gpe_sce_download(struct onu_device *p_dev,
				    const struct sce_download_cfg *param);
#ifndef SWIG
enum onu_errorcode gpe_sce_selected_download(struct onu_device *p_dev,
					     const char *name,
					     const uint8_t num_pe);
#endif


enum onu_errorcode gpe_sce_version_get(struct onu_device *p_dev,
				       const struct sce_pe_index *in,
				       struct sce_version *out);

enum onu_errorcode
gpe_flat_egress_path_create(struct onu_device *p_dev,
			    const struct gpe_flat_egress_path *param);

enum onu_errorcode gpe_fsqm_check(struct onu_device *p_dev, uint16_t len);

enum onu_errorcode gpe_cop_download(struct onu_device *p_dev,
				    const struct cop_download_cfg *param);

#ifndef SWIG
enum onu_errorcode gpe_iqueue_write_debug(struct onu_device *p_dev,
					  const struct ictrlc_write *param);

enum onu_errorcode onu_gpe_omci_handle(struct onu_control *ctrl);

int onu_gpe_egress_cpu_port_handle(struct onu_control *ctrl,
				   const uint32_t irnicr);
enum onu_errorcode gpe_gem_cnt_update(	struct onu_control *ctrl,
					const uint16_t index,
					const uint64_t reset_mask,
					const bool curr,
					void *p_data);
enum onu_errorcode gpe_bridge_cnt_update(struct onu_control *ctrl,
					 const uint16_t index,
					 const uint64_t reset_mask,
					 const bool curr,
					 void *p_data);
enum onu_errorcode gpe_bridge_port_cnt_update(struct onu_control *ctrl,
					 const uint16_t index,
					 const uint64_t reset_mask,
					 const bool curr,
					 void *p_data);
int onu_cop_version_get(struct onu_control *ctrl,
			int cop_id,
			char *cop_name,
			int *major,
			int *minor);
#endif

enum onu_errorcode
gpe_lan_exception_cfg_set(struct onu_device *p_dev,
			  const struct gpe_lan_exception_cfg *param);
enum onu_errorcode
gpe_lan_exception_cfg_get(struct onu_device *p_dev,
			  const struct gpe_lan_exception_idx *in,
			  struct gpe_lan_exception_cfg *out);
enum onu_errorcode
gpe_ani_exception_cfg_set(struct onu_device *p_dev,
			  const struct gpe_ani_exception_cfg *param);
enum onu_errorcode
gpe_ani_exception_cfg_get(struct onu_device *p_dev,
			  const struct gpe_ani_exception_idx *in,
			  struct gpe_ani_exception_cfg *out);
enum onu_errorcode
gpe_exception_queue_cfg_set(struct onu_device *p_dev,
			    const struct gpe_exception_queue_cfg *param);
enum onu_errorcode
gpe_exception_queue_cfg_get(struct onu_device *p_dev,
			    const struct gpe_exception_queue_idx *in,
			    struct gpe_exception_queue_cfg *out);

#ifndef SWIG
enum onu_errorcode
gpe_tr181_counter_get(struct onu_device *p_dev,
		      const struct gpe_tr181_counters_cfg *in,
		      struct gpe_tr181_counters *out);
#endif

#ifdef INCLUDE_CLI_SUPPORT
struct gpe_lan_port_acl {
	uint16_t port_index;
	bool acl_filter_enable;
	uint8_t acl_filter_index;
	bool acl_filter_mode_whitelist;
};

struct gpe_lan_port_acl_index {
	uint16_t port_index;
};

enum onu_errorcode gpe_lan_port_acl_set(struct onu_device *p_dev,
					const struct gpe_lan_port_acl *in);

enum onu_errorcode gpe_lan_port_acl_get(struct onu_device *p_dev,
					const struct gpe_lan_port_acl_index *in,
					struct gpe_lan_port_acl *out);
#endif

#ifndef SWIG
enum onu_errorcode gpe_device_capability_get(struct gpe_capability *cap);
#endif

enum onu_errorcode gpe_capability_get(struct onu_device *p_dev,
				      struct gpe_capability *param);

enum onu_errorcode
gpe_exception_profile_cfg_set(struct onu_device *p_dev,
			      const struct gpe_exception_profile_cfg *param);

enum onu_errorcode
gpe_exception_profile_cfg_get(struct onu_device *p_dev,
			      const struct gpe_exception_profile_idx *in,
			      struct gpe_exception_profile_cfg *out);

enum onu_errorcode gpe_egress_port_enable(struct onu_device *p_dev,
					  const struct gpe_epn *param);

enum onu_errorcode gpe_egress_port_disable(struct onu_device *p_dev,
					   const struct gpe_epn *param);

#ifndef SWIG
/**
   Enable the connected egress queues based on given egress port value.
   All connected scheduler will be evaluated for connected queues.

   \param ctrl    device control context
   \param epn     egress port
   \param ena     enable/disable
*/
void gpe_enqueue_enable(struct onu_control *ctrl, const uint32_t epn, const bool ena);

/**
   Flush all packets stored in the connected queues.
   The egress queues should be disabled first using gpe_enqueue_enable() .

   \param ctrl    device control context
   \param epn     egress port
*/
uint32_t gpe_enqueue_flush(struct onu_control *ctrl, const uint16_t epn);

void gpe_enqueue_modify(struct onu_control *ctrl, const uint16_t qid, const bool ena);
#endif

/*! @} */

/*! @} */

EXTERN_C_END
#endif
