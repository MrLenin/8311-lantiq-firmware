/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_gpe_tables_api.h
   Device Driver, GPON Packer Engine
*/
#ifndef _drv_onu_gpe_tables_api_h
#define _drv_onu_gpe_tables_api_h

#include "drv_onu_std_defs.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gpe_tables.h"
#include "drv_onu_gpe_tables_interface.h"
#include "drv_onu_types.h"
#include "drv_onu_ll_tbm.h"

EXTERN_C_BEGIN
/** \addtogroup ONU_GPE_INTERNAL
   @{
*/
#ifndef SWIG

/* Counters based on bridge port number */
#define COP_COUNT_BASE_IBP_GOOD					0x0000
#define COP_COUNT_BASE_IBP_DISCARD				0x0080
#define COP_COUNT_BASE_LIM						0x0100
#define COP_COUNT_BASE_EBP_GOOD					0x0180
#define COP_COUNT_BASE_EBP_DISCARD				0x0200
/* Counters based on IQN port number */
#define COP_COUNT_BASE_UC						0x0280
#define COP_COUNT_BASE_MC						0x0289
#define COP_COUNT_BASE_BC						0x0292
#define COP_COUNT_BASE_IPN_DISCARD				0x029B
/* Counters based on UNI port number 0-7 */
#define COP_COUNT_BASE_PPPOE					0x02A4
/* Counters based on UNI port number 0-3 */
#define COP_COUNT_BASE_MC_EGRESS				0x02AC
#define COP_COUNT_BASE_BC_EGRESS				0x02B0
/* Policer thresholds based on UNI port number 0-4 */
#define COP_COUNT_BASE_LAN_POLICER				0x02B4
/* simple Policer thresholds used for exceptions */
#define COP_COUNT_BASE_ANI_EXCEPTION_POLICER	0x02B9
#define COP_COUNT_BASE_EXCEPTION_POLICER		0x02BA
#define COP_COUNT_BASE_IGMP_EXCEPTION_POLICER	0x02BB
/* Unused space */
#define COP_COUNT_BASE_UNUSED1					0x02BC
#define COP_COUNT_BASE_UNUSED2					0x02BD
#define COP_COUNT_BASE_UNUSED3					0x02BE
/* global statistic count of lost exceptions due to policing */
#define COP_COUNT_BASE_EXCEPTIONS_LOST			0x02BF

#define TABLE_GET(ctrl, p_table_entry) \
		gpe_table_entry_intresp(ctrl, p_table_entry, ONU_GPE_COP_GET)

#define TABLE_READ(ctrl, p_table_entry) \
		gpe_table_entry_intresp(ctrl, p_table_entry, ONU_GPE_COP_READ)

enum sce_process_mode {
	SCE_MODE_PACKET = 0,
	SCE_MODE_COMMAND = 1
};

struct sce_cnt_get_helper {
	enum gpe_sce_cnt_type type;
	uint16_t cop_base;
	uint16_t offset_max;
};

/** Structure to find a LAN port for a multicast flow.
*/
struct gpe_mc_match {
	/** Matching bridge port for requested MAC address */
	uint32_t port_map_index;
	/** Bridge index field used for key completion of short FWD table */
	uint32_t bridge_index;
};

/** Union to specify MC forwarding address (MAC or IP)*/
union gpe_mc_addr {
	/** MC MAC address*/
	uint8_t mc_mac[6];
	/** MC IP address */
	uint8_t mc_ip[4];
};

extern const struct onu_entry gpe_table_function_table[];
extern const unsigned int gpe_table_function_table_size;

enum onu_errorcode
gpe_table_reinit(struct onu_device *p_dev,
		 const struct gpe_reinit_table *reinit_table);

/**
   Table access function which writes a specific table entry.
   This function calls the base function N times (where N is number of PE,
   which should receive table data)

   \param fw_info	Firmware information
   \param num_pe	NUmber of PEs
   \param entry		Table entry structure
*/
enum onu_errorcode
sce_pe_table_entry_write(const struct pe_fw_info *fw_info,
			 const uint8_t num_pe,
			 const struct gpe_table_entry *entry);

/**
   Table access function which reads a specific table entry.

   \param fw_info	Firmware information
   \param num_pe	Number of PEs
   \param entry		Table data structure
*/
enum onu_errorcode sce_pe_table_entry_read(const struct pe_fw_info *fw_info,
					   const uint8_t num_pe,
					   struct gpe_table_entry *entry);

enum onu_errorcode gpe_table_entry_set(struct onu_device *p_dev,
				       struct gpe_table_entry *param);
enum onu_errorcode gpe_table_entry_get(struct onu_device *p_dev,
				       const struct gpe_table *in,
				       struct gpe_table_entry *out);
enum onu_errorcode gpe_table_entry_add(struct onu_device *p_dev,
				       struct gpe_table_entry *param);
enum onu_errorcode gpe_table_entry_nil_add(struct onu_device *p_dev,
				       struct gpe_table_entry *param,
				       const bool);
enum onu_errorcode gpe_table_entry_delete(struct onu_device *p_dev,
				       struct gpe_table_entry *param);
enum onu_errorcode gpe_table_entry_search(struct onu_device *p_dev,
					  struct gpe_table_entry *param);
enum onu_errorcode gpe_table_entry_do(struct onu_device *p_dev,
				      struct gpe_table_entry *param,
				      uint32_t instruction_id);
enum onu_errorcode gpe_table_entry_read(struct onu_device *p_dev,
					const struct gpe_table *in,
					struct gpe_table_entry *out);
enum onu_errorcode gpe_table_entry_write(struct onu_device *p_dev,
					 struct gpe_table_entry *param);
enum onu_errorcode gpe_table_entry_intresp(struct onu_control *ctrl,
					   struct gpe_table_entry *param,
					   uint32_t cmd);
enum onu_errorcode gpe_table_entry_intcmd(struct onu_control *ctrl,
					  struct gpe_table_entry *param,
					  uint32_t cmd);
enum onu_errorcode sce_cnt_get(struct onu_control *ctrl,
			       struct gpe_table_entry *entry,
			       uint32_t idx);

enum onu_errorcode gpe_sce_constant_mac_set(struct onu_control *ctrl,
					    const uint8_t mac[6]);

enum onu_errorcode gpe_sce_constant_set(struct onu_control *ctrl,
					const uint32_t idx,
					const uint32_t val);
enum onu_errorcode gpe_sce_constant_get(struct onu_control *ctrl,
					const uint32_t idx,
					uint32_t *val);
enum onu_errorcode gpe_sce_process_mode_set(struct onu_control *ctrl,
					    enum sce_process_mode mode);

enum onu_errorcode gpe_sce_pe_init(struct onu_control *ctrl);
#endif

#ifndef SWIG
enum onu_errorcode gpe_bridge_port_cfg_set(struct onu_device *p_dev,
					   const struct gpe_bridge_port *param);

enum onu_errorcode gpe_ext_vlan_set(struct onu_device *p_dev,
				    const struct gpe_ext_vlan *param);
enum onu_errorcode gpe_ext_vlan_get(struct onu_device *p_dev,
				    const struct gpe_ext_vlan_index *in,
				    struct gpe_ext_vlan *out);
enum onu_errorcode gpe_ext_vlan_do(struct onu_device *p_dev,
				   const struct gpe_table_entry *in,
				   struct gpe_table_entry *out);
enum onu_errorcode gpe_ext_vlan_custom_set(struct onu_device *p_dev,
					const struct gpe_ext_vlan_custom *in);
enum onu_errorcode gpe_ext_vlan_custom_get(struct onu_device *p_dev,
					  struct gpe_ext_vlan_custom *out);

enum onu_errorcode gpe_fid_add(	struct onu_device *p_dev,
			        const struct gpe_table_entry *in);
enum onu_errorcode gpe_fid_delete(struct onu_device *p_dev,
				  const struct gpe_table_entry *in);
enum onu_errorcode gpe_fid_get(struct onu_device *p_dev,
			       const struct gpe_table_entry *in,
			       struct gpe_table_entry *out);

enum onu_errorcode gpe_long_fwd_add(struct onu_device *p_dev,
				    const struct gpe_table_entry *in);
enum onu_errorcode gpe_long_fwd_delete(	struct onu_device *p_dev,
					const struct gpe_table_entry *param);
enum onu_errorcode gpe_long_fwd_forward(struct onu_device *p_dev,
					struct gpe_table_entry *in);

enum onu_errorcode gpe_tagging_filter_do(struct onu_device *p_dev,
					 const struct gpe_tagg_filter *in,
					 struct gpe_tagg_filter *out);
enum onu_errorcode gpe_tagging_filter_get(struct onu_device *p_dev,
					  const struct gpe_tagging_index *in,
					  struct gpe_tagging *out);
enum onu_errorcode gpe_tagging_filter_set(struct onu_device *p_dev,
					  const struct gpe_tagging *param);
enum onu_errorcode gpe_cop_table0_read(struct onu_device *p_dev,
				       struct gpe_table_entry *entry);

enum onu_errorcode gpe_short_fwd_add(struct onu_device *p_dev,
				     struct gpe_table_entry *in);
enum onu_errorcode gpe_short_fwd_delete(struct onu_device *p_dev,
					struct gpe_table_entry *in);
enum onu_errorcode gpe_short_fwd_relearn(struct onu_device *p_dev,
					 struct gpe_table_entry *in);
enum onu_errorcode gpe_short_fwd_forward(struct onu_device *p_dev,
					 struct gpe_table_entry *in);

enum onu_errorcode gpe_aging_trigger_set(struct onu_control *ctrl);

enum onu_errorcode gpe_age_get(	struct onu_device *p_dev,
				struct gpe_table_entry *in,
				struct sce_mac_entry_age *out);

enum onu_errorcode gpe_age(struct onu_device *p_dev,
				struct gpe_table_entry *in);

#endif

enum onu_errorcode
gpe_short_fwd_mac_mc_port_add(struct onu_device *p_dev,
			      const struct gpe_mac_mc_port *in);
enum onu_errorcode
gpe_short_fwd_mac_mc_port_delete(struct onu_device *p_dev,
				 const struct gpe_mac_mc_port *in);
enum onu_errorcode
gpe_short_fwd_mac_mc_port_modify(struct onu_device *p_dev,
				 const struct gpe_mac_mc_port_modify *in);

enum onu_errorcode
gpe_short_fwd_ipv4_mc_port_add(struct onu_device *p_dev,
			       const struct gpe_ipv4_mc_port *in);
enum onu_errorcode
gpe_short_fwd_ipv4_mc_port_delete(struct onu_device *p_dev,
				  const struct gpe_ipv4_mc_port *in);
enum onu_errorcode
gpe_short_fwd_ipv4_mc_port_modify(struct onu_device *p_dev,
				  const struct gpe_ipv4_mc_port_modify *in);

enum onu_errorcode gpe_aging_time_set(struct onu_device *p_dev,
				      const struct sce_aging_time *in);
enum onu_errorcode gpe_aging_time_get(struct onu_device *p_dev,
				      struct sce_aging_time *out);
enum onu_errorcode gpe_aging_time_set_debug( struct onu_device *p_dev,
					const struct sce_aging_time *in);

enum onu_errorcode gpe_sce_constants_get(struct onu_device *p_dev,
					 struct gpe_sce_constants *param);
enum onu_errorcode gpe_sce_constants_set(struct onu_device *p_dev,
					 const struct gpe_sce_constants *param);
enum onu_errorcode gpe_sce_mac_get(struct onu_device *p_dev,
				   struct gpe_sce_mac *param);
enum onu_errorcode gpe_sce_mac_set(struct onu_device *p_dev,
				   const struct gpe_sce_mac *param);

enum onu_errorcode gpe_vlan_fid_add(struct onu_device *p_dev,
				    const struct gpe_vlan_fid_in *in,
				    struct gpe_vlan_fid_out *out);
enum onu_errorcode gpe_vlan_fid_get(struct onu_device *p_dev,
				    const struct gpe_vlan_fid_in *in,
				    struct gpe_vlan_fid_out *out);
enum onu_errorcode gpe_vlan_fid_delete(struct onu_device *p_dev,
				       const struct gpe_vlan_fid_in *in);

#ifndef SWIG
enum onu_errorcode gpe_bridge_cnt_get(struct onu_control *ctrl,
				      const uint32_t bridge_index,
				      struct gpe_cnt_bridge_val *counter);
enum onu_errorcode
gpe_bridge_port_cnt_get(			      struct onu_control *ctrl,
						const uint32_t index,
						      struct gpe_cnt_bridge_port_val *counter);
#endif

#ifndef SWIG
enum onu_errorcode
gpe_bridge_port_config_get(struct onu_control *ctrl,
			   const struct gpe_bridge_port_index *in,
			   struct gpe_bridge_port *out);
#endif

enum onu_errorcode
gpe_bridge_port_cfg_get(struct onu_device *p_dev,
			const struct gpe_bridge_port_index *in,
			struct gpe_bridge_port *out);

enum onu_errorcode gpe_cop_debug_set(struct onu_device *p_dev,
				     const struct gpe_cop_tracing *in);
enum onu_errorcode gpe_cop_debug_server(struct onu_device *p_dev,
					const struct gpe_cop_debug *in);

enum onu_errorcode
gpe_acl_table_entry_set(struct onu_device *p_dev,
			const struct gpe_acl_table_entry *param);
enum onu_errorcode
gpe_acl_table_entry_get(struct onu_device *p_dev,
			const struct gpe_acl_table_entry_idx *in,
			struct gpe_acl_table_entry *out);
enum onu_errorcode
gpe_acl_table_entry_delete(struct onu_device *p_dev,
			   const struct gpe_acl_table_entry_idx *param);

#if defined(INCLUDE_DUMP)

/**
   Dump the gpe tables.
*/
void gpe_table_dump(struct seq_file *s);
void gpe_table_dsgem(struct seq_file *s);
void gpe_table_usgem(struct seq_file *s);
void gpe_table_fidhash(struct seq_file *s);
void gpe_table_fidass(struct seq_file *s);
void gpe_table_tagg(struct seq_file *s);
void gpe_table_vlan(struct seq_file *s);
void gpe_table_extvlan(struct seq_file *s);
void gpe_table_vlanrule(struct seq_file *s);
void gpe_table_vlantreatment(struct seq_file *s);
void gpe_table_shortfwdhash(struct seq_file *s);
void gpe_table_shortfwdmac(struct seq_file *s);
void gpe_table_shortfwdmacmc(struct seq_file *s);
void gpe_table_shortfwdipv4(struct seq_file *s);
void gpe_table_shortfwdipv4mc(struct seq_file *s);
void gpe_table_longfwdhash(struct seq_file *s);
void gpe_table_longfwdipv6(struct seq_file *s);
void gpe_table_longfwdipv6mc(struct seq_file *s);
void gpe_table_dsmcipv4(struct seq_file *s);
void gpe_table_dsmcipv6(struct seq_file *s);
void gpe_table_learnlim(struct seq_file *s);
void gpe_table_exp(struct seq_file *s);
void gpe_table_macfilter(struct seq_file *s);
void gpe_table_counter(struct seq_file *s);
void gpe_table_bridgeport(struct seq_file *s);
void gpe_table_pmapper(struct seq_file *s);
void gpe_table_lanport(struct seq_file *s);
void gpe_table_pcpdec(struct seq_file *s);
void gpe_table_dscpdec(struct seq_file *s);
void gpe_table_pcpenc(struct seq_file *s);
void gpe_table_dscpenc(struct seq_file *s);
void gpe_table_redir(struct seq_file *s);
void gpe_table_aclfilt(struct seq_file *s);
void gpe_table_bridge(struct seq_file *s);
void gpe_table_const(struct seq_file *s);
void gpe_table_status(struct seq_file *s);
void gpe_table_ethertype_filter(struct seq_file *s);
void gpe_table_enqueue(struct seq_file *s);

#endif

/*! @} */

EXTERN_C_END
#endif
