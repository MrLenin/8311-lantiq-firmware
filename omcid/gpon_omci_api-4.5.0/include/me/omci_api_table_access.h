/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \addtogroup OMCI_API_TABLE_ACCESS

   @{
*/

/** Maximum number of supported ports per bridge */
#define OMCI_API_MAX_BRIDGE_PORT		16

enum omci_api_return table_read(struct omci_api_ctx *ctx,
				const uint32_t id,
				const uint16_t idx,
				const uint32_t size,
				struct gpe_table_entry *entry);

enum omci_api_return table_write(struct omci_api_ctx *ctx,
				const uint32_t size,
				struct gpe_table_entry *entry);

enum omci_api_return
omci_api_bridge_flooding_modify(struct omci_api_ctx *ctx,
			        const bool is_uni,
			        const uint8_t lan_port,
			        const uint16_t bridge_index,
			        const uint16_t bridge_port_index);

enum omci_api_return omci_api_bridge_init(struct omci_api_ctx *ctx,
					  const uint16_t bridge_index);

enum omci_api_return omci_api_bridge_get(struct omci_api_ctx *ctx,
					 const uint16_t bridge_index,
					 uint8_t *bridge_port);

enum omci_api_return omci_api_bridge_clear(struct omci_api_ctx *ctx,
					   const uint16_t bridge_index);

enum omci_api_return
omci_api_bridge_port_ingress_color_marking_modify(struct omci_api_ctx *ctx,
						  const uint16_t index,
						  const uint8_t color_marking);

enum omci_api_return
omci_api_bridge_port_egress_color_marking_modify(struct omci_api_ctx *ctx,
						  const uint16_t index,
						  const uint8_t color_marking);

enum omci_api_return
omci_api_bridge_port_bridge_get(struct omci_api_ctx *ctx,
				const uint16_t bridge_port_index,
				uint8_t *bridge_index);

enum omci_api_return
omci_api_bridge_port_tp_modify(struct omci_api_ctx *ctx,
			       const uint16_t bridge_port_index,
			       const uint16_t tp_type,
			       const uint16_t tp_pointer);

enum omci_api_return
omci_api_bridge_port_eth_uni_index_get(struct omci_api_ctx *ctx,
				       uint16_t bp_me_id,
				       uint8_t *port_index);

enum omci_api_return omci_api_gem_port_loop_modify(struct omci_api_ctx *ctx,
						   const uint16_t gpix,
						   const uint16_t loop);

enum omci_api_return
omci_api_gem_port_interworking_modify(struct omci_api_ctx *ctx,
				      const uint16_t gpix,
				      const uint16_t interworking_option,
				      const uint8_t gem_port_type,
				      const uint8_t port_index);

enum omci_api_return
omci_api_bridge_port_learning_limitation_modify(struct omci_api_ctx *ctx,
						const uint16_t
						bridge_port_index,
						const uint8_t learning_ind,
						const uint8_t
						mac_learning_depth);

enum omci_api_return
omci_api_bridge_port_local_switching_modify(struct omci_api_ctx *ctx,
					    const uint16_t bridge_port_index,
					    const uint8_t port_bridging_ind);

enum omci_api_return
omci_api_bridge_port_uuc_mac_flood_modify(struct omci_api_ctx *ctx,
					  const uint16_t bridge_port_index,
					  const uint8_t unknown_mac_discard);

enum omci_api_return
omci_api_bridge_port_umc_mac_flood_modify(struct omci_api_ctx *ctx,
					  const uint16_t bridge_port_index,
					  const uint8_t flag1,
					  const uint8_t flag2);

enum omci_api_return omci_api_bridge_port_add(struct omci_api_ctx *ctx,
					      const uint16_t bridge_port_index,
					      const uint16_t bridge_index);

enum omci_api_return
omci_api_bridge_port_delete(struct omci_api_ctx *ctx,
			    const uint16_t bridge_port_index);

enum omci_api_return omci_api_mac_bridge_port_is_ani(struct omci_api_ctx *ctx,
						     uint16_t me_id,
						     bool *ani_indication);

/** Get bridge port TP type and connected termination point index.
    Used by ME 171 and ME 78 to determine dispatch path.
    \param[in]  ctx       OMCI API context pointer
    \param[in]  me_id     MAC Bridge Port Config Data ME identifier
    \param[out] tp_type   TP type (0=PPTP, 2=p-Mapper, 3=ITP)
    \param[out] conn_idx  Connected TP instance index
*/
enum omci_api_return
omci_api_bridge_port_tp_info_get(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 uint8_t *tp_type,
				 uint8_t *conn_idx);

enum omci_api_return omci_api_gem_port_us_add(struct omci_api_ctx *ctx,
					      const uint16_t gpix,
					      const uint16_t egress_queue_index);

enum omci_api_return omci_api_gem_port_us_delete(struct omci_api_ctx *ctx,
						 const uint16_t gpix);

enum omci_api_return
omci_api_gem_port_us_ext_vlan_modify(struct omci_api_ctx *ctx,
				     const uint16_t gpix,
				     const bool ext_vlan_enable,
				     const uint8_t ext_vlan_index,
				     const uint8_t ext_vlan_incremental_enable);

enum omci_api_return omci_api_gem_port_us_info_get(struct omci_api_ctx *ctx,
						   const uint16_t gpix,
						   bool *valid);

enum omci_api_return omci_api_gem_port_ds_add(struct omci_api_ctx *ctx,
					      const uint16_t gpix,
					      const uint16_t egress_queue_index);

enum omci_api_return omci_api_gem_port_ds_delete(struct omci_api_ctx *ctx,
						 const uint16_t gpix);

enum omci_api_return
omci_api_gem_port_ds_ext_vlan_modify(struct omci_api_ctx *ctx,
				     const uint16_t gpix,
				     const bool ext_vlan_enable,
				     const uint8_t ext_vlan_index);

enum omci_api_return
omci_api_gem_port_ds_type_modify(struct omci_api_ctx *ctx,
				 const uint16_t gpix,
				 const bool mc);

enum omci_api_return
omci_api_gem_port_ds_ingress_color_marking_modify(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const uint8_t marking);

enum omci_api_return
omci_api_gem_port_us_queue_marking_mode_modify(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const uint8_t marking);

enum omci_api_return
omci_api_gem_port_ds_prio_selection_modify(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const bool enable,
						  const uint16_t prio);

enum omci_api_return
omci_api_gem_port_shaper_add(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const uint16_t queue_ptr,
						  const uint16_t td_ptr);

enum omci_api_return
omci_api_gemport_shaper_delete(struct omci_api_ctx *ctx,
						   const uint16_t gpix,
						   const uint16_t td_ptr);

enum omci_api_return
omci_api_gemport_meter_add(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const uint16_t me_id,
						  const uint16_t td_ptr);

enum omci_api_return
omci_api_gemport_meter_delete(struct omci_api_ctx *ctx,
						   const uint16_t gpix,
						   const uint16_t me_id,
						   const uint16_t td_ptr);

enum omci_api_return
omci_api_meter_create(struct omci_api_ctx *ctx,
					   uint32_t *meter_idx);

enum omci_api_return
omci_api_meter_delete(struct omci_api_ctx *ctx,
					   const uint8_t meter_idx);

enum omci_api_return
omci_api_bridge_port_meter_add(struct omci_api_ctx *ctx,
			       const uint16_t bridge_port_idx,
				  const uint16_t me_id,
			       const uint16_t tp_ptr,
			       const uint16_t tp_type,
			       const uint16_t ptr,
			       const uint8_t inbound);

enum omci_api_return
omci_api_bridge_port_meter_delete(struct omci_api_ctx *ctx,
				  const uint16_t bridge_port_idx,
				  const uint16_t me_id,
				  const uint16_t tp_ptr,
				  const uint16_t tp_type,
				  const uint16_t ptr,
				  const uint8_t inbound);

enum omci_api_return
omci_api_lan_port_queue_marking_mode_modify(struct omci_api_ctx *ctx,
					    const uint16_t port_index,
					    const uint8_t queue_marking_mode);

enum omci_api_return
omci_api_lan_port_ppoe_modify(struct omci_api_ctx *ctx,
			      const uint16_t port_index,
			      const uint8_t pppoe_filter_enable);

enum omci_api_return
omci_api_lan_port_interworking_modify(struct omci_api_ctx *ctx,
				      const uint16_t port_index,
				      const uint8_t queue_index,
				      const uint8_t interworking_option,
				      const uint8_t interworking_index);

enum omci_api_return
omci_api_lan_port_base_queue_get(struct omci_api_ctx *ctx,
				 const uint16_t port_index,
				 uint8_t *queue_index);

enum omci_api_return
omci_api_lan_port_ext_vlan_get(struct omci_api_ctx *ctx,
			       uint16_t port_index,
			       uint8_t *ext_vlan_enable_egress,
			       uint8_t *ext_vlan_index_egress,
			       uint8_t *ext_vlan_enable_ingress,
			       uint8_t *ext_vlan_index_ingress,
			       uint8_t *ext_vlan_incremental_enable);

enum omci_api_return
omci_api_lan_port_ext_vlan_modify(struct omci_api_ctx *ctx,
				  const uint16_t port_index,
				  const uint8_t ext_vlan_enable_egress,
				  const uint8_t ext_vlan_index_egress,
				  const uint8_t ext_vlan_enable_ingress,
				  const uint8_t ext_vlan_index_ingress,
				  const uint8_t ext_vlan_incremental_enable);

enum omci_api_return
omci_api_lan_port_mc_ext_vlan_modify(struct omci_api_ctx *ctx,
				     const uint16_t port_index,
				     const uint8_t ext_vlan_mc_enable_egress,
				     const uint8_t ext_vlan_mc_enable_ingress);

enum omci_api_return omci_api_lan_port_enable(struct omci_api_ctx *ctx,
					      const uint16_t port_index,
					      const uint8_t enable);

enum omci_api_return omci_api_op_state_get(struct omci_api_ctx *ctx,
					   const uint16_t gpix,
					   const uint8_t direction,
					   uint8_t *op_state);

enum omci_api_return
omci_api_pmapper_add(struct omci_api_ctx *ctx,
		     const uint16_t pmapper_index,
		     const uint32_t *gpix,
		     const uint16_t unmarked_frame_option,
		     const uint16_t default_priority_marking,
		     const uint16_t dscp_profile_index);

enum omci_api_return
omci_api_pmapper_get(struct omci_api_ctx *ctx,
		     const uint16_t pmapper_index,
		     uint32_t *gpix,
		     uint8_t *unmarked_frame_option,
		     uint8_t *default_priority_marking,
		     uint8_t *dscp_profile_index);

enum omci_api_return
omci_api_dscp_profile_add(struct omci_api_ctx *ctx,
			  const uint16_t dscp_profile_index,
			  const uint8_t *pcp);

enum omci_api_return omci_api_pmapper_remove(struct omci_api_ctx *ctx,
					     const uint16_t pmapper_index);

/** @} */
