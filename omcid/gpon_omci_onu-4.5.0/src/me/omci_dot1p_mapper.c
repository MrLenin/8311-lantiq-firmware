/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_dot1p_mapper.c
*/

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_dot1p_mapper.h"
#include "me/omci_api_dot1p_mapper.h"
#include "me/omci_gem_interworking_tp.h"
#include "me/omci_gem_port_network_ctp.h"
#include "me/omci_mac_bridge_port_config_data.h"
#include "me/omci_api_mac_bridge_port_config_data.h"

/** \addtogroup OMCI_ME_DOT1P_MAPPER
    @{
*/

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_dot1p_mapper *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_dot1p_mapper *) data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	switch (upd_data->tp_type) {
	case 0x00:
		if (upd_data->tp_ptr != 0xffff)
			error = OMCI_ERROR;

		break;

	case 0x01:
		error = mib_me_find(context, OMCI_ME_PPTP_ETHERNET_UNI,
				    upd_data->tp_ptr, NULL);

		break;

	case 0x02:
		error = mib_me_find(context, OMCI_ME_IP_HOST_CONFIG_DATA,
				    upd_data->tp_ptr, NULL);

		break;

	case 0x03:
		error = mib_me_find(context, OMCI_ME_ETHERNET_FLOW_TP,
				    upd_data->tp_ptr, NULL);

		break;

	case 0x04:
		error = mib_me_find(context, OMCI_ME_PPTP_XDSL_UNI_1,
				    upd_data->tp_ptr, NULL);

		break;

	case 0x05:
		error = mib_me_find(context, OMCI_ME_PPTP_80211_UNI,
				    upd_data->tp_ptr, NULL);

		break;

	case 0x06:
		error = mib_me_find(context, OMCI_ME_PPTP_MOCA_UNI,
				    upd_data->tp_ptr, NULL);

		break;

	default:
		error = OMCI_ERROR;
		break;
	}

	if (error) {
		*exec_mask |= omci_attr2mask(omci_me_dot1p_mapper_tp_ptr);
		*exec_mask |= omci_attr2mask(omci_me_dot1p_mapper_tp_type);
	}

	/** \todo validate DSCP to P-bit mapping ?! */

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Walker which finds MAC bridge port config data associated with the specified
    p-mapper.

  \param[in]     context     OMCI context pointer
  \param[in]     me          Managed Entity pointer
  \param[in,out] shared_data Data shared between all calls
*/
static enum omci_error find_pmapper_bridge_port(struct omci_context *context,
				 struct me *me,
				 void *shared_data)
{
	uint8_t tp_type;
	uint16_t tp_ptr;
	enum omci_error error;
	struct pmapper_data *pmapper =
		(struct pmapper_data *)shared_data;

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_tp_type,
			     &tp_type, sizeof(tp_type));
	RETURN_IF_ERROR(error);

	if (tp_type != 3)
		return OMCI_SUCCESS;

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_tp_ptr,
			     &tp_ptr, sizeof(tp_ptr));
	RETURN_IF_ERROR(error);

	if (tp_ptr != pmapper->me_id)
		return OMCI_SUCCESS;

	if (pmapper->count >= 8)
		return OMCI_SUCCESS;

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			     &pmapper->bridge_me_id[pmapper->count],
			     sizeof(uint16_t));
	RETURN_IF_ERROR(error);

	pmapper->bridge_port_me_id[pmapper->count++] = me->instance_id;

	return OMCI_SUCCESS;
}

/** Walker which finds MAC bridge ports config data associated with
    a given bridge

  \param[in]     context     OMCI context pointer
  \param[in]     me          Managed Entity pointer
  \param[in,out] shared_data Data shared between all calls
*/
enum omci_error find_bridge_ports(struct omci_context *context,
				 struct me *me,
				 void *shared_data)
{
	uint16_t bridge_me_id;
	enum omci_error error;
	struct bridge_data *data = (struct bridge_data *)shared_data;

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			     &bridge_me_id, sizeof(bridge_me_id));
	RETURN_IF_ERROR(error);

	if (bridge_me_id != data->me_id)
		return OMCI_SUCCESS;

	if (data->count < BRIDGE_DATA_PORT) {
		data->port[data->count].me_id = me->instance_id;

		error = me_attr_read(context, me,
				     omci_me_mac_bridge_port_config_data_tp_type,
				     &data->port[data->count].tp_type,
				     sizeof(uint8_t));
		RETURN_IF_ERROR(error);

		error = me_attr_read(context, me,
				     omci_me_mac_bridge_port_config_data_tp_ptr,
				     &data->port[data->count].tp_ptr,
				     sizeof(uint16_t));
		RETURN_IF_ERROR(error);

		data->count++;
	}

	return OMCI_SUCCESS;
}

static enum omci_error pmapper_walker(struct omci_context *context, const uint32_t me_id)
{
	uint16_t i,k;
	enum omci_error error;
	struct pmapper_data pmapper;
	struct bridge_data bridge;

	pmapper.count = 0;
	pmapper.me_id = me_id;
	error = mib_walk_by_class(context,
				  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				  find_pmapper_bridge_port, &pmapper);
	RETURN_IF_ERROR(error);

	for (k=0;k<pmapper.count;k++) {
		bridge.me_id = pmapper.bridge_me_id[k];
		bridge.count = 0;
		error = mib_walk_by_class(context,
					  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
					  find_bridge_ports, &bridge);
		RETURN_IF_ERROR(error);
		for (i=0;i<bridge.count;i++) {
			switch (bridge.port[i].tp_type) {
			case 1:
				omci_api_mac_bridge_port_config_data_uni(context->api,
							bridge.me_id,
							bridge.port[i].me_id,
							bridge.port[i].tp_ptr);
				break;
			case 3:
				omci_api_mac_bridge_port_config_data_pmapper(context->api,
							pmapper.bridge_me_id[k],
							pmapper.bridge_port_me_id[k],
							pmapper.me_id);
				break;
			}
		}
	}

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	uint16_t gem_port_id[8];
	enum omci_error error;
	struct omci_dot1p_mapper *upd_data;
	struct omci_dot1p_mapper *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_dot1p_mapper *) data;
	me_data = (struct omci_dot1p_mapper *) me->data;

	gem_port_id[0] = upd_data->interwork_tp_ptr0;
	gem_port_id[1] = upd_data->interwork_tp_ptr1;
	gem_port_id[2] = upd_data->interwork_tp_ptr2;
	gem_port_id[3] = upd_data->interwork_tp_ptr3;
	gem_port_id[4] = upd_data->interwork_tp_ptr4;
	gem_port_id[5] = upd_data->interwork_tp_ptr5;
	gem_port_id[6] = upd_data->interwork_tp_ptr6;
	gem_port_id[7] = upd_data->interwork_tp_ptr7;

	ret = omci_api_8021p_mapper_service_profile_update(context->api,
							   me->instance_id,
							   upd_data->tp_ptr,
							   gem_port_id,
							   upd_data->
							   unmarked_frame_option,
							   upd_data->
							   dscp_to_pbit_mapping,
							   upd_data->
							   default_pbit_mapping,
							   upd_data->tp_type);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "can't update");
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	error = pmapper_walker(context, me->instance_id);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	error = default_me_init(context, me, init_data, suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	struct omci_dot1p_mapper *me_data;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_data = (struct omci_dot1p_mapper *) me->data;

	ret = omci_api_8021p_mapper_service_profile_destroy(context->api,
							    me->instance_id,
							    0,
							    me_data->tp_type);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t unmarked_frame_option_cp[] = { 0, 1 };
static uint16_t tp_type_cp[] = { 0, 1, 2, 3, 4, 5, 6 };

/** Managed Entity class */
struct me_class me_dop1p_mapper_class = {
	/* Class ID */
	OMCI_ME_DOT1P_MAPPER_SERVICE_PROFILE,
	/* Attributes */
	{
		/* 1. Termination Point Pointer  */
		ATTR_PTR("TP ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  tp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 2. Interwork Termination Point pointer for P-bit priority 0
		*/
		ATTR_PTR("Interwork TP ptr prio 0",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  interwork_tp_ptr0),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. Interworking Termination Point Pointer for P-bit
		   Priority 1 */
		ATTR_PTR("Interwork TP ptr prio 1",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  interwork_tp_ptr1),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 4. Interworking Termination Point Pointer for P-bit
		   Priority 2 */
		ATTR_PTR("Interwork TP ptr prio 2",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  interwork_tp_ptr2),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 5. Interworking Termination Point Pointer for P-bit
		   Priority 3 */
		ATTR_PTR("Interwork TP ptr prio 3",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  interwork_tp_ptr3),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 6. Interworking Termination Point Pointer for P-bit
		   Priority 4 */
		ATTR_PTR("Interwork TP ptr prio 4",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  interwork_tp_ptr4),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 7. Interworking Termination Point Pointer for P-bit
		   Priority 5 */
		ATTR_PTR("Interwork TP ptr prio 5",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  interwork_tp_ptr5),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 8. Interworking Termination Point Pointer for P-bit
		   Priority 6 */
		ATTR_PTR("Interwork TP ptr prio 6",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  interwork_tp_ptr6),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 9. Interworking Termination Point Pointer for P-bit
		   Priority 7 */
		ATTR_PTR("Interwork TP ptr prio 7",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_dot1p_mapper,
				  interwork_tp_ptr7),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 10. Unmarked Frame Option */
		ATTR_ENUM("Unmarked frame option",
			  ATTR_SUPPORTED,
			  unmarked_frame_option_cp,
			  offsetof(struct omci_dot1p_mapper,
				   unmarked_frame_option),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 11. DSCP to P-bit Mapping */
		ATTR_STR("DSCP to P-bit mapping",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_dot1p_mapper,
				  dscp_to_pbit_mapping),
			 24,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 12. Default P-bit Marking */
		ATTR_UINT("Default P-bit marking",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_dot1p_mapper,
				   default_pbit_mapping),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 13. Termination Point Type */
		ATTR_ENUM("TP type",
			  ATTR_SUPPORTED,
			  tp_type_cp,
			  offsetof(struct omci_dot1p_mapper,
				   tp_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_PARTLY,
			  NULL),
		/* 14-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		create_action_handle,
		NULL,
		/* Delete */
		delete_action_handle,
		NULL,
		/* Set */
		set_action_handle,
		/* Get */
		get_action_handle,
		NULL,
		/* Get all alarms */
		NULL,
		/* Get all alarms next */
		NULL,
		/* MIB upload */
		NULL,
		/* MIB upload next */
		NULL,
		/* MIB reset */
		NULL,
		/* Alarm */
		NULL,
		/* Attribute value change */
		NULL,
		/* Test */
		NULL,
		/* Start SW download */
		NULL,
		/* Download section */
		NULL,
		/* End SW download */
		NULL,
		/* Activate software */
		NULL,
		/* Commit software */
		NULL,
		/* Synchronize Time */
		NULL,
		/* Reboot */
		NULL,
		/* Get next */
		NULL,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	NULL,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_dot1p_mapper),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"802.1p mapper service pro",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
