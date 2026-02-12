/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_gem_interworking_tp.c

   \todo clarify verifying of Interworking termination point pointer
*/
#include "ifxos_time.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_gem_interworking_tp.h"
#include "me/omci_gem_port_network_ctp.h"
#include "me/omci_api_gem_interworking_tp.h"
#include "me/omci_mac_bridge_port_config_data.h"

/** \addtogroup OMCI_ME_GEM_INTERWORKING_TP
   @{
*/

static enum omci_error op_state_change(struct omci_context *context,
				       struct timeout *timeout)
{
	enum omci_error error;
	struct me *me = NULL;

	if (context == NULL) {
		dbg_err("%s: ctx pointer invalid", __func__);
		return OMCI_SUCCESS;
	}

	mib_lock_read(context);

	error = mib_me_find(context, OMCI_ME_GEM_INTERWORKING_TP,
			    (uint16_t)timeout->arg1, &me);
	if (error)
		goto exit;

	if (me != NULL) {
		me_lock(context, me);
		error = avc_send(context, me,
				 omci_me_gem_interworking_tp_oper_state);
		me_unlock(context, me);
		if (error)
			goto exit;
	} else {
		dbg_err("%s: ctx pointer invalid", __func__);
	}

exit:
	mib_unlock(context);

	if (error)
		RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask, const void *data)
{
	struct omci_me_gem_interworking_tp *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_gem_interworking_tp *)data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
			    upd_data->gem_port_network_ctp_ptr, NULL);

	if (error) {
		*exec_mask |=
			omci_attr2mask(omci_me_gem_interworking_tp_gem_port_network_ctp_ptr);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Walker which finds MAC bridge port config data associated with
    PPTP Ethernet UNI

  \param[in]     context     OMCI context pointer
  \param[in]     me          Managed Entity pointer
  \param[in,out] shared_data Data shared between all calls
*/
static enum omci_error me_walker_1(struct omci_context *context,
				   struct me *me,
				   void *shared_data)
{
	uint16_t bridge_me_id;
	enum omci_error error;
	struct bridge_data *bridge_data = (struct bridge_data *)shared_data;

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			     &bridge_me_id, sizeof(bridge_me_id));
	RETURN_IF_ERROR(error);

	if (bridge_me_id != bridge_data->me_id)
		return OMCI_SUCCESS;

	if (bridge_data->count < BRIDGE_DATA_PORT) {
		bridge_data->port[bridge_data->count].me_id = me->instance_id;

		error = me_attr_read(context, me,
				     omci_me_mac_bridge_port_config_data_tp_type,
				     &bridge_data->port[bridge_data->count].tp_type,
				     sizeof(uint8_t));
		RETURN_IF_ERROR(error);

		error = me_attr_read(context, me,
				     omci_me_mac_bridge_port_config_data_tp_ptr,
				     &bridge_data->port[bridge_data->count].tp_ptr,
				     sizeof(uint16_t));
		RETURN_IF_ERROR(error);

		bridge_data->count++;
	}

	return OMCI_SUCCESS;
}

static enum omci_error me_walker_5(struct omci_context *context,
				   struct me *me,
				   void *shared_data)
{
	enum omci_error error;
	struct bridge_data *bridge_data = (struct bridge_data *)shared_data;
	uint8_t tp_type;
	uint16_t tp_ptr, bridge_me_id;

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			     &bridge_me_id, sizeof(bridge_me_id));
	RETURN_IF_ERROR(error);

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_tp_type,
			     &tp_type, sizeof(tp_type));
	RETURN_IF_ERROR(error);

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_tp_ptr,
			     &tp_ptr, sizeof(tp_ptr));
	RETURN_IF_ERROR(error);

	if (tp_type != 3)
		return OMCI_SUCCESS;

	if (tp_ptr != bridge_data->me_id)
		return OMCI_SUCCESS;

	if (bridge_data->count < BRIDGE_DATA_PORT) {
		bridge_data->me_id = bridge_me_id;

		bridge_data->port[bridge_data->count].me_id = me->instance_id;

		error = me_attr_read(context, me,
				     omci_me_mac_bridge_port_config_data_tp_type,
				     &bridge_data->port[bridge_data->count].tp_type,
				     sizeof(uint8_t));
		RETURN_IF_ERROR(error);

		error = me_attr_read(context, me,
				     omci_me_mac_bridge_port_config_data_tp_ptr,
				     &bridge_data->port[bridge_data->count].tp_ptr,
				     sizeof(uint16_t));
		RETURN_IF_ERROR(error);
		/* stop walking, at least one BP of the specified pmapper
		   was found*/
		bridge_data->count = BRIDGE_DATA_PORT;
	}

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	enum omci_error error;
	struct me *gem_port_nw_ctp_me;
	struct me *bridge_me;
	uint16_t gem_port_id;
	struct omci_me_gem_interworking_tp *upd_data;
	struct omci_me_gem_interworking_tp *me_data;
	struct bridge_data bridge_data;

	memset(&bridge_data, 0xff, sizeof(bridge_data));
	bridge_data.count = 0;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_gem_interworking_tp *)data;
	me_data = (struct omci_me_gem_interworking_tp *)me->data;

	if (upd_data->gem_port_network_ctp_ptr == 0) {
		return OMCI_SUCCESS;
	}

	error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
			    upd_data->gem_port_network_ctp_ptr,
			    &gem_port_nw_ctp_me);
	RETURN_IF_ERROR(error);

	me_lock(context, gem_port_nw_ctp_me);
	error = me_attr_read(context, gem_port_nw_ctp_me,
			     omci_me_gem_port_network_ctp_gem_port_id,
			     &gem_port_id, sizeof(gem_port_id));
	me_unlock(context, gem_port_nw_ctp_me);
	RETURN_IF_ERROR(error);

	switch (upd_data->interworking_option) {

		case 0x01:
		bridge_data.me_id = upd_data->service_profile_ptr;
		error = mib_walk_by_class(context,
					  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
					  me_walker_1, &bridge_data);
		RETURN_IF_ERROR(error);
		break;

		case 0x05:
		/* find the corresponding Bridge Port and get Bridge ID*/
		bridge_data.me_id = upd_data->service_profile_ptr;
		error = mib_walk_by_class(context,
					  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
					  me_walker_5, &bridge_data);
		RETURN_IF_ERROR(error);

		if (!bridge_data.count)
			/* not found*/
			break;

		/* start another search within tge found Bridge*/
		bridge_data.count = 0;
		error = mib_walk_by_class(context,
					  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
					  me_walker_1, &bridge_data);
		RETURN_IF_ERROR(error);
		break;

		case 0x06:
		/*
		the same as in option 1 - but loop over all bridges
		--> max 8 ports */
		break;
	}

	ret = omci_api_gem_interworking_tp_update(context->api,
						  me->instance_id,
						  gem_port_id,
						  upd_data->interworking_option,
						  upd_data->service_profile_ptr,
						  upd_data->interworking_tp_ptr,
						  upd_data->gal_loopback_config,
						  &bridge_data);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

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

	error = timeout_event_add(context, NULL, 2000,
				  op_state_change,
				  me->class->class_id,
				  me->instance_id,
				  me->instance_id, 0, 0);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);

	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	uint16_t gem_port_id;
	struct me *gem_port_nw_ctp_me;
	struct omci_me_gem_interworking_tp *me_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_data = (struct omci_me_gem_interworking_tp *)me->data;

	error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
			    me_data->gem_port_network_ctp_ptr,
			    &gem_port_nw_ctp_me);
	RETURN_IF_ERROR(error);

	me_lock(context, gem_port_nw_ctp_me);
	error = me_attr_read(context, gem_port_nw_ctp_me,
			     omci_me_gem_port_network_ctp_gem_port_id,
			     &gem_port_id, sizeof(gem_port_id));
	me_unlock(context, gem_port_nw_ctp_me);
	RETURN_IF_ERROR(error);

	ret = omci_api_gem_interworking_tp_destroy(context->api,
						   me->instance_id, gem_port_id,
						   me_data->interworking_option,
						   me_data->service_profile_ptr);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t interworking_option_cp[] = { 1, 5, 6 };
static uint16_t gal_loopback_config_cp[] = { 0, 1 };

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 0 };
#endif

/** Get operational state

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error op_state_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
	enum omci_api_return ret;
	enum omci_error error;
	struct me *gem_port_nw_ctp_me;
	uint16_t gem_port_id;
	struct omci_me_gem_interworking_tp *me_data;
	assert(data_size == 1);

	me_data = (struct omci_me_gem_interworking_tp *)me->data;

	error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
			    me_data->gem_port_network_ctp_ptr,
			    &gem_port_nw_ctp_me);
	RETURN_IF_ERROR(error);

	me_lock(context, gem_port_nw_ctp_me);
	error = me_attr_read(context, gem_port_nw_ctp_me,
			     omci_me_gem_port_network_ctp_gem_port_id,
			     &gem_port_id, sizeof(gem_port_id));
	me_unlock(context, gem_port_nw_ctp_me);
	RETURN_IF_ERROR(error);

	ret =  omci_api_gem_interworking_tp_op_state_get(context->api,
							 me->instance_id,
							 gem_port_id,
							 data);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_gem_interworking_tp_class = {
	/* Class ID */
	OMCI_ME_GEM_INTERWORKING_TP,
	/* Attributes */
	{
		/* 1. GEM port network CTP connectivity pointer */
		ATTR_PTR("GEM port network CTP ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_interworking_tp,
				  gem_port_network_ctp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 2. Interworking option */
		ATTR_ENUM("Interworking option",
			  ATTR_SUPPORTED,
			  interworking_option_cp,
			  offsetof(struct omci_me_gem_interworking_tp,
				   interworking_option),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Service profile pointer */
		ATTR_PTR("Service profile ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_interworking_tp,
				  service_profile_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 4. Interworking termination point pointer */
		ATTR_PTR("Interworking TP ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_interworking_tp,
				  interworking_tp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 5. PPTP counter */
		ATTR_UINT("PPTP counter",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_gem_interworking_tp,
				   pptp_counter),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6. Operational state */
		ATTR_BOOL("Operational state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_gem_interworking_tp,
				   oper_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_OPTIONAL,
			  op_state_get),
		/* 7. GAL profile pointer */
		ATTR_PTR("GAL profile ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_interworking_tp,
				  gal_profile_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 8. GAL loopback configuration */
		ATTR_ENUM("GAL loopback config",
			  ATTR_SUPPORTED,
			  gal_loopback_config_cp,
			  offsetof(struct omci_me_gem_interworking_tp,
				   gal_loopback_config),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 9-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
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
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_gem_interworking_tp),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"GEM interworking TP",
		/* Access */
		ME_CREATED_BY_OLT,
		/* Supported alarms */
		alarm_table,
		/* Supported alarms count */
		sizeof(alarm_table) / sizeof(alarm_table[0]),
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
