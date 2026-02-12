/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_sip_agent_config_data.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_sip_agent_config_data.h"
#include "me/omci_large_string.h"
#include "me/omci_tcp_udp_config_data.h"
#include "me/omci_network_address.h"
#include "me/omci_ip_host_config_data.h"
#include "me/omci_api_sip_agent_config_data.h"

#ifdef INCLUDE_OMCI_ONU_VOIP

/** \addtogroup OMCI_SIP_AGENT_CONFIG_DATA
   @{
*/

/** Structure that implements Tone Pattern Table */
struct sip_response_table_list_entry {
	/** Table entry */
	struct omci_sip_response_table table_entry;
	/** Next entry */
	struct sip_response_table_list_entry *next;
	/** Previous entry */
	struct sip_response_table_list_entry *prev;
};

/** Internal data */
struct internal_data {
	/** SIP Response Table (list head) */
	struct sip_response_table_list_entry list_head;
	/** Number of entries in the SIP Response Table */
	size_t entries_num;
};

/** Add/Remove SIP Response Table Entry

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static enum omci_error
sip_response_table_entry_set(struct omci_context *context,
			     struct me *me,
			     struct omci_sip_response_table *entry)
{
	struct internal_data *me_internal_data;
	struct sip_response_table_list_entry *list_entry;
	struct sip_response_table_list_entry *next_list_entry;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *) me->internal_data;

	entry->sip_response_code = ntoh16(entry->sip_response_code);
	entry->text_message = ntoh16(entry->text_message);

	if (entry->sip_response_code == 0) {
		/* clear table */
		me_dbg_msg(me, "Table clear");

		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);

			--me_internal_data->entries_num;

			IFXOS_MemFree(list_entry);
			list_entry = NULL;

			me_dbg_prn(me, "Removed table entry "
				   "(entries num = %lu)",
				   me_internal_data->entries_num);
		}
	} else {
		/* add entry */
		me_dbg_msg(me, "Entry add");

		/* insert new entry to the head */
		list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
		RETURN_IF_MALLOC_ERROR(list_entry);

		++me_internal_data->entries_num;

		memcpy(&list_entry->table_entry,
		       entry, sizeof(list_entry->table_entry));

		DLIST_ADD_TAIL(list_entry,
			       &me_internal_data->list_head);

		me_dbg_prn(me, "Added table entry (entries num = %lu)",
			   me_internal_data->entries_num);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error sip_response_tbl_copy(struct omci_context *context,
					     struct me *me,
					     unsigned int attr,
					     struct tbl_copy_entry *tbl_copy)
{
	struct internal_data *me_internal_data;
	struct sip_response_table_list_entry *list_entry;
	struct omci_sip_response_table *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, 0x%p", (void *)context, (void *)me,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *) me->internal_data;

	tbl_copy->data_size =
		sizeof(struct omci_sip_response_table)
			* me_internal_data->entries_num;
	if (tbl_copy->data_size) {
		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
	
		tbl_entry = (struct omci_sip_response_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {

			memcpy(tbl_entry, &list_entry->table_entry,
			       sizeof(*tbl_entry));

			tbl_entry->sip_response_code =
				ntoh16(tbl_entry->sip_response_code);
			tbl_entry->text_message =
				ntoh16(tbl_entry->text_message);

			++tbl_entry;
		}
	}

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	enum omci_error error;
	struct omci_sip_agent_config_data *upd_data;
	struct omci_sip_agent_config_data *me_data;
	struct me *proxy_me, *tcp_udp_me, *ip_host_me, *host_part_uri_me,
		  *registrar_me, *registrar_string_me;
	char proxy[OMCI_ME_LARGE_STRING_SIZE] = { 0 };
	char host_part_uri[OMCI_ME_LARGE_STRING_SIZE] = { 0 };
	char registrar[OMCI_ME_LARGE_STRING_SIZE] = { 0 };
	uint16_t port = 0;
	uint8_t proto = 0;
	uint32_t addr = 0;
	uint16_t ip_host_ptr;
	uint16_t registrar_ptr;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_sip_agent_config_data *) data;
	me_data = (struct omci_sip_agent_config_data *) me->data;

	if (attr_mask &
	    omci_attr2mask(omci_sip_agent_config_data_sip_response)) {
		error = sip_response_table_entry_set(
				context, me, &upd_data->sip_response);
		RETURN_IF_ERROR(error);
	}

	error = mib_me_find(context,
			    OMCI_ME_LARGE_STRING,
			    upd_data->proxy_ptr,
			    &proxy_me);

	if (error == OMCI_SUCCESS) {
		me_lock(context, proxy_me);
		large_string_get(context, proxy_me, proxy);
		me_unlock(context, proxy_me);
	}

	error = mib_me_find(context,
			    OMCI_ME_TCP_UDP_CONFIG_DATA,
			    upd_data->tcp_udp_ptr,
			    &tcp_udp_me);

	if (error == OMCI_SUCCESS) {
		me_lock(context, tcp_udp_me);

		error = me_attr_read(context, tcp_udp_me,
				     omci_me_tcp_udp_config_data_port_id,
				     &port, sizeof(port));
		if (error) {
			me_unlock(context, tcp_udp_me);
			RETURN_IF_ERROR(error);
		}

		error = me_attr_read(context, tcp_udp_me,
				     omci_me_tcp_udp_config_data_protocol,
				     &proto, sizeof(proto));
		if (error) {
			me_unlock(context, tcp_udp_me);
			RETURN_IF_ERROR(error);
		}

		error = me_attr_read(context, tcp_udp_me,
				     omci_me_tcp_udp_config_data_ip_host_ptr,
				     &ip_host_ptr, sizeof(ip_host_ptr));
		if (error) {
			me_unlock(context, tcp_udp_me);
			RETURN_IF_ERROR(error);
		}

		error = mib_me_find(context,
				    OMCI_ME_IP_HOST_CONFIG_DATA,
				    ip_host_ptr,
				    &ip_host_me);
		if (error) {
			me_unlock(context, tcp_udp_me);
			RETURN_IF_ERROR(error);
		}

		me_unlock(context, tcp_udp_me);

		me_lock(context, ip_host_me);
		error = me_attr_read(context, ip_host_me,
				     omci_me_ip_host_config_data_ip_address,
				     &addr, sizeof(addr));
		me_unlock(context, ip_host_me);
		RETURN_IF_ERROR(error);
	}

	error = mib_me_find(context,
			    OMCI_ME_LARGE_STRING,
			    upd_data->host_part_uri,
			    &host_part_uri_me);

	if (error == OMCI_SUCCESS) {
		me_lock(context, host_part_uri_me);
		large_string_get(context, host_part_uri_me,
				 host_part_uri);
		me_unlock(context, host_part_uri_me);
	}

	error = mib_me_find(context,
			    OMCI_ME_NETWORK_ADDRESS,
			    upd_data->sip_registrar,
			    &registrar_me);

	if (error == OMCI_SUCCESS) {
		me_lock(context, registrar_me);
		error = me_attr_read(context, registrar_me,
				     omci_me_network_address_address_ptr,
				     &registrar_ptr, sizeof(registrar_ptr));
		me_unlock(context, registrar_me);
		RETURN_IF_ERROR(error);

		error = mib_me_find(context,
				    OMCI_ME_LARGE_STRING,
				    registrar_ptr,
				    &registrar_string_me);
		if (error == OMCI_SUCCESS) {
			me_lock(context, registrar_string_me);
			large_string_get(context, registrar_string_me,
					 registrar);
			me_unlock(context, registrar_string_me);
		}
	}

	ret = omci_api_sip_agent_config_data_update(context->api,
						    me->instance_id,
						    proxy,
						    upd_data->primary_sip_dns,
						    upd_data->secondary_sip_dns,
						    addr,
						    proto,
						    port,
						    upd_data->ip_reg_exp_time,
						    upd_data->
						      sip_rereg_head_start_time,
						    host_part_uri,
						    registrar);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	me_internal_data = (struct internal_data *) me->internal_data;

	DLIST_HEAD_INIT(&me_internal_data->list_head);
	me_internal_data->entries_num = 0;

	RETURN_IF_PTR_NULL(init_data);

	error = me_data_write(context, me, init_data, me->class->data_size,
			      me->class->sbc_attr_mask, suppress_avc);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct sip_response_table_list_entry *list_entry;
	struct sip_response_table_list_entry *next_list_entry;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_internal_data = (struct internal_data *) me->internal_data;

	ret = omci_api_sip_agent_config_data_destroy(context->api,
						     me->instance_id);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	/* clear ringing event table */
	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->list_head) {
		/* remove entry */
		DLIST_REMOVE(list_entry);

		--me_internal_data->entries_num;

		IFXOS_MemFree(list_entry);
		list_entry = NULL;

		me_dbg_prn(me, "Removed sip response table entry "
			       "(entries num = %lu)",
					me_internal_data->entries_num);
	}

	IFXOS_MemFree(me->internal_data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_sip_agent_config_data_class = {
	/* Class ID */
	OMCI_ME_SIP_AGENT_CONFIG_DATA,
	/* Attributes */
	{
		ATTR_PTR("Proxy server",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_agent_config_data,
				  proxy_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Outbound proxy server",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_agent_config_data,
				  outbound_proxy_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_UINT("Primary SIP DNS",
			  ATTR_SUPPORTED,
			  0,
			  0xffffffff,
			  offsetof(struct omci_sip_agent_config_data,
				   primary_sip_dns),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Secondary SIP DNS",
			  ATTR_SUPPORTED,
			  0,
			  0xffffffff,
			  offsetof(struct omci_sip_agent_config_data,
				   secondary_sip_dns),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_PTR("TCP/UDP pointer",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_agent_config_data,
				  tcp_udp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		ATTR_UINT("IP reg exp time",
			  ATTR_SUPPORTED,
			  0,
			  0xffffffff,
			  offsetof(struct omci_sip_agent_config_data,
				   ip_reg_exp_time),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		ATTR_UINT("SIP rereg head start time",
			  ATTR_SUPPORTED,
			  0,
			  0xffffffff,
			  offsetof(struct omci_sip_agent_config_data,
				   sip_rereg_head_start_time),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		ATTR_PTR("Host part URI",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_agent_config_data,
				  host_part_uri),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_UINT("SIP status",
			  ATTR_SUPPORTED,
			  0,
			  0xff,
			  offsetof(struct omci_sip_agent_config_data,
				   sip_status),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		ATTR_PTR("SIP registrar",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_agent_config_data,
				  sip_registrar),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_UINT("Softswitch",
			  ATTR_SUPPORTED,
			  0,
			  0xffffffff,
			  offsetof(struct omci_sip_agent_config_data,
				   softswitch),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_TBL("Code points table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_sip_agent_config_data,
				  sip_response),
			 5,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		ATTR_BOOL("SIP option tx control",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_sip_agent_config_data,
				   sip_option_transmit_control),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("SIP URI format",
			  ATTR_SUPPORTED,
			  0,
			  0xff,
			  offsetof(struct omci_sip_agent_config_data,
				   sip_uri_format),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
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
	default_me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	sip_response_tbl_copy,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_sip_agent_config_data),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"SIP agent config data",
		/* Access */
		ME_CREATED_BY_OLT,
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

#endif
