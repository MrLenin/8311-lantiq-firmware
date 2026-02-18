/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "ifxos_debug.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_print_io.h"
#include "ifxos_time.h"

#define DLOG(fmt, ...) do { \
	FILE *_df = fopen("/tmp/8311_mib.log", "a"); \
	if (_df) { fprintf(_df, fmt "\n", ##__VA_ARGS__); fclose(_df); } \
} while (0)

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_msg_dump.h"
#include "omci_debug.h"
#include "me/omci_pptp_ethernet_uni.h"
#include "me/omci_onu_power_shedding.h"
#include "mcc/omci_api_mcc.h"
#ifdef INCLUDE_MCC
#include "mcc/omci_mcc.h"
#endif
#include "omci_ubus.h"

/** \addtogroup OMCI_API
   @{
*/

static void ploam_state_change_cb(struct omci_context *context,
				  int prev_state,
				  int curr_state)
{
	DLOG("ploam_state_change: %d -> %d", prev_state, curr_state);
	dbg_in(__func__, "%d, %d", prev_state, curr_state);

	switch (curr_state) {
	case 0:
	case 1:
	case 2:
	case 7:
		context_lock(context);
		IFX_Var_Fifo_Clear(&context->msg_fifo.fifo);
		context_unlock(context);
		if (curr_state == 2) {
			DLOG("ploam_state_change: triggering mib_reset(false)");
			mib_reset(context, false);
			DLOG("ploam_state_change: mib_reset returned");
		}
		break;

	default:
		break;
	}

	dbg_out(__func__);
}

static void error_cb(struct omci_context *context,
		     uint16_t class_id,
		     uint16_t instance_id,
		     enum omci_api_action_type action,
		     enum omci_api_return ret)
{
	dbg_in(__func__, "%u, %u, %u, %d", class_id, instance_id, action, ret);

	dbg_err("ERROR(%d) in the %u@%u '%s action' handler",
		ret, class_id, instance_id,
		(action == OMCI_API_ACTION_CREATE)
		? "create" : (action == OMCI_API_ACTION_UPDATE)
		? "update" : "destroy");

	/* v4.5.0 had for(;;){} here which hangs the process.
	   v7.5.1 error_notify is a no-op (never fires this event),
	   but if it ever does, log and continue rather than hang. */
	{
		char _buf[128];
		int _n = snprintf(_buf, sizeof(_buf),
			"[omcid] ERROR: %u@%u '%s' ret=%d\n",
			class_id, instance_id,
			(action == OMCI_API_ACTION_CREATE)
			? "create" : (action == OMCI_API_ACTION_UPDATE)
			? "update" : "destroy", ret);
		if (_n > 0) write(STDERR_FILENO, _buf, _n);
	}

	dbg_out(__func__);
}

static void link_state_cb(struct omci_context *context,
			  uint16_t instance_id,
			  bool state,
			  uint8_t config_ind)
{
	struct me *me;
	enum omci_error error;
	uint8_t admin_state;
	uint8_t oper_state = state ?
		OMCI_OPERATIONAL_STATE_ENABLED :
		OMCI_OPERATIONAL_STATE_DISABLED;
	uint8_t expected_type;
	uint8_t sensed_type;

	mib_lock_read(context);

	error = mib_me_find(context,
			    OMCI_ME_PPTP_ETHERNET_UNI,
			    instance_id,
			    &me);
	if (error) {
		dbg_err("ERROR(%d): "
			"Can't update link state for PPTP Ethernet UNI 0x%04x; "
			"ME not found", error, instance_id);
		goto unlock_mib;
	}

	me_lock(context, me);

	error = me_attr_read(context, me, omci_me_pptp_ethernet_uni_admin_state,
			     &admin_state,
			     sizeof(admin_state));

	/* we are not interested in reporting operational state change with
	 * administrative state locked */
	if (admin_state == OMCI_ADMINISTRATIVE_STATE_LOCKED &&
	    oper_state == OMCI_OPERATIONAL_STATE_ENABLED)
		goto unlock_me;

	error = me_attr_read(context, me, omci_me_pptp_ethernet_uni_expected_type,
			     &expected_type,
			     sizeof(expected_type));

	if (error) {
		dbg_err("ERROR(%d): "
			"Can't update link state for PPTP Ethernet UNI 0x%04x; "
			"expected type read failed", error, instance_id);
		goto unlock_me;
	}

	error = me_attr_write(context,
			      me,
			      omci_me_pptp_ethernet_uni_config_ind,
			      &config_ind,
			      sizeof(config_ind),
			      false);

	if (error) {
		dbg_err("ERROR(%d): "
			"Can't update link state for PPTP Ethernet UNI 0x%04x; "
			"config ind update failed", error, instance_id);
		goto unlock_me;
	}

	if (state) {
		if (expected_type)
			sensed_type = expected_type;
		else
			sensed_type = OMCI_CIRCUIT_PACK_TYPE_101001000BASET;
	} else {
		sensed_type = 0;
	}

	error = me_attr_write(context,
			      me,
			      omci_me_pptp_ethernet_uni_sensed_type,
			      &sensed_type,
			      sizeof(sensed_type),
			      false);

	if (error) {
		dbg_err("ERROR(%d): "
			"Can't update link state for PPTP Ethernet UNI 0x%04x; "
			"sensed type update failed", error, instance_id);
		goto unlock_me;
	}

	error = me_attr_write(context,
			      me,
			      omci_me_pptp_ethernet_uni_oper_state,
			      &oper_state,
			      sizeof(oper_state),
			      false);

	if (error) {
		dbg_err("ERROR(%d): "
			"Can't update link state for PPTP Ethernet UNI 0x%04x; "
			"operational state update failed", error, instance_id);
		goto unlock_me;
	}

	error = me_alarm_set(context, me,
			     omci_me_pptp_ethernet_uni_alarm_lan_los, !state);
	if (error) {
		dbg_err("ERROR(%d): "
			"Can't update alarm state for PPTP Ethernet UNI 0x%04x",
			error, instance_id);
		goto unlock_me;
	}

	me_unlock(context, me);
	mib_unlock(context);

	return;

unlock_me:
	me_unlock(context, me);

unlock_mib:
	mib_unlock(context);
}

static void event_cb(void *caller,
		     struct omci_api_event *event)
{
	struct omci_context *context = (struct omci_context *)caller;

	dbg_in(__func__, "%p, %p", caller, event);

	assert(caller);

	switch (event->type) {
	case OMCI_API_EVENT_ALARM:
		(void)omci_me_alarm_set(context,
					event->alarm.class_id,
					event->alarm.instance_id,
					event->alarm.alarm,
					event->alarm.active);
		break;

	case OMCI_API_EVENT_OMCI:
		(void)omci_msg_recv(context,
				    (const union omci_msg *)
				    event->omci.msg);

		break;

	case OMCI_API_EVENT_PLOAM_STATE:
		ploam_state_change_cb(context,
				      event->ploam_state.prev,
				      event->ploam_state.curr);

		break;

	case OMCI_API_EVENT_INTERVAL_END:
		(void)omci_interval_end(context,
					event->interval_end.interval_end_time);
		break;

	case OMCI_API_EVENT_ERROR:
		error_cb(context,
			 event->error.class_id,
			 event->error.instance_id,
			 event->error.action,
			 event->error.ret);

		break;

	case OMCI_API_EVENT_LINK_STATE:
		link_state_cb(context,
			      event->link_state.instance_id,
			      event->link_state.state,
			      event->link_state.config_ind);

		break;

	case OMCI_API_EVENT_AC_POWER_ON:
		ac_power_on_cb(context);
		break;

	case OMCI_API_EVENT_AC_POWER_OFF:
		ac_power_off_cb(context);
		break;

	default:
		dbg_wrn("Event %u was not handled", event->type);
		break;
	}

	dbg_out(__func__);
}

enum omci_error omci_init(struct omci_context **ref_context,
			  omci_mib_on_reset *mib_on_reset,
			  omci_cli_on_exec *cli_on_exec,
			  const enum omci_olt mib,
			  uint8_t omcc_version,
			  uint32_t iop_mask,
			  uint8_t lct_port)
{
	enum omci_error error;
	struct omci_context *context;
	struct omci_api_init_data omci_api_init_data;
	int _lfd;

	RETURN_IF_PTR_NULL(ref_context);
	RETURN_IF_PTR_NULL(mib_on_reset);

	_lfd = open("/tmp/omcid_init.log",
		    O_WRONLY | O_APPEND | O_CREAT, 0644);

#define ILOG(msg) do { \
	write(STDERR_FILENO, msg, sizeof(msg) - 1); \
	if (_lfd >= 0) { write(_lfd, msg, sizeof(msg) - 1); } \
} while (0)

	ILOG("[omcid] init: entered\n");

	dbg_in(__func__, "%p, %p, %p, %d, 0x%02x, 0x%08x, %u",
	       (void *)ref_context, (void *)mib_on_reset,
	       cli_on_exec, mib, omcc_version, iop_mask, lct_port);

	ILOG("[omcid] init: heap_check\n");
	heap_check_init();

	/* ensure that ref_context points to NULL */
	if (*ref_context != NULL) {
		dbg_err("ERROR(%d) ref_context "
			"should point to NULL"
			" in %s",
			OMCI_ERROR_INVALID_PTR, __func__);

		dbg_out_ret(__func__, OMCI_ERROR_INVALID_PTR);
		if (_lfd >= 0) close(_lfd);
		return OMCI_ERROR_INVALID_PTR;
	}

	/* ensure that ref_context is not NULL */
	RETURN_IF_PTR_NULL(ref_context);

#ifndef OMCI_DEBUG_DISABLE
	/* apply IFXOS debug level */
	omci_dbg_module_level_set(OMCI_DBG_MODULE_IFXOS,
				  dbg_modules[OMCI_DBG_MODULE_IFXOS].level);

	/* apply VoIP debug level */
	omci_dbg_module_level_set(OMCI_DBG_MODULE_VOIP,
				  dbg_modules[OMCI_DBG_MODULE_VOIP].level);
#endif

	ILOG("[omcid] init: alloc ctx\n");

	/* allocate context */
	context = IFXOS_MemAlloc(sizeof(struct omci_context));
	RETURN_IF_MALLOC_ERROR(context);

	ILOG("[omcid] init: dbg_in\n");
	dbg_prn("Using MIB for OLT #%d", mib);

	memset(context, 0, sizeof(struct omci_context));
	context->olt = mib;
	context->omcc_version = omcc_version;
	context->iop_mask = iop_mask;
	context->lct_port = lct_port;

	/** \todo get ONU ID */
	context->onu_id = 0x0012;
	context->failsafe = false;
	context->action_timeout = OMCI_DEFAUL_MAX_ACTION_TIMEOUT;

	ILOG("[omcid] init: lock\n");
	/* init context lock */
	error = lock_init(&context->lock);
	if (error)
		goto free_context;

	ILOG("[omcid] init: alarm_copy\n");
	/* init alarm copy */
	error = alarm_copy_init(context);
	if (error)
		goto delete_context_lock;

	ILOG("[omcid] init: mib_copy\n");
	/* init MIB copy */
	error = mib_copy_init(context);
	if (error)
		goto do_alarm_copy_shutdown;

	ILOG("[omcid] init: tbl_copy\n");
	/* init table attributes copy */
	error = tbl_copy_init(context);
	if (error)
		goto do_mib_copy_shutdown;

	ILOG("[omcid] init: msg_fifo\n");
	/* create received messages FIFO */
	error = msg_fifo_init(context);
	if (error)
		goto do_tbl_copy_shutdown;

	ILOG("[omcid] init: timeout\n");
	/* init timeout module and start timeout thread */
	error = timeout_init(context);
	if (error)
		goto do_msg_fifo_shutdown;

	ILOG("[omcid] init: events\n");
	context->mib_on_reset = mib_on_reset;
#ifdef INCLUDE_CLI_SUPPORT
	context->cli_on_exec = cli_on_exec;
#endif
	context->olt = OMCI_OLT_NSN;

	/* Initialize Action Event object*/
	if (IFXOS_EventInit(&context->action_event) != IFX_SUCCESS) {
		dbg_err("ERROR(%d): Action Event init failed", OMCI_ERROR);
		goto do_msg_fifo_shutdown;
	}

	/* Initialize Action Handled Event object (v7.5.1 addition) */
	if (IFXOS_EventInit(&context->action_handled_event) != IFX_SUCCESS) {
		dbg_err("ERROR(%d): Action Handled Event init failed",
			OMCI_ERROR);
		goto do_msg_fifo_shutdown;
	}

	/* Initialize Message Event object*/
	if (IFXOS_EventInit(&context->msg_event) != IFX_SUCCESS) {
		dbg_err("ERROR(%d): Message Event init failed", OMCI_ERROR);
		goto do_msg_fifo_shutdown;
	}

	/* called before the initial MIB was created */
	ILOG("[omcid] omci_api_init...\n");
	memset(&omci_api_init_data, 0, sizeof(omci_api_init_data));
	error = (enum omci_error)omci_api_init(&omci_api_init_data,
					       event_cb,
					       context,
					       NULL,
					       NULL,
					       &context->api);
	if (error) {
		dbg_err("ERROR(%d) OMCI API init error", error);
		goto do_timeout_shutdown;
	}

	/* create MIB */
	ILOG("[omcid] mib_create...\n");
	error = mib_create(context);
	if (error)
		goto do_omci_api_shutdown;

	/* called after the initial MIB was created */
	ILOG("[omcid] omci_api_start...\n");
	error = (enum omci_error)omci_api_start(context->api);
	if (error) {
		dbg_err("ERROR(%d) OMCI API start error", error);
		goto do_mib_destroy;
	}

#ifdef INCLUDE_MCC
	/* initialize multicast control — non-fatal, omcid must work without it */
	ILOG("[omcid] omci_mcc_init...\n");
	error = omci_mcc_init(context);
	if (error) {
		dbg_err("MCC init failed (%d), multicast disabled", error);
		error = OMCI_SUCCESS;
	}
#endif

	/* initialize ubus event monitoring — non-fatal */
	ILOG("[omcid] omci_ubus_init...\n");
	(void)omci_ubus_init(context);

	/* start core thread */
	ILOG("[omcid] core_thread_start...\n");
	error = core_thread_start(context);
	if (error)
		goto do_mcc_shutdown;

	/* start message handler thread */
	ILOG("[omcid] action_thread_start...\n");
	error = action_thread_start(context);
	if (error)
		goto do_core_thread_stop;

#ifdef INCLUDE_PM
	/* initialize performance monitoring */
	ILOG("[omcid] pm_init...\n");
	error = pm_init(context);
	if (error)
		goto do_pm_shutdown;
#endif

	/* start OMCI processing */
	ILOG("[omcid] omci_processing_enable...\n");
	(void)omci_processing_enable(context, true);

	/* store startup time */
	context->startup_time = IFXOS_ElapsedTimeMSecGet(0);

	/* point ref_context to allocated context */
	*ref_context = context;

	ILOG("[omcid] init complete\n");
	if (_lfd >= 0) close(_lfd);
	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;

#ifdef INCLUDE_PM
do_pm_shutdown:
	(void)pm_shutdown(context);
#endif

do_action_thread_destroy:
	(void)IFXOS_EventWakeUp(&context->action_event);
	(void)action_thread_stop(context);

do_core_thread_stop:
	(void)IFXOS_EventWakeUp(&context->msg_event);
	(void)core_thread_stop(context);

do_mcc_shutdown:
	omci_ubus_exit(context);
#ifdef INCLUDE_MCC
	(void)omci_mcc_exit(context);
#endif

do_mib_destroy:
	(void)mib_destroy(context);

do_omci_api_shutdown:
	(void)omci_api_shutdown(context->api);

do_timeout_shutdown:
	(void)timeout_shutdown(context);

do_msg_fifo_shutdown:
	(void)msg_fifo_shutdown(context);

do_tbl_copy_shutdown:
	(void)tbl_copy_shutdown(context);

do_mib_copy_shutdown:
	(void)mib_copy_shutdown(context);

do_alarm_copy_shutdown:
	(void)alarm_copy_shutdown(context);

delete_context_lock:
	(void)lock_delete(&context->lock);

	(void)IFXOS_EventDelete(&context->msg_event);
	(void)IFXOS_EventDelete(&context->action_event);
	(void)IFXOS_EventDelete(&context->action_handled_event);

free_context:
	IFXOS_MemFree(context);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error omci_shutdown(struct omci_context *context)
{
	if (context == NULL)
		return OMCI_SUCCESS;

	dbg_in(__func__, "%p", (void *)context);

	context->omci_shutdown_in_progress = true;

#ifdef INCLUDE_PM
	(void)pm_shutdown(context);
#endif
	omci_ubus_exit(context);
#ifdef INCLUDE_MCC
	(void)omci_mcc_exit(context);
#endif
	(void)IFXOS_EventWakeUp(&context->msg_event);
	(void)IFXOS_EventWakeUp(&context->action_handled_event);
	(void)core_thread_stop(context);
	(void)msg_fifo_shutdown(context);
	(void)timeout_shutdown(context);

	(void)IFXOS_EventWakeUp(&context->action_event);
	(void)action_thread_stop(context);

	(void)mib_copy_shutdown(context);
	(void)alarm_copy_shutdown(context);
	(void)tbl_copy_shutdown(context);

	mib_lock_write(context);
	(void)mib_destroy(context);
	mib_unlock(context);

	(void)omci_api_shutdown(context->api);

	(void)lock_delete(&context->lock);

	(void)IFXOS_EventDelete(&context->msg_event);
	(void)IFXOS_EventDelete(&context->action_event);
	(void)IFXOS_EventDelete(&context->action_handled_event);

	IFXOS_MemFree(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_version_info_get(struct omci_context *context,
				      struct omci_version *version)
{
	struct omci_api_ver_inf omci_api_ver;
	int ret;
	uint8_t ifxos_ver[3];

	dbg_in(__func__, "%p, %p", (void *)context, (void *)version);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(version);

	strcpy(version->omci_version, PACKAGE_VERSION);
	strcpy(version->firmware_version, "n/a");

	IFXOS_versionGet(&ifxos_ver[0], &ifxos_ver[1], &ifxos_ver[2]);
	(void)IFXOS_SNPrintf(version->ifxos_version,
			     sizeof(version->ifxos_version),
			     "%u.%u.%u", ifxos_ver[0], ifxos_ver[1],
			     ifxos_ver[2]);

	ret = omci_api_ver_inf_get(context->api, &omci_api_ver);
	if (!ret) {
		strcpy(version->onu_version, omci_api_ver.driver_version);
		strcpy(version->omci_api_version,
		       omci_api_ver.omci_api_version);
	} else {
		strcpy(version->onu_version, "n/a");
		strcpy(version->omci_api_version, "n/a");
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

#ifndef OMCI_DEBUG_DISABLE
enum omci_error omci_dbg_module_level_set(enum omci_dbg_module module,
					  enum omci_dbg level)
{
	dbg_in(__func__, "%d, %d", module, level);

	if (module > OMCI_DBG_MODULE_MAX) {
		dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
		return OMCI_ERROR_BOUNDS;
	}

	if (level > OMCI_DBG_LVL_MAX) {
		dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
		return OMCI_ERROR_BOUNDS;
	}

	if (module == OMCI_DBG_MODULE_IFXOS) {
		level = (level == OMCI_DBG_MSG) ? OMCI_DBG_PRN : level;
		IFXOS_PRN_USR_LEVEL_SET(IFXOS, level);
	}

	dbg_modules[module].level = level;

	if (module == OMCI_DBG_MODULE_API)
		omci_api_debug_level_set(OMCI_API_DBG_MODULE_API, level);

#ifdef INCLUDE_OMCI_ONU_VOIP
	if (module == OMCI_DBG_MODULE_VOIP)
		omci_api_debug_level_set(OMCI_API_DBG_MODULE_VOIP, level);
#endif
#ifdef LINUX
	if (module == OMCI_DBG_MODULE_MCC)
		omci_api_debug_level_set(OMCI_API_DBG_MODULE_MCC, level);
#endif

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}
#endif

#ifndef OMCI_DEBUG_DISABLE
enum omci_error omci_dbg_module_level_get(enum omci_dbg_module module,
					  enum omci_dbg *level)
{
	uint8_t tmp=0;

	dbg_in(__func__, "%d, %p", module, (void *)level);

	RETURN_IF_PTR_NULL(level);

	if (module > OMCI_DBG_MODULE_MAX) {
		*level = OMCI_DBG_LVL_MIN;

		dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
		return OMCI_ERROR_BOUNDS;
	}

	if (module == OMCI_DBG_MODULE_API) {
		omci_api_debug_level_get(OMCI_API_DBG_MODULE_API, &tmp);
		*level = (enum omci_dbg)tmp;
	} else if (module == OMCI_DBG_MODULE_VOIP) {
		omci_api_debug_level_get(OMCI_API_DBG_MODULE_VOIP, &tmp);
		*level = (enum omci_dbg)tmp;
	} else if (module == OMCI_DBG_MODULE_MCC) {
		omci_api_debug_level_get(OMCI_API_DBG_MODULE_MCC, &tmp);
		*level = (enum omci_dbg)tmp;
	} else {
		*level = dbg_modules[module].level;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}
#endif

#ifndef OMCI_DEBUG_DISABLE
enum omci_error omci_dbg_level_set(enum omci_dbg level)
{
	unsigned int module;

	dbg_in(__func__, "%d", level);

	if (level > OMCI_DBG_LVL_MAX) {
		dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
		return OMCI_ERROR_BOUNDS;
	}

	for (module = (unsigned int)OMCI_DBG_MODULE_MIN;
	     module <= (unsigned int)OMCI_DBG_MODULE_MAX; module++) {

		(void)omci_dbg_module_level_set(module, level);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}
#endif

enum omci_error omci_msg_recv(struct omci_context *context,
			      const union omci_msg *msg)
{
	union omci_msg *fifo_item;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)msg);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(msg);

	context_lock(context);

	fifo_item = (union omci_msg *)
		IFX_Var_Fifo_writeElement(&context->msg_fifo.fifo,
					  sizeof(union omci_msg));

	if (fifo_item == NULL) {
		context_unlock(context);

		dbg_out_ret(__func__, OMCI_ERROR_MSG_FIFO_FULL);
		return OMCI_ERROR_MSG_FIFO_FULL;
	}

	memcpy(fifo_item, msg, sizeof(union omci_msg));

	context_unlock(context);

	/* Wakeup message event */	
	if (IFXOS_EventWakeUp(&context->msg_event) < IFX_SUCCESS)
		dbg_err("omci_msg_recv - message event wakeup failed");

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_msg_send(struct omci_context *context,
			      const union omci_msg *msg)
{
	enum omci_error error;
#ifndef OMCI_DEBUG_DISABLE
	unsigned long omci_counter;
#endif

	dbg_in(__func__, "%p, %p", (void *)context, (void *)msg);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(msg);

	context_lock(context);

#ifndef OMCI_DEBUG_DISABLE
	context->omci_sent++;
	msg_dump(context, "TX:", msg, context->omci_sent);
#endif
	error = (enum omci_error)omci_api_msg_send(context->api, 
		(const uint8_t *)msg, 40);

	context_unlock(context);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_alarm_set(struct omci_context *context,
				  uint16_t class_id,
				  uint16_t instance_id,
				  unsigned int alarm,
				  bool active)
{
	struct me *me;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %u, %u", (void *)context, class_id,
	       instance_id, alarm, (unsigned int)active);

	RETURN_IF_PTR_NULL(context);

	mib_lock_read(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error)
		goto unlock_mib;

	me_lock(context, me);
	error = me_alarm_set(context, me, (uint8_t)alarm, active);
	me_unlock(context, me);

	if (error)
		goto unlock_mib;

	mib_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;

unlock_mib:
	mib_unlock(context);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error omci_me_alarm_get(struct omci_context *context,
				  uint16_t class_id,
				  uint16_t instance_id,
				  unsigned int alarm,
				  bool *active)
{
	struct me *me;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %u, %p", (void *)context, class_id,
	       instance_id, alarm, (void *)active);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(active);

	mib_lock_read(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error)
		goto unlock_mib;

	me_lock(context, me);
	error = me_alarm_get(context, me, (uint8_t)alarm, active);
	me_unlock(context, me);

	if (error)
		goto unlock_mib;

	mib_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;

unlock_mib:
	mib_unlock(context);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error omci_processing_enable(struct omci_context *context,
				       bool enable)
{
	dbg_in(__func__, "%p, %u", (void *)context, (unsigned int)enable);

	RETURN_IF_PTR_NULL(context);

	context_lock(context);
	if (enable == true) {
		dbg_prn("Enable OMCI processing");
		context->omci_enabled = true;
	} else {
		dbg_prn("Disable OMCI processing");
		context->omci_enabled = false;
	}
	context_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_prop_get(struct omci_context *context,
				 uint16_t class_id,
				 enum omci_me_prop *me_prop)
{
	const struct me_class *me_class;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %p", (void *)context, class_id,
	       (void *)me_prop);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(me_prop);

	error = mib_me_class_resolve(context, class_id, &me_class);
	RETURN_IF_ERROR(error);

	*me_prop = me_class->prop;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_create(struct omci_context *context,
			       const bool active,
			       const uint16_t class_id,
			       const uint16_t instance_id,
			       void *data,
			       const uint16_t suppress_avc)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p, 0x%04x", (void *)context, class_id,
	       instance_id, (void *)data, suppress_avc);

	RETURN_IF_PTR_NULL(context);

	mib_lock_write(context);

	error = mib_me_create(context, active, class_id, instance_id, NULL,
			      data, suppress_avc);
	if (error != OMCI_SUCCESS) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	mib_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_delete(struct omci_context *context,
			       uint16_t class_id,
			       uint16_t instance_id)
{
	enum omci_error error;
	struct me *me;

	dbg_in(__func__, "%p, %u, %u", (void *)context, class_id, instance_id);

	RETURN_IF_PTR_NULL(context);

	mib_lock_write(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error != OMCI_SUCCESS) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	error = mib_me_delete(context, me);
	if (error != OMCI_SUCCESS) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	mib_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
enum omci_error omci_me_name_get(struct omci_context *context,
				 uint16_t class_id,
				 char name[26])
{
	const struct me_class *me_class;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %p", (void *)context, class_id, (void *)name);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(name);

	error = mib_me_class_resolve(context, class_id, &me_class);
	RETURN_IF_ERROR(error);

	memcpy(name, me_class->desc.name, DESC_MAX_NAME_LEN);
	name[DESC_MAX_NAME_LEN] = 0;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}
#endif

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
enum omci_error omci_me_attr_name_get(struct omci_context *context,
				      uint16_t class_id,
				      unsigned int attr,
				      char attr_name[26])
{
	const struct me_class *me_class;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p", (void *)context, class_id, attr,
	       (void *)attr_name);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(attr_name);

	error = mib_me_class_resolve(context, class_id, &me_class);
	RETURN_IF_ERROR(error);

	if (attr == 0 || attr > OMCI_ATTRIBUTES_NUM)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	if (me_attr_prop_get(me_class, attr) == OMCI_ATTR_PROP_NONE)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	memcpy(attr_name, me_attr_name_get(me_class, attr), DESC_MAX_NAME_LEN);
	attr_name[DESC_MAX_NAME_LEN] = 0;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}
#endif

enum omci_error omci_me_attr_size_get(struct omci_context *context,
				      uint16_t class_id,
				      unsigned int attr,
				      size_t *attr_size)
{
	const struct me_class *me_class;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p", (void *)context, class_id, attr,
	       (void *)attr_size);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(attr_size);

	error = mib_me_class_resolve(context, class_id, &me_class);
	RETURN_IF_ERROR(error);

	if (attr == 0 || attr > OMCI_ATTRIBUTES_NUM)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	if (me_attr_prop_get(me_class, attr) == OMCI_ATTR_PROP_NONE)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	*attr_size = me_attr_size_get(me_class, attr);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_attr_prop_get(struct omci_context *context,
				      uint16_t class_id,
				      unsigned int attr,
				      enum omci_attr_prop *attr_prop)
{
	const struct me_class *me_class;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p", (void *)context, class_id, attr,
	       (void *)attr_prop);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(attr_prop);

	error = mib_me_class_resolve(context, class_id, &me_class);
	RETURN_IF_ERROR(error);

	if (attr == 0 || attr > OMCI_ATTRIBUTES_NUM)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	if (me_attr_prop_get(me_class, attr) == OMCI_ATTR_PROP_NONE)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	*attr_prop = me_attr_prop_get(me_class, attr);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_data_get(struct omci_context *context,
				 uint16_t class_id,
				 uint16_t instance_id,
				 enum omci_pm_interval interval,
				 void *attr_data,
				 size_t attr_data_size)
{
	struct me *me;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %lu, %p, %lu", (void *)context, class_id,
	       instance_id, interval, (void *)attr_data, attr_data_size);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(attr_data);

	if ((int)interval >= (int)OMCI_PM_INTERVAL_MAX)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_VAL);

	mib_lock_read(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	me_lock(context, me);
	error = me_data_read(context, me, attr_data, attr_data_size, interval);
	me_unlock(context, me);

	mib_unlock(context);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error omci_me_tbl_data_get(struct omci_context *context,
				     uint16_t class_id,
				     uint16_t instance_id,
				     unsigned int attr,
				     void **tbl_data,
				     size_t *tbl_data_size)
{
	struct me *me;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %u, %p, %p", (void *)context, class_id,
	       instance_id, attr, (void *)tbl_data, (void *)tbl_data_size);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(tbl_data);
	RETURN_IF_PTR_NULL(tbl_data_size);

	mib_lock_read(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	if (!is_me_attr_exist(me->class, attr)) {
		mib_unlock(context);
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);
	}

	me_lock(context, me);
	error = me_tbl_data_read(context, me, attr, tbl_data, tbl_data_size);
	me_unlock(context, me);

	mib_unlock(context);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error omci_me_attr_type_get(struct omci_context *context,
				      uint16_t class_id,
				      unsigned int attr,
				      enum omci_attr_type *attr_type)
{
	const struct me_class *me_class;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p", (void *)context, class_id, attr,
		(void *)attr_type);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(attr_type);

	error = mib_me_class_resolve(context, class_id, &me_class);
	RETURN_IF_ERROR(error);

	if (attr == 0 || attr > OMCI_ATTRIBUTES_NUM)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	if (me_attr_prop_get(me_class, attr) == OMCI_ATTR_PROP_NONE)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	*attr_type = me_attr_type_get(me_class, attr);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_attr_offset_get(struct omci_context *context,
					uint16_t class_id,
					unsigned int attr,
					size_t *attr_offset)
{
	const struct me_class *me_class;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p", (void *)context, class_id, attr,
		(void *)attr_offset);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(attr_offset);

	error = mib_me_class_resolve(context, class_id, &me_class);
	RETURN_IF_ERROR(error);

	if (attr == 0 || attr > OMCI_ATTRIBUTES_NUM)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	if (me_attr_prop_get(me_class, attr) == OMCI_ATTR_PROP_NONE)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	*attr_offset = me_attr_offset_get(me_class, attr);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_attr_get(struct omci_context *context,
				 uint16_t class_id,
				 uint16_t instance_id,
				 unsigned int attr,
				 void *data,
				 size_t data_size)
{
	struct me *me;
	enum omci_error error;

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(data);

	mib_lock_read(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	me_lock(context, me);
	error = me_attr_read(context, me, attr, data, data_size);
	me_unlock(context, me);

	mib_unlock(context);

	return error;
}

enum omci_error omci_me_attr_set(struct omci_context *context,
				 uint16_t class_id,
				 uint16_t instance_id,
				 unsigned int attr,
				 const void *data,
				 size_t data_size,
				 bool suppress_avc)
{
	struct me *me;
	enum omci_error error;

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(data);

	mib_lock_write(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	me_lock(context, me);
	error = me_attr_write(context, me, attr, data, data_size, suppress_avc);
	me_unlock(context, me);

	mib_unlock(context);

	return error;
}

enum omci_error omci_me_alarm_bitmap_get(struct omci_context *context,
					 uint16_t class_id,
					 uint16_t instance_id,
					 uint8_t alarm_bitmap
					 [OMCI_ALARM_BITMAP_SIZE])
{
	struct me *me;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p", (void *)context, class_id,
	       instance_id, (void *)alarm_bitmap);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(alarm_bitmap);

	mib_lock_read(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	me_lock(context, me);

	if (me->alarm_bitmap != NULL) {
		memcpy(alarm_bitmap, me->alarm_bitmap,
		       OMCI_ALARM_BITMAP_SIZE);
		error = OMCI_SUCCESS;
	} else {
		error = OMCI_ERROR_INVALID_ME_ACTION;
	}

	me_unlock(context, me);
	mib_unlock(context);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error omci_me_count_get(struct omci_context *context, size_t *count)
{
	dbg_in(__func__, "%p, %p", (void *)context, (void *)count);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(count);

	context_lock(context);
	*count = context->mib.me_count;
	context_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_list_get(struct omci_context *context,
				 struct omci_me *array,
				 size_t array_size)
{
	int i;
	unsigned int me_num = 0;
	struct mib_me_list_entry *me_entry;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)array,
	       array_size);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(array);

	mib_lock_read(context);

	for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
		for (me_entry = context->mib.me_class_array[i].me_list;
		     me_entry != NULL;
		     me_entry = me_entry->next) {
			if (array_size / sizeof(struct omci_me) < me_num) {
				dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
				return OMCI_ERROR_BOUNDS;
			}

			array[me_num].class_id = me_entry->me.class->class_id;
			array[me_num].instance_id = me_entry->me.instance_id;

			me_num++;
		}

	}
	mib_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_attr_change(struct omci_context *context,
				 uint16_t class_id,
				 uint16_t instance_id,
				 uint16_t attr)
{
	struct me *me;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %u", (void *)context, class_id,
	       instance_id, attr);

	RETURN_IF_PTR_NULL(context);

	mib_lock_read(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error != OMCI_SUCCESS) {
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	if (is_me_attr_exist(me->class, attr) == false) {
		mib_unlock(context);
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);
	}

	if (me_attr_prop_get(me->class, attr) & OMCI_ATTR_PROP_AVC) {
		if (me_attr_get_handler_get(me->class, attr) == 0) {
			dbg_err("ERROR(%d) no get handler for "
				"volatile attribute "
				"(%u@%u #%u)", -1,
				me->class->class_id,
				me->instance_id, attr);
			error = OMCI_ERROR;
			mib_unlock(context);
			RETURN_IF_ERROR(error);
		} else {
			error = avc_send(context, me, attr);
			if (error != OMCI_SUCCESS) {
				mib_unlock(context);
				RETURN_IF_ERROR(error);
			}
		}
	} else {
		dbg_err("ERROR(%d) non-volatile attribute "
			"has been changed (%u@%u #%u)", -1,
			me->class->class_id, me->instance_id, attr);

		error = OMCI_ERROR;
		mib_unlock(context);
		RETURN_IF_ERROR(error);
	}

	mib_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_interval_end(struct omci_context *context,
				  uint8_t interval_end_time)
{
	enum omci_error error = OMCI_SUCCESS;

#ifdef INCLUDE_PM
	error = pm_interval_end(context, interval_end_time);
#endif

	return error;
}

enum omci_error omci_olt_get(struct omci_context *context,
			     enum omci_olt *olt)
{
	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(olt);

	dbg_in(__func__, "%p, %p", (void *)context, (void *)olt);

	context_lock(context);
	*olt = context->olt;
	context_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_mib_reset(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	RETURN_IF_PTR_NULL(context);

	error = mib_reset(context, false);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_me_is_supported(struct omci_context *context,
				     uint16_t class_id)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %u", (void *)context, class_id);

	RETURN_IF_PTR_NULL(context);

	error = mib_me_class_resolve(context, class_id, NULL);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_failsafe_enable(struct omci_context *context,
				     bool enable)
{
	dbg_in(__func__, "%p, %u", (void *)context, (unsigned int)enable);

	RETURN_IF_PTR_NULL(context);

	context_lock(context);
	if (enable == true) {
		dbg_prn("Enable OMCI failsafe mode");
		context->failsafe = true;
	} else {
		dbg_prn("Disable OMCI failsafe mode");
		context->failsafe = false;
	}
	context_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_action_timeout_set(struct omci_context *context,
					uint32_t action_timeout)
{
	dbg_in(__func__, "%p, %u", (void *)context, action_timeout);

	RETURN_IF_PTR_NULL(context);

	context_lock(context);
	context->action_timeout = action_timeout;
	context_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_action_timeout_get(struct omci_context *context,
					uint32_t *action_timeout)
{
	dbg_in(__func__, "%p, %u", (void *)context, action_timeout);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(action_timeout);

	context_lock(context);
	*action_timeout = context->action_timeout;
	context_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_msg_num_get(struct omci_context *context,
				 unsigned int *num)
{
	dbg_in(__func__, "%p, %p", (void *)context, (void *)num);

	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(num);

	context_lock(context);
	*num = IFX_Var_Fifo_getCount(&context->msg_fifo.fifo);
	context_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

void *omci_api_ctx_get(struct omci_context *context)
{
	dbg_in(__func__, "%p", (void *)context);
	if (!context)
		return NULL;
	if (!context->api)
		return NULL;

	return (void*)context->api;
}

enum omci_error omci_attr_avc_send(struct omci_context *context,
				   uint16_t class_id,
				   uint16_t instance_id,
				   unsigned int attr)
{
	enum omci_error error;
	struct me *me;

	dbg_in(__func__, "%p, %hu, %hu, %u", (void *)context, class_id,
						instance_id, attr);

	RETURN_IF_PTR_NULL(context);

	mib_lock_read(context);

	error = mib_me_find(context, class_id, instance_id, &me);
	if (error)
		goto on_exit;

	me_lock(context, me);
	error = avc_send(context, me, attr);
	me_unlock(context, me);

on_exit:
	mib_unlock(context);
	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error omci_iop_mask_set(struct omci_context *context,
				  uint32_t mask)
{
	RETURN_IF_PTR_NULL(context);

	context_lock(context);
	context->iop_mask = mask;
	context_unlock(context);

	return OMCI_SUCCESS;
}

enum omci_error omci_iop_mask_get(struct omci_context *context,
				  uint32_t *mask)
{
	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(mask);

	context_lock(context);
	*mask = context->iop_mask;
	context_unlock(context);

	return OMCI_SUCCESS;
}

bool omci_iop_mask_isset(struct omci_context *context, unsigned int option)
{
	if (context == NULL)
		return false;

	return (context->iop_mask & (1u << option)) != 0;
}

enum omci_error omci_omcc_version_get(struct omci_context *context,
				      uint8_t *omcc_version)
{
	RETURN_IF_PTR_NULL(context);
	RETURN_IF_PTR_NULL(omcc_version);

	*omcc_version = context->omcc_version;

	return OMCI_SUCCESS;
}

/** @} */
