/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "drv_onu_config.h"
#endif

#ifndef ONU_LIBRARY
#include "ifxos_memory_alloc.h"
#endif
#include "ifxos_time.h"

#if defined(__GNUC__) && ! defined(__KERNEL__)
#include <stdarg.h>
#endif

#include "drv_onu_api.h"
#include "drv_onu_lan_api.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_cli_core.h"
#include "drv_onu_ploam_api.h"
#include "drv_onu_timer.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_ll_gtc.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_eim.h"
#include "drv_onu_ll_ictrll.h"
#include "drv_onu_ll_octrll.h"
#include "drv_onu_gtc_api.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_gpe_tables_api.h"
#include "drv_onu_register.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_event_api.h"
#include "drv_onu_ll_sce.h"
#include "drv_onu_ll_cop.h"
#include "drv_onu_ll_ssb.h"

/** dump tables instead of using detailed printout */
uint8_t raw_mode = 0;

#ifdef INCLUDE_DEBUG_SUPPORT
#  if defined(__GNUC__)
#     if defined(__KERNEL__)
const char *onu_dbg_str[] = { KERN_INFO, KERN_WARNING, KERN_ERR, "" };
#else
const char *onu_dbg_str[] = { " msg - ", " wrn - ", " err - ", "" };
#endif

int onu_debug_print(const enum onu_debug_level level, const char *format, ...)
{
	int ret = 0;
	va_list ap;

	if ((level < ONU_DBG_OFF) && (level >= onu_debug_lvl)) {
		va_start(ap, format);
#     if defined(__KERNEL__)
		ret = printk("%s" DEBUG_PREFIX " ", onu_dbg_str[level]);
		ret = vprintk(format, ap);
		ret = printk(ONU_CRLF);
#     else
		ret = printf(DEBUG_PREFIX "%s", onu_dbg_str[level]);
		ret = vprintf(format, ap);
		ret = printf(ONU_CRLF);
#     endif
		va_end(ap);
	}
	return ret;
}
#  else
int onu_debug_print_err(const char *format, ...)
{
	va_list ap;
	int ret = 0;

	va_start(ap, format);
	ret = printf(DEBUG_PREFIX " err - ");
	ret = vprintf(format, ap);
	ret = printf(ONU_CRLF);
	va_end(ap);

	return ret;
}

int onu_debug_print_wrn(const char *format, ...)
{
	va_list ap;
	int ret = 0;

	va_start(ap, format);
	ret = printf(DEBUG_PREFIX " wrn - ");
	ret = vprintf(format, ap);
	ret = printf(ONU_CRLF);
	va_end(ap);

	return ret;
}

int onu_debug_print_msg(const char *format, ...)
{
	va_list ap;
	int ret = 0;

	va_start(ap, format);
	ret = printf(DEBUG_PREFIX " msg - ");
	ret = vprintf(format, ap);
	ret = printf(ONU_CRLF);
	va_end(ap);

	return ret;
}
#  endif
#endif

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \addtogroup ONU_COMMON_INTERNAL
   @{
*/

/** what string support, driver version string */
const char onu_whatversion[] = ONU_WHAT_STR;

/** pointer to control structures. */
struct onu_control onu_control[MAX_ONU_INSTANCES];

/** chip version */
enum gpe_chip gpe_chip_version = GPE_CHIP_UNKNOWN;

enum onu_errorcode onu_fifo_init(struct onu_fifo *fifo, const char *p_name)
{
	fifo->name = p_name;
	fifo->mask = 0;
	fifo->overflow = 0;
	fifo->lost = 0;

	if (IFX_Var_Fifo_Init(&fifo->data,
			      (ulong_t *) &fifo->buf[0],
			      (ulong_t *) &(fifo->buf[ONU_FIFO_SIZE]),
			      ONU_FIFO_SIZE) != IFX_SUCCESS) {
		ONU_DEBUG_ERR("Can't initialize fifo %s.", p_name);
		return ONU_STATUS_ERR;
	}

	if (onu_spin_lock_init(&fifo->lock, p_name) != 0)
		return ONU_STATUS_ERR;

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_fifo_delete(struct onu_fifo *fifo)
{
	if (onu_spin_lock_delete(&fifo->lock) != 0)
		return ONU_STATUS_ERR;
	return ONU_STATUS_OK;
}

STATIC enum onu_errorcode onu_fifo_clone_entry(struct onu_fifo *fifo,
					       const void *buf,
					       const uint32_t len)
{
	void *p_data;
	unsigned long flags = 0;

	onu_spin_lock_get(&fifo->lock, &flags);
	p_data = IFX_Var_Fifo_writeElement(&fifo->data, len);
	if (p_data) {
		memcpy(p_data, buf, len);
		fifo->overflow = false;
	} else {
		fifo->lost++;
		fifo->overflow = true;
	}
	onu_spin_lock_release(&fifo->lock, flags);

	return p_data ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode onu_fifo_write(struct onu_fifo *fifo,
				  const uint32_t control,
				  const void *buf, const uint32_t len)
{
	uint8_t *p_data, *pBuffer;
	unsigned long flags = 0;

	onu_spin_lock_get(&fifo->lock, &flags);
	p_data =
	    (uint8_t *)IFX_Var_Fifo_writeElement(&fifo->data,
						 sizeof(struct onu_fifo_header)
						 + len);
	if (p_data) {
		((struct onu_fifo_header *) p_data)->id = control;
		((struct onu_fifo_header *) p_data)->len = len;
		if (len) {
			pBuffer = p_data + sizeof(struct onu_fifo_header);
			memcpy(&pBuffer[0], buf, len);
		}
		fifo->overflow = false;
	} else {
		fifo->lost++;
		fifo->overflow = true;
	}
	onu_spin_lock_release(&fifo->lock, flags);

	return p_data ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode onu_fifo_write_value(struct onu_fifo *fifo,
					const uint32_t control,
					const uint32_t value)
{
	uint8_t *p_data, *buff;
	unsigned long flags = 0;

	onu_spin_lock_get(&fifo->lock, &flags);
	p_data = (uint8_t *)IFX_Var_Fifo_writeElement(
				&fifo->data,
				sizeof(struct onu_fifo_header) + 4);
	if (p_data) {
		((struct onu_fifo_header *) p_data)->id = control;
		((struct onu_fifo_header *) p_data)->len = 4;
		buff = p_data + sizeof(struct onu_fifo_header);
		*((uint32_t *)buff) = value;
		fifo->overflow = false;
	} else {
		fifo->lost++;
		fifo->overflow = true;
	}
	onu_spin_lock_release(&fifo->lock, flags);

	return p_data ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

enum onu_errorcode onu_fifo_read(struct onu_fifo *fifo, void *buf,
				 uint32_t *len)
{
	void *ptr;
	unsigned long flags = 0;

	onu_spin_lock_get(&fifo->lock, &flags);
	ptr = (struct onu_fifo_header *) IFX_Var_Fifo_readElement(&fifo->data,
								  len);
	if (ptr && buf && *len)
		memcpy(buf, ptr, *len);

	onu_spin_lock_release(&fifo->lock, flags);

	return ptr ? ONU_STATUS_OK : ONU_STATUS_ERR;
}

#ifndef ONU_LIBRARY
static void event_clone(struct onu_control *ctrl,
			struct onu_fifo_header *src,
			uint32_t len)
{
	struct onu_device *p_dev;

	if (IFXOS_MutexGet(&ctrl->list_lock) != IFX_SUCCESS)
		return;

	p_dev = ctrl->p_dev_head;

	while (p_dev) {
		if (p_dev->nfc_fifo.mask & (1 << src->id)) {
			if (onu_fifo_clone_entry(&p_dev->nfc_fifo, src, len) ==
			    ONU_STATUS_OK) {
				IFXOS_DrvSelectQueueWakeUp(
					&p_dev->select_queue,
					IFXOS_DRV_SEL_WAKEUP_TYPE_RD);
			}
		}
		p_dev = p_dev->p_next;
	}

	IFXOS_MutexRelease(&ctrl->list_lock);
}

int32_t onu_worker_thread(IFXOS_ThreadParams_t *param)
{
	struct onu_control *ctrl = (struct onu_control *)param->nArg1;
	struct onu_fifo_header *src;
	uint32_t len = 0;
	int ret;

	while (ctrl->run_worker) {
		ret = event_queue_wait(ctrl);
		if (ret)
			break;

		len = 0;
		src =
		    (struct onu_fifo_header *) IFX_Var_Fifo_peekElement(
						&ctrl->nfc_fifo.data, &len);
		if (src == NULL)
			continue;

		if (src->id == ONU_EVENT_STATE_CHANGE) {
			struct onu_fifo_data *p =
						(struct onu_fifo_data *) src;
			onu_hot_plug_state(p->data.state.curr_state,
					 p->data.state.previous_state);
		}

		if (ctrl->p_dev_head == NULL) {
			onu_fifo_read(&ctrl->nfc_fifo, NULL, &len);
			continue;
		}

		event_clone(ctrl, src, len);
		onu_fifo_read(&ctrl->nfc_fifo, NULL, &len);
	}

	return 0;
}

#endif /* ONU_LIBRARY */

void onu_ploam_log(const uint32_t id, void *data, const uint16_t size)
{
	event_add(&onu_control[0], id, data, size);
}

void onu_ploam_state_change(struct onu_control *ctrl,
				const enum ploam_state curr_state,
				const enum ploam_state previous_state,
				const uint32_t elapsed_msec)
{
	onu_wan_status_cb_t cb;
	struct ploam_state_data_get param;

	param.curr_state = curr_state;
	param.previous_state = previous_state;
	param.elapsed_msec = elapsed_msec;

	event_add(ctrl, ONU_EVENT_STATE_CHANGE,
		  &param, sizeof(param));

	cb = ctrl->net_cb_list[ONU_NET_NETDEV_WAN_PORT].
						cb[NET_CB_WAN_STATUS];
	if (cb != NULL)
		cb(ctrl->net_cb_list[ONU_NET_NETDEV_WAN_PORT].net_dev,
		   curr_state == PLOAM_STATE_O5 ?
			true : false);
}

enum onu_errorcode onu_gtc_ds_handle(struct onu_control *ctrl,
				     uint32_t timer_no)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	int read_msg = -1;
#if 0				/* (defined(LINUX) && defined(__KERNEL__)) */
	static unsigned long old_jiffies;
#endif
	struct ploam_context *ploam_ctx = &ctrl->ploam_ctx;
	vuint32_t downstr_gtc_dsistat_1, downstr_gtc_dsstat_1,
		  downstr_gtc_dsimask_1;
#ifdef ONU_LIBRARY
	if (!ctrl->ploam_fsm_enable)
		return ret;
#endif
	downstr_gtc_dsistat_1 = gtc_r32(downstr_gtc_dsistat_1);
	downstr_gtc_dsstat_1 = gtc_r32(downstr_gtc_dsstat_1);
	downstr_gtc_dsimask_1 = gtc_r32(downstr_gtc_dsimask_1);

	if (timer_no == ONU_MAX_TIMER) {
		if ((downstr_gtc_dsistat_1 &
		     (GTC_DSISTAT_1_RXDAT | GTC_DSISTAT_1_GTCLSF |
		      GTC_DSISTAT_1_GTCLOF | GTC_DSISTAT_1_DLOS |
		      GTC_DSISTAT_1_BERINTV | GTC_DSISTAT_1_SF)) == 0) {
			return ret;
		}
	}

	/* PSync */
	if (ploam_ctx->curr_state == PLOAM_STATE_O1) {
		if (downstr_gtc_dsstat_1 & GTC_DSSTAT_1_STATE_SYNC) {
			ploam_ctx->event |= PLOAM_GTC_FRAME_SYNC;
		} else {
			onu_timer_stop(ONU_TIMER_TO0);
			onu_timer_start(ONU_TIMER_TO0, ONU_TIMER_SYNC_VALUE);
		}
	}

	/* LOS */
	if (downstr_gtc_dsistat_1 & GTC_DSISTAT_1_DLOS)
		ploam_ctx->event |= PLOAM_LOS;

	/* LOF */
	if (downstr_gtc_dsistat_1 &
	    (GTC_DSISTAT_1_GTCLSF | GTC_DSISTAT_1_GTCLOF))
		ploam_ctx->event |= PLOAM_LOS;

	/* SF */
	gtc_refresh_rdi();

	/* PLOAMd received (ploamd fifo is not empty) */
	if ((downstr_gtc_dsistat_1 & GTC_DSISTAT_1_RXDAT)
	    || (downstr_gtc_dsstat_1 & GTC_DSSTAT_1_RXDAT)) {
		read_msg =
		    gtc_ploam_rd(&ploam_ctx->ds_msg,
				 &ploam_ctx->ds_msg_previous,
				 &ploam_ctx->ds_repeat_count);
		if (read_msg == 0) {
			ploam_ctx->event |= PLOAM_MSG_RECEIVED;
			onu_ploam_log(ONU_EVENT_PLOAM_DS,
					&ploam_ctx->ds_msg,
					sizeof(struct ploam_msg));
		}
	}
	/* BER interval expired */
	if ((downstr_gtc_dsistat_1 & ploam_ctx->
	     dsimask) & GTC_DSISTAT_1_BERINTV) {
#if 0				/* (defined(LINUX) && defined(__KERNEL__)) */
		unsigned long tmp;
		tmp = jiffies - old_jiffies;
		old_jiffies = jiffies;
		ONU_DEBUG_ERR("IRQ REI %u", tmp / HZ);
#endif
		ploam_ctx->event |= PLOAM_BER_EXPIRED;
		gtc_total_berr_update(ctrl);
	}
	switch (timer_no) {
	case ONU_TIMER_TO1:
		ploam_ctx->event |= PLOAM_TO1_EXPIRED;
		break;
	case ONU_TIMER_TO2:
		ploam_ctx->event |= PLOAM_TO2_EXPIRED;
		break;
	}

	if (timer_no != ONU_TIMER_TO0 && ploam_ctx->event == 0) {
		ret = ONU_STATUS_ERR;
		goto err;
	}

	if ((ret = ploam_fsm(ploam_ctx)) < 0) {
		ret = ONU_STATUS_ERR;
		goto err;
	}

	if (ret & PLOAM_FSM_STATE_CHANGED)
		onu_ploam_state_change(ctrl,
				  ploam_ctx->curr_state,
				  ploam_ctx->previous_state,
				  ploam_ctx->elapsed_msec);

err:
	gtc_w32(downstr_gtc_dsistat_1 & downstr_gtc_dsimask_1,
		downstr_gtc_dsistat_1);

	return ret;

}

#ifndef ONU_LIBRARY
enum onu_errorcode onu_device_list_add(struct onu_control *ctrl,
				       struct onu_device *p_dev)
{
	struct onu_device *old;

	if (IFXOS_MutexGet(&ctrl->list_lock) != IFX_SUCCESS)
		return ONU_STATUS_ERR;

	if (ctrl->p_dev_head == NULL) {
		ctrl->p_dev_head = p_dev;
	} else {
		old = ctrl->p_dev_head;
		while (old->p_next)
			old = old->p_next;

		old->p_next = p_dev;
		p_dev->p_previous = old;
	}

	IFXOS_MutexRelease(&ctrl->list_lock);

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_device_list_delete(struct onu_control *ctrl,
					  struct onu_device *p_dev)
{
	if (IFXOS_MutexGet(&ctrl->list_lock) != IFX_SUCCESS)
		return ONU_STATUS_ERR;

	if (p_dev->p_previous && p_dev->p_next) {
		((struct onu_device *)p_dev->p_previous)->p_next =
							p_dev->p_next;
		((struct onu_device *)p_dev->p_next)->p_previous =
							p_dev->p_previous;
	} else if (p_dev->p_previous && (p_dev->p_next == NULL)) {
		((struct onu_device *)p_dev->p_previous)->p_next = NULL;
	} else if ((p_dev->p_previous == NULL) && p_dev->p_next) {
		((struct onu_device *)p_dev->p_next)->p_previous = NULL;
		ctrl->p_dev_head = p_dev->p_next;
	} else {
		ctrl->p_dev_head = NULL;
	}

	IFXOS_MutexRelease(&ctrl->list_lock);

	return ONU_STATUS_OK;
}
#endif

#ifdef INCLUDE_DEBUG_SUPPORT
enum onu_errorcode onu_debug_level_set(struct onu_device *p_dev,
				       const struct onu_dbg_level *param)
{
	(void)p_dev;

	onu_debug_lvl = param->level;

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_debug_level_get(struct onu_device *p_dev,
				       struct onu_dbg_level *param)
{
	(void)p_dev;

	param->level = onu_debug_lvl;

	return ONU_STATUS_OK;
}
#endif

enum gpe_chip onu_chip_get(void)
{
	uint32_t chipid, config;
	uint16_t ver;

	status_chipid_get(&chipid, &config);

	ver = 0xA00 + ((((config & STATUS_CONFIG_SUBVERS_MASK) >>
			 STATUS_CONFIG_SUBVERS_OFFSET) >> 2) << 8);
	ver |= ((((config & STATUS_CONFIG_SUBVERS_MASK) >>
		  STATUS_CONFIG_SUBVERS_OFFSET) & 3) + 1);
	ver |= (((chipid & STATUS_CHIPID_VERSION_MASK) >>
		 STATUS_CHIPID_VERSION_OFFSET) << 4);

	switch (ver) {
	case 0xA11:
		return GPE_CHIP_A11;
	case 0xA12:
		return GPE_CHIP_A12;
	case 0xA21:
	case 0xA22:
	case 0xA23:
		return GPE_CHIP_A21;
	default:
		return GPE_CHIP_UNKNOWN;
	}
}

enum onu_errorcode onu_version_get(struct onu_device *p_dev,
				   struct onu_version_string *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	int cop_id;
	int cop_major = 0, cop_minor = 0;
	int max_cop_major = 0, max_cop_minor = 0;
	uint32_t chipid, chipid_partnr, chipid_version;
	uint32_t config, config_subvers;

	/* ONU driver */
	strncpy(&param->onu_version[0],
		onu_ver_str,
		sizeof(param->onu_version));
	param->onu_version[sizeof(param->onu_version) - 1] = '\0';

	/* PE firmware */
	onu_snprintf(&param->fw_version[0],
		 sizeof(param->fw_version),
		 "%u.%u.%u.%u",
		 ctrl->pe_fw[0].ver.major,
		 ctrl->pe_fw[0].ver.minor,
		 ctrl->pe_fw[0].ver.patch,
		 ctrl->pe_fw[0].ver.internal);

	/* max. COP */
	for (cop_id = 0; cop_id < 6; cop_id++) {
		if (onu_cop_version_get(ctrl, cop_id, NULL,
					&cop_major, &cop_minor))
			return ONU_STATUS_ERR;

		if (cop_major > max_cop_major ||
		    (cop_major == max_cop_major &&
		     cop_minor > max_cop_minor)) {
			max_cop_major = cop_major;
			max_cop_minor = cop_minor;
		}
	}

	onu_snprintf(&param->cop_version[0],
		 sizeof(param->cop_version),
		 "%u.%u", max_cop_major, max_cop_minor);

	/* SCE interface */
	strncpy(&param->sce_interface_version[0],
		GPON_SCE_INTERFACE_VERSION,
		sizeof(param->sce_interface_version));
	param->sce_interface_version[sizeof(param->sce_interface_version) - 1] =
		'\0';

	/* Chip id */
	status_chipid_get(&chipid, &config);
	if ((chipid & STATUS_CHIPID_CONST1) != STATUS_CHIPID_CONST1) {
		strcpy(param->chip_id, "n\\a");
	} else {
		chipid_partnr = (chipid & STATUS_CHIPID_PARTNR_MASK)
			>> STATUS_CHIPID_PARTNR_OFFSET;
		chipid_version = (chipid & STATUS_CHIPID_VERSION_MASK)
			>> STATUS_CHIPID_VERSION_OFFSET;
		config_subvers = (config & STATUS_CONFIG_SUBVERS_MASK)
			>> STATUS_CONFIG_SUBVERS_OFFSET;

		if (chipid_partnr != 0x01B8) {
			strcpy(param->chip_id, "n\\a");
		} else {
			onu_snprintf(&param->chip_id[0],
				 sizeof(param->chip_id),
				 "%c%d%d",
				 'A' + (config_subvers >> 2),
				 chipid_version, (config_subvers & 3) + 1);
		}
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_device_open(struct onu_control *ctrl,
				   struct onu_device *p_dev)
{
	if (p_dev == NULL)
		return ONU_STATUS_ERR;

	memset(p_dev, 0x00, sizeof(struct onu_device));

	if (onu_fifo_init(&p_dev->nfc_fifo, "device") != ONU_STATUS_OK)
		return ONU_STATUS_ERR;

#ifndef ONU_LIBRARY
	IFXOS_DrvSelectQueueInit(&p_dev->select_queue);
#endif

	p_dev->ploam_ctx = &ctrl->ploam_ctx;
	p_dev->ctrl = ctrl;
	/*ctrl->cnt_cfg.disable_update = true;*/

#ifndef ONU_LIBRARY
	if (onu_device_list_add(ctrl, p_dev) != ONU_STATUS_OK)
		return ONU_STATUS_ERR;
#endif

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_device_close(struct onu_device *p_dev)
{
	if (p_dev == NULL)
		return ONU_STATUS_ERR;

	onu_fifo_delete(&p_dev->nfc_fifo);
#ifndef ONU_LIBRARY
	IFXOS_MemFree(p_dev);
#endif
	return ONU_STATUS_OK;
}

enum onu_errorcode onu_reset(struct onu_device *p_dev)
{
	(void)p_dev;

	ONU_DEBUG_MSG("Reset device");

	return ONU_STATUS_ERR;
}

enum onu_errorcode onu_register_set(struct onu_device *p_dev,
				    const struct onu_reg_addr_val *param)
{
	(void)p_dev;

	switch (param->form) {
	case 32:
		reg_w32(param->value,
			(unsigned long *)(KSEG1 | param->address));
		break;

	default:
		return ONU_STATUS_ERR;
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_register_get(struct onu_device *p_dev,
				    const struct onu_reg_addr *param_in,
				    struct onu_reg_val *param_out)
{
	(void)p_dev;

	param_out->form = param_in->form;

	switch (param_in->form) {
	case 32:
		param_out->value =
			reg_r32((unsigned long *)(KSEG1 | param_in->address));
		break;

	default:
		return ONU_STATUS_ERR;
	}

	return ONU_STATUS_OK;
}

#ifndef ONU_LIBRARY
/* add test mode key here*/
/** Handles certain (temporarly) test modes */
enum onu_errorcode onu_test_mode_set(struct onu_device *p_dev,
				     const struct onu_test_mode *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (strstr(param->mode, ONU_TESTMODE_IOCTL_TRACE_KEY)) {
		if (param->mode[strlen(ONU_TESTMODE_IOCTL_TRACE_KEY)+1] == '0')
			ctrl->ioctl_trace = false;
		else
			ctrl->ioctl_trace = true;
	}
	if (strstr(param->mode, ONU_TESTMODE_RAW_KEY)) {
		if (param->mode[strlen(ONU_TESTMODE_RAW_KEY)+1] == '0') {
			raw_mode = false;
		} else {
			raw_mode = true;
		}
	}
	/* possible extensions use simple number:
		ctrl->my_mode =
	#if defined(LINUX) && defined(__KERNEL__)
			simple_strtol
	#else
			strtol
	#endif
			((char*)param->mode +
			strlen(TESTMODE_MY_KEY)+1, NULL, 10);
	*/
	/* use scanf for converting complex string to number.
	ret = onu_cli_sscanf(ret+strlen(TESTMODE_MY_KEY)+1, "%X", &val);
	*/
	return ONU_STATUS_OK;
}
#endif /* ONU_LIBRARY */

#ifdef INCLUDE_CLI_SUPPORT
enum onu_errorcode onu_cli(struct onu_device *p_dev, char *param)
{
	return onu_cli_command_execute(p_dev, param, ONU_IO_BUF_SIZE);
}
#endif

enum onu_errorcode ploam_ds_insert(struct onu_device *p_dev,
				   const struct ploam_message *msg)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	struct ploam_context *ploam_ctx = &ctrl->ploam_ctx;

	memcpy(&ploam_ctx->ds_msg, msg, 12);

	ploam_ctx->event = PLOAM_MSG_RECEIVED;
	if(ploam_ctx->curr_state == 1)
		ploam_ctx->event |= PLOAM_GTC_FRAME_SYNC;

	if ((ret = ploam_fsm(ploam_ctx)) < 0) {
		ret = ONU_STATUS_ERR;
	} else {
		if (ret & PLOAM_FSM_STATE_CHANGED) {
			onu_ploam_state_change(ctrl,
					  ploam_ctx->curr_state,
					  ploam_ctx->previous_state,
					  ploam_ctx->elapsed_msec);
		}
	}

	return ret;
}

enum onu_errorcode onu_line_enable_set(struct onu_device *p_dev,
				       const struct onu_enable *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct ploam_state_data_set fsm;
	static bool once = false;
	uint32_t pe_run_mask[ONU_GPE_NUMBER_OF_PE_MAX] = {
		0x7, 0x77, 0x777, 0x7777, 0x77777, 0x777777
	};

	ctrl->ploam_fsm_enable = param->enable;

	if (param->enable == true) {
		if (once == false) {
			once = true;
			onu_timer_start(ONU_TIMER_LAN_PORT_POLL,
					ONU_TIMER_LAN_PORT_POLL_VALUE);
			onu_timer_start(ONU_TIMER_COUNTER,
					ONU_TIMER_COUNTER_VALUE);
			sce_fw_pe_run(pe_run_mask[ctrl->num_pe - 1]);
			if (gpe_sce_process_mode_set(ctrl, SCE_MODE_PACKET)) {
				ONU_DEBUG_ERR(	"FW run error in "
						"sce_process_mode_set!");
			}
			onu_timer_start(ONU_TIMER_STUCK_WD, 
				ONU_TIMER_STUCK_WD_VALUE);
		}
		fsm.state = PLOAM_STATE_O0;
		ploam_state_set(p_dev, &fsm);
		onu_timer_start(ONU_TIMER_TO0, 1);
		onu_irq_enable(ctrl, IRQ_TMU_FLAG |
			       IRQ_GTC_US_FlAG | IRQ_GTC_DS_FLAG | IRQ_LINK_FLAG);
	} else {
		onu_irq_enable(ctrl, IRQ_TMU_FLAG | IRQ_LINK_FLAG);
		gtc_tx_enable(false);
		onu_timer_stop(ONU_TIMER_TO0);
		onu_timer_stop(ONU_TIMER_TO1);
		onu_timer_stop(ONU_TIMER_TO2);
		fsm.state = PLOAM_STATE_O0;
		ploam_state_set(p_dev, &fsm);
#ifdef ONU_LIBRARY
		/*gtc_downstream_imask_set(0);*/
#endif
		onu_hot_plug_state(0, 0);
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_line_enable_get(struct onu_device *p_dev,
				       struct onu_enable *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	param->enable = ctrl->ploam_fsm_enable;
	return ONU_STATUS_OK;
}

STATIC void onu_counter_reset(struct onu_control *ctrl)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&ctrl->cnt_lock, &flags);
	/* switch intervals*/
	ctrl->current_counter = ctrl->current_counter ? 0 : 1;
	onu_spin_lock_release(&ctrl->cnt_lock, flags);

	/* reset all current interval GPE counters*/
	onu_interval_counter_update(ctrl, 0xFFFF, 0, UINT64_MAX, true, NULL);
}

enum onu_errorcode onu_counters_reset(struct onu_device *p_dev,
					   const struct onu_cnt_reset *param)
{
	/* reset all interval GPE counters*/
	onu_interval_counter_update(p_dev->ctrl,
				   0xFFFF, 0, UINT64_MAX, param->curr, NULL);

	return ONU_STATUS_OK;
}

#define ONU_INTRVL_SUPERVISION_EXT_POLL_TIME	10

enum onu_errorcode onu_sync_time_set(struct onu_device *p_dev,
				     const struct onu_sync_time *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t to_cnt = 2 * ONU_TIMER_COUNTER_VALUE/
				ONU_INTRVL_SUPERVISION_EXT_POLL_TIME;

	ctrl->b15_min_supervision = param->interval_enable;
	ctrl->interval_supervision_ext = param->interval_supervision_ext;

	if (param->interval_supervision_ext) {
		ctrl->interval_trigger_ext = true;
		while (ctrl->interval_trigger_ext && --to_cnt)
			IFXOS_MSecSleep(ONU_INTRVL_SUPERVISION_EXT_POLL_TIME);

		if (to_cnt == 0) {
			ONU_DEBUG_ERR("External interval supervision"
				      " not handled!");
			return ONU_STATUS_ERR;
		}
	} else {
		if (ctrl->b15_min_supervision) {
			ctrl->b15_min_second = 0;
			onu_counter_reset(ctrl);
		}
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_counters_cfg_set(struct onu_device *p_dev,
					const struct onu_cnt_cfg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	memcpy(&ctrl->cnt_cfg, param, sizeof(struct onu_cnt_cfg));

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_counters_cfg_get(struct onu_device *p_dev,
					struct onu_cnt_cfg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	memcpy(param, &ctrl->cnt_cfg, sizeof(struct onu_cnt_cfg));

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_sync_time_get(struct onu_device *p_dev,
				     struct onu_sync_time *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	param->interval_enable = ctrl->b15_min_supervision;
	param->interval_supervision_ext = ctrl->interval_supervision_ext;

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_interval_counter_update(	struct onu_control *ctrl,
						const uint16_t index,
						const uint32_t sel,
						const uint64_t rst_mask,
						const bool curr,
						void *data)
{
	uint32_t k;
	unsigned long flags = 0;

	onu_spin_lock_get(&ctrl->cnt_lock, &flags);

	if (index == 0xFFFF) {
		for (k = 0; k < ONU_GPE_MAX_GPIX; k++)
			gpe_gem_cnt_update(ctrl, k, rst_mask, true, data);

		for (k = 0; k < ONU_GPE_MAX_ETH_UNI; k++)
			lan_cnt_update(ctrl, (uint8_t)k, rst_mask, true, data);

		for (k = 0; k < ONU_GPE_MAX_BRIDGES; k++)
			gpe_bridge_cnt_update(ctrl, k, rst_mask, true, data);

		for (k = 0; k < ONU_GPE_MAX_BRIDGE_PORT; k++)
			gpe_bridge_port_cnt_update(ctrl, k, rst_mask, true, data);

		gtc_counter_update(ctrl, rst_mask, true, data);
	} else {
		switch (sel) {
		case GEM_COUNTER:
			gpe_gem_cnt_update(ctrl, index, rst_mask, curr, data);
			break;
		case LAN_COUNTER:
			lan_cnt_update(ctrl, (uint8_t)index, rst_mask, curr, data);
			break;
		case BRIDGE_COUNTER:
			gpe_bridge_cnt_update(ctrl, index, rst_mask, curr, data);
			break;
		case GTC_COUNTER:
			gtc_counter_update(ctrl, rst_mask, curr, data);
			break;
		case BRIDGE_PORT_COUNTER:
			gpe_bridge_port_cnt_update(ctrl, index, rst_mask, curr, data);
			break;
		default:
			break;
		}
	}

	onu_spin_lock_release(&ctrl->cnt_lock, flags);

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_counter_update(struct onu_control *ctrl)
{
	/* GPE counters update*/
	onu_interval_counter_update(ctrl, 0xFFFF, 0, 0, true, NULL);

	if (!ctrl->interval_supervision_ext)
		ctrl->b15_min_second++;

	if (ctrl->b15_min_second == 900 || ctrl->interval_trigger_ext) {
		ONU_DEBUG_MSG("counter interval expired");

		ctrl->b15_min_second = 0;
		if (ctrl->b15_min_supervision) {
			onu_counter_reset(ctrl);
		}
		ctrl->interval_trigger_ext = false;

		event_add(ctrl, ONU_EVENT_15MIN_INTERVAL_END, NULL, 0);
	}

	/**
	\todo make counters poll time adjustments if required*/
	return ONU_STATUS_OK;
}

/*
    General counter handling:
    All hardware counters roll over if they reach the maximum count value. When
    reading the counter registers, the current value is checked with the most
    recent value and the difference is added to the logical counter.

    If the difference is positive, the increment is
    nIncrement = nHW_Counter - nHW_CounterKeep.

    If the difference is negative, the counter has wrapped around and the
    increment is nIncrement = nCounterSize - nHW_CounterKeep + nHW_Counter.
*/

int onu_counter_value_update(uint64_t *const dest, const uint64_t threshold,
			     uint64_t *const tca, uint64_t *const shadow,
			     const uint64_t cnt)
{
	int ret = 0;
	uint64_t max_val;

	if (cnt == *shadow)
		return ret;

	if (cnt > *shadow) {
		*dest += (cnt - *shadow);
	} else {
		if (*shadow <= (uint64_t)UINT16_MAX)
			max_val = (uint64_t)UINT16_MAX;
		else if (*shadow <= (uint64_t)UINT32_MAX)
			max_val = (uint64_t)UINT32_MAX;
		else
			max_val = (uint64_t)UINT64_MAX;

		*dest += (max_val - *shadow + cnt);
	}

	*shadow = cnt;

	if ((*dest >= threshold) && (*tca == 0)) {
		*tca = *dest;
		ret = 1;
	}

	return ret;
}

STATIC enum onu_errorcode onu_lan_status_update(struct onu_control *ctrl)
{
	uint8_t i;
	uint32_t port_sts_prev;
	onu_lan_status_cb_t cb;
	struct onu_link_state link_state;

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {

		if (!ctrl->lan_port_sts_fct[i])
			continue;

		port_sts_prev = ctrl->lan_link_status[i].up;

		/* update port status*/
		if (ctrl->lan_port_sts_fct[i](ctrl, i) != ONU_STATUS_OK)
			return ONU_STATUS_ERR;

		/* Check link status change */
		if (port_sts_prev != ctrl->lan_link_status[i].up) {
			cb = ctrl->net_cb_list[net_port_get(i)].
							cb[NET_CB_LAN_STATUS];
			if (cb != NULL)
				cb(ctrl->net_cb_list[net_port_get(i)].
					net_dev,
				   i, ctrl->lan_link_status[i].up);

			link_state.port = i;
			link_state.old = port_sts_prev;
			link_state.new = ctrl->lan_link_status[i].up;

			event_add(ctrl, ONU_EVENT_LINK_STATE_CHANGE,
				  &link_state, sizeof(link_state));
		}
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_timer_exec(struct onu_control *ctrl, ulong_t timer_no)
{
	if (timer_no <= ONU_TIMER_TO2) {
		struct ploam_context *ploam_ctx = &ctrl->ploam_ctx;
		gtc_downstream_imask_set(0);
		onu_gtc_ds_handle(ctrl, timer_no);
		gtc_downstream_imask_set(ploam_ctx->dsimask);
	} else if (timer_no == ONU_TIMER_COUNTER) {
		struct ploam_context *ploam_ctx = &ctrl->ploam_ctx;
		if (ploam_ctx->ds_pee) {
			bool status_change = false;

			if (ploam_ctx->ds_count_pee == 0)
				status_change = true;

			ploam_ctx->ds_count_pee++;
			if (ploam_ctx->ds_count_pee > 3) {
				ploam_ctx->ds_pee = false;
				status_change = true;
			}
			if (status_change) {
				struct gtc_status param;
				gtc_ll_status_get(&param);
				/* Physical Equipment Error (PEE) received from
				   OLT through PLOAMd */
				param.ds_physical_equipment_error =
				    ploam_ctx->ds_pee;
				event_add(ctrl, ONU_EVENT_GTC_STATUS_CHANGE,
					  &param, sizeof(param));
			}
		}

		if (!ctrl->cnt_cfg.disable_update)
			onu_counter_update(ctrl);

		onu_timer_start(ONU_TIMER_COUNTER, ONU_TIMER_COUNTER_VALUE);
	} else if (timer_no == ONU_TIMER_LAN_PORT_POLL) {
		if (onu_lan_status_update(ctrl) < ONU_STATUS_OK)
			ONU_DEBUG_WRN("LAN status update failed!");

		onu_timer_start(ONU_TIMER_LAN_PORT_POLL,
			       ONU_TIMER_LAN_PORT_POLL_VALUE);
	} else if (timer_no == ONU_TIMER_AGING_TRIG) {
		if (gpe_aging_trigger_set(ctrl) != ONU_STATUS_OK)
			ONU_DEBUG_WRN("GPE Aging Trigger failed!");

		if (ctrl->gpe_aging_trigger.ttrig)
			onu_timer_start(ONU_TIMER_AGING_TRIG,
					ctrl->gpe_aging_trigger.ttrig);
	} else if (timer_no == ONU_TIMER_STUCK_WD) {
		if (lan_traffic_watchdog (ctrl) != ONU_STATUS_OK) {
			/* event_add(ctrl, ONU_EVENT_GTC_STATUS_CHANGE,
					  &param, sizeof(param));*/
		}
		onu_timer_start(ONU_TIMER_STUCK_WD, ONU_TIMER_STUCK_WD_VALUE);
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode onu_event_enable_set(struct onu_device *p_dev,
					const struct onu_event_mask *param)
{
	p_dev->nfc_fifo.mask = param->val;
	return ONU_STATUS_OK;
}

enum onu_errorcode onu_event_enable_get(struct onu_device *p_dev,
					struct onu_event_mask *param)
{
	param->val = p_dev->nfc_fifo.mask;
	return ONU_STATUS_OK;
}

enum onu_errorcode onu_locked_memcpy(	onu_lock_t *lock,
					void *to, const void *from,
					size_t sz_byte)
{
	unsigned long flags = 0;

	onu_spin_lock_get(lock, &flags);
	memcpy(to, from, sz_byte);
	onu_spin_lock_release(lock, flags);

	return ONU_STATUS_OK;
}

/**
  Return the module initialization status set after all low level
  modules are enabled.

  \remarks only working for one device as this is a global function
*/
bool onu_is_initialized(void)
{
	return onu_control[0].init;
}

static void event_trace_clone(struct onu_control *ctrl,
			      const unsigned long event_id,
			      const void *data,
			      const size_t data_size)
{
#ifndef ONU_LIBRARY
	struct onu_device *p_dev;

	if (IFXOS_MutexGet(&ctrl->list_lock) != IFX_SUCCESS)
		return;

	p_dev = ctrl->p_dev_head;

	while (p_dev) {
		if (p_dev->nfc_fifo.mask & (1 << event_id)) {
			if (onu_fifo_write(&p_dev->nfc_fifo,
					   event_id,
					   data, data_size) == ONU_STATUS_OK) {
				IFXOS_DrvSelectQueueWakeUp(
					&p_dev->select_queue,
					IFXOS_DRV_SEL_WAKEUP_TYPE_RD);
			}
		}
		p_dev = p_dev->p_next;
	}

	IFXOS_MutexRelease(&ctrl->list_lock);
#endif /* ONU_LIBRARY */
}

enum onu_errorcode event_add(struct onu_control *ctrl,
			     const unsigned long event_id,
			     const void *data,
			     const size_t data_size)
{
	enum onu_errorcode ret;
	static const char *event_name[] = {
		"ONU_EVENT_HARDWARE",
		"ONU_EVENT_PLOAM_DS",
		"ONU_EVENT_PLOAM_US",
		"ONU_EVENT_STATE_CHANGE",
		"ONU_EVENT_OMCI_RECEIVE",
		"ONU_EVENT_GTC_TCA",
		"ONU_EVENT_GPE_TCA",
		"ONU_EVENT_LAN_TCA",
		"ONU_EVENT_GTC_STATUS_CHANGE",
		"ONU_EVENT_SCE_BP_REACHED",
		"ONU_EVENT_BWMAP_TRACE",
		"ONU_EVENT_OMCI_SENT",
		"ONU_EVENT_IOCTL_TRACE",
		"ONU_EVENT_LINK_STATE_CHANGE",
		"ONU_EVENT_15MIN_INTERVAL_END",
		"ONU_EVENT_EXCEPTION_PACKET",
		"ONU_EVENT_BRIDGE_TCA",
		"ONU_EVENT_BRIDGE_PORT_TCA"
	};

	if (event_id == ONU_EVENT_IOCTL_TRACE) {
		event_trace_clone(ctrl, event_id, data, data_size);
		return ONU_STATUS_OK;
	}

	ret = onu_fifo_write(&ctrl->nfc_fifo,
			     event_id,
			     data,
			     data_size);

	if (ret)
		ONU_DEBUG_ERR("FIFO overflow (%lu - %s) %d",
			      event_id,
			      event_id < ARRAY_SIZE(event_name) ?
			      event_name[event_id] : "?",
			      IFX_Var_Fifo_getCount(&ctrl->nfc_fifo.data));

	event_queue_wakeup(ctrl);

	return ret;
}

uint32_t onu_round_div(const uint32_t x, const uint32_t y)
{
	uint64_t z;

	z = (uint64_t)(2*x + y);
	do_div(z, 2 * y);

	return (uint32_t)z;
}

uint32_t onu_bit_rev(uint32_t x)
{
	x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555);
	x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333);
	x = ((x & 0x0f0f0f0f) << 4) | ((x >> 4) & 0x0f0f0f0f);
	x = (x << 24) | ((x & 0xff00) << 8) | ((x >> 8) & 0xff00) | (x >> 24);
	return x;
}

const struct onu_entry common_function_table[] = {
	TE1in(FIO_ONU_REGISTER_SET,
		sizeof(struct onu_reg_addr_val), onu_register_set),
	TE2(FIO_ONU_REGISTER_GET,
		sizeof(struct onu_reg_addr), sizeof(struct onu_reg_val),
		onu_register_get),
#ifdef INCLUDE_DEBUG_SUPPORT
	TE1in(FIO_ONU_DEBUG_LEVEL_SET,
		sizeof(struct onu_dbg_level), onu_debug_level_set),
	TE1out(FIO_ONU_DEBUG_LEVEL_GET,
		sizeof(struct onu_dbg_level), onu_debug_level_get),
#else
	TE1in(FIO_ONU_DEBUG_LEVEL_SET, 0, NULL),
	TE1in(FIO_ONU_DEBUG_LEVEL_GET, 0, NULL),
#endif
	TE1out(FIO_ONU_VERSION_GET,
		sizeof(struct onu_version_string), onu_version_get),
	TE0(FIO_ONU_INIT, NULL),
	TE0(FIO_ONU_RESET, onu_reset),
	TE1in(FIO_ONU_LINE_ENABLE_SET,
		sizeof(struct onu_enable), onu_line_enable_set),
	TE1out(FIO_ONU_LINE_ENABLE_GET,
		sizeof(struct onu_enable), onu_line_enable_get),
	TE1in(FIO_ONU_SYNC_TIME_SET,
		sizeof(struct onu_sync_time), onu_sync_time_set),
	TE1out(FIO_ONU_SYNC_TIME_GET,
		sizeof(struct onu_sync_time), onu_sync_time_get),
	TE1in_opt(FIO_ONU_TEST_MODE_SET,
		sizeof(struct onu_test_mode),
		onu_test_mode_set),
	TE1in(FIO_ONU_COUNTERS_CFG_SET,
		sizeof(struct onu_cnt_cfg),
		onu_counters_cfg_set),
	TE1out(FIO_ONU_COUNTERS_CFG_GET,
		sizeof(struct onu_cnt_cfg), onu_counters_cfg_get),
	TE1in(FIO_ONU_COUNTERS_RESET,
		sizeof(struct onu_cnt_reset), onu_counters_reset)
};

const unsigned int common_function_table_size = ARRAY_SIZE(common_function_table);

/*! @} */

/*! @} */
