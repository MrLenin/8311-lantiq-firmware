/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_SIMULATION_INTERNAL Simulation Specific Implementation

   This chapter describes the internal interface of the ONU simulation.

   @{
*/

#ifdef HAVE_CONFIG_H
#include "drv_onu_config.h"
#endif

#ifdef ONU_SIMULATION

#include <stdlib.h>

#include "drv_onu_api.h"

#include "ifxos_device_io.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"

#include "drv_onu_cli_core.h"
#include "drv_onu_gtc_api.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_gpe_tables_api.h"
#include "drv_onu_lan_api.h"
#include "drv_onu_ploam_api.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_event_api.h"
#include "drv_onu_timer.h"
#include "drv_onu_register.h"

/** common callbacks used by ioctl() */
extern const struct onu_entry common_function_table[];
extern const unsigned int common_function_table_size;
extern const struct onu_entry ploam_function_table[];
extern const unsigned int ploam_function_table_size;

#define IFXOS_BlockAlloc IFXOS_MemAlloc
#define IFXOS_BlockFree IFXOS_MemFree

long onu_open(void *device, const char *appendix);
int onu_release(void *pprivate);
int onu_write(void *pprivate, const char *src, const int length);
int onu_read(void *pprivate, char *dest, const int length);
int onu_ioctl(void *pprivate, unsigned int cmd, ulong_t argument);
int onu_poll(void *pprivate);
void onu_irq_handler(void *dev_id);

STATIC unsigned int major_number;
onu_lock_t mailbox_lock;
onu_lock_t cop_lock;
onu_lock_t ictrlc_lock;
onu_lock_t octrlc_lock;
onu_lock_t link_lock;
onu_lock_t sce_lock;
onu_lock_t meter_lock;
onu_lock_t tmu_lock;
onu_lock_t enqueue_lock;

#ifdef INCLUDE_DEBUG_SUPPORT
enum onu_debug_level onu_debug_lvl = ONU_DBG_OFF;
#endif

struct onu_reg_gtc g_gtc;
struct onu_reg_gtc *gtc = &g_gtc;
struct onu_reg_gpearb g_gpearb;
struct onu_reg_gpearb *gpearb = &g_gpearb;
union onu_reg_eim g_eim;
union onu_reg_eim *eim = &g_eim;
struct onu_reg_sxgmii g_sxgmii;
struct onu_reg_sxgmii *sxgmii = &g_sxgmii;
struct onu_reg_iqm g_iqm;
struct onu_reg_iqm *iqm = &g_iqm;
struct onu_reg_fsqm g_fsqm;
struct onu_reg_fsqm *fsqm = &g_fsqm;
struct onu_reg_ictrlc g_ictrlc;
struct onu_reg_ictrlc *ictrlc = &g_ictrlc;
struct onu_reg_octrlc g_octrlc;
struct onu_reg_octrlc *octrlc = &g_octrlc;
struct onu_reg_ictrll g_ictrll;
struct onu_reg_ictrll *ictrll = &g_ictrll;
struct onu_reg_ictrlg g_ictrlg;
struct onu_reg_ictrlg *ictrlg = &g_ictrlg;
struct onu_reg_octrll g_octrll;
struct onu_reg_octrll *octrll = &g_octrll;
struct onu_reg_octrlg g_octrlg;
struct onu_reg_octrlg *octrlg = &g_octrlg;
struct onu_reg_sys_eth g_sys_eth;
struct onu_reg_sys_eth *sys_eth = &g_sys_eth;
struct onu_reg_sys_gpe g_sys_gpe;
struct onu_reg_sys_gpe *sys_gpe = &g_sys_gpe;
struct onu_reg_tmu g_tmu;
struct onu_reg_tmu *tmu = &g_tmu;
struct onu_reg_tbm g_tbm;
struct onu_reg_tbm *tbm = &g_tbm;
struct onu_reg_sbs0ctrl g_sbs0ctrl;
struct onu_reg_sbs0ctrl *sbs0ctrl = &g_sbs0ctrl;
struct onu_reg_merge g_merge;
struct onu_reg_merge *merge = &g_merge;
struct onu_reg_disp g_disp;
struct onu_reg_disp *disp = &g_disp;
struct onu_reg_pe g_pe;
struct onu_reg_pe *pe = &g_pe;
struct onu_reg_pctrl g_pctrl;
struct onu_reg_pctrl *pctrl = &g_pctrl;
struct onu_reg_link g_link;
struct onu_reg_link *link = &g_link;
struct onu_reg_tod g_tod;
struct onu_reg_tod *tod = &g_tod;
struct onu_reg_status g_status;
struct onu_reg_status *status;

/** ONU related data */
struct ploam_context ploam_ctx;

/**
   Open the device.

   At the first time:
   - allocating internal memory for each new device
   - initialize the device

   \return
   - 0 - if error,
   - device context - if success
*/
long onu_open(void *ctrl, const char *appendix)
{
	struct onu_device *p_dev =
	    (struct onu_device *)IFXOS_MemAlloc(sizeof(struct onu_device));
	(void)appendix;

	if (onu_device_open((struct onu_control *)ctrl, p_dev) !=
								ONU_STATUS_OK) {
		ONU_DEBUG_ERR("Init failed");
		goto open_error;
	}
	return (long)p_dev;

open_error:
	onu_device_close(p_dev);
	return 0;
}

/**
   Release the device.

   \param inode pointer to the inode
   \param filp pointer to the file descriptor

   \return
   - 0 - on success
   - otherwise error code
*/
int onu_release(void *pprivate)
{
	struct onu_device *p_dev = (struct onu_device *)pprivate;

	if (p_dev == NULL)
		return -1;

	if (onu_device_list_delete(p_dev->ctrl, p_dev) == ONU_STATUS_ERR)
		return -1;

	onu_device_close(p_dev);
	return 0;
}

/**
   Writes data to the device.

   \param filp pointer to the file descriptor
   \param buf source buffer
   \param count data length
   \param ppos unused

   \return
   length or a negative error code
*/
int onu_write(void *pprivate, const char *src, const int length)
{
	int total = 0;
	struct onu_device *p_dev = (struct onu_device *)pprivate;
	(void)p_dev;
	(void)src;
	(void)length;

	return total;
}

/**
   Reads data from the device.

   \param filp pointer to the file descriptor
   \param buf destination buffer
   \param count max size of data to read
   \param ppos unused

   \return
   len - data length
*/
int onu_read(void *pprivate, char *dest, const int length)
{
	int len = 0;
	struct onu_device *p_dev = (struct onu_device *)pprivate;
	(void)p_dev;
	(void)dest;
	(void)length;

	return len;
}

/**
   The select function of the driver.
   A user space program may sleep until the driver it wakes up.

\param
      filp - pointer to the file descriptor
\param
      wait   - wait table

\return
   - POLLIN - data available
   - 0 - no data
   - POLLERR - device pointer is zero
*/
int onu_poll(void *pprivate)
{
	struct onu_device *p_dev = (struct onu_device *)pprivate;

	if (IFX_Var_Fifo_isEmpty(&p_dev->nfc_fifo.data) == 0)
		/* data available */
		return 1;
	else
		p_dev->nfc_need_wake_up = true;

	return 0;
}

static void cp(struct onu_device *p_dev, const struct onu_entry *table,
	       struct fio_exchange *exchange, uint32_t nr, uint8_t *buf)
{
	if (_IOC_DIR(table[nr].id) & _IOC_WRITE)
		memcpy(buf, exchange->p_data, table[nr].size_in);

	if (table[nr].p_entry0)
		exchange->error = table[nr].p_entry0(p_dev);
	else if (table[nr].p_entry1)
		exchange->error = table[nr].p_entry1(p_dev, p_dev->io_buf);
	else if (table[nr].p_entry2)
		exchange->error =
		    table[nr].p_entry2(p_dev, p_dev->io_buf, p_dev->io_buf);

	if (_IOC_DIR(table[nr].id) & _IOC_READ) {
		memcpy(exchange->p_data, buf, table[nr].size_out);
		exchange->length = table[nr].size_out;
	} else {
		exchange->length = 0;
	}
}

/**
   Configuration and control interface of the device.

   \param inode pointer to the inode
   \param filp pointer to the file descriptor
   \param cmd function id's
   \param arg optional argument

   \return
   - 0 and positive values - success,
   - negative value - ioctl failed
*/
int onu_ioctl(void *pprivate, unsigned int cmd, ulong_t arg)
{
	int32_t ret = -1, i;
	struct onu_device *p_dev = (struct onu_device *)pprivate;
	uint8_t *buf;
	struct fio_exchange *exchange = (struct fio_exchange *) arg;

	uint32_t type = _IOC_TYPE(cmd);
	uint32_t nr = _IOC_NR(cmd);
#ifndef ONU_SIMULATION
	uint32_t size = _IOC_SIZE(cmd);
#endif
	uint32_t dir = _IOC_DIR(cmd);
	(void)dir;

	buf = &p_dev->io_buf[0];

#ifndef ONU_SIMULATION
	if (size >= ONU_IO_BUF_SIZE)
		return ret;
#endif

	if ((type == ONU_MAGIC) && (nr < common_function_table_size)
	    && (nr == _IOC_NR(common_function_table[nr].id))) {
		cp(p_dev, common_function_table, exchange, nr, buf);
	} else if ((type == PLOAM_MAGIC) && (nr < ploam_function_table_size)
		   && (nr == _IOC_NR(ploam_function_table[nr].id))) {
		cp(p_dev, ploam_function_table, exchange, nr, buf);
	} else if ((type == GTC_MAGIC) && (nr < gtc_func_tbl_size)
		   && (nr == _IOC_NR(gtc_func_tbl[nr].id))) {
		cp(p_dev, gtc_func_tbl, exchange, nr, buf);
	} else if ((type == GPE_MAGIC) && (nr < gpe_function_table_size)
		   && (nr == _IOC_NR(gpe_function_table[nr].id))) {
		cp(p_dev, gpe_function_table, exchange, nr, buf);
	} else if ((type == GPE_TABLE_MAGIC) && (nr < gpe_table_function_table_size)
		   && (nr == _IOC_NR(gpe_table_function_table[nr].id))) {
		cp(p_dev, gpe_table_function_table, exchange, nr, buf);
	} else if ((type == LAN_MAGIC) && (nr < lan_function_table_size)
		   && (nr == _IOC_NR(lan_function_table[nr].id))) {
		cp(p_dev, lan_function_table, exchange, nr, buf);
#ifdef INCLUDE_CLI_SUPPORT
	} else if ((type == _IOC_TYPE(FIO_ONU_CLI))
		   && (nr == _IOC_NR(FIO_ONU_CLI))) {
		if (exchange->length < (ONU_IO_BUF_SIZE - 1)) {
			memcpy(buf, exchange->p_data, exchange->length + 1);
			i = onu_cli(p_dev, (char *)buf);
			if (i >= 0 && i < (ONU_IO_BUF_SIZE - 1)) {
				memcpy(exchange->p_data, buf, i + 1);
				exchange->length = i + 1;
				exchange->error = 0;
			} else {
				exchange->length = 0;
				exchange->error = -1;
			}
		}
#endif
	} else if ((type == _IOC_TYPE(FIO_ONU_EVENT_FIFO))
		   && (nr == _IOC_NR(FIO_ONU_EVENT_FIFO))) {
		uint32_t len = 0;
		struct onu_fifo_header *p_data =
		    (struct onu_fifo_header *) IFX_Var_Fifo_peekElement(
						&p_dev->nfc_fifo.data, &len);

		if (p_data) {
			memcpy(exchange->p_data, p_data, len);
			exchange->length = len;
			if (p_dev->nfc_fifo.overflow) {
				exchange->error = 1;
			} else {
				exchange->error = 0;
			}
			onu_fifo_read(&p_dev->nfc_fifo, IFX_NULL, &len);
		} else {
			exchange->length = 0;
			exchange->error = -1;
		}
	} else if ((type == _IOC_TYPE(FIO_ONU_EVENT_ENABLE_SET))
		   && (nr == _IOC_NR(FIO_ONU_EVENT_ENABLE_SET))) {
		onu_event_enable_set(p_dev,
				     (struct onu_event_mask *)
				             exchange->p_data);
	} else if ((type == _IOC_TYPE(FIO_ONU_EVENT_ENABLE_GET))
		   && (nr == _IOC_NR(FIO_ONU_EVENT_ENABLE_GET))) {
		onu_event_enable_get(p_dev,
				     (struct onu_event_mask *)
					    exchange->p_data);
	} else {
		return ret;
	}

	return 0;
}

/**
   Start ONU timer

   \param timer_no Timer Index
   \param timeout  Timeout in mseconds.
*/
void onu_timer_start(const uint32_t timer_no, uint32_t timeout)
{
	(void)timer_no;
	(void)timeout;
}

/**
   Stop Timer

   \param timer_no Timer Index
*/
void onu_timer_stop(const uint32_t timer_no)
{
	(void)timer_no;
}

/**
   Retrieve pseudo random number within a specified range

   \param range_min   lowest value
   \param range_max   highest value
*/
uint32_t onu_random_get(const uint32_t range_min, const uint32_t range_max)
{
	return (uint32_t)(((double)rand() / (double)RAND_MAX) * range_max +
			  range_min);
}

void onu_led_set(const uint32_t idx, const uint32_t state)
{
	(void)idx;
	(void)state;
}

void onu_irq_enable(struct onu_control *ctrl, uint32_t mask)
{
	(void)ctrl;
	(void)mask;
}

void onu_irq_add(struct onu_control *ctrl, uint32_t mask)
{
	(void)ctrl;
	(void)mask;
}

void onu_irq_remove(struct onu_control *ctrl, uint32_t mask)
{
	(void)ctrl;
	(void)mask;
}

void onu_udelay(uint32_t u_sec)
{
	(void)u_sec;
}

void onu_hot_plug_state(const enum ploam_state state,
			const enum ploam_state old_state)
{
	(void)state;
	(void)old_state;
}

int onu_pe_fw_load(const char *name, struct onu_fw *pe_fw)
{
	(void) name;
	(void) pe_fw;

	return 0;
}

void onu_fw_release(struct onu_fw *pe_fw)
{
	(void) pe_fw;
}

int onu_pe_fw_info_load(const struct onu_fw *pe_fw, struct pe_fw_info *info)
{
	(void) pe_fw;
	(void) info;

	return 0;
}

void onu_pe_fw_info_release(struct pe_fw_info *info)
{
	(void) info;
}

int onu_microcode_load(struct onu_control *ctrl, const char *name)
{
	(void) ctrl;
	(void) name;
	return 0;
}

int onu_gphy_firmware_download(struct onu_control *ctrl, const char *name)
{
	(void) ctrl;
	(void) name;
	return 0;
}

int32_t onu_spin_lock_init(onu_lock_t * id, const char *p_name)
{
	if (IFXOS_MutexInit(id) != IFX_SUCCESS) {
		ONU_DEBUG_ERR("Can't initialize %s mutex.", p_name);
		return -1;
	}
	return 0;
}

int32_t onu_spin_lock_delete(onu_lock_t *id)
{
	return IFXOS_MutexDelete(id);
}

int32_t onu_spin_lock_get(onu_lock_t *id, ulong_t *flags)
{
	IFXOS_MutexGet(id);
	(void)flags;
	return 0;
}

int32_t onu_spin_lock_release(onu_lock_t *id, ulong_t c)
{
	IFXOS_MutexRelease(id);
	(void)c;
	return 0;
}

void onu_time_to_tm(uint32_t totalsecs, int offset, struct onu_tm *result)
{
	memset(result, 0, sizeof(*result));
}

unsigned long onu_elapsed_time_sec_get(unsigned long ref)
{
	return ref;
}

#ifdef INCLUDE_CLI_SUPPORT
char *onu_strsep(char **stringp, const char *delim)
{
	(void)stringp;
	(void)delim;
	return NULL;
}
#endif

/**
   Initialize the driver module.

   \return
   - 0 on success
   - Error code

   \remarks
   Called by the kernel.
*/
int onu_init(void)
{
	char buf[64];
	uint32_t i;

#ifdef INCLUDE_DEBUG_SUPPORT
	onu_debug_lvl = (enum onu_debug_level) 0;
#endif

	ONU_DEBUG_MSG("%s", &onu_whatversion[4]);

	major_number = DEVIO_driver_install(onu_open,
					    onu_release,
					    onu_read,
					    onu_write, onu_ioctl, onu_poll);

	if (major_number == (unsigned)-1) {
		ONU_DEBUG_ERR("can't get major %d", major_number);
		return -1;
	}

	memset(&g_gtc, 0x00, sizeof(g_gtc));

	for (i = 0; i < ONU_MAX_TIMER; i++) {
		/*init_timer(&onu_timer[i]);
		   onu_timer[i].data = i;
		   onu_timer[i].function = onu_timer_exec; */
	}

	memset(onu_control, 0x00, sizeof(onu_control));

	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		sprintf(buf, "/dev/%s%d", ONU_NAME, i);
		memset(&onu_control[i], 0, sizeof(struct onu_control));
		if ((signed)
		    DEVIO_device_add(&onu_control[i], &buf[0],
				     major_number) == IFX_ERROR) {
			ONU_DEBUG_ERR("unable to create device.");
			goto ONU_INIT_ERROR;
		}
		if (IFXOS_MutexInit(&onu_control[i].list_lock) != IFX_SUCCESS) {
			ONU_DEBUG_ERR("can't init list_lock mutex %d", i);
			continue;
		}
		if (ploam_context_init(&onu_control[i]) != ONU_STATUS_OK) {
			ONU_DEBUG_ERR("can't init PLOAM context %d", i);
			continue;
		}
		onu_control[i].run_worker = true;
		if (IFXOS_ThreadInit(&onu_control[i].worker_ctx,
				     "onu",
				     onu_worker_thread,
				     ONU_WORKER_THREAD_STACK_SIZE,
				     ONU_WORKER_THREAD_PRIO,
				     (ulong_t) & onu_control[i],
				     0) != IFX_SUCCESS) {
			ONU_DEBUG_ERR("can't start worker thread %d", i);
			continue;
		}
		onu_timer_start(i << 16 | ONU_TIMER_TO1, 10);
	}

#ifdef INCLUDE_CLI_SUPPORT
	onu_cli_init();
#endif

	return 0;

      ONU_INIT_ERROR:

	onu_exit();

	return -1;
}

/**
   Clean up the module if unloaded.

   \remarks
   Called by the kernel.
*/
void onu_exit(void)
{
	int i;
	struct onu_device *p_dev, *pDelete;

	DEVIO_driver_remove(major_number, 1);

	for (i = 0; i < MAX_ONU_INSTANCES; i++)
		onu_control[i].run_worker = false;
	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		IFXOS_ThreadDelete(&onu_control[i].worker_ctx, 2000);
		if (IFXOS_MutexGet(&onu_control[i].list_lock) == IFX_SUCCESS) {
			p_dev = onu_control[i].p_dev_head;
			while (p_dev) {
				pDelete = p_dev;
				p_dev = p_dev->p_next;
				onu_device_close(pDelete);
			}
			IFXOS_MutexRelease(&onu_control[i].list_lock);
		}
		IFXOS_MutexDelete(&onu_control[i].list_lock);
		ploam_context_free(&onu_control[i]);
	}

	ONU_DEBUG_MSG("cleanup successful");
}

void event_queue_init(struct onu_control *ctrl)
{
}

int event_queue_wait(struct onu_control *ctrl)
{
	if (IFX_Var_Fifo_isEmpty(&ctrl->nfc_fifo.data))
		IFXOS_MSecSleep(10);

	return 0;
}

void event_queue_wakeup(struct onu_control *ctrl)
{
}

uint32_t onu_gpon_link_status_get(void)
{
	return 0;
}

uint32_t onu_mac_link_status_get(const uint8_t idx)
{
	return 0;
}

uint32_t onu_gpon_packet_count_get(const uint8_t rx)
{
	return 0;
}

uint32_t onu_mac_packet_count_get(const uint8_t idx, const uint8_t rx)
{
	return 0;
}

#endif				/* ONU_SIMULATION */

/*! @} */

/*! @} */
