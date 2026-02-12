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

#if defined(ONU_LIBRARY)

#include <stdlib.h>
#include <sys_tickedtimer.h>
#include "drv_onu_api.h"
#include "kernel.h"
#include "device_io.h"

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
#include "drv_onu_ll_gpearb.h"
#include "drv_onu_ll_eim.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_fsqm.h"
#include "drv_onu_ll_iqm.h"
#include "drv_onu_ll_octrlg.h"
#include "drv_onu_ll_octrll.h"
#include "drv_onu_ll_ictrlg.h"
#include "drv_onu_ll_ictrll.h"
#include "drv_onu_ll_ssb.h"
#include "drv_onu_ll_sce.h"
#include "drv_onu_ll_gtc.h"
#include "drv_onu_ll_tmu.h"
#include "drv_onu_reg_ictrlc.h"
#include "drv_onu_reg_sbs0ctrl.h"
#include "drv_onu_ll_cop.h"
#include "drv_onu_ll_tbm.h"
#include "drv_onu_ll_tod.h"

/** common callbacks used by ioctl() */
extern const struct onu_entry common_function_table[];
extern const unsigned int common_function_table_size;
extern const struct onu_entry ploam_function_table[];
extern const unsigned int ploam_function_table_size;

#define IFXOS_BlockAlloc IFXOS_MemAlloc
#define IFXOS_BlockFree IFXOS_MemFree

long onu_open(void *device, const char *appendix);
int onu_release(void *pprivate);
int onu_ioctl(void *pprivate, unsigned int cmd, ulong_t argument);

struct timer_list onu_timer[ONU_MAX_TIMER];
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

STATIC void onu_proc_version_get(struct seq_file *s);
STATIC void onu_proc_status_get(struct seq_file *s);
STATIC void onu_proc_ls(struct seq_file *s);

struct onu_reg_gtc *gtc = (struct onu_reg_gtc *)ONU_GTC_BASE;
struct onu_reg_gpearb *gpearb = (struct onu_reg_gpearb *)ONU_GPEARB_BASE;
union onu_reg_eim *eim = (union onu_reg_eim *)ONU_EIM_BASE;
struct onu_reg_sxgmii *sxgmii = (struct onu_reg_sxgmii *)ONU_SXGMII_BASE;
struct onu_reg_iqm *iqm = (struct onu_reg_iqm *)ONU_IQM_BASE;
struct onu_reg_fsqm *fsqm = (struct onu_reg_fsqm *)ONU_FSQM_BASE;
struct onu_reg_ictrlc *ictrlc = (struct onu_reg_ictrlc *)ONU_ICTRLC0_BASE;
struct onu_reg_octrlc *octrlc = (struct onu_reg_octrlc *)ONU_OCTRLC_BASE;
struct onu_reg_ictrll *ictrll = (struct onu_reg_ictrll *)ONU_ICTRLL0_BASE;
struct onu_reg_ictrlg *ictrlg = (struct onu_reg_ictrlg *)ONU_ICTRLG_BASE;
struct onu_reg_octrll *octrll = (struct onu_reg_octrll *)ONU_OCTRLL0_BASE;
struct onu_reg_octrlg *octrlg = (struct onu_reg_octrlg *)ONU_OCTRLG_BASE;
struct onu_reg_sys_eth *sys_eth = (struct onu_reg_sys_eth *)ONU_SYS_ETH_BASE;
struct onu_reg_sys_gpe *sys_gpe = (struct onu_reg_sys_gpe *)ONU_SYS_GPE_BASE;
struct onu_reg_tmu *tmu = (struct onu_reg_tmu *)ONU_TMU_BASE;
struct onu_reg_tbm *tbm = (struct onu_reg_tbm *)ONU_TBM_BASE;
struct onu_reg_sbs0ctrl *sbs0ctrl = (struct onu_reg_sbs0ctrl *)ONU_SBS0CTRL_BASE;
struct onu_reg_merge *merge = (struct onu_reg_merge *)ONU_MERGE_BASE;
struct onu_reg_disp *disp = (struct onu_reg_disp *)ONU_DISP_BASE;
struct onu_reg_pe *pe = (struct onu_reg_pe *)ONU_PE0_BASE;
struct onu_reg_pctrl *pctrl = (struct onu_reg_pctrl *)ONU_PCTRL_BASE;
struct onu_reg_link *link = (struct onu_reg_link *)ONU_LINK0_BASE;
struct onu_reg_tod *tod = (struct onu_reg_tod *)ONU_TOD_BASE;
/*struct onu_reg_status *status = (struct onu_reg_status *)ONU_STATUS_BASE;*/
struct onu_reg_sys1 *sys1 = (struct onu_sys1_tod *)ONU_SYS1_BASE;

/** ONU related data */
struct ploam_context ploam_ctx;
static struct onu_device onu_device;

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
	struct onu_device *p_dev = &onu_device;
	(void)appendix;

	if (gpe_chip_version == GPE_CHIP_UNKNOWN)
		gpe_chip_version = onu_chip_get();

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

	onu_device_close(p_dev);
	return 0;
}

/**
   Quick check if the notification FIFO is filled.

\return
   - 1 - data available
   - 0 - no data available
*/
int onu_poll(void)
{
	if (IFX_Var_Fifo_isEmpty(&onu_control[0].nfc_fifo.data) == 0)
		/* data available */
		return 1;
	return 0;
}

STATIC int onu_table_check(const char *name,
			   const struct onu_entry *tbl,
			   const uint32_t num)
{
	uint32_t i;
	int ret = 0;

	for(i=0; i<num; i++) {
		if(_IOC_NR(tbl[i].id) == 0)
			continue;
		if(tbl[i].p_entry0 == NULL &&
			tbl[i].p_entry1 == NULL &&
			tbl[i].p_entry2 == NULL )
			continue;
		if(_IOC_NR(tbl[i].id) != i) {
			ONU_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x - "
				      "id not in ascending order",
				      name, i, tbl[i].name, tbl[i].id);
			ret = -1;
		}
		if (_IOC_DIR(tbl[i].id) & _IOC_READ && tbl[i].size_out == 0) {
			ONU_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x - read size 0",
				      name, i, tbl[i].name, tbl[i].id);
			ret = -1;
		}
		if (_IOC_DIR(tbl[i].id) & _IOC_WRITE && tbl[i].size_in == 0) {
			ONU_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x - write size 0",
					name, i, tbl[i].name, tbl[i].id);
			ret = -1;
		}
		if ((_IOC_DIR(tbl[i].id) & _IOC_READ) == 0 && tbl[i].size_out) {
			ONU_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x - "
				      "read size %d but _IOC_READ not set",
				      name, i, tbl[i].name, tbl[i].id,
				      tbl[i].size_out);
			ret = -1;
		}
		if ((_IOC_DIR(tbl[i].id) & _IOC_WRITE) == 0 && tbl[i].size_in) {
			ONU_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x - "
				      "write size %d but _IOC_WRITE not set",
				      name, i, tbl[i].name, tbl[i].id,
				      tbl[i].size_out);
			ret = -1;
		}
	}
	return ret;
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
	int32_t ret = -1;
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
	} else if ((type == _IOC_TYPE(FIO_ONU_EVENT_FIFO))
		   && (nr == _IOC_NR(FIO_ONU_EVENT_FIFO))) {
		uint32_t len = 0;
		struct onu_fifo_header *p_data =
		    (struct onu_fifo_header *) IFX_Var_Fifo_peekElement(
						&onu_control[0].nfc_fifo.data, &len);
		if (p_data) {
			memcpy(exchange->p_data, p_data, len);
			exchange->length = len;
			if (onu_control[0].nfc_fifo.overflow) {
				exchange->error = 1;
			} else {
				exchange->error = 0;
			}
			onu_fifo_read(&onu_control[0].nfc_fifo, NULL, &len);
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
	if (onu_timer[timer_no].running) {
		printf("timer %d is pending" ONU_CRLF, timer_no);
	} else {
		timer_start (&onu_timer[timer_no], timeout, 0);
	}
}

/**
   Stop Timer

   \param timer_no Timer Index
*/
void onu_timer_stop(const uint32_t timer_no)
{
	tick_timer_stop (&onu_timer[timer_no]);
}

/** Timer Handler

   \param timer_no Indicates the timer index
*/
STATIC void onu_timer_handler(unsigned long timer_no)
{
#if (MAX_ONU_INSTANCES == 1)
	onu_timer_exec(&onu_control[0], timer_no);
#else
	uint32_t num = timer_no & 0xFFFF;
	struct onu_control *ctrl = &onu_control[timer_no >> 16];

	onu_timer_exec(ctrl, num);
#endif
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
	udelay(u_sec);
}

void onu_hot_plug_state(const enum ploam_state state,
			const enum ploam_state old_state)
{
	(void)state;
	(void)old_state;
	printf("%d", state);
}

void onu_irq_poll(void)
{
	uint32_t irnicr;
	static const uint32_t link_port[3] = {
		0,
		ONU_LINK0_SIZE / 4,
		(2 * ONU_LINK0_SIZE) / 4
	};

	onu_gtc_ds_handle(&onu_control[0], ONU_MAX_TIMER);
	gtc_us_handle(&onu_control[0]);

	irnicr = tmu_r32(irnicr);
	onu_gpe_egress_cpu_port_handle(&onu_control[0], irnicr);

	irnicr = link_r32_table(irnicr, link_port[1]);
	if (irnicr & LINK_IRNICR_RXR) {
		onu_gpe_omci_handle(&onu_control[0]);
	}
}

int onu_pe_fw_load(const char *name, struct onu_fw *pe_fw)
{
	int ret = 0;
	const struct firmware *fw;

	if (strlen(name) > ONU_PE_FIRMWARE_NAME_MAX - 1) {
		ONU_DEBUG_ERR(" Error loading firmware (fw name is too long)");
		return -5;
	}

	if (request_firmware(&fw, name)) {
		if (!pe_fw->bin || !pe_fw->len) {
			return -3;
		} else {
			/* use the provided firmware*/
			return 0;
		}
	} else {
		onu_fw_release(pe_fw);
	}

	if (fw->size <= PE_FW_HEADER_SIZE) {
		ONU_DEBUG_ERR("Error loading firmware (invalid firmware binary)");
		return -4;
	}

	pe_fw->len = fw->size;
	pe_fw->bin = (uint8_t *)fw->data; /* cast away the const qualifier */
	strncpy(pe_fw->fw_name, name, ONU_PE_FIRMWARE_NAME_MAX);

	release_firmware(fw);

	return ret;
}

void onu_fw_release(struct onu_fw *pe_fw)
{
	(void) pe_fw;
}

int onu_pe_fw_info_load(const struct onu_fw *pe_fw, struct pe_fw_info *info)
{
	uint32_t opt_hdr_len;
#if 0
	uint8_t *opt_hdr;
	unsigned long flags = 0;
#endif

	if (info->opt_hdr)
		return -1;

	strncpy(info->fw_name, pe_fw->fw_name, ONU_PE_FIRMWARE_NAME_MAX);

	info->flags[0] = ((uint32_t*)pe_fw->bin)[PE_FW_FLAG0_OFFSET_WORD];
	info->flags[1] = ((uint32_t*)pe_fw->bin)[PE_FW_FLAG1_OFFSET_WORD];

	opt_hdr_len = info->flags[0] & PE_FW_FLAG0_OPT_HEADER_MASK ?
		   ((uint32_t*)pe_fw->bin)[PE_FW_OPT_HDR_LEN_OFFSET_WORD] : 0;

	memcpy(&info->ver.major, pe_fw->bin, 4);

	if (!opt_hdr_len)
		return 0;

	if (info->opt_hdr_len % sizeof(uint32_t))
		return -1;

#if 0
	opt_hdr = vmalloc(info->opt_hdr_len);

	if (!opt_hdr) {
		printk(KERN_ERR DEBUG_PREFIX
			" Error alloc opt header (allocate %d bytes)\n",
				info->opt_hdr_len);
		return -2;
	} else {
		onu_spin_lock_get(&mailbox_lock, &flags);
		info->opt_hdr_len = opt_hdr_len;
		info->opt_hdr = opt_hdr;
		memcpy(info->opt_hdr, pe_fw->bin + PE_FW_HEADER_SIZE,
		       info->opt_hdr_len);
		onu_spin_lock_release(&mailbox_lock, flags);
	}
#endif

	return 0;
}

void onu_pe_fw_info_release(struct pe_fw_info *info)
{
	(void) info;
}

int onu_microcode_load(struct onu_control *ctrl, const char *name)
{
	const struct firmware *fw;

	if (request_firmware(&fw, name)) {
		ONU_DEBUG_ERR("Error loading microcode (microcode not available)");
		return -3;
	}
	if (fw->size < 32 || fw->size >= ONU_MAX_COP_SIZE) {
		ONU_DEBUG_ERR("Error loading microcode (invalid microcode binary)");
		return -4;
	}

	memcpy(ctrl->cop_microcode_bin, fw->data, fw->size);
	ctrl->cop_microcode_len = fw->size;

	release_firmware(fw);

	return 0;
}

int onu_gphy_firmware_download(struct onu_control *ctrl, const char *name)
{
	const char *error_cause = NULL;
	const struct firmware *fw;
	uint32_t load_offset = (16 << 10); /* gphy needs 16k alignment */

	if (ctrl->lan_gphy_fw_ram_addr) {
		error_cause = "already loaded";
		goto error_out;
	}

	if (request_firmware(&fw, name)) {
		error_cause = "no firmware";
		goto error_out;
	}

	if (fw->size < 8) {
		error_cause = "invalid binary";
		goto error_release;
	}

	if (fw->size > (48 << 10)) {
		error_cause = "invalid binary size (too big)";
		goto error_release;
	}

	/* copy firmware data*/
	memcpy((void*)(ONU_SBS0RAM_BASE | load_offset), fw->data, fw->size);
	ctrl->lan_gphy_fw_ram_addr = (ONU_SBS0RAM_BASE | load_offset);

	ONU_DEBUG_ERR("GPHY Firmware loaded (%s)", name);

error_release:
	release_firmware(fw);

error_out:
	if (error_cause) {
		ONU_DEBUG_ERR(" Error loading GPHY firmware (%s)", error_cause);
		return -1;
	}

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

/**
   Clean up the module if unloaded.

   \remarks
   Called by the kernel.
*/
void onu_exit(void)
{
	int i;

	DEVIO_driver_remove(major_number, 1);

	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		ploam_context_free(&onu_control[i]);
	}

	ONU_DEBUG_MSG("cleanup successful");
}

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
	int res;

#ifdef INCLUDE_DEBUG_SUPPORT
	onu_debug_lvl = ONU_DBG_MSG;
#endif

	ONU_DEBUG_MSG("%s", &onu_whatversion[4]);

#ifdef INCLUDE_DEBUG_SUPPORT
	onu_debug_lvl = ONU_DBG_WRN;
#endif

	res = onu_table_check(	"common", &common_function_table[0],
				common_function_table_size);
	if (res) 
		return -1;
	res = onu_table_check(	"gtc", &gtc_func_tbl[0],
				gtc_func_tbl_size);
	if (res) 
		return -1;
	res = onu_table_check(	"ploam", &ploam_function_table[0],
				ploam_function_table_size);
	if (res) 
		return -1;
	res = onu_table_check(	"gpe", &gpe_function_table[0],
				gpe_function_table_size);
	if (res) 
		return -1;
	res = onu_table_check(	"gpe_table", &gpe_table_function_table[0],
				gpe_table_function_table_size);
	if (res) 
		return -1;
	res = onu_table_check(	"lan", &lan_function_table[0],
				lan_function_table_size);
	if (res) 
		return -1;

	major_number = DEVIO_driver_install(onu_open,
					    onu_release,
					    NULL,
					    NULL, onu_ioctl, NULL);

	if (major_number == (unsigned)-1) {
		ONU_DEBUG_ERR("can't get major %d", major_number);
		return -1;
	}

	for (i = 0; i < ONU_MAX_TIMER; i++) {
		timer_init (&onu_timer[i], onu_timer_handler, i);
	}

	memset(onu_control, 0x00, sizeof(onu_control));

	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		/*sprintf(buf, "/dev/%s%d", ONU_NAME, i);*/
		strcpy(buf, "/dev/onu0");
		memset(&onu_control[i], 0, sizeof(struct onu_control));
		if ((signed)
		    DEVIO_device_add(&onu_control[i], &buf[0],
				     major_number) == IFX_ERROR) {
			ONU_DEBUG_ERR("unable to create device.");
			goto ONU_INIT_ERROR;
		}
		if (ploam_context_init(&onu_control[i]) != ONU_STATUS_OK) {
			ONU_DEBUG_ERR("can't init PLOAM context %d", i);
			continue;
		}
	}

	return 0;

ONU_INIT_ERROR:

	onu_exit();

	return -1;
}

void event_queue_init(struct onu_control *ctrl)
{
}

int event_queue_wait(struct onu_control *ctrl)
{
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
	return 1;
}

uint32_t onu_gpon_packet_count_get(const uint8_t rx)
{
	return 0;
}

uint32_t onu_mac_packet_count_get(const uint8_t idx, const uint8_t rx)
{
	return 0;
}

#if defined(INCLUDE_DUMP)

typedef void (*proc_single_callback_t)(struct seq_file *);
typedef int (*proc_callback_t)(struct seq_file *, int);
typedef int (*proc_init_callback_t)(void);

struct proc_entry {
	char const *name;
	proc_single_callback_t single_callback;
	proc_callback_t callback;
	proc_init_callback_t init_callback;
};

static struct proc_entry proc_entries[] = {
	{"ls",			onu_proc_ls, NULL, NULL},
	{"version",		onu_proc_version_get, NULL, NULL},
	{"status",		onu_proc_status_get, NULL, NULL},
	{"eim",			eim_dump, NULL, NULL},
	{"sys",			sys_dump, NULL, NULL},
	{"octrlg",		octrlg_dump, NULL, NULL},
	{"octrlg_table",	octrlg_table_dump, NULL, NULL},
	{"octrll",		octrll_dump, NULL, NULL},
	{"ictrlg",		ictrlg_dump, NULL, NULL},
	{"ictrlg_table",	ictrlg_table_dump, NULL, NULL},
	{"ictrll",		ictrll_dump, NULL, NULL},
	{"fsqm",		fsqm_dump, NULL, NULL},
	{"fsqm_llt",		NULL, fsqm_llt, NULL},
	{"fsqm_rcnt",		NULL, fsqm_rcnt, NULL},
	{"iqm",			iqm_dump, NULL, NULL},
	{"ssb",			ssb_dump, NULL, NULL},
	{"gpearb",		gpearb_dump, NULL, NULL},
	{"sce",			sce_dump, NULL, NULL},
	{"merge",		merge_dump, NULL, NULL},
	{"tmu",			tmu_dump, NULL, NULL},
	{"tmu_eqt",		tmu_eqt_dump, NULL, NULL},
	{"tmu_ept",		tmu_ept_dump, NULL, NULL},
	{"tmu_sbit",		tmu_sbit_dump, NULL, NULL},
	{"tmu_sbot",		tmu_sbot_dump, NULL, NULL},
	{"tmu_tbst",		tmu_tbst_dump, NULL, NULL},
	{"tmu_ppt",		NULL, tmu_ppt_dump, tmu_ppt_dump_start},
	{"tbm",			tbm_dump, NULL, NULL},
	{"gpe_table",		gpe_table_dump, NULL, NULL},
	{"gpe_dsgem",		gpe_table_dsgem, NULL, NULL},
	{"gpe_usgem",		gpe_table_usgem, NULL, NULL},
	{"gpe_fidhash",		gpe_table_fidhash, NULL, NULL},
	{"gpe_fidass",		gpe_table_fidass, NULL, NULL},
	{"gpe_tagg",		gpe_table_tagg, NULL, NULL},
	{"gpe_vlan",		gpe_table_vlan, NULL, NULL},
	{"gpe_extvlan",		gpe_table_extvlan, NULL, NULL},
	{"gpe_vlanrule",	gpe_table_vlanrule, NULL, NULL},
	{"gpe_vlantreatment",	gpe_table_vlantreatment,NULL, NULL},
	{"gpe_shortfwdhash",	gpe_table_shortfwdhash, NULL, NULL},
	{"gpe_shortfwdmac",	gpe_table_shortfwdmac, NULL, NULL},
	{"gpe_shortfwdmacmc",	gpe_table_shortfwdmacmc, NULL, NULL},
	{"gpe_shortfwdipv4",	gpe_table_shortfwdipv4, NULL, NULL},
	{"gpe_shortfwdipv4mc",	gpe_table_shortfwdipv4mc, NULL, NULL},
	{"gpe_longfwdhash",	gpe_table_longfwdhash, NULL, NULL},
	{"gpe_longfwipv6",	gpe_table_longfwdipv6, NULL, NULL},
	{"gpe_longfwipv6mc",	gpe_table_longfwdipv6mc, NULL, NULL},
	{"gpe_dsmcipv4",	gpe_table_dsmcipv4, NULL, NULL},
	{"gpe_dsmcipv6",	gpe_table_dsmcipv6, NULL, NULL},
	{"gpe_learnlim",	gpe_table_learnlim, NULL, NULL},
	{"gpe_exp",		gpe_table_exp, NULL, NULL},
	{"gpe_macfilter",	gpe_table_macfilter, NULL, NULL},
	{"gpe_copcounter",	gpe_table_counter, NULL, NULL},
	{"gpe_bridgeport",	gpe_table_bridgeport, NULL, NULL},
	{"gpe_pmapper",		gpe_table_pmapper, NULL, NULL},
	{"gpe_lanport",		gpe_table_lanport, NULL, NULL},
	{"gpe_pcpdec",		gpe_table_pcpdec, NULL, NULL},
	{"gpe_dscpdec",		gpe_table_dscpdec, NULL, NULL},
	{"gpe_pcpenc",		gpe_table_pcpenc, NULL, NULL},
	{"gpe_dscpenc",		gpe_table_dscpenc, NULL, NULL},
	{"gpe_redir",		gpe_table_redir, NULL, NULL},
	{"gpe_aclfilt",		gpe_table_aclfilt, NULL, NULL},
	{"gpe_bridge",		gpe_table_bridge, NULL, NULL},
	{"gpe_const",		gpe_table_const, NULL, NULL},
	{"gpe_status",		gpe_table_status, NULL, NULL},
	{"gpe_ethfilter",	gpe_table_ethertype_filter, NULL, NULL},
	{"gtc",			gtc_dump, NULL, NULL}
};

STATIC void onu_proc_version_get(struct seq_file *s)
{
	seq_printf(s, "%s" ONU_CRLF, &onu_whatversion[4]);
	seq_printf(s, "Compiled on %s, %s for base kernel" ONU_CRLF,
		   __DATE__, __TIME__);
}

STATIC void onu_proc_status_get(struct seq_file *s)
{
	unsigned int i, k;
	struct onu_device *p_dev;
	uint32_t *ptr, l, m, prev, idx;
	uint8_t *ptr8;

	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		seq_printf(s, "PLOAM[%d]" ONU_CRLF, i);
		seq_printf(s, "current state = %d" ONU_CRLF,
			   onu_control[i].ploam_ctx.curr_state);
		seq_printf(s, "previous state = %d" ONU_CRLF,
			   onu_control[i].ploam_ctx.previous_state);
		seq_printf(s, "NFC FIFO mask = 0x%x" ONU_CRLF,
			   onu_control[i].nfc_fifo.mask);
		seq_printf(s, "NFC FIFO avail = %d" ONU_CRLF,
			   IFX_Var_Fifo_getCount(&onu_control[i].nfc_fifo.
						 data));
		seq_printf(s, "NFC FIFO lost = %d" ONU_CRLF,
			   onu_control[i].nfc_fifo.lost);
		seq_printf(s, "OMCI downstream = %d" ONU_CRLF,
			   onu_control[i].omci_downstream);
		seq_printf(s, "OMCI dropped downstream = %d" ONU_CRLF,
			   onu_control[i].omci_downstream_dropped);
		seq_printf(s, "OMCI upstream = %d" ONU_CRLF,
			   onu_control[i].omci_upstream);
#if 0
		if (IFXOS_MutexGet(&onu_control[i].list_lock) == IFX_SUCCESS) {
			p_dev = onu_control[i].p_dev_head;
			k = 0;
			while (p_dev) {
				seq_printf(s, "Device[%d][%d]" ONU_CRLF, i, k);
				seq_printf(s, "NFC FIFO mask = 0x%x" ONU_CRLF,
					   p_dev->nfc_fifo.mask);
				seq_printf(s, "NFC FIFO avail = %d" ONU_CRLF,
					   IFX_Var_Fifo_getCount(
						&p_dev->nfc_fifo.data));
				seq_printf(s, "NFC FIFO lost = %d" ONU_CRLF,
					   p_dev->nfc_fifo.lost);
				p_dev = p_dev->p_next;
				k++;
			}
			IFXOS_MutexRelease(&onu_control[i].list_lock);
		}
#endif
	}
}

STATIC void onu_proc_ls(struct seq_file *s)
{
	struct proc_entry *p = &proc_entries[0];
	unsigned int i;

	for(i=0; i<sizeof(proc_entries)/sizeof(proc_entries[0]); i++, p++) {
		seq_printf(s, "%s\n", p->name);
	}
}

void proc_show(const char *name, char *buf, const uint32_t max_size)
{
	unsigned int i, ret;
	struct proc_entry *p = &proc_entries[0];
	struct seq_file s;

	for(i=0; i<sizeof(proc_entries)/sizeof(proc_entries[0]); i++, p++) {
		ret = strcmp(name, p->name);
		if(ret == 0)
			break;
	}

	if(i == sizeof(proc_entries)/sizeof(proc_entries[0]))
		return;

	s.pos = 0;
	s.buf = buf;
	buf[0] = 0;
	s.max_size = max_size;
	if(p->init_callback)
		s.pos = p->init_callback();
	if(p->single_callback)
		p->single_callback(&s);
	if(p->callback)
		p->callback(&s, s.pos);
}

int seq_printf(struct seq_file *s, const char *fmt, ...)
{
	va_list ap;
	int ret = 0;
	int remaining = (s->max_size - 1) - s->pos;

	va_start(ap, fmt);
	ret = vsprintf(NULL, fmt, ap);
	if(ret > 0) {
		if(ret < remaining)
			ret = vsprintf(s->buf + s->pos, fmt, ap);
		else
			ret = 0;
	}
	va_end(ap);
	if(ret > 0) {
		s->pos += ret;
		s->buf[s->pos] = 0;
	}

	return ret;
}

#endif

#endif				/* ONU_LIBRARY */

/*! @} */

/*! @} */
