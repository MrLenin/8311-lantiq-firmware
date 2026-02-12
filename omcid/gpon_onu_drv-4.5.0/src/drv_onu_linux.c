/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_LINUX_INTERNAL Linux Specific Implementation
   @{
*/

#ifdef HAVE_CONFIG_H
#include "drv_onu_config.h"
#endif

#if defined(LINUX) && !defined(ONU_SIMULATION)

#ifdef __KERNEL__
#  include <linux/kernel.h>
#  include <linux/time.h>
#endif

#ifdef MODULE
#  include <linux/module.h>
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
#  include <linux/proc_fs.h>
#  include <linux/seq_file.h>
#endif

#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
#   include <linux/utsrelease.h>
#else
#   include <generated/utsrelease.h>
#endif
#include <linux/semaphore.h>
#include <linux/interrupt.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/jiffies.h>

#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/kobject.h>
#include <asm/uaccess.h>
#include <linux/leds.h>
#include <linux/firmware.h>

/* for die notification */
#include <linux/kdebug.h>
#ifndef ST0_NMI
#define ST0_NMI                   0x00080000
#endif

#ifdef CONFIG_IFXMIPS
#  if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
#     include <asm/ifxmips/ifxmips.h>
#     include <asm/ifxmips/ifxmips_irq.h>
#     include <asm/ifxmips/ifxmips_gpio.h>
#     include <gpio.h>
#  else
#     include <ifxmips.h>
#     include <ifxmips_irq.h>
#     include <ifxmips_gpio.h>
#  endif
#  ifdef CONFIG_SOC_FALCON
#     include <falcon/falcon_irq.h>
#  endif
#elif CONFIG_LANTIQ
#  include <lantiq.h>
#  include <falcon_irq.h>
#else
#  include <asm/ifx/ifx_regs.h>
#  include <asm/ifx/ifx_gpio.h>
#  define IFXMIPS_EIU_IR0 IFX_EIU_IR0
#  define IFXMIPS_EIU_EXIN_C IFX_ICU_EIU_EXIN_C
#  define IFXMIPS_EIU_INEN IFX_ICU_EIU_INEN
#  define ifxmips_w32 IFX_REG_W32
#  define ifxmips_r32 IFX_REG_R32
#endif

#include "ifxos_device_io.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"

#include "drv_onu_api.h"
#include "drv_onu_reg_gtc.h"
#include "drv_onu_cli_core.h"
#include "drv_onu_gtc_api.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_gpe_tables_api.h"
#include "drv_onu_lan_api.h"
#include "drv_onu_timer.h"
#include "drv_onu_register.h"
#include "drv_onu_ploam_api.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_event_api.h"
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

typedef irqreturn_t (*irq_hndl_fct_t)(int irq, void *ctrl);

struct onu_irq_table {
	/** IRQ line number*/
	uint32_t irq_num;
	/** IRQ name. Will be displayed under /proc/interrupts */
	char *irq_name;
	/** ISR handler */
	irq_hndl_fct_t irq_hndl;
	/** true if irq handler requested */
	bool installed;
	/** true if enabled */
	bool enabled;
	/** max. duration in msec */
	volatile unsigned long duration;
};

STATIC irqreturn_t onu_isr_gtc_ds(int irq, void *ctrl);
STATIC irqreturn_t onu_isr_gtc_us(int irq, void *ctrl);
STATIC irqreturn_t onu_isr_iqm(int irq, void *ctrl);
STATIC irqreturn_t onu_isr_tmu(int irq, void *ctrl);
STATIC irqreturn_t onu_isr_config_break(int irq, void *ctrl);
STATIC irqreturn_t onu_isr_tod(int irq, void *ctrl);
STATIC irqreturn_t onu_isr_link(int irq, void *ctrl);

struct onu_irq_table onu_irq_tbl[] = {
	{FALCON_IRQ_GTC_DS,	  "gtc_ds",  onu_isr_gtc_ds,	   false, 0},
	{FALCON_IRQ_GTC_US,	  "gtc_us",  onu_isr_gtc_us,	   false, 0},
	{FALCON_IRQ_IQM,	  "iqm",     onu_isr_iqm,	   false, 0},
	{FALCON_IRQ_TMU,    	  "tmu",     onu_isr_tmu,	   false, 0},
	{FALCON_IRQ_CONFIG_BREAK, "cfg_brk", onu_isr_config_break, false, 0},
	{FALCON_IRQ_TOD,    	  "tod",     onu_isr_tod,	   false, 0},
	{FALCON_IRQ_LINK1,    	  "link",    onu_isr_link,	   false, 0}
};

static struct class *gpon_class;
static struct device *dev[MAX_ONU_INSTANCES];

/** common callbacks used by ioctl() */
extern const struct onu_entry common_function_table[];
extern const unsigned int common_function_table_size;
extern const struct onu_entry ploam_function_table[];
extern const unsigned int ploam_function_table_size;

STATIC int onu_open(struct inode *inode, struct file *filp);
STATIC int onu_release(struct inode *inode, struct file *filp);
STATIC ssize_t onu_write(struct file *filp,
			 const char *buf, size_t count, loff_t *ppos);
STATIC ssize_t onu_read(struct file *filp,
			char *buf, size_t length, loff_t *ppos);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))
STATIC int onu_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
		     unsigned long arg);
#else
STATIC long onu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#endif
STATIC unsigned int onu_poll(struct file *filp, poll_table *table);

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
STATIC void onu_proc_version_get(struct seq_file *s);
STATIC void onu_proc_status_get(struct seq_file *s);
STATIC int onu_proc_install(void);
#endif

STATIC struct timer_list onu_timer[ONU_MAX_TIMER];
#ifdef DEFINE_SEMAPHORE
STATIC DEFINE_SEMAPHORE(RW_buf_sem);
#else
STATIC DECLARE_MUTEX(RW_buf_sem);
#endif

STATIC unsigned char major_number = 0;

onu_lock_t mailbox_lock;
onu_lock_t cop_lock;
onu_lock_t ictrlc_lock;
onu_lock_t octrlc_lock;
onu_lock_t link_lock;
onu_lock_t sce_lock;
onu_lock_t meter_lock;
onu_lock_t tmu_lock;
onu_lock_t enqueue_lock;

extern u64 uevent_next_seqnum(void);

/** install parameter debug: off (4), msg (0), warn (1), err (2) */
STATIC unsigned char debug = ONU_DBG_ERR;

module_param(debug, byte, 0);
MODULE_PARM_DESC(debug, "off (4), msg (0), warn (1), err (2)");

STATIC struct file_operations onu_fops = {
      owner:THIS_MODULE,
      read:onu_read,
      write:onu_write,
      poll:onu_poll,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))
      ioctl:onu_ioctl,
#else
      unlocked_ioctl:onu_ioctl,
#endif
      open:onu_open,
      release:onu_release
};

enum onu_debug_level onu_debug_lvl = ONU_DBG_OFF;
struct onu_reg_gtc *gtc = NULL;
struct onu_reg_gpearb *gpearb = NULL;
union onu_reg_eim *eim = NULL;
struct onu_reg_sxgmii *sxgmii = NULL;
struct onu_reg_iqm *iqm = NULL;
struct onu_reg_fsqm *fsqm = NULL;
struct onu_reg_ictrlc *ictrlc = NULL;
struct onu_reg_octrlc *octrlc = NULL;
struct onu_reg_ictrll *ictrll = NULL;
struct onu_reg_ictrlg *ictrlg = NULL;
struct onu_reg_octrll *octrll = NULL;
struct onu_reg_octrlg *octrlg = NULL;
struct onu_reg_sys_eth *sys_eth = NULL;
struct onu_reg_sys_gpe *sys_gpe = NULL;
struct onu_reg_tmu *tmu = NULL;
struct onu_reg_sbs0ctrl *sbs0ctrl = NULL;
struct onu_reg_merge *merge = NULL;
struct onu_reg_disp *disp = NULL;
struct onu_reg_link *link = NULL;
struct onu_reg_pe *pe = NULL;
struct onu_reg_tbm *tbm = NULL;
struct onu_reg_pctrl *pctrl = NULL;
struct onu_reg_tod *tod = NULL;
struct onu_reg_status *status = NULL;
struct onu_reg_sys1 *sys1 = NULL;

struct onu_reg_table {
	/** register pointer reference */
	void **reg;
	/** base address */
	uint32_t base;
	/** register block size */
	uint32_t size;
	/** resource name. Will be displayed under /proc/iomem */
	const char *name;
};
static const struct onu_reg_table onu_reg_tbl[] =
{
	{ (void **)&gtc, ONU_GTC_BASE, ONU_GTC_SIZE, "onu|gtc" },
	{ (void **)&gpearb, ONU_GPEARB_BASE, ONU_GPEARB_SIZE, "onu|gpearb" },
	{ (void **)&eim, ONU_EIM_BASE, ONU_EIM_SIZE, "onu|eim" },
	{ (void **)&sxgmii, ONU_SXGMII_BASE, ONU_SXGMII_SIZE, "onu|sxgmii" },
	{ (void **)&iqm, ONU_IQM_BASE, ONU_IQM_SIZE, "onu|iqm" },
	{ (void **)&fsqm, ONU_FSQM_BASE, ONU_FSQM_SIZE, "onu|fsqm" },
	{ (void **)&ictrlc, ONU_ICTRLC0_BASE, 2*ONU_ICTRLC0_SIZE, "onu|ictrlc"},
	{ (void **)&octrlc, ONU_OCTRLC_BASE, ONU_OCTRLC_SIZE, "onu|octrlc"},
	{ (void **)&ictrll, ONU_ICTRLL0_BASE, 4*ONU_ICTRLL0_SIZE, "onu|ictrll"},
	{ (void **)&ictrlg, ONU_ICTRLG_BASE, ONU_ICTRLG_SIZE, "onu|ictrlg"},
	{ (void **)&octrll, ONU_OCTRLL0_BASE, 4*ONU_OCTRLL0_SIZE, "onu|octrll"},
	{ (void **)&octrlg, ONU_OCTRLG_BASE, ONU_OCTRLG_SIZE, "onu|octrlg"},
	{ (void **)&sys_eth, ONU_SYS_ETH_BASE, ONU_SYS_ETH_SIZE, "onu|sys_eth"},
	{ (void **)&sys_gpe, ONU_SYS_GPE_BASE, ONU_SYS_GPE_SIZE, "onu|sys_gpe"},
	{ (void **)&tmu, ONU_TMU_BASE, ONU_TMU_SIZE, "onu|tmu"},
	{ (void **)&sbs0ctrl,
			  ONU_SBS0CTRL_BASE, ONU_SBS0CTRL_SIZE, "onu|sbs0ctrl"},
	{ (void **)&merge, ONU_MERGE_BASE, ONU_MERGE_SIZE, "onu|merge"},
	{ (void **)&disp, ONU_DISP_BASE, ONU_DISP_SIZE, "onu|disp"},
	{ (void **)&link, ONU_LINK0_BASE, 3*ONU_LINK0_SIZE, "onu|link"},
	{ (void **)&pe, ONU_PE0_BASE, 6*ONU_PE0_SIZE, "onu|pe"},
	{ (void **)&tbm, ONU_TBM_BASE, ONU_TBM_SIZE, "onu|tbm"},
	{ (void **)&pctrl, ONU_PCTRL_BASE, ONU_PCTRL_SIZE, "onu|pctrl"},
	{ (void **)&tod, ONU_TOD_BASE, ONU_TOD_SIZE, "onu|tod"},
	{ (void **)&status, ONU_STATUS_BASE, ONU_STATUS_SIZE, "onu|status"},
	{ (void **)&sys1, ONU_SYS1_BASE, ONU_SYS1_SIZE, "onu|sys1"}
};

DEFINE_SPINLOCK(reg_lock);

int reg_dump_enable;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
extern struct sock *uevent_sock;
int broadcast_uevent(struct sk_buff *skb, __u32 pid, __u32 group,
		     gfp_t allocation)
{
	if (!uevent_sock) {
		kfree_skb(skb);
		return -ENODEV;
	}

	return netlink_broadcast(uevent_sock, skb, pid, group, allocation);;
}
#endif

#include <asm/io.h>
uint32_t onu_register_read(void *reg)
{
	uint32_t val = 0;
	val = __raw_readl(reg);
	if (reg_dump_enable)
		printk("r[0x%x]=0x%x\n", (uint32_t)reg, val);
	return val;
}

void onu_register_write(void *reg, uint32_t val)
{
	if (reg_dump_enable)
		printk("w[0x%x]=0x%x\n", (uint32_t)reg, val);
	__raw_writel(val,reg);
}

/**
   Open the device.

   At the first time:
   - allocating internal memory for each new device
   - initialize the device
   - set up the interrupt

   \param inode pointer to the inode
   \param filp pointer to the file descriptor

   \return
   - 0 - if no error,
   - otherwise error code
*/
STATIC int onu_open(struct inode *inode, struct file *filp)
{
	int res = -1, num;
	struct onu_device *p_dev = NULL;

	num = MINOR(inode->i_rdev);

	if (num >= MAX_ONU_INSTANCES) {
		ONU_DEBUG_ERR("max. device number exceeded.");
		res = -ENODEV;
		goto OPEN_ERROR;
	}
	p_dev = (struct onu_device *)IFXOS_MemAlloc(sizeof(struct onu_device));
	if (p_dev == NULL) {
		ONU_DEBUG_ERR("allocation failure.");
		res = -ENODEV;
		goto OPEN_ERROR;
	}

	if (gpe_chip_version == GPE_CHIP_UNKNOWN)
		gpe_chip_version = onu_chip_get();

	if (onu_device_open(&onu_control[num], p_dev) != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("device open failed.");
		goto OPEN_ERROR;
	}

	filp->private_data = p_dev;
	return 0;
OPEN_ERROR:
	onu_device_close(p_dev);
	return res;
}

/**
   Release the device.

   \param inode pointer to the inode
   \param filp pointer to the file descriptor

   \return
   - 0 - on success
   - otherwise error code
*/
STATIC int onu_release(struct inode *inode, struct file *filp)
{
	struct onu_device *p_dev = (struct onu_device *)filp->private_data;

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
   - length or a negative error code
*/
STATIC ssize_t onu_write(struct file *filp, const char *buf, size_t count,
			 loff_t *ppos)
{
	int total = 0;

	/*struct onu_device *p_dev = (struct onu_device *)filp->private_data;*/

	return total;
}

/**
   Reads data from the device.

   \param filp pointer to the file descriptor
   \param buf destination buffer
   \param count max size of data to read
   \param ppos unused

   \return
   - len - data length
*/
STATIC ssize_t onu_read(struct file *filp, char *buf, size_t count,
			loff_t *ppos)
{
	int len = 0;

	/*struct onu_device *p_dev = (struct onu_device *)filp->private_data;*/

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
STATIC unsigned int onu_poll(struct file *filp, poll_table *wait)
{
	struct onu_device *p_dev = (struct onu_device *)filp->private_data;

	poll_wait(filp, &p_dev->select_queue, wait);
	if (IFX_Var_Fifo_getCount(&p_dev->nfc_fifo.data))
		return POLLIN;

	return 0;
}

STATIC int onu_table_check(const char *name,
			   const struct onu_entry *tbl,
			   const uint32_t num)
{
	uint32_t i;
	int ret = 0;

	for(i = 0; i < num; i++) {
		if(_IOC_NR(tbl[i].id == 0))
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

/**
   Check whether given IOCTL (with handler passed via `f`) is allowed to be
   executed. All commands are allowed after GPE init, only a subset of
   commands - \ref PRE_GPE_INIT_COMMANDS - is allowed prior to GPE init.
*/
STATIC bool is_cmd_allowed(struct onu_device *p_dev, void *f)
{
	static const void *preinit_cmds[] = { PRE_GPE_INIT_COMMANDS };
	int i;

	if (((struct onu_control*)p_dev->ctrl)->gpe_init == false) {
		for (i = 0; i < ARRAY_SIZE(preinit_cmds); i++)
			if (preinit_cmds[i] == f)
				return true;

		return false;
	} else {
		return true;
	}
}

STATIC void onu_io_copy(struct onu_device *p_dev, const struct onu_entry *table,
			struct fio_exchange *exchange, uint8_t *buf)
{
#ifdef INCLUDE_CLI_DUMP_SUPPORT
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	int len;
#endif

	ONU_DEBUG_MSG("ioctl %s", table->name);

	if (_IOC_DIR(table->id) & _IOC_WRITE) {
		if(exchange->length < table->size_in)
			copy_from_user(buf, exchange->p_data, exchange->length);
		else
			copy_from_user(buf, exchange->p_data, table->size_in);
	}

#ifdef INCLUDE_CLI_DUMP_SUPPORT
	/* check if the ioctl trace was enabled and we can add a trace*/
	if (table->p_entry_dump && ctrl->ioctl_trace) {
		len = table->p_entry_dump(p_dev->io_trace_buf, (void*)buf);

		if (len > 0)
			event_add(ctrl, ONU_EVENT_IOCTL_TRACE,
				  (void*)p_dev->io_trace_buf,
				  (uint32_t)(len+1));
	}
#endif

	if (table->p_entry0) {
		if (is_cmd_allowed(p_dev, table->p_entry0))
			exchange->error = table->p_entry0(p_dev);
		else
			exchange->error = ONU_STATUS_GPE_NOT_INITIALIZED;
	} else if (table->p_entry1) {
		if (is_cmd_allowed(p_dev, table->p_entry1))
			exchange->error = table->p_entry1(p_dev, p_dev->io_buf);
		else
			exchange->error = ONU_STATUS_GPE_NOT_INITIALIZED;
	} else if (table->p_entry2) {
		if (is_cmd_allowed(p_dev, table->p_entry2))
			exchange->error = table->p_entry2(p_dev, p_dev->io_buf,
							  p_dev->io_buf);
		else
			exchange->error = ONU_STATUS_GPE_NOT_INITIALIZED;
	}

	if (_IOC_DIR(table->id) & _IOC_READ) {
		copy_to_user(exchange->p_data, buf, table->size_out);
		exchange->length = table->size_out;
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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))
STATIC int onu_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
		     unsigned long arg)
#else
STATIC long onu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
	int32_t ret = 0;
	struct onu_device *p_dev = (struct onu_device *)filp->private_data;
	uint8_t *buf = &p_dev->io_buf[0];
	struct fio_exchange temp_exchange;
	struct fio_exchange *exchange = &temp_exchange;
	uint32_t type = _IOC_TYPE(cmd);
	uint32_t nr = _IOC_NR(cmd);
	uint32_t size = _IOC_SIZE(cmd);
	unsigned long t = jiffies, diff;

	/* uint32_t dir = _IOC_DIR(cmd); */
	if (size >= ONU_IO_BUF_SIZE) {
		ONU_DEBUG_ERR("buffer size");
		return (-EINVAL);
	}

	if (p_dev->ploam_ctx == NULL) {
		ONU_DEBUG_ERR("ONU context invalid");
		return (-EINVAL);
	}

	ONU_DEBUG_MSG("ioctl (cmd 0x%x, type 0x%x, nr 0x%x)", cmd, type, nr);
	copy_from_user(exchange, (void *)arg, sizeof(struct fio_exchange));
	if ((type == ONU_MAGIC) && (nr < common_function_table_size)
	    && (nr == _IOC_NR(common_function_table[nr].id))) {
		onu_io_copy(p_dev, &common_function_table[nr], exchange, buf);
	} else if ((type == PLOAM_MAGIC) && (nr < ploam_function_table_size)
		   && (nr == _IOC_NR(ploam_function_table[nr].id))) {
		onu_io_copy(p_dev, &ploam_function_table[nr], exchange, buf);
	} else if ((type == GTC_MAGIC) && (nr < gtc_func_tbl_size)
		   && (nr == _IOC_NR(gtc_func_tbl[nr].id))) {
		onu_io_copy(p_dev, &gtc_func_tbl[nr], exchange, buf);
	} else if ((type == GPE_MAGIC) && (nr < gpe_function_table_size)
		   && (nr == _IOC_NR(gpe_function_table[nr].id))) {
		onu_io_copy(p_dev, &gpe_function_table[nr], exchange, buf);
	} else if ((type == GPE_TABLE_MAGIC) &&
		   (nr < gpe_table_function_table_size) &&
		   (nr == _IOC_NR(gpe_table_function_table[nr].id))) {
		onu_io_copy(p_dev, &gpe_table_function_table[nr],
			    exchange, buf);
	} else if ((type == LAN_MAGIC) && (nr < lan_function_table_size) &&
		   (nr == _IOC_NR(lan_function_table[nr].id))) {
		onu_io_copy(p_dev, &lan_function_table[nr], exchange, buf);
#ifdef INCLUDE_CLI_SUPPORT
	} else if ((type == _IOC_TYPE(FIO_ONU_CLI))
		   && (nr == _IOC_NR(FIO_ONU_CLI))) {
		if (exchange->length < (ONU_IO_BUF_SIZE - 1)) {
			copy_from_user(buf, exchange->p_data,
				       exchange->length + 1);
			ONU_DEBUG_MSG("ioctl (%s)", buf);
			size = onu_cli(p_dev, buf);
			ONU_DEBUG_MSG("ioctl (%s)", buf);
			if (size >= 0 && size < (ONU_IO_BUF_SIZE - 1)) {
				copy_to_user(exchange->p_data, buf, size + 1);
				exchange->length = size + 1;
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
			copy_to_user(exchange->p_data, p_data, len);
			exchange->length = len;
			if (p_dev->nfc_fifo.overflow)
				exchange->error = 1;
			else
				exchange->error = 0;

			onu_fifo_read(&p_dev->nfc_fifo, NULL, &len);
		} else {
			exchange->length = 0;
			exchange->error = -1;
		}
	} else if ((type == _IOC_TYPE(FIO_ONU_EVENT_ENABLE_SET))
		   && (nr == _IOC_NR(FIO_ONU_EVENT_ENABLE_SET))) {
		if (exchange->length == sizeof(struct onu_event_mask)) {
			copy_from_user(buf, exchange->p_data,
				       sizeof(struct onu_event_mask));
			onu_event_enable_set(p_dev,
					(struct onu_event_mask *) & buf[0]);
		} else {
			return (-EINVAL);
		}
	} else if ((type == _IOC_TYPE(FIO_ONU_EVENT_ENABLE_GET))
		   && (nr == _IOC_NR(FIO_ONU_EVENT_ENABLE_GET))) {
		struct onu_event_mask *p_data =
					(struct onu_event_mask *) & buf[0];
		onu_event_enable_get(p_dev, p_data);
		copy_to_user(exchange->p_data, p_data,
			     sizeof(struct onu_event_mask));
		exchange->length = sizeof(struct onu_event_mask);
		exchange->error = 0;
	} else {
		ONU_DEBUG_ERR("onu_status_ioctl_not_found_err "
			      "(cmd 0x%x, type 0x%x, nr 0x%x)\n",
			      cmd, type, nr);
		exchange->error = (int)ONU_STATUS_IOCTL_NOT_FOUND_ERR;
		ret = (-EIO);
	}
	copy_to_user((void *)arg, exchange, sizeof(struct fio_exchange));

	diff = (long)jiffies - (long)t;
	if (diff > onu_control[0].ioctrl_duration) {
		onu_control[0].ioctrl_duration = diff;
		onu_control[0].ioctrl_cmd = cmd;
	}

	return ret;
}

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
/**
   Read the version information from the driver.

   \param buf destination buffer

   \return
   - length of the string
*/
STATIC void onu_proc_version_get(struct seq_file *s)
{
	seq_printf(s, "%s" ONU_CRLF, &onu_whatversion[4]);
	seq_printf(s, "Compiled on %s, %s for Linux kernel %s" ONU_CRLF,
		   __DATE__, __TIME__, UTS_RELEASE);
}

/**
   Read the status information from the driver.

   \param buf  destination buffer

   \return
   - length of the string
*/
STATIC void onu_proc_status_get(struct seq_file *s)
{
	int i, k;
	struct onu_device *p_dev;
	uint32_t m;

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
#ifndef ONU_LIBRARY
		seq_printf(s, "OMCI downstream = %d" ONU_CRLF,
			   onu_control[i].omci_downstream);
		seq_printf(s, "OMCI dropped downstream = %d" ONU_CRLF,
			   onu_control[i].omci_downstream_dropped);
		seq_printf(s, "OMCI upstream = %d" ONU_CRLF,
			   onu_control[i].omci_upstream);
		seq_printf(s, "max ioctrl duration = %lu msec (cmd: 0x%lx)"
			      ONU_CRLF,
				onu_control[i].ioctrl_duration * 1000 / HZ,
				onu_control[i].ioctrl_cmd);
		for (m = 0; m < ARRAY_SIZE(onu_irq_tbl); m++) {
			seq_printf(s, "%s max duration = %lu msec" ONU_CRLF,
				onu_irq_tbl[m].irq_name,
				onu_irq_tbl[m].duration * 1000 / HZ);
		}
		seq_printf(s, "GC: " ONU_CRLF);
		for (m = 0; m < ONU_GPE_MAX_EGRESS_PORT;) {
			seq_printf(s, "%010d ", onu_control[i].gc_count[m]);
			if((++m % 8) == 0) seq_printf(s, ONU_CRLF);
		}
		seq_printf(s, ONU_CRLF);
#endif
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
	}
}
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
typedef void (*proc_single_callback_t)(struct seq_file *);
typedef int (*proc_callback_t)(struct seq_file *, int);
typedef int (*proc_init_callback_t)(void);

struct proc_file_entry {
	proc_callback_t callback;
	int pos;
};

struct proc_entry {
	char *name;
	proc_single_callback_t single_callback;
	proc_callback_t callback;
	proc_init_callback_t init_callback;
	struct file_operations ops;
};

STATIC void *onu_seq_start(struct seq_file *s, loff_t *pos)
{
	struct proc_file_entry *p = s->private;

	if (p->pos < 0)
		return NULL;

	return p;
}

STATIC void *onu_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct proc_file_entry *p = s->private;

	*pos = p->pos;

	if (p->pos >= 0)
		return p;
	else
		return NULL;
}

STATIC void onu_seq_stop(struct seq_file *s, void *v)
{
}

STATIC int onu_seq_show(struct seq_file *s, void *v)
{
	struct proc_file_entry *p = s->private;

	if (p->pos >= 0)
		p->pos = p->callback(s, p->pos);

	return 0;
}

STATIC int onu_proc_open(struct inode *inode, struct file *file);

static const struct seq_operations onu_seq_ops = {
	.start	= onu_seq_start,
	.next	= onu_seq_next,
	.stop	= onu_seq_stop,
	.show	= onu_seq_show
};

STATIC int onu_proc_open(struct inode *inode, struct file *file)
{
	struct seq_file *s;
	struct proc_file_entry *p;
	struct proc_entry *entry;
	int ret;

	ret = seq_open(file, &onu_seq_ops);
	if (ret)
		return ret;

	s = file->private_data;
	p = kmalloc(sizeof(*p), GFP_KERNEL);

	if (!p) {
		(void)seq_release(inode, file);
		return -ENOMEM;
	}

	entry = PDE(inode)->data;

	p->callback = entry->callback;
	if (entry->init_callback)
		p->pos = entry->init_callback();
	else
		p->pos = 0;

	s->private = p;

	return 0;
}

STATIC int onu_proc_release(struct inode *inode, struct file *file)
{
	struct seq_file *s;

	s = file->private_data;
	kfree(s->private);

	return seq_release(inode, file);
}

STATIC int onu_seq_single_show(struct seq_file *s, void *v)
{
	struct proc_entry *p = s->private;

	p->single_callback(s);
	return 0;
}

STATIC int onu_proc_single_open(struct inode *inode, struct file *file)
{
	return single_open(file, onu_seq_single_show, PDE(inode)->data);
}

static struct proc_entry proc_entries[] = {
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
	{"gtc",			gtc_dump, NULL, NULL},
	{"gpe_enqueue",		gpe_table_enqueue, NULL, NULL}
};

STATIC void onu_proc_entry_create(struct proc_dir_entry *parent_node,
				  struct proc_entry *proc_entry)
{
	memset(&proc_entry->ops, 0, sizeof(struct file_operations));
	proc_entry->ops.owner = THIS_MODULE;

	if (proc_entry->single_callback) {
		proc_entry->ops.open = onu_proc_single_open;
		proc_entry->ops.release = single_release;
	} else {
		proc_entry->ops.open = onu_proc_open;
		proc_entry->ops.release = onu_proc_release;
	}

	proc_entry->ops.read = seq_read;
	proc_entry->ops.llseek = seq_lseek;

	proc_create_data(proc_entry->name,
			 (S_IFREG | S_IRUGO),
			 parent_node, &proc_entry->ops, proc_entry);
}

/**
   Initialize and install the proc entry

   \return
   -1 or 0 on success

   \remarks
   Called by the kernel.
*/
STATIC int onu_proc_install(void)
{
	struct proc_dir_entry *driver_proc_node;

	driver_proc_node = proc_mkdir("driver/" ONU_NAME, NULL);
	if (driver_proc_node != NULL) {
		int i;
		for (i = 0; i < ARRAY_SIZE(proc_entries); i++)
			onu_proc_entry_create(driver_proc_node,
					      &proc_entries[i]);
	} else {
		ONU_DEBUG_ERR("cannot create proc entry");
		return -1;
	}
	return 0;
}
#endif

/* As long as the idx is different from different interrupt calls
   we may not protect this function from concurrent
   interrupts to minimize the time where interrupts are disabled. */
STATIC void isr_statistics_update(int idx, unsigned long start)
{
	unsigned long diff = (long)jiffies - (long)start;

	if (diff > onu_irq_tbl[idx].duration)
		onu_irq_tbl[idx].duration = diff;
}

STATIC irqreturn_t onu_isr_gtc_ds(int irq, void *ctrl)
{
	unsigned long t = jiffies;
	unsigned long flags;

	local_irq_save(flags);
	onu_gtc_ds_handle((struct onu_control *)ctrl, ONU_MAX_TIMER);
	local_irq_restore(flags);

	isr_statistics_update(0, t);

	return IRQ_HANDLED;
}

STATIC irqreturn_t onu_isr_gtc_us(int irq, void *ctrl)
{
	unsigned long t = jiffies;
	unsigned long flags;

	local_irq_save(flags);
	gtc_us_handle((struct onu_control *)ctrl);
	local_irq_restore(flags);

	isr_statistics_update(1, t);

	return IRQ_HANDLED;
}

STATIC irqreturn_t onu_isr_iqm(int irq, void *ctrl)
{
	unsigned long t = jiffies;
	uint32_t irnicr = iqm_r32(irnicr);
	unsigned long flags;

	if (irnicr & IQM_IRNCR_QF7) {
		local_irq_save(flags);
		onu_gpe_omci_handle((struct onu_control *)ctrl);
		local_irq_restore(flags);
	}
	isr_statistics_update(2, t);

	return IRQ_HANDLED;
}

STATIC irqreturn_t onu_isr_link(int irq, void *ctrl)
{
	unsigned long t = jiffies;
	unsigned long flags;
	local_irq_save(flags);
	onu_gpe_omci_handle((struct onu_control *)ctrl);
	local_irq_restore(flags);
	isr_statistics_update(6, t);

	return IRQ_HANDLED;
}

STATIC irqreturn_t onu_isr_tmu(int irq, void *ctrl)
{
	unsigned long t = jiffies;
	uint32_t irnicr = tmu_r32(irnicr);
	unsigned long flags;

	local_irq_save(flags);
	onu_gpe_egress_cpu_port_handle((struct onu_control *)ctrl, irnicr);
	local_irq_restore(flags);

	isr_statistics_update(3, t);

	return IRQ_HANDLED;
}

#if defined(INCLUDE_SCE_DEBUG)
STATIC irqreturn_t onu_isr_config_break(int irq, void *ctrl)
{
	unsigned long t = jiffies;
	uint32_t vm_group;
	uint32_t pc;
	uint32_t tid;
	struct sce_break_point sce_break_point;
	struct onu_control *ctrl_ = (struct onu_control *)ctrl;

	sce_fw_pe_break_check(&vm_group);

	for (tid = 0; tid < ctrl_->num_pe*4; ++tid) {
		if (vm_group & (0x1 << tid)) {
			sce_fw_pe_pc_get(tid, &pc);
			sce_break_point.tid = tid;
			sce_break_point.addr = pc;
			event_add(ctrl_, ONU_EVENT_SCE_BP_REACHED,
				  &sce_break_point,
				  sizeof(sce_break_point));
		}
	}

	isr_statistics_update(4, t);

	return IRQ_HANDLED;
}
#else
STATIC irqreturn_t onu_isr_config_break(int irq, void *ctrl)
{
	(void)irq;
	(void)ctrl;

	return IRQ_HANDLED;
}
#endif

STATIC irqreturn_t onu_isr_tod(int irq, void *ctrl)
{
	unsigned long t = jiffies;

	tod_isr_handle();

	isr_statistics_update(5, t);

	tod_w32(tod_r32(irncr), irncr);
	return IRQ_HANDLED;
}

/** Timer Handler

   \param timer_no Indicates the timer index
*/
STATIC void onu_timer_handler(unsigned long timer_no)
{
	uint32_t num = timer_no & 0xFFFF;
	struct onu_control *ctrl = &onu_control[timer_no >> 16];
	unsigned long flags;

	local_irq_save(flags);
	onu_timer_exec(ctrl, num);
	local_irq_restore(flags);
}

STATIC void onu_irq_mask_set(uint32_t mask)
{
	int res = -1;
	bool force_free = mask == 0 ? true : false;
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(onu_irq_tbl); i++) {
		if ((1 << i) & mask) {
			if (onu_irq_tbl[i].installed == false) {
				ONU_DEBUG_MSG("request irq: %d %s",
						onu_irq_tbl[i].irq_num,
						onu_irq_tbl[i].irq_name);
				res = request_irq(onu_irq_tbl[i].irq_num,
						     onu_irq_tbl[i].irq_hndl,
						     IRQ_LEVEL,
						     onu_irq_tbl[i].irq_name,
						     &onu_control[0]);
				if (res) {
					printk(KERN_ERR DEBUG_PREFIX
						"Failed to request %s IRQ\n",
						onu_irq_tbl[i].irq_name);
				} else {
					onu_irq_tbl[i].installed = true;
				}
			} else {
				if (onu_irq_tbl[i].enabled == false) {
					ONU_DEBUG_MSG("enable irq: %d %s",
						onu_irq_tbl[i].irq_num,
						onu_irq_tbl[i].irq_name);
					enable_irq(onu_irq_tbl[i].irq_num);
				}
			}
			onu_irq_tbl[i].enabled = true;
		} else {
			if (force_free) {
				if (onu_irq_tbl[i].installed) {
					ONU_DEBUG_MSG("free irq: %d %s",
						onu_irq_tbl[i].irq_num,
						onu_irq_tbl[i].irq_name);
					free_irq(onu_irq_tbl[i].irq_num,
							&onu_control[0]);
					onu_irq_tbl[i].installed = false;
				}
			} else {
				if (onu_irq_tbl[i].enabled) {
					ONU_DEBUG_MSG("disable irq: %d %s",
						onu_irq_tbl[i].irq_num,
						onu_irq_tbl[i].irq_name);
					disable_irq(onu_irq_tbl[i].irq_num);
				}
			}
			onu_irq_tbl[i].enabled = false;
		}
	}
}

void onu_irq_enable(struct onu_control *ctrl, uint32_t mask)
{
	if (!ctrl)
		return;

	down(&ctrl->irq_mask_sema);
	ctrl->irq_enabled_mask = mask;
	onu_irq_mask_set(ctrl->irq_enabled_mask);
	up(&ctrl->irq_mask_sema);
}

void onu_irq_add(struct onu_control *ctrl, uint32_t mask)
{
	if (!ctrl)
		return;

	down(&ctrl->irq_mask_sema);
	ctrl->irq_enabled_mask = (ctrl->irq_enabled_mask) | mask;
	onu_irq_mask_set(ctrl->irq_enabled_mask);
	up(&ctrl->irq_mask_sema);
}

void onu_irq_remove(struct onu_control *ctrl, uint32_t mask)
{
	if (!ctrl)
		return;

	down(&ctrl->irq_mask_sema);
	ctrl->irq_enabled_mask = (ctrl->irq_enabled_mask) & (~mask);
	onu_irq_mask_set(ctrl->irq_enabled_mask);
	up(&ctrl->irq_mask_sema);
}

void onu_udelay(uint32_t u_sec)
{
	udelay(u_sec);
}

/**
   Start ONU timer

   \param timer_no Timer Index
   \param timeout  Timeout in mseconds.
*/
void onu_timer_start(const uint32_t timer_no, uint32_t timeout)
{
	/*printk("start timer %d" ONU_CRLF, timer_no); */
	if (timer_pending(&onu_timer[timer_no])) {
		printk("timer %d is pending" ONU_CRLF, timer_no);
	} else {
		onu_timer[timer_no].expires = jiffies + timeout * HZ / 1000;
		add_timer(&onu_timer[timer_no]);
	}
}

/**
   Stop Timer

   \param timer_no Timer Index
*/
void onu_timer_stop(const uint32_t timer_no)
{
	/*printk("stop timer %d" ONU_CRLF, timer_no); */
	del_timer(&onu_timer[timer_no]);
}

/*
 * This helper function is required for accessing the count register.
 */
static uint32_t get_cp0_count(void)
{
	uint32_t count = 0;
	__asm __volatile__ (
		"mfc0\t%0, $9\n\t"
		: "=r" (count) :
	);
	return count;
}

/**
   Retrieve pseudo random number within a specified range

   \param range_min   lowest value
   \param range_max   highest value
*/
uint32_t onu_random_get(const uint32_t range_min,
			const uint32_t range_max)
{
	return (get_cp0_count() % range_max);
}

int32_t onu_spin_lock_init(onu_lock_t *id, const char *p_name)
{
	spin_lock_init(id);
	return 0;
}

int32_t onu_spin_lock_delete(onu_lock_t *id)
{
	return 0;
}

int32_t onu_spin_lock_get(onu_lock_t *id, ulong_t *flags)
{
	spin_lock_irqsave(id, *flags);
	return 0;
}

int32_t onu_spin_lock_release(onu_lock_t *id, ulong_t flags)
{
	spin_unlock_irqrestore(id, flags);
	return 0;
}

STATIC inline void onu_message_add(struct sk_buff *skb, char *msg)
{
	char *scratch;
	scratch = skb_put(skb, strlen(msg) + 1);
	sprintf(scratch, msg);
}

void onu_hot_plug_state(const uint32_t state, const uint32_t old_state)
{
	struct sk_buff *skb;
	char buf[128];
	u64 seq;
	size_t len;
	char *scratch;

	len = strlen("0") + 2;
	skb = alloc_skb(len + 2048, GFP_KERNEL);
	if (!skb)
		return;

	scratch = skb_put(skb, len);
	sprintf(scratch, "%d@", state);
	onu_message_add(skb, "HOME=/");
	onu_message_add(skb, "PATH=/sbin:/bin:/usr/sbin:/usr/bin");
	onu_message_add(skb, "SUBSYSTEM=gpon");
	onu_message_add(skb, "DEVICENAME=onu0");
	snprintf(buf, 128, "STATE=%d", state);
	onu_message_add(skb, buf);
	snprintf(buf, 128, "OLD_STATE=%d", old_state);
	onu_message_add(skb, buf);
	seq = uevent_next_seqnum();
	snprintf(buf, 128, "SEQNUM=%llu", (unsigned long long)seq);
	onu_message_add(skb, buf);

	NETLINK_CB(skb).dst_group = 1;
	broadcast_uevent(skb, 0, 1, GFP_KERNEL);
}

uint8_t *firmware_data;
uint32_t *firmware_len;

int onu_pe_fw_load(const char *name, struct onu_fw *pe_fw)
{
#ifdef PE_FW_SIMULATION
	(void) name;
	(void) pe_fw;

	return 0;
#else
	int ret = 0;
	const struct firmware *fw;
	static char dirname[ONU_PE_FIRMWARE_NAME_MAX + 4];

	if (strlen(name) > ONU_PE_FIRMWARE_NAME_MAX - 1) {
		printk(KERN_ERR DEBUG_PREFIX
		       " Error loading firmware (fw name is too long)\n");
		return -5;
	}

	if (dev[0] == NULL) {
		printk(KERN_ERR DEBUG_PREFIX
		       " Error loading firmware (device invalid)\n");
		return -2;
	}
	if (is_falcon_chip_a1x())
		sprintf (dirname, "a1x/%s", name);
	else
		sprintf (dirname, "a2x/%s", name);

	if (request_firmware(&fw, dirname, dev[0])) {
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
		printk(KERN_ERR DEBUG_PREFIX
		       " Error loading firmware (invalid firmware binary)\n");
		return -4;
	}

	pe_fw->len = fw->size;
	pe_fw->bin = (uint8_t *)vmalloc(pe_fw->len);

	if (pe_fw->bin) {
		memcpy(pe_fw->bin, fw->data, pe_fw->len);
		strncpy(pe_fw->fw_name, name, ONU_PE_FIRMWARE_NAME_MAX);
	} else {
		printk(KERN_ERR DEBUG_PREFIX
		       " Error loading firmware (allocate %d bytes)\n",
		       pe_fw->len);
		memset(pe_fw, 0, sizeof(*pe_fw));
		ret = -1;
	}

	release_firmware(fw);

	return ret;
#endif
}

int onu_pe_fw_info_load(const struct onu_fw *pe_fw, struct pe_fw_info *info)
{
	uint32_t opt_hdr_len;
	uint8_t *opt_hdr;
	unsigned long flags = 0;

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

	if (opt_hdr_len % sizeof(uint32_t))
		return -1;

	opt_hdr = vmalloc(opt_hdr_len);

	if (!opt_hdr) {
		printk(KERN_ERR DEBUG_PREFIX
			" Error alloc opt header (allocate %d bytes)\n",
				opt_hdr_len);
		return -2;
	} else {
		onu_spin_lock_get(&mailbox_lock, &flags);
		info->opt_hdr_len = opt_hdr_len;
		info->opt_hdr = opt_hdr;
		memcpy(info->opt_hdr, pe_fw->bin + PE_FW_HEADER_SIZE,
		       info->opt_hdr_len);
		onu_spin_lock_release(&mailbox_lock, flags);
	}

	return 0;
}

void onu_pe_fw_info_release(struct pe_fw_info *info)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&mailbox_lock, &flags);

	if (info->opt_hdr && info->opt_hdr_len)
		vfree(info->opt_hdr);
	memset(info, 0, sizeof(*info));

	onu_spin_lock_release(&mailbox_lock, flags);
}

void onu_fw_release(struct onu_fw *pe_fw)
{
	if (pe_fw->bin)
		vfree(pe_fw->bin);
	memset(pe_fw, 0, sizeof(*pe_fw));
}

int onu_microcode_load(struct onu_control *ctrl, const char *name)
{
	const struct firmware *fw;

#ifdef PE_FW_SIMULATION
	return 0;
#else
	static char dirname[20];

	if (dev[0] == NULL) {
		printk(KERN_ERR DEBUG_PREFIX
		       " Error loading microcode (device invalid)\n");
		return -2;
	}
	if (is_falcon_chip_a1x())
		sprintf (dirname, "a1x/%s", name);
	else
		sprintf (dirname, "a2x/%s", name);
	printk(KERN_ERR DEBUG_PREFIX
		"loading microcode %s\n", dirname);
	if (request_firmware(&fw, dirname, dev[0])) {
		printk(KERN_ERR DEBUG_PREFIX
		       " Error loading microcode %s (microcode not available)\n",
		       dirname);
		return -3;
	}
	if (fw->size < 32 || fw->size >= ONU_MAX_COP_SIZE) {
		printk(KERN_ERR DEBUG_PREFIX
		       " Error loading microcode (invalid microcode binary)\n");
		return -4;
	}

	memcpy(ctrl->cop_microcode_bin, fw->data, fw->size);
	ctrl->cop_microcode_len = fw->size;

	release_firmware(fw);

	return 0;
#endif
}

static unsigned int gphy_firmware_version_get(const uint8_t *data,
					      size_t data_len,
					      uint8_t *version,
					      size_t version_len)
{
	size_t i, version_pos;
	int begin_found = 0;

	for (i = 0; i + 2 < data_len; i++) {
		if (data[i] == 0x7E &&
		    data[i + 1] == 0x81 &&
		    data[i + 2] == 0x7E) {
			begin_found = 1;
			version_pos = 0;
			i += 2;
		} else if (data[i] == 0x81 &&
		    data[i + 1] == 0x7E &&
		    data[i + 2] == 0x81) {
			if (begin_found)
				return version_pos;
		} else {
			if (begin_found && version_pos < version_len)
				version[version_pos++] = data[i];
		}
	}

	return 0;
}

static int gphy_firmware_download(struct onu_control *ctrl,
				  const char *name,
				  int check_version)
{
	const char *error_cause = NULL;
	const struct firmware *fw;
	uint32_t load_offset = (16 << 10); /* gphy needs 16k alignment */
	uint8_t version[ONU_GPHY_FIRMWARE_VERSION_MAX];

	if (ctrl->lan_gphy_fw_ram_addr) {
		error_cause = "already loaded";
		goto error_out;
	}

	if (dev[0] == NULL) {
		error_cause = "device invalid";
		goto error_out;
	}

	if (request_firmware(&fw, name, dev[0])) {
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

	if (check_version) {
		if (gphy_firmware_version_get(fw->data, fw->size,
					      version, sizeof(version))) {
			if (is_falcon_chip_a1x()) {
				if (memcmp(version, "PHY_1V4", 7) != 0) {
					error_cause = "wrong firmware device";
					goto error_release;
				}
			} else {
				if (memcmp(version, "PHY_1V5", 7) != 0) {
					error_cause = "wrong firmware device";
					goto error_release;
				}
			}
			memcpy(ctrl->lan_gphy_fw_version, version, sizeof(version));
		}
	}

	/* copy firmware data*/
	memcpy((void*)(ONU_SBS0RAM_BASE | load_offset), fw->data, fw->size);
	ctrl->lan_gphy_fw_ram_addr = (ONU_SBS0RAM_BASE | load_offset);

	printk(KERN_INFO DEBUG_PREFIX " GPHY Firmware loaded into RAM (%s)\n", name);

error_release:
	release_firmware(fw);

error_out:
	if (error_cause) {
		printk(KERN_ERR DEBUG_PREFIX
		       " Error loading GPHY firmware '%s' (%s)\n",
		       name, error_cause);
		return -1;
	}

	return 0;
}

int onu_gphy_firmware_download(struct onu_control *ctrl, const char *name)
{
	int ret;
	static char dirname[ONU_GPHY_FIRMWARE_NAME_MAX + 4];

	ret = gphy_firmware_download(ctrl, name, 1);
	if (ret) {
		if (is_falcon_chip_a1x())
			snprintf(dirname, sizeof(dirname), "a1x/%s", name);
		else
			snprintf(dirname, sizeof(dirname), "a2x/%s", name);

		ret = gphy_firmware_download(ctrl, dirname, 0);
	}

	return ret;
}

void * onu_probe(const unsigned long addr, const unsigned long size,
		 const char *name)
{
	struct resource *ioarea;
	void *ptr;
	unsigned long phys_addr = (addr & ~KSEG1);

	ioarea = request_mem_region(phys_addr, size, name);
	if (!ioarea) {
		printk(KERN_ERR DEBUG_PREFIX
			" Requesting mem reqion failed (%s at 0x%08lX), "
			"try anyway\n", name, phys_addr);

		/* WORKAROUND: try to remap even if request has failed! */
		ptr = ioremap_nocache(phys_addr, size);
		if (!ptr) {
			printk(KERN_ERR DEBUG_PREFIX
				" Error in ioremap (%s at 0x%08lX)\n",
				name, phys_addr);
			return NULL;
		} else
			return ptr;
	}
	ptr = ioremap_nocache(ioarea->start, resource_size(ioarea));
	if (!ptr)
		goto err_release_mem_region;
	return ptr;

err_release_mem_region:
	printk(KERN_ERR DEBUG_PREFIX " Error probing mem reqion (%s)\n", name);
	release_mem_region(phys_addr, size);
	return NULL;
}

u32 onu_gpon_link_status_get(void)
{
	return onu_control[0].ploam_ctx.curr_state == PLOAM_STATE_O5 ? 1 : 0;
}

u32 onu_gpon_packet_count_get(const u8 rx)
{
	if(rx) {
		struct gpe_cnt_ictrlg_val rx;
		ictrlg_counter_get(&rx);
		return rx.rx_gem_frames_total;
	} else {
		struct gpe_cnt_octrlg_val tx;
		octrlg_counter_get(&tx);
		return tx.tx_gem_frames_total;
	}
	return 0;
}

u32 onu_mac_link_status_get(const u8 idx)
{
	return onu_control[0].lan_link_status[idx].up;
}

u32 onu_mac_packet_count_get(const u8 idx, const u8 rx)
{
	if (onu_control[0].lan_link_status[idx].up)
		return rx ? ictrll_pcnt_get(idx) : octrll_pcnt_get(idx);
	else
		return 0;
}

void onu_time_to_tm(uint32_t totalsecs, int offset, struct onu_tm *result)
{
	struct tm tm_time;

	time_to_tm((time_t)totalsecs, offset, &tm_time);

	result->tm_sec 	= (uint8_t)tm_time.tm_sec;
	result->tm_min 	= (uint8_t)tm_time.tm_min;
	result->tm_hour = (uint8_t)tm_time.tm_hour;
	result->tm_mday = (uint8_t)tm_time.tm_mday;
	result->tm_mon 	= (uint8_t)tm_time.tm_mon;
	result->tm_year = (uint16_t)tm_time.tm_year;
	result->tm_wday = (uint8_t)tm_time.tm_wday;
	result->tm_yday = (uint16_t)tm_time.tm_yday;
}

unsigned long onu_elapsed_time_sec_get(unsigned long ref)
{
	unsigned long time_sec = jiffies / HZ;

	return time_sec >= ref ? time_sec - ref :
				 (ULONG_MAX/HZ - ref) + time_sec;
}

#ifdef INCLUDE_CLI_SUPPORT
char *onu_strsep(char **stringp, const char *delim)
{
	return strsep(stringp, delim);
}
#endif

static int onu_die_notify(struct notifier_block *self, unsigned long cmd,
			  void *ptr)
{
	struct die_args *args = (struct die_args *)ptr;
	struct pt_regs *regs = args->regs;

	if (regs->cp0_status & ST0_NMI)
		printk(KERN_ERR DEBUG_PREFIX " NMI!\n");

	/* return NOTIFY_STOP to don't call further notifiers */
	return NOTIFY_DONE;
}

static struct notifier_block onu_die_notifier = {
	.notifier_call = onu_die_notify,
};

/**
   Initialize the driver module.

   \return
   - 0 on success
   - Error code

   \remarks
   Called by the kernel.
*/
int __init onu_init(void)
{
	int res = 0, i, j;

	printk("%s" ONU_CRLF, &onu_whatversion[4]);

	onu_debug_lvl = ONU_DBG_ERR;
	reg_dump_enable = 0;

	res = onu_table_check(	"common", &common_function_table[0],
				common_function_table_size);
	res = onu_table_check(	"gtc", &gtc_func_tbl[0],
				gtc_func_tbl_size);
	res = onu_table_check(	"ploam", &ploam_function_table[0],
				ploam_function_table_size);
	res = onu_table_check(	"gpe", &gpe_function_table[0],
				gpe_function_table_size);
	res = onu_table_check(	"gpe_table", &gpe_table_function_table[0],
				gpe_table_function_table_size);
	res = onu_table_check(	"lan", &lan_function_table[0],
				lan_function_table_size);

	major_number = register_chrdev(0, ONU_NAME, &onu_fops);
	if (!major_number) {
		ONU_DEBUG_ERR("can't get major number");
		res = -ENODEV;
		goto out;
	}

	gpon_class = class_create(THIS_MODULE, "gpondev");
	if (IS_ERR(gpon_class)) {
		res = PTR_ERR(gpon_class);
		ONU_DEBUG_ERR("can't create class");
		goto out_unreg_chrdev;
	}

	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		dev[i] = device_create(gpon_class, NULL, MKDEV(major_number, i),
				       NULL, "onu%d", i);
		if (IS_ERR(dev[i]))
			goto out_unreg_class;
	}

	memset(onu_control, 0x00, sizeof(onu_control));

	for (i = 0; i < ARRAY_SIZE(onu_reg_tbl); i++) {
		*onu_reg_tbl[i].reg = onu_probe(onu_reg_tbl[i].base,
			onu_reg_tbl[i].size, onu_reg_tbl[i].name);
		if (*onu_reg_tbl[i].reg == NULL) {
			/* FIXME: free resources! */
			res = -ENOMEM;
			goto out_unreg_class;
		}
	}

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
	onu_proc_install();
#endif

	for (i = 0; i < ONU_MAX_TIMER; i++) {
		init_timer(&onu_timer[i]);
		onu_timer[i].data = i;
		onu_timer[i].function = onu_timer_handler;
	}

	if (onu_spin_lock_init( &mailbox_lock, "mailbox") != 0)
		ONU_DEBUG_ERR("can't init mailb_lock spinlock");

	if (onu_spin_lock_init( &cop_lock, "cop") != 0)
		ONU_DEBUG_ERR("can't init cop spinlock");

	if (onu_spin_lock_init( &ictrlc_lock, "ictrlc") != 0)
		ONU_DEBUG_ERR("can't init ictrlc spinlock");

	if (onu_spin_lock_init( &octrlc_lock, "octrlc") != 0)
		ONU_DEBUG_ERR("can't init octrlc spinlock");

	if (onu_spin_lock_init( &link_lock, "link") != 0)
		ONU_DEBUG_ERR("can't init link spinlock");

	if (onu_spin_lock_init( &sce_lock, "sce") != 0)
		ONU_DEBUG_ERR("can't init sce spinlock");

	if (onu_spin_lock_init( &meter_lock, "meter") != 0)
		ONU_DEBUG_ERR("can't init meter spinlock");

	if (onu_spin_lock_init( &tmu_lock, "tmu") != 0)
		ONU_DEBUG_ERR("can't init tmu spinlock");

	if (onu_spin_lock_init( &enqueue_lock, "enqueue") != 0)
		ONU_DEBUG_ERR("can't init enqueue spinlock");

	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		if (onu_spin_lock_init(&onu_control[i].cnt_lock, "cnt") != 0) {
			ONU_DEBUG_ERR("can't init cnt_lock spinlock %d", i);
			continue;
		}
		if (onu_spin_lock_init(	&onu_control[i].mdio_lock,
					"mdio") != 0) {
			ONU_DEBUG_ERR("can't init mdio_lock spinlock %d", i);
			continue;
		}

		for (j = 0; j < ONU_GPE_MAX_ETH_UNI; j++) {
			if (onu_spin_lock_init(	&onu_control[i].lan_lock[j],
						"lan") != 0) {
				ONU_DEBUG_ERR(
					"can't init lan_lock spinlock %d-%d",
									i, j);
				continue;
			}
		}

		if (IFXOS_MutexInit(&onu_control[i].list_lock) != IFX_SUCCESS) {
			ONU_DEBUG_ERR("can't init list_lock mutex %d", i);
			continue;
		}

		sema_init(&onu_control[i].irq_mask_sema, 1);
	}

#ifdef INCLUDE_CLI_SUPPORT
	onu_cli_init();
#endif

	onu_hot_plug_state(0, 0);

	register_die_notifier(&onu_die_notifier);

	return 0;

out_unreg_class:
	class_destroy(gpon_class);
out_unreg_chrdev:
	unregister_chrdev(major_number, ONU_NAME);
out:
	return res;
}

/**
   Clean up the module if unloaded.

   \remarks
   Called by the kernel.
*/
void __exit onu_exit(void)
{
	int i, j;
	char buf[64];
	struct onu_device *p_dev, *pDelete;

	unregister_die_notifier(&onu_die_notifier);

	onu_irq_mask_set(0);

	for (i = 0; i < MAX_ONU_INSTANCES; i++)
		device_destroy(gpon_class, MKDEV(major_number, i));

	unregister_chrdev(major_number, ONU_NAME);
	class_destroy(gpon_class);

	for (i = 0; i < ONU_MAX_TIMER; i++)
		del_timer(&onu_timer[i]);

#ifdef INCLUDE_CLI_SUPPORT
	onu_cli_shutdown();
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
	for (i = 0; i < ARRAY_SIZE(proc_entries); i++) {
		sprintf(buf, "driver/" ONU_NAME "/%s", proc_entries[i].name);
		remove_proc_entry(buf, 0);
	}
	remove_proc_entry("driver/" ONU_NAME, 0);
#endif

	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		onu_control[i].run_worker = false;
		for (j = 0; j < onu_control[i].num_pe; j++)
			onu_pe_fw_info_release(&(onu_control[i].pe_fw[i]));
	}
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
	for (i = 0; i < MAX_ONU_INSTANCES; i++) {
		onu_spin_lock_delete(&onu_control[i].cnt_lock);
		onu_spin_lock_delete(&onu_control[i].mdio_lock);
	}

	ONU_DEBUG_MSG("cleanup successful");
}

void event_queue_init(struct onu_control *ctrl)
{
	init_completion(&ctrl->worker_completion);
}

int event_queue_wait(struct onu_control *ctrl)
{
	int ret;

	if (IFX_Var_Fifo_isEmpty(&ctrl->nfc_fifo.data)) {
		ret = wait_for_completion_interruptible_timeout(
			&ctrl->worker_completion, HZ);

		if (ret < 0)
			return ret;
	}

	return 0;
}

void event_queue_wakeup(struct onu_control *ctrl)
{
	complete(&ctrl->worker_completion);
}

EXPORT_SYMBOL(net_pdu_info_get);
EXPORT_SYMBOL(net_pdu_read);
EXPORT_SYMBOL(net_pdu_write);
EXPORT_SYMBOL(net_cb_list_register);
EXPORT_SYMBOL(net_dev_register);
EXPORT_SYMBOL(net_rx_enable);
EXPORT_SYMBOL(net_uni_get);
EXPORT_SYMBOL(onu_gpon_link_status_get);
EXPORT_SYMBOL(onu_gpon_packet_count_get);
EXPORT_SYMBOL(onu_mac_link_status_get);
EXPORT_SYMBOL(onu_mac_packet_count_get);
EXPORT_SYMBOL(net_lan_mac_set);
EXPORT_SYMBOL(net_lan_max_port_get);

#ifdef ONU_DBG_EXPORTS
EXPORT_SYMBOL(cop_message);
EXPORT_SYMBOL(gpe_table_entry_write);
EXPORT_SYMBOL(gpe_table_entry_read);
EXPORT_SYMBOL(gpe_table_entry_set);
EXPORT_SYMBOL(gpe_table_entry_get);
EXPORT_SYMBOL(gpe_table_entry_delete);
EXPORT_SYMBOL(gpe_table_entry_add);
EXPORT_SYMBOL(gpe_tagging_filter_set);
EXPORT_SYMBOL(gpe_tagging_filter_get);
EXPORT_SYMBOL(gpe_tagging_filter_do);
#ifdef INCLUDE_COP_DEBUG
EXPORT_SYMBOL(cop_debug_set);
EXPORT_SYMBOL(cop_debug_get);
#endif
EXPORT_SYMBOL(gpe_fid_add);
EXPORT_SYMBOL(gpe_short_fwd_relearn);
EXPORT_SYMBOL(gpe_short_fwd_delete);
EXPORT_SYMBOL(gpe_table_reinit);
EXPORT_SYMBOL(gpe_ext_vlan_set);
EXPORT_SYMBOL(gpe_ext_vlan_get);
EXPORT_SYMBOL(gpe_ext_vlan_do);
EXPORT_SYMBOL(gpe_ext_vlan_custom_set);
EXPORT_SYMBOL(gpe_ext_vlan_custom_get);
EXPORT_SYMBOL(gpe_long_fwd_add);
EXPORT_SYMBOL(gpe_iqueue_write_debug);
EXPORT_SYMBOL(gpe_ethertype_filter_cfg_set);
EXPORT_SYMBOL(gpe_ethertype_filter_cfg_get);
EXPORT_SYMBOL(tmu_low_power_idle_cfg_set);
EXPORT_SYMBOL(tmu_low_power_idle_cfg_get);
EXPORT_SYMBOL(tmu_low_power_idle_status_get);
#endif

MODULE_AUTHOR("ralph.hempel@lantiq.com");
MODULE_DESCRIPTION("GPON ONU Driver - www.lantiq.com");
MODULE_SUPPORTED_DEVICE("FALC ON");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(onu_ver_str);

module_init(onu_init);
module_exit(onu_exit);

#endif				/* LINUX */

/*! @} */

/*! @} */
