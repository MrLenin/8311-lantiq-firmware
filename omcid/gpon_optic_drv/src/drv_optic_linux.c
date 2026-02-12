/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_LINUX_INTERNAL Linux Specific Implementation - Internal
   @{
*/
#ifdef HAVE_CONFIG_H
#include "drv_optic_config.h"
#endif

#ifdef EVENT_LOGGER_DEBUG
#define IFXOS_LIBRARY_USED
#include <el_log_macros.h>
#endif /* EVENT_LOGGER_DEBUG */

#if defined(LINUX) && !defined(OPTIC_SIMULATION)

#ifdef __KERNEL__
#  include <linux/kernel.h>
#endif

#ifdef MODULE
#  include <linux/module.h>
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
#  include <linux/proc_fs.h>
#  include <linux/seq_file.h>
#endif

#include <linux/version.h>
/** \todo doxygen problem, LINUX_VERSION_CODE not found */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
#   include <linux/utsrelease.h>
#else
#   include <generated/utsrelease.h>
#endif
#include <linux/interrupt.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/delay.h>

#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/kobject.h>
#include <asm/uaccess.h>
#include <linux/leds.h>
#include <linux/sched.h>
#include <linux/timer.h>

/* for reboot notification */
#include <linux/notifier.h>
#include <linux/reboot.h>

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
#elif CONFIG_LANTIQ
# include <lantiq.h>
# include <falcon_irq.h>
#else
#  include <asm/ifx/ifx_regs.h>
#  include <asm/ifx/ifx_gpio.h>
#endif

#include "ifxos_device_io.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_calc.h"
#include "drv_optic_bosa.h"
#include "drv_optic_cli_core.h"
#include "drv_optic_timer.h"
#include "drv_optic_register.h"
#include "drv_optic_event_interface.h"
#include "drv_optic_dcdc_apd.h"

#include "drv_optic_reg_base.h"
#include "drv_optic_ll_fcsi.h"
#include "drv_optic_ll_int.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_ll_dcdc_apd.h"
#include "drv_optic_ll_dcdc_core.h"


typedef irqreturn_t (*irq_hndl_fct_t)(int irq, void *ctrl);

struct optic_irq_table
{
	/** IRQ line number*/
	uint32_t irq_num;
	/** IRQ name. Will be displayed under /proc/..*/
	const char *irq_name;
	/** IRQ flags */
	uint32_t irq_flag;
	/** ISR*/
	irq_hndl_fct_t irq_hndl;
};

STATIC struct timer_list optic_timer[OPTIC_TIMER_GLOBAL_MAX];

/** common timer handler */
STATIC void optic_timer_handler ( ulong_t timer_no );

STATIC irqreturn_t optic_isr_pma_200 ( int irq, void *ctrl );
STATIC irqreturn_t optic_isr_pma_rx ( int irq, void *ctrl );
STATIC irqreturn_t optic_isr_pma_tx ( int irq, void *ctrl );
STATIC irqreturn_t optic_isr_gpio_sd ( int irq, void *ctrl );

struct optic_irq_table optic_irq_tbl_omu[] =
{
	{0, "gpio_sd", IRQ_TYPE_EDGE_BOTH , optic_isr_gpio_sd}
};

struct optic_irq_table optic_irq_tbl_bosa[] =
{
	{FALCON_IRQ_PMA_200M, "pma_200", IRQ_LEVEL, optic_isr_pma_200},
	{FALCON_IRQ_PMA_RX, "pma_rx", IRQ_LEVEL, optic_isr_pma_rx},
	{FALCON_IRQ_PMA_TX, "pma_tx", IRQ_LEVEL, optic_isr_pma_tx},
};

struct optic_reg_pma *pma;
struct optic_reg_dcdc *dcdc_core;
struct optic_reg_dcdc *dcdc_ddr;
struct optic_reg_dcdc *dcdc_apd;
struct optic_reg_fcsic *fcsic;
struct optic_reg_fcsi *fcsi;
struct optic_reg_gtc_pma *gtc_pma;
struct optic_reg_pma_int200 *pma_int200;
struct optic_reg_pma_intrx *pma_intrx;
struct optic_reg_pma_inttx *pma_inttx;
struct optic_reg_octrlg *octrlg;
struct optic_reg_status *status;
struct optic_reg_sys1 *sys1;
struct optic_reg_sys_gpon *sys_gpon;
struct optic_reg_gtc *gtc;

static struct class *optic_class;

STATIC int optic_open ( struct inode *inode,
                        struct file *filp);
STATIC int optic_release ( struct inode *inode,
                           struct file *filp );
STATIC ssize_t optic_write ( struct file *filp,
                             const char *buf,
                             size_t count,
                             loff_t *p_pos );
STATIC ssize_t optic_read ( struct file *filp,
                            char *buf,
                            size_t length,
                            loff_t *ppos );
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))
STATIC int optic_ioctl ( struct inode *inode,
                         struct file *filp,
                         unsigned int cmd,
                         unsigned long arg );
#else
STATIC long optic_ioctl ( struct file *filp,
                         unsigned int cmd,
                         unsigned long arg );
#endif
STATIC unsigned int optic_poll ( struct file *filp,
                                 poll_table *table );

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
STATIC void optic_proc_version_get ( struct seq_file *s );
STATIC void optic_proc_status_get ( struct seq_file *s );
STATIC int optic_proc_install ( void );
#endif

#if 0
STATIC unsigned char rw_buf[256];
#endif

#ifdef DEFINE_SEMAPHORE
STATIC DEFINE_SEMAPHORE(rw_buf_sem);
#else
STATIC DECLARE_MUTEX(rw_buf_sem);
#endif

STATIC unsigned char major_number = 0;

extern u64 uevent_next_seqnum(void);

/** install parameter debug: off (4), msg (0), warn (1), err (2) */
STATIC unsigned char debug = OPTIC_DBG_ERR;

module_param(debug, byte, 0);
MODULE_PARM_DESC(debug, "off (4), msg (0), warn (1), err (2)");

STATIC struct file_operations optic_fops =
{
	owner:		THIS_MODULE,
	read:		optic_read,
	write:		optic_write,
	poll:		optic_poll,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))
	ioctl:		optic_ioctl,
#else
	unlocked_ioctl:	optic_ioctl,
#endif
	open:		optic_open,
	release:	optic_release
};

enum optic_debug_levels optic_debug_level = OPTIC_DBG_OFF;

DEFINE_SPINLOCK(reg_lock);

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

uint32_t optic_register_read ( uint8_t form, void *reg)
{
	vuint32_t *addr = (vuint32_t *) ((ulong_t) reg | KSEG1);
	unsigned long flags;
	uint32_t value;

	spin_lock_irqsave(&reg_lock, flags);

	if ((form == 16) &&
	    (optic_in_range(reg, OPTIC_FCSI_BASE, OPTIC_FCSI_END))) {
		optic_ll_fcsi_read ( (vuint16_t *) ((ulong_t)reg & 0xFF),
		                            &value );
	} else
	if (form == 32) {
#if (OPTIC_CHECK_ADDRESSES == ACTIVE)
		if ((!optic_in_range(reg, OPTIC_PMA_BASE, OPTIC_PMA_END)) &&
		    (!optic_in_range(reg, OPTIC_SYS_GPON_BASE,
		    		          OPTIC_SYS_GPON_END)) &&
		    (!optic_in_range(reg, OPTIC_STATUS_BASE,
		                          OPTIC_STATUS_END)) &&
		    (!optic_in_range(reg, OPTIC_GTC_PMA_BASE,
		                          OPTIC_GTC_PMA_END)) &&
		    (!optic_in_range(reg, OPTIC_FCSIC_BASE, OPTIC_FCSIC_END)) &&
		    (!optic_in_range(reg, OPTIC_DCDC_APD_BASE,
		    			  OPTIC_DCDC_APD_END)) &&
		    (!optic_in_range(reg, OPTIC_P0_BASE, OPTIC_P0_END)) &&
		    (!optic_in_range(reg, OPTIC_P1_BASE, OPTIC_P1_END)) &&
		    (!optic_in_range(reg, OPTIC_P2_BASE, OPTIC_P2_END)) &&
		    (!optic_in_range(reg, OPTIC_P3_BASE, OPTIC_P3_END)) &&
		    (!optic_in_range(reg, OPTIC_P4_BASE, OPTIC_P4_END))) {
		    	ret = OPTIC_STATUS_POOR;
		    	value = 0xFFFFFFFF;
		} else
#endif
			value = *addr;
	} else {
		value = 0xFFFFFFFF;
	}

	spin_unlock_irqrestore(&reg_lock, flags);
#ifdef EVENT_LOGGER_DEBUG
	if (!(optic_in_range(reg, OPTIC_FCSIC_BASE, OPTIC_FCSIC_END)) &&
		!in_interrupt() ) {
		EL_LOG_EVENT_REG_RD (1, 0, 0,
			(uint32_t)reg, &value, form / 16);
	}
#endif
#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_REG_R == ACTIVE))
	OPTIC_DEBUG_WRN(" reg read @0x%08X: 0x%08X", (ulong_t) reg, value );
#endif

	return value;
}

enum optic_errorcode optic_register_write ( uint8_t form,
                                            void *reg,
                                            uint32_t value )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	vuint32_t *addr = (vuint32_t *) ((ulong_t) reg | KSEG1);
	unsigned long flags;

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_REG_W == ACTIVE))
	OPTIC_DEBUG_WRN(" reg write @0x%08X: 0x%08X", (ulong_t) reg, value );
#endif

	spin_lock_irqsave(&reg_lock, flags);

	if ((form == 16) &&
	    (optic_in_range(reg, OPTIC_FCSI_BASE, OPTIC_FCSI_END))) {

		ret = optic_ll_fcsi_write ( (vuint16_t *) ((ulong_t)reg & 0xFF),
				            value );
	} else
	if (form == 32) {
#if (OPTIC_CHECK_ADDRESSES == ACTIVE)
		if ((!optic_in_range(reg, OPTIC_PMA_BASE, OPTIC_PMA_END)) &&
		    (!optic_in_range(reg, OPTIC_SYS_GPON_BASE,
		    		          OPTIC_SYS_GPON_END)) &&
		    (!optic_in_range(reg, OPTIC_STATUS_BASE,
		                          OPTIC_STATUS_END)) &&
		    (!optic_in_range(reg, OPTIC_GTC_PMA_BASE,
		                          OPTIC_GTC_PMA_END)) &&
		    (!optic_in_range(reg, OPTIC_FCSIC_BASE, OPTIC_FCSIC_END)) &&
		    (!optic_in_range(reg, OPTIC_DCDC_APD_BASE,
		                          OPTIC_DCDC_APD_END)) &&
		    (!optic_in_range(reg, OPTIC_DCDC_CORE_BASE,
		                          OPTIC_DCDC_CORE_END)) &&
		    (!optic_in_range(reg, OPTIC_DCDC_DDR_BASE,
		                          OPTIC_DCDC_DDR_END)) &&
		    (!optic_in_range(reg, OPTIC_P0_BASE, OPTIC_P0_END)) &&
		    (!optic_in_range(reg, OPTIC_P1_BASE, OPTIC_P1_END)) &&
		    (!optic_in_range(reg, OPTIC_P2_BASE, OPTIC_P2_END)) &&
		    (!optic_in_range(reg, OPTIC_P3_BASE, OPTIC_P3_END)) &&
		    (!optic_in_range(reg, OPTIC_P4_BASE, OPTIC_P4_END))) {
		    	ret = OPTIC_STATUS_POOR;
		} else
#endif
			*addr = value;
	} else {
		ret = OPTIC_STATUS_POOR;
	}

	spin_unlock_irqrestore(&reg_lock, flags);
#ifdef EVENT_LOGGER_DEBUG
	if (!(optic_in_range(reg, OPTIC_FCSIC_BASE, OPTIC_FCSIC_END)) &&
		!in_interrupt() ) {
		EL_LOG_EVENT_REG_WR (1, 0, 0,
			(uint32_t)reg, &value, form / 16);
	}
#endif

	return ret;
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
STATIC int optic_open ( struct inode *inode,
                        struct file *filp )
{
	int result = -1, num;
	struct optic_device *p_dev = NULL;

	num = MINOR(inode->i_rdev);

	if (num >= OPTIC_INSTANCES_MAX) {
		OPTIC_DEBUG_ERR("max. device number exceeded.");
		result = -ENODEV;
		goto OPEN_ERROR;
	}
	p_dev = (struct optic_device *)
		IFXOS_MemAlloc (sizeof(struct optic_device));
	if (p_dev == NULL) {
		OPTIC_DEBUG_ERR("allocation failure.");
		result = -ENODEV;
		goto OPEN_ERROR;
	}
	if (optic_device_open ( &optic_ctrl[num], p_dev ) != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("device open failed.");
		goto OPEN_ERROR;
	}

	filp->private_data = p_dev;
	return 0;

OPEN_ERROR:
	optic_device_close ( p_dev );
	return result;
}

/**
   Release the device.

   \param inode pointer to the inode
   \param filp pointer to the file descriptor

   \return
   - 0 - on success
   - otherwise error code
*/
STATIC int optic_release ( struct inode *inode,
                           struct file *filp )
{
	struct optic_device *p_dev =
				(struct optic_device *) filp->private_data;

	if (p_dev == NULL)
		return -1;

	if (optic_devicelist_delete ( p_dev->p_ctrl,
				      p_dev) == OPTIC_STATUS_ERR )
		return -1;

	optic_device_close ( p_dev );
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
STATIC ssize_t optic_write ( struct file *filp,
                             const char *buf,
                             size_t count,
                             loff_t *p_pos )
{
	int total = 0;

	/* struct optic_device *p_dev = (struct optic_device *)filp->private_data; */

#if 0
	down(&rw_buf_sem);
	do {
		int c = count;

		if (c > sizeof(rw_buf))
			c = sizeof(rw_buf);

		if (copy_from_user(rw_buf, buf, c)) {
			OPTIC_DEBUG_ERR("copy_from_user() failed.");
			/* error during copy */
		if (!total)
			total = -EFAULT;
			break;
		}

		/* put data */
		/* ... */
	}
	while (count);

	up(&rw_buf_sem);
#endif

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
STATIC ssize_t optic_read ( struct file *filp,
                            char *buf,
                            size_t count,
                            loff_t *p_pos )
{
	int len = 0;

	/* struct optic_device *p_dev = (struct optic_device *)filp->private_data; */

#if 0
	down(&rw_buf_sem);

	/* get data */
	/* ... */

	if (copy_to_user(buf, rw_buf, len)) {
		OPTIC_DEBUG(OPTIC_DBG_LOW, ("copy_to_user() failed!"));
		/* error during copy */
		len = -EFAULT;
	}

	up(&rw_buf_sem);
#endif
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
STATIC unsigned int optic_poll ( struct file *filp,
                                 poll_table *wait )
{
	struct optic_device *p_dev = (struct optic_device *)
				      filp->private_data;

	poll_wait (filp, &p_dev->select_queue, wait);
	if (IFX_Var_Fifo_getCount (&p_dev->fifo_nfc.data)) {
		return POLLIN;
	}
	return 0;
}

STATIC int optic_table_check ( const char *name,
			       const struct optic_entry *tbl,
			       const uint32_t num, const uint32_t size)
{
	uint32_t i;
	int ret = 0;

	if (num != size)
		OPTIC_DEBUG_ERR("%s - size doesn't match (%d - %d)",
				name, num, size);

	for (i=0; i<num; i++) {
		if (_IOC_NR(tbl[i].id == 0))
			continue;
		if (_IOC_NR(tbl[i].id) != i) {
			OPTIC_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x: "
					"id not in ascending order",
					name, i, tbl[i].name, tbl[i].id);
			ret = -1;
		}
		if ((_IOC_DIR(tbl[i].id) & _IOC_READ) &&
		    (tbl[i].size_out == 0)) {
			OPTIC_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x: "
					"read size 0",
				      	name, i, tbl[i].name, tbl[i].id);
			ret = -1;
		}
		if ((_IOC_DIR(tbl[i].id) & _IOC_WRITE) &&
		    (tbl[i].size_in == 0)) {
			OPTIC_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x: "
					"write size 0",
					name, i, tbl[i].name, tbl[i].id);
			ret = -1;
		}
		if (((_IOC_DIR(tbl[i].id) & _IOC_READ) == 0) &&
		    (tbl[i].size_out)) {
			OPTIC_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x: "
					"read size %d but _IOC_READ not set",
					name, i, tbl[i].name, tbl[i].id,
					tbl[i].size_out);
			ret = -1;
		}
		if (((_IOC_DIR(tbl[i].id) & _IOC_WRITE) == 0) &&
		    (tbl[i].size_in)) {
			OPTIC_DEBUG_ERR("%s[%02d] %s - cmd 0x%08x: "
					"write size %d but _IOC_WRITE not set",
					name, i, tbl[i].name, tbl[i].id,
					tbl[i].size_out);
			ret = -1;
		}
	}
	return ret;
}

STATIC void optic_ll_copy ( struct optic_device *p_dev,
                            const struct optic_entry *table,
                            struct optic_exchange *p_exchange,
                            uint32_t nr, uint8_t *buf )
{
	if (_IOC_DIR(table[nr].id) & _IOC_WRITE) {
		copy_from_user(buf, p_exchange->p_data, table[nr].size_in);
	}
	if (table[nr].p_entry0) {
		p_exchange->error = table[nr].p_entry0(p_dev);
	} else if (table[nr].p_entry1) {
		p_exchange->error = table[nr].p_entry1(p_dev, p_dev->io_buf);
	} else if (table[nr].p_entry2) {
		p_exchange->error = table[nr].p_entry2(p_dev, p_dev->io_buf, p_dev->io_buf);
	}
	if (_IOC_DIR(table[nr].id) & _IOC_READ) {
		copy_to_user(p_exchange->p_data, buf, table[nr].size_out);
		p_exchange->length = table[nr].size_out;
	} else {
		p_exchange->length = 0;
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
STATIC int optic_ioctl ( struct inode *inode,
                         struct file *filp,
                         unsigned int cmd,
                         unsigned long arg )
#else
STATIC long optic_ioctl ( struct file *filp,
                         unsigned int cmd,
                         unsigned long arg )
#endif
{
	int32_t ret = -EINVAL;
	struct optic_device *p_dev = (struct optic_device *)
				       filp->private_data;
	enum optic_errorcode errorcode;
	uint8_t *buf = &p_dev->io_buf[0];
	struct optic_exchange temp_exchange;
	struct optic_exchange *p_exchange = &temp_exchange;
	uint32_t type = _IOC_TYPE(cmd);
	uint32_t nr = _IOC_NR(cmd);
	uint32_t size = _IOC_SIZE(cmd);
	uint8_t width;
	uint8_t table_type;

	void *p_mem = NULL;
	void *p_mem_original;
	uint8_t number;
	struct optic_transfer_table_set *p_transtable_set;
	struct optic_transfer_table_get_in *p_transtable_get_in;
	struct optic_transfer_table_get_out *p_transtable_get_out;
	struct optic_measure_rssi_1490_get_in *p_measure_rssi_1490_get_in;
	struct optic_measure_rssi_1490_get_out *p_measure_rssi_1490_get_out;

   /* uint32_t dir = _IOC_DIR(cmd); */
   	if (size >= OPTIC_IO_BUF_SIZE) {
		OPTIC_DEBUG_ERR("buffer size");
		return ret;
	}

	copy_from_user(p_exchange, (void *)arg, sizeof(struct optic_exchange));

	if ((type == OPTIC_MAGIC) && (nr < OPTIC_MAX) &&
	    (nr == _IOC_NR(optic_function_table[nr].id))) {
		optic_ll_copy ( p_dev, optic_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_GOI_MAGIC) && (nr < OPTIC_GOI_MAX) &&
	    (nr == _IOC_NR(goi_function_table[nr].id))) {
		if (nr == _IOC_NR(FIO_GOI_TABLE_SET)) {
			/* transfer parameters into kernel space */
			if (_IOC_DIR(goi_function_table[nr].id) & _IOC_WRITE)
				copy_from_user(buf, p_exchange->p_data,
						goi_function_table[nr].size_in);

			p_transtable_set = (struct optic_transfer_table_set *)
			                   buf;

			/* transfer table from user space to kernel space */
			table_type = p_transtable_set->table_type;
			errorcode = optic_temptrans_size_get ( table_type,
			                                       &width );
			if (errorcode != OPTIC_STATUS_OK)
				return ret;

			p_mem = IFXOS_MemAlloc(width *
			                       p_transtable_set->table_depth);
			copy_from_user ( p_mem, p_transtable_set->p_data,
					 width * p_transtable_set->table_depth);
			p_transtable_set->p_data = p_mem;

			/* call API routine */
			if (goi_function_table[nr].p_entry1) {
				p_exchange->error =
					goi_function_table[nr].p_entry1 ( p_dev,
								p_dev->io_buf );
         		} else
         		if (goi_function_table[nr].p_entry2) {
				p_exchange->error =
					goi_function_table[nr].p_entry2 ( p_dev,
						p_dev->io_buf, p_dev->io_buf );
         		}

			/* transfer return parameters back into user space */
			if (_IOC_DIR(goi_function_table[nr].id) & _IOC_READ) {
				copy_to_user(p_exchange->p_data, buf,
					     goi_function_table[nr].size_out);
				p_exchange->length =
						goi_function_table[nr].size_out;
			} else {
				p_exchange->length = 0;
			}

			if (p_mem != NULL)
				IFXOS_MemFree(p_mem);

		} else
		if (nr == _IOC_NR(FIO_GOI_TABLE_GET)) {
			/* transfer parameters into kernel space */
			if (_IOC_DIR(goi_function_table[nr].id) & _IOC_WRITE)
				copy_from_user(buf, p_exchange->p_data,
						goi_function_table[nr].size_in);

			p_transtable_get_in = (struct
					       optic_transfer_table_get_in *)
					       buf;
			p_transtable_get_out = (struct
					        optic_transfer_table_get_out *)
					        buf;

			/* transfer (temporarly allocated) table from kernel
			   space to user space */
			table_type = p_transtable_get_in->table_type;
			errorcode = optic_temptrans_size_get ( table_type,
			                                       &width );
			if (errorcode != OPTIC_STATUS_OK)
				return ret;

			p_mem = IFXOS_MemAlloc(width *
			                      p_transtable_get_in->table_depth);
			p_mem_original = p_transtable_get_in->p_data;
			p_transtable_get_in->p_data = p_mem;

			/* call API routine */
			if (goi_function_table[nr].p_entry1) {
				p_exchange->error =
					goi_function_table[nr].p_entry1 ( p_dev,
								p_dev->io_buf );
         		} else
         		if (goi_function_table[nr].p_entry2) {
				p_exchange->error =
					goi_function_table[nr].p_entry2 ( p_dev,
						p_dev->io_buf, p_dev->io_buf );
         		}

			copy_to_user ( p_mem_original, p_mem, width *
			               p_transtable_get_out->table_depth);

			/* transfer return parameters back into user space */
			if (_IOC_DIR(goi_function_table[nr].id) & _IOC_READ) {
				copy_to_user(p_exchange->p_data, buf,
					     goi_function_table[nr].size_out);
				p_exchange->length =
						goi_function_table[nr].size_out;
			} else {
				p_exchange->length = 0;
			}

			if (p_mem != NULL)
				IFXOS_MemFree(p_mem);
		} else {
			optic_ll_copy ( p_dev, goi_function_table, p_exchange,
			                nr, buf );
		}
	} else
	if ((type == OPTIC_FCSI_MAGIC) && (nr < OPTIC_FCSI_MAX) &&
	    (nr == _IOC_NR(fcsi_function_table[nr].id))) {
		optic_ll_copy ( p_dev, fcsi_function_table, p_exchange, nr,
		                buf );
	} else
	if ((type == OPTIC_MM_MAGIC) && (nr < OPTIC_MM_MAX) &&
	    (nr == _IOC_NR(mm_function_table[nr].id))) {
		optic_ll_copy ( p_dev, mm_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_MPD_MAGIC) && (nr < OPTIC_MPD_MAX) &&
	    (nr == _IOC_NR(mpd_function_table[nr].id))) {
		optic_ll_copy ( p_dev, mpd_function_table, p_exchange, nr,
		                buf );
	} else
	if ((type == OPTIC_BERT_MAGIC) && (nr < OPTIC_BERT_MAX) &&
            (nr == _IOC_NR(bert_function_table[nr].id))) {
		optic_ll_copy ( p_dev, bert_function_table, p_exchange, nr,
				buf );
	} else
	if ((type == OPTIC_OMU_MAGIC) && (nr < OPTIC_OMU_MAX) &&
	    (nr == _IOC_NR(omu_function_table[nr].id))) {
		optic_ll_copy ( p_dev, omu_function_table, p_exchange, nr,
		                buf );
	} else
	if ((type == OPTIC_BOSA_MAGIC) && (nr < OPTIC_BOSA_MAX) &&
	    (nr == _IOC_NR(bosa_function_table[nr].id))) {
		optic_ll_copy ( p_dev, bosa_function_table, p_exchange, nr,
		                buf );
	} else
	if ((type == OPTIC_CAL_MAGIC) && (nr < OPTIC_CAL_MAX) &&
	    (nr == _IOC_NR(cal_function_table[nr].id))) {
		if (nr == _IOC_NR(FIO_CAL_MEASURE_RSSI_1490_GET)) {
			/* transfer parameters into kernel space */
			if (_IOC_DIR(cal_function_table[nr].id) & _IOC_WRITE)
				copy_from_user(buf, p_exchange->p_data,
						cal_function_table[nr].size_in);

			p_measure_rssi_1490_get_in = (struct
					optic_measure_rssi_1490_get_in *) buf;
			p_measure_rssi_1490_get_out = (struct
					optic_measure_rssi_1490_get_out *) buf;

			number = p_measure_rssi_1490_get_in->number;
			p_mem_original = p_measure_rssi_1490_get_in->p_data;

			if (p_mem_original != NULL)
				p_mem = IFXOS_MemAlloc( sizeof(uint16_t) *
							number);
			else
				p_mem = NULL;

			p_measure_rssi_1490_get_in->p_data = p_mem;

			/* call API routine */
			if (cal_function_table[nr].p_entry1) {
				p_exchange->error =
					cal_function_table[nr].p_entry1 ( p_dev,
								p_dev->io_buf );
         		} else
         		if (cal_function_table[nr].p_entry2) {
				p_exchange->error =
					cal_function_table[nr].p_entry2 ( p_dev,
						p_dev->io_buf, p_dev->io_buf );
         		}

			if ((p_mem != NULL) && (p_mem_original != NULL))
				copy_to_user ( p_mem_original, p_mem,
					       sizeof(uint16_t) * number);

			/* transfer return parameters back into user space */
			if (_IOC_DIR(cal_function_table[nr].id) & _IOC_READ) {
				copy_to_user(p_exchange->p_data, buf,
					     cal_function_table[nr].size_out);
				p_exchange->length =
						cal_function_table[nr].size_out;
			} else {
				p_exchange->length = 0;
			}


			if (p_mem != NULL)
				IFXOS_MemFree(p_mem);

		} else {
			optic_ll_copy ( p_dev, cal_function_table, p_exchange,
			                nr, buf );
		}
	} else
	if ((type == OPTIC_DCDC_APD_MAGIC) && (nr < OPTIC_DCDC_APD_MAX) &&
	    (nr == _IOC_NR(dcdc_apd_function_table[nr].id))) {
		optic_ll_copy ( p_dev, dcdc_apd_function_table, p_exchange, nr,
				buf );
	} else
	if ((type == OPTIC_DCDC_CORE_MAGIC) && (nr < OPTIC_DCDC_CORE_MAX) &&
	    (nr == _IOC_NR(dcdc_core_function_table[nr].id))) {
		optic_ll_copy ( p_dev, dcdc_core_function_table, p_exchange, nr,
				buf );
	} else
	if ((type == OPTIC_DCDC_DDR_MAGIC) && (nr < OPTIC_DCDC_DDR_MAX) &&
	    (nr == _IOC_NR(dcdc_ddr_function_table[nr].id))) {
		optic_ll_copy ( p_dev, dcdc_ddr_function_table, p_exchange, nr,
				buf );
	} else
	if ((type == OPTIC_LDO_MAGIC) && (nr < OPTIC_LDO_MAX) &&
	    (nr == _IOC_NR(ldo_function_table[nr].id))) {
		optic_ll_copy ( p_dev, ldo_function_table, p_exchange, nr,
				buf );
	} else
#ifdef INCLUDE_CLI_SUPPORT
	if ((type == _IOC_TYPE(FIO_OPTIC_CLI)) &&
	    (nr == _IOC_NR(FIO_OPTIC_CLI))) {
		if (p_exchange->length<(OPTIC_IO_BUF_SIZE-1)) {
			copy_from_user(buf, p_exchange->p_data,
							p_exchange->length + 1);
			size = optic_cli ( p_dev, buf );

			if (size >= 0 && size<(OPTIC_IO_BUF_SIZE-1)) {
				copy_to_user(p_exchange->p_data, buf, size + 1);
				p_exchange->length = size + 1;
				p_exchange->error = 0;
			} else {
				p_exchange->length = 0;
				p_exchange->error = -1;
			}
		}
	} else
#else
#  warning CLI support not enabled
#endif
	if ((type == _IOC_TYPE(FIO_OPTIC_EVENT_FIFO)) &&
	    (nr == _IOC_NR(FIO_OPTIC_EVENT_FIFO))) {
		uint32_t len = 0;
		struct optic_fifo_data *p_data = (struct optic_fifo_data *)
			IFX_Var_Fifo_peekElement (&p_dev->fifo_nfc.data, &len);
		if (p_data) {
			copy_to_user ( p_exchange->p_data, p_data, len );
			p_exchange->length = len;
			p_exchange->error = 0;
			optic_fifo_read ( &p_dev->fifo_nfc, NULL, &len );
		} else {
			p_exchange->length = 0;
			p_exchange->error = -1;
		}
	} else
	if ((type == _IOC_TYPE(FIO_OPTIC_EVENT_SET)) &&
	    (nr == _IOC_NR(FIO_OPTIC_EVENT_SET))) {
		enum optic_activation *p_data = (enum optic_activation *) &buf[0];
		copy_from_user ( buf, p_exchange->p_data,
		                 sizeof(enum optic_activation) );
		if (p_exchange->length == sizeof(enum optic_activation)) {
			p_dev->fifo_nfc.enable = (*p_data == OPTIC_ENABLE) ?
								true : false;
		} else {
			return ret;
		}
	} else
	if ((type == _IOC_TYPE(FIO_OPTIC_EVENT_GET)) &&
	    (nr == _IOC_NR(FIO_OPTIC_EVENT_GET))) {
		enum optic_activation *p_data = (enum optic_activation *)&buf[0];
		*p_data = (p_dev->fifo_nfc.enable == true) ?
						OPTIC_ENABLE : OPTIC_DISABLE;
		copy_to_user ( p_exchange->p_data, p_data,
		               sizeof(enum optic_activation) );
		p_exchange->length = sizeof(enum optic_activation);
		p_exchange->error = 0;
	} else {
		return ret;
	}

	copy_to_user((void *)arg, p_exchange, sizeof(struct optic_exchange));
	return 0;
}

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
/**
   Read the version information from the driver.

   \param buf destination buffer

   \return
   - length of the string
*/
STATIC void optic_proc_version_get ( struct seq_file *s )
{
	seq_printf(s, "%s" OPTIC_CRLF, &optic_whatversion[4]);
	seq_printf(s, "Compiled on %s, %s for Linux kernel %s" OPTIC_CRLF,
		   __DATE__, __TIME__, UTS_RELEASE);
}
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
/**
   Read the Temperature Table details from the driver.

   \param buf  destination buffer

   \return
   - length of the string
*/
STATIC void optic_proc_temptable_get ( struct seq_file *s )
{
	int i, temp;
	struct optic_control *p_ctrl;
	int16_t bias_high[3], mod_high[3], vapd_high, corr_high, pth_high,
	        ith_high, se_high, power_high[3];
	uint16_t bias_low[3], mod_low[3], vapd_low, corr_low, pth_low,
	         ith_low, se_low, power_low[3];
	struct optic_table_temperature_corr *tab;
	uint8_t *quality;
	uint8_t j;

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		/*
		seq_printf(s, "OPTIC[%d]" OPTIC_CRLF, i);
		*/
		p_ctrl = &optic_ctrl[i];
		if (p_ctrl->table_temperature_corr == NULL)
			continue;

		tab = p_ctrl->table_temperature_corr;

		/**
		300K:  Ibias,Imod,age (qual) ref:   1.00  1.00  12345  (1)
		       Ibias,Imod,age (qual) -3dB:  1.00  1.00  12345  (1)
		       Ibias,Imod,age (qual) +3dB:  1.00  1.00  12345  (1)
		       Vapd (qual):
		300K: Ibias/Imod[ref|-3dB|-6dB]:  11.00/11.00  11.00/11.00  11.00/11.00 (3)
		      Vapd, MPDresp_corr, age:    10.00 (1)     1.123 (2)   90000:11 (3)
		*/


		for (temp=p_ctrl->config.range.tabletemp_extcorr_min;
		     temp<=p_ctrl->config.range.tabletemp_extcorr_max; temp++) {
			i = temp - p_ctrl->config.range.tabletemp_extcorr_min;
			quality = p_ctrl->table_temperature_corr[i].quality;

			for (j=0; j<3; j++) {
				optic_float2int ( tab[i].ibiasimod.ibias[j],
		                	  	  OPTIC_FLOAT2INTSHIFT_CURRENT,
						  100, &(bias_high[j]),
						  &(bias_low[j]) );

				optic_float2int ( tab[i].ibiasimod.imod[j],
		                	  	  OPTIC_FLOAT2INTSHIFT_CURRENT,
						  100, &(mod_high[j]),
						  &(mod_low[j]) );
			}

			optic_float2int ( tab[i].factor[OPTIC_CFACTOR_PTH].
					  corr_factor,
					  OPTIC_FLOAT2INTSHIFT_CORRFACTOR,
					  1000, &pth_high, &pth_low );

			optic_float2int ( tab[i].laserref.ith,
					  OPTIC_FLOAT2INTSHIFT_CURRENT,
					  100, &ith_high, &ith_low );

			optic_float2int ( tab[i].laserref.se,
					  OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY,
					  100, &se_high, &se_low );

			optic_float2int ( tab[i].factor[OPTIC_CFACTOR_MPDRESP].
					  corr_factor,
					  OPTIC_FLOAT2INTSHIFT_CORRFACTOR,
					  1000, &corr_high, &corr_low );

			optic_float2int ( tab[i].vapd.vref,
					  OPTIC_FLOAT2INTSHIFT_VOLTAGE,
					  100, &vapd_high, &vapd_low );

			optic_float2int ( tab[i].factor[OPTIC_CFACTOR_RSSI1490].
					  corr_factor,
					  OPTIC_FLOAT2INTSHIFT_CORRFACTOR,
					  1000, &power_high[0], &power_low[0] );

			optic_float2int ( tab[i].factor[OPTIC_CFACTOR_RSSI1550].
					  corr_factor,
					  OPTIC_FLOAT2INTSHIFT_CORRFACTOR,
					  1000, &power_high[1], &power_low[1] );

			optic_float2int ( tab[i].factor[OPTIC_CFACTOR_RF1550].
					  corr_factor,
					  OPTIC_FLOAT2INTSHIFT_CORRFACTOR,
					  1000, &power_high[2], &power_low[2] );

			seq_printf(s, "%03dK: Ibias/Imod [ref|-3dB|-6dB]:   %2d.%02d/%2d.%02d   %2d.%02d/%2d.%02d   %2d.%02d/%2d.%02d (%d)" OPTIC_CRLF,
					temp, bias_high[0], bias_low[0],
					mod_high[0], mod_low[0],
					bias_high[1], bias_low[1],
					mod_high[1], mod_low[1],
					bias_high[2], bias_low[2],
					mod_high[2], mod_low[2],
					quality[OPTIC_TABLETYPE_IBIASIMOD-
						OPTIC_TABLETYPE_TEMP_CORR_MIN]);

			seq_printf(s, "      Pth factor, Ith/SE, age:       %d.%03d (%1d)    %2d.%02d/%3d.%02d (%1d)  %4d:%02d:%02d" OPTIC_CRLF,
					pth_high, pth_low,
					quality[OPTIC_TABLETYPE_PTH-
						OPTIC_TABLETYPE_TEMP_CORR_MIN],
					ith_high, ith_low,
					se_high, se_low,
					quality[OPTIC_TABLETYPE_LASERREF-
						OPTIC_TABLETYPE_TEMP_CORR_MIN],
					tab[i].laserref.age / 3600,
					(tab[i].laserref.age / 60) % 60,
					tab[i].laserref.age % 60);

			seq_printf(s, "      MPDrespCorr factor, Vapd/sat:  %1d.%03d (%1d)    %2d.%02d/%d (%1d)    " OPTIC_CRLF,
				   	corr_high, corr_low,
				   	quality[OPTIC_TABLETYPE_MPDRESP-
						OPTIC_TABLETYPE_TEMP_CORR_MIN],
					vapd_high, vapd_low,
					tab[i].vapd.sat,
					quality[OPTIC_TABLETYPE_VAPD-
				        	OPTIC_TABLETYPE_TEMP_CORR_MIN]);
			seq_printf(s, "      factor [RX1490|RX1550|RF1550]: %1d.%03d (%1d)     %1d.%03d (%1d)     %1d.%03d (%1d)    " OPTIC_CRLF,
				   	power_high[0], power_low[0],
				   	quality[OPTIC_TABLETYPE_RSSI1490-
						OPTIC_TABLETYPE_TEMP_CORR_MIN],
				   	power_high[1], power_low[1],
				   	quality[OPTIC_TABLETYPE_RSSI1550-
						OPTIC_TABLETYPE_TEMP_CORR_MIN],
				   	power_high[2], power_low[2],
				   	quality[OPTIC_TABLETYPE_RF1550-
						OPTIC_TABLETYPE_TEMP_CORR_MIN]);

		}

	}
}
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
/**
   Read the Temperature Translation Table from the driver.

   \param buf  destination buffer

   \return
   - length of the string
*/
STATIC void optic_proc_temptrans_get ( struct seq_file *s )
{
	int i, temp;
	struct optic_control *p_ctrl;
	struct optic_temptrans *trans;
	uint8_t *quality;

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		/*
		seq_printf(s, "OPTIC[%d]" OPTIC_CRLF, i);
		*/
		p_ctrl = &optic_ctrl[i];
		if (p_ctrl->table_temperature_nom == NULL)
			continue;

		/**
		300K -> 300K (1)   301K -> 302K (2)   302K -> 302K (3)   303K -> 303K (4)
		300K -> 300K (1)   301K -> 302K (2)   302K -> 302K (3)   303K -> 303K (4)
		300K -> 300K (1)   301K -> 302K (2)   302K -> 302K (3)   303K -> 303K (4)
		300K -> 300K (1)   301K -> 302K (2)   302K -> 302K (3)   303K -> 303K (4)
		*/

		for (temp=p_ctrl->config.range.tabletemp_extnom_min;
		     temp<=p_ctrl->config.range.tabletemp_extnom_max; temp++) {
			i = temp - p_ctrl->config.range.tabletemp_extnom_min;
			quality = p_ctrl->table_temperature_nom[i].quality;
			trans = &(p_ctrl->table_temperature_nom[i].temptrans);


			seq_printf(s, "%03dK -> %03dK (%1d)   ", temp,
			           trans->temp_corr,
			           quality[OPTIC_TABLETYPE_TEMPTRANS-
			            	   OPTIC_TABLETYPE_TEMP_NOM_MIN]);
			if (((i+1) % 4) == 0)
				seq_printf(s, OPTIC_CRLF);
		}
	}
}
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
/**
   Read the gain settings details from the driver.

   \param buf  destination buffer

   \return
   - length of the string
*/
STATIC void optic_proc_gainsettings_get ( struct seq_file *s )
{
	int i;
	struct optic_control *p_ctrl;
	int16_t factor_high, corr_high;
	uint16_t factor_low, corr_low;
	struct optic_measurement *measure;

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
/*
		seq_printf(s, "OPTIC[%d]" OPTIC_CRLF, i);
*/
		p_ctrl = &optic_ctrl[i];
		measure = &(p_ctrl->calibrate.measurement);

		seq_printf(s,    "gain selector   gain factor   offset   gain correction " OPTIC_CRLF);
		/*                     1              0,25        133        1234,993         */
		for (i=0; i<OPTIC_GAIN_SELECTOR_MAX; i++) {

			optic_float2int ( measure->gain[i].factor,
					  OPTIC_FLOAT2INTSHIFT_GAINFACTOR,
					  100, &factor_high, &factor_low );

			optic_float2int ( measure->gain[i].correction,
					  OPTIC_FLOAT2INTSHIFT_CORRFACTOR,
					  1000, &corr_high, &corr_low  );

			seq_printf(s, "     %d             %2d.%02d      %5d        %2d.%03d " OPTIC_CRLF,
				i, factor_high, factor_low,
				measure->gain[i].offset,
				corr_high,corr_low);
		}
	}
}
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
/**
   Read the gain settings details from the driver.

   \param buf  destination buffer

   \return
   - length of the string
*/
STATIC void optic_proc_monitor_get ( struct seq_file *s )
{
	int i,j;
	struct optic_control *p_ctrl;
	int16_t ratio_high[2],
		dcal_ref_p0_high[OPTIC_POWERLEVEL_MAX],
		dcal_ref_p1_high[OPTIC_POWERLEVEL_MAX],
		dref_p0_high[OPTIC_POWERLEVEL_MAX],
		dref_p1_high[OPTIC_POWERLEVEL_MAX];
	uint16_t ratio_low[2],
	         dcal_ref_p0_low[OPTIC_POWERLEVEL_MAX],
		 dcal_ref_p1_low[OPTIC_POWERLEVEL_MAX],
		 dref_p0_low[OPTIC_POWERLEVEL_MAX],
		 dref_p1_low[OPTIC_POWERLEVEL_MAX];

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
/*
      seq_printf(s, "OPTIC[%d]" OPTIC_CRLF, i);
*/
		p_ctrl = &optic_ctrl[i];

		seq_printf(s, "                                  ref.        -3dB        -6dB        global" OPTIC_CRLF);
		/*                     1              0,25        133        1234,993         */
		seq_printf(s, " tia gain selector (0x%04x):        %1d           %1d           %1d           %1d" OPTIC_CRLF,
			p_ctrl->config.fcsi.gvs,
		        p_ctrl->config.monitor.tia_gain_selector[OPTIC_GAINBANK_PL0],
		        p_ctrl->config.monitor.tia_gain_selector[OPTIC_GAINBANK_PL1],
		        p_ctrl->config.monitor.tia_gain_selector[OPTIC_GAINBANK_PL2],
		        p_ctrl->config.monitor.tia_gain_selector[OPTIC_GAINBANK_GLOBAL]);
		seq_printf(s, " MPD calibration selector:          %1d           %1d           %1d           %1d" OPTIC_CRLF,
		        p_ctrl->config.monitor.cal_current[OPTIC_GAINBANK_PL0],
		        p_ctrl->config.monitor.cal_current[OPTIC_GAINBANK_PL1],
		        p_ctrl->config.monitor.cal_current[OPTIC_GAINBANK_PL2],
		        p_ctrl->config.monitor.cal_current[OPTIC_GAINBANK_GLOBAL]);
		seq_printf(s, " tia offset coarse:               %3d         %3d         %3d         %3d" OPTIC_CRLF,
			p_ctrl->calibrate.dac_offset_tia_c[OPTIC_GAINBANK_PL0],
			p_ctrl->calibrate.dac_offset_tia_c[OPTIC_GAINBANK_PL1],
			p_ctrl->calibrate.dac_offset_tia_c[OPTIC_GAINBANK_PL2],
			p_ctrl->calibrate.dac_offset_tia_c[OPTIC_GAINBANK_GLOBAL]);
		seq_printf(s, " tia offset fine:                 %3d         %3d         %3d         %3d" OPTIC_CRLF,
			p_ctrl->calibrate.dac_offset_tia_f[OPTIC_GAINBANK_PL0],
			p_ctrl->calibrate.dac_offset_tia_f[OPTIC_GAINBANK_PL1],
			p_ctrl->calibrate.dac_offset_tia_f[OPTIC_GAINBANK_PL2],
			p_ctrl->calibrate.dac_offset_tia_f[OPTIC_GAINBANK_GLOBAL]);
		seq_printf(s, " P1 offset coarse:                %3d         %3d         %3d         %3d" OPTIC_CRLF,
			p_ctrl->calibrate.dac_offset_delta_p1_c[OPTIC_GAINBANK_PL0],
			p_ctrl->calibrate.dac_offset_delta_p1_c[OPTIC_GAINBANK_PL1],
			p_ctrl->calibrate.dac_offset_delta_p1_c[OPTIC_GAINBANK_PL2],
			p_ctrl->calibrate.dac_offset_delta_p1_c[OPTIC_GAINBANK_GLOBAL]);
		seq_printf(s, " P1 offset fine:                  %3d         %3d         %3d         %3d" OPTIC_CRLF,
			p_ctrl->calibrate.dac_offset_delta_p1_f[OPTIC_GAINBANK_PL0],
			p_ctrl->calibrate.dac_offset_delta_p1_f[OPTIC_GAINBANK_PL1],
			p_ctrl->calibrate.dac_offset_delta_p1_f[OPTIC_GAINBANK_PL2],
			p_ctrl->calibrate.dac_offset_delta_p1_f[OPTIC_GAINBANK_GLOBAL]);

		optic_float2int ( p_ctrl->calibrate.ratio_p0,
		                  OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO,
		                  1000, &(ratio_high[0]), &(ratio_low[0]) );

		optic_float2int ( p_ctrl->calibrate.ratio_p1,
		                  OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO,
		                  1000, &(ratio_high[1]), &(ratio_low[1]) );

		seq_printf(s, " P0 gain c/f-ratio:                                                   %2d.%03d " OPTIC_CRLF,
			ratio_high[0], ratio_low[0]);
		seq_printf(s, " P1 gain c/f-ratio:                                                   %2d.%03d " OPTIC_CRLF,
			ratio_high[1], ratio_low[1]);

		for (j=0; j<OPTIC_POWERLEVEL_MAX; j++) {
			optic_float2int ( p_ctrl->config.monitor.dcal_ref_p0[j],
		                	  OPTIC_FLOAT2INTSHIFT_DREF,
		                	  10, &(dcal_ref_p0_high[j]),
		                	  &(dcal_ref_p0_low[j]) );

			optic_float2int ( p_ctrl->config.monitor.dcal_ref_p1[j],
		                	  OPTIC_FLOAT2INTSHIFT_DREF,
		                	  10, &(dcal_ref_p1_high[j]),
		                	  &(dcal_ref_p1_low[j])  );
		}

		seq_printf(s, " P0 Dcal_ref:                  %6d.%01d    %6d.%01d    %6d.%01d" OPTIC_CRLF,
			dcal_ref_p0_high[OPTIC_POWERLEVEL_0],
			dcal_ref_p0_low[OPTIC_POWERLEVEL_0],
			dcal_ref_p0_high[OPTIC_POWERLEVEL_1],
			dcal_ref_p0_low[OPTIC_POWERLEVEL_1],
			dcal_ref_p0_high[OPTIC_POWERLEVEL_2],
			dcal_ref_p0_low[OPTIC_POWERLEVEL_2]);
		seq_printf(s, " P1 Dcal_ref:                  %6d.%01d    %6d.%01d    %6d.%01d" OPTIC_CRLF,
			dcal_ref_p1_high[OPTIC_POWERLEVEL_0],
			dcal_ref_p1_low[OPTIC_POWERLEVEL_0],
			dcal_ref_p1_high[OPTIC_POWERLEVEL_1],
			dcal_ref_p1_low[OPTIC_POWERLEVEL_1],
			dcal_ref_p1_high[OPTIC_POWERLEVEL_2],
			dcal_ref_p1_low[OPTIC_POWERLEVEL_2]);

		for (j=0; j<OPTIC_POWERLEVEL_MAX; j++) {
			optic_float2int ( p_ctrl->config.monitor.dref_p0[j],
		                	  OPTIC_FLOAT2INTSHIFT_DREF,
		                	  10, &(dref_p0_high[j]),
		                	  &(dref_p0_low[j]) );

			optic_float2int ( p_ctrl->config.monitor.dref_p1[j],
		                	  OPTIC_FLOAT2INTSHIFT_DREF,
		                	  10, &(dref_p1_high[j]),
		                	  &(dref_p1_low[j]) );
		}

		seq_printf(s, " P0 Dref:                      %6d.%01d    %6d.%01d    %6d.%01d" OPTIC_CRLF,
			dref_p0_high[OPTIC_POWERLEVEL_0],
			dref_p0_low[OPTIC_POWERLEVEL_0],
			dref_p0_high[OPTIC_POWERLEVEL_1],
			dref_p0_low[OPTIC_POWERLEVEL_1],
			dref_p0_high[OPTIC_POWERLEVEL_2],
			dref_p0_low[OPTIC_POWERLEVEL_2]);
		seq_printf(s, " P1 Dref:                      %6d.%01d    %6d.%01d    %6d.%01d" OPTIC_CRLF,
			dref_p1_high[OPTIC_POWERLEVEL_0],
			dref_p1_low[OPTIC_POWERLEVEL_0],
			dref_p1_high[OPTIC_POWERLEVEL_1],
			dref_p1_low[OPTIC_POWERLEVEL_1],
			dref_p1_high[OPTIC_POWERLEVEL_2],
			dref_p1_low[OPTIC_POWERLEVEL_2]);
	}

}
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
/**
   Read the Temperature Translation Table from the driver.

   \param buf  destination buffer

   \return
   - length of the string
*/
STATIC void optic_proc_temperatures_get ( struct seq_file *s )
{
	uint8_t i;
	struct optic_control *p_ctrl;
	struct optic_state *stat;

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		/*
		seq_printf(s, "OPTIC[%d]" OPTIC_CRLF, i);
		*/
		p_ctrl = &optic_ctrl[i];
		stat = &p_ctrl->state;

		/**
		jiffies temp_int temp_ext
		*/

		i = stat->index_temperature;

		do {
			if (i >= OPTIC_TEMPERATURE_HISTORY_DEPTH)
				i = 0;

			if (stat->temperatures[i].timestamp != 0) {
				seq_printf(s, "[ %u, %d, %d ]," OPTIC_CRLF,
					stat->temperatures[i].timestamp,
					stat->temperatures[i].temp_int,
					stat->temperatures[i].temp_ext);
			}

			i++;
		} while (i != stat->index_temperature);
	}
}
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
/**
   Read the status information from the driver.

   \param buf  destination buffer

   \return
   - length of the string
*/
STATIC void optic_proc_status_get ( struct seq_file *s )
{
	int i, k;
	uint32_t* p_int_cnt;
	struct optic_device *p_dev;

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		seq_printf(s, "OPTIC[%d]" OPTIC_CRLF, i);

		seq_printf(s, "OPTIC FIFO enable = %d" OPTIC_CRLF,
		           optic_ctrl[i].fifo_worker.enable);
		seq_printf(s, "OPTIC FIFO avail = %d" OPTIC_CRLF,
			IFX_Var_Fifo_getCount(&optic_ctrl[i].fifo_worker.data));
		seq_printf(s, "OPTIC FIFO lost = %d" OPTIC_CRLF,
			   optic_ctrl[i].fifo_worker.lost);
		if (IFXOS_MutexGet(&optic_ctrl[i].list_lock) == IFX_SUCCESS) {
			p_dev = optic_ctrl[i].p_dev_head;
			k = 0;
			while (p_dev) {
				seq_printf(s, "Device[%d][%d]" OPTIC_CRLF,
				           i, k);
				seq_printf(s, "NFC FIFO enable = %d" OPTIC_CRLF,
					   p_dev->fifo_nfc.enable);
				seq_printf(s, "NFC FIFO avail = %d" OPTIC_CRLF,
				  IFX_Var_Fifo_getCount(&p_dev->fifo_nfc.data));
				seq_printf(s, "NFC FIFO lost = %d" OPTIC_CRLF,
					   p_dev->fifo_nfc.lost);
				p_dev = p_dev->p_next;
				k++;
			}
			IFXOS_MutexRelease(&optic_ctrl[i].list_lock);
		}
		optic_ll_int_counter_get (&p_int_cnt);
		seq_printf(s, "BP0IBA = %d, BP0BA = %d, SIGDET = %d, LOS = %d" OPTIC_CRLF,
		           p_int_cnt[0], p_int_cnt[1], p_int_cnt[3], p_int_cnt[3]);

	}
}
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
typedef void (*optic_dump) (struct seq_file *s);

STATIC int optic_proc_show ( struct seq_file *s, void *p )
{
	optic_dump dump = s->private;

	if (dump != NULL)
		dump(s);

	return 0;
}

STATIC int optic_proc_open ( struct inode *inode, struct file *file )
{
	return single_open ( file, optic_proc_show, PDE(inode)->data );
}

struct proc_entry
{
	const char *name;
	void *callback;
	struct file_operations ops;
};

static struct proc_entry proc_entries[] =
{
	{ "version", optic_proc_version_get},
	{ "temptable", optic_proc_temptable_get},
	{ "temptrans", optic_proc_temptrans_get},
	{ "gainset", optic_proc_gainsettings_get},
	{ "monitor", optic_proc_monitor_get},
	{ "temperatures", optic_proc_temperatures_get},
	{ "status", optic_proc_status_get},
};
#define optic_permission (S_IFREG | S_IRUGO)


STATIC void optic_proc_entrycreate ( struct proc_dir_entry *parent_node,
				     struct proc_entry *proc_entry)
{
	memset(&proc_entry->ops, 0, sizeof(struct file_operations));
	proc_entry->ops.owner   = THIS_MODULE;
	proc_entry->ops.open    = optic_proc_open;
	proc_entry->ops.read    = seq_read;
	proc_entry->ops.llseek  = seq_lseek;
	proc_entry->ops.release = single_release;

	proc_create_data ( proc_entry->name, optic_permission, parent_node,
			   &proc_entry->ops, proc_entry->callback);
}


/**
   Initialize and install the proc entry

   \return
   -1 or 0 on success

   \remarks
   Called by the kernel.
*/
STATIC int optic_proc_install ( void )
{
	struct proc_dir_entry *driver_proc_node;
	int i;

	driver_proc_node = proc_mkdir("driver/" GPON_OPTIC_NAME, NULL);
	if (driver_proc_node == NULL) {
		OPTIC_DEBUG_ERR("cannot create proc entry");
		return -1;
	}

	for(i=0; i<sizeof(proc_entries)/sizeof(proc_entries[0]);i++) {
		optic_proc_entrycreate ( driver_proc_node, &proc_entries[i] );
	}

	return 0;
}
#endif

STATIC irqreturn_t optic_isr_pma_200 ( int irq, void *ctrl )
{
	struct optic_control *p_ctrl = (struct optic_control *) ctrl;
	optic_ll_int_bosa_handle ( OPTIC_IRQ_TYPE_INT200,
			           p_ctrl->config.callback_isr,
			           p_ctrl->calibrate.thresh_codeword_los,
			           p_ctrl->calibrate.thresh_codeword_ovl,
			           &(p_ctrl->state.interrupts) );

	return IRQ_HANDLED;
}

STATIC irqreturn_t optic_isr_pma_rx ( int irq, void *ctrl )
{
	struct optic_control *p_ctrl = (struct optic_control *) ctrl;
	optic_ll_int_bosa_handle ( OPTIC_IRQ_TYPE_INTRX ,
			           p_ctrl->config.callback_isr,
			           p_ctrl->calibrate.thresh_codeword_los,
			           p_ctrl->calibrate.thresh_codeword_ovl,
			           &(p_ctrl->state.interrupts) );

	return IRQ_HANDLED;
}

STATIC irqreturn_t optic_isr_pma_tx ( int irq, void *ctrl )
{
	struct optic_control *p_ctrl = (struct optic_control *) ctrl;
	optic_ll_int_bosa_handle ( OPTIC_IRQ_TYPE_INTTX ,
			           p_ctrl->config.callback_isr,
			           p_ctrl->calibrate.thresh_codeword_los,
			           p_ctrl->calibrate.thresh_codeword_ovl,
			           &(p_ctrl->state.interrupts) );

	return IRQ_HANDLED;
}

STATIC irqreturn_t optic_isr_gpio_sd ( int irq, void *ctrl )
{
	struct optic_control *p_ctrl = (struct optic_control *) ctrl;

	if (p_ctrl->config.omu.signal_detect_avail == true) {
		optic_ll_int_omu_handle ( OPTIC_IRQ_TYPE_GPIO_SD ,
				          p_ctrl->config.callback_isr,
				          p_ctrl->config.omu.signal_detect_port,
				          &(p_ctrl->state.interrupts) );
	}

	return IRQ_HANDLED;
}

void optic_irq_omu_init ( const uint8_t signal_detect_irq )
{
	uint8_t i;

	for (i=0; i<ARRAY_SIZE(optic_irq_tbl_omu); i++) {
		if (optic_irq_tbl_omu[i].irq_hndl == optic_isr_gpio_sd) {
			optic_irq_tbl_omu[i].irq_num = signal_detect_irq;
			break;
		}
	}
}

void optic_enable_irq (uint32_t irq)
{
	enable_irq (irq);
}

void optic_disable_irq (uint32_t irq)
{
	disable_irq (irq);
}

void optic_irq_set ( enum optic_manage_mode mode,
                     enum optic_activation act )
{
	int result = -1;
	uint8_t i, max;
	static enum optic_activation act_old = OPTIC_DISABLE;
	struct optic_irq_table *optic_irq_tbl;

	if (act_old == act)
		return;

	switch (mode) {
	case OPTIC_OMU:
		optic_irq_tbl = optic_irq_tbl_omu;
		max = ARRAY_SIZE(optic_irq_tbl_omu);
		break;
	case OPTIC_BOSA:
	case OPTIC_BOSA_2:
		optic_irq_tbl = optic_irq_tbl_bosa;
		max = ARRAY_SIZE(optic_irq_tbl_bosa);
		break;
	default:
		printk(KERN_ERR DEBUG_PREFIX " undefined mode %d \n", mode);
		return;
	}

	if (act == OPTIC_ENABLE) {
		for (i=0; i<max; i++) {
			result = request_irq ( optic_irq_tbl[i].irq_num,
					       optic_irq_tbl[i].irq_hndl,
					       optic_irq_tbl[i].irq_flag,
					       optic_irq_tbl[i].irq_name,
					       &optic_ctrl[0]);

			if (result)
				printk(KERN_ERR DEBUG_PREFIX
					" Failed to request %s IRQ %d\n",
					optic_irq_tbl[i].irq_name,
					optic_irq_tbl[i].irq_num);
		}
	} else {
		for (i=0; i<max; i++)
			free_irq ( optic_irq_tbl[i].irq_num, &optic_ctrl[0] );
	}

	act_old = act;
	return;
}


void optic_udelay ( uint32_t u_sec )
{
	udelay(u_sec);
}

/** Timer Handler

   \param timer Indicates the timer index
*/
STATIC void optic_timer_handler(unsigned long timer_no)
{
	struct optic_control *ctrl = &optic_ctrl[0];
	unsigned long flags;

	local_irq_save(flags);
	if (timer_no == OPTIC_TIMER_ID_MEASURE)
		optic_timer_measure (ctrl);
	if (timer_no == OPTIC_TIMER_ID_APD_ADAPT)
		optic_timer_dcdc_apd_adapt (ctrl);
	local_irq_restore(flags);
}

/**
   Start optic timer

   \param timer Timer Reference
   \param timeout  Timeout in mseconds.
*/
void optic_timer_start(const uint32_t timer_no, uint32_t timeout)
{
	/*printk("start timer %d" OPTIC_CRLF, timer_no); */
	if (!timer_pending(&optic_timer[timer_no])) {
		optic_timer[timer_no].expires = jiffies + timeout * HZ / 1000;
		add_timer(&optic_timer[timer_no]);
	}
}

/**
   Stop Timer

   \param timer_no Timer Index
*/
void optic_timer_stop(const uint32_t timer_no)
{
	/*printk("stop timer %d" OPTIC_CRLF, timer_no); */
	del_timer(&optic_timer[timer_no]);
}

int32_t optic_spinlock_init ( optic_lock *id, const char *name )
{
	spin_lock_init(id);
	return 0;
}

int32_t optic_spinlock_delete ( optic_lock *id)
{
	return 0;
}

int32_t optic_spinlock_get ( optic_lock *id, ulong_t *flags )
{
	spin_lock_irqsave ( id, *flags );
	return 0;
}

int32_t optic_spinlock_release ( optic_lock *id, ulong_t flags )
{
	spin_unlock_irqrestore(id, flags);
	return 0;
}

void * optic_probe(const unsigned long addr, const unsigned long size,
		 const char *name)
{
	struct resource *ioarea;
	void *ptr;

	ioarea = request_mem_region(addr & ~KSEG1, size, name);
	if (ioarea == NULL)
		return NULL;
	ptr = ioremap_nocache(ioarea->start, resource_size(ioarea));
	if (ptr == NULL) {
		goto err_release_mem_region;
	}
	return ptr;

err_release_mem_region:
	release_mem_region(addr, size);
	printk(KERN_ERR DEBUG_PREFIX " Error probing mem reqion (%s)\n", name);
	return NULL;
}

STATIC inline void optic_message_add ( struct sk_buff *skb, char *msg )
{
	char *scratch;
	scratch = skb_put(skb, strlen(msg) + 1);
	sprintf(scratch, msg);
}

#ifdef OPTIC_STATE_HOTPLUG_EVENT
void optic_hotplug_state ( const enum optic_statetype state )
{
	struct sk_buff *skb;
	char buf[128];
	static uint16_t cnt = 0;
	static enum optic_statetype old_state = 0;
	u64 seq;

	skb = alloc_skb(1024, GFP_KERNEL);
	if (skb == NULL)
		return;

	snprintf(buf, 128, "%d@", state);
	optic_message_add(skb, buf);
	optic_message_add(skb, "HOME=/");
	optic_message_add(skb, "PATH=/sbin:/bin:/usr/sbin:/usr/bin");
	optic_message_add(skb, "SUBSYSTEM=gpon");
	optic_message_add(skb, "DEVICENAME=optic");
	snprintf(buf, 128, "STATE=%d", state);
	optic_message_add(skb, buf);
	snprintf(buf, 128, "OLD_STATE=%d", old_state);
	optic_message_add(skb, buf);
	snprintf(buf, 128, "COUNTER=%d", cnt++);
	optic_message_add(skb, buf);
	seq = uevent_next_seqnum();
	snprintf(buf, 128, "SEQNUM=%llu", (unsigned long long)seq);
	optic_message_add(skb, buf);

	NETLINK_CB(skb).dst_group = 1;
	broadcast_uevent(skb, 0, 1, GFP_KERNEL);

	old_state = state;
}
#endif

void optic_hotplug_timestamp ( const uint32_t timestamp )
{
	struct sk_buff *skb;
	char buf[128];
	u64 seq;

	skb = alloc_skb(1024, GFP_KERNEL);
	if (skb == NULL)
		return;

	snprintf(buf, 128, "%u@", timestamp);
	optic_message_add(skb, buf);
	optic_message_add(skb, "HOME=/");
	optic_message_add(skb, "PATH=/sbin:/bin:/usr/sbin:/usr/bin");
	optic_message_add(skb, "SUBSYSTEM=gpon");
	optic_message_add(skb, "DEVICENAME=optic");
	snprintf(buf, 128, "TIMESTAMP=%u", timestamp);
	optic_message_add(skb, buf);
	seq = uevent_next_seqnum();
	snprintf(buf, 128, "SEQNUM=%llu", (unsigned long long)seq);
	optic_message_add(skb, buf);

	NETLINK_CB(skb).dst_group = 1;
	broadcast_uevent(skb, 0, 1, GFP_KERNEL);
}

int optic_signal_pending(void *sig)
{
	return signal_pending((struct task_struct*)sig);
}


#if (OPTIC_DYING_GASP_SHUTDOWN == ACTIVE)
static int optic_die_notify(struct notifier_block *self, unsigned long cmd,
			void *ptr)
{
	struct die_args *args = (struct die_args *)ptr;
	struct pt_regs *regs = args->regs;
	enum optic_errorcode ret;

	if (regs->cp0_status & ST0_NMI) {
		ret = optic_ll_dcdc_apd_set ( OPTIC_DISABLE );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		printk(KERN_ERR DEBUG_PREFIX " DCDC APD disabled\n");
	}

	/* return NOTIFY_STOP to don't call further notifiers */
	return NOTIFY_DONE;
}

static struct notifier_block optic_die_notifier = {
	.notifier_call = optic_die_notify,
};
#endif


static int optic_reboot_notify(struct notifier_block *self, unsigned long event,
			void *ptr)
{
	unsigned long irqflags;

	local_irq_save(irqflags);
	optic_ll_dcdc_core_restore_hw_values();
	local_irq_restore(irqflags);
	printk(KERN_ERR DEBUG_PREFIX " DCDC Core: restored HW values\n");
	return NOTIFY_OK;
}

static struct notifier_block optic_reboot_notifier = {
	.notifier_call = optic_reboot_notify,
};

/**
   Initialize the driver module.

   \return
   - 0 on success
   - Error code

   \remarks
   Called by the kernel.
*/
int __init optic_init ( void )
{
	int result=0, i;
	struct device *dev;

	printk("%s" OPTIC_CRLF, &optic_whatversion[4]);

	optic_debug_level = OPTIC_DBG_WRN;

	result = optic_table_check ( "common", &optic_function_table[0],
				     ARRAY_SIZE(optic_function_table),
				     OPTIC_MAX);
	result = optic_table_check ( "goi", &goi_function_table[0],
				     ARRAY_SIZE(goi_function_table),
				     OPTIC_GOI_MAX);
	result = optic_table_check ( "fcsi", &fcsi_function_table[0],
				     ARRAY_SIZE(fcsi_function_table),
				     OPTIC_FCSI_MAX);
	result = optic_table_check ( "mm", &mm_function_table[0],
				     ARRAY_SIZE(mm_function_table),
				     OPTIC_MM_MAX);
	result = optic_table_check ( "mpd", &mpd_function_table[0],
				     ARRAY_SIZE(mpd_function_table),
				     OPTIC_MPD_MAX);
	result = optic_table_check ( "bert", &bert_function_table[0],
				     ARRAY_SIZE(bert_function_table),
				     OPTIC_BERT_MAX);
	result = optic_table_check ( "omu", &omu_function_table[0],
				     ARRAY_SIZE(omu_function_table),
				     OPTIC_OMU_MAX);
	result = optic_table_check ( "bosa", &bosa_function_table[0],
				     ARRAY_SIZE(bosa_function_table),
				     OPTIC_BOSA_MAX);
	result = optic_table_check ( "cal", &cal_function_table[0],
				     ARRAY_SIZE(cal_function_table),
				     OPTIC_CAL_MAX);
	result = optic_table_check ( "dcdc_apd", &dcdc_apd_function_table[0],
				     ARRAY_SIZE(dcdc_apd_function_table),
				     OPTIC_DCDC_APD_MAX);

	major_number = register_chrdev(0, GPON_OPTIC_NAME, &optic_fops);
	if (!major_number) {
		OPTIC_DEBUG_ERR("can't get major number");
		result = -ENODEV;
		goto out;
	}

	optic_class = class_create(THIS_MODULE, "gpon-optic");
	if (IS_ERR(optic_class)) {
		result = PTR_ERR(optic_class);
		OPTIC_DEBUG_ERR("can't get major number");
		goto out_unreg_chrdev;
	}

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		dev = device_create ( optic_class, NULL,
				      MKDEV(major_number, i),
				      NULL, "optic%d", i);
		if (IS_ERR(dev)) {
			goto out_unreg_class;
		}
	}

	memset(optic_ctrl, 0x00, sizeof(optic_ctrl));

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
	optic_proc_install();
#endif

	for (i = 0; i < OPTIC_TIMER_GLOBAL_MAX; i++) {
		init_timer(&optic_timer[i]);
		optic_timer[i].data = i;
		optic_timer[i].function = optic_timer_handler;
	}

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		if (optic_context_init(&optic_ctrl[i], i) != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("can't init context %d", i);
			continue;
		}
	}
	pma = optic_probe(OPTIC_PMA_BASE, OPTIC_PMA_SIZE, "optic|pma");
	if (!pma)
		result = -ENODEV;
	dcdc_core = (struct optic_reg_dcdc *) optic_probe (OPTIC_DCDC_CORE_BASE,
		OPTIC_DCDC_CORE_SIZE, "optic|dcdc_core");
	dcdc_ddr = (struct optic_reg_dcdc *) optic_probe (OPTIC_DCDC_DDR_BASE,
		OPTIC_DCDC_DDR_SIZE, "optic|dcdc_ddr");
	dcdc_apd = (struct optic_reg_dcdc *)optic_probe (OPTIC_DCDC_APD_BASE,
		OPTIC_DCDC_APD_SIZE, "optic|dcdc_apd");
	fcsic = (struct optic_reg_fcsic *)optic_probe (OPTIC_FCSIC_BASE,
		OPTIC_FCSIC_SIZE, "optic|fcsic");
	gtc_pma = (struct optic_reg_gtc_pma *)optic_probe (OPTIC_GTC_PMA_BASE,
		OPTIC_GTC_PMA_SIZE, "optic|gtc_pma");
	pma_int200 = (struct optic_reg_pma_int200 *)optic_probe (OPTIC_PMA_INT200_BASE,
		OPTIC_PMA_INT200_SIZE, "optic|pma_int200");
	pma_intrx = (struct optic_reg_pma_intrx *) optic_probe (OPTIC_PMA_INTRX_BASE,
		OPTIC_PMA_INTRX_SIZE, "optic|pma_intrx");
	pma_inttx =(struct optic_reg_pma_inttx *) optic_probe (OPTIC_PMA_INTTX_BASE,
		OPTIC_PMA_INTTX_SIZE, "optic|pma_inttx");
	octrlg = (struct optic_reg_octrlg *)OPTIC_OCTRLG_BASE;
	status = (struct optic_reg_status *)OPTIC_STATUS_BASE;
	/*
	octrlg = (struct optic_reg_octrlg *)optic_probe (OPTIC_OCTRLG_BASE,
		OPTIC_OCTRLG_SIZE, "optic|octrlg");
	status = (struct optic_reg_status *)optic_probe (OPTIC_STATUS_BASE,
		OPTIC_STATUS_SIZE, "optic|status");
	*/
	sys1 = (struct optic_reg_sys1 *)optic_probe (OPTIC_SYS1_BASE,
		OPTIC_SYS1_SIZE, "optic|sys1");
	sys_gpon = (struct optic_reg_sys_gpon *) optic_probe (OPTIC_SYS_GPON_BASE,
		OPTIC_SYS_GPON_SIZE, "optic|sys_gpon");
	gtc = (struct optic_reg_gtc *)OPTIC_GTC_BASE;
#ifdef INCLUDE_CLI_SUPPORT
	optic_cli_init();
#endif
#ifdef EVENT_LOGGER_DEBUG
	EL_REG_Register ("optic", 1, 0, NULL);
#endif

	register_die_notifier(&optic_die_notifier);
	register_reboot_notifier(&optic_reboot_notifier);

	return 0;

out_unreg_class:
	class_destroy ( optic_class );
out_unreg_chrdev:
	unregister_chrdev(major_number, GPON_OPTIC_NAME);
out:

	return result;
}

/**
   Clean up the module if unloaded.

   \remarks
   Called by the kernel.
*/
void __exit optic_exit ( void )
{
	int i;
#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
	char buf[64];
#endif

	unregister_reboot_notifier(&optic_reboot_notifier);
	unregister_die_notifier (&optic_die_notifier);

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		device_destroy (optic_class, MKDEV(major_number, i));
	}
	unregister_chrdev (major_number, GPON_OPTIC_NAME);
	class_destroy (optic_class);

	for (i = 0; i < OPTIC_TIMER_GLOBAL_MAX; i++) {
		del_timer (&optic_timer[i]);
	}

#ifdef INCLUDE_CLI_SUPPORT
	optic_cli_shutdown();
#endif

#if defined(CONFIG_PROC_FS) && defined(INCLUDE_PROCFS_SUPPORT)
	for(i=0;i<sizeof(proc_entries)/sizeof(proc_entries[0]);i++) {
		sprintf(buf, "driver/" GPON_OPTIC_NAME "/%s",
			proc_entries[i].name);
		remove_proc_entry (buf, 0);
	}
	remove_proc_entry ("driver/" GPON_OPTIC_NAME, 0);
#endif

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		optic_context_free ( &optic_ctrl[i] );
	}

	OPTIC_DEBUG_MSG("cleanup successful");
}

EXPORT_SYMBOL(optic_register_read);
EXPORT_SYMBOL(optic_register_write);
EXPORT_SYMBOL(optic_isr_register);
EXPORT_SYMBOL(optic_ll_tx_fifo_set);
EXPORT_SYMBOL(optic_ll_tx_fifo_get);
EXPORT_SYMBOL(optic_ll_tx_laserdelay_set);
EXPORT_SYMBOL(optic_ll_tx_laserdelay_get);
EXPORT_SYMBOL(optic_powerlevel_set);
EXPORT_SYMBOL(optic_powerlevel_get);
EXPORT_SYMBOL(goi_lts_trigger);
EXPORT_SYMBOL(optic_tx_enable);

MODULE_AUTHOR("lantiq.com");
MODULE_DESCRIPTION("GPON optic driver - www.lantiq.com");
MODULE_SUPPORTED_DEVICE("FALC ON");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(OPTIC_VER_STR);


module_init(optic_init);
module_exit(optic_exit);

#endif /* LINUX */

/*! @} */

/*! @} */
