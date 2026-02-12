/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_SIMULATION_INTERNAL Simulation Specific Implementation - Internal
   @{
*/



#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_timer.h"

#ifdef OPTIC_SIMULATION

#include <stdlib.h>

#include "ifxos_device_io.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"
#include "ifxos_event.h"

#include "drv_optic_cli_core.h"
#include "drv_optic_event_interface.h"
#include "drv_optic_timer.h"
#include "drv_optic_register.h"
#include "drv_optic_ll_simulator.h"
#include "drv_optic_ll_fcsi.h"

#include "ifxos_event.h"
#include "ifxos_thread.h"

struct timer_list
{
   ulong_t data;
   bool start;
   uint32_t delay;
   IFXOS_event_t timeout_event;
   void (*function) (ulong_t param);
   IFXOS_ThreadCtrl_t thread_context;
};

#define IFXOS_BlockAlloc IFXOS_MemAlloc
#define IFXOS_BlockFree IFXOS_MemFree

long optic_open ( void *ctrl,
                  const char *appendix );
int optic_release ( void *dev );
int optic_write ( void *dev,
                  const char *p_src,
                  const int length );
int optic_read( void *dev,
                char *p_dst,
                const int length );
int optic_ioctl ( void *dev,
                  unsigned int cmd,
                  ulong_t arg );
int optic_poll ( void *dev );

STATIC unsigned int major_number;

#ifdef INCLUDE_DEBUG_SUPPORT
enum optic_debug_levels optic_debug_level = OPTIC_DBG_OFF;
#endif

STATIC struct timer_list optic_timer[OPTIC_TIMER_GLOBAL_MAX];

void *current = NULL;

/**
   Open the device.

   At the first time:
   - allocating internal memory for each new device
   - initialize the device

   \return
   - 0 - if error,
   - device context - if success
*/
long optic_open ( void *ctrl, const char *appendix)
{
	struct optic_device *p_dev = (struct optic_device *)
   				IFXOS_MemAlloc(sizeof(struct optic_device));
	(void) appendix;

	if (optic_device_open ( (struct optic_control *) ctrl,
					p_dev ) != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("Init failed");
		goto OPEN_ERROR;
	}
	return (long) p_dev;

OPEN_ERROR:
	optic_device_close ( p_dev );
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
int optic_release ( void *dev )
{
	struct optic_device *p_dev = (struct optic_device *) dev;

	if (p_dev == NULL)
		return -1;

	if (optic_devicelist_delete ( p_dev->p_ctrl, p_dev ) ==
	    OPTIC_STATUS_ERR)
		return -1;

	optic_device_close( p_dev );
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
int optic_write ( void *dev, const char *p_src, const int length )
{
	int total = 0;
	struct optic_device *p_dev = (struct optic_device *) dev;
	(void) p_dev;
	(void) p_src;
	(void) length;

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
int optic_read ( void *dev, char *p_dst, const int length )
{
	int len = 0;
	struct optic_device *p_dev = (struct optic_device *) dev;
	(void) p_dev;
	(void) p_dst;
	(void) length;

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
int optic_poll ( void *dev )
{
	struct optic_device *p_dev = (struct optic_device *) dev;

	/* data available */
	if (IFX_Var_Fifo_isEmpty (&p_dev->fifo_nfc.data) == 0) {
      		return 1;
	} else {
		p_dev->nfc_need_wakeup = true;
	}

	return 0;
}

static void cp ( struct optic_device *p_dev,
		 const struct optic_entry *table,
		 struct optic_exchange *p_exchange,
		 uint32_t nr,
		 uint8_t *buf )
{
	if (_IOC_DIR(table[nr].id) & _IOC_WRITE)
		memcpy(buf, p_exchange->p_data, table[nr].size_in);

	if (table[nr].p_entry0) {
		p_exchange->error = table[nr].p_entry0(p_dev);
	} else
	if (table[nr].p_entry1) {
		p_exchange->error = table[nr].p_entry1(p_dev, p_dev->io_buf);
	} else
	if (table[nr].p_entry2) {
		p_exchange->error = table[nr].p_entry2(p_dev, p_dev->io_buf,
							p_dev->io_buf);
	}

	if (_IOC_DIR(table[nr].id) & _IOC_READ) {
		memcpy (p_exchange->p_data, buf, table[nr].size_out);
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
int optic_ioctl ( void *dev, unsigned int cmd, ulong_t arg)
{
	int32_t ret = -1, i;
	struct optic_device *p_dev = (struct optic_device *) dev;
	uint8_t *buf;
	struct optic_exchange *p_exchange = (struct optic_exchange *) arg;

	uint32_t type = _IOC_TYPE(cmd);
	uint32_t nr = _IOC_NR(cmd);
/*	uint32_t size = _IOC_SIZE(cmd); */
	uint32_t dir = _IOC_DIR(cmd);
	(void) dir;

	buf = &p_dev->io_buf[0];

#ifndef OPTIC_SIMULATION
	if (size >= OPTIC_IO_BUF_SIZE)
		return ret;
#endif

	if ((type == OPTIC_MAGIC) && (nr < OPTIC_MAX) &&
	    (nr == _IOC_NR(optic_function_table[nr].id))) {
		cp ( p_dev, optic_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_GOI_MAGIC) && (nr < OPTIC_GOI_MAX) &&
	    (nr == _IOC_NR(goi_function_table[nr].id))) {
		cp ( p_dev, goi_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_FCSI_MAGIC) && (nr < OPTIC_FCSI_MAX) &&
	    (nr == _IOC_NR(fcsi_function_table[nr].id))) {
		cp ( p_dev, fcsi_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_MM_MAGIC) && (nr < OPTIC_MM_MAX) &&
	    (nr == _IOC_NR(mm_function_table[nr].id))) {
		cp ( p_dev, mm_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_MPD_MAGIC) && (nr < OPTIC_MPD_MAX) &&
	    (nr == _IOC_NR(mpd_function_table[nr].id))) {
		cp ( p_dev, mpd_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_BERT_MAGIC) && (nr < OPTIC_BERT_MAX) &&
	    (nr == _IOC_NR(bert_function_table[nr].id))) {
		cp ( p_dev, bert_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_OMU_MAGIC) && (nr < OPTIC_OMU_MAX) &&
	    (nr == _IOC_NR(omu_function_table[nr].id))) {
		cp ( p_dev, omu_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_BOSA_MAGIC) && (nr < OPTIC_BOSA_MAX) &&
	    (nr == _IOC_NR(bosa_function_table[nr].id))) {
		cp ( p_dev, bosa_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_CAL_MAGIC) && (nr < OPTIC_CAL_MAX) &&
	    (nr == _IOC_NR(cal_function_table[nr].id))) {
		cp ( p_dev, cal_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_DCDC_APD_MAGIC) && (nr < OPTIC_DCDC_APD_MAX) &&
	    (nr == _IOC_NR(dcdc_apd_function_table[nr].id))) {
		cp ( p_dev, dcdc_apd_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_DCDC_CORE_MAGIC) && (nr < OPTIC_DCDC_CORE_MAX) &&
	    (nr == _IOC_NR(dcdc_core_function_table[nr].id))) {
		cp ( p_dev, dcdc_core_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_DCDC_DDR_MAGIC) && (nr < OPTIC_DCDC_DDR_MAX) &&
	    (nr == _IOC_NR(dcdc_ddr_function_table[nr].id))) {
		cp ( p_dev, dcdc_ddr_function_table, p_exchange, nr, buf );
	} else
	if ((type == OPTIC_LDO_MAGIC) && (nr < OPTIC_LDO_MAX) &&
	    (nr == _IOC_NR(ldo_function_table[nr].id))) {
		cp ( p_dev, ldo_function_table, p_exchange, nr, buf );
	} else
#ifdef INCLUDE_CLI_SUPPORT
	if ((type == _IOC_TYPE(FIO_OPTIC_CLI)) &&
	    (nr == _IOC_NR(FIO_OPTIC_CLI))) {
		if (p_exchange->length<(OPTIC_IO_BUF_SIZE-1)) {
			memcpy(buf, p_exchange->p_data, p_exchange->length + 1);
			i = optic_cli ( p_dev, (char*)buf );
			if ((i >= 0) && (i<(OPTIC_IO_BUF_SIZE-1))) {
				memcpy(p_exchange->p_data, buf, i + 1);
				p_exchange->length = i + 1;
				p_exchange->error = 0;
			} else {
				p_exchange->length = 0;
				p_exchange->error = -1;
			}
		}
	} else
#endif
	if ((type == _IOC_TYPE(FIO_OPTIC_EVENT_FIFO)) &&
	    (nr == _IOC_NR(FIO_OPTIC_EVENT_FIFO))) {
		uint32_t len = 0;
		struct optic_fifo_data *p_data = (struct optic_fifo_data *)
                          IFX_Var_Fifo_peekElement(&p_dev->fifo_nfc.data, &len);

		if (p_data) {
			memcpy(p_exchange->p_data, p_data, len);
			p_exchange->length = len;
			p_exchange->error = 0;
			optic_fifo_read ( &p_dev->fifo_nfc, IFX_NULL, &len );
		} else {
			p_exchange->length = 0;
			p_exchange->error = -1;
		}
	} else
	if ((type == _IOC_TYPE(FIO_OPTIC_EVENT_SET)) &&
	    (nr == _IOC_NR(FIO_OPTIC_EVENT_SET))) {
		enum optic_activation *p_data = (enum optic_activation *)
							p_exchange->p_data;
		p_dev->fifo_nfc.enable = (*p_data == OPTIC_ENABLE)?
					 true : false;
	} else
	if ((type == _IOC_TYPE(FIO_OPTIC_EVENT_GET)) &&
	    (nr == _IOC_NR(FIO_OPTIC_EVENT_GET))) {
		enum optic_activation *p_data = (enum optic_activation *)
							p_exchange->p_data;
		*p_data = (p_dev->fifo_nfc.enable == true)?
						OPTIC_ENABLE : OPTIC_DISABLE;
	} else {
		return ret;
	}

	return 0;
}

/**
   Start optic timer

   \param timer Timer Index
   \param timeout  Timeout in mseconds.
*/
void optic_timer_start(const uint32_t timer_no, uint32_t timeout)
{
	struct timer_list *timer = &optic_timer[timer_no];
	if (timer->start == false) {
		timer->delay = timeout;
		timer->start = true;

		IFXOS_EventWakeUp(&timer->timeout_event);
	}
}



/**
   Stop Timer

   \param timer Timer Index
*/
void optic_timer_stop ( const uint32_t timer_no )
{
	struct timer_list *timer = &optic_timer[timer_no];
	timer->delay = 0;
	timer->start = false;
}

void optic_udelay ( uint32_t u_sec )
{
	(void) u_sec;
}

#ifdef OPTIC_STATE_HOTPLUG_EVENT
void optic_hotplug_state ( const enum optic_statetype state )
{
	(void) state;
}
#endif

void optic_hotplug_timestamp (const uint32_t timestamp)
{
	(void) timestamp;
}

int optic_signal_pending(void *sig)
{
	(void) sig;
	return 0;
}

int32_t optic_spinlock_init ( optic_lock *id, const char *name )
{
	if (IFXOS_MutexInit (id) != IFX_SUCCESS) {
		OPTIC_DEBUG_ERR("Can't initialize %s mutex.", name);
		return -1;
	}

	/* clear warning for unused parameter (OPTIC_DEBUG_ERR predefined) */
	(void) name;

	return 0;
}

int32_t optic_spinlock_delete ( optic_lock *id )
{
	return IFXOS_MutexDelete(id);
}

int32_t optic_spinlock_get ( optic_lock *id, ulong_t *flags )
{
	IFXOS_MutexGet(id);
	(void) flags;
	return 0;
}

int32_t optic_spinlock_release ( optic_lock *id, ulong_t c )
{
	IFXOS_MutexRelease(id);
	(void) c;
	return 0;
}

int32_t optic_timer_thread ( IFXOS_ThreadParams_t *param )
{
	struct timer_list *p_timer = (struct timer_list *) param->nArg1;
	while (1) {
		if ((p_timer->start) && (p_timer->delay)) {
			IFXOS_MSecSleep (p_timer->delay);
			if (p_timer->start)
				p_timer->function (p_timer->data);
		} else {
			/* wait for Activating */
			IFXOS_EventWait (&p_timer->timeout_event, 1000, NULL);
		}
	}
}

void init_timer ( struct timer_list *timer )
{
	static uint8_t nr = 0;
	char buffer[20];
	sprintf(buffer, "optic-timer-%2d", nr ++);

	timer->start = false;

	/* Initialize timeout event */
	if (IFXOS_EventInit (&timer->timeout_event) == IFX_SUCCESS) {
		if (IFXOS_ThreadInit ( &timer->thread_context, buffer,
                                       optic_timer_thread,
				       OPTIC_TIMER_THREAD_STACK_SIZE,
				       OPTIC_TIMER_THREAD_PRIO,
				       (ulong_t) timer, 0) == IFX_SUCCESS ) {
			return;
		}
	}
	OPTIC_DEBUG_ERR("can't start timer thread %d", nr-1);
}

void del_timer ( struct timer_list *timer )
{
	IFXOS_ThreadDelete ( &timer->thread_context, 0 );
	IFXOS_EventDelete ( &timer->timeout_event );
}

void optic_enable_irq (uint32_t irq)
{
	(void) irq;
}

void optic_disable_irq (uint32_t irq)
{
	(void) irq;
}

/**
   Initialize the driver module.

   \return
   - 0 on success
   - Error code

   \remarks
   Called by the kernel.
*/
int optic_init ( void )
{
	char buf[64];
	uint32_t i;

#ifdef INCLUDE_DEBUG_SUPPORT
	optic_debug_level = (enum optic_debug_levels) 0;
#endif

	OPTIC_DEBUG_MSG("DEVIO - SIMULATION ");
	OPTIC_DEBUG_MSG("%s", &optic_whatversion[4]);

	major_number = DEVIO_driver_install ( optic_open,
					      optic_release,
					      optic_read,
					      optic_write,
					      optic_ioctl,
					      optic_poll );

	if (major_number == (unsigned)-1) {
		OPTIC_DEBUG_ERR("can't get major %d", major_number);
		return -1;
	}

	/*for (i = 0; i < OPTIC_TIMER_GLOBAL_MAX; i++) {
		init_timer ( &optic_timer[i] );
		optic_timer[i].data = i;
		optic_timer[i].function = optic_timer_handler;
	}*/

	memset(optic_ctrl, 0x00, sizeof(optic_ctrl));

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		sprintf(buf, "%s%d", DRV_IO_GPON_OPTIC, i);
		if ((signed) DEVIO_device_add ( &optic_ctrl[i], &buf[0],
		     major_number) == IFX_ERROR) {
			OPTIC_DEBUG_ERR("unable to create device.");
			goto OPTIC_INIT_ERROR;
		}

		if (optic_context_init ( &optic_ctrl[i], i ) !=
		    OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("can't init optic context %d", i);
			continue;
		}
/*
		OPTIC_TimerStart(&optic_timer[i], 5000);
*/
	}

#ifdef INCLUDE_CLI_SUPPORT
	optic_cli_init();
#endif

	return 0;

OPTIC_INIT_ERROR:

	optic_exit();

	return -1;
}

/**
   Clean up the module if unloaded.

   \remarks
   Called by the kernel.
*/
void optic_exit ( void )
{
	int i;

	DEVIO_driver_remove ( major_number, 1 );

	for (i = 0; i < OPTIC_INSTANCES_MAX; i++) {
		optic_context_free ( &optic_ctrl[i] );
	}

	OPTIC_DEBUG_MSG("cleanup successful");
}

#endif /* OPTIC_SIMULATION */

/*! @} */

/*! @} */
