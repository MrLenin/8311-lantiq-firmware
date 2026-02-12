/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifdef HAVE_CONFIG_H
#include "drv_optic_config.h"
#endif

#ifdef OPTIC_LIBRARY
#include <stddefs.h>
#include <stdlib.h>
#include "config.h"
#include "device_io.h"
#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "sys_tickedtimer.h"
#include "drv_optic_timer.h"

#include "drv_optic_dcdc_apd.h"
#include "drv_optic_register.h"
#include "drv_optic_ll_fcsi.h"
#include "drv_optic_reg_base.h"
#include "drv_optic_reg_sys_gpon.h"
#include "drv_optic_reg_status.h"
#include "drv_optic_reg_dcdc.h"
#include "drv_optic_reg_sys1.h"
#include "drv_optic_reg_pma.h"
#include "drv_optic_reg_gtc_pma.h"
#include "drv_optic_reg_pma_int200.h"
#include "drv_optic_reg_pma_intrx.h"
#include "drv_optic_reg_pma_inttx.h"
#include "drv_optic_reg_fcsic.h"
#include "drv_optic_ll_int.h"

#define IFXOS_BlockAlloc IFXOS_MemAlloc
#define IFXOS_BlockFree IFXOS_MemFree

long optic_open ( void *ctrl,
                  const char *appendix );

int optic_ioctl ( void *dev,
                  unsigned int cmd,
                  ulong_t arg );
int optic_poll ( void *dev );

struct optic_device g_optic_device;

struct optic_reg_pma *pma = (struct optic_reg_pma *)OPTIC_PMA_BASE;
struct optic_reg_dcdc *dcdc_core =
	(struct optic_reg_dcdc *)OPTIC_DCDC_CORE_BASE;
struct optic_reg_dcdc *dcdc_ddr =
	(struct optic_reg_dcdc *) OPTIC_DCDC_DDR_BASE;
struct optic_reg_dcdc *dcdc_apd =
	(struct optic_reg_dcdc *) OPTIC_DCDC_APD_BASE;
struct optic_reg_fcsic *fcsic = 
	(struct optic_reg_fcsic *) OPTIC_FCSIC_BASE;
struct optic_reg_gtc_pma *gtc_pma = 
	(struct optic_reg_gtc_pma *) OPTIC_GTC_PMA_BASE;
struct optic_reg_pma_int200 *pma_int200 = 
	(struct optic_reg_pma_int200 *)OPTIC_PMA_INT200_BASE;
struct optic_reg_pma_intrx *pma_intrx = 
	(struct optic_reg_pma_intrx *) OPTIC_PMA_INTRX_BASE;
struct optic_reg_pma_inttx *pma_inttx =
	(struct optic_reg_pma_inttx *) OPTIC_PMA_INTTX_BASE;
struct optic_reg_status *status = 
	(struct optic_reg_status *)OPTIC_STATUS_BASE;
struct optic_reg_sys1 *sys1 = 
	(struct optic_reg_sys1 *)OPTIC_SYS1_BASE;
struct optic_reg_sys_gpon *sys_gpon = 
	(struct optic_reg_sys_gpon *) OPTIC_SYS_GPON_BASE;


struct optic_reg_fcsi *fcsi;
STATIC struct timer_list optic_timer[OPTIC_TIMER_GLOBAL_MAX];

#ifdef INCLUDE_DEBUG_SUPPORT
enum optic_debug_levels optic_debug_level = OPTIC_DBG_ERR;
#endif

STATIC unsigned int major_number;

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
	struct optic_device *p_dev = &g_optic_device;
	(void) appendix;

	if (optic_device_open (&optic_ctrl[0], p_dev) !=
	    OPTIC_STATUS_OK) {
		optic_device_close ( p_dev );
		return -1;
	}
	return (long) p_dev;
}

/**
   Release the device.

   \param inode pointer to the inode
   \param filp pointer to the file descriptor

   \return
   - 0 - on success
   - otherwise error code
*/
int optic_release (long p_dev)
{
	optic_device_close ((struct optic_device *) p_dev );

	return 0;
}


void optic_irq_poll (void)
{
	int i;
	struct optic_control *p_ctrl = &optic_ctrl[0];

	if (p_ctrl->config.mode != OPTIC_OMU) {
		for (i = 0; i < 3; i++)
			optic_ll_int_bosa_handle ( i, NULL,
					   p_ctrl->calibrate.thresh_codeword_los,
					   p_ctrl->calibrate.thresh_codeword_ovl,
					   &(p_ctrl->state.interrupts) );
	} else {
		optic_ll_int_omu_handle ( OPTIC_IRQ_TYPE_GPIO_SD ,
				  p_ctrl->config.callback_isr,
				  p_ctrl->config.omu.signal_detect_port,
				  &(p_ctrl->state.interrupts) );
	}
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
	return 0;
}

static void cp ( struct optic_device *p_dev,
		 const struct optic_entry *table,
		 struct optic_exchange *p_exchange,
		 uint32_t nr,
		 uint8_t *buf )
{
	/*
	if (_IOC_DIR(table[nr].id) & _IOC_WRITE)
		memcpy(buf, p_exchange->p_data, table[nr].size_in);
	*/
	if (table[nr].p_entry0) {
		p_exchange->error = table[nr].p_entry0 (p_dev);
	} else
	if (table[nr].p_entry1) {
		p_exchange->error = table[nr].p_entry1 (p_dev,
							p_exchange->p_data);
	} else
	if (table[nr].p_entry2) {
		p_exchange->error = table[nr].p_entry2 (p_dev,
							p_exchange->p_data,
							p_exchange->p_data);
	}

	if (_IOC_DIR(table[nr].id) & _IOC_READ) {
		/*memcpy(p_exchange->p_data, buf, table[nr].size_out);*/
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
	struct optic_device *p_dev = (struct optic_device *) dev;
	uint8_t *buf = NULL;
	struct optic_exchange *p_exchange = (struct optic_exchange *) arg;

	uint32_t type = _IOC_TYPE(cmd);
	uint32_t nr = _IOC_NR(cmd);
	uint32_t dir = _IOC_DIR(cmd);
	(void) dir;


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
#if (OPTIC_OCAL_SUPPORT == ACTIVE)
	if ((type == OPTIC_CAL_MAGIC) && (nr < OPTIC_CAL_MAX) &&
	    (nr == _IOC_NR(cal_function_table[nr].id))) {
		cp ( p_dev, cal_function_table, p_exchange, nr, buf );
	} else
#endif
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
	}

	return 0;
}

void optic_udelay ( uint32_t u_sec )
{
	udelay(u_sec);
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

void optic_irq_set ( enum optic_manage_mode mode,
                     enum optic_activation act )
{
	(void) mode;
	(void) act;

	return;
}

void optic_enable_irq (uint32_t irq)
{
	(void) irq;
}

void optic_disable_irq (uint32_t irq)
{
	(void) irq;
}

/** Timer Handler

   \param timer Indicates the timer index
*/
STATIC void optic_timer_handler(unsigned long timer_no)
{
	struct optic_control *ctrl = &optic_ctrl[0];

	if (timer_no == OPTIC_TIMER_ID_MEASURE)
		optic_timer_measure (ctrl);
	if (timer_no == OPTIC_TIMER_ID_APD_ADAPT)
		optic_timer_dcdc_apd_adapt (ctrl);
}

/**
   Start optic timer

   \param timer Timer Reference
   \param timeout  Timeout in mseconds.
*/
void optic_timer_start(const uint32_t timer_no, uint32_t timeout)
{
	timer_start (&optic_timer[timer_no], timeout, 0);
}

/**
   Stop Timer

   \param timer_no Timer Index
*/
void optic_timer_stop(const uint32_t timer_no)
{
	tick_timer_stop (&optic_timer[timer_no]);
}

void* optic_malloc (size_t size, uint32_t id)
{
	static char temp_corr[8850];
	static char temp_nom[1024];

	printf ("Optic malloc #%d %d bytes\n", id, size);
	switch (id) {
	case MEM_TBL_TEMP_CORR:
		return &temp_corr;
	case MEM_TBL_TEMP_NOM:
		return &temp_nom;
	default:
		return NULL;
	}
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
	int i;
#ifdef INCLUDE_DEBUG_SUPPORT
	optic_debug_level = (enum optic_debug_levels) OPTIC_DBG_WRN;
#endif
	OPTIC_DEBUG_MSG("%s", &optic_whatversion[4]);

	major_number = DEVIO_driver_install ( (DEVIO_device_open)optic_open,
					      (DEVIO_device_close)optic_release,
					      NULL,
					      NULL,
					      optic_ioctl,
					      optic_poll );

	if (major_number == (unsigned)-1) {
		OPTIC_DEBUG_ERR("can't get major %d", major_number);
		return -1;
	}
	memset(optic_ctrl, 0x00, sizeof(optic_ctrl));

	if (DEVIO_device_add ( &optic_ctrl[0],
				"/dev/optic0",
				major_number) == (unsigned int)IFX_ERROR) {
		OPTIC_DEBUG_ERR("unable to create device.");
		return -1;
	}

	if (optic_context_init (&optic_ctrl[0], 0 ) !=
		OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("unable to create device.");
		return -1;
	}
	for (i = 0; i < OPTIC_TIMER_GLOBAL_MAX; i++) {
		timer_init ( &optic_timer[i], optic_timer_handler, i);
	}

	return 0;
}

void optic_irq_omu_init ( const uint8_t signal_detect_irq )
{
	(void) signal_detect_irq;

	return;
}

#endif
