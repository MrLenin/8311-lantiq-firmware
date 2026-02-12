/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_resource.h"
#include "drv_onu_api.h"
#include "drv_onu_ploam_api.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_ll_gtc.h"
#include "drv_onu_gtc_api.h"
#include "drv_onu_register.h"

#ifdef ONU_SIMULATION

int onu_gtc_read(ulong_t base, ulong_t offset, uint32_t *val)
{
	ulong_t addr = base + offset;

	if ((ulong_t) & gtc->downstr_gtc_mrx_1 == addr) {
		gtc->downstr_gtc_dsstat_1 &=
		    ~(GTC_DSSTAT_1_RXDAT | GTC_DSSTAT_1_RXOFL |
		      GTC_DSSTAT_1_RXFUL);
	}
	*val = *(vuint32_t *) (addr);
	return 0;
}

int onu_gtc_write(ulong_t base, ulong_t offset, uint32_t val)
{
	ulong_t addr = base + offset;

	/* clear on write, write 1 becomes 0 */
	if ((ulong_t) & gtc->downstr_gtc_dsistat_1 == addr) {
		gtc->downstr_gtc_dsistat_1 = gtc->downstr_gtc_dsistat_1 & ~val;
		return 0;
	}
	if ((ulong_t) & gtc->upstr_gtc_usistat == addr) {
		gtc->upstr_gtc_usistat = gtc->upstr_gtc_usistat & ~val;
		return 0;
	}
	/* action on writing PLOAM TX control */
	if ((ulong_t) & gtc->upstr_gtc_mtx_ctrl == addr) {
		ONU_DEBUG_MSG("GTC_MTX_CTRL: %x", val);
		if (val & GTC_MTX_CTRL_FLUSH)
			ONU_DEBUG_MSG("GTC_MTX_CTRL: FLUSH");
		return 0;
	}

	return 1;
}

int in_range(void *ptr, ulong_t start, ulong_t end)
{
	if ((ulong_t) ptr >= start && (ulong_t) ptr < end)
		return 1;
	return 0;
}

uint32_t onu_register_read(void *reg)
{
	uint32_t val = 0;

	if (in_range(reg, (ulong_t) gtc, (ulong_t) gtc + 0x200)) {
		if (onu_gtc_read
		    ((ulong_t) gtc, (ulong_t) reg - (ulong_t) gtc, &val) == 0) {
			return val;
		}
	}
	if (in_range(reg, 0xb4005000, 0xb4005000 + 0x200)) {
		if (onu_gtc_read(0xb4005000, (ulong_t) reg - 0xb4005000, &val)
		    == 0) {
			return val;
		}
	}
	/*return *(vuint32_t *) (reg); */
	return 0;
}

void onu_register_write(void *reg, uint32_t val)
{
	if (in_range(reg, (ulong_t) gtc, (ulong_t) gtc + 0x200)) {
		if (onu_gtc_write
		    ((ulong_t) gtc, (ulong_t) reg - (ulong_t) gtc, val) == 0) {
			return;
		}
	}
	if (in_range(reg, 0xb4005000, 0xb4005000 + 0x200)) {
		if (onu_gtc_write(0xb4005000, (ulong_t) reg - 0xb4005000, val)
		    == 0) {
			return;
		}
	}
   /**(vuint32_t *) (reg) = val;*/
}

#if 0
int optic_ll_tx_fifo_set ( const uint16_t delay_enable,
				const uint16_t delay_disable,
				const uint16_t size_fifo )
{
	return 0;
}

int optic_ll_tx_fifo_get ( uint16_t *delay_enable,
				uint16_t *delay_disable,
				uint16_t *size_fifo )
{
	return 0;
}

int optic_ll_tx_laserdelay_set ( const uint8_t bitdelay )
{
	return 0;
}

int optic_powerlevel_set ( const uint8_t powerlevel )
{
	return 0;
}
#endif

#endif				/* ONU_SIMULATION */
