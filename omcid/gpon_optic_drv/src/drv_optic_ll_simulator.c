/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_calc.h"
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

#ifdef OPTIC_SIMULATION

#include "drv_optic_ll_simulator.h"

struct optic_reg_sys_gpon g_sys_gpon;
struct optic_reg_sys_gpon *sys_gpon = &g_sys_gpon;

/*
struct optic_reg_octrlg g_octrlg;
struct optic_reg_octrlg *octrlg = &g_octrlg;
*/

struct optic_reg_status g_status;
struct optic_reg_status *status = &g_status;

struct optic_reg_gtc_pma g_gtc_pma;
struct optic_reg_gtc_pma *gtc_pma = &g_gtc_pma;

struct optic_reg_pma g_pma;
struct optic_reg_pma *pma = &g_pma;

struct optic_reg_fcsic g_fcsic;
struct optic_reg_fcsic *fcsic = &g_fcsic;

struct optic_reg_fcsi g_fcsi;
struct optic_reg_fcsi *fcsi = &g_fcsi;

struct optic_reg_dcdc g_dcdc_apd;
struct optic_reg_dcdc *dcdc_apd = &g_dcdc_apd;

struct optic_reg_dcdc g_dcdc_core;
struct optic_reg_dcdc *dcdc_core = &g_dcdc_core;

struct optic_reg_dcdc g_dcdc_ddr;
struct optic_reg_dcdc *dcdc_ddr = &g_dcdc_ddr;

struct optic_reg_sys1 g_sys1;
struct optic_reg_sys1 *sys1 = &g_sys1;

struct optic_reg_pma_int200 g_pma_int200;
struct optic_reg_pma_int200 *pma_int200 = &g_pma_int200;

struct optic_reg_pma_intrx g_pma_intrx;
struct optic_reg_pma_intrx *pma_intrx = &g_pma_intrx;

struct optic_reg_pma_inttx g_pma_inttx;
struct optic_reg_pma_inttx *pma_inttx = &g_pma_inttx;

int optic_ll_fcsic_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)fcsic + (reg & ~OPTIC_FCSIC_BASE);

	*val = *(vuint32_t *) (addr);

	/* simulate ready bits */
	if (addr == (ulong_t)&fcsic->stat)
		*val |= FCSIC_STAT_XR_FRDY |
			FCSIC_STAT_XE_FEMP |
			FCSIC_STAT_RR_FRDY;

	return 0;
}

int optic_ll_fcsic_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)fcsic + (reg & ~OPTIC_FCSIC_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}

int optic_ll_pma_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)pma + (reg & ~OPTIC_PMA_BASE);

	*val = *(vuint32_t *) (addr);

	/* simulate pll lock */
	if (addr == (ulong_t)&pma->gpon_pll_slice_pdi_status)
		*val |= (1 << PMA_STATUS_STARTUP_RDY_OFFSET) |
			PMA_STATUS_LOCK;

	return 0;
}

int optic_ll_pma_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)pma + (reg & ~OPTIC_PMA_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}

int optic_ll_sysgpon_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)sys_gpon + (reg & ~OPTIC_SYS_GPON_BASE);

	*val = *(vuint32_t *) (addr);
	return 0;
}

int optic_ll_sysgpon_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)sys_gpon + (reg & ~OPTIC_SYS_GPON_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}

/*
int optic_ll_octrlg_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)octrlg + (reg & ~OPTIC_OCTRLG_BASE);

	*val = *(vuint32_t *) (addr);
	return 0;
}

int optic_ll_octrlg_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)octrlg + (reg & ~OPTIC_OCTRLG_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}
*/

int optic_ll_status_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)status + (reg & ~OPTIC_STATUS_BASE);

	*val = *(vuint32_t *) (addr);
	return 0;
}

int optic_ll_status_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)status + (reg & ~OPTIC_STATUS_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}

int optic_ll_gtc_pma_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)gtc_pma + (reg & ~OPTIC_GTC_PMA_BASE);

	*val = *(vuint32_t *) (addr);
	return 0;
}

int optic_ll_gtc_pma_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)gtc_pma + (reg & ~OPTIC_GTC_PMA_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}

int optic_ll_fcsi_simread ( ulong_t reg, uint32_t *val )
{
	uint16_t temp;
	ulong_t addr = (ulong_t)fcsi + (reg & ~OPTIC_FCSI_BASE)*2;

	temp = *(vuint16_t *) (addr);
	*val = temp;
	return 0;
}

int optic_ll_fcsi_simwrite ( ulong_t reg, uint32_t val )
{
	uint16_t temp = (uint16_t) val;
	ulong_t addr = (ulong_t)fcsi + (reg & ~OPTIC_FCSI_BASE)*2;

	*(vuint16_t *) (addr) = temp;
	return 0;
}

int optic_ll_dcdc_apd_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)dcdc_apd + (reg & ~OPTIC_DCDC_APD_BASE);

	*val = *(vuint32_t *) (addr);
	return 0;
}

int optic_ll_dcdc_apd_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)dcdc_apd + (reg & ~OPTIC_DCDC_APD_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}

int optic_ll_dcdc_core_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)dcdc_core + (reg & ~OPTIC_DCDC_CORE_BASE);

	*val = *(vuint32_t *) (addr);
	return 0;
}

int optic_ll_dcdc_core_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)dcdc_core + (reg & ~OPTIC_DCDC_CORE_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}

int optic_ll_dcdc_ddr_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)dcdc_ddr + (reg & ~OPTIC_DCDC_DDR_BASE);

	*val = *(vuint32_t *) (addr);
	return 0;
}

int optic_ll_dcdc_ddr_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)dcdc_ddr + (reg & ~OPTIC_DCDC_DDR_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}

int optic_ll_sys1_simread ( ulong_t reg, uint32_t *val )
{
	ulong_t addr = (ulong_t)sys1 + (reg & ~OPTIC_SYS1_BASE);

	*val = *(vuint32_t *) (addr);
	return 0;
}

int optic_ll_sys1_simwrite ( ulong_t reg, uint32_t val )
{
	ulong_t addr = (ulong_t)sys1 + (reg & ~OPTIC_SYS1_BASE);

	*(vuint32_t *) (addr) = val;
	return 0;
}


void optic_register_correct ( uint8_t form, void **reg )
{
	/* memory address in case of reg_ macro access */
	if ((form == 16) &&
	    (optic_in_range ( *reg, (ulong_t)fcsi, (ulong_t)fcsi +
	                      (OPTIC_FCSI_END - OPTIC_FCSI_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)fcsi +
				OPTIC_FCSI_BASE);
	} else
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)fcsic, (ulong_t)fcsic +
			      (OPTIC_FCSIC_END - OPTIC_FCSIC_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)fcsic +
				OPTIC_FCSIC_BASE);
	} else
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)pma, (ulong_t)pma +
	    		      (OPTIC_PMA_END - OPTIC_PMA_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)pma + OPTIC_PMA_BASE);
	} else
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)sys_gpon, (ulong_t)sys_gpon +
	                      (OPTIC_SYS_GPON_END - OPTIC_SYS_GPON_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)sys_gpon +
				OPTIC_SYS_GPON_BASE);
	} else
/*
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)octrlg, (ulong_t)octrlg +
	                      (OPTIC_OCTRLG_END - OPTIC_OCTRLG_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)octrlg +
				OPTIC_OCTRLG_BASE);
	} else
*/
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)status, (ulong_t)status +
	                      (OPTIC_STATUS_END - OPTIC_STATUS_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)status +
				OPTIC_STATUS_BASE);
	} else
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)gtc_pma, (ulong_t)gtc_pma +
	    		      (OPTIC_GTC_PMA_END - OPTIC_GTC_PMA_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)gtc_pma +
				OPTIC_GTC_PMA_BASE);
	} else
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)dcdc_apd, (ulong_t)dcdc_apd +
	                      (OPTIC_DCDC_APD_END - OPTIC_DCDC_APD_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)dcdc_apd +
				OPTIC_DCDC_APD_BASE);
	} else
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)dcdc_core, (ulong_t)dcdc_core +
	                      (OPTIC_DCDC_CORE_END - OPTIC_DCDC_CORE_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)dcdc_core +
				OPTIC_DCDC_CORE_BASE);
	} else
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)dcdc_ddr, (ulong_t)dcdc_ddr +
	                      (OPTIC_DCDC_DDR_END - OPTIC_DCDC_DDR_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)dcdc_ddr +
				OPTIC_DCDC_DDR_BASE);
	}
	if ((form == 32) &&
	    (optic_in_range ( *reg, (ulong_t)sys1, (ulong_t)sys1 +
	                      (OPTIC_SYS1_END - OPTIC_SYS1_BASE) ) )) {
		*reg = (void*) ((ulong_t)*reg - (ulong_t)sys1 +
				OPTIC_SYS1_BASE);
	}
}

uint32_t optic_register_read ( uint8_t form, void *reg)
{
	uint32_t value = 0;

	/* memory address in case of reg_ macro access */
	optic_register_correct (form, &reg);

	if ((form == 16) &&
	    (optic_in_range ( reg, OPTIC_FCSI_BASE, OPTIC_FCSI_END ))) {
		optic_ll_fcsi_simread((ulong_t)reg, &value);
	} else
	if ((form == 32) &&
	    (optic_in_range(reg, OPTIC_FCSIC_BASE, OPTIC_FCSIC_END ))) {
		optic_ll_fcsic_simread((ulong_t)reg, &value);
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_PMA_BASE, OPTIC_PMA_END ))) {
		optic_ll_pma_simread((ulong_t)reg, &value);
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_SYS_GPON_BASE, OPTIC_SYS_GPON_END ))) {
		optic_ll_sysgpon_simread((ulong_t)reg, &value);
	} else
/*
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_OCTRLG_BASE, OPTIC_OCTRLG_END ))) {
		optic_ll_octrlg_simread((ulong_t)reg, &value);
	} else
*/
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_STATUS_BASE, OPTIC_STATUS_END ))) {
		optic_ll_status_simread((ulong_t)reg, &value);
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_GTC_PMA_BASE, OPTIC_GTC_PMA_END ))) {
	      optic_ll_gtc_pma_simread((ulong_t)reg, &value);
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_DCDC_APD_BASE, OPTIC_DCDC_APD_END ))) {
		optic_ll_dcdc_apd_simread((ulong_t)reg, &value);
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_DCDC_CORE_BASE,
	    			   OPTIC_DCDC_CORE_END ))) {
		optic_ll_dcdc_core_simread((ulong_t)reg, &value);
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_DCDC_DDR_BASE, OPTIC_DCDC_DDR_END ))) {
		optic_ll_dcdc_ddr_simread((ulong_t)reg, &value);
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_SYS1_BASE, OPTIC_SYS1_END ))) {
		optic_ll_sys1_simread((ulong_t)reg, &value);
	} else
		OPTIC_DEBUG_ERR ("reg 0x%x read access not supported", reg);


	return value;
}


enum optic_errorcode optic_register_write ( uint8_t form,
					    void *reg,
                                            uint32_t value )
{
	enum optic_errorcode ret = OPTIC_STATUS_ERR;

	/* memory address in case of reg_ macro access */
	optic_register_correct (form, &reg);

	if ((form == 16) &&
	    (optic_in_range ( reg, OPTIC_FCSI_BASE, OPTIC_FCSI_END ))) {
		if (optic_ll_fcsi_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_FCSIC_BASE, OPTIC_FCSIC_END ))) {
		if (optic_ll_fcsic_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_PMA_BASE, OPTIC_PMA_END ))) {
		if (optic_ll_pma_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_SYS_GPON_BASE, OPTIC_SYS_GPON_END ))) {
		if (optic_ll_sysgpon_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
/*
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_OCTRLG_BASE, OPTIC_OCTRLG_END ))) {
		if (optic_ll_octrlg_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
*/
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_STATUS_BASE, OPTIC_STATUS_END ))) {
		if (optic_ll_status_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_GTC_PMA_BASE, OPTIC_GTC_PMA_END ))) {
		if (optic_ll_gtc_pma_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_DCDC_APD_BASE, OPTIC_DCDC_APD_END ))) {
		if (optic_ll_dcdc_apd_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_DCDC_CORE_BASE,
	    			   OPTIC_DCDC_CORE_END ))) {
		if (optic_ll_dcdc_core_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_DCDC_DDR_BASE, OPTIC_DCDC_DDR_END ))) {
		if (optic_ll_dcdc_ddr_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
	if ((form == 32) &&
	    (optic_in_range ( reg, OPTIC_SYS1_BASE, OPTIC_SYS1_END ))) {
		if (optic_ll_sys1_simwrite((ulong_t)reg, value) == 0)
			ret = OPTIC_STATUS_OK;
	} else
		OPTIC_DEBUG_ERR ("reg 0x%x write access not supported", reg);


	return ret;
}

void optic_irq_set ( enum optic_manage_mode mode,
                     enum optic_activation act )
{
	(void) mode;
	(void) act;

	return;
}

void optic_irq_omu_init ( const uint8_t signal_detect_irq )
{
	(void) signal_detect_irq;

	return;
}

#endif /* OPTIC_SIMULATION */
