/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_register_h
#define _drv_onu_register_h

/* exclude some parts from SWIG generation */
#ifndef SWIG

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/
/*! \defgroup ONU_REGISTER_INTERNAL Device Register Access
   @{
*/
#include "drv_onu_std_defs.h"
#include "drv_onu_reg_base.h"
#include "drv_onu_reg_fsqm.h"
#include "drv_onu_reg_gtc.h"
#include "drv_onu_reg_gpearb.h"
#include "drv_onu_reg_iqm.h"
#include "drv_onu_reg_eim.h"
#include "drv_onu_reg_sxgmii.h"
#include "drv_onu_reg_ictrll.h"
#include "drv_onu_reg_ictrlg.h"
#include "drv_onu_reg_octrll.h"
#include "drv_onu_reg_octrlg.h"
#include "drv_onu_reg_pctrl.h"
#include "drv_onu_reg_sbs0ctrl.h"
#include "drv_onu_reg_sys_eth.h"
#include "drv_onu_reg_sys_gpe.h"
#include "drv_onu_reg_pe.h"
#include "drv_onu_reg_pctrl.h"
#include "drv_onu_reg_coplink_cop.h"
#include "drv_onu_reg_ictrlc.h"
#include "drv_onu_reg_octrlc.h"
#include "drv_onu_reg_link.h"
#include "drv_onu_reg_tbm.h"
#include "drv_onu_reg_tmu.h"
#include "drv_onu_reg_merge.h"
#include "drv_onu_reg_disp.h"
#include "drv_onu_reg_tod.h"
#include "drv_onu_reg_status.h"
#include "drv_onu_reg_sys1.h"

#define COPLINK_COP_BASE	0

#if 1 /* defined(ONU_SIMULATION) */
#define ONU_REGISTER_FUNC
uint32_t onu_register_read(void *reg);
void onu_register_write(void *reg, uint32_t val);
#endif

#ifdef ONU_REGISTER_FUNC
/** Read value of register

   \param reg  register address
   \return register contents
*/
#define reg_r32(reg) onu_register_read(reg)
/** Write value to register

   \param val  register value
   \param reg  register address
*/
#define reg_w32(val, reg) onu_register_write(reg, val)
#else
#include <asm/io.h>
/* no simulation, FPGA, ... -> direct access possible */
/** Read value of register

   \param reg  register address
   \return register contents
*/
#define reg_r32(reg)		__raw_readl(reg)
/** Write value to register

   \param val  register value
   \param reg  register address
*/
#define reg_w32(val, reg)	__raw_writel(val,reg)
#endif
/** Clear / set bits within a register

   \param clear   clear mask
   \param set     set mask
   \param reg     register address
*/
#define reg_w32_mask(clear, set, reg) reg_w32((reg_r32(reg) & ~(clear)) | (set), reg)
#define reg_r32_table(reg, idx) reg_r32(&((uint32_t *)&reg)[idx])
/** Write value to table entry

   \param val  register value
   \param reg  register address
   \param idx  number of the uint32 table element
*/
#define reg_w32_table(val, reg, idx) reg_w32(val, &((uint32_t *)&reg)[idx])
/** Write value to table entry

   \param clear   clear mask
   \param set     set mask
   \param reg     register address
   \param idx     number of the uint32 table element
*/
#define reg_w32_table_mask(clear, set, reg, idx) reg_w32_table((reg_r32_table(reg, idx) & ~(clear)) | (set), reg, idx)
/** Return the address of table entry

   \param reg  register address
   \param idx  number of the uint32 table element
*/
#define adr_table(reg, idx) (uint32_t)(&((uint32_t *)&reg)[idx])

extern struct onu_reg_fsqm *fsqm;
extern struct onu_reg_gpearb *gpearb;
extern struct onu_reg_gtc *gtc;
extern struct onu_reg_ictrlc *ictrlc;
extern struct onu_reg_octrlc *octrlc;
extern struct onu_reg_ictrlg *ictrlg;
extern struct onu_reg_ictrll *ictrll;
extern struct onu_reg_iqm *iqm;
extern struct onu_reg_link *link;
extern struct onu_reg_octrlg *octrlg;
extern struct onu_reg_octrll *octrll;
extern struct onu_reg_sbs0ctrl *sbs0ctrl;
extern struct onu_reg_sys_gpe *sys_gpe;
extern struct onu_reg_sys_eth *sys_eth;
extern struct onu_reg_tbm *tbm;
extern struct onu_reg_tmu *tmu;
extern struct onu_reg_merge *merge;
extern struct onu_reg_disp *disp;
extern union onu_reg_eim *eim;
extern struct onu_reg_sxgmii *sxgmii;
extern struct onu_reg_pctrl *pctrl;
extern struct onu_reg_pe *pe;
extern struct onu_reg_tod *tod;
extern struct onu_reg_status *status;
extern struct onu_reg_sys1 * sys1;

#define set_val(reg, val, mask, offset) do {(reg) &= ~(mask); (reg) |= (((val) << (offset)) & (mask)); } while(0)
#define get_val(val, mask, offset) (((val) & (mask)) >> (offset))

/*! @} */
/*! @} */

EXTERN_C_END
#endif				/* SWIG */
#endif
