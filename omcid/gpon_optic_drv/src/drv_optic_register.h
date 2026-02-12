
/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_register_h
#define _drv_optic_register_h

/* exclude some parts from SWIG generation */
#ifndef SWIG

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/*! \defgroup OPTIC_REGISTER_INTERNAL Register Access - Internal
   @{
*/

#include "drv_optic_std_defs.h"
#include "drv_optic_debug.h" /* INLINE */
#include "drv_optic_reg_base.h"

#define OPTIC_REGISTER_FUNC

#ifdef OPTIC_REGISTER_FUNC

/** Read value of register

   \param reg  register address
   \return register contents
*/
#define reg_r32(reg) optic_register_read(32, reg)
#define reg_r16(reg) optic_register_read(16, reg)
#define reg_r8(reg) optic_register_read(8, reg)

/** Write value to register

   \param val  register value
   \param reg  register address
*/
#define reg_w32(val, reg) optic_register_write(32, reg, val)
#define reg_w16(val, reg) optic_register_write(16, reg, val)
#define reg_w8(val, reg) optic_register_write(8, reg, val)

#else

#if !defined(OPTIC_SIMULATION)

#define __sync_optic()                          \
        __asm__ __volatile__(                   \
                ".set   push\n\t"               \
                ".set   noreorder\n\t"          \
                ".set   mips2\n\t"              \
                "sync\n\t"                      \
                ".set   pop"                    \
                : /* no output */               \
                : /* no input */                \
                : "memory")

#define SYNC __sync_optic();

#else

#define SYNC

#endif


/** Read value of register

   \param reg  register address
   \return register contents
*/
#define reg_r32(reg) OPTIC_SyncRegRead(reg)
static INLINE uint32_t OPTIC_SyncRegRead(vuint32_t *reg) {
   vuint32_t val;
   vuint32_t *addr = (vuint32_t *)reg;
   SYNC
   val = *addr;
   return val;
}

/** Write value to register

   \param val  register value
   \param reg  register address
*/
#define reg_w32(val, reg) OPTIC_SyncRegWrite(reg, val)
static INLINE void OPTIC_SyncRegWrite(vuint32_t *reg, uint32_t val) {
   vuint32_t *addr = (vuint32_t *)reg;
   *addr = val;
   SYNC
}

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
*/
#define reg_w32_table(val, reg, idx) reg_w32(val, &((uint32_t *)&reg)[idx])

#define reg_w32_table_mask(clear, set, reg, idx) reg_w32_table((reg_r32_table(reg, idx) & ~(clear)) | (set), reg, idx)

/** return the address of table entry */
#define adr_table(reg, idx) (uint32_t)(&((uint32_t *)&reg)[idx])

#define set_val(reg, val, mask, offset) do {(reg) |= (((val) << (offset)) & (mask)); } while(0)

extern struct optic_reg_pma *pma;
extern struct optic_reg_status *status;
extern struct optic_reg_sys_gpon *sys_gpon;
extern struct optic_reg_octrlg *octrlg;
extern struct optic_reg_gtc_pma *gtc_pma;
extern struct optic_reg_fcsic *fcsic;
/*extern struct optic_reg_fcsi *fcsi;*/
extern struct optic_reg_dcdc *dcdc_apd;
extern struct optic_reg_dcdc *dcdc_core;
extern struct optic_reg_dcdc *dcdc_ddr;
extern struct optic_reg_sys1 *sys1;
extern struct optic_reg_pma_int200 *pma_int200;
extern struct optic_reg_pma_intrx *pma_intrx;
extern struct optic_reg_pma_inttx *pma_inttx;
extern struct optic_reg_gtc *gtc;

/*! @} */
/*! @} */

EXTERN_C_END

#endif /* SWIG */


#endif
