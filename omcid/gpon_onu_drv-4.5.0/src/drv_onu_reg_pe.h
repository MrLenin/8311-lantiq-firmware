/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_pe_h
#define _drv_onu_reg_pe_h

/** \addtogroup PE_REGISTER
   @{
*/
/* access macros */
#define pe_r32(pe_idx, reg) reg_r32(&pe->pe[pe_idx].reg)
#define pe_w32(pe_idx, val, reg) reg_w32(val, &pe->pe[pe_idx].reg)
#define pe_w32_mask(pe_idx, clear, set, reg) reg_w32_mask(clear, set, &pe->pe[pe_idx].reg)
#define pe_r32_table(pe_idx, reg, idx) reg_r32_table(pe->pe[pe_idx].reg, idx)
#define pe_w32_table(pe_idx, val, reg, idx) reg_w32_table(val, pe->pe[pe_idx].reg, idx)
#define pe_w32_table_mask(pe_idx, clear, set, reg, idx) reg_w32_table_mask(clear, set, pe->pe[pe_idx].reg, idx)
#define pe_adr_table(pe_idx, reg, idx) adr_table(pe->pe[pe_idx].reg, idx)

/** single PE register structure */
struct onu_pe
{
   /** PE Host Interface
       This register provides access to the PE host address space. */
   unsigned int host[4096]; /* 0x00000000 */
   /** PE Hardware Breakpoint Register
       This register is to set the hardware breakpoint. */
   unsigned int breakp[2048]; /* 0x00004000 */
   /** PE Configuration Register */
   unsigned int pecfg[2048]; /* 0x00006000 */
   /** PE Program Memory
       This register provides access to the PE program memory address space. */
   unsigned int prog[8192]; /* 0x00008000 */
};

/** all PE register structure */
struct onu_reg_pe
{
	struct onu_pe pe[6];
};


/* Fields of "PE Host Interface" */
/** PE Host Interface
    Address space for PE host. */
#define PE_HOST_HOSTREG_MASK 0x7FFFFFFF
/** field offset */
#define PE_HOST_HOSTREG_OFFSET 0

/* Fields of "PE Hardware Breakpoint Register" */
/** PE Hardware Breakpoint Enable
    This is to enable the breakpoint registers. */
#define PE_BREAKP_BREAK_EN 0x80000000
/** PE Hardware Breakpoint
    This value is to set the hardware breakpoint at this certain program count. */
#define PE_BREAKP_BREAKP_MASK 0x00003FF8
/** field offset */
#define PE_BREAKP_BREAKP_OFFSET 3

/* Fields of "PE Configuration Register" */
/** Write Protection
    Write the value 0x504C to this register to enable write access to the LSUCEE register.This has to be done each time you want to write LSUCEE. */
#define PE_PECFG_WPROT_MASK 0xFFFF0000
/** field offset */
#define PE_PECFG_WPROT_OFFSET 16
/** LSU Condition Execution Enable */
#define PE_PECFG_LSUCEE 0x00000001

/* Fields of "PE Program Memory" */
/** PE Program Memory
    Address space for program memory. */
#define PE_PROG_PROGREG_MASK 0x7FFFFFFF
/** field offset */
#define PE_PROG_PROGREG_OFFSET 0

/*! @} */ /* PE_REGISTER */

#endif /* _drv_onu_reg_pe_h */
