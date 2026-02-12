/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_vdac_h
#define _drv_optic_reg_fcsi_vdac_h

/** \addtogroup VDAC_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define vdac_r16(reg) reg_r16(&vdac->reg)
#define vdac_w16(val, reg) reg_w16(val, &vdac->reg)
#define vdac_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &vdac->reg)
#define vdac_r16_table(reg, idx) reg_r16_table(vdac->reg, idx)
#define vdac_w16_table(val, reg, idx) reg_w16_table(val, vdac->reg, idx)
#define vdac_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, vdac->reg, idx)
#define vdac_adr_table(reg, idx) adr_table(vdac->reg, idx)


/** VDAC register structure */
struct fcsi_reg_vdac
{
   /** Measurement Module Control Register; #15
       DAC output as function of VWD and LREN: */
   unsigned short ctrl; /* 0x00 */
};

#define FCSI_VDAC_CTRL   ((volatile unsigned short*)(FCSI_VDAC_BASE + 0x00))

#else /* __ASSEMBLY__ */

#define FCSI_VDAC_CTRL   (FCSI_VDAC_BASE + 0x00)

#endif /* __ASSEMBLY__ */

/* Fields of "Measurement Module Control Register; #15" */
/** Operating mode (video_pd)
    Video DAC operating mode */
#define VDAC_CTRL_OM 0x0400
/** Powerup. */
#define VDAC_CTRL_OM_PU 0x0000
/** Powerdown. */
#define VDAC_CTRL_OM_PD 0x0400
/** Low Range Enable (video_range_low)
    program the output range of the video dac. */
#define VDAC_CTRL_LREN 0x0200
/** Disable */
#define VDAC_CTRL_LREN_DIS 0x0000
/** Enable */
#define VDAC_CTRL_LREN_EN 0x0200
/** Video Word (video_word)
    Digital programming word for R2R dac. */
#define VDAC_CTRL_VWD_MASK 0x01FF
/** field offset */
#define VDAC_CTRL_VWD_OFFSET 0

/*! @} */ /* VDAC_REGISTER */

#endif /* _drv_optic_reg_fcsi_vdac_h */
