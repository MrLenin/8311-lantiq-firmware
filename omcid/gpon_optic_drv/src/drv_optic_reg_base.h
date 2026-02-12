/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_base_h
#define _drv_optic_reg_base_h

/** \addtogroup OPTIC_BASE
   @{
*/

#ifndef KSEG1
#define KSEG1 0xA0000000
#endif

/** address range for gtc
    0x1DC05000--0x1DC052D4 */
#define OPTIC_GTC_BASE			(KSEG1 | 0x1DC00000)
#define OPTIC_GTC_END			(KSEG1 | 0x1DC002D4)
#define OPTIC_GTC_SIZE			0x000002D5
/** address range for octrlg
    0x1D420000--0x1D42FFFF */
#define OPTIC_OCTRLG_BASE		(KSEG1 | 0x1D420000)
#define OPTIC_OCTRLG_END		(KSEG1 | 0x1D42FFFF)
#define OPTIC_OCTRLG_SIZE		0x00010000
/** address range for pma
    0x1DD00000--0x1DD003FF */
#define OPTIC_PMA_BASE			(KSEG1 | 0x1DD00000)
#define OPTIC_PMA_END			(KSEG1 | 0x1DD003FF)
#define OPTIC_PMA_SIZE			0x00000400
/** address range for fcsic
    0x1DD00600--0x1DD0061F */
#define OPTIC_FCSIC_BASE		(KSEG1 | 0x1DD00600)
#define OPTIC_FCSIC_END			(KSEG1 | 0x1DD0061F)
#define OPTIC_FCSIC_SIZE		0x00000020
/** address range for pma_int200
    0x1DD00700--0x1DD0070F */
#define OPTIC_PMA_INT200_BASE		(KSEG1 | 0x1DD00700)
#define OPTIC_PMA_INT200_END		(KSEG1 | 0x1DD0070F)
#define OPTIC_PMA_INT200_SIZE		0x00000010
/** address range for pma_inttx
    0x1DD00720--0x1DD0072F */
#define OPTIC_PMA_INTTX_BASE		(KSEG1 | 0x1DD00720)
#define OPTIC_PMA_INTTX_END		(KSEG1 | 0x1DD0072F)
#define OPTIC_PMA_INTTX_SIZE		0x00000010
/** address range for pma_intrx
    0x1DD00740--0x1DD0074F */
#define OPTIC_PMA_INTRX_BASE		(KSEG1 | 0x1DD00740)
#define OPTIC_PMA_INTRX_END		(KSEG1 | 0x1DD0074F)
#define OPTIC_PMA_INTRX_SIZE		0x00000010
/** address range for gtc_pma
    0x1DEFFF00--0x1DEFFFFF */
#define OPTIC_GTC_PMA_BASE		(KSEG1 | 0x1DEFFF00)
#define OPTIC_GTC_PMA_END		(KSEG1 | 0x1DEFFFFF)
#define OPTIC_GTC_PMA_SIZE		0x00000100
/** address range for sys_gpon
    0x1DF00000--0x1DF000FF */
#define OPTIC_SYS_GPON_BASE		(KSEG1 | 0x1DF00000)
#define OPTIC_SYS_GPON_END		(KSEG1 | 0x1DF000FF)
#define OPTIC_SYS_GPON_SIZE		0x00000100
/** address range for status
    0x1E802000--0x1E80207F */
#define OPTIC_STATUS_BASE		(KSEG1 | 0x1E802000)
#define OPTIC_STATUS_END		(KSEG1 | 0x1E80207F)
#define OPTIC_STATUS_SIZE		0x00000080
/** address range for dcdc_core
    0x1E803000--0x1E8033FF */
#define OPTIC_DCDC_CORE_BASE		(KSEG1 | 0x1E803000)
#define OPTIC_DCDC_CORE_END		(KSEG1 | 0x1E8033FF)
#define OPTIC_DCDC_CORE_SIZE		0x00000400
/** address range for dcdc_ddr
    0x1E804000--0x1E8043FF */
#define OPTIC_DCDC_DDR_BASE		(KSEG1 | 0x1E804000)
#define OPTIC_DCDC_DDR_END		(KSEG1 | 0x1E8043FF)
#define OPTIC_DCDC_DDR_SIZE		0x00000400
/** address range for dcdc_apd
    0x1E805000--0x1E8053FF */
#define OPTIC_DCDC_APD_BASE		(KSEG1 | 0x1E805000)
#define OPTIC_DCDC_APD_END		(KSEG1 | 0x1E8053FF)
#define OPTIC_DCDC_APD_SIZE		0x00000400
/** address range for sys1
    0x1EF00000--0x1EF000FF */
#define OPTIC_SYS1_BASE			(KSEG1 | 0x1EF00000)
#define OPTIC_SYS1_END			(KSEG1 | 0x1EF000FF)
#define OPTIC_SYS1_SIZE			0x00000100

/*! @} */ /* OPTIC_BASE */

#endif /* _drv_optic_reg_base_h */

