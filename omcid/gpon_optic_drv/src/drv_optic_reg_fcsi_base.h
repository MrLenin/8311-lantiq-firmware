/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_base_h
#define _drv_optic_reg_fcsi_base_h

/** \addtogroup FCSI_BASE
   @{
*/
/** address range for txbosa
    0x00--0x07 */
#define FCSI_TXBOSA_BASE		0x00
#define FCSI_TXBOSA_END		0x07
#define FCSI_TXBOSA_SIZE		0x08
/** address range for txomu
    0x08--0x0A */
#define FCSI_TXOMU_BASE		0x08
#define FCSI_TXOMU_END		0x0A
#define FCSI_TXOMU_SIZE		0x03
/** address range for rxbosa
    0x0B--0x0B */
#define FCSI_RXBOSA_BASE		0x0B
#define FCSI_RXBOSA_END		0x0B
#define FCSI_RXBOSA_SIZE		0x01
/** address range for rxomu
    0x0D--0x0D */
#define FCSI_RXOMU_BASE		0x0D
#define FCSI_RXOMU_END		0x0D
#define FCSI_RXOMU_SIZE		0x01
/** address range for mm
    0x0E--0x0E */
#define FCSI_MM_BASE		0x0E
#define FCSI_MM_END		0x0E
#define FCSI_MM_SIZE		0x01
/** address range for vdac
    0x0F--0x0F */
#define FCSI_VDAC_BASE		0x0F
#define FCSI_VDAC_END		0x0F
#define FCSI_VDAC_SIZE		0x01
/** address range for bfd
    0x10--0x12 */
#define FCSI_BFD_BASE		0x10
#define FCSI_BFD_END		0x12
#define FCSI_BFD_SIZE		0x03
/** address range for pi
    0x13--0x13 */
#define FCSI_PI_BASE		0x13
#define FCSI_PI_END		0x13
#define FCSI_PI_SIZE		0x01
/** address range for cbias
    0x14--0x15 */
#define FCSI_CBIAS_BASE		0x14
#define FCSI_CBIAS_END		0x15
#define FCSI_CBIAS_SIZE		0x02
/** address range for vdll
    0x18--0x18 */
#define FCSI_VDLL_BASE		0x18
#define FCSI_VDLL_END		0x18
#define FCSI_VDLL_SIZE		0x01

/*! @} */ /* FCSI_BASE */

#endif /* _drv_optic_reg_fcsi_base_h */

