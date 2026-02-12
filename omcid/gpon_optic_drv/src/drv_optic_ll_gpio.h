/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_gpio.h
*/
#ifndef _drv_optic_ll_gpio_h
#define _drv_optic_ll_gpio_h

#include "drv_optic_api.h"
#include "drv_optic_common.h"

EXTERN_C_BEGIN

#define OPTIC_P0_BASE		(KSEG1 | 0x1D810000)
#define OPTIC_P0_END		(KSEG1 | 0x1D810080)
#define OPTIC_P1_BASE		(KSEG1 | 0x1E800100)
#define OPTIC_P1_END		(KSEG1 | 0x1E800180)
#define OPTIC_P2_BASE		(KSEG1 | 0x1D810100)
#define OPTIC_P2_END		(KSEG1 | 0x1D810180)
#define OPTIC_P3_BASE		(KSEG1 | 0x1E800200)
#define OPTIC_P3_END		(KSEG1 | 0x1E800280)
#define OPTIC_P4_BASE		(KSEG1 | 0x1E800300)
#define OPTIC_P4_END		(KSEG1 | 0x1E800380)

#define EXINTCR1		0x1C

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_GPIO_INTERNAL GPIO Module - Internal
   @{
*/


enum optic_errorcode optic_ll_gpio_init ( const uint8_t signal_detect_port,
					  uint8_t *signal_detect_irq );
enum optic_errorcode optic_ll_gpio_exit ( const uint8_t signal_detect_port );
enum optic_errorcode optic_ll_gpio_signaldetect_get ( const uint8_t
						      signal_detect_port,
						      bool *sd );



/*! @} */

/*! @} */

EXTERN_C_END

#endif
