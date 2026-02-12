/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_int.h
*/
#ifndef _drv_optic_ll_int_h
#define _drv_optic_ll_int_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"
#include "drv_optic_interface.h"

#if defined(LINUX) && defined(__KERNEL__)
#include <linux/interrupt.h>
#ifdef CONFIG_SOC_FALCON
#include <falcon/falcon_irq.h>
#endif
#endif

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_IRQ_INTERNAL Interrupt Module - Internal
   @{
*/

#define OPTIC_INT200_SET   0x00000007
#define OPTIC_INT200_RESET 0x00000000

#define OPTIC_INTTX_RESET 0x00000000

#define OPTIC_INTRX_SET   0x00000001
#define OPTIC_INTRX_RESET 0x00000000

enum optic_irq_type {
	OPTIC_IRQ_TYPE_INT200,
	OPTIC_IRQ_TYPE_INTRX,
	OPTIC_IRQ_TYPE_INTTX,
	OPTIC_IRQ_TYPE_GPIO_SD
};

#ifndef FALCON_IRQ_PMA_200M
#	define FALCON_IRQ_PMA_200M 47
#endif
#ifndef FALCON_IRQ_PMA_TX
#	define FALCON_IRQ_PMA_TX 48
#endif
#ifndef FALCON_IRQ_PMA_RX
#	define FALCON_IRQ_PMA_RX 49
#endif

enum optic_errorcode optic_ll_int_reset ( struct optic_interrupts *irq );
enum optic_errorcode optic_ll_int_all_set ( const enum optic_activation mode );
enum optic_errorcode optic_ll_int_omu_handle ( const enum optic_irq_type type,
					       const optic_isr callback_isr,
					       const uint8_t signal_detect_port,
					       struct optic_interrupts *irq );
enum optic_errorcode optic_ll_int_omu_get ( const bool signal_detect_avail,
					    struct optic_interrupts *irq,
					    bool *loss_of_signal,
					    bool *loss_of_lock );
enum optic_errorcode optic_ll_int_bosa_handle ( const enum optic_irq_type type,
					        const optic_isr callback_isr,
					        const uint16_t thresh_cw_los,
					        const uint16_t thresh_cw_ovl,
					        struct optic_interrupts *irq );
enum optic_errorcode optic_ll_int_poll ( struct optic_interrupts *irq );

void optic_ll_int_counter_get (uint32_t **p_int_cnt);

void optic_enable_irq (uint32_t irq);
void optic_disable_irq (uint32_t irq);

/*! @} */

/*! @} */

EXTERN_C_END

#endif
