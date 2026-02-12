/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, PMA INT Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_INT_INTERNAL Interrupt Module - Internal
   @{
*/
#include "drv_optic_api.h"
#include "drv_optic_register.h"
#include "drv_optic_ll_int.h"
#include "drv_optic_ll_gpio.h"
#include "drv_optic_ll_mm.h"
#include "drv_optic_ll_rx.h"
#include "drv_optic_ll_pll.h"

#include "drv_optic_reg_pma_int200.h"
#include "drv_optic_reg_pma_inttx.h"
#include "drv_optic_reg_pma_intrx.h"
#include "drv_optic_reg_pma.h"

#if defined(LINUX) && !defined(OPTIC_SIMULATION)
DEFINE_SPINLOCK(irq_lock);
#endif

static uint32_t int_cnt[4];

enum optic_errorcode optic_ll_int_reset ( struct optic_interrupts *irq )
{
	irq->signal_overload = false;
	irq->signal_valid = false;
	irq->signal_lost = false;

	irq->rx_lock_lost = false;

	irq->tx_overcurrent = false;
	irq->tx_p0_interburst_alarm = false;
	irq->tx_p0_intraburst_alarm = false;
	/*
	irq->tx_p1_interburst_alarm = false;
	irq->tx_p1_intraburst_alarm = false;
	*/
	irq->tx_bias_limit = false;
	irq->tx_mod_limit = false;

	irq->temp_alarm_yellow = false;
	irq->temp_alarm_red = false;

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_int_all_set ( const enum optic_activation mode )
{
	static enum optic_activation mode_old = OPTIC_DISABLE;
#if defined(LINUX) && !defined(OPTIC_SIMULATION)
	unsigned long flags;
#endif
	if (mode == mode_old)
		return OPTIC_STATUS_OK;
#if defined(LINUX) && !defined(OPTIC_SIMULATION)
	spin_lock_irqsave(&irq_lock, flags);
#endif

	mode_old = mode;

	switch (mode) {
	case OPTIC_ENABLE:
		/* GPONSW-588, never enable HW interrupt for 200MHz */
		pma_int200_w32 ( OPTIC_INT200_RESET , irnen);
		pma_intrx_w32 ( OPTIC_INTRX_SET , irnen);
		/* rogue interrupts are separately set */
		pma_inttx_w32 (PMA_INTTX_IRNCR_MODL | PMA_INTTX_IRNCR_BIASL |
			PMA_INTTX_IRNICR_OV, irnen);
		break;
	case OPTIC_DISABLE:
		pma_int200_w32 ( OPTIC_INT200_RESET , irnen);
		pma_intrx_w32 ( OPTIC_INTRX_RESET , irnen);
		pma_inttx_w32 ( OPTIC_INTTX_RESET , irnen);
		break;
	default:
#if defined(LINUX) && !defined(OPTIC_SIMULATION)
		spin_unlock_irqrestore(&irq_lock, flags);
#endif
		return OPTIC_STATUS_POOR;
	}

#if defined(LINUX) && !defined(OPTIC_SIMULATION)
	spin_unlock_irqrestore(&irq_lock, flags);
#endif
	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_int_omu_handle ( const enum optic_irq_type type,
					       const optic_isr callback_isr,
					       const uint8_t signal_detect_port,
					       struct optic_interrupts *irq )
{
	enum optic_errorcode ret;
	bool sd;

	switch (type) {
	case OPTIC_IRQ_TYPE_GPIO_SD:
		ret = optic_ll_gpio_signaldetect_get ( signal_detect_port,
							     &sd );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if (sd == true) {
			irq->signal_valid = true;
			irq->signal_lost = false;

			optic_ll_rx_cdr_bpd ( OPTIC_ENABLE );
			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_SD );
			else
				OPTIC_DEBUG_WRN("IRQ gpio: Signal Detect");
		} else {
			irq->signal_valid = false;
			irq->signal_lost = true;
			irq->rx_lock_lost = true;

			optic_ll_rx_cdr_bpd ( OPTIC_DISABLE );
			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_LOS );
			else
				OPTIC_DEBUG_WRN("IRQ gpio: Loss Of Signal");
		}

		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_int_omu_get ( const bool signal_detect_avail,
					    struct optic_interrupts *irq,
					    bool *loss_of_signal,
					    bool *loss_of_lock )
{
	enum optic_errorcode ret;

	if ((loss_of_signal == NULL) || (loss_of_lock == NULL))
		return OPTIC_STATUS_ERR;

	if (signal_detect_avail == false) {
		*loss_of_signal = true;
		*loss_of_lock = true;
		return OPTIC_STATUS_OK;
	}

	*loss_of_signal = irq->signal_lost;

	/* get LOL status */
	if (irq->signal_valid == true) {
		ret = optic_ll_rx_lol_get ( &(irq->rx_lock_lost) );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		*loss_of_lock = irq->rx_lock_lost;
	} else {
		*loss_of_lock = true;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_int_bosa_handle ( const enum optic_irq_type type,
					        const optic_isr callback_isr,
					        const uint16_t thresh_cw_los,
					        const uint16_t thresh_cw_ovl,
					        struct optic_interrupts *irq )
{
#if (OPTIC_BOSA_LOS_DISABLE_RX == ACTIVE)||(OPTIC_BOSA_IRQ_THRESHOLD_CHECK == ACTIVE)
	enum optic_errorcode ret;
#endif
	uint32_t reg, mask;
	bool correctness;

	switch (type) {
	case OPTIC_IRQ_TYPE_INT200:
		reg = pma_int200_r32 ( irncr );

		if (reg & PMA_INT200_IRNCR_OVL) {
#if (OPTIC_BOSA_IRQ_THRESHOLD_CHECK == ACTIVE)
			ret = optic_ll_mm_check_thresh ( OPTIC_IRQ_OVL,
							       thresh_cw_los,
							       thresh_cw_ovl,
							       &correctness );
			if (ret != OPTIC_STATUS_OK)
				correctness = false;
#else
			correctness = true;
			/* avoid compiler warnings */
			(void)thresh_cw_los;
			(void)thresh_cw_ovl;
#endif
			pma_int200_w32_mask ( PMA_INT200_IRNCR_OVL, 0, irnen);
			    	return OPTIC_STATUS_ERR;

			if (correctness == false)
			    	return OPTIC_STATUS_ERR;

			irq->signal_overload = true;
			irq->signal_valid = false;


			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_OVL );
			else
				OPTIC_DEBUG_WRN("IRQ INT200: OverLoad");

		}
		if (reg & PMA_INT200_IRNCR_SIGDET) {
#if (OPTIC_BOSA_IRQ_THRESHOLD_CHECK == ACTIVE)
			ret = optic_ll_mm_check_thresh ( OPTIC_IRQ_SD,
							       thresh_cw_los,
							       thresh_cw_ovl,
							       &correctness );
			if (ret != OPTIC_STATUS_OK)
				correctness = false;
#else
			correctness = true;
#endif

			pma_int200_w32_mask ( PMA_INT200_IRNCR_SIGDET, 0,
					      irnen);

			if (correctness == false)
			    	return OPTIC_STATUS_ERR;


			irq->signal_valid = true;
			irq->signal_overload = false;
			irq->signal_lost = false;

#if (OPTIC_BOSA_LOS_DISABLE_RX == ACTIVE)
			ret = optic_ll_rx_afectrl_set ( OPTIC_ENABLE,
							      false );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("optic_ll_rx_afectrl_set: %d",
						ret);
				return ret;
			}
#endif

			int_cnt[3]++;
			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_SD );
			else
				OPTIC_DEBUG_MSG("IRQ INT200: Signal Detect");
		}
		if (reg & PMA_INT200_IRNCR_LOS) {
#if (OPTIC_BOSA_IRQ_THRESHOLD_CHECK == ACTIVE)
			ret = optic_ll_mm_check_thresh ( OPTIC_IRQ_LOS,
							       thresh_cw_los,
							       thresh_cw_ovl,
							       &correctness );
			if (ret != OPTIC_STATUS_OK)
				correctness = false;
#else
			correctness = true;
#endif

			pma_int200_w32_mask ( PMA_INT200_IRNCR_LOS, 0, irnen);

			if (correctness == false)
			    	return OPTIC_STATUS_ERR;

			irq->signal_lost = true;
			irq->signal_overload = false;
			irq->signal_valid = false;

#if (OPTIC_BOSA_LOS_DISABLE_RX == ACTIVE)
			ret = optic_ll_rx_afectrl_set ( OPTIC_DISABLE,
							      false );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("optic_ll_rx_afectrl_set: %d",
						ret);
				return ret;
			}
#endif

			int_cnt[2]++;
			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_LOS );
			else
				OPTIC_DEBUG_MSG("IRQ INT200: Loss of Signal");
		}
		/* quit */
		pma_int200_w32 ( reg, irncr );
		break;
	case OPTIC_IRQ_TYPE_INTRX:
		reg = pma_intrx_r32 ( irncr );
		if (reg & PMA_INTRX_IRNCR_LOL) {
			pma_intrx_w32_mask ( PMA_INTRX_IRNCR_LOL, 0, irnen);

			irq->rx_lock_lost = true;

			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_LOL );
			else
				OPTIC_DEBUG_WRN("IRQ INTRX: Loss Of Lock");
		}
		pma_intrx_w32 ( reg, irncr );
		break;
	case OPTIC_IRQ_TYPE_INTTX:
		reg = pma_inttx_r32 ( irncr );
		mask = 0;
		if (reg & PMA_INTTX_IRNCR_OV) {
			mask |= PMA_INTTX_IRNCR_OV;

			irq->tx_overcurrent = true;

			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_OV );
			else
				OPTIC_DEBUG_WRN("IRQ INTTX: Overcurrent");
		}
#if 0
		/* disabled for further investigation */
		if (reg & PMA_INTTX_IRNCR_BP1IBA) {
			mask |= PMA_INTTX_IRNCR_BP1IBA;

			irq->tx_p1_interburst_alarm = true;

			if (callback_isr != NULL)
				callback_isr (OPTIC_IRQ_BP1IBA);
			else
				OPTIC_DEBUG_WRN("IRQ INTTX: P1 Interburst Alarm");
		}
		if (reg & PMA_INTTX_IRNCR_BP1BA) {
			mask |= PMA_INTTX_IRNCR_BP1BA;

			irq->tx_p1_intraburst_alarm = true;

			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_BP1BA );
			else
				OPTIC_DEBUG_WRN("IRQ INTTX: P1 Intraburst Alarm");
		}
#endif
		if (reg & PMA_INTTX_IRNCR_BP0IBA) {
			mask |= PMA_INTTX_IRNCR_BP0IBA;
			irq->tx_p0_interburst_alarm = true;

			int_cnt[1]++;
			optic_ll_pll_rogue();
			if (callback_isr != NULL)
				callback_isr (OPTIC_IRQ_BP0IBA);
			else
				OPTIC_DEBUG_ERR("P0 Interburst Alarm -> "
						"TX Disabled (Dualloop switched off) ");
		}
		if (reg & PMA_INTTX_IRNCR_BP0BA) {
			mask |= PMA_INTTX_IRNCR_BP0BA;
			irq->tx_p0_intraburst_alarm = true;
			int_cnt[0]++;

			optic_ll_pll_module_set (OPTIC_PLL_TX, false);
			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_BP0BA );
			else
				OPTIC_DEBUG_ERR("OPTIC P0 Intraburst Alarm -> "
						"TX Disabled");
		}
		if (reg & PMA_INTTX_IRNCR_BIASL) {
			mask |= PMA_INTTX_IRNCR_BIASL;

			irq->tx_bias_limit = true;

			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_BIASL );
			else
				OPTIC_DEBUG_WRN("IRQ INTTX: Bias Limit");
		}
		if (reg & PMA_INTTX_IRNCR_MODL) {
			mask |= PMA_INTTX_IRNCR_MODL;

			irq->tx_mod_limit = true;

			if (callback_isr != NULL)
				callback_isr ( OPTIC_IRQ_MODL );
			else
				OPTIC_DEBUG_WRN("IRQ INTTX: Modulation Limit");
		}

		pma_inttx_w32_mask (mask, 0, irnen);
		pma_inttx_w32 ( reg, irncr );
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_int_poll ( struct optic_interrupts *irq )
{
/*
	uint32_t reg;
*/
	/** poll int200 irqs */

	/* int 200 interrupts enable each other - no polling necessary */
/*
	reg = pma_int200_r32 ( irnicr );
*/
#if 1
	if (irq->signal_overload == false) {
		pma_int200_w32_mask ( 0, PMA_INT200_IRNCR_OVL, irnen);
	}
	if (irq->signal_valid == false) {
	    	pma_int200_w32_mask ( 0, PMA_INT200_IRNCR_SIGDET, irnen);
	}
	if (irq->signal_lost == false) {
	    	pma_int200_w32_mask ( 0, PMA_INT200_IRNCR_LOS, irnen);
	}
#else
	/* edge triggered */
	if ((irq->signal_overload == true) &&
	    !(reg & PMA_INT200_IRNCR_OVL)) {
	    	irq->signal_overload = false;
		pma_int200_w32_mask ( 0, PMA_INT200_IRNCR_OVL, irnen);
	}
	if ((irq->signal_valid == true) &&
	    !(reg & PMA_INT200_IRNCR_SIGDET)) {
	    	irq->signal_valid = false;
		pma_int200_w32_mask ( 0, PMA_INT200_IRNCR_SIGDET, irnen);
	}
	if ((irq->signal_lost == true) &&
	    !(reg & PMA_INT200_IRNCR_LOS)) {
	    	irq->signal_lost = false;
		pma_int200_w32_mask ( 0, PMA_INT200_IRNCR_LOS, irnen);
	}
#endif

	/** poll rx irqs */
/*
	reg = pma_intrx_r32 ( irnicr );
*/
	if (irq->rx_lock_lost == false) {
		pma_intrx_w32_mask ( 0, PMA_INTRX_IRNCR_LOL, irnen);
	}

	/** poll tx irqs */
/*
	reg = pma_inttx_r32 ( irnicr );
*/

	if (irq->tx_overcurrent == false) {
		pma_inttx_w32_mask ( 0, PMA_INTTX_IRNCR_OV, irnen);
	}
#if 0
	if (irq->tx_p1_interburst_alarm == false) {
		pma_inttx_w32_mask ( 0, PMA_INTTX_IRNCR_BP1IBA, irnen);
	}
	if (irq->tx_p1_intraburst_alarm == false) {
		pma_inttx_w32_mask ( 0, PMA_INTTX_IRNCR_BP1BA, irnen);
	}
	if (irq->tx_p0_interburst_alarm == false) {
		pma_inttx_w32_mask ( 0, PMA_INTTX_IRNCR_BP0IBA, irnen);
	}
	if (irq->tx_p0_intraburst_alarm == false) {
		pma_inttx_w32_mask ( 0, PMA_INTTX_IRNCR_BP0BA, irnen);
	}
#endif
	if (irq->tx_bias_limit == false) {
		pma_inttx_w32_mask ( 0, PMA_INTTX_IRNCR_BIASL, irnen);
	}
	if (irq->tx_mod_limit == false) {
		pma_inttx_w32_mask ( 0, PMA_INTTX_IRNCR_MODL, irnen);
	}
	return OPTIC_STATUS_OK;
}


void optic_ll_int_counter_get (uint32_t **p_int_cnt)
{
	*p_int_cnt = int_cnt;
}


/*! @} */
/*! @} */
