/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, GPIO Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_GPIO_INTERNAL GPIO Module - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_register.h"
#include "drv_optic_ll_gpio.h"

#if defined(LINUX)
#ifdef __KERNEL__
#include <linux/gpio.h>
#endif
#endif
#ifdef OPTIC_LIBRARY
#include <gpio.h>
#endif

#ifdef OPTIC_SIMULATION
#undef OPTIC_GPIO
#define OPTIC_GPIO INACTIVE
#endif

extern struct optic_irq_table * optic_irq_tbl;

static enum optic_errorcode optic_ll_gpio_check ( uint16_t port )
{
	uint8_t pin= port % 100;

	switch (port / 100) {
	case 0:
		if (pin > 14)
			return OPTIC_STATUS_POOR;
		break;
	case 1:
		if (pin > 13)
			return OPTIC_STATUS_POOR;
		break;
	case 2:
		if (pin > 24)
			return OPTIC_STATUS_POOR;
		break;
	case 3:
		if ((pin > 8) && ((pin < 23) || (pin > 25)))
			return OPTIC_STATUS_POOR;
		break;
	case 4:
		if ((pin > 6) && ((pin < 22) || (pin > 24)))
			return OPTIC_STATUS_POOR;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

/**
   Initialisate GPIO pins.

   \return
   - OPTIC_STATUS_OK - no errors,
   - OPTIC_STATUS_ERR - error occurs
*/
enum optic_errorcode optic_ll_gpio_init ( const uint8_t signal_detect_port,
					  uint8_t *signal_detect_irq )
{
	enum optic_errorcode ret;

	OPTIC_DEBUG_ERR("gpio_to_irq: %d", signal_detect_port);
	if (signal_detect_irq == NULL)
		return OPTIC_STATUS_ERR;

	ret = optic_ll_gpio_check ( signal_detect_port );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	/* configure dir register */
#if (OPTIC_GPIO == ACTIVE)
	if (gpio_request (signal_detect_port,"OPTIC SignalDetectAlarm") < 0) {
		OPTIC_DEBUG_ERR("gpio_request (%d) failed", signal_detect_port);
		return OPTIC_STATUS_INIT_FAIL;
	}

#ifndef OPTIC_LIBRARY
	*signal_detect_irq = gpio_to_irq ( signal_detect_port );
	if (*signal_detect_irq <= 0) {
		OPTIC_DEBUG_ERR("gpio_to_irq (%d): %d",
		                signal_detect_port, *signal_detect_irq);
		return OPTIC_STATUS_INIT_FAIL;
	}
#endif
#endif

	return ret;
}

enum optic_errorcode optic_ll_gpio_exit ( const uint8_t signal_detect_port )
{
#if (OPTIC_GPIO == ACTIVE)
	gpio_free ( signal_detect_port );
#else
	(void)signal_detect_port;
#endif

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_gpio_signaldetect_get ( const uint8_t
						      signal_detect_port,
                                                      bool *sd )
{
	enum optic_errorcode ret;

	if (sd == NULL)
		return OPTIC_STATUS_ERR;

	ret = optic_ll_gpio_check ( signal_detect_port );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* read GPIO port */
#if (OPTIC_GPIO == ACTIVE)
	if (gpio_get_value ( signal_detect_port ))
		*sd = true;
	else
		*sd = false;
#else
	*sd = false;
#endif

	return OPTIC_STATUS_OK;
}


/*! @} */
/*! @} */
