/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_ictrll_h
#define _drv_onu_ictrll_h

#include "drv_onu_types.h"

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_ICTRLL LAN Input Control Low-level Functions

   Low-level functions to access the LAN input control unit (ICTRLL).
   @{
*/

/**
   Initialize the ICTRLL block (ictrll).
   \param port_id   LAN port ID
*/
void ictrll_init(const uint16_t port_id);

/**
   Read RX packets counter.
   \param uni_port_id  The LAN port ID
*/
uint32_t ictrll_pcnt_get(const uint8_t uni_port_id);

/**
   Read Packet Discard Counter.
   \param uni_port_id  The LAN port ID
   \return Packet Discard Counter value
*/
uint32_t ictrll_pdc_get(const uint8_t uni_port_id);

/**
   Read hardware counter.
   \param uni_port_id  The LAN port ID
   \param counter  Get value of LAN port counter
*/
int ictrll_counter_get(const uint8_t uni_port_id,
		       struct ictrll_counter *counter);

int ictrll_macerr_get(const uint8_t uni_port_id,
		       uint32_t *mac_error);

/**
   Set LAN port enable bit.
   Use this function to enable or disable a LAN port.
   \param port_id  The LAN port ID
   \param value  Set value
*/
void ictrll_enable(const uint16_t port_id, const bool value);

/**
   Get LAN port enable bit.
   Use this function to get status of a LAN port enable bit.
   \param port_id  The LAN port ID
*/
bool ictrll_is_enabled(const uint16_t port_id);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set LAN port debug mode bit.
   If this bit is set, ICTRL will always write out data to IQM, regardless
   if IQM FIFO is ready or not.
   \param port_id  The LAN port ID
   \param value  Set value
*/
void ictrll_debug_mode_set(const uint16_t port_id, const bool value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get LAN port debug mode bit.
   \param port_id  The LAN port ID
   \param value  Get value
*/
void ictrll_debug_mode_get(const uint16_t port_id, bool *value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set LAN port broadcast filter for RAW mode bit.
   If this bit is set, all packets with destination address 0xFFFF_FFFF_FFFF
   are accepted.
   \param port_id  The LAN port ID
   \param value  Set value
*/
void ictrll_bc_mode_set(const uint16_t port_id, const bool value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get LAN port broadcast filter for RAW mode bit.
   \param port_id  The LAN port ID
   \param value  Get value
*/
void ictrll_bc_mode_get(const uint16_t port_id, bool *value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Set maximum allowed PDU size for PDU type 0 (Ethernet mode).
   \param port_id  The LAN port ID
   \param value  Set value
*/
void ictrll_max_size_pdu_type0_set(const uint16_t port_id,
				   const uint16_t value);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get maximum allowed PDU size for PDU type 0 (Ethernet mode).
   \param port_id  The LAN port ID
   \param value  Get value
*/
void ictrll_max_size_pdu_type0_get(const uint16_t port_id, uint16_t *value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set specified interrupt mask.
   Disabled interrupts are not visible in the IRNCR register and are not
   signalled via the interrupt line towards the controller.
   \param port_id  The LAN port ID
   \param value  Set value
*/
void ictrll_interrupt_mask_set(const uint16_t port_id, const uint32_t value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set an specified interrupt.
   A write operation directly effects the interrupts.
   This can be used to trigger events under software control for testing
   purposes.
   \param port_id  The LAN port ID
   \param value  Set value
*/
void ictrll_interrupt_set(const uint16_t port_id, const uint32_t value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get currently active interrupt events masked with the corresponding enable
   bits of the IRNEN register.
   The interrupts can be acknowledged by a write operation.
   \param port_id  The LAN port ID
   \param value  Get value
*/
void ictrll_interrupt_get(const uint16_t port_id, uint32_t *value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#if defined(INCLUDE_DUMP)

/**
   Dump the ICTRLL register block.
*/
void ictrll_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
