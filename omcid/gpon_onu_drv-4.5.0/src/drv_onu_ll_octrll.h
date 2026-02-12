/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_octrll_h
#define _drv_onu_octrll_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_OCTRLL LAN Output Control Low-level Functions

   Low-level functions to access the LAN output control unit (OCTRLL).
   @{
*/

/**
   Initialize the OCTRLL block (octrl).
   \param port_id   LAN port ID
*/
void octrll_init(const uint32_t port_id);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Configure LAN port queue timeout.
   \param lan_port_timeout  LAN port timeout value, given in 1-s units, single
	  value for all port's
   \param lan_port_timeout_en LAN queue timeout enable.
*/
void octrll_port_timeout_set(const uint32_t lan_port_timeout,
			     const bool lan_port_timeout_en[4]);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Read the LAN port queue timeout.
   \param lan_port_timeout  LAN port timeout value, given in 1-s units, single
	   value for all port's
   \param lan_port_timeout_en LAN queue timeout enable.
*/
void octrll_port_timeout_get(uint32_t *lan_port_timeout,
			     bool lan_port_timeout_en[4]);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Set EPN for LAN port
   \param uni_port_id  		LAN port ID
   \param eport_idx 	Egress Port Number

   \remarks Modify only when CTRL.ACT is disabled!
*/
int octrll_port_set(const uint32_t uni_port_id, const uint32_t eport_idx);

/**
   Get EPN for LAN port
   \param uni_port_id   LAN port ID
   \param eport_idx 	Get Egress Port Number
*/
int octrll_port_get(const uint32_t uni_port_id, uint32_t *eport_idx);

/**
   Write RAW configuration for LAN port
   \param uni_port_id  		LAN port ID
   \param max_len  		Maximum PDU length
   \param hlsa  		Head LSA
   \param tlsa  		Tail LSA

   \remarks Modify only when RAWCTRL.RAWTX is disabled!
*/
int octrll_write(const uint32_t uni_port_id, const uint32_t max_len,
		 const uint32_t hlsa, const uint32_t tlsa);

/**
   Read TX packets counter.
   \param uni_port_id  		LAN port ID
*/
uint32_t octrll_pcnt_get(const uint32_t uni_port_id);

/**
   Read hardware counter.
   \param uni_port_id  		LAN port ID
   \param counter  		Get counter Value
*/
int octrll_counter_get(const uint32_t uni_port_id,
		       struct octrll_counter *counter);

void octrll_state_get (const uint32_t uni_port_id,
		      uint32_t* state, uint32_t* txpcnt);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set specified interrupt mask.
   Disabled interrupts are not visible in the IRNCR register and are not
   signalled via the interrupt line towards the controller.
   \param port_id  The LAN port ID
   \param value  Set value
*/
void octrll_interrupt_mask_set(const uint32_t port_id, const uint32_t value);
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
void octrll_interrupt_set(const uint32_t port_id, const uint32_t value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get currently active interrupt events masked with the corresponding enable
   bits of the IRNEN register.
   The interrupts can be acknowledged by a write operation.
   \param port_id  The LAN port ID
   \param value  Get value
*/
void octrll_interrupt_get(const uint32_t port_id, uint32_t *value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Set LAN port enable bit.
   Use this function to enable or disable a LAN port.
   \param port_id  The LAN port ID
   \param value  Set value
*/
void octrll_enable(const uint32_t port_id, const bool value);

/**
   Get LAN port enable bit.
   Use this function to get status of a LAN port enable bit.
   \param port_id  The LAN port ID
*/
bool octrll_is_enabled(const uint32_t port_id);

#if defined(INCLUDE_DUMP)

/**
   Dump the OCTRLG register block.
*/
void octrll_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
