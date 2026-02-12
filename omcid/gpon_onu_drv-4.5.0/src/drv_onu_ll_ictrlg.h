/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_ictrlg_h
#define _drv_onu_ictrlg_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_ICTRLG GPON Input Control Low-level Functions

   Low-level functions to access the GPON input control unit (ICTRLG).
   @{
*/

#define GPT_LEN  4096

/**
   Initialize the ICTRLG block (ictrlg).
*/
void ictrlg_init(void);

/** Retrieve a free GPIX entry */
uint16_t ictrlg_gpix_free_get(void);

/**
   Set Maximum PDU size in downstream direction.
   \param pdu_sz_max Maximum PDU size in downstream direction
*/
void ictrlg_pdu_size_set(const uint32_t pdu_sz_max[8]);

/**
   Get Maximum PDU size in downstream direction.
   \param pdu_sz_max Maximum PDU size in downstream direction
*/
void ictrlg_pdu_size_get(uint32_t pdu_sz_max[8]);

/**
	Set configuration for the GPIX table.
	\param gem_port_index GEM port index (0-255)
	\param iqn Ingress queue number (5-7)
	\param pdu_type PDU type, base Protocol for each GEM port
 */
int ictrlg_gpix_config_set(const uint32_t gem_port_index, const uint32_t iqn,
			   const enum gpe_pdu_type pdu_type);

/**
	Retrieve the GEM port index (0-255) using the GEM port ID (0-4095).
	\param gem_port_id GEM port ID (0-4095)
	\param gem_port_index	point to GPIX number

	\return
	- -1 on error
	- 0 on success
 */
int ictrlg_gpix_get(const uint32_t gem_port_id, uint16_t *gem_port_index);

/**
	Get GEM port table entry.
	\param gem_port_id	GEM port ID (0-4095)
	\param gem_port_enable	Get value of port enable bit
	\param gem_port_is_omci	Get value of PDU type information
	\param gem_port_is_mc	Get value of Ingress Queue number
				(IQN: 5= Unicast, 6=Multicast, 7=OMCI)
	\param gem_port_index	Returned GPIX
	\param data_direction	Get value of data direction
 */
int ictrlg_gem_port_get(const uint32_t gem_port_id, uint32_t *gem_port_enable,
		        uint32_t *gem_port_is_omci, uint32_t *gem_port_is_mc,
		        uint32_t *gem_port_index,
		        enum gpe_direction * data_direction);

/**
	Set GEM port table entry.
	\param gem_port_id	GEM port ID (0-4095)
	\param gem_port_is_omci	PDU type information
	\param gem_port_is_mc	Ingress Queue number information
				(IQN: 5= Unicast, 6=Multicast, 7=OMCI)
	\param gem_port_index	GEM port index (0-255)
	\param data_direction	Data direction of GEM port
 */
int ictrlg_gem_port_set(const uint32_t gem_port_id,
			const uint32_t gem_port_is_omci,
			const uint32_t gem_port_is_mc,
			const uint32_t gem_port_index,
			const enum gpe_direction data_direction);

/**
	Remove a new GEM port table entry.
	\param gem_port_id		GEM port ID (0-4095)
 */
int ictrlg_gem_port_delete(const uint32_t gem_port_id);

/**
   Read GEM port related hardware counter.
   \param gpix		GEM port index
   \param counter	Get value of GEM port counter
*/
int ictrlg_gem_counter_get(const uint32_t gpix,
			   struct gpe_cnt_ictrlg_gem_val *counter);

/**
   Read global GEM hardware counter.
   \param counter			Get value of GEM global counter
*/
int ictrlg_counter_get(struct gpe_cnt_ictrlg_val *counter);

/**
   Set ICTRLG enable bit.
   Use this function to enable or disable the ICTRLG.
   \param act  Set value
*/
void ictrlg_enable(const uint32_t act);

/**
   Get ICTRLG enable bit.
   Use this function to get status of the ICTRLG enable bit.
*/
uint32_t ictrlg_is_enabled(void);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set ICTRLG debug mode bit.
   If this bit is set, ICTRL will always write out data to IQM, regardless if
   IQM FIFO is ready or not.
   \param act  Set value
*/
void ictrlg_debug_mode_set(const uint32_t act);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get ICTRLG debug mode bit.
   \param act Get value
*/
void ictrlg_debug_mode_get(uint32_t *act);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set GEM port CRC check enable bit.
   If set, this bit enables the CRC checking for OMCI and Ethernet frames.
   \param act Set value
*/
void ictrlg_crc_check_set(const uint32_t act);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get GEM port CRC check enable bit.
   \param act Get value
*/
void ictrlg_crc_check_get(uint32_t *act);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set specified interrupt mask.
   Disabled interrupts are not visible in the IRNCR register and are not
   signalled via the interrupt line towards the controller.
   \param mask Set value
*/
void ictrlg_interrupt_mask_set(const uint32_t mask);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set an specified interrupt.
   A write operation directly effects the interrupts.
   This can be used to trigger events under software control for testing
   purposes.
   \param val Set value
*/
void ictrlg_interrupt_set(const uint32_t val);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get currently active interrupt events masked with the corresponding enable
   bits of the IRNEN register.
   The interrupts can be acknowledged by a write operation.
   \param val Get value
*/
void ictrlg_interrupt_get(uint32_t *val);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#if defined(INCLUDE_DUMP)

/**
   Dump the ICTRLL register block.
*/
void ictrlg_dump(struct seq_file *s);

/**
   Dump the ICTRLL table block.
*/
void ictrlg_table_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
