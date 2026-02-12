/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_octrlg_h
#define _drv_onu_octrlg_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_OCTRLG GPON Output Control Low-level Functions

   Low-level functions to access the GPON output control unit (OCTRLG).
   @{
*/

#define TCMAP_LEN     	4096
#define GPIXTABLE_LEN	256
#define TCTABLE_LEN	32
#define DPTRTABLE_LEN 	64

/**
   Initialize the OCTRLG block (octrlg).
*/
int octrlg_init(void);

/**
   Set OCTRLG configuration.
   \param gem_block_len GEM block size, used to calculate block-related
	  values. Given in number of bytes, the default is 48
   \param gem_payload_sz_max Maximum GEM payload size in upstream direction
*/
int octrlg_config_set(const uint32_t gem_block_len,
		      const uint32_t gem_payload_sz_max);

/**
   Get OCTRLG configuration.
   \param gem_block_len Get GEM block size, used to calculate block-related
	  values. Given in number of bytes.
   \param gem_payload_sz_max Get Maximum GEM payload size in upstream direction
*/
int octrlg_config_get(uint32_t *gem_block_len, uint32_t *gem_payload_sz_max);

/**
   Set OCTRLG EPN.
   \param tcont_idx Tcont index number
   \param egress_port_idx EPN which should be mapped to TCONT index
   \param prempted_epn_idx Preempted EPN which should be mapped to TCONT index
*/
int octrlg_epn_set(const uint32_t tcont_idx, const uint32_t egress_port_idx,
		   const uint32_t prempted_epn_idx);

/**
   Get OCTRLG EPN.
   \param tcont_idx Tcont index number
   \param egress_port_idx Get EPN of mapped to TCONT index
   \param prempted_epn_idx Get Preempted EPN which should be mapped to
	  TCONT index
*/
int octrlg_epn_get(const uint32_t tcont_idx, uint32_t *egress_port_idx,
		   uint32_t *prempted_epn_idx);

/**
   Set OCTRLG TCONT mapping table.
   \param tcont_idx Tcont index number
   \param alloc_id Tcont ID of incoming request

*/
int octrlg_tcont_set(const uint32_t tcont_idx, const uint32_t alloc_id);

/**
   Get OCTRLG TCONT mapping table.
   \param tcont_idx Tcont index number
   \param alloc_id Get Tcont ID of incoming request
*/
int octrlg_tcont_get(const uint32_t tcont_idx, uint32_t *alloc_id);

/**
   Delete an entry in TCMAP table by TCONT index number
   \param tcont_idx Tcont index number
*/
int octrlg_tcont_delete(const uint32_t tcont_idx);

/**
   Delete an entry in TCMAP table by Allocation ID
   \param alloc_id Allocation ID
*/
int octrlg_tcont_alloc_id_delete(const uint32_t alloc_id);

/**
   Retrieve a TCONT index value based on given Allocation ID.
   
   \param alloc_id Allocation ID
   \param tcont_idx Tcont index number
*/
int octrlg_tcont_alloc_id_get(const uint32_t alloc_id, uint32_t *tcont_idx);

/**
	Set GEM port table entry.
	\param gem_port_id	GEM port ID (0-4095)
	\param gem_port_index	GEM port index (0-255)
	\param data_direction	Data direction of GEM port
 */
int octrlg_gem_port_set(const uint32_t gem_port_id,
			const uint32_t gem_port_index,
			const enum gpe_direction data_direction);

/**
	Get GEM port Index.
	\param gem_port_id	GEM port ID (0-255)
	\param gem_port_index	GEM port index
*/
int octrlg_gpix_get(const uint32_t gem_port_id, uint32_t *gem_port_index);

/**
	Remove a new GEM port table entry.
	\param gem_port_index	GEM port index (0-255
 */
int octrlg_gem_port_delete(const uint32_t gem_port_index);

/**
   Read GEM port related hardware counter.
   \param gpix				GEM port index
   \param counter			Get value of GEM port counter
*/
int octrlg_gem_counter_get(const uint32_t gpix,
			   struct gpe_cnt_octrlg_gem_val *counter);

/**
   Read global GEM hardware counter.
   \param counter			Get value of GEM global counter
*/
int octrlg_counter_get(struct gpe_cnt_octrlg_val *counter);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set Upstream GTC Fifo Threshold
	Filling Level below or equal this threshold will cause Idle Frame
	insertion. The granularity is 1 Fifo entry, i.e. 4 Bytes.
	The IRN*.GTCFIFOTHRES interrupt can be used for reporting.
   \param value  Set value
*/
void octrlg_gtc_fifo_threshold_set(const uint32_t value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get Upstream GTC Fifo Threshold
	Filling Level below or equal this threshold will cause Idle Frame
	insertion. The granularity is 1 Fifo entry, i.e. 4 Bytes.
	The IRN*.GTCFIFOTHRES interrupt can be used for reporting.
	\param value  Get value
*/
void octrlg_gtc_fifo_threshold_get(uint32_t *value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set Idle Frame Length
   Max number of Idle Frame Bytes used.
   \param value  Set value
*/
int octrlg_idle_len_set(const uint32_t value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Get Idle Frame Length
	\return value  Get value
*/
uint32_t octrlg_idle_len_get(void);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set specified interrupt mask.
   Disabled interrupts are not visible in the IRNCR register and are not
   signalled via the interrupt line towards the controller.
   \param value  Set value
*/
void octrlg_interrupt_mask_set(const uint32_t value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Set an specified interrupt.
   A write operation directly effects the interrupts.
   This can be used to trigger events under software control for testing
   purposes.
   \param value  Set value
*/
void octrlg_interrupt_set(const uint32_t value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get currently active interrupt events masked with the corresponding enable
   bits of the IRNEN register.
   The interrupts can be acknowledged by a write operation.
   \param value  Get value
*/
void octrlg_interrupt_get(uint32_t *value);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Set OCTRLG enable bit.
   Use this function to enable or disable the OCTRLG
   \param act Activation status, true = active
*/
void octrlg_enable(const uint32_t act);

/**
   Get OCTRLG enable bit.
   Use this function to get status of the OCTRLG enable bit.
*/
uint32_t octrlg_is_enabled(void);


/**
   Set OCTRLG DBRu debug bit.
   Use this function to enable or disable the OCTRLG DBRu debug mode
   \param act Activation status, true = active
*/
void octrlg_dbru_mode_dbg_set(const uint32_t act);
/**
   Get OCTRLG DBRu debug bit.
   Use this function to get status of the OCTRLG DBRu debug mode bit.
*/
void octrlg_dbru_mode_dbg_get(uint32_t *act);

/**
   Set OCTRLG DBRu debug register.
   Use this function to set DBRu mode 2 green, yellow or DBRu mode1 debug value
   \param mode2y yellow value for DBRu mode2
   \param mode2g green value for DBRu mode2
   \param mode1 value for DBRu mode1
*/
void octrlg_dbru_debug_set(const uint32_t mode2y,
			   const uint32_t mode2g,
			   const uint32_t mode1);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/**
   Get OCTRLG DBRu debug register.
   Use this function to get DBRu mode 2 green, yellow or DBRu mode1 debug value
   \param mode2y yellow value for DBRu mode2
   \param mode2g green value for DBRu mode2
   \param mode1 value for DBRu mode1
*/
void octrlg_dbru_debug_get(uint32_t *mode2y, uint32_t *mode2g, uint32_t *mode1);
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Get OCTRLG DBRu mode
   \param mode value for DBRu mode
*/
void octrlg_dbru_mode_get(uint32_t *mode);

void octrlg_laser_ageupdate (uint32_t *seconds);

#if defined(INCLUDE_DUMP)

/**
   Dump the OCTRLG register block.
*/
void octrlg_dump(struct seq_file *s);

/**
   Dump the OCTRLG table block.
*/
void octrlg_table_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
