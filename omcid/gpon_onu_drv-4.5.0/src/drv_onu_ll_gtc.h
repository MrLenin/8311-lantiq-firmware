/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_ll_gtc_h
#define _drv_onu_ll_gtc_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_GTC GPON TC Layer Low-level Functions

   Low-level functions to access the GPON TC layer (GTC) hardware module.
   @{
*/

/**
   Initialize the PLOAM hardware

   \param ploam_ctx    The PLOAM context pointer.
   \param param        GTC initialization data

   \return
   - 0  Initialization successfully
   - -1    Error occurred during initialization
*/
int gtc_ll_init(struct ploam_context *ploam_ctx,
		const struct gtc_init_data *param);

/** Flush message FIFO

   \return -1 In case of error
   \return 0 If message FIFO was flushed
*/
int gtc_ploam_flush(void);

/** Read PLOAMd message from the device PLOAMd FIFO

    Returns filtered messages (with 0 < msg_id < 21) that directed to us or
    broadcast!

   \param msg_curr  Pointer to ploam_msg where received message
                    will be placed
   \param msg_prev Pointer to ploam_msg of the previous received message
   \param ds_repeat_count will contain how often this message was repeated

   \return -1 If no message (or all messages in FIFO were incorrect)
   \return 0 If message was read
*/
int gtc_ploam_rd(struct ploam_msg *msg_curr, struct ploam_msg *msg_prev,
		 uint8_t *ds_repeat_count);

/** Send PLOAMu message repeat_factor times

   \param msg Pointer to message to send
   \param repeat_factor Number of messages to send (should equal to 1 or 3)

   \return -1 If repeat_factor is incorrect
   \return 0 If message was sent
*/
int gtc_ploam_wr(union ploam_up_msg *msg, uint8_t repeat_factor);

/** Set the No Message content

   \param msg Pointer to message to the message content

   \return 0 If message was set
*/
int gtc_no_message_set(union ploam_up_msg *msg);

/** Set the Dying Gasp message content

   \param msg Pointer to message to the message content

   \return 0 If message was set
*/
int gtc_dying_gasp_message_set(const struct gtc_dgasp_msg *msg);

/** Set device's ONU-ID

   \param onu_id ONU-ID to set

   \return -1 If onu_id > PLOAM_ID_VALUE_ASSIGNABLE
   \return 0 If ONU-ID was set
*/
int gtc_onu_id_set(const uint32_t onu_id);

/**
   Set Alloc-ID for a given TCONT index.

   \param tcont_idx TCONT index
   \param alloc_id Alloc-ID to be written

   \return -2 alloc_id >= ONU_GPE_MAX_ALLOCATION_ID
   \return -1 tcont_idx >= ONU_GPE_MAX_TCONT
   \return 0 If Alloc-ID was set
*/
int gtc_tcont_set(const uint32_t tcont_idx, const uint32_t alloc_id);

/**
   Add Alloc-ID to the first free TCONT.

   \param alloc_id Alloc-ID to be written
   \param tcont Used T-CONT index

   \return -2 no free TCONT found
   \return -1 alloc_id >= ONU_GPE_MAX_ALLOCATION_ID
   \return 0 If Alloc-ID was set
*/
int gtc_tcont_alloc_id_add(const uint32_t alloc_id, uint32_t *tcont);

/**
   Find the first free TCONT.

   \param tcont Used T-CONT index

   \return -1 no free TCONT found
   \return 0 free TCONT found was set
*/
int gtc_tcont_alloc_id_find(uint32_t *tcont);

/**
   Remove Alloc-ID.

   \param alloc_id Alloc-ID to be removed

   \return -2 Allocid not found
   \return -1 alloc_id >= ONU_GPE_MAX_ALLOCATION_ID
   \return positive value which is equal to the TCONT index
*/
int gtc_tcont_alloc_id_remove(const uint32_t alloc_id);

/**
   Get alloc_id for a given TCONT index.
   \param tcont_idx TCONT index
   \param alloc_id Pointer to the alloc_id
	\param used TCONT validity
   \return -1 If tcont_idx not in use
   \return 0 on success
*/
int gtc_tcont_get(const uint32_t tcont_idx, uint32_t *alloc_id, bool *used);
/**
   Delete TCONT with given Allocation ID.

   \param tcont_idx Remove the allocation ID used by the specified TCONT.

   \return -1 If no TCONT within ONU_GPE_MAX_TCONT
   \return 0 on success
*/
int gtc_tcont_delete(const uint32_t tcont_idx);

/**
   Delete all AllocIDs from TCONT table.

*/
void gtc_tcont_clean(void);

/** Set device's random delay

   \param delay Random Delay to set
   \return 0
*/
int gtc_random_delay_set(const uint32_t delay);

/** Get device's Random Delay

   \return Random delay
*/
uint32_t gtc_random_delay_get(void);

/** Set device's ranged delay

   \param delay Ranged Delay to set
   \return 0
*/
int gtc_ranged_delay_set(const uint32_t delay);

/** Get device's ranged delay

   \return Ranged Delay
*/
uint32_t gtc_ranged_delay_get(void);

/** Get device's psync delay

   \return PSYNC Delay
*/
uint8_t gtc_psync_delay_get(void);

/** Enable ranged delay

   \return 0
*/
int gtc_ranged_delay_enable(const uint32_t enable);

/** Request upstream mode

   \return true If ranged delay is enabled
   \return false If ranged delay is disabled
*/
int gtc_ranged_delay_is_enable(void);

/** Set device's pre-assigned delay

   \param delay pre-assigned delay to set
   \return 0
*/
int gtc_preassigned_delay_set(const uint32_t delay);

/** Get device's pre-assigned delay

   \return pre-assigned delay
*/
uint32_t gtc_preassigned_delay_get(void);

/** Get device's Upstream header Length

   \return Upstream header length (bytes)
*/
uint8_t gtc_upstream_header_len_get(void);

/** Create device's Upstream Header

   \param guard_bits Number of guard bits
   \param t1_bits Number of type 1 preamble bits
   \param t2_bits Number of type 2 preamble bits
   \param t3_bits Number of type 3 preamble bits
   \param t3_pattern Pattern to be used for type 3 preamble bits
   \param delimiter Data to be programmed in delimiter(0x00xxxxxx)

   \return -1 If Upstream header was not created (because of errors
      in the arguments)
   \return 0 If header was created
*/
int gtc_upstream_header_create(const uint32_t guard_bits,
			       const uint32_t t1_bits,
			       const uint32_t t2_bits,
			       const uint32_t t3_bits,
			       const uint8_t t3_pattern,
			       const uint8_t delimiter[3]);

/** Fix the frame offset
*/
void gtc_offset_set(const uint16_t hdrlength, const uint16_t sstart_min,
		    uint16_t *offset_max);

/** Enable upstream transmission

   \return 0
*/
int gtc_tx_enable(const uint32_t enable);

/** Request upstream mode

   \return true If upstream is enabled
   \return false If upstream is disabled
*/
int gtc_tx_is_enable(void);

/** Enable dozing mode

   \return 0
*/
int gtc_dozing_enable(const uint32_t enable);

/** Request dozing mode

   \return true If dozing is enabled
   \return false If dozing is disabled
*/
int gtc_dozing_is_enable(void);

/** Retrieve existing Port ID information.

   \param port_id Port ID to operate on
   \param valid
      - true - if Port ID enabled
      - false - if Port ID disabled
   \param decryption_en
      - true - encryption enable
      - false - encryption disable

   \return -1 If port_id > 0xfff
   \return 0 If Port ID was modified
*/
int gtc_port_id_get(const uint16_t port_id, uint32_t *valid,
		    uint32_t *decryption_en);

/** Activate/Deactivate given Port ID

   \param port_id Port ID to operate on
   \param act
      - true - activate Port ID
      - false - deactivate Port ID

   \return -1 If port_id > 0xfff
   \return 0 If Port ID was (de)activated
*/
int gtc_port_id_enable(const uint16_t port_id, const uint32_t act);

/** Check if given Port ID is active

   \param port_id Port ID to check
   \param valid true if enabled

   \return 0 if successful
   \return -1 if Port ID is not valid
*/
int gtc_port_id_is_active(const uint16_t port_id, uint32_t *valid);

/** Set Port ID frame type

   \param port_id Port ID to operate on
   \param type PORTID_TYPE_

   \return 0 if Port ID was set
   \return -1 otherwise
*/
int gtc_port_id_type_set(const uint16_t port_id, const uint8_t type);

/** Encrypt/Decrypt given Port ID

   \param port_id Port ID to operate on
   \param bEncrypt
      - true - encrypt Port ID
      - false - decrypt Port ID

   \return -1 If port_id > 0xfff
   \return 0 If Port ID was encrypted/decrypted
*/
int gtc_port_id_encryption_set(const uint16_t port_id,
			       const uint32_t decryption_en);

/** Set switching time value

   \return 0
*/
int gtc_switching_time_set(const uint32_t frame_cnt);

/** Set AES keys

   \return 0
*/
int gtc_key_set(const uint32_t key1, const uint32_t key2,
		const uint32_t key3, const uint32_t key4);

/** Set BER interval

   \return 0
   \return -1 if the interval was out of range
*/
int gtc_bip_interval_set(const uint32_t err_interval);

/** Set threshold values

   \return 0
   \return -1 if the threshold value out of range
*/
int gtc_threshold_set(const uint8_t sf_thrhld, const uint8_t sd_thrhld);

/** Get GTC status

   \return 0
*/
void gtc_ll_status_get(struct gtc_status *param);

/** Enable only PLOAM requests
   - true during pre-05
   - false during 05

   \return 0
*/
void gtc_ploam_request_only_enable(const uint32_t enable);

/** Get BIP value

   \return BIP value
*/
uint32_t gtc_bip_value_get(void);

/** Enable / disable downstream GTC interrupts
*/
void gtc_downstream_imask_set(const uint32_t dsimask);

/** Return true if the BW-Map Trace is enabled */
uint32_t gtc_trace_enabled(void);

/** adjust the delay in the transmission path */
void gtc_delay_adjust(uint32_t reset);

/** Get GEM Receive Byte Counter

   \return GEM Receive Byte Counter value
*/
uint32_t gtc_gem_rxbcnt_get(void);

/** Get GEM Receive Frame Counter

   \return GEM Receive Frame Counter value
*/
uint32_t gtc_gem_rxfcnt_get(void);

/** Get FEC Uncorrectable Error Counter

   \return FEC Uncorrectable Error Counter value
*/
uint32_t gtc_gem_fuerrcnt_get(void);

/** refresh RDI indication */
void gtc_refresh_rdi(void);

/** Get GTC counters

   \param gem_herr_1 GEM HEC error counter 1
   \param gem_herr_2 GEM HEC error counter 2
   \param gem_bwmcerr GEM bandwidth map correctable error counter
   \param gem_bwmuerr GEM bandwidth map uncorrectable error counter
   \param gtc_frcbcnt FEC receive corrected byte counter
   \param gtc_fcerrcnt FEC correctable error counter
   \param gtc_fuerrcnt FEC uncorrectable error counter
   \param gtc_frcnt FEC receive block counter
   \param gem_rxfcnt GEM receive frame counter
   \param alloc_total GTC All TCONT Counter
   \param alloc_lost GTC Rejected TCONT Counter
*/
void gtc_cnt_get(uint32_t *gem_herr_1,
		 uint32_t *gem_herr_2,
		 uint32_t *gem_bwmcerr,
		 uint32_t *gem_bwmuerr,
		 uint32_t *gtc_frcbcnt,
		 uint32_t *gtc_fcerrcnt,
		 uint32_t *gtc_fuerrcnt,
		 uint32_t *gtc_frcnt,
		 uint32_t *gem_rxfcnt,
		 uint32_t *alloc_total,
		 uint32_t *alloc_lost);

/** Get US header pattern

   \param data US pattern data

   \return US header length
*/
uint8_t gtc_ll_us_header_cfg_get(uint32_t data[32]);

/** Get low level GTC layer alarm information

   \param dsstat GTC downstream status
   \param dsistat GTC downstream interrupts status
   \param usstat GTC upstream status
   \param usistat GTC upstream interrupts status
*/
void gtc_ll_alarm_get(uint32_t *dsstat, uint32_t *dsistat,
		      uint32_t *usstat, uint32_t *usistat);

/** Set low level GTC DS interrupt status register

   \param val GTC downstream interrupt status register content to set
*/
void gtc_ll_dsistat_set(uint32_t val);

/** Set low level GTC US interrupt status register

   \param val GTC upstream interrupt status register content to set
*/
void gtc_ll_usistat_set(uint32_t val);

/** Get GTC BW-Map Interrupt Status Register
*/
uint32_t gtc_ll_bwmstat_get(void);

/** Set GTC BW-Map Interrupt Status Register

   \param val GTC BW-Map Interrupt Status Register content to set
*/
void gtc_ll_bwmstat_set(uint32_t val);

/** The gtc_cfg_get function is used to read back the basic configuration of
    the GTC hardware module.
*/
/** Get low level GTC configuration

   \param berrintv GTC BIP error interval
   \param rtime GTC ranging time
*/
void gtc_ll_cfg_get(uint32_t *berrintv, uint32_t *rtime);

/** Set the rogue parameter to shut off the transmit laser through reception
    of a dedicated PLOAMd message.

   \param msg_id PLOAMd rogue ONU message identifier.
   \param msg_rpt PLOAMd rogue ONU message required repeat count.
   \param msg_enable PLOAMd rogue ONU message reception enable.

   \return 0
*/
void gtc_rogue_set(const uint32_t msg_id, const uint32_t msg_rpt,
                   const uint32_t msg_enable);

/** Retrieve the rogue settings.

   \param msg_id PLOAMd rogue ONU message identifier.
   \param msg_rpt PLOAMd rogue ONU message required repeat count.
   \param msg_enable PLOAMd rogue ONU message reception enable.

   \return 0
*/
void gtc_rogue_get(uint32_t *msg_id, uint32_t *msg_rpt,
                  uint32_t *msg_enable);

#if defined(INCLUDE_DUMP)

/**
   Dump the GTC register block.
*/
void gtc_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
