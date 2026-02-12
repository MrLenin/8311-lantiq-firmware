/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_tbm_h
#define _drv_onu_tbm_h

#define TBM_CORECLOCK			625


/* exclude some parts from SWIG generation */
#ifndef SWIG

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/**
   This structure is used to set the parameters of a token bucket meter.

   \remarks The rate parameter is given in bytes/sec.
   \remarks The burst size parameter is given in bytes.
*/
struct tbm_token_bucket_meter_params {
	/**
	    This field selects the TBM identifier.
	    */
	uint16_t tbid;
	/**
	    This field indicates the TBM operating mode.
	    - 0H: MOD_0, RFC 4115 color blind.
	    - 1H: MOD_1, RFC 4115 color aware.
	    - 0H: MOD_2, RFC 2698 color blind.
	    - 2H: MOD_3, RFC 2698 color aware.
	    */
	uint16_t mod;
	/**
	    This bit indicates if the meter bucket is enabled.
	    - 0H: DIS, Disable.
	    - 1H: EN, Enable.
	    */
	uint16_t tbe;
	/**
	    Information Rate in bytes/s.
	    Supported range is 8,000 ... 125,000,000 bytes/s
	    */
	uint32_t rate;

	/**
	    Maximum Burst Size in bytes.
	    */
	uint32_t mbs;
};


/**
   This structure is used to hold the attributes of a complete TBM entry.
*/
struct tbm_tbmt_entry {
	uint32_t mbs;
	uint32_t tbc;
	uint32_t lts;
	uint16_t tbe;
	uint16_t mod;
	uint16_t cf;
	uint16_t tss;
	uint16_t mrm;
	uint16_t mre;
	uint16_t ets;
	uint16_t vts;
	uint16_t tbid;
};


/** \addtogroup ONU_LL_TBM Token Bucket Meter Low-level Functions

   Low-level functions to control the Dual Token Bucket Meter (TBM).
   @{
*/

/* ***************************************************************************/

/**
   Set Activate / Deactivate switch for TBM state machines.
*/
void tbm_enable(const bool act);

/**
   Get Activate / Deactivate switch of  TBM state machines.
*/
bool tbm_is_enabled(void);

/**
   Initialize the IQM block.
*/
void tbm_init(void);

/**
   Set configuration parameters of a tbm meter entry
*/
void tbm_meter_cfg_set(const struct tbm_token_bucket_meter_params *tbmt);

/**
   get configuration parameters of a tbm meter entry
*/
void tbm_meter_cfg_get(struct tbm_token_bucket_meter_params *tbmt);

/**
   Set a tbm meter entry
*/
void tbm_meter_set(const struct tbm_tbmt_entry *tbmt);

/**
   Get a tbm meter entry
*/
void tbm_meter_get(struct tbm_tbmt_entry *tbmt);

/**
   Set tbm meter registers
*/
void tbm_meter_register_set(const struct tbm_tbmt_entry *tbmt);

/**
   Get tbm meter registers
*/
void tbm_meter_register_get(struct tbm_tbmt_entry *tbmt);

/**
  Identify the correct mod field for the register
 */
int16_t find_meter_mode(const struct gpe_meter_cfg *param);


#if defined(INCLUDE_DUMP)

/**
   Dump the TBM register block.
*/
void tbm_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif /* #ifndef SWIG*/

#endif
