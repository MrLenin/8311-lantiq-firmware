/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_tod_h
#define _drv_onu_tod_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_TOD Time Of Dat Low-level Functions

   Low-level functions to control the Time Of Day (TOD).
   @{
*/

/* ***************************************************************************/

#define TOD_RLDNS_LO_FREQ	(31104UL)	/* 10kHz*/
#define TOD_RLDNS_LO_FREQ_SCALE	(100000UL)
#define TOD_RLDNS_HI_STEP	(100000UL)	/* ns*/

#define TOD_NSEC		(1000000000UL)	/* ns*/
#define TOD_USEC		(1000000UL)	/* us*/
#define TOD_MSEC		(1000UL)	/* ms*/

#define TOD_GTC_DS_DEL_SCALE	(100000UL)
#define TOD_GTC_DS_DEL_DIV	(248832UL)

/** Structure for the TOD reload
*/
struct tod_reload {
	/** Reload seconds */
	uint32_t sec;
	/** Reload nseconds High part */
	uint16_t nsec_high;
	/** Reload nseconds Low part */
	uint16_t nsec_low;
};

/** Stricture to specify TOD correction values
*/
struct tod_corr {
	/** Variable downstream synchronization delay.
	    Contains the PSYNC Delay in range from 0 to 31.
	    This value represents the Delay of the MSB Bit of the PSYNC Word in
	    the 32 Bit Data In Word. */
	uint8_t gtc_ds_delay;
};

/** Initialize TOD (write CFG register)

    \param intdel	Selects the delay of the delayable interrupt with
			respect to the rising edge of the pps signal in
			multiples of 100us.
    \param pw		Selects the pulsewidth of the pps-signal in multiples
			of 100us.
*/
void tod_init(const uint16_t intdel, const uint16_t pw);

/** Enable/disable the Free Running mode

    \param enable	enable/disable Free Running Mode
*/
void tod_frm_enable(const bool enable);

/** Set the Superframe Counter Compare register

    \param val		counter value
*/
void tod_sfcc_set(const uint32_t val);

/** Get the Superframe Counter Compare register

    \return counter value
*/
uint32_t tod_sfcc_get(void);

/** Set Seconds Reload Register

    \param val		reload value
*/
void tod_rlds_set(const uint32_t val);

/** Get Seconds Reload Register

    \return reload value
*/
uint32_t tod_rlds_get(void);

/** Set Nanoseconds Reload Register

    \param high		high part value, bits 29:16
    \param low		high part value, bits 14:0
*/
void tod_rldns_set(const uint16_t high, const uint16_t low);

/** Get Nanoseconds Reload Register

    \return Nanoseconds Reload Register
*/
uint32_t tod_rldns_get(void);

/** Convert Nanoseconds Reload Register to Nanoseconds

    \param rldns	RLDNS register value

    \return Nanoseconds
*/
uint32_t tod_rldns2nsec(const uint32_t rldns);

/** Get Reload structure

    \param sec		input seconds
    \param nsec		input nseconds
    \param corr		nseconds correction
    \param rld		pointer to the reload data to fill
*/
void tod_reload_get(const uint32_t sec, const uint32_t nsec,
		    const struct tod_corr *corr, struct tod_reload *rld);

/** Get the seconds part of the ToD counter
    \return seconds part of the ToD counter
*/
uint32_t tod_pps_get(void);

/** Control the IRNEN register

    \param clear	interupt clear mask
    \param set		interrupt set mask
*/
void tod_interrupt_enable_set(const uint32_t clear, const uint32_t set);

/** ToD ISR
*/
void tod_isr_handle(void);

#if defined(INCLUDE_DUMP)

/**
   Dump the TOD register block.
*/
void tod_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
