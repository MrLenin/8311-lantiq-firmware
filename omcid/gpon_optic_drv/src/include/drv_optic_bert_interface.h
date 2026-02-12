/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_bert_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, BERT block.
*/
#ifndef _drv_optic_bert_interface_h_
#define _drv_optic_bert_interface_h_

#include "drv_optic_std_defs.h"


#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__        /* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI Optical Interface API Reference
   @{
*/

/** \defgroup OPTIC_BERT BERT Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface for BERT configuration.
   @{
*/

/** This enumeration defines the selectable test pattern types. */
enum optic_bert_modi {
	/** All-zero signal. */
	OPTIC_BERT_CONST_ZERO = 0,
	/** All-ones signal. */
	OPTIC_BERT_CONST_ONE = 1,
	/** Alternating 1-0-1-0- signal. */
	OPTIC_BERT_CLOCK = 3,
	/** PRBS signal with a polynomial length of 7 bit. */
	OPTIC_BERT_PRBS7 = 7,
	/** PRBS signal with a polynomial length of 11 bit. */
	OPTIC_BERT_PRBS11 = 11,
	/** PRBS signal with a polynomial length of 15 bit. */
	OPTIC_BERT_PRBS15 = 15,
	/** PRBS signal with a polynomial length of 18 bit. */
	OPTIC_BERT_PRBS18 = 18,
	/** PRBS signal with a polynomial length of 21 bit. */
	OPTIC_BERT_PRBS21 = 21,
	/** PRBS signal with a polynomial length of 23 bit. */
	OPTIC_BERT_PRBS23 = 23,
	/** PRBS signal with a polynomial length of 31 bit. */
	OPTIC_BERT_PRBS31 = 31
};

/** BERT configuration parameters.
   Used by \ref FIO_BERT_CFG_SET and \ref FIO_BERT_CFG_GET.
   The BERT operation mode is set by a combination of the given parameters.
   Depending on the selected mode, some of the parameters are not needed and
   ignored by the driver function. Invalid selections are checked and an error
   code is returned. */
struct optic_bert_cfg {
	/** Basic pattern mode selection:
		- 0: Use the BERT pattern generator
		- 1: Use the fixed pattern from a dedicated buffer

		The BERT pattern generator provides four pre-defined pattern
		types, one of which is selected through pattern_mode.

		The pattern is composed of four segments (slots), the pattern
		type and length is individually selectable for each pattern
		segment (see the pattern_type and pattern_length parameters).

		The pattern buffer can be used to define a fixed bit pattern
		(see the fixed_pattern parameter). The pattern length is
		programmable up to a size
		of 76 byte. */
	uint8_t pattern_mode;
	/** Pattern type definition
	    Four pattern types are defined, each of which can be set to:
		- 0: clock pattern (configurable frequency and duty cycle)
		- 1: PRBS pattern (multiple types)
		- 2: fixed pattern (32 bit)
		- 3: all-zero
	    This parameter is ignored, if pattern_mode == 1. */
      /* configured in BERT_CONTROL.mux_sel1...4 */
	uint8_t pattern_type[4];
	/** Pattern length definition.
	    If pattern_mode == 0, each of the four patterns is sent in a
	    dedicated time slot for a given number of:
		- nibbles at 1.244 Gbit/s (3.2 ns)
		- bytes at 2.488 Gbit/s (3.2 ns).
		If set to 0, no pattern is driven through the related time slot.
		The maximum slot time is 255 * 3.2 ns = 820 ns.

	    If pattern_mode == 0, pattern_length(0) defines the fixed
	    pattern length in number of bytes (up to 76). */
	uint8_t pattern_length[4];
	/** Fixed pattern definition. The pattern is shifted out t.b.d. first.
	   - If pattern_mode == 0, fixed_pattern(0) defines the 32-bit pattern,
	   fixed_pattern(1...19) are ignored.
	   - If pattern_mode == 1, fixed_pattern(0...19) defines the (up to)
	   76-byte pattern. pattern_length(0) defines the used
	   length of the pattern. */
	/* configure in BERT_PATTERN or GTCPMAIF */
	uint8_t fixed_pattern[78];
	/** Clock period definition, in multiples of 3.2 ns */
	/* configure in BERT_CLK */
	uint8_t clock_period;
	/** Clock-type pattern high phase definition, in multiples of 3.2 ns.
	    This parameter is ignored, if pattern_mode == 1. */
	/* configure in BERT_CLK */
	uint8_t clock_high;
	/** PRBS pattern type, valid selections are 7, 11, 15, 18, 21, 23,
	    and 31. Other selections are rejected and result in an error
	    message.
	    This parameter is ignored, if pattern_mode == 1. */
	/* configure in BERT_CONTROL.PRBS_SEL */
	uint8_t prbs_type;
	/** Transmit high data rate.
		- false: 1.244 Gbit/s
		- true: 2.488 Gbit/s
	    This parameter is ignored, if pattern_mode == 1. */
	/* configure in BERT_CONTROL */
	bool datarate_tx_high;
	/** Receive high data rate.
		- false: 1.244 Gbit/s
		- true: 2.488 Gbit/s
	    This parameter is ignored, if pattern_mode == 1. */
	/* configure in BERT_CONTROL */
	bool datarate_rx_high;
	/** Enable an electrical, serial loop from transmit to receive
	    direction. */
	bool loop_enable;
} __PACKED__;

/** BERT status parameters.
   Used by \ref FIO_BERT_STATUS_GET. This function returns the number of
   received bits and the number of detected errors to calculate the Bit Error
   Rate (BER).
*/

struct optic_bert_status {
	/** BERT enable status, true if the BERT is enabled. */
	bool bert_enable;
	/** Word count, number of 32-bit doublewords that have been received. */
	uint32_t word_cnt;
	/** Bit error count, number of single-bit errors that have been
	    received. */
	uint32_t error_cnt;
} __PACKED__;

/** BERT mode parameters.
   Used by \ref FIO_BERT_MODE_SET.
*/

struct optic_bert_mode {
	/** BERT mode selection. */
	enum optic_bert_modi mode;
} __PACKED__;

/* IOCTL Command Declaration - GOI BERT
   ==================================== */

/**
   Set the configuration for the diagnostics receiver and transmitter (Bit
   Error Rate Tester, BERT).
   This function defines the bit patterns and data rate for testing of the
   optical interface in upstream and/or downstream direction. Using the BERT
   function is intended for system tests or calibration.
   The BERT operation mode is set by a combination of the given parameters.
   Depending on the selected mode, some of the parameters are not needed and
   ignored by the driver function. Invalid selections are checked and an error
   code is returned.

   The parameters can be read back through the \ref FIO_BERT_CFG_GET function.

   \attention
   The BERT function must not be used in a running system that is connected to
   an OLT through an ODN. This would disturb the traffic of all other ONUs that
   are connected to the same ODN.

   \param optic_bert_cfg Pointer to \ref optic_bert_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BERT_CFG_SET _IOW(OPTIC_BERT_MAGIC, 0, struct optic_bert_cfg )

/**
   Read back the BERT configuration. This returns the parameters that have been
   set by the \ref FIO_BERT_CFG_SET function.

   \param optic_bert_cfg Pointer to \ref optic_bert_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BERT_CFG_GET _IOR(OPTIC_BERT_MAGIC, 1, struct optic_bert_cfg )

/**
   Enable the diagnostics receiver and transmitter (BERT).

   \remarks This function shall never be used in a life system that is running
   traffic between an OLT and multiple ONUs.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BERT_ENABLE _IO(OPTIC_BERT_MAGIC, 2)

/**
   Disable the diagnostics receiver and transmitter (BERT).

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BERT_DISABLE _IO(OPTIC_BERT_MAGIC, 3)

/**
   Synchronize the received PRBS or fixed 32-bit pattern to the internal
   pattern generator of the BERT module.
   Before valid bit error rate measurements can be made, the received data
   pattern must be synchronized with the on-chip pattern generator by running
   this function. Bit errors can not be detected if the received pattern is
   different from the pattern selected through the \ref FIO_BERT_CFG_SET
   function.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BERT_SYNC _IO(OPTIC_BERT_MAGIC, 4)

/**
   Read back the BERT status (enabled or disabled) as well as the number of
   received bits and detected bit errors. This can be used to calculate the Bit
   Error Rate (BER).

   \param optic_bert_status Pointer to \ref optic_bert_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BERT_STATUS_GET _IOR(OPTIC_BERT_MAGIC, 5, struct optic_bert_status )

/**
   Set the configuration for the diagnostics receiver and transmitter (Bit
   Error Rate Tester, BERT).
   This function simply differs between basic modes constant zero, constant one
   and PRBS.

   The detailed configuration can be read back through the
   \ref FIO_BERT_CFG_GET function.

   \attention
   The BERT function must not be used in a running system that is connected to
   an OLT through an ODN. This would disturb the traffic of all other ONUs that
   are connected to the same ODN.

   \param optic_bert_mode Pointer to \ref optic_bert_mode.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BERT_MODE_SET _IOW(OPTIC_BERT_MAGIC, 6, struct optic_bert_mode )

/**
   Resets the BERT counters.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_BERT_CNT_RESET _IO(OPTIC_BERT_MAGIC, 7)

/** Number of BERT FIO functions. */
#define OPTIC_BERT_MAX                              8


/*! @} */

/*! @} */

EXTERN_C_END

#ifdef __PACKED_DEFINED__
#  if !defined (__GNUC__) && !defined (__GNUG__)
#    pragma pack()
#  endif
#  undef __PACKED_DEFINED__
#  undef __PACKED__
#endif
#endif                          /* _drv_optic_bert_interface_h_ */
