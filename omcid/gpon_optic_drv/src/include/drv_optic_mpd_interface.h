/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_mpd_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, MPD block.
*/
#ifndef _drv_optic_mpd_interface_h_
#define _drv_optic_mpd_interface_h_

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

/** \defgroup OPTIC_MPD Monitor Photo Diode (MPD) Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface for MPD configuration.
   @{
*/

/** MPD configuration parameters. Used by \ref FIO_MPD_CFG_SET and
   \ref FIO_MPD_CFG_GET. */
struct optic_mpd_config {
	/** TIA gain configuration, four gain bank selections are provided:
	   - 0: Power level 0 (0 dB).
	   - 1: Power level 1 (-3 dB).
	   - 2: Power level 2 (-6 dB).
	   - 3: Global setting (used for coarse/fine ratio calibration). */
	uint8_t tia_gain_selector[4];
	/** Calibration current definition, per gain bank selection
	    (100uA or 1mA), according to the tia_gain_selector settings. */
	uint8_t cal_current[4];

	/** Scaling factor for the translation between Imod and Dmod per transmit
	    power level, ~1	<<OPTIC_FLOAT2INTSHIFT_CORRFACTOR */
	uint16_t scalefactor_mod[3];

	/** DcalrefP0 at Tref, individual values per transmit power level. */
	int32_t dcal_ref_p0[3];
	/** DcalrefP1 at Tref, individual values per transmit power level. */
	int32_t dcal_ref_p1[3];
	/** DrefP0, individual values per transmit power level. */
	int32_t dref_p0[3];
	/** DrefP1, individual values per transmit power level. */
	int32_t dref_p1[3];

	/** Coarse/fine DAC ratio for
	    P0/P1 << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO */
	uint16_t ratio_coarse_fine;
	/** Power-save mode */
	enum optic_activation powersave;

	/** Number of CID bits for P0 detection */
	uint8_t cid_size_p0;
	/** Number of CID bits for P1 detection */
	uint8_t cid_size_p1;
	/** Select, if any (false) or all (true) bits of p0 CID mask
	    have to be set.
	    - false: any bit of p0 CID mask has to be set.
	    - true: all bits of p0 CID mask have to be set. */
	bool cid_match_all_p0;
	/** Select, if any (false) or all (true) bits of p1 CID mask
	    have to be set.
	    - false: any bit of p1 CID mask has to be set.
	    - true: all bits of p1 CID mask have to be set. */
	bool cid_match_all_p1;
	/** CID mask for P0 detection */
	uint16_t cid_mask_p0;
	/** CID mask for P1 detection */
	uint16_t cid_mask_p1;
	/* Select rogue interburst alarms.
	   - false: disable interburst alarms 
  	   - true: enable interburst alarms */
	bool rogue_interburst;
	/* Select rogue intraburst alarms.
	   - false: disable intraburst alarms 
  	   - true: enable intraburst alarms */
	bool rogue_intraburst;
} __PACKED__;

/** MPD trace buffer contents. Used by \ref FIO_MPD_TRACE_GET. */
struct optic_mpd_trace {
	/** 16-bit trace pattern P0. */
	uint16_t trace_pattern_p0;
	/** 16-bit trace pattern P1. */
	uint16_t trace_pattern_p1;
	/** 16-bit tx data P0. */
	uint16_t correlator_trace_p0;
	/** 16-bit tx data P1. */
	uint16_t correlator_trace_p1;
} __PACKED__;


/**
   Set the configuration for the Monitor Photo Diode (MPD).

   \param optic_mpd_config Pointer to \ref optic_mpd_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MPD_CFG_SET _IOW(OPTIC_MPD_MAGIC, 0, struct optic_mpd_config)

/**
   Read back the Monitor Photo Diode (MPD) configuration.

   \param optic_mpd_config Pointer to \ref optic_mpd_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MPD_CFG_GET _IOR(OPTIC_MPD_MAGIC, 1, struct optic_mpd_config)

/**
   Read back the MPD trace buffer information (16-bit pattern).

   \param optic_mpd_trace Pointer to \ref optic_mpd_trace.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MPD_TRACE_GET _IOR(OPTIC_MPD_MAGIC, 2, struct optic_mpd_trace)

#define OPTIC_MPD_MAX 3


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
#endif                          /* _drv_optic_mpd_interface_h_ */
