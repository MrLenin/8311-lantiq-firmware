/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_fec_pmhd_h
#define _omci_fec_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_FEC_PMHD FEC Performance Monitoring History Data Managed Entity

     This Managed Entity collects performance monitoring data associated with
     downstream FEC counters. Instances of this Managed Entity are created and
     deleted by the OLT. An instance of this Managed Entity is associated with
     an instance of the ANI-G Managed Entity.

     @{
*/

/** This structure holds the attributes of the FEC Performance Monitoring
    History Data Managed Entity.
*/
struct omci_me_fec_pmhd {
	/** Interval End Time

	    This attribute identifies the most recently finished 15-minute
	    interval. The sequence of 15-minute intervals is initiated by the
	    synchronize time action, issued by the OLT. The counter is
	    incremented every 15 minutes autonomously by the ONU and rolls over
	    from 255 to 0.

	    This attribute is read-only by the OLT.
	*/
	uint8_t interval_end_time;

	/** Threshold Data 1/2 ID

	    This attribute points to an instance of the threshold data 1 Managed
	    Entity that contains PM threshold values.
	    Since no threshold value attribute number exceeds 7, a threshold
	    data 2 Managed Entity is optional.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t thr_data_id;

	/** Corrected FEC Byte Count

	    This attribute counts the number of bytes that were corrected by the
	    downstream FEC function.

	    This attribute is read-only by the OLT.
	*/
	uint32_t corrected_byte_count;

	/** Corrected FEC Word Count

	    This attribute counts the code words that were corrected by the
	    downstream FEC function.

	    This attribute is read-only by the OLT.
	*/
	uint32_t corrected_word_count;

	/** Uncorrectable FEC Word Count

	    This attribute counts the code words that were not corrected by the
	    downstream FEC function.

	    This attribute is read-only by the OLT.
	*/
	uint32_t uncorrectable_word_count;

	/** Total FEC Code Word Count

	    This attribute counts the total number of received downstream FEC
	    code words.

	    This attribute is read-only by the OLT.
	*/
	uint32_t total_word_count;

	/** FEC Errored Second Count

	    This attribute counts one-second intervals during which there was a
	    Forward Error Correction anomaly (uncorrectable FEC words).

	    This attribute is read-only by the OLT.
	*/
	uint16_t fec_seconds;

} __PACKED__;

/** This enumerator holds the attribute numbers of the FEC Performance
   Monitoring History Data Managed Entity.
*/
enum {
	omci_me_fec_pmhd_interval_end_time = 1,
	omci_me_fec_pmhd_thr_data_id = 2,
	omci_me_fec_pmhd_corrected_byte_count = 3,
	omci_me_fec_pmhd_corrected_word_count = 4,
	omci_me_fec_pmhd_uncorrectable_word_count = 5,
	omci_me_fec_pmhd_total_word_count = 6,
	omci_me_fec_pmhd_fec_seconds = 7
};

/** @} */

/** @} */

__END_DECLS

#endif
