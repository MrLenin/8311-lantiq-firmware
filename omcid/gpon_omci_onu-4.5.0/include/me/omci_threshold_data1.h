/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_threshold_data1_h
#define _omci_threshold_data1_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_THRESHOLD_DATA Threshold Data Managed Entity

    Threshold data is partitioned into two Managed Entities to permit the
    set-by-create operation on all attributes, as limited by OMCI message size.

    An instance of this Managed Entity, together with an optional instance of
    the threshold data 2 Managed Entity, contains threshold values for
    performance monitoring counters in history data Managed Entities.

    @{
*/

/** This structure holds the attributes of the Threshold Data 1 Managed Entity.
*/
struct omci_me_threshold_data1 {
	/** Threshold Value 1

	    4-byte threshold data value.
	*/
	uint32_t thr_data1;

	/** Threshold Value 2

	    4-byte threshold data value.
	*/
	uint32_t thr_data2;

	/** Threshold Value 3

	    4-byte threshold data value.
	*/
	uint32_t thr_data3;

	/** Threshold Value 4

	    4-byte threshold data value.
	*/
	uint32_t thr_data4;

	/** Threshold Value 5

	    4-byte threshold data value.
	*/
	uint32_t thr_data5;

	/** Threshold Value 6

	    4-byte threshold data value.
	*/
	uint32_t thr_data6;

	/** Threshold Value 7

	    4-byte threshold data value.
	*/
	uint32_t thr_data7;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Threshold Data 1 Managed
   Entity.
*/
enum {
	omci_me_threshold_data1_thr_data1 = 1,
	omci_me_threshold_data1_thr_data2 = 2,
	omci_me_threshold_data1_thr_data3 = 3,
	omci_me_threshold_data1_thr_data4 = 4,
	omci_me_threshold_data1_thr_data5 = 5,
	omci_me_threshold_data1_thr_data6 = 6,
	omci_me_threshold_data1_thr_data7 = 7
};

#ifdef OMCI_PRIVATE
/** Update thresholds for all Managed Entities bounded to given Thresholds Data
   Managed Entity

   \param[in] context OMCI context pointer
   \param[in] me      Threshold data 1 or 2 ME pointer
   \param[in] thr     Updated thresholds
*/
enum omci_error pm_thr_update(struct omci_context *context,
			      struct me *me,
			      uint32_t thr[PM_THR_NUM]);
#endif

/** @} */

/** @} */

__END_DECLS

#endif
