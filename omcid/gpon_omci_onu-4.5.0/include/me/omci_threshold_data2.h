/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_threshold_data2_h
#define _omci_threshold_data2_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \addtogroup OMCI_ME_THRESHOLD_DATA

    Together with an instance of the threshold data 1 Managed Entity, an
    instance of this Managed Entity contains threshold values for the
    performance monitoring parameters maintained in one or more instances of
    history data Managed Entities.

    @{
*/

/** This structure holds the attributes of the Threshold Data 2 Managed Entity.
*/
struct omci_me_threshold_data2 {
	/** Threshold Value 8

	    4-byte threshold data value.
	*/
	uint32_t thr_data8;

	/** Threshold Value 9

	    4-byte threshold data value.
	*/
	uint32_t thr_data9;

	/** Threshold Value 10

	    4-byte threshold data value.
	*/
	uint32_t thr_data10;

	/** Threshold Value 11

	    4-byte threshold data value.
	*/
	uint32_t thr_data11;

	/** Threshold Value 12

	    4-byte threshold data value.
	*/
	uint32_t thr_data12;

	/** Threshold Value 13

	    4-byte threshold data value.
	*/
	uint32_t thr_data13;

	/** Threshold Value 14

	    4-byte threshold data value.
	*/
	uint32_t thr_data14;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Threshold Data 2 Managed
   Entity.
*/
enum {
	omci_me_threshold_data2_thr_data8 = 1,
	omci_me_threshold_data2_thr_data9 = 2,
	omci_me_threshold_data2_thr_data10 = 3,
	omci_me_threshold_data2_thr_data11 = 4,
	omci_me_threshold_data2_thr_data12 = 5,
	omci_me_threshold_data2_thr_data13 = 6,
	omci_me_threshold_data2_thr_data14 = 7
};

/** @} */

/** @} */

__END_DECLS

#endif
