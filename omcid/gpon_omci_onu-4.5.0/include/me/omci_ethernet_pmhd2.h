/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_ethernet_pmhd2_h
#define _omci_ethernet_pmhd2_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME_ETHERNET_PMHD
   @{
*/

/** This structure holds the attributes of the Ethernet Performance Monitoring
    History Data 2 Managed Entity.

    This Managed Entity collects additional performance monitoring data for an
    Ethernet interface. Instances of this Managed Entity are created and deleted
    by the OLT.
*/
struct omci_me_ethernet_pmhd2 {
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

	/** PPPoE filtered Frame Count

	    This attribute counts the number of frames discarded due to PPPoE
	    filtering.
	*/
	uint32_t filtered_pppoe_count;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Ethernet Performance
   Monitoring History Data 2 Managed Entity.
*/
enum {
	omci_me_ethernet_pmhd2_interval_end_time = 1,
	omci_me_ethernet_pmhd2_thr_data_id = 2,
	omci_me_ethernet_pmhd2_filtered_pppoe_count = 3
};

/** @} */

__END_DECLS

#endif
