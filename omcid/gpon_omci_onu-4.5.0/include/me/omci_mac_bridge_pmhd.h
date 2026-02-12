/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_pmhd_h
#define _omci_mac_bridge_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_PMHD MAC Bridge Performance Monitoring History Data Managed Entity

    This Managed Entity collects performance monitoring data associated with a
    MAC bridge. Instances of this Managed Entity are created and deleted by the
    OLT.

    This Managed Entity is associated with one instance of a MAC bridge service
    profile.

    @{
*/

/** This structure holds the attributes of the MAC Bridge Performance
    Monitoring History Data Managed Entity.
*/
struct omci_me_mac_bridge_pmhd {
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

	/** Bridge learning entry discard count

	    This attribute counts forwarding database entries that have been or
	    would have been learned but were discarded or replaced due to lack
	    of space in the MAC address table or due to limitation by the port
	    learning limit.
	*/
	uint32_t bridge_learning_discard_count;

} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Performance
    Monitoring History Data Managed Entity.
*/
enum {
	omci_me_mac_bridge_pmhd_interval_end_time = 1,
	omci_me_mac_bridge_pmhd_thr_data_id = 2,
	omci_me_mac_bridge_pmhd_bridge_learning_discard_count = 3
};

/** @} */

/** @} */

__END_DECLS

#endif
