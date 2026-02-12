/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_gal_ethernet_pmhd_h
#define _omci_gal_ethernet_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_GAL_ETHERNET_PMHD GAL Ethernet Performance Monitoring History Data Managed Entity

    This Managed Entity collects performance monitoring data associated with a
    GEM interworking termination point when the GEM layer provides Ethernet
    service.

    Instances of this Managed Entity are created and deleted by the OLT.

    @{
*/

/** This structure holds the attributes of the GAL Ethernet Performance
    Monitoring History Data Managed Entity.
*/
struct omci_me_gal_ethernet_pmhd {
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

	/** Discarded Frames

	    This attribute counts the number of downstream GEM frames discarded
	    for any reason (erroneous FCS, too long length, buffer overflow, or
	    other).
	*/
	uint32_t discarded_frames;

} __PACKED__;

/** This enumerator holds the attribute numbers of the GAL Ethernet Performance
    Monitoring History Data Managed Entity.
*/
enum {
	omci_me_gal_ethernet_pmhd_inverval_end_time = 1,
	omci_me_gal_ethernet_pmhd_thr_data_id = 2,
	omci_me_gal_ethernet_pmhd_discaded_frames = 3
};

/** @} */

/** @} */

__END_DECLS

#endif
