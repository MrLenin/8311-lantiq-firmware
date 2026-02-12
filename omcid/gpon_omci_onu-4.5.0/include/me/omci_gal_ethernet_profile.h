/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_gal_ethernet_profile_h
#define _omci_gal_ethernet_profile_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_GAL_ETHERNET_PROFILE GAL Ethernet Profile Managed Entity

    This Managed Entity organizes data that describes the GTC adaptation layer
    processing functions of the ONU for Ethernet services. It is used with the
    GEM interworking termination point Managed Entity.
    Instances of this Managed Entity are created and deleted on request of the
    OLT. An instance may be associated with zero or more instances of the
    GEM interworking termination point Managed Entity.

    @{
*/

/** This structure holds the attributes of the GAL Ethernet Profile
    Managed Entity.
*/
struct omci_me_gal_ethernet_profile {
	/** Maximum GEM Payload Size

	    This attribute defines the maximum payload size generated in the
	    associated GEM interworking termination point Managed Entity.
	    This value limits the size of GEM frames that are generated in
	    upstream direction (from the ONU to the OLT).
	*/
	uint16_t max_gem_payload_size;

} __PACKED__;

/** This enumerator holds the attribute numbers of the GAL Ethernet Profile
    Managed Entity.
*/
enum {
	omci_me_gal_ethernet_profile_max_gem_payload_size = 1
};

/** @} */

/** @} */

__END_DECLS

#endif
