/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_olt_g_h
#define _omci_olt_g_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_OLT_G OLT-G Managed Entity

    This Managed Entity identifies the OLT to which an ONT is connected.
    It provides a way for the ONT to configure itself for operability with a
    particular OLT.

    An ONU that supports this Managed Entity automatically creates an
    instance of it. Immediately following the startup phase, the OLT should
    set the ONU to the desired configuration. Interpretation of the attributes
    is a matter of negotiation between the two vendors involved.

    @{
*/

/** This structure holds the attributes of the OLT-G Managed Entity.
*/
struct omci_me_olt_g {
	/** OLT Vendor ID

	    This attribute identifies the OLT vendor. It is the same as the four
	    most significant bytes of an ONU serial number specified in G.984.3.
	    Upon instantiation, this attribute comprises all spaces.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t olt_vendor_id[4];

	/** OLT Equipment ID

	    This attribute may be used to identify the specific type of OLT.
	    The default value of all spaces indicates that equipment ID
	    information is not available or applicable to the OLT being
	    represented.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t olt_equipment_id[20];

	/** OLT Version

	    This attribute identifies the version of the OLT as defined by the
	    vendor.
	    The default left-justified ASCII string "0" (padded with trailing
	    nulls) indicates that version information is not available or
	    applicable to the OLT being represented.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t olt_version[14];

#ifdef INCLUDE_G984_4_AMENDMENT_2
	/** Time of day information

	    This attribute provides the information required to achieve time of
	    day synchronization between a reference clock at the OLT and a
	    local clock at the ONT. This attribute comprises two fields: the
	    first field (4 bytes) is the sequence number of the specified GEM
	    superframe. The second field (10 bytes) is TstampN as defined in
	    G.984.3, clause 10.4.6, using the timestamp format of
	    IEEE 1588-2008, clause 5.3.3. The value 0 in all bytes
	    is reserved as a null value.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t tod_info[14];
#endif

} __PACKED__;

/** This enumerator holds the attribute numbers of the OLT-G Managed Entity. */
enum {
	omci_me_olt_g_olt_vendor_id = 1,
	omci_me_olt_g_olt_equipment_id = 2,
	omci_me_olt_g_olt_version = 3
};

/** @} */

/** @} */

__END_DECLS

#endif
