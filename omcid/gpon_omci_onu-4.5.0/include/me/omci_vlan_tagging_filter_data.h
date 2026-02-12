/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_vlan_tagging_filter_data_h
#define _omci_vlan_tagging_filter_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_VLAN_TAGGING_FILTER_DATA VLAN Tagging Filter Data Managed Entity

    This Managed Entity organizes data associated with VLAN tagging.
    Instances of this Managed Entity are created and deleted by the OLT.
    An instance of this Managed Entity is associated with an instance of a MAC
    bridge port configuration data Managed Entity.

    @{
*/

/** This structure holds the attributes of the VLAN Tagging Filter Data
    Managed Entity.

    \remarks Each time a VLAN is added or removed, the broadcast configuration
             ("flood map") must be updated, because the flood map is configured
             per FID (which in turn depends on the configured VLAN(s)).
*/
struct omci_me_vlan_tagging_filter_data {
	/** VLAN Filter List

	    This attribute lists provisioned TCI (Tag Control Information)
	    values for the bridge port.
	    A TCI value (consisting of user priority, CFI and VID) is
	    represented by two bytes. 12 VLAN entries are supported. The first
	    N are valid, where N is given by the number of entries attribute.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t filter_list[12];

	/** Forwarding Operation

	    When a frame is received, it is processed according to the operation
	    specified by the forward operation table (see ITU-T G.984.4,
	    clause 9.3.11).

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t forwarding_oper;

	/** Number of Entries

	    This attribute specifies the number of valid entries in the VLAN
	    filter list.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t entries_num;

} __PACKED__;

/** This enumerator holds the attribute numbers of the VLAN Tagging Filter Data
    Managed Entity.
*/
enum {
	omci_me_vlan_tagging_filter_data_filter_list = 1,
	omci_me_vlan_tagging_filter_data_forward_oper = 2,
	omci_me_vlan_tagging_filter_data_entries_num = 3
};

/** @} */

/** @} */

__END_DECLS

#endif
