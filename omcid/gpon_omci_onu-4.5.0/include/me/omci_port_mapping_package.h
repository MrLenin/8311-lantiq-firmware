/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_port_mapping_package_h
#define _omci_port_mapping_package_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_PORT_MAPPING_PACKAGE Port Mapping Package Managed Entity

    This Managed Entity provides a way to map a heterogeneous set of physical
    path termination points (ports) to a parent equipment, which may be a
    cardholder or the ONT itself. It could be useful, for example, if a single
    plug-in circuit pack contained a PON ANI as port 1, a video UNI as port 2,
    and a craft UNI as port 3. It also provides an option for an integrated ONU
    to represent its ports without the use of virtual cardholders and virtual
    circuit packs. If the port mapping package is supported for the ONT as a
    whole, it is automatically created by the ONU. If the port mapping package
    is supported for plug-in circuit packs, it is created and destroyed by the
    ONU when the corresponding circuit pack is installed or pre-provisioned in a
    cardholder.

    A port mapping package may be contained by an ONU-G or a cardholder.

    Each port list contains a sequence of Managed Entity types. These Managed
    Entity type codes define what kind of PPTP or ANI corresponds to the
    specific port number.

    @{
*/

/** This structure holds the attributes of the Port Mapping Package
    Managed Entity.
*/

struct omci_me_port_mapping_package {
	/** Maximum Port Number

	    This attribute indicates the largest port number contained in the
	    port list attributes. Ports are numbered from 1 to this maximum,
	    possibly with embedded 0 entries, but no port may exist beyond the
	    maximum.

	    This value is application dependent.

	    This attribute is read-only by the OLT.
	*/
	uint8_t max_port_num;

	/** Each of the following attributes is a list of 8 ports, in
	    increasing port number sequence. Each list entry is a two-byte field
	    containing the Managed Entity type of the UNI or ANI corresponding
	    to the port number.
	    Placeholders for unused port numbers are indicated with the value 0.

	    The following types are supported:
	    - 0x000B Physical path termination point Ethernet UNI
	    - 0x0026 ANI
	    - 0x0035 Physical Path Termination Point POTS UNI

	    The attributes are read-only by the OLT.
	*/
	uint8_t port_list1[16];
	uint8_t port_list2[16];
	uint8_t port_list3[16];
	uint8_t port_list4[16];
	uint8_t port_list5[16];
	uint8_t port_list6[16];
	uint8_t port_list7[16];
	uint8_t port_list8[16];

} __PACKED__;

/** This enumerator holds the attribute numbers of the Port Mapping Package
    Managed Entity.
*/
enum {
	omci_me_port_mapping_package_max_port_num = 1,
	omci_me_port_mapping_package_port_list1 = 2,
	omci_me_port_mapping_package_port_list2 = 3,
	omci_me_port_mapping_package_port_list3 = 4,
	omci_me_port_mapping_package_port_list4 = 5,
	omci_me_port_mapping_package_port_list5 = 6,
	omci_me_port_mapping_package_port_list6 = 7,
	omci_me_port_mapping_package_port_list7 = 8,
	omci_me_port_mapping_package_port_list8 = 9
};

/** @} */

/** @} */

__END_DECLS

#endif
