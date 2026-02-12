/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_equipment_extension_package_h
#define _omci_equipment_extension_package_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_EQUIPMENT_EXTENSION_PACKAGE Optical Equipment Extension Package Managed Entity

    This Managed Entity supports optional extensions to circuit pack Managed
    Entities. If the circuit pack supports these features, the ONT creates and
    deletes this Managed Entity along with its associated real or virtual
    circuit pack.

    An equipment extension package may be contained by an ONT-G or cardholder.

    The implementation of this Managed Entity is application specific, using
    the GPIO interface.

    @{
*/

/** This structure holds the attributes of the Equipment Extension Package
    Managed Entity.
*/
struct omci_me_equipment_extension_package {
	/** Environmental Sense

	    This attribute provisions an ONU that supports external sense
	    points, for example physical security detectors at an enclosure.
	    Each pair of bits is defined as follows:
	    - 00 Sense point disabled (default)
	    - 01 Report contact closure
	    - 10 Report contact open
	    - 11 Sense point disabled (same as 00)
	    If the byte is represented in binary as 0b hhgg ffee ddcc bbaa,
	    bits hh correspond to sense point 1, while bits aa correspond to
	    sense point 8.

	    Each of these function uses a single GPIO pin in input mode.

	    \remarks Some specific sense point applications are already defined
       ONT-G Managed Entity. It is the vendor's choice how to configure and
	    configure and report sense points that appear both generically and
	    specifically.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t environmental_sense;

	/** Contact Closure Output

	    This attribute provisions an ONU that supports external contact
	    closure outputs, for example sump pump or air conditioner activation
	    at an ONU enclosure. A contact point is said to be released when it
	    is not energized. Whether this corresponds to an open or a closed
       circuit depends on the ONT's wiring options. Upon ONT initialization, all
	    initialization, all contact points should go to the released state.

	    If the byte is represented in binary as 0b hhgg ffee ddcc bbaa, bits
	    hh correspond to contact output point 1, while bits aa correspond to
	    contact output point 8.

	    On write, the bits of this attribute have the following meaning:
	    - 0x No change to contact output point state
	    - 10 Release contact output point
	    - 11 Operate contact output point

	    On read, the left bit in each pair should be set to 0 at the ONU and
	    ignored at the OLT. The right bit indicates a released output point
	    with 0 and an operated point with 1.

	    Each of these function uses a single GPIO pin in output mode.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t contact_closure_output;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Equipment Extension
   Package Managed Entity.
*/
enum {
	omci_me_equipment_extension_package_environmental_sense = 1,
	omci_me_equipment_extension_package_contact_closure_output = 2
};

/** @} */

/** @} */

__END_DECLS

#endif
