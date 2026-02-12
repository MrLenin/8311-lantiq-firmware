/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_uni_g_h
#define _omci_uni_g_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_UNI_G UNI-G Managed Entity

    The UNI-G Managed Entity organizes data associated with User Network
    Interfaces (UNIs).

    One instance of the UNI-G Managed Entity exists for each UNI supported
    by the ONT. The ONT automatically creates or deletes instances of this
    Managed Entity upon the creation or deletion of a real or virtual Circuit
    Pack Managed Entity, one per port.

    Through an identical ID, this Managed Entity is implicitly linked to an
    instance of a physical path termination point.

    @{
*/

/** This structure holds the attributes of the UNI-G Managed Entity.
*/
struct omci_me_uni_g {
	/** Configuration Option Status

	    This attribute holds the UNI configuration code field.

	    Each of the 16 bit positions has a dedicated function:
	    - Bit 0: N/A
	    - Bit 1: Server trail fault propagation TC layer
	    - Bit 2: Server trail fault propagation PHY layer
	    - Bit 3: Server trail fault propagation GAL layer
	    - Bit 4 to 15: Reserved

	    A value of 0b0 inhibits alarm reporting through the OMCC, a value
	    of 0b1 enables alarm reporting through the OMCC for the related
	    layer.

	    The default value is 0x0000.

	    The attribute is readable and writable by the OLT.
	*/
	uint16_t config_option_status;

	/** Administrative State

	    This attribute locks (0x01) and unlocks (0x00) the functions
	    performed by this Managed Entity.

	    When the administrative state is set to lock, all user functions of
	    this Managed Entity are blocked, and alarms, TCAs, and AVCs for
	    this Managed Entity and all dependent Managed Entities are no
	    longer generated.

	    The default value is 0x00.

	    The attribute is readable and writable by the OLT.
	*/
	uint8_t admin_state;

#ifdef INCLUDE_G984_4_AMENDMENT_2
	/** Management capability

	    An ONU may support the ability for some or all of its PPTPs to
	    be managed either directly by OMCI or from non-OMCI management
	    environment such as TR-69. This attribute advertises the ONU's
	    capabilities for each PPTP.

	    This attribute is an enumeration with the following code points:
	    - 0 OMCI only
	    - 1 Non-OMCI only. In this case, the PPTP may be visible to OMCI,
	        but only in a read-only sense, eg for PM collection.
	    - 2 Both OMCI and non-OMCI
	*/
	uint8_t mgmt_capability;
	/** Non-OMCI management identifier

	    If a PPTP can be managed either directly by OMCI or a non-OMCI
	    management environment, this attribute specifies how it is in
	    fact to be managed.

	    This attribute is either 0 (default = OMCI management),
	    or it is a pointer to a virtual Ethernet interface point,
	    which in turn links to a non-OMCI management environment.
	 */
	uint16_t non_omci_mgmg_id;
#endif
} __PACKED__;

/** This enumerator holds the attribute numbers of the UNI-G Managed Entity.
*/
enum {
	omci_me_uni_g_config_option_status = 1,
	omci_me_uni_g_admin_state = 2
};

/** @} */

/** @} */

__END_DECLS

#endif
