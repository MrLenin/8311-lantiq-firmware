/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_cardholder_h
#define _omci_cardholder_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_CARDHOLDER Cardholder Managed Entity

    The Cardholder represents the fixed equipment slot configuration of the
    ONU. One or more of these entities is contained in the ONU. Each Cardholder
    can contain 0 or 1 circuit packs. The circuit pack models equipment
    information that can change over the lifetime of the ONU, for example
    through replacement.

    An instance of this Managed Entity exists for each physical slot in an ONU
    that has pluggable circuit packs. One or more instances of this Managed
    Entity may also exist in an integrated ONU, to represent virtual slots.

    Instances of this Managed Entity are created automatically by the ONU, and
    the status attributes are populated according to data within the ONU itself.

    This implementation supports only integrated ONUs with a single virtual
    slot.

    \remarks To indicate that this is an integrated ONU with one or more virtual
    slots the first byte of the Managed Entity ID is set to 0x01 and the
    second byte is set to the virtual slot number.

    @{
*/

/** This structure holds the attributes of the Cardholder Managed Entity.
*/
struct omci_me_cardholder {
	/** Actual Plug-in Type

	    This attribute is equal to the type of the circuit pack in the
	    Cardholder or 0x00 if the Cardholder is empty. This attribute is
	    then redundant with the type attribute of the circuit pack Managed
	    Entity.

	    This attribute is read-only by the OLT.
	*/
	uint8_t actual_plugin_type;

	/*
	   The three following attributes permit the OLT to specify its
	   intentions for future equipage of a slot. Once some or all of these
	   are set, the ONU can proceed to instantiate circuit pack and PPTP
	   MEs, along with other predeterminable MEs, and allow the OLT to
	   create related discretionary MEs, thereby supporting service
	   preprovisioning.
	*/

	/** Expected Plug-in Type

	    This attribute provisions the type of circuit pack for the slot.

	    The value 0x00 means that the Cardholder is not provisioned to
	    contain a circuit pack. The value 0xFF means that the Cardholder is
	    configured for plug and play. Upon ME instantiation, the ONU sets
	    this attribute to 0x00.
	    For integrated interfaces, this attribute may be used to represent
	    the type of interface.

	    Although this attribute is marked read-write, the integrated ONT
	    should deny attempts to change its value.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t expected_plugin_type;

	/** Expected Port Count

	    This attribute permits the OLT to specify the number of ports it
	    expects in a circuit pack. Prior to provisioning by the OLT, the ONU
	    initializes this attribute to 0x00.

	    This attribute is readable and writable by the OLT.

	    As with the expected plug-in type, which is also read-write, an
	    integrated ONT should deny an attempt to change the value of this
	    attribute.

	    \remarks If the OLT tries to define more ports than are physically
	    available, this shall be refused.
	*/
	uint8_t expected_port_count;

	/** Expected Equipment ID

	    This attribute provisions the specific type of expected circuit
	    pack.

	    This attribute applies only to ONUs that do not have integrated
	    interfaces.
	    In North America, this may be the expected equipment CLEI code.
	    Upon Managed Entity instantiation, the ONU sets this attribute to
	    all spaces.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t expected_equipment_id[20];

	/** Actual Equipment ID

	    This attribute identifies the specific type of circuit pack, once
	    it is installed. This attribute applies only to ONUs that do not
	    have integrated interfaces. In North America, this may be the
	    equipment CLEI code. When the slot is empty or the equipment ID is
	    not known, this attribute should be set to all spaces.
	    This attribute is read-only by the OLT.

	    \remarks This value is always set to all spaces, because we support
	    only integrated interfaces.
	*/
	uint8_t actual_equipment_id[20];

	/** Protection Profile Pointer

	    This attribute indicates an equipment protection profile that
	    may be associated with the Cardholder. Its value is the least
	    significant byte of the Managed Entity id of the equipment
	    protection profile with which it is associated, or 0x00 if equipment
	    protection is not used.  This attribute is read-only by the OLT.

	    \remarks This value is always set to 0x00, equipment protection is
	    not supported.
	*/
	uint8_t protection_profile_ptr;

	/** Invoke Protection Switch

	    The OLT may use this attribute to control equipment protection
	    switching.

	    This attribute is readable and writable by the OLT.

	    \remarks As equipment protection is not supported, the ONU shall
	    deny any protection switching attempt by the OLT.
	*/
	uint8_t invoke_protection_switch;

	/** Alarm Reporting Control

	    This attribute allows the activation of alarm reporting control
	    (ARC) for this PPTP.

	    The attribute works in concert with the ARC_interval
	    attribute. A value of 0x00 indicates disable, while a value of 0x01
	    indicates enable. The default value is disabled.

	    When the ARC attribute is set to disabled (0x00), the PPTP is in the
	    "ALM" state, alarms are reported normally.
	    When the ARC attribute is set to enabled (0x01), the PPTP is in the
	    "NALM-QI" state, alarms are suppressed.

	    The PPTP moves from the ALM state to the NALM-QI state when the OLT
	    changes the ARC attribute to enabled. The PPTP moves from the
	    NALM-QI state to the ALM state when either 1) the PPTP is trouble
	    free and the ARC_interval timer expires, or 2) the ARC attribute is
	    set to disable by the OLT. If the ARC_interval timer expires, the
	    ONT sets the ARC attribute to disabled autonomously, and sends an
	    AVC to notify the OLT.

	    This value can be read and modified by the OLT.
	*/
	uint8_t arc;

	/** Alarm Reporting Interval

	    This attribute defines the interval to be used with the ARC function
	    for this PPTP. The values 0x00 through 0xFE give the duration in
	    minutes for the NALM-QI timer. The special value of 0xFF means that
	    the timer never expires.

	    The default value is 0x00.

	    This value can be read and modified by the OLT.
	*/
	uint8_t arc_interval;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Cardholder Managed
   Entity.
*/
enum {
	omci_me_cardholder_actual_plugin_type = 1,
	omci_me_cardholder_expected_plugin_type = 2,
	omci_me_cardholder_expected_port_count = 3,
	omci_me_cardholder_expected_equipment_id = 4,
	omci_me_cardholder_actual_equipment_id = 5,
	omci_me_cardholder_protection_profile_ptr = 6,
	omci_me_cardholder_invoke_protection_switch = 7,
	omci_me_cardholder_arc = 8,
	omci_me_cardholder_arc_interval = 9
};

/** @} */

/** @} */

__END_DECLS

#endif
