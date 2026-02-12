/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_pptp_ethernet_uni_h
#define _omci_pptp_ethernet_uni_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_PPTP_ETHERNET_UNI PPTP Ethernet UNI Managed Entity

    The Physical Path Termination Point (PPTP) Ethernet User Network Interface
    (UNI) Managed Entity represents the point at an Ethernet UNI where the
    physical path terminates and Ethernet physical level functions are
    performed.

    The ONT automatically creates an instance of this Managed Entity per
    physical Ethernet port.

    The number and type of available Ethernet ports depends on the device
    version that is indicated by fuses.

    The handling of pluggable cardholder units is not supported by this
    software.

    @{
*/

/** This structure hold the attributes of the PPTP Ethernet UNI
    Managed Entity.
*/
struct omci_me_pptp_ethernet_uni {
	/** Expected Ethernet UNI Type

	    This attribute supports Ethernet pre-provisioning.
	    The following code points are supported:
	    - 0: Autosense (the interface type is stored in NVM)
	    - 22: 10BASE-T (fixed rate of 10 Mbit/s)
	    - 23: 100BASE-T (fixed rate of 100 Mbit/s)
	    - 24: 10/100BASE-T (selectable rate of 10 or 100 Mbit/s)
	    - 47: 10/100/1000BASE-T (selectable rate of 10, 100, or 1000 Mbit/s)

	    Upon instantiation, a value of 0x00 is set.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t expected_type;

	/** Sensed Ethernet UNI Type

	    This attribute represents the type as one of the values defined for
	    \ref expected_type. If the value of the expected type is not 0x00,
	    then the value of the sensed type should be the same as the value of
	    the expected type.

	    Upon instantiation, the ONT sets this attribute to 0x00.

	    This attribute is read-only by the OLT.
	*/
	uint8_t sensed_type;

	/** Automatic Ethernet UNI Type Detection Configuration

	    This attribute sets the Ethernet port configuration. The following
	    code points are supported:

	    \verbatim
	    Codepoint  Rate        Duplex
	    - 0x00       Auto        Auto
	    - 0x01       10M only    Full duplex only
	    - 0x02       100M only   Full duplex only
	    - 0x03       1000M only  Full duplex only - if the physical port is
	    1000M capable
	    - 0x04       Auto        Full duplex only
	    - 0x10       10M only    Auto
	    - 0x11       10M only    Half duplex only
	    - 0x12       100M only   Half duplex only
	    - 0x13       1000M only  Half duplex only - if the physical port is
	    1000M capable
	    - 0x14       Auto        Half duplex only
	    - 0x20       1000M only  Auto             - if the physical port is
	    1000M capable
	    - 0x30       100M only   Auto
	    \endverbatim

	    The hardware programming is related to the Ethernet PHY module,
	    which is controlled through standard IEEE control registers. The
	    following registers need to be configured:

	    \verbatim
	    MDIO address - Register Name - Bit Name - Usage
	    -------------------------------------------------------------------
	    - 0x00         - CTRL          - SSM      - forced speed selection
	    - 0x00         - CTRL          - SSL      - forced speed selection
	    - 0x00         - CTRL          - DPLX     - forced duplex mode
	    selection
	    - 0x04         - AN_ADV        - TAF      - capability advertising
	    - 0x09         - GCTRL         - MBTHD    - capability advertising
	    - 0x09         - GCTRL         - MBTFD    - capability advertising
	    \endverbatim

	    Upon instantiation, the ONT sets this attribute to 0x00.

	    This attribute is read-only by the OLT.
	*/
	uint8_t auto_detect_config;

	/** Ethernet UNI Loopback Configuration

	    This attribute sets the Ethernet loopback configuration. The
	    following code points are supported:
	    - 0x00: No loopback (normal operation)
	    - 0x03: Loopback of downstream traffic after the PHY transceiver.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t ether_loopback_config;

	/** Administrative State

	    This attribute locks (0x01) and unlocks (0x00) the functions
	    performed by this Managed Entity. When the administrative state is
	    set to lock, all user functions are blocked, and alarms, TCAs and
	    AVCs for this Managed Entity and all dependent Managed Entities are
	    no longer generated.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This value can be read and modified by the OLT.
	*/
	uint8_t admin_state;

	/** Operational State

	    This attribute reports whether the Managed Entity is currently
	    capable of performing its function. Valid values are
	    OMCI_OPERATIONAL_STATE_ENABLED (0x00) and
	    OMCI_OPERATIONAL_STATE_DISABLED (0x01).

	    The default value of this attribute is read from a non-volatile
	    memory.

	    It is set to OMCI_OPERATIONAL_STATE_ENABLED
	    as soon as all other attributes as well as the directly related
	    Managed Entities are defined and can be accessed by the OLT.

	    This attribute is read-only by the OLT.
	*/
	uint8_t oper_state;

	/** Ethernet UNI Configuration Status Indication

	    This attribute indicates the configuration status of the
	    Ethernet UNI.

	    The value 0x00 indicates that the configuration status is unknown
	    (for example, the Ethernet link is not established or the circuit
	    pack is not yet installed). Upon Managed Entity instantiation, the
	    ONT sets this attribute to 0x00.

	    The following values are supported:
	    - 0x01 10BASE-T full duplex
	    - 0x02 100BASE-T full duplex
	    - 0x03 1000BASE-T full duplex
	    - 0x11 10BASE-T half duplex
	    - 0x12 100BASE-T half duplex
	    - 0x13 1000BASE-T Ethernet half duplex

	    This attribute is read-only by the OLT.
	*/
	uint8_t config_ind;

	/** Maximum Ethernet Frame Size

	    This attribute denotes the maximum frame size allowed across this
	    interface.

	    Upon Managed Entity instantiation, the ONT sets the
	    attribute to a value of 1518.

	    This value can be read and modified by the OLT.
	*/
	uint16_t max_frame_size;

	/** DTE/DCE Type Indication

	    This attribute specifies the Ethernet interface wiring.

	    This setting influences the hardware configuration if the interface
	    type is MII. If DCE is selected the MII interface is set to PHY mode
	    (generating the clock) while for DTE the MII interface is set to MAC
	    mode (receiving the clock).

	    The supported values are:
	    - 0x00 DCE (default setting)
	    - 0x01 DTE

	    This value can be read and modified by the OLT.

	    \remarks The MII interface is typically used for on-board
	    connections, so the MAC/PHY setting is defined by the application
	    and shall not be changed by the OLT.
	*/
	uint8_t dte_dce_ind;

	/** Ethernet Pause Time

	    This attribute allows the PPTP to ask the subscriber terminal to
	    temporarily suspend sending data.

	    Units are in pause quanta (1 pause quantum is 512 bit times of the
	    particular implementation).

	    The valid value range is from 0x0000 to 0xFFFF.
	    Upon Managed Entity instantiation, the ONT sets this attribute to
	    0x0000.

	    \remarks The MAC hardware needs to be programmed according to this
	    value.
	    The hardware supports only a value of 0xFFFF.
	*/
	uint16_t pause_time;

	/** Bridge/Router Indication

	    This attribute specifies whether the Ethernet interface is bridged
	    or derived from an IP router function.

	    The supported values are:
	    - 0x00 Bridged (this is the only mode that is supported)
	    - 0x01 IP router (not supported)
	    - 0x02 Depends on the parent circuit pack. It means that the circuit
	    pack's attribute is either 0x00 or 0x01.
	*/
	uint8_t bridged_ip_ind;

	/** ARC

	    This attribute allows the activation of alarm reporting
	    control (ARC) for this PPTP.

	    The attribute works in concert with the ARC_interval
	    attribute. A value of 0x00 indicates disable, while a value of 0x01
	    indicates enable.

	    The default value is disabled.

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

	/** ARC Interval

	    This attribute defines the interval to be used with the ARC function
	    for this PPTP. The values 0x00 through 0xFE give the duration in
	    minutes for the NALM-QI timer. The special value of 0xFF means that
	    the timer never expires.

	    The default value is 0x00.

	    This value can be read and modified by the OLT.
	*/
	uint8_t arc_interval;

	/** PPPoE Filter Setting

	    This attribute controls filtering of PPPoE packets on this Ethernet
	    port.

	    The value 0x00 (OMCI_FALSE) allows packets of all types.
	    The value 0x01 (OMCI_TRUE) discards everything but PPPoE
	    packets.

	    The default value is 0x00.

	    \remarks If discard mode is selected, the SCE hardware needs to be
	    programmed to discard frames that are not PPPoE frames.

	    This value can be read and modified by the OLT.
	*/
	bool pppoe_filter;

	/** Power-over-Ethernet Control

	    This attribute controls whether power is provided to an external
	    equipment over the Ethernet PPTP.

	    The value 0x01 enables power over the Ethernet port.
	    The default value of 0x00 disables power feed.

	    The support of this function depends on the application, indicated
	    by a value stored in an external memory.

	    This value can be read and modified by the OLT.
	*/
	bool power_control;

} __PACKED__;

/** This enumerator holds the attribute numbers of the PPTP Ethernet UNI
    Managed Entity.
*/
enum {
	omci_me_pptp_ethernet_uni_expected_type = 1,
	omci_me_pptp_ethernet_uni_sensed_type = 2,
	omci_me_pptp_ethernet_uni_auto_detect_config = 3,
	omci_me_pptp_ethernet_uni_ether_loopback_config = 4,
	omci_me_pptp_ethernet_uni_admin_state = 5,
	omci_me_pptp_ethernet_uni_oper_state = 6,
	omci_me_pptp_ethernet_uni_config_ind = 7,
	omci_me_pptp_ethernet_uni_max_frame_size = 8,
	omci_me_pptp_ethernet_uni_dte_dce_ind = 9,
	omci_me_pptp_ethernet_uni_pause_time = 10,
	omci_me_pptp_ethernet_uni_bridged_ip_ind = 11,
	omci_me_pptp_ethernet_uni_arc = 12,
	omci_me_pptp_ethernet_uni_arc_interval = 13,
	omci_me_pptp_ethernet_uni_pppoe_filter = 14,
	omci_me_pptp_ethernet_uni_power_control = 15
};

/** This enumerator holds supported alarms of the PPTP Ethernet UNI
    Managed Entity.
*/
enum {
	omci_me_pptp_ethernet_uni_alarm_lan_los = 0
};

/** @} */

/** @} */

__END_DECLS

#endif
