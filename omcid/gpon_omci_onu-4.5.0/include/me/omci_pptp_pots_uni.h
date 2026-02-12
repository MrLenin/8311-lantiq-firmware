/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_pptp_pots_uni_h
#define _omci_pptp_pots_uni_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_PPTP_POTS_UNI PPTP POTS UNI Managed Entity

    The Physical Path Termination Point (PPTP) POTS User Network Interface
    (UNI) Managed Entity represents the point at a POTS UNI where the
    physical path terminates and POTS physical level functions are
    performed.

    The ONT automatically creates an instance of this Managed Entity per
    physical POTS port.

    The number and type of available POTS ports depends on the device
    version that is indicated by fuses.

    @{
*/

/** This structure hold the attributes of the PPTP POTS UNI
    Managed Entity.
*/
struct omci_me_pptp_pots_uni {
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

	/** Interworking TP Pointer

	    This attribute points to the associated instance of the GEM
	    interworking termination point managed entity.
	    The value 0x0000 0000 is a null pointer.
	    This value can be read and modified by the OLT.
	    */
	uint16_t interworking_tp_ptr;

	/** ARC

	    This attribute allows the activation of alarm reporting control
	    (ARC) for this PPTP.

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

	/** Impedance

	    This attribute specifies the impedance for the POTS UNI. Valid
	    values include:
	    - 0x00: 600 Ohm (default upon Managed Entity instantiation)
	    - 0x01: 900 Ohm
	    - 0x02: C1 = 150 nF, R1 =  750 Ohm, R2 = 270 Ohm
	    - 0x03: C1 = 115 nF, R1 =  820 Ohm, R2 = 220 Ohm
	    - 0x04: C1 = 230 nF, R1 = 1050 Ohm, R2 = 320 Ohm
	    - 0x05 to 0xFF: reserved
	    This value can be read and modified by the OLT.
	*/
	uint8_t impedance;

	/** Transmission Path
	    This attribute allows setting the POTS UNI either to full-time
	    on-hook transmission (0x00) or part-time on-hook transmission
	    (0x01). Upon ME instantiation, the ONT sets this attribute to 0x00.
	    This value can be read and modified by the OLT.
	*/
	uint8_t transmission_path;

	/** Receive Gain
	    This attribute specifies a gain value for the received signal in
	    the form of a 2s complement number. Valid values are -120
	    (-12.0 dB) to 60 (+6.0 dB). Upon ME instantiation, the ONT sets
	    this attribute to 0x00.
	    This value can be read and modified by the OLT.
	*/
	uint8_t rx_gain;

	/** Transmit Gain
	    This attribute specifies a gain value for the transmit signal in
	    the form of a 2s complement number. Valid values are -120
	    (-12.0 dB) to 60 (+6.0 dB). Upon ME instantiation, the ONT sets
	    this attribute to 0x00.
	    This value can be read and modified by the OLT.
	*/
	uint8_t tx_gain;

	/** Operational State

	    This attribute reports whether the managed entity is currently
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

	/** Hook State
	    This attribute indicates the current state of the subscriber line:
	    - 0x00 = on hook
	    - 0x01 = off hook
	    This value can be read and modified by the OLT.
	*/
	uint8_t hook_state;

	/** POTS Holdover Time
	    This attribute determines the time during which POTS loop voltage
	    is held up when the ONT is not ranged on the PON. After the
	    specified time elapses, the ONT drops loop voltage, and may thereby
	    cause premises intrusion alarm circuits to go active. When the ONT
	    ranges successfully on the PON, it restores POTS loop voltage
	    immediately and resets the timer to zero. The attribute is
	    expressed in seconds. The default value 0x0000 selects the vendor's
	    factory policy.
	    This value can be read and modified by the OLT.
	*/
	uint16_t pots_holdover_time;

} __PACKED__;

/** This enumerator holds the attribute numbers of the PPTP POTS UNI
    Managed Entity.
*/
enum {
	omci_me_pptp_pots_uni_admin_state = 1,
	omci_me_pptp_pots_uni_interworking_tp_ptr = 2,
	omci_me_pptp_pots_uni_arc = 3,
	omci_me_pptp_pots_uni_arc_interval = 4,
	omci_me_pptp_pots_uni_impedance = 5,
	omci_me_pptp_pots_uni_transmission_path = 6,
	omci_me_pptp_pots_uni_rx_gain = 7,
	omci_me_pptp_pots_uni_tx_gain = 8,
	omci_me_pptp_pots_uni_oper_state = 9,
	omci_me_pptp_pots_uni_hook_state = 10,
	omci_me_pptp_pots_uni_pots_holdover_time = 11
};

/** @} */

/** @} */

__END_DECLS

#endif
