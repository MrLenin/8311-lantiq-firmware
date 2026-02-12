/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_ani_g_h
#define _omci_ani_g_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_ANI_G ANI-G Managed Entity

    This Managed Entity organizes data associated with each access network
    interface supported by the ONT. The ONT automatically creates an instance
    of this Managed Entity for the PON physical port.

    @{
*/

/** This structure holds the attributes of the ANI-G Managed Entity.
*/
struct omci_me_ani_g {
	/** Status Reporting Indication

       This Boolean attribute indicates the ONT's capability to report queue
	    queue status for DBA. The value OMCI_TRUE means that status
	    reporting is available for all T-CONTs that are associated with the
	    ANI.

	    The default value is defined by the application the hardware
	    supports queue-based status reporting.

	    This attribute is read-only by the OLT.
	*/
	bool sr_indication;

	/** Total T-CONT Number

	    This attribute indicates the total number of T-CONTs that can be
	    supported on this ANI.

	    The maximum number of T-CONTS that are physically available is read
	    from a non-volatile memory.

	    This attribute is read-only by the OLT.
	*/
	uint16_t total_tcon_num;

	/** GEM Block Length

	    This attribute specifies the reporting block size for GEM mode, in
	    units of bytes. The value set by the OLT is used by all T-CONTs on
	    this ANI.  Upon Managed Entity instantiation, the ONT sets this
	    attribute to 48 (0x30).

	    This value is readable and writable by the OLT.
	*/
	uint16_t gem_block_len;

	/** Piggy-back Dynamic Bandwidth Allocation

       This attribute indicates the ONT's piggyback DBA reporting format
	    capabilities. G.984.3 defines two piggyback reporting modes.
	    - Reporting mode 0: The single field is the entire report.
	    - Reporting mode 1: The DBA report is two fields long.

	    Mode 0 is mandatory for ONTs that utilize the piggyback DBA
	    reporting method, modes 1 is optional. The supported modes are
	    application-dependent.

       The following coding indicates the ONT's piggyback DBA reporting mode
	    mode capabilities:

	    - 0x00 Mode 0 only
	    - 0x01 Modes 0 and 1
	    - 0x04 Piggyback DBA reporting not supported

	    The setting is defined by an NVM-based configuration parameter.

	    The attribute is read-only by the OLT.
	*/
	uint8_t piggyback_dba;

	/** Whole ONT DBA Reporting

	    This attribute is deprecated. It should be set to FALSE by the ONU
	    and ignored by the OLT.

	    The attribute is read-only by the OLT.
	*/
	bool whole_ont_dba_reporting;

	/** Signal Fail Threshold

	    This attribute specifies the downstream Bit Error Rate (BER)
	    threshold to detect the Signal Fail (SF) alarm. When this value is
	    y, the BER threshold is 10^-y. Valid values are from 0x03 to 0x08.
	    Upon Managed Entity  instantiation, the ONU sets this attribute to
	    0x05.

	    This value is readable and writable by the OLT.
	*/
	uint8_t sf_thr;

	/** Signal Degrade Threshold

	    This attribute specifies the downstream BER threshold to detect the
	    Signal Degrade (SD) alarm. When this value is x, the BER threshold
	    for SD is 10^-x. Valid values are from 0x04 to 0x0A. The SD
	    threshold must be lower than the SF threshold. Upon Managed Entity
	    instantiation, the ONU sets this attribute to 0x09.

	    This value is readable and writable by the OLT.
	*/
	uint8_t sd_thr;

	/** Alarm Reporting Control

	    This attribute allows the activation of alarm reporting control
	    (ARC) for this PPTP.

	    The attribute works in concert with the ARC_interval
	    attribute. A value of 0x00 indicates disable, while a value of
	    0x01 indicates enable. The default value is disabled.

	    When the ARC attribute is set to disabled (0x00), the PPTP is in
	    the "ALM" state, alarms are reported normally.
	    When the ARC attribute is set to enabled (0x01), the PPTP is in
	    the "NALM-QI" state, alarms are suppressed.

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
	    the timer never expires. The default value is 0x00.

	    This value can be read and modified by the OLT.
	 */
	uint8_t arc_interval;

	/** Optical Signal Level Downstream

	    This attribute reports the current measurement of total optical
	    signal level at 1490 nm (downstream wavelength). Its value is a 2s
	    complement integer referred to 1 mW (= dBm), with 0.002 dB
	    granularity.

	    The attribute is read-only by the OLT.
	*/
	uint16_t optical_signal_level;

	/** Lower Optical Threshold

	    This attribute specifies the optical level the ONU uses to declare
	    the 1490 nm low received optical power alarm. Valid values are
	    -127 dBm (coded as 0xFE) to 0 dBm (coded as 0x00) in 0.5 dB
	    increments.

	    The default value 0xFF selects the ONT's internal policy (disables
	    alarm declaration).

	    This value can be read and modified by the OLT.
	*/
	uint8_t lower_optical_thr;

	/** Upper Optical Threshold

	    This attribute specifies the optical level the ONU uses to declare
	    the 1490 nm high received optical power alarm. Valid values are
	    -127 dBm (coded as 0xFE) to 0 dBm (coded as 0x00) in 0.5 dB
	    increments.

	    The default value 0xFF selects the ONT's internal policy (disables
	    alarm declaration).

	    This value can be read and modified by the OLT.
	*/
	uint8_t upper_optical_thr;

	/** ONT Response Time

	    This attribute indicates actual ONT response time recorded by ONT.

	    The range of this attribute should is the range of 34 to 36
	    microseconds.
	    The unit is nanoseconds. Valid values are:
	    - 0x0000: function not supported
	    - 0x84D0 (34000) to 8CA0 (36000): response time in nanoseconds

	    The default value is 35000 ns.
	    The attribute is read-only by the OLT.
	*/
	uint16_t ont_response_time;

	/** Transmit Optical Level

	    This attribute reports the current measurement of optical transmit
	    power level. Its value is a 2s complement integer referred to 1 mW
	    (= dBm), with 0.002 dB granularity.
	    The attribute is read-only by the OLT.
	*/
	uint16_t transmit_optical_level;

	/** Lower Transmit Power Threshold

	    This attribute specifies the optical level the ONU uses to declare
	    the low transmit optical power alarm. Its value is a 2s complement
	    integer referred to 1 mW (= dBm), with 0.5 dB granularity.
       The default value of -63.5 dBm (0x81) selects the ONT's internal policy
	    policy (this disables the alarm declaration).

	    This value can be read and modified by the OLT.
	*/
	uint8_t lower_transmit_power_thr;

	/** Upper Transmit Power Threshold

	    This attribute specifies the optical level the ONU uses to declare
	    the high transmit optical power alarm. Its value is a 2s complement
	    integer referred to 1 mW (= dBm), with 0.5 dB granularity. The
       value of -63.5 dBm (0x81) selects the ONT's internal policy (disables
	    (disables alarm declaration).

	    This value can be read and modified by the OLT.
	*/
	uint8_t upper_transmit_power_thr;

} __PACKED__;

/** This enumerator holds the attribute numbers of the ANI-G Managed Entity.
*/
enum {
	omci_me_ani_g_sr_indication = 1,
	omci_me_ani_g_total_tcont_num = 2,
	omci_me_ani_g_gem_block_len = 3,
	omci_me_ani_g_piggyback_dba = 4,
	omci_me_ani_g_whole_ont_dba_reporting = 5,
	omci_me_ani_g_sf_thr = 6,
	omci_mE_ani_g_sd_thr = 7,
	omci_me_ani_g_arc = 8,
	omci_me_ani_g_arc_interval = 9,
	omci_me_ani_g_optical_signal_level = 10,
	omci_me_ani_g_lower_optical_thr = 11,
	omci_me_ani_g_upper_optical_thr = 12,
	omci_me_ani_g_ont_response_time = 13,
	omci_me_ani_g_transmit_optical_level = 14,
	omci_me_ani_g_lower_transmit_power_thr = 15,
	omci_me_ani_g_upper_transmit_power_thr = 16
};

/** @} */

/** @} */

__END_DECLS

#endif
