/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_onu_power_shedding_h
#define _omci_onu_power_shedding_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_ONU_POWER_SHEDDING ONU Power Shedding Managed Entity

    This Managed Entity models the ONU's ability to shed services when the ONU
    goes into battery operation mode after AC power failure or manual shut-off.
    Shedding classes are defined, which may span multiple circuit pack types.
    This feature works in conjunction with the power shed override attribute of
    the circuit pack Managed Entity, which can selectively prevent power
    shedding of priority ports.

    An ONU that supports power shedding automatically creates an instance of
    this Managed Entity.

    The support is application dependent.

    @{
*/

/** This structure holds the attributes of the ONU Power Shedding
    Managed Entity.
*/
struct omci_me_onu_power_shedding {
	/** Restore Power Timer Reset Interval

	    The time delay, in seconds, before resetting shedding timers after
	    full power restoration. Upon Managed Entity instantiation, the ONU
	    sets this attribute to 0x0000.
	    This attribute is readable and writable by the OLT.
	*/
	uint16_t restore_power_timer_interval;

	/*
	   For each type of service, an interval attribute is defined below. The
	   value 0x0000 disables power shedding, while the value 0x0001 enables
	   immediate power shed, that is, as soon as AC power fails. Other values
	   specify the time, in seconds, to keep the service active after AC failure
	   before shutting them down and shedding power. Upon Managed Entity
	   instantiation, the ONU sets each of the interval attributes to 0x0000.
	*/

	/** Data Power Shedding Interval
	    This attribute is readable and writable by the OLT.
	*/
	uint16_t data_power_shed_interval;

	/** Voice Power Shedding Interval
	    This attribute is readable and writable by the OLT.
	*/
	uint16_t voice_power_shed_interval;

	/** Video Overlay Power Shedding Interval
	    This attribute is readable and writable by the OLT.
	*/
	uint16_t video_overlay_power_shed_interval;

	/** Video Return Power Shedding Interval
	    This attribute is readable and writable by the OLT.
	*/
	uint16_t video_return_power_shed_interval;

	/** DSL Power Shedding Interval

	    DSL applications are not supported.
	    This attribute is readable and writable by the OLT.
	*/
	uint16_t dsl_power_shed_interval;

	/** ATM Power Shedding Interval

	    This attribute is readable and writable by the OLT.
	    ATM applications are not supported.
	*/
	uint16_t atm_power_shed_interval;

	/** CES Power Shedding Interval

	    This attribute is readable and writable by the OLT.
	    CES applications are not supported.
	*/
	uint16_t ces_power_shed_interval;

	/** Frame Power Shedding Interval

	    This attribute is readable and writable by the OLT.
	    Frame applications are not supported.
	*/
	uint16_t frame_power_shed_interval;

	/** SONET Power Shedding Interval

	    This attribute is readable and writable by the OLT.
	    SONET applications are not supported
	*/
	uint16_t sonet_power_shed_interval;

	/** Power Shedding Status

	    Boolean indication of power shedding status for each shedding type.
	    If this two-byte field is depicted 0b ABCD EFGH IJKL MNOP, its bits
	    are assigned:
	    - A Data
	    - B Voice
	    - C Video overlay
	    - D Video return path
	    - E DSL (= 0b0)
	    - F ATM (= 0b0)
	    - G CES (= 0b0)
	    - H Frame (= 0b0)
	    - I SONET (= 0b0)
	    - J..P reserved (= 0b0)

	    The ONU sets each bit when power shedding is active, and clears it
	    when the service is restored.

	    This attribute is read-only by the OLT.
	*/
	uint16_t power_shed_status;

} __PACKED__;

/** This enumerator holds the attribute numbers of the ONU Power Shedding
    Managed Entity.
*/
enum {
	omci_me_onu_power_shedding_restore_power_timer_interval = 1,
	omci_me_onu_power_shedding_data_power_shed_interval = 2,
	omci_me_onu_power_shedding_voice_power_shed_interval = 3,
	omci_me_onu_power_shedding_video_overlay_power_shed_interval = 4,
	omci_me_onu_power_shedding_video_return_power_shed_interval = 5,
	omci_me_onu_power_shedding_dsl_power_shed_interval = 6,
	omci_me_onu_power_shedding_atm_power_shed_interval = 7,
	omci_me_onu_power_shedding_ces_power_shed_interval = 8,
	omci_me_onu_power_shedding_frame_power_shed_interval = 9,
	omci_me_onu_power_shedding_sonet_power_shed_interval = 10,
	omci_me_onu_power_shedding_power_shed_status = 11
};

#ifdef OMCI_PRIVATE
/** Callback called upon AC power ON */
void ac_power_on_cb(struct omci_context *context);
/** Callback called upon AC power OFF */
void ac_power_off_cb(struct omci_context *context);
#endif

/** @} */

/** @} */

__END_DECLS

#endif
