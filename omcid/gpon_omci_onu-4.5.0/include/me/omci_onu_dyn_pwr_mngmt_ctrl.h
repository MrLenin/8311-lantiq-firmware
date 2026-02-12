
/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_onu_dyn_pwr_mngmt_ctrl_h
#define _omci_onu_dyn_pwr_mngmt_ctrl_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_ONU_DYN_PWR_MNGMT_CTRL ONU dynamic power management control Managed Entity

    This Managed Entity models the ONU's ability to enter power conservation
    modes in cooperation with the OLT in a G.987 system. [ITU-T G.987.3]
    specifies two modes, doze and cyclic sleep.
    An ONU that supports power conservation modes automatically creates an
    instance of this Managed Entity. 

    @{
*/

/** This structure holds the attributes of the ONU dynamic power management
    control Managed Entity. */
struct omci_me_onu_dyn_pwr_mngmt_ctrl {
	/** Power reduction management capability

	    This attribute declares the ONU's support for managed power
	    conservation modes, as defined in [ITU-T G.987.3]. It is a bit map
	    in which the bit value 0 indicates no support for the specified
	    mode, Rec. ITU-T G.988 (10/2010) - Prepublished version 91 while the
	    bit value 1 indicates that the ONU does support the specified mode. 

	    This attribute is readable by the OLT.
	*/
	uint8_t pwr_reduction_mngmt_cap;

	/** Power reduction management mode

	    This attribute enables one or more of the ONU's managed power
	    conservation modes. It is a bit map in which the bit value 0
	    disables the mode, while the value 1 enables the mode. Bit
	    assignments are the same as those of the power reduction management
	    capability attribute. The default value of each bit is 0.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t pwr_reduction_mngmt_mode;

	/** Itransinit

	    This attribute is the ONU vendor's statement of the complete
	    transceiver initialization time: the time required for the ONU to
	    regain full functionality when leaving the Asleep state (i.e.,
	    turning on both receiver and transmitter and acquiring
	    synchronization to the downstream flow), measured in units of
	    125 microsecond frames. The value zero indicates that the sleeping
	    ONU can respond to a bandwidth grant without delay.

	    This attribute is readable by the OLT.
	*/
	uint16_t itransinit;

	/** Itxinit

	    This attribute is the ONU vendor's statement of the transmitter
	    initialization time: the time required for the ONU to regain full
	    functionality when leaving the Listen state (i.e., turning on the
	    transmitter), measured in units of 125 microsecond frames. The value
	    zero indicates that the dozing ONU can respond to a bandwidth grant
	    without delay.

	    This attribute is readable by the OLT.
	*/
	uint16_t itxinit;

	/** Maximum sleep interval

	    The Isleep attribute specifies the maximum time the ONU spends in
	    its asleep or listen states, as a count of 125 microsecond frames.
	    Local or remote events may truncate the ONU's sojourn in these
	    states. The default value of this attribute is 0.

	    This attribute is readable and writable by the OLT..
	*/
	uint32_t max_sleep_interval;

	/** Minimum aware interval

	    The Iaware attribute specifies the time the ONU spends in its aware
	    state, as a count of 125 microsecond frames, before it re-enters
	    asleep or listen states. Local or remote events may independently
	    cause the ONU to enter an active state rather than returning to a
	    sleep state. The default value of this attribute is 0.

	    This attribute is readable and writable by the OLT..
	*/
	uint32_t min_aware_interval;

	/** Minimum active held interval

	    The Ihold attribute specifies the minimum time during which the ONU
	    remains in the active held state, as a count of 125 microsecond
	    frames. Its initial value is zero.

	    This attribute is readable and writable by the OLT..
	*/
	uint16_t min_active_held_interval;
} __PACKED__;

/** This enumerator holds the attribute numbers of the ONU dynamic power
    management control Managed Entity. */
enum {
	omci_me_onu_dyn_pwr_mngmt_ctrl_pwr_red_mngmt_cap = 1,
	omci_me_onu_dyn_pwr_mngmt_ctrl_pwr_red_mngmt_mode = 2,
	omci_me_onu_dyn_pwr_mngmt_ctrl_itransinit = 3,
	omci_me_onu_dyn_pwr_mngmt_ctrl_itxinit = 4,
	omci_me_onu_dyn_pwr_mngmt_ctrl_max_sleep_interval = 5,
	omci_me_onu_dyn_pwr_mngmt_ctrl_min_aware_interval = 6,
	omci_me_onu_dyn_pwr_mngmt_ctrl_min_active_held_interval = 7
};

/** @} */

/** @} */

__END_DECLS

#endif
