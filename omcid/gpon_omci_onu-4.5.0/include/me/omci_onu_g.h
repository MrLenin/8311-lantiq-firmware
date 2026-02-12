/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_onu_g_h
#define _omci_onu_g_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_ONU_G ONU-G Managed Entity

    The ONU-G Managed Entity represents the ONT/ONU as equipment.

    The ONU automatically creates an instance of this Managed Entity.
    It assigns values to read-only attributes according to data within
    the ONU itself.

    @{
*/

/** This structure holds the attributes of the ONU-G Managed Entity.
*/
struct omci_me_onu_g {
	/** ONU Vendor ID

	    The Vendor ID is a fixed read-only value. The value is defined by
	    the application, identical for all GPON ONU boxes of an ONU vendor.
	    It is the same as the four most significant bytes of the ONU serial
	    number as specified in ITU-T G.984.3.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint8_t vendor_id[4];

	/** ONU Version

	    The Version Number is a fixed read-only value. The value is defined
	    by the application, identical for all GPON ONU boxes of a certain
	    hardware and software product version.
	    The character value "0" indicates that version information is not
	    available or not applicable.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint8_t version[14];

	/** ONU Serial Number

	    The Serial Number is a fixed read-only value. The value is defined
	    by the application, individual for each GPON ONU box.
	    It is defined in ITU-T G.984.3 and contains the vendor id and
	    version number. The first four bytes are an ASCII encoded vendor ID
	    four letter mnemonic. The second four bytes are a binary encoded
	    serial number, under the control of the ONU vendor.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint8_t serial_num[8];

	/** Traffic Management Option Capability

	    The Traffic Management Option identifies the upstream traffic
	    management function implemented in the ONU. There are two options:
	    0x00: Priority controlled and flexibly scheduled upstream traffic
	    The traffic scheduler and priority queue mechanism are used for
	    upstream traffic.
	    0x01: Rate controlled upstream traffic
	    The maximum upstream traffic of each individual connection is
	    guaranteed by shaping.
	    0x02: Priority and rate controlled upstream traffic
	    The traffic scheduler and priority queue mechanism are used for
	    upstream traffic. The maximum upstream traffic of each individual
	    connection is guaranteed by shaping.

	    This attribute is read-only by the OLT.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    Upon ME instantiation, the ONU sets this attribute to the value that
	    describes its implementation. The OLT must adapt its model to
	    conform to the ONU's selection.
	*/
	uint8_t traffic_management;

	/** VP/VC Capability

	    This attribute is not used. It is fixed to a value of 0x00.
	*/
	uint8_t vp_vc;

	/** Battery Backup Capability

	    This Boolean attribute specifies whether the ONU supports backup
	    battery monitoring. OMCI_FALSE disables battery alarm
	    monitoring, OMCI_TRUE enables battery alarm monitoring.
	    The OLT can modify the setting from OMCI_TRUE to
	    OMCI_FALSE, if the default is OMCI_TRUE. If the
	    default is OMCI_FALSE, the OLT is not allowed to change
	    the setting.

	    The default value of this attribute is read from a non-volatile
	    memory.
	*/
	bool battery_backup;

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
	    It is set to OMCI_OPERATIONAL_STATE_ENABLED as soon as all other
	    attributes as well as the directly related Managed Entities are
	    defined and can be accessed by the OLT.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint8_t oper_state;

	/** ONU Survival Time

	    This attribute indicates the minimum guaranteed time in milliseconds
	    between the loss of external power and the silence of the ONU.
	    This value depends on the surrounding application and is defined by
	    the ONU vendor. A value of 0x00 implies that the actual time is not
	    known.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint8_t survival_time;

} __PACKED__;

/** This enumerator holds the attribute numbers of the ONU-G Managed Entity.
*/
enum {
	omci_me_onu_g_vendor_id = 1,
	omci_me_onu_g_version = 2,
	omci_me_onu_g_serial_num = 3,
	omci_me_onu_g_traffic_management = 4,
	omci_me_onu_g_vp_vc = 5,
	omci_me_onu_g_battery_backup = 6,
	omci_me_onu_g_admin_state = 7,
	omci_me_onu_g_oper_state = 8,
	omci_me_onu_g_onu_survival_time = 9
};

/** @} */

/** @} */

__END_DECLS

#endif
