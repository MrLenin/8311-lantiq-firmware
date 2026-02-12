/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_circuit_pack_h
#define _omci_circuit_pack_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_CIRCUIT_PACK Circuit Pack Managed Entity

    The Circuit Pack Managed Entity models a Circuit Pack that is equipped in
    an ONT slot. For ONUs with integrated interfaces, this Managed Entity may
    be used to distinguish available types of interfaces, such as Ethernet or
    POTS. The port mapping package is another way.

    For ONUs with integrated interfaces (which is the type that is supported
    by this software), the ONU automatically creates an instance of this
    Managed Entity for each instance of the virtual cardholder Managed Entity.
    The ONU also creates an instance of this Managed Entity when the OLT
    provisions the cardholder to expect a Circuit Pack (i.e., when the OLT sets
    the expected plug-in unit type or equipment ID of the cardholder to a
    Circuit Pack type. The ONU also creates an instance of this Managed Entity
    when a Circuit Pack is installed in a cardholder whose expected plug-in
    unit type is 0xFF = plug-and-play, and whose equipment ID is not
    provisioned. Finally, when the cardholder is provisioned for plug-and-play,
    an instance of this Managed Entity can be created at the request of the OLT.
    ONUs with integrated interfaces do not delete Circuit Pack instances.

    \remarks Creation and deletion by the OLT is retained for backward
    compatibility.

    @{
*/

/** This structure holds the attributes of the Circuit Pack Managed Entity.
*/
struct omci_me_circuit_pack {
	/** Circuit Pack Type

	    This attribute identifies the Circuit Pack type. It uses one of the
	    following codes:
	    - 22:  10BASE-T (fixed rate of 10 Mbit/s)
	    - 23:  100BASE-T (fixed rate of 100 Mbit/s)
	    - 24:  10/100BASE-T (selectable rate of 10 or 100 Mbit/s)
	    - 32:  POTS
	    - 47:  10/100/1000BASE-T (selectable rate of 10, 100,
	    or 1000 Mbit/s)
	    - 255: Unrecognized

	    The default value is defined by the application.
	*/
	uint8_t type;

	/** Number of Ports

	    This attribute is the number of access ports on the Circuit Pack.
	    If the port mapping package-G is supported for this Circuit Pack,
	    this attribute should be set to the total number of ports of all
	    types.

	    The default value is defined by the application.

	    This value is read-only by the OLT.
	*/
	uint8_t number_of_ports;

	/** Circuit Pack Serial Number

	    The serial number is unique for each Circuit Pack and may contain
	    the vendor ID and/or version number. For integrated ONUs, this value
	    is identical to the value of the serial number attribute of the
	    ONT-G Managed Entity.

	    The default value is defined by the application.

	    This value is read-only by the OLT.
	*/
	uint8_t serial_num[8];

	/** Circuit Pack Version

	    This attribute is a string that identifies the version of the
	    circuit pack as defined by the vendor. The value 0 indicates that
	    version information is not available or applicable. For integrated
	    ONUs, this value is identical to the value of the version attribute
	    of the ONU-G Managed Entity.

	    The default value is defined by the application.

	    This value is read-only by the OLT.
	*/
	uint8_t version[14];

	/** Circuit Pack Vendor ID

	    This attribute identifies the vendor of the Circuit Pack. For ONUs
	    with integrated interfaces, this value is identical to the value of
	    the vendor ID attribute of the ONT-G Managed Entity.

	    The default value is defined by the application.

	    This value is read-only by the OLT.
	*/
	uint8_t vendor_id[4];

	/** Administrative State

	    This attribute locks (0x01) and unlocks (0x00) the functions
	    performed by this Managed Entity. When the administrative state is
	    set to lock, all user functions are blocked, and alarms, TCAs and
	    AVCs for this Managed Entity and all dependent Managed Entities are
	    no longer generated.

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

	    This attribute is read-only by the OLT.
	*/
	uint8_t oper_state;

	/** Bridge or IP Router Indication

	    This attribute specifies whether the Ethernet interface is bridged
	    or derived from an IP router function.

	    The supported values are:
	    - 0x00 Bridged (this is the only mode that is supported)
	    - 0x01 IP router (not supported)
	    - 0x02 Both bridged and IP router functions.

	    The default value is 0x00.

	    This attribute is read-only by the OLT and only applicable for
	    circuit packs with Ethernet interfaces.
	*/
	uint8_t bridged_or_ip;

	/** Equipment ID

	    The Equipment ID is a fixed read-only value. The value is defined by
	    the application, identical for a specific type of GPON ONT box.
	    In North America, this may be the equipment CLEI code.
	    Upon managed Entity instantiation, the ONU sets this attribute to
	    all spaces or to the equipment ID of the Circuit Pack that is
	    physically present (this is application dependent).

	    This attribute is read-only by the OLT.
	*/
	uint8_t equipment_id[20];

	/** Card Configuration

	    This attribute selects the appropriate configuration on configurable
	    Circuit Packs. This kind of hardware is not supported, the value is
	    set to 0x00.

	    This value can be read and modified by the OLT, but changing to
	    another value that 0x00 is refused by the software.
	*/
	uint8_t card_configuration;

	/** Total T-CONT Buffer Number

	    This attribute reports the total number of T-CONT buffers
	    associated with the Circuit Pack. Upon ME instantiation, the ONU
	    sets this attribute to 0x00 or to the value supported by the
	    physical Circuit Pack (this is application dependent, a value other
	    than 0x00 is mandatory for Circuit Packs that provide a traffic
	    scheduler function).

	    This attribute is read-only by the OLT.
	*/
	uint8_t total_tcont_buffer_num;

	/** Total Priority Queue Number

	    This value reports the total number of priority queues associated
	    with the Circuit Pack. Upon Managed Entity instantiation, the ONU
	    sets the attribute to 0x00 or to the value supported by the physical
	    Circuit Pack (this is application dependent, a value other than 0x00
	    is mandatory for circuit packs that provide a traffic scheduler
	    function).

	    This attribute is read-only by the OLT.
	*/
	uint8_t total_priority_queue_num;

	/** Total Traffic Scheduler Number

	    This value reports the total number of traffic schedulers associated
	    with the Circuit Pack.

	    The ONU supports null function, HOL (head of line) scheduling and
	    WRR (weighted round robin) from the priority control and guarantee
	    of minimum rate control points of view, respectively.

	    If the Circuit Pack has no traffic scheduler, this attribute should
	    be 0x00.

	    Upon Managed Entity instantiation, the ONU sets the attribute to
	    0x00 or to the value supported by the physical Circuit Pack (this
	    is application dependent, a value other than 0x00 is mandatory for
	    Circuit Packs that provide a traffic scheduler function).

	    This attribute is read-only by the OLT.
	*/
	uint8_t total_traffic_scheduler_num;

	/** Power Shedding Override

	    This attribute allows ports to be excluded from the power shed
	    control. It is a bit mask that takes port 1 as the MSB.
	    A bit value of 0b1 marks the corresponding port to override the
	    power-shed timer. For hardware that cannot shed power per port, this
	    attribute is a slot override rather than a port override, with any
	    non-zero port value causing the entire Circuit Pack to override
	    power shedding.

	    This value can be read and modified by the OLT.
	*/
	uint32_t power_shed_override;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Circuit Pack Managed
   Entity.
*/
enum {
	omci_me_circuit_pack_type = 1,
	omci_me_circuit_pack_number_of_ports = 2,
	omci_me_circuit_pack_serial_num = 3,
	omci_me_circuit_pack_version = 4,
	omci_me_circuit_pack_vendor_id = 5,
	omci_me_circuit_pack_admin_state = 6,
	omci_me_circuit_pack_oper_state = 7,
	omci_me_circuit_pack_bridged_or_ip = 8,
	omci_me_circuit_pack_equipment_id = 9,
	omci_me_circuit_pack_card_configuration = 10,
	omci_me_circuit_pack_total_tcont_buffer_num = 11,
	omci_me_circuit_pack_total_priority_queue_num = 12,
	omci_me_circuit_pack_total_traffic_scheduler_num = 13,
	omci_me_circuit_pack_power_shed_override = 14
};

/** @} */

/** @} */

__END_DECLS

#endif
