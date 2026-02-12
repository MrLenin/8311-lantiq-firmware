/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_onu2_g_h
#define _omci_onu2_g_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_ONU2_G ONU2-G Managed Entity

    This Managed Entity contains additional attributes associated with the ONU.

    The ONU automatically creates an instance of this Managed Entity. Its
    attributes are populated according to the data within the ONU itself.

    @{
*/

/** This structure holds the attributes of the ONU2-G Managed Entity. */
struct omci_me_onu2_g {
	/** Equipment ID

	    The Equipment ID is a fixed read-only value. The value is defined by
	    the application, identical for a specific type of GPON ONU box.
	    In North America, this may be the equipment CLEI code.
	    This attribute is read-only by the OLT.
	*/
	uint8_t equipment_id[20];

	/** OMCC Version

	    This attribute identifies the version of the OMCC protocol being
	    used by the ONU.
	    This is a fixed value that is related to the software build version.
	    The version supported by this software is 0x85.
	    This attribute is read-only by the OLT.
	*/
	uint8_t omci_version;

	/** Vendor Product Code

	    This attribute provides a vendor-specific product code for the ONU.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint16_t vendor_product_code;

	/** Security Capability

	    This attribute advertises the security capabilities of the ONU.
	    This value is fixed to 0x01 and indicates that AES encryption of the
	    downstream payload is supported.
	    This attribute is read-only by the OLT.
	*/
	uint8_t security_capability;

	/** Security Mode

	    This attribute is read-only by the OLT.
	    This value is fixed to 0x01 and indicates that only AES encryption
	    of the downstream payload is supported. If the OLT tries to change
	    this value, this is refused. The hardware does not support any
	    other encryption mode.
	*/
	uint8_t security_mode;

	/** Total Priority Queue Number
	    This attribute reports the total number of priority queues that
	    are associated with the ONU in its entirety. The maximum value
	    is 0x0FFF.
	    Upon Managed Entity instantiation, the ONU sets this attribute to
	    the value that represents its capabilities.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint16_t total_priority_queue_num;

	/** Total Traffic Scheduler Number
	    This attribute reports the total number of traffic schedulers
	    that are associated with the ONU in its entirety.

	    If the ONU has no traffic schedulers, this attribute is 0x00.

	    The default value of this attribute is read from a non-volatile
	    memory.

	    This attribute is read-only by the OLT.
	*/
	uint8_t total_traffic_scheduler_num;

	/** GEM/ATM Mode
	    This value is fixed to 0x02 and indicates that only GEM mode is
	    supported and ATM is not.
	    This attribute is read-only by the OLT.
	*/
	uint8_t mode;

	/** Total GEM Port Number
	    This attribute reports the total number of GEM port-IDs supported by
	    the ONU. The maximum value is 0x0FFF. Upon ME instantiation, the ONU
	    sets this attribute to the value that represents its capabilities.
	    This attribute is read-only by the OLT.
	*/
	uint16_t total_gem_port_id_num;

	/** System Up-time
	    This attribute counts the 10-ms intervals since the ONU was last
	    initialized. It rolls over to 0x0000 0000 when full.
	*/
	uint32_t sys_uptime;

	/**
	    This attribute indicates the Ethernet connectivity models that the
	    ONU can support. The value 0 indicates that the capability is not
	    supported; 1 signifies support.
	*/
	uint16_t connectivity_capability;

	/**
	    This attribute specifies the Ethernet connectivity model that
	    the OLT wishes to use.
	*/
	uint8_t current_connectivity_mode;

	/**
	    This attribute reports whether various managed entities in
	    the ONU are fixed by the ONU's architecture or whether they are
	    configurable. For backward compatibility, and if the ONU does not
	    support this attribute, all such attributes are understood to be
	    hard-wired.
	*/
	uint16_t qos_configuration_flexibility;

	/**
	   If this optional attribute is implenented, it specifies the scale
	   factor of several attributes of the priority queue Managed Entity
	   of clause 9.2.10. The default value of this attribute is 1.
	*/
	uint16_t priority_queue_scale_factor;

} __PACKED__;

/** This enumerator holds the attribute numbers of the ONU2-G Managed Entity.
*/
enum {
	omci_me_onu2_g_equipment_id = 1,
	omci_me_onu2_g_omcc_version = 2,
	omci_me_onu2_g_vendor_product_code = 3,
	omci_me_onu2_g_security_capability = 4,
	omci_me_onu2_g_security_mode = 5,
	omci_me_onu2_g_total_priority_queue_num = 6,
	omci_me_onu2_g_total_traffic_scheduler_num = 7,
	omci_me_onu2_g_mode = 8,
	omci_me_onu2_g_total_gem_port_id_num = 9,
	omci_me_onu2_g_sys_uptime = 10,
	omci_me_onu2_g_connectivity_capability = 11,
	omci_me_onu2_g_current_connectivity_mode = 12,
	omci_me_onu2_g_qos_configuration_flexibility = 13,
	omci_me_onu2_g_priority_queue_scale_factor = 14
};

/** @} */

/** @} */

__END_DECLS

#endif
