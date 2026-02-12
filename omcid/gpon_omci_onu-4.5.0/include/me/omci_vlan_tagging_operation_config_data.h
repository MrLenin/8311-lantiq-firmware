/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_vlan_tagging_operation_config_data_h
#define _omci_vlan_tagging_operation_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_VLAN_TAGGING_OPERATION_CONFIG_DATA VLAN Tagging Operation Configuration Data Managed Entity

    This Managed Entity organizes data associated with VLAN tagging. Instances
    of this Managed Entity are created and deleted by the OLT.

    Zero or one instance of this Managed Entity may exist for an instance of any
    Managed Entity that can terminate or modify an Ethernet stream.
    By definition, tagging operation occurs farther away from the MAC bridge
    than filtering.

    @{
*/

/** This structure holds the attributes of the VLAN Tagging Operation
    Configuration Data Managed Entity.
*/
struct omci_me_vlan_tagging_operation_config_data {
	/** Upstream VLAN Tagging Operation Mode

	    This attribute controls upstream VLAN tagging. Valid values are:
	    - 0x00 Upstream frames are sent "as is", regardless of any VLAN tag.
	    - 0x01 The upstream frame is tagged, whether or not the received
	    frame was tagged. The frame's TCI, consisting of VID, CFI and user
	    priority, is attached or overwritten with the upstream VLAN tag
	    TCI value.
	    - 0x02 The upstream frame is prepended with a tag, whether or not
	    the received frame was tagged. If the received frame is tagged, a
	    second tag (Q-in-Q) is added to the frame. If the received frame
	    is not tagged, a tag is attached to the frame. The added tag is
	    defined by the upstream VLAN tag TCI value attribute.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t us_tagging_mode;

	/** Upstream VLAN Tag TCI Value

	    This attribute specifies the TCI for upstream VLAN tagging. It is
	    used when the upstream VLAN tagging operation mode is 0x01 or 0x02.
	*/
	uint16_t us_tci_value;

	/** Downstream VLAN Tagging Operation Mode

	    This attribute controls downstream VLAN tagging. Valid values are:
	    - 0x00 Downstream frames are sent "as is", regardless of any VLAN
	    tag.
	    - 0x01 If the received frame is tagged, the outer tag is stripped.
	    An untagged frame is forwarded unchanged.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t ds_tagging_mode;

	/** Association Type

	    This attribute specifies the type of the Managed Entity that is
	    associated with this VLAN tagging operation configuration data
	    Managed Entity.
	    Values are assigned in accordance with the following list:

	    - 0x00 (default) Physical path termination point Ethernet UNI (for
	    backward compatibility, may also be an IP host config data ME;
	    they must not have the same ME ID). The associated ME instance is
	    implicit; its identifier is the same as that of this VLAN tagging
	    operation configuration data.
	    - 0x01 IP host config data
	    - 0x02 IEEE 802.1p mapper service profile
	    - 0x03 MAC bridge port configuration data
	    - 0x04 Physical path termination point xDSL UNI
	    - 0x05 GEM interworking termination point
	    - 0x06 Multicast GEM interworking termination point
	    - 0x07 Physical path termination point MoCA UNI
	    - 0x08 Physical path termination point 802.11 UNI
	    - 0x09 Ethernet flow termination point
	    - 0x0A Physical path termination point Ethernet UNI

	    The associated Managed Entity instance is identified by the
	    associated Managed Entity pointer.
	*/
	uint8_t association_type;

	/** Associated Managed Entity Pointer

	    When the association type attribute is non-zero, this attribute
	    points to the Managed Entity with which this VLAN tagging operation
	    configuration data Managed Entity is associated. Otherwise, this
	    attribute is undefined, and the association is implicit.
	*/
	uint16_t associated_me_ptr;

} __PACKED__;

/** This enumerator holds the attribute numbers of the VLAN Tagging Operation
    Configuration Data Managed Entity.
*/
enum {
	omci_me_vlan_tagging_operation_config_data_us_tagging_mode = 1,
	omci_me_vlan_tagging_operation_config_data_us_tag_tci_value = 2,
	omci_me_vlan_tagging_operation_config_data_ds_tagging_mode = 3,
	omci_me_vlan_tagging_operation_config_data_association_type = 4,
	omci_me_vlan_tagging_operation_config_data_associated_me_ptr = 5
};

/** @} */

/** @} */

__END_DECLS

#endif
