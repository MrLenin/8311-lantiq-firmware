/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_extended_vlan_config_data_h
#define _omci_extended_vlan_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_EXTENDED_VLAN_CONFIG_DATA Extended VLAN Tag Operation Configuration Data Managed Entity

    This Managed Entity organizes data associated with VLAN tagging. Regardless
    of its point of attachment, the specified tagging operations refer to the
    upstream direction. Instances of this Managed Entity are created and
    deleted by the OLT.

    Zero or one instance of this Managed Entity may exist for an instance of any
    Managed Entity that can terminate or modify an Ethernet stream.

    When this Managed Entity is associated with a UNI-side termination point, it
    performs its upstream classification and tagging operations before offering
    the upstream frame to other filtering, bridging or switching functions.
    In the downstream direction, the defined inverse operation is the last
    operation performed on the frame before offering it to the UNI-side
    termination.

    When this Managed Entity is associated with an ANI-side termination point,
    it performs its upstream classification and tagging operations as the last
    step before transmission to the OLT, after having received the upstream
    frame from other filtering, bridging or switching functions.
    In the downstream direction, the defined inverse operation is the first
    operation performed on the frame before offering it to possible filter,
    bridge or switch functions.

    @{
*/

/** Received Frame VLAN Tagging Operation Table Entry. See \ref
   omci_me_extended_vlan_config_data::rx_vlan_oper_table */
struct omci_rx_vlan_oper_table {
#if (IFXOS_BYTE_ORDER == IFXOS_BIG_ENDIAN)
	uint32_t filter_outer_prio:4;
	uint32_t filter_outer_vid:13;
	uint32_t filter_outer_tpid_de:3;
	uint32_t word1_padding:12;

	uint32_t filter_inner_prio:4;
	uint32_t filter_inner_vid:13;
	uint32_t filter_inner_tpid_de:3;
	uint32_t word2_padding:8;
	uint32_t filter_ether_type:4;

	uint32_t treatment_tags_remove:2;
	uint32_t word3_padding:10;
	uint32_t treatment_outer_prio:4;
	uint32_t treatment_outer_vid:13;
	uint32_t treatment_outer_tpid_de:3;

	uint32_t word4_padding:12;
	uint32_t treatment_inner_prio:4;
	uint32_t treatment_inner_vid:13;
	uint32_t treatment_inner_tpid_de:3;
#else
	uint32_t word1_padding:12;
	uint32_t filter_outer_tpid_de:3;
	uint32_t filter_outer_vid:13;
	uint32_t filter_outer_prio:4;

	uint32_t filter_ether_type:4;
	uint32_t word2_padding:8;
	uint32_t filter_inner_tpid_de:3;
	uint32_t filter_inner_vid:13;
	uint32_t filter_inner_prio:4;

	uint32_t treatment_outer_tpid_de:3;
	uint32_t treatment_outer_vid:13;
	uint32_t treatment_outer_prio:4;
	uint32_t word3_padding:10;
	uint32_t treatment_tags_remove:2;

	uint32_t treatment_inner_tpid_de:3;
	uint32_t treatment_inner_vid:13;
	uint32_t treatment_inner_prio:4;
	uint32_t word4_padding:12;
#endif
} __PACKED__;

/** This structure holds the attributes of the Extended VLAN Tag Operation
    Configuration Data Managed Entity.
*/
struct omci_me_extended_vlan_config_data {
	/** Association Type

	    This attribute identifies the type of the Managed Entity associated
	    with this extended VLAN tagging Managed Entity. Values are assigned
	    as follows:
	    - 0x00 MAC bridge port configuration data
	    - 0x01 IEEE 802.1p mapper service profile
	    - 0x02 Physical path termination point Ethernet UNI
	    - 0x03 IP host config data
	    - 0x04 Physical path termination point xDSL UNI
	    - 0x05 GEM interworking termination point
	    - 0x06 Multicast GEM interworking termination point
	    - 0x07 Physical path termination point MoCA UNI
	    - 0x08 Physical path termination point 802.11 UNI
	    - 0x09 Ethernet flow termination point

	    \remarks If a MAC bridge is configured, codepoints 0x01, 0x05, and
	    0x06 are associated with the ANI side of the MAC bridge, and the
	    other codepoints are associated with the UNI side. Codepoint 0x00
	    is associated with the ANI or UNI side depending on where the MAC
	    bridge port is.  When the extended VLAN tagging ME is associated
	    with the ANI side, it behaves as an upstream egress rule, and as a
	    downstream ingress rule when the downstream mode attribute is equal
	    to 0. When the extended VLAN tagging ME is associated with the UNI
	    side, the extended VLAN tagging Managed Entity behaves as an
	    upstream ingress rule, and as a downstream egress rule when the
	    downstream mode attribute is equal to 0x00.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t association_type;

	/** Received Frame VLAN Tagging Operation Table Maximum Size

	    This attribute indicates the maximum number of VLAN tagging
	    operation entries that can be set in the received frame VLAN
	    tagging operation table.

	    This attribute is application dependent and read-only by the OLT.
	*/
	uint16_t rx_vlan_oper_table_size;

	/** Input Termination Point ID

	    This attribute gives the special TPID value for operations on the
	    input (filtering) side of the table. Typical values include 0x8A88
	    and 0x9100.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t input_tp_id;

	/** Output Termination Point ID

	    This attribute gives the special TPID value for operations on the
	    output (tagging) side of the table. Typical values include 0x8a88
	    and 0x9100.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t output_tp_id;

	/** Downstream Mode

	    Regardless of its association, the extended VLAN tagging operation
	    configuration data Managed Entity pertains to upstream traffic.
	    This attribute specifies the mode for downstream mapping:
	    - 0x00 The operation performed in the downstream direction is the
	    inverse of that performed in the upstream direction. For one-to-one
	    VLAN mappings, the inverse is trivially defined. Many-to-one
	    mappings are possible, however, and these are treated as follows.
	    If the many-to-one mapping results from multiple operation rules
	    producing the same ANI-side tag configuration, then the first
	    rule in the list defines the inverse operation. If the
            many-to-one mapping results from don't care fields in the filter
	    being replaced with provisioned fields in the ANI-side tags,
	    then the inverse is defined to set the corresponding fields on
	    the ANI-side with their lowest value.
	    - 0x01 No operation is performed in the downstream direction.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t ds_mode;

	/** Received Frame VLAN Tagging Operation Table

	    This attribute is a table that filters and tags upstream frames.
	    Each entry represents a tagging rule, comprising a filtering part
	    (the first 7 fields) and a treatment part (the last 7 fields). Each
	    incoming upstream packet is matched against each rule in list order.
	    The first rule that matches the packet is selected as the active
	    rule, and the packet is then treated according to that rule.

	    There are three categories of rules: zero-tag, single-tag, and
	    double-tag rules. Logically, these categories are separate, and
	    apply to their respective incoming frame types. In other words, a
	    single-tag rule should not apply to a double-tagged frame, even
	    though the single-tag rule might match the outer tag of the
	    double-tagged frame.

	    When the table is created, the ONU should predefine three entries
	    that list the default treatment (of normal forwarding) for untagged,
	    single tagged, and double tagged frames.

	    For more detail see ITU-T G.984.4, clause 9.3.13.

	    This attribute is readable and writable by the OLT.
	*/
	struct omci_rx_vlan_oper_table rx_vlan_oper_table;

	/** Associated Managed Entity Pointer

	    This attribute points to the Managed Entity with which this extended
	    VLAN tagging operation configuration data Managed Entity is
	    associated.

	    \remarks When the association type is xDSL, the two most significant
	    bits may be used to indicate a bearer channel.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t associated_me_ptr;

	/** DSCP to P-bit Mapping

	    This attribute specifies mapping from DSCP to P-bits.
	    The attribute can be considered a bit string sequence of 64
	    3-bit groups. The 64 sequence entries represent the possible values
	    of the 6-bit DSCP field. Each 3-bit group specifies the P-bit value
	    to which the associated DSCP value should be mapped.

	    \remarks If certain bits in the DSCP field are to be ignored in the
	    mapping process, the attribute should be provisioned such that all
	    possible values of those bits produce the same p-bit mapping. This
	    can be applied to the case where instead of full DSCP, the operator
	    wishes to adopt the priority mechanism based on IP precedence,
	    which needs only the three MSBs of the DSCP field.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t dscp_to_pbit_mapping[24];

} __PACKED__;

/** This enumerator holds the attribute numbers of the Extended VLAN Tag
   Operation Configuration Data Managed Entity.
*/
enum {
	omci_me_extended_vlan_config_data_association_type = 1,
	omci_me_extended_vlan_config_data_rx_vlan_oper_table_size = 2,
	omci_me_extended_vlan_config_data_input_tp_id = 3,
	omci_me_extended_vlan_config_data_output_tp_id = 4,
	omci_me_extended_vlan_config_data_ds_mode = 5,
	omci_me_extended_vlan_config_data_rx_vlan_oper_table = 6,
	omci_me_extended_vlan_config_data_associated_me_ptr = 7,
	omci_me_extended_vlan_config_data_dscp_to_pbit_mapping = 8
};

/** @} */

/** @} */

__END_DECLS

#endif
