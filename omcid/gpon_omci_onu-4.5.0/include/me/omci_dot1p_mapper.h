/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_gem_dot1p_mapper_h
#define _omci_gem_dot1p_mapper_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_DOT1P_MAPPER IEEE 802.1p Mapper Service Profile Managed Entity

    This Managed Entity associates the priorities of 802.1P priority tagged
    frames with specific connections. The operation of this Managed Entity
    affects only upstream traffic. Instances of this Managed Entity are created
    and deleted by the OLT.

    At its root, an instance of this Managed Entity may be associated with zero
    or one instances of a PPTP UNI, MAC bridge port configuration data, or any
    type of interworking termination point Managed Entity that carries IEEE 802
    traffic. Each of its eight branches is associated with zero or one GEM
    interworking termination point.

    @{
*/

/** This structure holds the attributes of the 802.1p Mapper Managed Entity.
*/
struct omci_dot1p_mapper {
	/** Termination Point Pointer

	    This attribute points to an instance of the associated termination
	    point.
	    The termination point type is determined by the TP type attribute:
	    - 0x00 Null, set to 0xFFFF
	    - 0x01 PPTP Ethernet UNI
	    - 0x02 IP  host configuration data
	    - 0x03 Ethernet flow TP
	    - 0x04 PPTP xDSL UNI
	    - 0x05 PPTP 802.11 UNI
	    - 0x06 PPTP MoCA UNI

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t tp_ptr;

	/** Interwork Termination Point pointer for P-bit priority 0

	    Points to the GEM interworking termination point associated with a
	    P-bit value of 0.
	    The null pointer 0xFFFF specifies that frames with the associated
	    priority are to be discarded.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interwork_tp_ptr0;

	/** Interworking Termination Point Pointer for P-bit Priority 1

	    Points to the GEM interworking termination point associated with a
	    P-bit value of 1.
	    The null pointer 0xFFFF specifies that frames with the associated
	    priority are to be discarded.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interwork_tp_ptr1;

	/** Interworking Termination Point Pointer for P-bit Priority 2

	    Points to the GEM interworking termination point associated with a
	    P-bit value of 2.
	    The null pointer 0xFFFF specifies that frames with the associated
	    priority are to be discarded.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interwork_tp_ptr2;

	/** Interworking Termination Point Pointer for P-bit Priority 3

	    Points to the GEM interworking termination point associated with a
	    P-bit value of 3.
	    The null pointer 0xFFFF specifies that frames with the associated
	    priority are to be discarded.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interwork_tp_ptr3;

	/** Interworking Termination Point Pointer for P-bit Priority 4

	    Points to the GEM interworking termination point associated with a
	    P-bit value of 4.
	    The null pointer 0xFFFF specifies that frames with the associated
	    priority are to be discarded.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interwork_tp_ptr4;

	/** Interworking Termination Point Pointer for P-bit Priority 5

	    Points to the GEM interworking termination point associated with a
	    P-bit value of 5.
	    The null pointer 0xFFFF specifies that frames with the associated
	    priority are to be discarded.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interwork_tp_ptr5;

	/** Interworking Termination Point Pointer for P-bit Priority 6

	    Points to the GEM interworking termination point associated with a
	    P-bit value of 6.
	    The null pointer 0xFFFF specifies that frames with the associated
	    priority are to be discarded.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interwork_tp_ptr6;

	/** Interworking Termination Point Pointer for P-bit Priority 7

	    Points to the GEM interworking termination point associated with a
	    P-bit value of 7.
	    The null pointer 0xFFFF specifies that frames with the associated
	    priority are to be discarded.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interwork_tp_ptr7;

	/** Unmarked Frame Option

	    This attribute specifies how the ONT should handle untagged Ethernet
	    frames received across the associated interface. Although it does
	    not alter the frame in any way, the ONT routes the frame as if it
	    were tagged with P bits (PCP field) according to the following code
	    points.
	    - 0x00 Derive the implied PCP field from the DSCP bits of received
	    frame.
	    - 0x01 Set the implied PCP field to a fixed value specified by the
	    default P-bit marking attribute.

	    The default value is 0x01.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t unmarked_frame_option;

	/** DSCP to P-bit Mapping

	    This attribute is valid when the unmarked frame option attribute
	    is set to 0x00. The DSCP to P-bit attribute can be considered a bit
	    string sequence of 64 3-bit groupings. The 64 sequence entries
	    represent the possible values of the 6-bit DSCP field. Each 3-bit
	    grouping specifies the P-bit value to which the associated DSCP
	    value should be mapped. The unmarked frame is then directed to the
	    GEM interworking termination point indicated by the interworking TP
	    pointer mappings.

	    \remarks If certain bits in the DSCP field are to be ignored in the
	    mapping process, the attribute should be provisioned such that all
	    possible values of those bits produce the same p-bit mapping.
	    This can be applied to the case where instead of full DSCP, the
	    operator wishes to adopt the priority mechanism based on IP
	    precedence, which needs only the three MSBs of the DSCP field.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t dscp_to_pbit_mapping[24];

	/** Default P-bit Marking

	    This attribute is valid when the unmarked frame option attribute is
	    set to 0x01. In its least significant bits, the default P-bit
	    marking attribute contains the default PCP field to be assumed. The
	    unmodified frame is then directed to the GEM interworking
	    termination point indicated by the interworking TP pointer mappings.

	    The default setting is 0x00.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t default_pbit_mapping;

	/** Termination Point Type

	    This attribute identifies the type of termination point associated
	    with the mapper.
	    - 0x00 Mapper used for bridging-mapping
	    - 0x01 Mapper directly associated with a PPTP Ethernet UNI
	    - 0x02 Mapper directly associated with an IP host service
	    - 0x03 Mapper directly associated with an Ethernet flow termination
	    point
	    - 0x04 Mapper directly associated with a PPTP xDSL UNI
	    - 0x05 Mapper directly associated with a PPTP 802.11 UNI
	    - 0x06 Mapper directly associated with a PPTP MoCA UNI

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t tp_type;

} __PACKED__;

/** This enumerator holds the attribute numbers of the 802.1p Mapper Managed
   Entity.
*/
enum {
	omci_me_dot1p_mapper_tp_ptr = 1,
	omci_me_dot1p_mapper_interwork_tp_ptr0 = 2,
	omci_me_dot1p_mapper_interwork_tp_ptr1 = 3,
	omci_me_dot1p_mapper_interwork_tp_ptr2 = 4,
	omci_me_dot1p_mapper_interwork_tp_ptr3 = 5,
	omci_me_dot1p_mapper_interwork_tp_ptr4 = 6,
	omci_me_dot1p_mapper_interwork_tp_ptr5 = 7,
	omci_me_dot1p_mapper_interwork_tp_ptr6 = 8,
	omci_me_dot1p_mapper_interwork_tp_ptr7 = 9,
	omci_me_dot1p_mapper_unmarked_frame_option = 10,
	omci_me_dot1p_mapper_dscp_to_pbit_mapping = 11,
	omci_me_dot1p_mapper_default_pbit_mapping = 12,
	omci_me_dot1p_mapper_tp_type = 13
};

/** @} */

/** @} */

__END_DECLS

#endif
