/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_attribute_h
#define _omci_attribute_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_ATTRIBUTE Attribute Managed Entity

    This Managed Entity describes a particular attribute type that is supported
    by the ONU. This Managed Entity is not included in MIB upload. One or more
    "Attribute" Managed Entities are related to each "Managed Entity" Managed
    Entity. More than one "Managed Entity" Managed Entity can refer to a given
    "Attribute" Managed Entity.

    @{
*/

/** This structure holds the attributes of the "Attribute" Managed Entity.
*/
struct omci_me_attribute {
	/** Name

	    This attribute contains a 25 byte mnemonic tag for the attribute.
	    Strings shorter than 25 bytes are padded with null characters.

	    This string is read-only by the OLT.
	*/
	uint8_t name[25];

	/** Size

	    This attribute contains the size of the attribute, in bytes.
	    The value 0 indicates that the attribute can have a variable/unknown
	    size.

	    This value is read-only by the OLT.
	*/
	uint16_t size;

	/** Access

	    This attribute represents the OMCI access characteristics of the
	    attribute.

	    The following code points are defined:
	    - 1: Read
	    - 2: Write
	    - 3: Read and write
	    - 5: Read, set-by-create
	    - 6: Write, set-by-create
	    - 7: Read and write, set-by-create

	    This value is read-only by the OLT.
	*/
	uint8_t access;

	/** Format

	    This attribute represents the format of the attribute.
	    The following code points are defined:
	    - 1: Pointer
	    - 2: Bit field
	    - 3: Signed integer
	    - 4: Unsigned integer
	    - 5: String
	    - 6: Enumeration (a set of defined code points)
	    - 7: Table

	    This value is read-only by the OLT.
	*/
	uint8_t format;

	/** Lower limit

	    This attribute provides the lowest value for the attribute. Valid
	    for numeric types (pointer, signed integer, unsigned integer) only.
	    For attributes smaller than 4 bytes, the desired numeric value is
	    expressed in 4 byte representation (for example, the signed 1-byte
	    integer 0xFE is expressed as 0xFFFF FFFE; the unsigned 1-byte
	    integer 0xFE is expressed as 0x0000 00FE).

	    This value is read-only by the OLT.
	*/
	uint32_t lower_limit;

	/** Upper limit

	    This attribute provides the highest value for the attribute.
	    It has the same validity and format as the lower limit attribute.

	    This value is read-only by the OLT.
	*/
	uint32_t upper_limit;

	/** Bit field

	    This attribute is a mask of the supported bits in a bit field
	    attribute. Valid for bit field type only. A 1 in any position
	    signifies that it code point is supported, while 0 indicates not
	    supported. For bit fields smaller than 4 bytes, the attribute is
	    aligned at the least significant end of the mask.

	    This value is read-only by the OLT.
	*/
	uint32_t bit_field;

	/** Code points table

	    This attribute lists the code points supported by an enumerated
	    attribute.

	    This table is read-only by the OLT.
	*/
	uint16_t code_points_table;

	/** Support

	    This attribute represents the level of support of the attribute
	    (same notation as the attribute of the same name in the
	    "Managed Entity" Managed Entity.
	    The following code points are defined:
	    - 1: Fully supported (supported as defined in this object)
	    - 2: Unsupported (OMCI returns an error code if accessed)
	    - 3: Partially supported (some aspects of attribute supported)
	    - 4: Ignored (OMCI supported, but underlying function is not)

	    This value is read-only by the OLT.
	*/
	uint8_t support;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Attribute Managed Entity.
*/
enum {
	omci_me_attribute_name = 1,
	omci_me_attribute_size = 2,
	omci_me_attribute_access = 3,
	omci_me_attribute_format = 4,
	omci_me_attribute_lower_limit = 5,
	omci_me_attribute_upper_limit = 6,
	omci_me_attribute_bit_field = 7,
	omci_me_attribute_code_point_table = 8,
	omci_me_attribute_support = 9
};

/*! @} */

/*! @} */

__END_DECLS

#endif
