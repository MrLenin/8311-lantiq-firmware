/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_large_string_h
#define _omci_large_string_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_LARGE_STRING Large String managed Entity

    The large string Managed Entity holds strings longer than 25 bytes, up to
    a length of 375 byte. It is maintained in up to 15 parts, each part
    containing a chunk of 25 byte. If the final part contains less than 25 byte,
    it is terminated by at least one null byte.

    Instances of this Managed Entity are created and deleted by the OLT. To use
    this Managed Entity, the OLT instantiates the large string ME and then
    points to the created Managed Entity from other Managed Entity instances.
    Systems that maintain the large string should ensure that the large string
    Managed Entity is not deleted while it is still linked.

    An instance of this Managed Entity may be cited by any Managed Entity that
    requires a text string longer than bytes.

    @{
*/

/** Large string maximum size (with \\0) */
#define OMCI_ME_LARGE_STRING_SIZE (15 * 25 + 1)

/** This structure holds the attributes of the Large String Managed Entity.
*/
struct omci_me_large_string {
	/** Number of Parts

	    This attribute specifies the number of non-empty parts that form the
	    large string. This attribute defaults to 0x00 to indicate no large
	    string is defined. The maximum allowed value is 0x0F.
	*/
	uint8_t number_of_parts;

	/** Fifteen additional attributes are defined below, they are identical.

	    The large string is simply divided into as many parts as necessary,
	    starting at part 1. If the end of the string does not lie at a part
	    boundary, it is marked with a null byte.

	    Part 1-15
	*/
	uint8_t part[15][25];

} __PACKED__;

/** This enumerator holds the attribute numbers of the Large String Managed
   Entity.
*/
enum {
	omci_me_large_string_number_of_parts = 1,
	omci_me_large_string_part1 = 2,
	omci_me_large_string_part2 = 3,
	omci_me_large_string_part3 = 4,
	omci_me_large_string_part4 = 5,
	omci_me_large_string_part5 = 6,
	omci_me_large_string_part6 = 7,
	omci_me_large_string_part7 = 8,
	omci_me_large_string_part8 = 9,
	omci_me_large_string_part9 = 10,
	omci_me_large_string_part10 = 11,
	omci_me_large_string_part11 = 12,
	omci_me_large_string_part12 = 13,
	omci_me_large_string_part13 = 14,
	omci_me_large_string_part14 = 15,
	omci_me_large_string_part15 = 16
};

#ifdef OMCI_PRIVATE
/** Read large string parts into provided buffer */
void large_string_get(struct omci_context *context,
		      struct me *me,
		      char buf[OMCI_ME_LARGE_STRING_SIZE]);
#endif

/** @} */

/** @} */

__END_DECLS

#endif
