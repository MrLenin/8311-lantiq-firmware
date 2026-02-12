/******************************************************************************

                              Copyright (c) 2010
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_foo_h
#define _omci_foo_h

#ifndef SWIG
#include "omci_api.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_FOO Foo Managed Entity

    TODO add your description here

    @{
*/

struct omci_me_foo_table {
	/** First table field */
	uint16_t number;

	/** Large string */
	uint8_t string[10];
} __PACKED__;

/** This structure holds the attributes of the Foo Managed Entity.
*/
struct omci_me_foo {
	/** Bool attribute #1 */
	bool flag;

	/** Unsigned 2-byte integer attribute #2 */
	uint16_t number;

	/** 10-byte wide string attribute #3 */
	uint8_t string[10];

	/** 12-byte wide table attribute #4 */
	struct omci_me_foo_table table;

	/* Other attributes are not defined */

} __PACKED__;

/** This enumerator holds the attribute numbers of the Foo Managed Entity. */
enum {
	omci_me_foo_flag = 1,
	omci_me_foo_number = 2,
	omci_me_foo_string = 3,
	omci_me_foo_table = 4
};

/** @} */

/** @} */

__END_DECLS

#endif
