/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_65306_h
#define _omci_me_65306_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_65306 ME-65306 Managed Entity

    @{
*/

/**ME-65306 Managed Entity attribute 2 table entry operation. */
#define OMCI_ME_65306_ATTR1_TABLE_ENTRY_OP                  (1 << 15)

/** This structure holds ME-65306 Managed Entity attribute 2 table.
*/
struct omci_me_65306_attr1 {
	uint8_t  v0;
	uint16_t v1;
	uint32_t v2;
	uint32_t v3;
	uint8_t  v4;
	uint8_t  v5;
	uint8_t  v6;
	uint8_t  v7;
	uint8_t  v8;
	uint8_t  v9;
	uint8_t  v10;
	uint8_t  v11;
} __PACKED__ ;

/** This structure holds the attributes of the ME-65306 Managed Entity.
*/
struct omci_me_65306 {
	struct omci_me_65306_attr1 attr1;
} __PACKED__;

/** This enumerator holds the attribute numbers of the ME-65306 Managed Entity.
*/
enum {
	omci_me_65306_attr1 = 1
};

/** @} */

/** @} */

__END_DECLS

#endif
