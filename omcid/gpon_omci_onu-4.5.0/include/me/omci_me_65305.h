/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_65305_h
#define _omci_me_65305_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_65305 ME-65305 Managed Entity

    @{
*/

/**ME-65305 Managed Entity attribute 2 table entry operation. */
#define OMCI_ME_65305_ATTR2_TABLE_ENTRY_OP                  (1 << 7)

/** This structure holds ME-65305 Managed Entity attribute 2 table.
*/
struct omci_me_65305_attr2 {
	uint8_t  v0;
	uint8_t  v1;
	uint16_t v2;
	uint16_t v3;
} __PACKED__ ;

/** This structure holds the attributes of the ME-65305 Managed Entity.
*/
struct omci_me_65305 {
	uint8_t attr1;
	struct omci_me_65305_attr2 attr2;
} __PACKED__;

/** This enumerator holds the attribute numbers of the ME-65305 Managed Entity.
*/
enum {
	omci_me_65305_attr1 = 1,
	omci_me_65305_attr2 = 2
};

/** @} */

/** @} */

__END_DECLS

#endif
