/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_65281_h
#define _omci_me_65281_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_65281 ME-65281 Managed Entity

    @{
*/

/** This structure holds the attributes of the ME-65281 Managed Entity.
*/
struct omci_me_65281 {
	uint8_t attr1;
	uint16_t attr2;
	uint8_t attr3;
	uint8_t attr4;
	uint8_t attr5;
	uint8_t attr6;
	uint8_t attr7;
	uint8_t attr8;
	uint8_t attr9;
	uint8_t attr10;
} __PACKED__;

/** @} */

/** @} */

__END_DECLS

#endif
