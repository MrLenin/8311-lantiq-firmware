/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_65296_h
#define _omci_me_65296_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_65296 ME-65296 Managed Entity

    @{
*/

/** This structure holds the attributes of the ME-65296 Managed Entity.
*/
struct omci_me_65296 {
	uint8_t attr1;
	uint8_t attr2;
	uint32_t attr3;
	uint8_t attr4;
	uint8_t attr5;
	uint8_t attr6;
	uint32_t attr7;
	uint8_t attr8;
	uint8_t attr9;
	uint8_t attr10[12];
} __PACKED__;

/** @} */

/** @} */

__END_DECLS

#endif
