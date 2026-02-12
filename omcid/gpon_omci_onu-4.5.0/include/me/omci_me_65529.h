/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_65529_h
#define _omci_me_65529_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_65529 ME-65529 Managed Entity

    @{
*/

/** This structure holds the attributes of the ME-65529 Managed Entity.
*/
struct omci_me_65529 {
	uint8_t attr1[4];
	uint8_t attr2;
	uint8_t attr3;
	uint8_t attr4;
} __PACKED__;

/** @} */

/** @} */

__END_DECLS

#endif
