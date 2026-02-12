/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_65530_h
#define _omci_me_65530_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_65530 ME-65530 Managed Entity

    @{
*/

/** This structure holds the attributes of the ME-65530 Managed Entity.
*/
struct omci_me_65530 {
	uint8_t attr1[24];
	uint8_t attr2[12];
	uint8_t attr3;
} __PACKED__;

/** @} */

/** @} */

__END_DECLS

#endif
