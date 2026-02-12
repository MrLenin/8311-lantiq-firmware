/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_244_h
#define _omci_me_244_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_244 ME-244 Managed Entity

    @{
*/

/** This structure holds the attributes of the ME-244 Managed Entity.
*/
struct omci_me_244 {
	/** dummy */
	uint8_t dummy[30];
} __PACKED__;

/** @} */

/** @} */

__END_DECLS

#endif
