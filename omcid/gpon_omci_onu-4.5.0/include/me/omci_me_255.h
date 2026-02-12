/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_255_h
#define _omci_me_255_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_255 ME-255 Managed Entity

    @{
*/

/** This structure holds the attributes of the ME-255 Managed Entity.
*/
struct omci_me_255 {
	/** dummy */
	uint8_t dummy[30];
} __PACKED__;

/** @} */

/** @} */

__END_DECLS

#endif
