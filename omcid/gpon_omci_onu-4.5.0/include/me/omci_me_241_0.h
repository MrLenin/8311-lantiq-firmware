/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_241_0_h
#define _omci_me_241_0_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_241_0 ME-241_0 Managed Entity

    @{
*/

/** This structure holds the attributes of the ME-241_0 Managed Entity.
*/
struct omci_me_241_0 {
	/** time of day */
	uint8_t time_of_day[7];
	/** start of iPVID */
	uint16_t start_of_ipvid;
} __PACKED__;

/** @} */

/** @} */

__END_DECLS

#endif
