/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_olt_g_h
#define _omci_api_me_olt_g_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_OLT_G OLT-G

   This optional Managed Entity identifies the OLT to which an ONU is connected.
   This ME provides a way for the ONU to configure itself for operability with
   a particular OLT.

   An ONU that supports this Managed Entity automatically creates an instance
   of it. Immediately following the startup phase, the OLT should set the ONU
   to the desired configuration. Interpretation of the attributes is a matter
   for negotiation between the two vendors involved.

   @{
*/

/** Updates OLT-G ME resources

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] multiframe_count      Time of day information 0 .. 3 bytes
   \param[in] tod_extended_seconds  Time of day information 4 .. 5 bytes
   \param[in] tod_seconds           Time of day information 6 .. 9 bytes
   \param[in] tod_nano_seconds      Time of day information 10 .. 13 bytes
*/
enum omci_api_return omci_api_olt_g_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint32_t multiframe_count,
					   uint32_t tod_extended_seconds,
					   uint32_t tod_seconds,
					   uint32_t tod_nano_seconds);

/** @} */

/** @} */

__END_DECLS

#endif
