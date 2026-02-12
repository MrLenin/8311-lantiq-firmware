/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_circuit_pack_h
#define _omci_api_me_circuit_pack_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_CIRCUIT_PACK Circuit Pack

   This Managed Entity models a circuit pack that is equipped in an ONU slot.
   For ONUs with integrated interfaces, this Managed Entity may be used to
   distinguish available types of interfaces (the port mapping package is
   another way). For ONUs with integrated interfaces, the ONU automatically
   creates an instance of this Managed Entity for each instance of the virtual
   cardholder Managed Entity. The ONU also creates an instance of this managed
   entity when the OLT provisions the cardholder to expect a circuit pack (for
   example when the OLT sets the expected plug-in unit type or equipment ID of
   the cardholder to a circuit pack type, as defined in clause 9.1.5).
   The ONU also creates an instance of this Managed Entity when a circuit pack
   is installed in a cardholder whose expected plug-in unit type is
   255 = plug-and-play, and whose equipment ID is not provisioned. Finally, when
   the cardholder is provisioned for plug-and-play, an instance of this managed
   entity can be created at the request of the OLT.

   @{
*/

/* ME ID value is the same as that of the cardholder Managed Entity containing
   this circuit pack instance. */

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

    \param[in] ctx                 OMCI API context pointer
    \param[in] me_id               Managed Entity identifier
    \param[in] type                Type
    \param[in] port_num            Number of ports
    \param[in] bridged_or_ip_ind   Bridged or IP ind
    \param[in] card_configuration  Card configuration
    \param[in] power_shed_override Power shed override
*/
enum omci_api_return
omci_api_circuit_pack_create(struct omci_api_ctx *ctx,
			     uint16_t me_id,
			     uint8_t type,
			     uint8_t port_num,
			     uint8_t bridged_or_ip_ind,
			     uint8_t card_configuration,
			     uint32_t power_shed_override);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

    \param[in] ctx   OMCI API context pointer
    \param[in] me_id Managed Entity identifier
*/
enum omci_api_return omci_api_circuit_pack_destroy(struct omci_api_ctx *ctx,
						   uint16_t me_id);

/** Update Circuit Pack ME resources

    \param[in] ctx                 OMCI API context pointer
    \param[in] me_id               Managed Entity identifier
    \param[in] bridged_or_ip_ind   Bridged or IP ind
    \param[in] card_configuration  Card configuration
    \param[in] power_shed_override Power shed override
*/
enum omci_api_return omci_api_circuit_pack_update(struct omci_api_ctx *ctx,
						  uint16_t me_id,
						  uint8_t bridged_or_ip_ind,
						  uint8_t card_configuration,
						  uint32_t power_shed_override);

/** @} */

/** @} */

__END_DECLS

#endif
