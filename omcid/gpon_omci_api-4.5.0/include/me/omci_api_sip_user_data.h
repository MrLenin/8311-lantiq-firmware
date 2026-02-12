/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_sip_user_data
#define _omci_api_me_sip_user_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_SIP_USER_DATA SIP user data

    The SIP user data defines the user specific configuration attributes
    associated with a specific VoIP CTP. This entity is conditionally required
    for ONUs that offer VoIP SIP services. If a non-OMCI interface is used to
    manage SIP for VoIP, this ME is unnecessary. The non-OMCI interface supplies
    the necessary data, which may be read back to the OLT via the SIP config
    portal ME.

    An instance of this managed entity is created and deleted by the OLT. A SIP
    user data instance is required for each POTS UNI port using SIP protocol and
    configured by OMCI.

   @{
*/

/** Update SIP user data ME resources

   \param[in] ctx               OMCI API context pointer
   \param[in] me_id             Managed Entity identifier
   \param[in] agent_ptr         SIP agent ME pointer
   \param[in] user_part_aor     User identification part of the address
   \param[in] username          SIP user name
   \param[in] password          SIP password
   \param[in] realm             Authentication security method ME realm
   \param[in] validation_scheme Authentication security method ME validation
                                scheme
   \param[in] pptp_ptr          PPTP POTS UNI pointer
   \param[in] ip_addr           IP host config data ME IP address
*/
enum omci_api_return
omci_api_sip_user_data_update(struct omci_api_ctx *ctx,
			      uint16_t me_id,
			      uint16_t agent_ptr,
			      char *user_part_aor,
			      char *username,
			      char *password,
			      char *realm,
			      uint8_t validation_scheme,
			      uint16_t pptp_ptr,
			      uint32_t ip_addr);

/** Clenup SIP user data ME resources

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
*/
enum omci_api_return
omci_api_sip_user_data_destroy(struct omci_api_ctx *ctx,
			       uint16_t me_id);

/** @} */

/** @} */

__END_DECLS

#endif
