/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_pptp_pots_uni
#define _omci_api_me_pptp_pots_uni

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_PPTP_POTS_UNI PPTP POTS UNI

    This managed entity represents a POTS UNI in the ONU, where a physical path
    terminates and physical path level functions (analogue telephony) are
    performed.

    The ONU automatically creates an instance of this managed entity per port:
       *  When the ONU has POTS ports built into its factory configuration
       *  When a cardholder is provisioned to expect a circuit pack of POTS type
       *  When a cardholder provisioned for plug and play is equipped with a
	  circuit pack of POTS type. Note that the installation of a plug and
	  play card may indicate the presence of POTS ports via equipment ID as
	  well as type, and indeed may cause the ONU to instantiate a port
	  mapping package that specifies POTS ports.

    The ONU automatically deletes instances of this managed entity when a
    cardholder is neither provisioned to expect a POTS circuit pack, nor is
    equipped with a POTS circuit pack.

   @{
*/

/** Update PPTP POTS UNI ME resources

   \param[in] ctx		OMCI API context pointer
   \param[in] me_id		Managed Entity identifier
   \param[in] admin_state	Administrative state
   \param[in] impedance		Impedance
   \param[in] rx_gain		Rx gain
   \param[in] tx_gain		Tx gain
*/
enum omci_api_return
omci_api_pptp_pots_uni_update(struct omci_api_ctx *ctx,
			      uint16_t me_id,
			      uint8_t admin_state,
			      uint8_t impedance,
			      uint8_t rx_gain,
			      uint8_t tx_gain);

/** Allocate PPTP POTS UNI ME resouces

   \param[in] ctx       OMCI API context pointer
   \param[in] me_id     Managed Entity identifier
*/
enum omci_api_return
omci_api_pptp_pots_uni_create(struct omci_api_ctx *ctx,
			      uint16_t me_id);

/** Cleanup PPTP POTS UNI ME resouces

   \param[in] ctx       OMCI API context pointer
   \param[in] me_id     Managed Entity identifier
*/
enum omci_api_return
omci_api_pptp_pots_uni_destroy(struct omci_api_ctx *ctx,
			       uint16_t me_id);

/** Get hoot state

   \param[in]  ctx        OMCI API context pointer
   \param[in]  me_id      Managed Entity identifier
   \param[out] hook_state Returns hook state
*/
enum omci_api_return
omci_api_pptp_pots_uni_hook_state_get(struct omci_api_ctx *ctx,
				      uint16_t me_id,
				      uint8_t *hook_state);

/** @} */

/** @} */

__END_DECLS

#endif
