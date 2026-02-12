/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_cardholder_h
#define _omci_api_me_cardholder_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_CARDHOLDER Cardholder

   The cardholder represents the fixed equipment slot configuration of the ONU.
   One or more of these entities is contained in the ONU. Each cardholder can
   contain 0 or 1 circuit packs; the circuit pack models equipment information
   that can change over the lifetime of the ONU, e.g., through replacement.
   An instance of this Managed Entity exists for each physical slot in an ONU
   that has pluggable circuit packs. One or more instances of this managed
   entity may also exist in an integrated ONU, to represent virtual slots.
   Instances of this Managed Entity are created automatically by the ONU, and
   the status attributes are populated according to data within the ONU itself.
   There is potential for conflict in the semantics of the expected plug-in unit
   type, the expected port count and the expected equipment id, both when the
   slot is not populated and when a new circuit pack is inserted. The expected
   plug-in unit type and the plug-in type mismatch alarm are mandatory, although
   plug-and-play/unknown (circuit pack type 255) may be used as a way to
   minimize their significance. It is recommended that an ONU deny the
   provisioning of inconsistent combinations of expected equipment attributes.
   When a circuit pack is plugged into a cardholder, or when a cardholder is
   preprovisioned to expect a circuit pack of a given type, it may trigger the
   ONU to instantiate a number of managed entities and update the values of
   others, depending on the circuit pack type. The ONU may also delete a variety
   of other managed entities when a circuit pack is reprovisioned to expect no
   circuit pack or a circuit   pack of a different type. These actions are
   described in the definitions of the various managed entities.
   Expected equipment id and expected port count are alternate ways to trigger
   the same preprovisioning effects. These tools may be useful if an ONU is
   prepared to accept more than one circuit pack of a given type but with
   different port counts, or if a circuit pack is a hybrid that matches none of
   the types in Table 9.1.5-1, but whose identification (e.g., part number) is
   known.

   @{
*/

/** Size of Expected equipment id parameter in
    \ref omci_api_cardholder_create and
    \ref omci_api_cardholder_update
*/
#define OMCI_API_CARDHOLDER_EQUIPMENTID_SIZE 20

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

   \param[in] ctx                        OMCI API context pointer
   \param[in] me_id                      Managed Entity identifier
   \param[in] expected_plug_in_unit_type Expected plug-in unit type
   \param[in] expected_port_count        Expected port count
   \param[in] expected_equipment_id      Expected equipment id
   \param[in] invoke_protection_switch   Invoke protection switch
*/
enum omci_api_return
omci_api_cardholder_create(struct omci_api_ctx *ctx,
			   uint16_t me_id,
			   uint8_t expected_plug_in_unit_type,
			   uint8_t expected_port_count,
			   const uint8_t expected_equipment_id
			   [OMCI_API_CARDHOLDER_EQUIPMENTID_SIZE],
			   uint8_t invoke_protection_switch);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return omci_api_cardholder_destroy(struct omci_api_ctx *ctx,
						 uint16_t me_id);

/** Update Cardholder ME resources

   \param[in] ctx                        OMCI API context pointer
   \param[in] me_id                      Managed Entity identifier
   \param[in] expected_plug_in_unit_type Expected plug-in unit type
   \param[in] expected_port_count        Expected port count
   \param[in] expected_equipment_id      Expected equipment id
   \param[in] invoke_protection_switch   Invoke protection switch
*/
enum omci_api_return
omci_api_cardholder_update(struct omci_api_ctx *ctx,
			   uint16_t me_id,
			   uint8_t expected_plug_in_unit_type,
			   uint8_t expected_port_count,
			   const uint8_t expected_equipment_id
			   [OMCI_API_CARDHOLDER_EQUIPMENTID_SIZE],
			   uint8_t invoke_protection_switch);

/** @} */

/** @} */

__END_DECLS

#endif
