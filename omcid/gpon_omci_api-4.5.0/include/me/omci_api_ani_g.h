/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_ani_g_h
#define _omci_api_me_ani_g_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_ANI_G ANI-G
   This Managed Entity models the ONU's upstream interface towards the OLT.
   @{
*/

/** Disable Managed Entity identifier mapping to driver index and clear
   corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier

   \remark me_id is not used by device (therefore no mapping)
*/
enum omci_api_return omci_api_ani_g_destroy(struct omci_api_ctx *ctx,
					    uint16_t me_id);

/** Update ANI-G ME resources

   \param[in] ctx                      OMCI API context pointer
   \param[in] me_id                    Managed Entity identifier
   \param[in] gem_block_len            GEM block length
   \param[in] sf_threshold             SF threshold
   \param[in] sd_threshold             SD threshold
   \param[in] lower_optic_threshold    Lower optical threshold
   \param[in] upper_optic_threshold    Upper optical threshold
   \param[in] lower_tx_power_threshold Lower transmit power threshold
   \param[in] upper_tx_power_threshold Upper transmit power threshold

   \remark me_id is not used by device (therefore no mapping)
*/
enum omci_api_return omci_api_ani_g_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t gem_block_len,
					   uint8_t sf_threshold,
					   uint8_t sd_threshold,
					   uint8_t lower_optic_threshold,
					   uint8_t upper_optic_threshold,
					   uint8_t lower_tx_power_threshold,
					   uint8_t upper_tx_power_threshold);

/** Retrieve SR indication mode

   \param[in]  ctx                 OMCI API context pointer
   \param[in]  me_id               Managed Entity identifier
   \param[out] sr_indication       SR indication mode

   \remark me_id is not used by device (therefore no mapping)
*/
enum omci_api_return omci_api_ani_g_sr_indication_get(struct omci_api_ctx *ctx,
						      uint16_t me_id,
						      uint8_t *sr_indication);

/** Retrieve total available T-CONT number

   \param[in]  ctx                 OMCI API context pointer
   \param[in]  me_id               Managed Entity identifier
   \param[out] total_tcon_num      Total available T-CONT number

   \remark me_id is not used by device (therefore no mapping)
*/
enum omci_api_return
omci_api_ani_g_total_tcon_num_get(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t *total_tcon_num);

/** Retrieve current Optical Signal Level

   \param[in]  ctx                 OMCI API context pointer
   \param[in]  me_id               Managed Entity identifier
   \param[out] optical_signal_level Optical Signal level

   \remark me_id is not used by device (therefore no mapping)
*/
enum omci_api_return
omci_api_ani_g_optical_signal_level_get(struct omci_api_ctx *ctx,
					uint16_t me_id,
					int16_t *optical_signal_level);

/** Retrieve actual ONU response time

   \param[in]  ctx              OMCI API context pointer
   \param[in]  me_id            Managed Entity identifier
   \param[out] ont_response_time ONU Response Time

   \remark me_id is not used by device (therefore no mapping)
*/
enum omci_api_return
omci_api_ani_g_response_time_get(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 uint16_t *ont_response_time);

/** Retrieve current Transmit Optical Level

   \param[in]  ctx              OMCI API context pointer
   \param[in]  me_id            Managed Entity identifier
   \param[out] tx_optical_level Transmit Optical Level

   \remark me_id is not used by device (therefore no mapping)
*/
enum omci_api_return
omci_api_ani_g_tx_optical_level_get(struct omci_api_ctx *ctx,
				    uint16_t me_id,
				    int16_t *tx_optical_level);

/** Retrieve laser bias current (G.988 Table 9.2.1)

   \param[in]  ctx                OMCI API context pointer
   \param[in]  me_id              Managed Entity identifier
   \param[out] laser_bias_current Laser bias current in units of 2 uA

   \remark Uses FIO_BOSA_TX_STATUS_GET (v7.5.1 24-byte struct)
*/
enum omci_api_return
omci_api_ani_g_laser_bias_current_get(struct omci_api_ctx *ctx,
				      uint16_t me_id,
				      uint16_t *laser_bias_current);

/** Retrieve laser/module temperature (G.988 Table 9.2.1)

   \param[in]  ctx         OMCI API context pointer
   \param[in]  me_id       Managed Entity identifier
   \param[out] temperature Temperature in units of 1/256 degree C (signed)

   \remark Uses FIO_MM_LASER_TEMPERATURE_GET
*/
enum omci_api_return
omci_api_ani_g_laser_temperature_get(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     int16_t *temperature);

/** Retrieve supply voltage (G.988 Table 9.2.1)

   \param[in]  ctx            OMCI API context pointer
   \param[in]  me_id          Managed Entity identifier
   \param[out] supply_voltage Supply voltage in units of 20 mV

   \remark Uses FIO_MM_SUPPLY_VOLTAGE_GET (new in v7.5.1, ioctl #10)
*/
enum omci_api_return
omci_api_ani_g_supply_voltage_get(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t *supply_voltage);

/** Retrieve GEM block length from hardware

   \param[in]  ctx           OMCI API context pointer
   \param[in]  me_id         Managed Entity identifier
   \param[out] gem_block_len GEM block length in bytes
*/
enum omci_api_return
omci_api_ani_g_gem_block_len_get(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 uint16_t *gem_block_len);

/** @} */

/** @} */

__END_DECLS

#endif
