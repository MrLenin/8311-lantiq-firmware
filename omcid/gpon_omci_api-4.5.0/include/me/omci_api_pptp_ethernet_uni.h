/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_pptp_ethernet_uni
#define _omci_api_me_pptp_ethernet_uni

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_PPTP_ETHERNET_UNI Physical Path Termination Point Ethernet UNI

   This Managed Entity represents the point at an Ethernet UNI where the
   physical path terminates and Ethernet physical level functions are performed.

   The ONU automatically creates an instance of this Managed Entity per port:
   - When the ONU has Ethernet ports built into its factory configuration.
   - When a cardholder is provisioned to expect a circuit pack of Ethernet type.
   - When a cardholder provisioned for plug-and-play is equipped with a circuit
      pack of Ethernet type. Note that the installation of a plug-and-play card
      may indicate the presence of Ethernet ports via equipment ID as well as
      its type, and indeed may cause the ONU to instantiate a port mapping
      package that specifies Ethernet ports.

   The ONU automatically deletes instances of this Managed Entity when a
   cardholder is neither provisioned to expect an Ethernet circuit pack, nor is
   it equipped with an Ethernet circuit pack.

   @{
*/

/** Maximum PPTP Eth UNI instances count*/
#define OMCI_API_PPPTP_ETHERNET_UNI_MAX 4

/** Supported values of Auto detection configuration parameter in
    \ref omci_api_pptp_ethernet_uni_create and
    \ref omci_api_pptp_ethernet_uni_update
*/
enum omci_api_ppptp_ethernet_uni_auto_detect_cfg {
	/** Rate = Auto, DUPLEX = Auto */
	OMCI_API_PPPTPETHUNI_DETECT_AUTO = 0x00,
	/** Rate = 10 only, DUPLEX = FULL only */
	OMCI_API_PPPTPETHUNI_DETECT_10_FULL = 0x01,
	/** Rate = 100 only, DUPLEX = FULL only */
	OMCI_API_PPPTPETHUNI_DETECT_100_FULL = 0x02,
	/** Rate = 1000 only, DUPLEX = FULL only */
	OMCI_API_PPPTPETHUNI_DETECT_1000_FULL = 0x03,
	/** Rate = Auto, DUPLEX = FULL only */
	OMCI_API_PPPTPETHUNI_DETECT_AUTO_FULL = 0x04,
	/** Rate = 10 only, DUPLEX = AUTO */
	OMCI_API_PPPTPETHUNI_DETECT_10_AUTO = 0x10,
	/** Rate = 10 only, DUPLEX = Half only */
	OMCI_API_PPPTPETHUNI_DETECT_10_HALF = 0x11,
	/** Rate = 100 only, DUPLEX = Half only */
	OMCI_API_PPPTPETHUNI_DETECT_100_HALF = 0x12,
	/** Rate = 1000 only, DUPLEX = Half only */
	OMCI_API_PPPTPETHUNI_DETECT_1000_HALF = 0x13,
	/** Rate = Auto, DUPLEX = Half only */
	OMCI_API_PPPTPETHUNI_DETECT_AUTO_HALF = 0x14,
	/** Rate = 1000 only, DUPLEX = Auto */
	OMCI_API_PPPTPETHUNI_DETECT_1000_AUTO = 0x20,
	/** Rate = 100 only, DUPLEX = Auto */
	OMCI_API_PPPTPETHUNI_DETECT_100_AUTO = 0x30,
};

/** Supported values of Expected type */
enum omci_api_ppptp_ethernet_uni_expected_type {
	/* Default value - auto negotiation */
	OMCI_API_PPTPETHUNI_EXPECTED_TYPE_NOLIM = 0,
	/* 10 BaseT Ethernet LAN IF */
	OMCI_API_PPTPETHUNI_EXPECTED_TYPE_10BASET = 22,
	/* 100 BaseT Ethernet LAN IF */
	OMCI_API_PPTPETHUNI_EXPECTED_TYPE_100BASET = 23,
	/* 10/100 BaseT Ethernet LAN IF */
	OMCI_API_PPTPETHUNI_EXPECTED_TYPE_10_100BASET = 24,
	/* 10/100/1000 BaseT Ethernet LAN IF */
	OMCI_API_PPTPETHUNI_EXPECTED_TYPE_10_100_1000BASET = 47,
};

/** Supported values of Ethernet loopback configuration parameter in
    \ref omci_api_pptp_ethernet_uni_create and
    \ref omci_api_pptp_ethernet_uni_update
*/
enum omci_api_ppptp_ethernet_uni_ethernet_loopback {
	/** No loopback */
	OMCI_API_PPPTPETHUNI_LOOPBACK_DISABLED = 0,
	/** Loopback of downstream traffic after PHY transceiver */
	OMCI_API_PPPTPETHUNI_LOOPBACK_ENABLED = 3
};

/** Supported values of Bridged or IP ind parameter in
    \ref omci_api_pptp_ethernet_uni_create and
    \ref omci_api_pptp_ethernet_uni_update
*/
enum omci_api_bridge_or_router_cfg {
	/** Bridged */
	OMCI_API_BRIDGE,
	/** IP router */
	OMCI_API_ROUTER,
	/** Depends on the parent circuit pack */
	OMCI_API_PARENT_DEPEND
};

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

   \param[in] ctx                  OMCI API context pointer
   \param[in] me_id                Managed Entity identifier
   \param[in] admin_state          Administrative state
   \param[in] expected_type        Expected type
   \param[in] auto_detect_cfg      Auto detection configuration
   \param[in] ethernet_loopback    Ethernet loopback configuration
   \param[in] max_frame_size       Max frame size
   \param[in] dte_dce_ind          DTE or DCE ind
   \param[in] pause_time           Pause time
   \param[in] bridge_or_router_cfg Bridged or IP ind
   \param[in] pppoe_filter         PPPoE filter
   \param[in] power_control        Power control
*/
enum omci_api_return
omci_api_pptp_ethernet_uni_create(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint8_t admin_state,
				  uint8_t expected_type,
				  uint8_t auto_detect_cfg,
				  uint8_t ethernet_loopback,
				  uint16_t max_frame_size,
				  uint8_t dte_dce_ind,
				  uint16_t pause_time,
				  uint8_t bridge_or_router_cfg,
				  uint8_t pppoe_filter,
				  uint8_t power_control);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_pptp_ethernet_uni_destroy(struct omci_api_ctx *ctx,
				   uint16_t me_id);

/** Update PPTP Ethernet UNI ME resources

   \param[in] ctx                  OMCI API context pointer
   \param[in] me_id                Managed Entity identifier
   \param[in] admin_state          Administrative state
   \param[in] expected_type        Expected type
   \param[in] auto_detect_cfg      Auto detection configuration
   \param[in] ethernet_loopback    Ethernet loopback configuration
   \param[in] max_frame_size       Max frame size
   \param[in] dte_dce_ind          DTE or DCE ind
   \param[in] pause_time           Pause time
   \param[in] bridge_or_router_cfg Bridged or IP ind
   \param[in] pppoe_filter         PPPoE filter
   \param[in] power_control        Power control
*/
enum omci_api_return
omci_api_pptp_ethernet_uni_update(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint8_t admin_state,
				  uint8_t expected_type,
				  uint8_t auto_detect_cfg,
				  uint8_t ethernet_loopback,
				  uint16_t max_frame_size,
				  uint8_t dte_dce_ind,
				  uint16_t pause_time,
				  uint8_t bridge_or_router_cfg,
				  uint8_t pppoe_filter,
				  uint8_t power_control);

/** Retrieve current Configuration indication

   \param[in]  ctx            OMCI API context pointer
   \param[in]  me_id          Managed Entity identifier
   \param[out] cfg_ind        Configuration ind
*/
enum omci_api_return
omci_api_pptp_ethernet_uni_configuration_ind_get(struct omci_api_ctx *ctx,
						 uint16_t me_id,
						 uint8_t *cfg_ind);

/** @} */

/** @} */

__END_DECLS

#endif
