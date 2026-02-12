/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_ll_eim_h
#define _drv_onu_ll_eim_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_EIM Ethernet Interface Module Low-level Functions

   Low-level functions to access the Ethernet interface hardware module (EIM).
   @{
*/

#define EIM_RGMII_CLK_DELAY_MAX				(7)

#define EIM_GMII_XMII_IDX				(0)

enum eim_gmii_mode {
	/**
	mode detected by autonegotiation */
	EIM_GMII_MODE_AUTO = 0,
	/**
	MII/RMII interface mode at 10, 100, or 200 Mbit/s*/
	EIM_GMII_MODE_MII  = 1,
	/**
	GMII/RGMII interface mode at 1000 Mbit/s*/
	EIM_GMII_MODE_GMII = 2
};

enum eim_xmii_mode {
	/**
	(G)MII PHY mode, connected to external MAC*/
	EIM_XMII_MODE_MIIP  = 0,
	/**
	(G)MII MAC mode, connected to external PHY*/
	EIM_XMII_MODE_MIIM  = 1,
	/**
	RMII PHY mode, connected to external MAC*/
	EIM_XMII_MODE_RMIIP = 2,
	/**
	RMII MAC mode, connected to external PHY*/
	EIM_XMII_MODE_RMIIM = 3,
	/**
	RGMII MAC mode, connected to external PHY*/
	EIM_XMII_MODE_RGMII = 4
};

/**
   Selects the data and clock rate for the xMII interface.
   This setting is used for MII, TMII PHY, and for RGMII tx_clk.
   IN RMII mode, 50 MHz must always be selected.
   Autopolling should not be selected for XMII TMII Phy Mode.*/
enum eim_xmii_clk_rate {
	/**
	2.5 MHz*/
	EIM_XMII_CLK_RATE_2P5MHZ = 0,
	/**
	25 MHz*/
	EIM_XMII_CLK_RATE_25MHZ  = 1,
	/**
	125 MHz*/
	EIM_XMII_CLK_RATE_125MHZ = 2,
	/**
	50 MHz*/
	EIM_XMII_CLK_RATE_50MHZ  = 3,
	/**
	Speed used from Autopolling*/
	EIM_XMII_CLK_RATE_AUTO   = 4
};

/**
   Read MDIO register.
*/
int eim_mdio_data_read(const uint8_t addr_dev, const uint8_t addr_reg,
		       uint16_t *data);

/**
   Write MDIO register.
*/
int eim_mdio_data_write(const uint8_t addr_dev, const uint8_t addr_reg,
			const uint16_t data);

/**
   Set address for internal PHY
*/
void eim_gphy_cfg_addr_set(const uint8_t phy_id, const uint8_t phy_addr);

/**
   Get address for internal PHY
*/
uint8_t eim_gphy_cfg_addr_get(const uint8_t phy_id);

/**
   Set address for automatic PHY status polling
*/
void eim_phy_addr_set(const uint8_t uni_port_id, const uint8_t phy_addr);

/**
   Set automatic PHY status polling

   \param uni_port_id port number
   \param enable enable/disable
*/
int eim_phy_autopoll_enable_set(const uint8_t uni_port_id, const bool enable);

/**
   Get automatic PHY status polling

   \param uni_port_id port number
   \param enable enable/disable
*/
int eim_phy_autopoll_enable_get(const uint8_t uni_port_id, bool *enable);

#ifdef CONFIG_WITH_FALCON_A2X
/**
   Force settings for temporary disabling of auto-polling

   \param phy_addr phy address for which
   \param port_id  pointer to return port number for later restore
   \param restore  pointer to return register value for later restore
   \return 0 for all cases, where settings must be restored,
           !0 for all other cases
*/
int eim_phy_autopoll_force_current(const uint8_t phy_addr, uint8_t *port_id,
				   uint32_t *restore);

/**
   Restore settings for auto-polling

   \param port_id port number
   \param restore register value to restore
*/
void eim_phy_autopoll_restore_settings(uint8_t port_id, uint32_t restore);

/**
   Get status register from auto-polling
*/
int eim_phy_autopoll_status_get(uint8_t port_id, uint32_t *mdio_stat);
#endif

/**
   Set short preamble mode

   \param uni_port_id port number
   \param enable enable/disable
*/
int eim_short_preamble_enable_set(const uint8_t uni_port_id, const bool enable);

/**
   Get short preamble mode

   \param uni_port_id port number
   \param enable enable/disable
*/
int eim_short_preamble_enable_get(const uint8_t uni_port_id, bool *enable);

/**
   Set flow control mode

   \param port_id port number
   \param mode flow control mode
*/
int eim_flow_ctrl_set(const uint8_t port_id,
		      const enum lan_mode_flow_control mode);

/**
   Set duplex mode

   \param port_id port number
   \param mode duplex mode
*/
int eim_duplex_mode_set(const uint8_t port_id, const enum lan_mode_duplex mode);

/**
   Get duplex mode

   \param port_id port number
   \param mode duplex mode
*/
void eim_duplex_mode_get(const uint8_t port_id, enum lan_mode_duplex *mode);


/**
   Set speed mode mode

   \param port_id port number
   \param mode speed mode
*/
int eim_speed_mode_set(const uint8_t port_id, const enum lan_mode_speed mode);

/**
   Enable/disable Frame checksum generation

   \param port_id port number
   \param enable enable/disable
*/
int eim_fcs_enable(const uint8_t port_id, const bool enable);

/**
   Set GMII mode

   \param port_id port number
   \param mode GMII mode
*/
int eim_gmii_mode_set(const uint8_t port_id, const enum eim_gmii_mode mode);

/**
   Get GMII mode

   \param port_id port number
   \param mode GMII mode
*/
int eim_gmii_mode_get(const uint8_t port_id, enum eim_gmii_mode *mode);

/**
   Enable xMII interface

   \param xmii_idx xMII index (0 or 1)
   \param enable enable/disable
*/
void eim_xmii_enable(const uint8_t xmii_idx, const bool enable);

/**
   Reset xMII interface

   \param xmii_idx xMII index (0 or 1)
   \param on       enable/disable
*/
void eim_xmii_reset(const uint8_t xmii_idx, const bool on);

/**
   Set xMII mode

   \param xmii_idx xMII index (0 or 1)
   \param mode xMII mode
*/
void eim_xmii_mode_set(const uint8_t xmii_idx, const enum eim_xmii_mode mode);

/**
   Enable xMII jitter buffers

   \param xmii_idx xMII index (0 or 1)
   \param rxb RX buffer enable/disable
   \param txb RX buffer enable/disable
*/
void eim_xmii_jitter_buf_enable(const uint8_t xmii_idx, const bool rxb,
				const bool txb);

/**
   Set xMII clock rate

   \param xmii_idx xMII index (0 or 1)
   \param val xMII clock rate value
*/
void eim_xmii_clk_rate_set(const uint8_t xmii_idx,
			   const enum eim_xmii_clk_rate val);

/**
   Set xMII clock delays

   \param xmii_idx xMII index (0 or 1)
   \param tx_dly TX clock delay
   \param rx_dly RX clock delay
*/
void eim_xmii_clk_dly_set(const uint8_t xmii_idx, const uint8_t tx_dly,
			  const uint8_t rx_dly);

/**
   Enable MAC Loop

   \param port_id port number
   \param en enable/disable
*/
void eim_mac_loop_enable(const uint8_t port_id, const bool en);

/**
   Enable xMII Loop

   \param xmii_idx xMII index (0 or 1)
   \param en enable/disable
*/
void eim_mii_loop_enable(const uint8_t xmii_idx, const bool en);

/**
   Enable SGMII Loop

   \param en enable/disable
*/
void eim_sgmii_loop_enable(const bool en);

/**
   Central EIM Interrupt Enable Set

   \param clear interrupt mask to clear
   \param set   interrupt mask to set
*/
void eim_central_interrupt_enable_set(const uint32_t clear, const uint32_t set);

/**
   Central EIM Interrupt Enable Get
*/
uint32_t eim_central_interrupt_enable_get(void);

/**
   EIM counters get

   \param idx   port number
   \param cnt   counters
*/
void eim_mac_cnt_get(const uint8_t idx, struct mac_counter *cnt);

/**
   Enable/disable MAC LPI mode

   \param port_id  port number
   \param en	   enable/disable
*/
void eim_mac_lpi_enable(const uint8_t port_id, const bool en);

/**
   Set MAC Frame Length

   \param val  MAC Frame Length, bits 0..13 valid
*/
void eim_mac_frame_length_set(const uint16_t val);

/**
   Get MAC Frame Length

   \return
   MAC Frame Length, bits 0..13 valid
*/
uint16_t eim_mac_frame_length_get(void);

void eim_mac_err_status_get(const uint8_t port_id, bool *toolong, bool *ig_ovfl);

#if defined(INCLUDE_DUMP)

/**
   Dump the OCTRLG register block.
*/
void eim_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
