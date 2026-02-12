/******************************************************************************

                              Copyright (c) 2011
                           Lantiq Deutschland GmbH

For licensing information, see the file 'LICENSE' in the root folder of
this software module.

******************************************************************************/
/**
   \file drv_onu_lan.c
   This is the GPON Ethernet interface module program file, used for Lantiq's
   FALCON GPON Modem driver.
*/

#include "ifxos_time.h"

#include "drv_onu_api.h"
#include "drv_onu_lan_api.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_gpe_tables_api.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_ll_eim.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_ssb.h"
#include "drv_onu_ll_ictrll.h"
#include "drv_onu_ll_octrll.h"
#include "drv_onu_ll_eim.h"
#include "drv_onu_ll_iqm.h"
#include "drv_onu_ll_fsqm.h"
#include "drv_onu_ll_tmu.h"
#include "drv_onu_ll_gpearb.h"
#include "drv_onu_register.h"
#include "drv_onu_timer.h"

/** If defined the standard PHY loop is used, otherwise a Lantiq special GPHY 
 loop is used. */
#define STD_PHY_NE_LOOP

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \addtogroup ONU_LAN_INTERNAL
   @{
*/

typedef enum onu_errorcode (*lan_mode_set_t) (	struct onu_control *const ctrl,
						const struct lan_port_cfg *in);

STATIC enum onu_errorcode lan_phy_loop_enable_set(struct onu_control *ctrl,
		const int8_t phy_addr, const bool fe, const bool ne);
STATIC enum onu_errorcode lan_phy_mode_control_set(struct onu_control *ctrl,
						   const int8_t phy_addr,
						   const enum lan_mode_speed
						   speed,
						   const enum lan_mode_duplex
						   duplex);
STATIC enum onu_errorcode lan_phy_fw_ver_get(struct onu_control *ctrl,
					     const int8_t phy_addr,
					     struct gphy_fw_version *fw_ver);
STATIC enum onu_errorcode lan_phy_wol_cfg_apply(struct onu_control *ctrl,
						const uint8_t port_num);
STATIC enum onu_errorcode lan_phy_settings_update(struct onu_control *ctrl,
						  const uint8_t port_num);

STATIC enum onu_errorcode gphy_phy_status_update(struct onu_control *ctrl,
						 const uint8_t port_num);

STATIC enum onu_errorcode lan_phy_status_get(struct onu_control *ctrl,
					     const uint8_t port_idx,
					     struct lan_link_status *link_status);

#if ONU_GPE_MAX_ETH_UNI > 2
STATIC enum onu_errorcode lan_gphy_led_init(struct onu_control *ctrl,
					    const uint8_t port_num);
#endif

STATIC enum onu_errorcode lan_phy_capability_cfg_apply(struct onu_control *ctrl,
						       int8_t phy_addr,
						       const struct
						       lan_port_capability_cfg
						       *param)
{
	enum onu_errorcode ret;
	uint32_t an_adv = 0;
	uint32_t gctrl = 0;
	uint32_t eee_set = 0;
	uint32_t eee_clear = 0;

	/* advertise pause */
	if (param->asym_pause)
		an_adv |= MDIO_PHY_AN_ADV_PS_ASYM;
	if (param->sym_pause)
		an_adv |= MDIO_PHY_AN_ADV_PS_SYM;

	/* advertise mode */
	if (param->mbit_10) {
		if (param->half_duplex)
			an_adv |= MDIO_PHY_AN_ADV_XBT_HDX;
		if (param->full_duplex)
			an_adv |= MDIO_PHY_AN_ADV_XBT_FDX;
	}

	if (param->mbit_100) {
		if (param->half_duplex)
			an_adv |= MDIO_PHY_AN_ADV_DBT_HDX;
		if (param->full_duplex)
			an_adv |= MDIO_PHY_AN_ADV_DBT_FDX;
	}

	ret = lan_mdio_access(ctrl,
			      phy_addr,
			      MDIO_PHY_AN_ADV,
			      MDIO_PHY_AN_ADV_TAF_MASK,
			      an_adv,
			      NULL);
	if (ret != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("MDIO(%d) AN_ADV set failed, %d!",
			      phy_addr, ret);
		return ret;
	}

	if (param->mbit_1000) {
		if (param->half_duplex)
			gctrl |= MDIO_PHY_MODE_GCTRL_MBTHD;
		if (param->full_duplex)
			gctrl |= MDIO_PHY_MODE_GCTRL_MBTFD;
	}

	ret = lan_mdio_access(ctrl,
			      phy_addr,
			      MDIO_PHY_MODE_GCTRL,
			      MDIO_PHY_MODE_GCTRL_MBTHD |
			      MDIO_PHY_MODE_GCTRL_MBTFD,
			      gctrl,
			      NULL);
	if (ret != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("MDIO(%d) GCTRL set failed, %d!",
			      phy_addr, ret);
		return ret;
	}

	/* advertise eee - not implemented, see GPONSW-768 */
	if (param->eee)
		eee_set = MMD_EEE_AN_ADV_EEE_100BTX |
			MMD_EEE_AN_ADV_EEE_1000BT;
	else
		eee_clear = MMD_EEE_AN_ADV_MASK;

	ret = lan_mmd_access(ctrl,
		   phy_addr,
		   MMD_ANEG_SEL,
		   MMD_EEE_AN_ADV,
		   eee_clear,
		   eee_set,
		   NULL);
	if (ret != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("MMD(%d) AN_ADV set failed, %d!",
			      phy_addr, ret);
		return ret;
	}

	return ONU_STATUS_OK;
}

static int8_t phy_addr_get(struct onu_control *ctrl, const uint8_t uni_port_id)
{
	return ctrl->mdio_dev_addr[uni_port_id & 0x3];
}

enum onu_errorcode lan_gphy_firmware_download(struct onu_device *p_dev,
					      const struct lan_gphy_fw *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	/* deactivate all GPHYs for FW download modules*/
	sys_eth_hw_deactivate(SYS_ETH_DEACT_GPHY1 |
			      SYS_ETH_DEACT_GPHY0);

	/* deactivate all GPHYs for FW download modules*/
	sys_eth_hw_deactivate(SYS_ETH_DEACT_GPHY1 |
			      SYS_ETH_DEACT_GPHY0);

	if (onu_gphy_firmware_download(ctrl, param->fw_name) != 0)
		return LAN_STATUS_ERR;

	return ONU_STATUS_OK;
}

/** The lan_init function is called upon GPON startup to provide initial
    settings for the Ethernet interface hardware module. All interfaces are
    deactivated.
*/

/** Hardware Programming Details
   Disable all clocks:
   - SYS_ETH.CLKLR.GPHY0MII2
   - SYS_ETH.CLKLR.GPHY1MII2
   - SYS_ETH.CLKLR.xMII
   - SYS_ETH.CLKLR.SGMII
   - SYS_ETH.CLKLR.GPHY0
   - SYS_ETH.CLKLR.GPHY1
   - SYS_ETH.CLKLR.MDIO
   - SYS_ETH.CLKLR.GMAC0
   - SYS_ETH.CLKLR.GMAC1
   - SYS_ETH.CLKLR.GMAC2
   - SYS_ETH.CLKLR.GMAC3
   Deactivate all modules:
   - SYS_ETH.DEACT.xMII
   - SYS_ETH.DEACT.SGMII
   - SYS_ETH.DEACT.GPHY0
   - SYS_ETH.DEACT.GPHY1
   - SYS_ETH.DEACT.MDIO
   - SYS_ETH.DEACT.GMAC0
   - SYS_ETH.DEACT.GMAC1
   - SYS_ETH.DEACT.GMAC2
   - SYS_ETH.DEACT.GMAC3
   Deactivate the multiplexer:
   - SYS_ETH.GMUXC.GMAC0
   - SYS_ETH.GMUXC.GMAC1
   - SYS_ETH.GMUXC.GMAC2
   - SYS_ETH.GMUXC.GMAC3

*/
enum onu_errorcode lan_init(struct onu_device *p_dev)
{
	(void)p_dev;
	/* disable clocks*/
	sys_eth_hw_clk_disable(SYS_ETH_CLKCLR_GPHY1MII2 |
			       SYS_ETH_CLKCLR_GPHY0MII2);

	/* deactivate all modules*/
	sys_eth_hw_deactivate(SYS_ETH_DEACT_xMII |
			      SYS_ETH_DEACT_SGMII |
			      SYS_ETH_DEACT_GPHY1 |
			      SYS_ETH_DEACT_GPHY0 |
			      SYS_ETH_DEACT_MDIO |
			      SYS_ETH_DEACT_GMAC3 |
			      SYS_ETH_DEACT_GMAC2 |
			      SYS_ETH_DEACT_GMAC1 |
			      SYS_ETH_DEACT_GMAC0);

	/* correct PLL setting for gphy */
	eim_w32(0x27, top_pdi.gphy_cfg_pll);
	if (is_falcon_chip_a2x()) {
		/* enable 25MHz strobe for internal timeouts */
		eim_w32_mask(0, EIM_EIM_STRB_GEN1_CTL_EN,
			top_pdi.eim_strb_gen1_ctl);
	}

	return ONU_STATUS_OK;
}

/** The lan_cfg_set function is used to provide basic configurations of the
   Ethernet interface hardware module.
*/

/** Hardware Programming Details
   General procedure:
   1. enable clock(s)
   2. configure mode(s)
   3. activate

   eLAN_interfaceMuxMode defines the selected interface mode. Depending on this,
   the configuration is done.

   \remark For FPGA, only single GMII mode is available
	   (eLAN_interfaceMuxMode = LAN_MUX_GMII).

   Check configuration values
   (option bUNI_PortEnable0..3, option nUNI_PortMode0..3)
   - SYS_ETH.CLKEN.GMAC[n] = SET if bGMAC_Enable == true
   - SYS_ETH.CLKEN.MDIO    = SET if mdio_en == true
   - SYS_ETH.CLKEN.xMII    = SET if bMII_Enable == true
   - SYS_ETH.DRC.MDC       = check bMDIO_DataRateFast
   - SYS_ETH.DRC.xMII0

   - LAN_TOP_PDI.GPHY_CFG_ADDR_0 = set MDIO address for GPHY 0 or EPHY 0/1
   - LAN_TOP_PDI.GPHY_CFG_ADDR_1 = set MDIO address for GPHY 1 or EPHY 2/3

   - SYS_ETH.GMUXC.GMAC0..3 = depending on interface multiplex mode

   - LAN.MAC_CTRL_0.GMII   = depending on interface multiplex mode
   - LAN.MAC_CTRL_0.FDUP   = EN (AUTO is not supported by HW)
   - LAN.MAC_CTRL_0.FCS    = EN

   - LAN.LAN_MII_PDI_[n].MII_CFG = depending on interface multiplex mode
   - LAN.LAN_MII_PDI_[n].MII_CFG = depending on interface multiplex mode
   - LAN.LAN_MII_PDI_[n].BUFF.TXB_EN = 1
   - LAN.LAN_MII_PDI_[n].BUFF.RXB_EN = 1

   - SYS_ETH.ACT.GMAC[n]   = SET if bGMAC_Enable == true
   - SYS_ETH.ACT.MDIO      = SSET if mdio_en == true
   - SYS_ETH.ACT.xMII      = SET if bMII_Enable == true
   - SYS_ETH.ACT.xMII      = SET if one of the xMII ports is used,
			     else SYS_ETH.DEACT.xMII = CLR
   - SYS_ETH.ACT.SGMII     = SET if one of the SGMII ports is used,
			     else SYS_ETH.DEACT.SGMII = CLR
   - SYS_ETH.ACT.GPHY0     = SET if GPHY 0 is used,
			     else SYS_ETH.DEACT.GPHY0 = CLR
   - SYS_ETH.ACT.GPHY1     = SET if GPHY 1 is used,
			     else SYS_ETH.DEACT.GPHY1 = CLR
   - SYS_ETH.ACT.MDIO      = SET
   - SYS_ETH.ACT.GMAC0     = SET if LAN port 0 is used,
			     else SYS_ETH.DEACT.GMAC0 = CLR
   - SYS_ETH.ACT.GMAC1     = SET if LAN port 1 is used,
			     else SYS_ETH.DEACT.GMAC1 = CLR
   - SYS_ETH.ACT.GMAC2     = SET if LAN port 2 is used,
			     else SYS_ETH.DEACT.GMAC2 = CLR
   - SYS_ETH.ACT.GMAC3     = SET if LAN port 3 is used,
			     else SYS_ETH.DEACT.GMAC3 = CLR

   In case of RGMII mode:
   - LAN.LAN_MII_PDI_0.PCDU.TXDLY = config parameter from flash
   - LAN.LAN_MII_PDI_0.PCDU.RXDLY = config parameter from flash
   - Poll until LAN.LAN_MII_PDI_0.PCDU.TXLOCK == LOCKED
   - Poll until LAN.LAN_MII_PDI_0.PCDU.RXLOCK == LOCKED
*/
enum onu_errorcode lan_cfg_set(struct onu_device *p_dev,
			       const struct lan_cfg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t gphy_fw_addr;
	uint8_t i, j;
	enum gmac_mux_mode *gmac_mux;
	enum gmac_mux_mode fephy4_mode[] = {
	    GMAC_GPHY0_GMII, GMAC_GPHY1_GMII, GMAC_GPHY0_MII2, GMAC_GPHY1_MII2};
	enum gmac_mux_mode gphy2_rgmii2_mode[] = {
	    GMAC_GPHY0_GMII, GMAC_GPHY1_GMII, GMAC_xMII0, GMAC_xMII1};
	enum gmac_mux_mode gphy2_rgmii_sgmii_mode[] = {
	    GMAC_GPHY0_GMII, GMAC_GPHY1_GMII, GMAC_xMII0, GMAC_SGMII};
	enum gmac_mux_mode gphy2_gmii_sgmii_mode[] = {
	    GMAC_GPHY0_GMII, GMAC_GPHY1_GMII, GMAC_xMII0, GMAC_SGMII};
	enum gmac_mux_mode gphy_rgmii2_sgmii_mode[] = {
	    GMAC_GPHY0_GMII, GMAC_xMII0, GMAC_xMII1, GMAC_SGMII};
	enum gmac_mux_mode rgmii2_sgmii_mode[] = {
	    GMAC_xMII0, GMAC_xMII1, GMAC_GPHY0_GMII /*dummy*/, GMAC_SGMII};

	/* check if already configured*/
	if (ctrl->lan_mux_mode != LAN_MUX_UNDEFINED)
		/* allow the configuration only once */
		return LAN_STATUS_ALREADY_INITIALIZED;

	switch (param->mux_mode) {
	case LAN_MUX_FEPHY4:
		gmac_mux = fephy4_mode;
		break;
	case LAN_MUX_GPHY2_RGMII2:
		gmac_mux = gphy2_rgmii2_mode;
		break;
	case LAN_MUX_GPHY2_RGMII_SGMII:
		gmac_mux = gphy2_rgmii_sgmii_mode;
		break;
	case LAN_MUX_GPHY2_GMII_SGMII:
		gmac_mux = gphy2_gmii_sgmii_mode;
		break;
	case LAN_MUX_GPHY_RGMII2_SGMII:
		gmac_mux = gphy_rgmii2_sgmii_mode;
		break;
	case LAN_MUX_RGMII2_SGMII:
	case LAN_MUX_RGMII1:
		gmac_mux = rgmii2_sgmii_mode;
		break;
	case LAN_MUX_UNDEFINED:
	default:
		return LAN_STATUS_VALUE_RANGE_ERR;
	}

	if (param->mdio_data_rate < MDIO_MODE_SPEED_2M5 ||
	    param->mdio_data_rate > MDIO_MODE_SPEED_20M)
		return LAN_STATUS_VALUE_RANGE_ERR;

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		if (param->mdio_dev_addr[i] > 31)
			return LAN_STATUS_VALUE_RANGE_ERR;
		else
			for (j = i+1; j < ONU_GPE_MAX_ETH_UNI; j++)
				if (param->mdio_dev_addr[i] ==
					param->mdio_dev_addr[j] &&
				    param->mdio_dev_addr[i] !=
					ONU_LAN_MDIO_ADDR_NULL)
					return LAN_STATUS_VALUE_RANGE_ERR;
	}

	/* store param->mux_mode in the internal ONU context*/
	ctrl->lan_mux_mode = param->mux_mode;

	/* Decision of which firmware to use */
	gphy_fw_addr = ctrl->lan_gphy_fw_ram_addr;
	if (ctrl->lan_mux_mode == LAN_MUX_FEPHY4) {
		/* first byte of version type is at index 8 */
		if (memcmp(ctrl->lan_gphy_fw_version+8, "22F", 3) != 0)
			gphy_fw_addr = 0;    /* overrides RAM firmware */
	} else {
		/* first byte of version type is at index 8 */
		if (memcmp(ctrl->lan_gphy_fw_version+8, "11G", 3) != 0)
			gphy_fw_addr = 0;    /* overrides RAM firmware */
	}
	if (gphy_fw_addr == 0) {
		if (is_falcon_chip_a11())
			gphy_fw_addr = (param->mux_mode == LAN_MUX_FEPHY4) ?
				GPHY_22F_FIRMWARE_A11_ROM_ADDR :
				GPHY_11G_FIRMWARE_A11_ROM_ADDR;
		else
			gphy_fw_addr = (param->mux_mode == LAN_MUX_FEPHY4) ?
				GPHY_22F_FIRMWARE_A12_ROM_ADDR :
				GPHY_11G_FIRMWARE_A12_ROM_ADDR;
		
		/* This is not an error message. */
		/* This means the fw is overridden by the ROM version. */
		ONU_DEBUG_ERR("GPHY Firmware loaded from ROM (%X)", gphy_fw_addr);
	}
	
	sys_eth_gphy_boot_addr_set(0, gphy_fw_addr);
	sys_eth_gphy_boot_addr_set(1, gphy_fw_addr);

	sys_eth_hw_clk_disable(SYS_ETH_CLKCLR_MDIO_CLR);

	sys_eth_mdio_clock_rate_set(param->mdio_data_rate);

	if (param->mdio_en || is_falcon_chip_a2x()) {
		sys_eth_hw_activate(SYS_ETH_ACT_MDIO);
		/* ...sleep a little bit, otherwise 1st MDIO access fails */
		IFXOS_MSecSleep(10);
	}

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		/* configure multiplexer */
		sys_eth_gmac_mux_set(i, gmac_mux[i]);
		if (param->mdio_dev_addr[i] != ONU_LAN_MDIO_ADDR_NULL) {
			/* set address for internal PHY */
			eim_gphy_cfg_addr_set(gmac_mux[i],
					      param->mdio_dev_addr[i]);
			eim_phy_addr_set(i, param->mdio_dev_addr[i]);
			eim_phy_autopoll_enable_set(i, true);
		} else
			eim_phy_autopoll_enable_set(i, false);

		/* control preamble setting, common for all ports */
		eim_short_preamble_enable_set(i, param->mdio_short_preamble_en);
	}

	/* store MDIO addresses internally */
	memcpy (ctrl->mdio_dev_addr, param->mdio_dev_addr,
		sizeof(param->mdio_dev_addr));

#if ONU_GPE_MAX_ETH_UNI > 2
	for (i = 2; i < ONU_GPE_MAX_ETH_UNI; i++)
		if (lan_gphy_led_init(ctrl, i) != ONU_STATUS_OK)
			ONU_DEBUG_WRN("GPHY LEDs init failed, port=%u!", i);
#endif

	return ONU_STATUS_OK;
}

/** The lan_cfg_get function is used to read back the basic configuration
    of the Ethernet interface hardware module.
*/
/** Hardware programming details: See lan_cfg_set.
*/
enum onu_errorcode lan_cfg_get(struct onu_device *p_dev, struct lan_cfg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	uint8_t i;
	bool short_preamble_en;

	param->mdio_short_preamble_en = false;

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		/* get PHY address*/
		param->mdio_dev_addr[i] = phy_addr_get(ctrl, i);
		/* get short preamble setting*/
		eim_short_preamble_enable_get(i, &short_preamble_en);
		/* check if at least one port has an enabled short preamble*/
		if (short_preamble_en)
			param->mdio_short_preamble_en = true;
	}

	/* get MDIO data rate*/
	param->mdio_data_rate = sys_eth_mdio_clock_rate_get();
	/* check if MDIO is active*/
	param->mdio_en = sys_eth_mdio_is_active();

	/* get mux_mode from the internal ONU context*/
	param->mux_mode = ctrl->lan_mux_mode;

	return ONU_STATUS_OK;
}

STATIC void lan_egress_port_enable(struct onu_control *ctrl, const uint32_t uni_port_id, bool ena)
{
	uint32_t epn;

	if (octrll_port_get(uni_port_id, &epn) != 0)
		return;

	if(ena) {
		tmu_egress_port_enable(epn, ena);
		gpe_enqueue_enable(ctrl, epn, ena);
	} else {
		gpe_enqueue_enable(ctrl, epn, ena);
		tmu_egress_port_enable(epn, ena);
	}
}

STATIC enum onu_errorcode phy_pwr_down_set(struct onu_control *ctrl,
					   const int8_t phy_addr,
					   const bool enable)
{
	enum onu_errorcode ret = ONU_STATUS_OK;

	/* read-modify-write*/
	ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_MODE_CTRL,
				MDIO_PHY_MODE_CONTROL_PWR_DOWN,
				enable ? MDIO_PHY_MODE_CONTROL_PWR_DOWN : 0,
				NULL);
	if (ret != 0) {
		ONU_DEBUG_ERR("MDIO(%d) mode control register modify failed!",
			      phy_addr);
		return ret;
	}

	return ret;
}

/** Returns Organizationally Unique Identifier (OUI) assigned to to the PHY */
STATIC enum onu_errorcode phy_oui_get(struct onu_control *ctrl,
				      const int8_t phy_addr,
				      uint32_t *oui)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint16_t reg_phyid[2];
	uint32_t local_oui;
	uint16_t i;

	if (!oui || !ctrl)
		return ONU_STATUS_ERR;

	/* Get PHYID1, PHYID2 register*/
	for (i = 0; i < 2; i++) {
		ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_PHYID1 + i, 0, 0,
				      &reg_phyid[i]);
		if (ret != ONU_STATUS_OK) {
			ONU_DEBUG_ERR("MDIO(%d) PHYID%u register read failed!",
				      phy_addr, i);
			return ret;
		}
	}

	reg_phyid[1] &= MDIO_PHY_PHYID2_OUI;
	local_oui = onu_bit_rev((reg_phyid[0] << 16) | reg_phyid[1]);
	*oui = local_oui << 2;

	return ret;
}

STATIC enum onu_errorcode phy_is_lantiq(struct onu_control *ctrl,
					const int8_t phy_addr)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint32_t oui = 0;

	ret = phy_oui_get(ctrl, phy_addr, &oui);
	if (ret != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("MDIO(%d) PHY OUI get failed!", phy_addr);
		return ret;
	}

	/* non-Lantiq PHY */
	if (oui != MDIO_PHY_LTQ_OUI)
		ret = ONU_STATUS_ERR;

	return ret;
}

STATIC enum onu_errorcode phy_lpi_rxckst_enable(struct onu_control *ctrl,
						const int8_t phy_addr,
						const bool enable)
{
	enum onu_errorcode ret = ONU_STATUS_OK;

	if (phy_is_lantiq(ctrl, phy_addr) != ONU_STATUS_OK)
		/* skip non-Lantiq PHYs*/
		return ret;

	ret = lan_mmd_access(ctrl, phy_addr,
			     MMD_EEE_SEL, MMD_EEE_CTRL1,
			     MMD_EEE_CTRL1_RXCKST_EN,
			     enable ? MMD_EEE_CTRL1_RXCKST_EN : 0,
			     NULL);
	if (ret != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("MMD(%d) EEE_CTRL1 set failed!", phy_addr);
		return ret;
	}

	return ret;
}

STATIC enum onu_errorcode lan_port_lpi_enable(struct onu_control *ctrl,
					      const uint8_t port_num,
					      const bool enable)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct tmu_low_pwr_idle_params lpi;

	eim_mac_lpi_enable(port_num, enable);

	lpi.thx = enable ? ONU_TMU_LPI_THX : 0;
	lpi.tof = ONU_TMU_LPI_TOF;
	lpi.ton = ONU_TMU_LPI_TON;

	tmu_low_power_idle_cfg_set(port_num, &lpi);

	return ret;
}

STATIC enum onu_errorcode fephy_port_enable(struct onu_control *ctrl,
					    const uint8_t port_num,
					    const bool enable)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint8_t	idx = port_num & 0x3;
	uint32_t clk_en_mask[] = {
		SYS_ETH_CLKEN_GMAC0 | SYS_ETH_CLKEN_GPHY0,
		SYS_ETH_CLKEN_GMAC1 | SYS_ETH_CLKEN_GPHY1,
		SYS_ETH_CLKEN_GMAC2 | SYS_ETH_CLKEN_GPHY0MII2,
		SYS_ETH_CLKEN_GMAC3 | SYS_ETH_CLKEN_GPHY1MII2};
	uint32_t act_mask[] = {
		SYS_ETH_ACT_GPHY0 | SYS_ETH_ACT_GMAC0,
		SYS_ETH_ACT_GPHY1 | SYS_ETH_ACT_GMAC1,
		SYS_ETH_ACT_GPHY0 | SYS_ETH_ACT_GMAC2,
		SYS_ETH_ACT_GPHY1 | SYS_ETH_ACT_GMAC3};
	unsigned long flags = 0;

	onu_spin_lock_get(&ctrl->lan_lock[idx], &flags);

	if (phy_pwr_down_set(ctrl, phy_addr_get(ctrl, port_num),
			     !enable) != ONU_STATUS_OK){
		ONU_DEBUG_ERR("phy %s failed, port=%u",
				enable ? "enable" : "disable",
				port_num);
		ret = ONU_STATUS_ERR;
	} else {
		if (enable) {
			sys_eth_hw_clk_enable(clk_en_mask[idx]);
			sys_eth_hw_activate(act_mask[idx]);
			sys_eth_gphy_reboot(idx & 0x1);
			/* MAC activation is done once the link is detected */
			if (lan_phy_settings_update(ctrl, port_num) != ONU_STATUS_OK) {
				ONU_DEBUG_ERR("updating phy settings failed, port=%u",
							port_num);
				ret = ONU_STATUS_ERR;
			}
		} else {
			lan_egress_port_enable(ctrl, port_num, false);
			/* need at least 1.64 ms for clearing sync fifo
			   from GPE to EIM, security factor 2 */
			onu_udelay (3300);
			sys_eth_hw_clk_disable(SYS_ETH_CLKEN_GMAC0 << idx);
		}
	}

	if (ret == ONU_STATUS_OK)
		ctrl->lan_port_en_status[idx] = enable;

	onu_spin_lock_release(&ctrl->lan_lock[idx], flags);

	return ret;
}

STATIC enum onu_errorcode fephy_config_set(struct onu_control *const ctrl,
					   const struct lan_port_cfg *in)
{
	if (in->mode != LAN_MODE_EPHY || in->speed_mode > LAN_MODE_SPEED_100)
		return LAN_STATUS_NO_SUPPORT;

	fephy_port_enable(ctrl, in->index, false);

	/* set duplex mode*/
	eim_duplex_mode_set(in->index, in->duplex_mode);
	/* set flow control*/
	eim_flow_ctrl_set(in->index, in->flow_control_mode);
	/* set speed mode*/
	eim_speed_mode_set(in->index, in->speed_mode);
	/* set fcs*/
	eim_fcs_enable(in->index, true);

	/* register port enable handler*/
	ctrl->lan_port_en_fct[in->index] = fephy_port_enable;
	/* register port status handler*/
	ctrl->lan_port_sts_fct[in->index] = gphy_phy_status_update;

	if (lan_port_lpi_enable(ctrl, in->index,
				in->lpi_enable) != ONU_STATUS_OK)
		return LAN_STATUS_ERR;

	return ONU_STATUS_OK;
}

STATIC enum onu_errorcode gphy_phy_status_update(struct onu_control *ctrl,
						 const uint8_t port_num)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct lan_link_status sts = {
		false, LAN_PHY_MODE_DUPLEX_AUTO, LAN_MODE_SPEED_AUTO};
	unsigned long flags = 0;
	uint32_t port_sts_prev;

	port_sts_prev = ctrl->lan_link_status[port_num].up;

	onu_spin_lock_get(&ctrl->lan_lock[port_num], &flags);
	if (ctrl->lan_port_en_status[port_num]) {
		if (lan_phy_status_get(ctrl, port_num, &sts) != ONU_STATUS_OK)
			ret = ONU_STATUS_ERR;
	}
	onu_spin_lock_release(&ctrl->lan_lock[port_num], flags);
	/* avoid switch off in case of forced link */
	if (!sts.up && ctrl->lan_force_link[port_num]) {
		sts.up = true;
		sts.speed = LAN_MODE_SPEED_AUTO;
		sts.duplex = LAN_PHY_MODE_DUPLEX_AUTO;
		ret = ONU_STATUS_OK;
	}

	/* Check link status change */
	if (ret == ONU_STATUS_OK && port_sts_prev != sts.up) {
		memcpy(&ctrl->lan_link_status[port_num], &sts,
			sizeof(ctrl->lan_link_status[port_num]));
		if (sts.up == true) {
			if (is_falcon_chip_a1x()) {
				/* reset MAC */
				onu_udelay (6000);
				sys_eth_hw_activate_or_reboot (SYS_ETH_ACT_GMAC0 << port_num);
				onu_udelay (6000);
			}
			/* switch on data */
			lan_egress_port_enable(ctrl, port_num, true);
		}
		else
			/* switch off data */
			lan_egress_port_enable(ctrl, port_num, false);
	}
	return ret;
}

STATIC enum onu_errorcode gphy_port_enable(struct onu_control *ctrl,
					   const uint8_t port_num,
					   const bool enable)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint8_t idx = port_num & 0x1;
	unsigned long flags = 0;

	onu_spin_lock_get(&ctrl->lan_lock[port_num], &flags);

	if (enable) {
		if (!sys_eth_hw_is_activated (SYS_ETH_ACT_GPHY0 << idx)) {
			/* MAC and GPHY activation is done only once for A22 */
			sys_eth_gphy_reboot(idx);
			/* MAC activation is done once the link is detected for A12 */
			if (is_falcon_chip_a2x()) {
				/* MAC activation is done 
				   only once for A22 */
				sys_eth_hw_activate (SYS_ETH_ACT_GMAC0 << idx);
			}
		}
		if (lan_phy_settings_update(ctrl, port_num) != ONU_STATUS_OK) {
			ONU_DEBUG_ERR("updating phy settings failed, port=%u",
						port_num);
			ret = ONU_STATUS_ERR;
		}
	} else {
		lan_egress_port_enable(ctrl, port_num, false);
		/* need at least 1.64 ms for clearing sync fifo
			from GPE to EIM, security factor 2 */
		onu_udelay (3300);
		sys_eth_hw_deactivate (SYS_ETH_ACT_GPHY0 << idx);
		sys_eth_hw_deactivate (SYS_ETH_ACT_GMAC0 << idx);
	}

	if (ret == ONU_STATUS_OK)
		ctrl->lan_port_en_status[port_num] = enable;

	onu_spin_lock_release(&ctrl->lan_lock[port_num], flags);

	return ret;
}

STATIC enum onu_errorcode gphy_config_set(struct onu_control *const ctrl,
					  const struct lan_port_cfg *in)
{
	uint8_t idx = in->index & 0x1;

	if (in->mode != LAN_MODE_GPHY || in->speed_mode == LAN_MODE_SPEED_200
				      || in->speed_mode == LAN_MODE_SPEED_2500)
		return LAN_STATUS_NO_SUPPORT;

	/* set duplex mode*/
	eim_duplex_mode_set(idx, in->duplex_mode);
	/* set flow control*/
	eim_flow_ctrl_set(idx, in->flow_control_mode);
	/* set speed mode*/
	eim_speed_mode_set(idx, in->speed_mode);
	/* set fcs*/
	eim_fcs_enable(idx, true);
	if (in->speed_mode != LAN_MODE_SPEED_AUTO)
		if (sys_eth_gphy_data_rate_set(idx, in->speed_mode) != 0)
			return LAN_STATUS_ERR;

	/* register port enable handler*/
	ctrl->lan_port_en_fct[in->index] = gphy_port_enable;
	/* register port status handler*/
	ctrl->lan_port_sts_fct[in->index] = gphy_phy_status_update;

	if (lan_port_lpi_enable(ctrl, in->index,
				in->lpi_enable) != ONU_STATUS_OK)
		return LAN_STATUS_ERR;

	return ONU_STATUS_OK;
}

STATIC enum onu_errorcode rxmii_phy_status_update(struct onu_control *ctrl,
						  const uint8_t port_num)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct lan_link_status sts = {
		false, LAN_PHY_MODE_DUPLEX_AUTO, LAN_MODE_SPEED_AUTO};
	uint32_t port_sts_prev = ctrl->lan_link_status[port_num].up;
	uint8_t idx = port_num & 0x3;
	uint32_t clk_mask[] = {
		SYS_ETH_CLKEN_GMAC0, SYS_ETH_CLKEN_GMAC1,
		SYS_ETH_CLKEN_GMAC2, SYS_ETH_CLKEN_GMAC3};
	unsigned long flags = 0;

	onu_spin_lock_get(&ctrl->lan_lock[idx], &flags);
	if (ctrl->lan_port_en_status[port_num]) {
		if (lan_phy_status_get(ctrl, idx, &sts) != ONU_STATUS_OK)
			ret = ONU_STATUS_ERR;
	}
	onu_spin_lock_release(&ctrl->lan_lock[idx], flags);
	/* avoid switch off in case of forced link */
	if (!sts.up && ctrl->lan_force_link[port_num]) {
		sts.up = true;
		sts.speed = LAN_MODE_SPEED_AUTO;
		sts.duplex = LAN_PHY_MODE_DUPLEX_AUTO;
		ret = ONU_STATUS_OK;
	}

	/* Check link status change */
	if (ret == ONU_STATUS_OK && port_sts_prev != sts.up) {

		memcpy(&ctrl->lan_link_status[idx], &sts,
			sizeof(ctrl->lan_link_status[idx]));

		/* switch off data */
		lan_egress_port_enable(ctrl, port_num, false);

		if (ctrl->lan_port_cfg[idx].speed_mode == LAN_MODE_SPEED_AUTO) {
			sys_eth_hw_clk_disable(clk_mask[idx]);
			/* set xmii data rate*/
			sys_eth_xmii_data_rate_set(port_num & 0x1, sts.speed);
			sys_eth_hw_clk_enable(clk_mask[idx]);
		}

		if (sts.up == true) {
			/* reset MAC */
			sys_eth_hw_activate_or_reboot (SYS_ETH_ACT_GMAC0 << port_num);
			/* switch on data */
			lan_egress_port_enable(ctrl, port_num, true);
		}
	}
	return ret;
}

STATIC enum onu_errorcode rxmii_port_enable(struct onu_control *ctrl,
			     const uint8_t port_num, const bool enable)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint8_t xmii_idx = port_num & 0x1, idx = port_num & 0x3;
	unsigned long flags = 0;

	onu_spin_lock_get(&ctrl->lan_lock[idx], &flags);

	if (phy_pwr_down_set(ctrl, phy_addr_get(ctrl, port_num),
			     !enable) != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("phy %s failed, port=%u",
				enable ? "enable" : "disable",
				port_num);
		ret = ONU_STATUS_ERR;
	} else {
		sys_eth_hw_activate(SYS_ETH_ACT_xMII);	/* activate xMII macro*/
	
		if (enable) {
			sys_eth_hw_activate(SYS_ETH_ACT_GMAC0 << idx);
			eim_xmii_reset(xmii_idx, false);   /* release reset*/
			eim_xmii_enable(xmii_idx, true);   /* enable xMII */
			if (lan_phy_settings_update(ctrl, port_num) != ONU_STATUS_OK) {
				ONU_DEBUG_ERR("updating phy settings failed, port=%u",
							port_num);
				ret = ONU_STATUS_ERR;
			}
		} else {
			lan_egress_port_enable(ctrl, port_num, false);
			/* need at least 1.64 ms for clearing sync fifo
			   from GPE to EIM, security factor 2 */
			onu_udelay (3300);
			eim_xmii_enable(xmii_idx, false);  /* disable xMII */
			sys_eth_hw_clk_disable(SYS_ETH_CLKEN_GMAC0 << idx);
		}
	}

	if (ret == ONU_STATUS_OK)
		ctrl->lan_port_en_status[idx] = enable;

	onu_spin_lock_release(&ctrl->lan_lock[idx], flags);

	return ret;
}

STATIC enum onu_errorcode rxmii_config_set(struct onu_control *const ctrl,
					   const struct lan_port_cfg *in)
{
	uint8_t xmii_idx = (in->index) & 0x1;
	bool phy_mode = false;
	enum eim_gmii_mode gmii_mode = EIM_GMII_MODE_GMII;
	enum eim_xmii_mode xmii_mode;
	enum eim_xmii_clk_rate xmii_clk_rate = EIM_XMII_CLK_RATE_125MHZ;

	if (in->speed_mode == LAN_MODE_SPEED_200 ||
	    in->speed_mode == LAN_MODE_SPEED_2500)
		return LAN_STATUS_NO_SUPPORT;

	switch (in->mode) {
	case LAN_MODE_RMII_PHY:
		phy_mode = true;
	case LAN_MODE_RMII_MAC:
		gmii_mode = EIM_GMII_MODE_MII;
		xmii_mode = in->mode == LAN_MODE_RMII_MAC ?
				      EIM_XMII_MODE_RMIIM : EIM_XMII_MODE_RMIIP;
		xmii_clk_rate = EIM_XMII_CLK_RATE_50MHZ;
		break;
	case LAN_MODE_RGMII_MAC:
		if (in->tx_clk_dly > EIM_RGMII_CLK_DELAY_MAX  ||
		    in->rx_clk_dly > EIM_RGMII_CLK_DELAY_MAX)
			return LAN_STATUS_NO_SUPPORT;

		xmii_mode = EIM_XMII_MODE_RGMII;

		xmii_clk_rate = in->speed_mode == LAN_MODE_SPEED_10   ?
				EIM_XMII_CLK_RATE_2P5MHZ : xmii_clk_rate;
		xmii_clk_rate = in->speed_mode == LAN_MODE_SPEED_100  ?
				EIM_XMII_CLK_RATE_25MHZ  : xmii_clk_rate;
		xmii_clk_rate = in->speed_mode == LAN_MODE_SPEED_AUTO ?
				EIM_XMII_CLK_RATE_AUTO   : xmii_clk_rate;
		break;
	default:
		return LAN_STATUS_NO_SUPPORT;
	}

	rxmii_port_enable(ctrl, in->index, true);
	rxmii_port_enable(ctrl, in->index, false);

	eim_gmii_mode_set(in->index, gmii_mode);
	eim_xmii_mode_set(xmii_idx, xmii_mode);

	if (!phy_mode) {
		eim_flow_ctrl_set(in->index, in->flow_control_mode);
		eim_fcs_enable(in->index, true);
		eim_duplex_mode_set(in->index, in->duplex_mode);
		eim_speed_mode_set(in->index, in->speed_mode);

		if (lan_port_lpi_enable(ctrl, in->index,
					in->lpi_enable) != ONU_STATUS_OK)
			return LAN_STATUS_ERR;
	}

	eim_xmii_jitter_buf_enable(xmii_idx, true, true);

	if (in->mode == LAN_MODE_RGMII_MAC)
		eim_xmii_clk_dly_set(xmii_idx, in->tx_clk_dly, in->rx_clk_dly);

	if (in->speed_mode != LAN_MODE_SPEED_AUTO)
		sys_eth_xmii_data_rate_set(xmii_idx, in->speed_mode);

	eim_xmii_clk_rate_set(xmii_idx, xmii_clk_rate);

	/* register port enable handler*/
	ctrl->lan_port_en_fct[in->index] = rxmii_port_enable;
	/* register port status handler*/
	ctrl->lan_port_sts_fct[in->index] = rxmii_phy_status_update;

	return ONU_STATUS_OK;
}

#if ONU_GPE_MAX_ETH_UNI >= 3
STATIC enum onu_errorcode xmii_port_enable(struct onu_control *ctrl,
					   const uint8_t port_num,
					   const bool enable)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint8_t idx = port_num & 0x3;
	uint32_t act_mask[] = {SYS_ETH_ACT_GMAC0, SYS_ETH_ACT_GMAC1,
			       SYS_ETH_ACT_GMAC2, SYS_ETH_ACT_GMAC3};
	enum eim_gmii_mode mode = EIM_GMII_MODE_AUTO;
	unsigned long flags = 0;

	sys_eth_hw_activate(SYS_ETH_ACT_xMII);

	onu_spin_lock_get(&ctrl->lan_lock[idx], &flags);

	eim_gmii_mode_get(port_num, &mode);
	if (mode == EIM_GMII_MODE_GMII) {
		if (enable)
			ctrl->lan_gmii_clko_status |= (1 << port_num);
		else
			ctrl->lan_gmii_clko_status &= ~(1 << port_num);

		/* Control the output driver of the CLKO pad */
		sys1_clko_enable(ctrl->lan_gmii_clko_status ?
							true : false);
	}

	if (enable) {
		sys_eth_hw_activate(act_mask[idx]);
		eim_xmii_reset(EIM_GMII_XMII_IDX, false);	/* release reset*/
		eim_xmii_enable(EIM_GMII_XMII_IDX, true);
		if (lan_phy_settings_update(ctrl, port_num) != ONU_STATUS_OK) {
			ONU_DEBUG_ERR("updating phy settings failed, port=%u",
						port_num);
			ret = ONU_STATUS_ERR;
		}
	} else {
		lan_egress_port_enable(ctrl, port_num, false);
		/* need at least 1.64 ms for clearing sync fifo
		   from GPE to EIM, security factor 2 */
		onu_udelay (3300);
		eim_xmii_enable(EIM_GMII_XMII_IDX, false);
	}

	if (ret == ONU_STATUS_OK)
		ctrl->lan_port_en_status[idx] = enable;

	onu_spin_lock_release(&ctrl->lan_lock[idx], flags);

	return ret;
}

STATIC enum onu_errorcode xmii_config_set(struct onu_control *const ctrl,
					  const struct lan_port_cfg *in)
{
	bool phy_mode = false, turbo = false;
	enum eim_gmii_mode gmii_mode = EIM_GMII_MODE_MII;
	enum eim_xmii_clk_rate xmii_clk_rate = EIM_XMII_CLK_RATE_125MHZ;

	if (in->speed_mode == LAN_MODE_SPEED_2500)
		return LAN_STATUS_NO_SUPPORT;

	switch (in->mode) {
	case LAN_MODE_GMII_PHY:
		phy_mode = true;
		if (in->speed_mode == LAN_MODE_SPEED_200)
			return LAN_STATUS_NO_SUPPORT;
	case LAN_MODE_GMII_MAC:
		gmii_mode = EIM_GMII_MODE_GMII;
		break;
	case LAN_MODE_MII_PHY:
		phy_mode = true;
	case LAN_MODE_MII_MAC:
		if (in->speed_mode == LAN_MODE_SPEED_200 ||
		    in->speed_mode == LAN_MODE_SPEED_1000)
			return LAN_STATUS_NO_SUPPORT;
		break;

	case LAN_MODE_TMII_PHY:
		phy_mode = true;
	case LAN_MODE_TMII_MAC:
		if (in->speed_mode != LAN_MODE_SPEED_200)
			return LAN_STATUS_NO_SUPPORT;
		xmii_clk_rate = EIM_XMII_CLK_RATE_50MHZ;
		turbo = true;
		break;
	case LAN_MODE_TBI_MAC:
	case LAN_MODE_TBI_PHY:
		/**
		\todo clarify how to handle these modes*/
	default:
		return LAN_STATUS_NO_SUPPORT;
	}

	xmii_clk_rate = in->speed_mode == LAN_MODE_SPEED_10   ?
				EIM_XMII_CLK_RATE_2P5MHZ : xmii_clk_rate;
	xmii_clk_rate = in->speed_mode == LAN_MODE_SPEED_100  ?
				EIM_XMII_CLK_RATE_25MHZ  : xmii_clk_rate;

	xmii_port_enable(ctrl, in->index, true);
	xmii_port_enable(ctrl, in->index, false);

	eim_gmii_mode_set(in->index, gmii_mode);
	eim_xmii_mode_set(EIM_GMII_XMII_IDX, phy_mode ?  EIM_XMII_MODE_MIIP :
							 EIM_XMII_MODE_MIIM);

	if (!phy_mode) {
		eim_flow_ctrl_set(in->index, in->flow_control_mode);
		eim_fcs_enable(in->index, true);
		eim_duplex_mode_set(in->index, in->duplex_mode);
		eim_speed_mode_set(in->index, in->speed_mode);

		if (lan_port_lpi_enable(ctrl, in->index,
					in->lpi_enable) != ONU_STATUS_OK)
			return LAN_STATUS_ERR;
	}

	eim_xmii_jitter_buf_enable(EIM_GMII_XMII_IDX, true, true);
	if (in->speed_mode != LAN_MODE_SPEED_AUTO)
		sys_eth_xmii_data_rate_set(EIM_GMII_XMII_IDX, in->speed_mode);
	eim_xmii_clk_rate_set(EIM_GMII_XMII_IDX, xmii_clk_rate);

	/* register port enable handler*/
	ctrl->lan_port_en_fct[in->index] = xmii_port_enable;
	/* register port status handler*/
	ctrl->lan_port_sts_fct[in->index] = rxmii_phy_status_update;

	return ONU_STATUS_OK;
}
#endif

#if ONU_GPE_MAX_ETH_UNI >= 4
STATIC int sgmii_port_enable(struct onu_control *ctrl,
			     const uint8_t port_num, const bool enable)
{
	(void)ctrl;

	if (enable) {
		sys_eth_hw_activate(SYS_ETH_ACT_SGMII);
	} else {
		lan_egress_port_enable(ctrl, port_num, false);
		/* need at least 1.64 ms for clearing sync fifo
		   from GPE to EIM, security factor 2 */
		onu_udelay (3300);
		sys_eth_hw_clk_disable(SYS_ETH_CLKEN_SGMII);
	}

	return 0;
}

STATIC enum onu_errorcode sgmii_config_set(struct onu_control *const ctrl,
					   const struct lan_port_cfg *in)
{
	enum gpe_arb_mode arb_mode;

	if (in->mode != LAN_MODE_SGMII_SLOW && in->mode != LAN_MODE_SGMII_FAST)
		return LAN_STATUS_NO_SUPPORT;

	if (in->speed_mode != LAN_MODE_SPEED_1000 &&
	    in->speed_mode != LAN_MODE_SPEED_2500)
		return LAN_STATUS_NO_SUPPORT;

	arb_mode = gpearb_mode_get();
	if ((in->mode == LAN_MODE_SGMII_SLOW && arb_mode != ARB_MODE_DEFAULT) ||
	    (in->mode == LAN_MODE_SGMII_FAST && arb_mode != ARB_MODE_GIG2_5))
		return LAN_STATUS_NO_SUPPORT;

	sgmii_port_enable(ctrl, in->index, false);

	sys_eth_sgmii_data_rate_set(in->mode == LAN_MODE_SGMII_SLOW ?
							LAN_MODE_SPEED_1000 :
							LAN_MODE_SPEED_2500);

	/* register port enable handler*/
	ctrl->lan_port_en_fct[in->index] = sgmii_port_enable;

	return ONU_STATUS_OK;
}
#endif

#if ONU_GPE_MAX_ETH_UNI >= 2
STATIC enum onu_errorcode null_config_set(struct onu_control *const ctrl,
					  const struct lan_port_cfg *in)
{
	(void)ctrl;
	(void)in;

	return LAN_STATUS_NO_SUPPORT;
}
#endif

STATIC lan_mode_set_t gphy2_rgmii2[ONU_GPE_MAX_ETH_UNI] = {
	 gphy_config_set
#if ONU_GPE_MAX_ETH_UNI >= 2
	,gphy_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 3
	,rxmii_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 4
	,rxmii_config_set
#endif
};

STATIC lan_mode_set_t gphy2_rgmii_sgmii[ONU_GPE_MAX_ETH_UNI] = {
	 gphy_config_set
#if ONU_GPE_MAX_ETH_UNI >= 2
	,gphy_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 3
	,rxmii_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 4
	,sgmii_config_set
#endif
};

STATIC lan_mode_set_t gphy2_gmii_sgmii[ONU_GPE_MAX_ETH_UNI] = {
	 gphy_config_set
#if ONU_GPE_MAX_ETH_UNI >= 2
	,gphy_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 3
	,xmii_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 4
	,sgmii_config_set
#endif
};

STATIC lan_mode_set_t gphy_rgmii2_sgmii[ONU_GPE_MAX_ETH_UNI] = {
	 gphy_config_set
#if ONU_GPE_MAX_ETH_UNI >= 2
	,rxmii_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 3
	,rxmii_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 4
	,sgmii_config_set
#endif
};

STATIC lan_mode_set_t rgmii2_sgmii[ONU_GPE_MAX_ETH_UNI] = {
	 rxmii_config_set
#if ONU_GPE_MAX_ETH_UNI >= 2
	,rxmii_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 3
	,null_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 4
	,sgmii_config_set
#endif
};

STATIC lan_mode_set_t rgmii1[ONU_GPE_MAX_ETH_UNI] = {
	 rxmii_config_set
#if ONU_GPE_MAX_ETH_UNI >= 2
	,null_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 3
	,null_config_set
#endif
#if ONU_GPE_MAX_ETH_UNI >= 4
	,null_config_set
#endif
};

/** The lan_port_cfg_set function is used to provide basic configurations of
   per-port functionality of the Ethernet interface hardware module.
*/

/** Hardware Programming Details
   - index: select one of the UNI ports (0 to 3)
   - eInterfaceMode:
	The following interface mode combinations are available, the attempt so
	set an invalid combination of port modes results in an error response
	(LAN_STATUS_NO_SUPPORT).

      - Option 1:
         - Port 0 = EPHY
         - Port 1 = EPHY
         - Port 2 = EPHY
         - Port 3 = EPHY

      - Option 2:
         - Port 0 = GPHY
         - Port 1 = GPHY
         - Port 2 = RMII/RGMII
         - Port 3 = RMII/RGMII

      - Option 3:
         - Port 0 = GPHY
         - Port 1 = GPHY
         - Port 2 = RMII/RGMII
         - Port 3 = SGMII

      - Option 4:
         - Port 0 = GPHY
         - Port 1 = GPHY
         - Port 2 = GMII/MII
         - Port 3 = SGMII

      - Option 5:
         - Port 0 = GPHY
         - Port 1 = RMII/RGMII
         - Port 2 = RMII/RGMII
         - Port 3 = SGMII

      - Option 6:
         - Port 0 = RMII/RGMII
         - Port 1 = RMII/RGMII
         - Port 2 = none
         - Port 3 = SGMII

   - ePhySpeed: If a PHY is connected, the speed can be selected
		The application SW shall set this to "auto", if no PHY is
		connected.
		The driver ignores this setting in non-PHY configurations.
		If 1000BASE-T is selected in 4 x EPHY mode (option 1), an error
		code (LAN_STATUS_NO_SUPPORT) is responded.
   - phy_duplex: If a PHY is connected, the duplex mode can be selected
		The application SW shall set this to "auto", if no PHY is
		connected.
		The driver ignores this setting in non-PHY configurations.
		\remark ePhySpeed and phy_duplex can be either both in auto
		mode or both must be set to one of the manual modes.
		Otherwise an error code is reported (LAN_STATUS_NO_SUPPORT).
   - nMaxFrameSize: The accepted frame size can be limited. If the given value
		is larger than the physical limit, the physical limit is
		used and an error code is responded
		(LAN_STATUS_VALUE_RANGE_ERR).
   - bgressLoopbackEnable: Enables the egress loop function, available for all
		physical ports.
   - bIngressLoopbackEnable: Enables the ingress loop function, available for
		PHY and SGMII ports only. The error code is set
		to LAN_STATUS_NO_SUPPORT, if incorrectly
		selected.
*/
enum onu_errorcode lan_port_cfg_set(struct onu_device *p_dev,
				    const struct lan_port_cfg *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	enum lan_interface_mux_mode lan_mux_mode;
	struct lan_port_cfg port_cfg_curr;

	if (param->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (param->speed_mode > LAN_MODE_SPEED_2500)
		return LAN_STATUS_VALUE_RANGE_ERR;
	if (param->duplex_mode > LAN_PHY_MODE_DUPLEX_HALF)
		return LAN_STATUS_VALUE_RANGE_ERR;
	if (param->flow_control_mode > LAN_FLOW_CONTROL_MODE_NONE)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (param->speed_mode == LAN_MODE_SPEED_AUTO &&
	    param->duplex_mode != LAN_PHY_MODE_DUPLEX_AUTO)
		return LAN_STATUS_NO_SUPPORT;

	if (param->duplex_mode == LAN_PHY_MODE_DUPLEX_AUTO &&
	    param->speed_mode != LAN_MODE_SPEED_AUTO)
		return LAN_STATUS_NO_SUPPORT;

	if (param->max_frame_size > ONU_GPE_MAX_ETHERNET_FRAME_LENGTH)
		return LAN_STATUS_VALUE_RANGE_ERR;

	/* get the current config */
	memcpy(&port_cfg_curr, &ctrl->lan_port_cfg[param->index],
		sizeof(struct lan_port_cfg));
	port_cfg_curr.max_frame_size = param->max_frame_size;
	ctrl->lan_force_link[param->index] = false;
	/* if only the max_frame_size was changed bypass the complete
	   reconfiguration*/
	if (memcmp(&port_cfg_curr, param, sizeof(struct lan_port_cfg)) != 0) {
		/* get mux_mode from the internal ONU context*/
		lan_mux_mode = ctrl->lan_mux_mode;

		switch (lan_mux_mode) {
		case LAN_MUX_FEPHY4:
			ret = fephy_config_set(ctrl, param);
			break;
		case LAN_MUX_GPHY2_RGMII2:
			ret = gphy2_rgmii2[param->index](ctrl, param);
			break;
		case LAN_MUX_GPHY2_RGMII_SGMII:
			ret = gphy2_rgmii_sgmii[param->index](ctrl, param);
			break;
		case LAN_MUX_GPHY2_GMII_SGMII:
			ret = gphy2_gmii_sgmii[param->index](ctrl, param);
			break;
		case LAN_MUX_GPHY_RGMII2_SGMII:
			ret = gphy_rgmii2_sgmii[param->index](ctrl, param);
			break;
		case LAN_MUX_RGMII2_SGMII:
			ret = rgmii2_sgmii[param->index](ctrl, param);
			break;
		case LAN_MUX_RGMII1:
			ret = rgmii1[param->index](ctrl, param);
			break;
		default:
			ret = LAN_STATUS_NOT_INITIALIZED;
			break;
		}

		if (ret == ONU_STATUS_OK) {
			memcpy(&ctrl->lan_port_cfg[param->index], param,
			       sizeof(struct lan_port_cfg));
			if (param->uni_port_en) {
				uint32_t ovfl;
				if (is_falcon_chip_a1x())
					ovfl = EIM_EIM_IER_A1X_LAN_IG_OVFL_0_EN
						<< param->index;
				else
					ovfl = EIM_EIM_IER_A2X_LAN_IG_OVFL_0_EN
						<< param->index;
				eim_central_interrupt_enable_set (0x0, ovfl);
			}
			if (ctrl->lan_port_en_fct != NULL)
				ret = ctrl->lan_port_en_fct[param->index](ctrl,
					param->index, param->uni_port_en);
		}
	}

	if (ret == ONU_STATUS_OK) {
		if (eim_mac_frame_length_get() < param->max_frame_size)
			eim_mac_frame_length_set(param->max_frame_size);

		ictrll_max_size_pdu_type0_set(param->index,
					      param->max_frame_size);
		ctrl->lan_port_cfg[param->index].max_frame_size =
							param->max_frame_size;
	}

	return ret;
}

/** The lan_port_cfg_get function is used to read back the basic per-port
   configuration of the Ethernet interface hardware module.
*/
/** Hardware programming details: See lan_port_cfg_set.
*/
enum onu_errorcode lan_port_cfg_get(struct onu_device *p_dev,
				    const struct lan_port_index *in,
				    struct lan_port_cfg *out)
{
	struct onu_control *ctrl = p_dev->ctrl;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED)
		return LAN_STATUS_NOT_INITIALIZED;

	if (in->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	memcpy(	out, &ctrl->lan_port_cfg[in->index],
		sizeof(struct lan_port_cfg));

	return ONU_STATUS_OK;
}

/** The lan_port_enable function is used to enable a single UNI port.
*/

/** Hardware Programming Details
   - index: select one of the UNI ports (0 to 3)
*/
enum onu_errorcode lan_port_enable(struct onu_device *p_dev,
				   const struct lan_port_index *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t ovfl;

	if (param->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED ||
	    ctrl->lan_port_en_fct[param->index] == NULL)
		return LAN_STATUS_NOT_INITIALIZED;
	if (is_falcon_chip_a1x())
		ovfl = EIM_EIM_IER_A1X_LAN_IG_OVFL_0_EN << param->index;
	else
		ovfl = EIM_EIM_IER_A2X_LAN_IG_OVFL_0_EN << param->index;
	eim_central_interrupt_enable_set (0x0, ovfl);

	if (ctrl->lan_port_en_fct[param->index](ctrl, param->index,
						true) != 0) {
		return LAN_STATUS_ERR;
	} else {
		ctrl->lan_port_cfg[param->index].uni_port_en = true;
		return ONU_STATUS_OK;
	}
}

/** The lan_port_disable function is used to disable a single UNI port.
*/

/** Hardware Programming Details
   - index: select one of the UNI ports (0 to 3)
*/
enum onu_errorcode lan_port_disable(struct onu_device *p_dev,
				    const struct lan_port_index *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	if (param->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED ||
	    ctrl->lan_port_en_fct[param->index] == NULL)
		return LAN_STATUS_NOT_INITIALIZED;

	ctrl->lan_force_link[param->index] = false;
	memset (&ctrl->lan_loop_cfg[param->index], 0,
		sizeof(struct lan_loop_cfg));

	if (ctrl->lan_port_en_fct[param->index](ctrl, param->index,
						false) != 0) {
		return LAN_STATUS_ERR;
	} else {
		ctrl->lan_port_cfg[param->index].uni_port_en = false;
		return ONU_STATUS_OK;
	}
}

STATIC enum onu_errorcode lan_loop_support_get(	enum lan_mode_interface mode,
						bool *phy, bool *mac, bool *mii,
						bool *sgmii)
{
	*phy   = true;
	*mac   = true;
	*mii   = false;
	*sgmii = false;

	switch (mode) {
	case LAN_MODE_GPHY:
	case LAN_MODE_EPHY:
		break;
	case LAN_MODE_RMII_PHY:
	case LAN_MODE_GMII_PHY:
	case LAN_MODE_MII_PHY:
	case LAN_MODE_TMII_PHY:
	case LAN_MODE_TBI_PHY:
		*mii = true;
		break;
	case LAN_MODE_SGMII_SLOW:
	case LAN_MODE_SGMII_FAST:
		*sgmii = true;
		*phy   = false;
		break;
	case LAN_MODE_RGMII_MAC:
	case LAN_MODE_RMII_MAC:
	case LAN_MODE_GMII_MAC:
	case LAN_MODE_MII_MAC:
	case LAN_MODE_TMII_MAC:
	case LAN_MODE_TBI_MAC:
		*phy = false;
		break;
	case LAN_MODE_OFF:
	default:
		return LAN_STATUS_NOT_INITIALIZED;
	}

	return ONU_STATUS_OK;
}
/** The LAN_LooptCfgSet function is used to enable a diagnostic loop.
*/

/** Hardware Programming Details
	- mux_mode
	- mode
	- index
	- mac_egress_loop_en
	- mii_ingress_loop_en
	- sgmii_ingress_loop_en
	- phy_ingress_loop_en
	- phy_egress_loop_en
*/
enum onu_errorcode lan_loop_cfg_set(struct onu_device *p_dev,
				    const struct lan_loop_cfg *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	bool phy = false, mii = false, sgmii = false, mac = false;

	if (param->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED ||
	    ctrl->lan_port_en_fct[param->index] == NULL)
		return LAN_STATUS_NOT_INITIALIZED;

	ret = lan_loop_support_get(ctrl->lan_port_cfg[param->index].mode,
				   &phy, &mac, &mii, &sgmii);
	if (ret != ONU_STATUS_OK)
		return ret;

	eim_mac_loop_enable(param->index, param->mac_egress_loop_en);
	if (param->phy_egress_loop_en || param->mac_egress_loop_en) {
		ctrl->lan_force_link[param->index] = true;
		if (ctrl->lan_link_status[param->index].up == false)
			ctrl->lan_port_sts_fct[param->index] (ctrl, param->index);
	}
	else
		ctrl->lan_force_link[param->index] = false;
	if (mii)
		eim_mii_loop_enable((~param->index) & 0x1,
				    param->mii_ingress_loop_en);

	if (phy) {
		if (lan_phy_loop_enable_set(ctrl,
				phy_addr_get(ctrl, param->index),
				param->phy_ingress_loop_en, 
				param->phy_egress_loop_en) != 0) {
			ONU_DEBUG_ERR("LAN(%d) port PHY loop set failed!",
				      param->index);
			return LAN_STATUS_ERR;
		}
		/* restart auto-negotiation */
		ret = lan_mdio_access(ctrl, phy_addr_get(ctrl, param->index),
				MDIO_PHY_MODE_CTRL,0,
				MDIO_PHY_MODE_CONTROL_AUTONEG_RESTART, NULL);
	}

	if (sgmii)
		eim_sgmii_loop_enable(param->sgmii_ingress_loop_en);

	memcpy(	&ctrl->lan_loop_cfg[param->index], param,
		sizeof(struct lan_loop_cfg));

	return ret;
}

/** The lan_loop_cfg_get function is used to read back the per-port loop
    settings of the Ethernet interface hardware module.
*/
/** Hardware programming details: See lan_loop_cfg_set.
*/
enum onu_errorcode lan_loop_cfg_get(struct onu_device *p_dev,
				    const struct lan_port_index *in,
				    struct lan_loop_cfg *out)
{
	struct onu_control *ctrl = p_dev->ctrl;

	if (in->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED ||
	    ctrl->lan_port_en_fct[in->index] == NULL)
		return LAN_STATUS_NOT_INITIALIZED;

	memcpy(	out, &ctrl->lan_loop_cfg[in->index],
		sizeof(struct lan_loop_cfg));

	return ONU_STATUS_OK;
}

/** The lan_port_status_get function provides a summary of status information
   that is available per port for the GPON Ethernet interface hardware module.
*/
/** Hardware Programming Details
	- index: select one of the UNI ports (0 to 3)
	- link_status: If a PHY is active on the selected port, the link status
		       is reported. If no PHY is active on the port, the status
		       is set to LAN_PHY_STATUS_NONE. Any change of the PHY
		       status is indicated by an interrupt. The interrupt
		       service routine checks the PHY status via MDIO access
		       and updates the status information.
		       If external PHYs are connected, on or more external
		       interrupt lines must be provided through GPIO pins.
		       The interrupt service routine is application dependent.
	- bPortEnabled: indicates if the port is active
*/
enum onu_errorcode lan_port_status_get(struct onu_device *p_dev,
				       const struct lan_port_index *in,
				       struct lan_port_status *out)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct lan_port_cfg lan_port_cfg;
	uint32_t act;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED)
		return LAN_STATUS_NOT_INITIALIZED;

	if (in->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED ||
	    ctrl->lan_port_en_fct[in->index] == NULL)
		return LAN_STATUS_NOT_INITIALIZED;

	memcpy(	&lan_port_cfg, &ctrl->lan_port_cfg[in->index],
		sizeof(struct lan_port_cfg));

	out->index = in->index;
	out->mode = lan_port_cfg.mode;
	out->uni_port_en = lan_port_cfg.uni_port_en;
	out->phy_duplex = LAN_PHY_MODE_DUPLEX_AUTO;
	if (lan_port_cfg.mode == LAN_MODE_OFF) {
		out->link_status = LAN_PHY_STATUS_OFF;
		return ONU_STATUS_OK;
	}

	act = ctrl->lan_link_status[in->index].up;

	if (act) {
		enum lan_mode_speed speed;

		if (sys_eth_gmac_data_rate_get(in->index, &speed) !=0 ) {
			/*
			ONU_DEBUG_ERR("GMAC(%d) data rate status get failed!",
					in->index);
			return LAN_STATUS_ERR;
			*/
			out->link_status = LAN_PHY_STATUS_UNKNOWN;
			return ONU_STATUS_OK;
		}

		switch (speed) {
		case LAN_MODE_SPEED_10:
			out->link_status = LAN_PHY_STATUS_10_UP;
			break;
		case LAN_MODE_SPEED_100:
			out->link_status = LAN_PHY_STATUS_100_UP;
			break;
		case LAN_MODE_SPEED_1000:
			out->link_status = LAN_PHY_STATUS_1000_UP;
			break;
		default:
			out->link_status = LAN_PHY_STATUS_UNKNOWN;
			break;
		}
		out->phy_duplex = ctrl->lan_link_status[in->index].duplex;
	} else {
		out->link_status = LAN_PHY_STATUS_DOWN;
	}

	return ONU_STATUS_OK;
}

/** The function is used to read the LAN-based counters.
*/
enum onu_errorcode lan_counter_get(struct onu_device *p_dev,
				   const struct lan_cnt_interval *in,
				   struct lan_counters *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->index >= ONU_GPE_MAX_ETH_UNI) {
		memset(out, 0x00, sizeof(struct lan_cnt_val));
		return LAN_STATUS_VALUE_RANGE_ERR;
	}

	onu_interval_counter_update(ctrl, (uint16_t)in->index,
				    LAN_COUNTER, in->reset_mask, in->curr,
				    &out->val);

	memcpy(&out->interval, in, sizeof(struct lan_cnt_interval));

	return ONU_STATUS_OK;
}

/** The lan_counter_reset function is used to reset the OCTRLL-based
    counters.
*/
enum onu_errorcode lan_counter_reset(struct onu_device *p_dev,
				     const struct lan_cnt_interval *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (param->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	onu_interval_counter_update(ctrl, (uint16_t)param->index,
				    LAN_COUNTER, param->reset_mask, true, NULL);

	return ONU_STATUS_OK;
}

/** The function is used to read the LAN-based counter thresholds.
*/
enum onu_errorcode lan_counter_threshold_get(struct onu_device *p_dev,
					     const struct lan_port_index *in,
					     struct lan_cnt_threshold *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->index >= ONU_GPE_MAX_ETH_UNI) {
		memset(out, 0x00, sizeof(struct lan_cnt_val));
		return LAN_STATUS_VALUE_RANGE_ERR;
	}

	memcpy(	&out->threshold,
		&ctrl->lan_cnt[0][ONU_COUNTER_THRESHOLD][in->index],
		sizeof(struct lan_cnt_val));

	out->index = in->index;

	return ONU_STATUS_OK;
}

/** The lan_counter_threshold_set function is used to write the LAN-based
    counter thresholds.
*/
enum onu_errorcode lan_counter_threshold_set(struct onu_device *p_dev,
					     const struct lan_cnt_threshold *in)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	onu_locked_memcpy(&ctrl->cnt_lock,
	     &ctrl->lan_cnt[0][ONU_COUNTER_THRESHOLD][in->index],
	     &in->threshold,
	     sizeof(struct lan_cnt_val));

	return ONU_STATUS_OK;
}

/** The function is used to read the LAN-based counter threshold crossing
    alarms (TCA).
*/
enum onu_errorcode lan_tca_get(	struct onu_device *p_dev,
				const struct uni_port_id *in,
				struct lan_cnt_val *out)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;

	if (in->uni_port_id >= ONU_GPE_MAX_ETH_UNI) {
		memset(out, 0x00, sizeof(struct lan_cnt_val));
		return LAN_STATUS_VALUE_RANGE_ERR;
	}

	onu_locked_memcpy(&ctrl->cnt_lock,
	     out,
	     &ctrl->lan_cnt[1][ONU_COUNTER_THRESHOLD][in->uni_port_id],
	     sizeof(struct lan_cnt_val));

	return ONU_STATUS_OK;
}

enum onu_errorcode lan_cnt_update(struct onu_control *ctrl,
				  const uint8_t index,
				  const uint64_t reset_mask,
				  const bool curr,
				  void *p_data)
{
	struct octrll_counter octrll_cnt;
	struct ictrll_counter ictrll_cnt;
	struct mac_counter mac_cnt;
	struct sce_lan_counter sce_cnt;
	struct lan_cnt_val *lan_data = (struct lan_cnt_val *)p_data;
	uint64_t *dest, *threshold, *shadow, *tca;
	uint64_t *src;
	uint8_t i, k, ret = 0;

	if (index >= ONU_GPE_MAX_ETH_UNI)
		return GPE_STATUS_VALUE_RANGE_ERR;

	if (curr)
		k = ctrl->current_counter ? 1 : 0;
	else
		k = ctrl->current_counter ? 0 : 1;

	if (curr) {
		dest = (uint64_t *) &ctrl->
				lan_cnt[k][ONU_COUNTER_ACC][index].tx;
		threshold = (uint64_t *) &ctrl->
				lan_cnt[0][ONU_COUNTER_THRESHOLD][index].tx;
		tca = (uint64_t *) &ctrl->
				lan_cnt[1][ONU_COUNTER_THRESHOLD][index].tx;
		shadow = (uint64_t *) &ctrl->
				lan_cnt[k][ONU_COUNTER_SHADOW][index].tx;
		src = octrll_counter_get(index, &octrll_cnt) != 0 ?
				shadow : (uint64_t *) &octrll_cnt;
		for (i = 0; i < sizeof(octrll_cnt) / sizeof(uint64_t); i++) {
			ret |= onu_counter_value_update(&dest[i], threshold[i],
							&tca[i], &shadow[i],
							src[i]);
		}
		dest = (uint64_t *) &ctrl->
				lan_cnt[k][ONU_COUNTER_ACC][index].rx;
		threshold = (uint64_t *) &ctrl->
				lan_cnt[0][ONU_COUNTER_THRESHOLD][index].rx;
		tca = (uint64_t *) &ctrl->
				lan_cnt[1][ONU_COUNTER_THRESHOLD][index].rx;
		shadow = (uint64_t *) &ctrl->
				lan_cnt[k][ONU_COUNTER_SHADOW][index].rx;
		ictrll_counter_get(index, &ictrll_cnt);
		ictrll_cnt.buffer_overflow =
			(uint64_t)iqm_iqueue_discard_counter_get((uint32_t)
									index);
		src = (uint64_t *) &ictrll_cnt;
		for (i = 0; i < sizeof(ictrll_cnt) / sizeof(uint64_t); i++) {
			ret |= onu_counter_value_update(&dest[i], threshold[i],
							&tca[i], &shadow[i],
							src[i]);
		}
		dest = (uint64_t *) &ctrl->
				lan_cnt[k][ONU_COUNTER_ACC][index].sce;
		threshold = (uint64_t *) &ctrl->
				lan_cnt[0][ONU_COUNTER_THRESHOLD][index].sce;
		tca = (uint64_t *) &ctrl->
				lan_cnt[1][ONU_COUNTER_THRESHOLD][index].sce;
		shadow = (uint64_t *) &ctrl->
				lan_cnt[k][ONU_COUNTER_SHADOW][index].sce;
		src = sce_lan_cnt_get(ctrl, index, &sce_cnt) != 0 ?
				shadow : (uint64_t *) &sce_cnt;
		for (i = 0; i < sizeof(sce_cnt) / sizeof(uint64_t); i++) {
			ret |= onu_counter_value_update(&dest[i], threshold[i],
							&tca[i], &shadow[i],
							src[i]);
		}
		dest = (uint64_t *) &ctrl->
				lan_cnt[k][ONU_COUNTER_ACC][index].mac;
		threshold = (uint64_t *) &ctrl->
				lan_cnt[0][ONU_COUNTER_THRESHOLD][index].mac;
		tca = (uint64_t *) &ctrl->
				lan_cnt[1][ONU_COUNTER_THRESHOLD][index].mac;
		shadow = (uint64_t *) &ctrl->
				lan_cnt[k][ONU_COUNTER_SHADOW][index].mac;
		eim_mac_cnt_get(index, &mac_cnt);
		src = (uint64_t *) &mac_cnt;
		for (i = 0; i < sizeof(mac_cnt) / sizeof(uint64_t); i++) {
			ret |= onu_counter_value_update(&dest[i], threshold[i],
							&tca[i], &shadow[i],
							src[i]);
		}
		if (ret)
			event_add(ctrl, ONU_EVENT_LAN_TCA,
				  &index, sizeof(index));
	}
	if (p_data) {
		memcpy(lan_data, &ctrl->lan_cnt[k][ONU_COUNTER_ACC][index],
		       sizeof(struct lan_cnt_val));
	}
	if (curr) {
		dest = (uint64_t *) &ctrl->lan_cnt[k][ONU_COUNTER_ACC][index];
		tca = (uint64_t *) &ctrl->
				lan_cnt[1][ONU_COUNTER_THRESHOLD][index];
		for (i = 0; i < sizeof(struct lan_cnt_val) / sizeof(uint64_t); i++) {
			if (reset_mask & (1 << i)) {
				dest[i] = 0;
				tca[i] = 0;
			}
		}
	}

	return ret ? ONU_STATUS_TCA : ONU_STATUS_OK;
}

/** The wol_cfg_set function is used to provide basic configurations of
   per-port WoL functionality of the Ethernet interface hardware module.
*/

/** Hardware Programming Details
   This function is available only for ports that use the on-chip GPHY.
   - index: Selects the port to be configured; the selected UNI port
		     must be configured as a GPHY or EPHY port.
		     The index defines the MDIO address that is used
		     to configure the WoL function.
   - MAC address: A MAC address must always be configured if the WoL function
                  shall be used.
      - WOLAD10.AD0 = wol_addr(0)
      - WOLAD10.AD1 = wol_addr(1)
      - WOLAD32.AD2 = wol_addr(2)
      - WOLAD32.AD3 = wol_addr(3)
      - WOLAD54.AD4 = wol_addr(4)
      - WOLAD54.AD5 = wol_addr(5)
   - Password: The password is optional. If no password shall be used, an
               all-zero password shall be programmed.
      - WOLPW10.PW0 = wol_password(0)
      - WOLPW10.PW1 = wol_password(1)
      - WOLPW32.PW2 = wol_password(2)
      - WOLPW32.PW3 = wol_password(3)
      - WOLPW54.PW4 = wol_password(4)
      - WOLPW54.PW5 = wol_password(5)
   - Password enable: If (wol_password_en == If false), set WOLPWnn to
                     all-zero and ignore the values given by wol_password.
   - wol_interrupt_en: t.b.d.
*/
enum onu_errorcode wol_cfg_set(struct onu_device *p_dev,
			       const struct wol_cfg *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	struct gphy_fw_version fw_ver;
	int8_t phy_addr;
	uint32_t mask;

	if (param->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED)
		return LAN_STATUS_NOT_INITIALIZED;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED ||
	    ctrl->lan_port_en_fct[param->index] == NULL)
		return LAN_STATUS_NOT_INITIALIZED;

	if (ctrl->lan_port_cfg[param->index].mode != LAN_MODE_GPHY &&
	    ctrl->lan_port_cfg[param->index].mode != LAN_MODE_EPHY)
		return LAN_STATUS_NO_SUPPORT;

	phy_addr = phy_addr_get(ctrl, param->index);

	if (phy_addr == ONU_LAN_MDIO_ADDR_NULL)
		return LAN_STATUS_NO_SUPPORT;

	ret = lan_phy_fw_ver_get(ctrl, phy_addr, &fw_ver);
	if (ret != ONU_STATUS_OK)
		return ret;

	if (fw_ver.major < GPHY_FW_MAJOR_NUM_WOL_SUPPORT)
		return LAN_STATUS_NO_SUPPORT;

	/* configure WOL interrupt*/
	if (is_falcon_chip_a1x()) {
		mask = param->index & 0x2 ? EIM_EIM_IER_A1X_GPHY1_IEN_EN :
					    EIM_EIM_IER_A1X_GPHY0_IEN_EN;
	} else {
		mask = param->index & 0x2 ? EIM_EIM_IER_A2X_GPHY1_IEN_EN :
					    EIM_EIM_IER_A2X_GPHY0_IEN_EN;
	}

	eim_central_interrupt_enable_set(
			param->wol_interrupt_en ? 0x0  : mask,
			param->wol_interrupt_en ? mask : 0x0);

	memcpy(&ctrl->lan_wol_cfg[param->index], param, sizeof(struct wol_cfg));

	ret = lan_phy_wol_cfg_apply(ctrl, param->index);

	return ret;
}

/** The wol_cfg_get function is used to read back the Wol
   configuration of the Ethernet interface hardware module.
*/
/** Hardware programming details: See wol_cfg_set.
*/
enum onu_errorcode wol_cfg_get(struct onu_device *p_dev,
			       const struct lan_port_index *in,
			       struct wol_cfg *out)
{
	struct onu_control *ctrl = p_dev->ctrl;

	if (in->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED)
		return LAN_STATUS_NOT_INITIALIZED;

	if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED ||
	    ctrl->lan_port_en_fct[in->index] == NULL)
		return LAN_STATUS_NOT_INITIALIZED;

	if (ctrl->lan_port_cfg[in->index].mode != LAN_MODE_GPHY &&
	    ctrl->lan_port_cfg[in->index].mode != LAN_MODE_EPHY &&
	    ctrl->lan_port_cfg[in->index].mode != LAN_MODE_RGMII_MAC)
		return LAN_STATUS_NO_SUPPORT;

	memcpy(out, &ctrl->lan_wol_cfg[in->index], sizeof(struct wol_cfg));

	return ONU_STATUS_OK;
}

/** The wol_status_get function provides a summary of status information
   that is available per port for the Wol function.
*/
/** Hardware Programming Details
   This function is available only for ports that use the on-chip GPHY.
   The per-port status information is read from the following hardware
   registers:
   - index: Selects the UNI port to be configured; the selected UNI
		     port must be configured as a GPHY or EPHY port.
		     The index defines the MDIO address that is used
		     to configure the WoL function.
   - wol_sts: Read the PHY's interrupt status register (t.b.d.).
*/
enum onu_errorcode wol_status_get(struct onu_device *p_dev,
				  const struct lan_port_index *in,
				  struct wol_status *out)
{
	(void)p_dev;
	(void)in;

	memset(out, 0x00, sizeof(*out));

	return ONU_STATUS_NOT_IMPLEMENTED;
}

/** The mdio_data_read function provides read access to an external or
   internal Ethernet PHY.
*/
/** Hardware Programming Details
   The information is read from the following hardware registers:
   - addr_dev: selected device address
   - addr_reg: selected register address
   - data: read data
*/
enum onu_errorcode mdio_data_read(struct onu_device *p_dev,
				  const struct mdio *in,
				  struct mdio_read *out)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return lan_mdio_access(ctrl, in->addr_dev, in->addr_reg,
				0, 0, &out->data);
}

/** The mdio_data_write function provides write access to an external or
   internal Ethernet PHY.
*/

/** Hardware Programming Details
   - addr_dev: selected device address
   - addr_reg: selected register address
   - data: data to be written
*/
enum onu_errorcode mdio_data_write(struct onu_device *p_dev,
				   const struct mdio_write *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return lan_mdio_access(ctrl, param->addr_dev, param->addr_reg,
				0xFFFF, param->data, NULL);
}

/** The mdio_enable function is used to enable the
	internal and/or external MDIO bus interface.
*/

/** Hardware Programming Details
   - mode == MDIO_INTERNAL: enable only the internal MDIO bus,
				  do not touch the MDIO pin configuration
   - mode == MDIO_EXTERNAL: enable the internal MDIO bus and enable
				  the MDIO pins (MDIO, MDC)
*/
enum onu_errorcode mdio_enable(struct onu_device *p_dev,
			       const struct mdio_en *param)
{
	(void)p_dev;

	switch (param->mode) {
	case MDIO_EXTERNAL:
		sys_eth_ext_phy(true, SYS_ETH_EXTPHYC_CLKSEL_F25);
	case MDIO_INTERNAL:
		sys_eth_hw_activate(SYS_ETH_ACT_MDIO);
		break;
	default:
		return LAN_STATUS_VALUE_RANGE_ERR;
	}

	return ONU_STATUS_OK;
}

/** The mdio_disable function is used to disable the
	internal and/or external MDIO bus interface.
*/

/** Hardware Programming Details
   - mode == MDIO_INTERNAL: disable the MDIO interface completely,
				  disable the MDIO pins (MDIO, MDC)
   - mode == MDIO_EXTERNAL: do not touch the internal MDIO bus,
				  disable the MDIO pins (MDIO, MDC)
*/
enum onu_errorcode mdio_disable(struct onu_device *p_dev,
				const struct mdio_dis *param)
{
	(void)p_dev;

	switch (param->mode) {
	case MDIO_EXTERNAL:
		sys_eth_ext_phy(false, SYS_ETH_EXTPHYC_CLKSEL_F25);
		break;
	case MDIO_INTERNAL:
		sys_eth_hw_clk_disable(SYS_ETH_CLKCLR_MDIO_CLR);
		break;
	default:
		return LAN_STATUS_VALUE_RANGE_ERR;
	}

	return ONU_STATUS_OK;
}



/** The mdio_data_read function provides read access to an external or
   internal Ethernet PHY.
*/
enum onu_errorcode mmd_data_read(struct onu_device *p_dev,
				  const struct mmd *in,
				  struct mmd_read *out)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return lan_mmd_access(ctrl, in->addr_dev, in->mmd_sel,
		in->mmd_addr, 0, 0, &out->data);
}

/** The mdio_data_write function provides write access to an external or
   internal Ethernet PHY.
*/

/** Hardware Programming Details
   - addr_dev: selected device address
   - addr_reg: selected register address
   - data: data to be written
*/
enum onu_errorcode mmd_data_write(struct onu_device *p_dev,
				   const struct mmd_write *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	return lan_mmd_access(ctrl, param->addr_dev, param->mmd_sel,
		param->mmd_addr, 0xFFFF, param->data, NULL);
}


enum onu_errorcode lan_mdio_access(struct onu_control *ctrl,
				   const int8_t a_dev,
				   const uint8_t a_reg,
				   uint16_t mask_clear,
				   uint16_t mask_set,
				   uint16_t *data)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	unsigned long flags = 0;
	uint16_t reg_data = 0;

	if (a_dev == ONU_LAN_MDIO_ADDR_NULL) {
		if (data)
			*data = 0xFFFF;
		return ONU_STATUS_OK;
	}

	/* lock mdio access */
	onu_spin_lock_get(&ctrl->mdio_lock, &flags);
	while (1) {
		if (mask_clear || mask_set) {
			if (eim_mdio_data_read(a_dev, a_reg, &reg_data) != 0) {
				ret = ONU_STATUS_ERR;
				break;
			}

			reg_data = (reg_data & ~mask_clear) | mask_set;

			if (eim_mdio_data_write(a_dev, a_reg, reg_data) != 0) {
				ret = ONU_STATUS_ERR;
				break;
			}
		} else if (data) {
			if (eim_mdio_data_read(a_dev, a_reg, &reg_data) != 0) {
				ret = ONU_STATUS_ERR;
				break;
			}
		} else {
			ret = ONU_STATUS_ERR;
			break;
		}

		if (data)
			*data = reg_data;

		break;
	}
	/* unlock mdio access */
	onu_spin_lock_release(&ctrl->mdio_lock, flags);

	return ret;
}


enum onu_errorcode lan_mmd_access(struct onu_control *ctrl,
				   const int8_t a_dev,
				   const uint8_t mmd_sel,
				   const uint16_t mmd_addr,
				   uint16_t mask_clear,
				   uint16_t mask_set,
				   uint16_t *data)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	unsigned long flags = 0;
	uint16_t reg_data = 0;
	uint16_t mmd_ctrl;
	/* autopoll disabling */
	bool do_restore = false;
#ifdef CONFIG_WITH_FALCON_A2X
	uint8_t port_id;
	uint32_t restore_val;
#endif

	if (a_dev == ONU_LAN_MDIO_ADDR_NULL) {
		if (data)
			*data = 0xFFFF;
		return ONU_STATUS_OK;
	}

	/* lock mdio access */
	onu_spin_lock_get(&ctrl->mdio_lock, &flags);
#ifdef CONFIG_WITH_FALCON_A2X
	if (is_falcon_chip_a2x()) {
		if (!eim_phy_autopoll_force_current(a_dev,
				&port_id, &restore_val))
			do_restore = true;
	}
#endif
	while (1) {
		mmd_ctrl = mmd_sel | (0<<14); /* function "address" = 00b */
		if (eim_mdio_data_write(a_dev, MDIO_PHY_MMD_CTRL, mmd_ctrl) != 0) {
			ret = ONU_STATUS_ERR;
			break;
		}
		if (eim_mdio_data_write(a_dev, MDIO_PHY_MMD_DATA, mmd_addr) != 0) {
			ret = ONU_STATUS_ERR;
			break;
		}
		mmd_ctrl = mmd_sel | (1<<14); /* function "data" = 01b */
		if (eim_mdio_data_write(a_dev, MDIO_PHY_MMD_CTRL, mmd_ctrl) != 0) {
			ret = ONU_STATUS_ERR;
			break;
		}
		if (mask_clear || mask_set) {
			if (eim_mdio_data_read(a_dev, MDIO_PHY_MMD_DATA, &reg_data) != 0) {
				ret = ONU_STATUS_ERR;
				break;
			}
			reg_data = (reg_data & ~mask_clear) | mask_set;
			if (eim_mdio_data_write(a_dev, MDIO_PHY_MMD_DATA, reg_data) != 0) {
				ret = ONU_STATUS_ERR;
				break;
			}
		} else if (data) {
			if (eim_mdio_data_read(a_dev, MDIO_PHY_MMD_DATA, &reg_data) != 0) {
				ret = ONU_STATUS_ERR;
				break;
			}
			*data = reg_data;
		} else {
			ret = ONU_STATUS_ERR;
			break;
		}
		break;
	}

#ifdef CONFIG_WITH_FALCON_A2X
	if (is_falcon_chip_a2x() && do_restore) {
		eim_phy_autopoll_restore_settings(port_id, restore_val);
	}
#endif
	/* unlock mdio access */
	onu_spin_lock_release(&ctrl->mdio_lock, flags);

	return ret;
}

enum onu_errorcode lan_port_capability_cfg_set(struct onu_device *p_dev,
					       const struct
					       lan_port_capability_cfg *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	struct onu_control *ctrl = p_dev->ctrl;
	int8_t phy_addr;

	if (param->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (param->full_duplex == false && param->half_duplex == false)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (param->mbit_10 == false &&
	    param->mbit_100 == false &&
	    param->mbit_1000 == false)
		return LAN_STATUS_VALUE_RANGE_ERR;

	if (param->eee == true)
		return LAN_STATUS_NO_SUPPORT;

	phy_addr = phy_addr_get(ctrl, param->index);
	if (phy_addr == ONU_LAN_MDIO_ADDR_NULL)
		return LAN_STATUS_NO_SUPPORT;

	if (memcmp(&ctrl->lan_port_capability_cfg[param->index],
		   param, sizeof(*param)) == 0)
		return ONU_STATUS_OK;

	ret = lan_phy_capability_cfg_apply(ctrl, phy_addr, param);
	if (ret != ONU_STATUS_OK)
		return ret;

	memcpy(&ctrl->lan_port_capability_cfg[param->index],
	       param, sizeof(struct lan_port_capability_cfg));

	/* restart auto-negotiation */
	ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_MODE_CTRL,
			      0, MDIO_PHY_MODE_CONTROL_AUTONEG_RESTART, NULL);

	return ret;
}

enum onu_errorcode lan_port_capability_cfg_get(struct onu_device *p_dev,
					       const struct lan_port_index *in,
					       struct
					       lan_port_capability_cfg *out)
{
	struct onu_control *ctrl = p_dev->ctrl;
	uint32_t index;

	if (in->index >= ONU_GPE_MAX_ETH_UNI)
		return LAN_STATUS_VALUE_RANGE_ERR;

	index = in->index;

	memcpy(out, &ctrl->lan_port_capability_cfg[in->index],
	       sizeof(struct lan_port_capability_cfg));

	out->index = index;

	return ONU_STATUS_OK;
}

#if ONU_GPE_MAX_ETH_UNI > 2
STATIC enum onu_errorcode lan_gphy_led_init(struct onu_control *ctrl,
					    const uint8_t port_num)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	int8_t phy_addr;
	uint8_t i;
	struct gphy_fw_version fw_ver;
	struct gphy_led_reg_init reg_init[] = {
		{MMD_LEDC_HIGH, MMD_LEDC_HIGH_NACS_NONE |
				MMD_LEDC_HIGH_SBF_F02HZ |
				MMD_LEDC_HIGH_FBF_F04HZ},
		{MMD_LEDC_LOW, 	MMD_LEDC_LOW_CBLINK_NONE |
				MMD_LEDC_LOW_SCAN_NONE},
		{MMD_LED0_HIGH, MMD_LEDX_HIGH_BLINKF_NONE |
				MMD_LEDX_HIGH_CON_LINK10XX},
		{MMD_LED0_LOW, 	MMD_LEDX_LOW_PULSE_NONE |
				MMD_LEDX_LOW_BLINKS_NONE},
		{MMD_LED1_HIGH, MMD_LEDX_HIGH_BLINKF_NONE |
				MMD_LEDX_HIGH_CON_NONE},
		{MMD_LED1_LOW, 	MMD_LEDX_LOW_PULSE_TXACT |
				MMD_LEDX_LOW_PULSE_RXACT |
				MMD_LEDX_LOW_BLINKS_NONE}
	};

	phy_addr = phy_addr_get(ctrl, port_num);
	if (phy_addr == ONU_LAN_MDIO_ADDR_NULL)
		return LAN_STATUS_NO_SUPPORT;

	ret = lan_phy_fw_ver_get(ctrl, phy_addr, &fw_ver);
	if (ret != ONU_STATUS_OK)
		return ret;

	if (fw_ver.major < GPHY_FW_MAJOR_NUM_LED_SUPPORT)
		return LAN_STATUS_NO_SUPPORT;

	for (i = 0; i < ARRAY_SIZE(reg_init); i++) {
		ret = lan_mmd_access(ctrl, phy_addr,
				     MMD_LED_SEL, reg_init[i].reg_addr,
				     0xFFFF, reg_init[i].reg_data, NULL);
		if (ret != ONU_STATUS_OK)
			return ret;
	}

	return ret;
}
#endif

STATIC enum onu_errorcode lan_phy_status_get_a1x(struct onu_control *ctrl,
	const int8_t phy_addr, struct lan_link_status *link_status)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint16_t data = 0xFFFF;

	ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_STATUS, 0, 0, &data);
	if (ret != ONU_STATUS_OK) {
		return ret;
	}

	if (data == 0xFFFF) {
		link_status->up = false;
		return ret;
	}

	/* Check PHY status register LINK field */
	link_status->up = data & MDIO_PHY_STATUS_LS ? true : false;

	if (link_status->speed != LAN_MODE_SPEED_AUTO) {
		/* fixed speed/duplex already set by calling function */
		return ret;
	}

	ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_GSTAT, 0, 0, &data);
	if (ret != 0) {
		ONU_DEBUG_ERR("MDIO(%d) GSTAT reg get failed, %d!",
			      phy_addr, ret);
		return ret;
	}

	if (data & MDIO_GSTAT_MBTFD) {
		link_status->duplex = LAN_PHY_MODE_DUPLEX_FULL;
		link_status->speed = LAN_MODE_SPEED_1000;
	} else if (data & MDIO_GSTAT_MBTHD) {
		link_status->duplex = LAN_PHY_MODE_DUPLEX_HALF;
		link_status->speed = LAN_MODE_SPEED_1000;
	} else {
		ret = lan_mdio_access (ctrl, phy_addr, MDIO_PHY_AN_LPA, 0, 0,
					&data);
		if (ret != 0) {
			ONU_DEBUG_ERR("MDIO(%d) AN_LPA reg get failed, %d!",
					phy_addr, ret);
			return ret;
		}

		if (data & MDIO_PHY_AN_LPA_DBT_FDX) {
			link_status->duplex = LAN_PHY_MODE_DUPLEX_FULL;
			link_status->speed = LAN_MODE_SPEED_100;
		} else if (data & MDIO_PHY_AN_LPA_DBT_HDX) {
			link_status->duplex = LAN_PHY_MODE_DUPLEX_HALF;
			link_status->speed = LAN_MODE_SPEED_100;
		} else if (data & MDIO_PHY_AN_LPA_XBT_FDX) {
			link_status->duplex = LAN_PHY_MODE_DUPLEX_FULL;
			link_status->speed = LAN_MODE_SPEED_10;
		} else if (data & MDIO_PHY_AN_LPA_XBT_HDX) {
			link_status->duplex = LAN_PHY_MODE_DUPLEX_HALF;
			link_status->speed = LAN_MODE_SPEED_10;
		} else {
			link_status->duplex = LAN_PHY_MODE_DUPLEX_AUTO;
			link_status->speed = LAN_MODE_SPEED_AUTO;
		}
	}

	return ret;
}

STATIC enum onu_errorcode lan_phy_status_get_a2x (struct onu_control *ctrl,
	const uint8_t port_idx, struct lan_link_status *link_status)
{
#ifdef CONFIG_WITH_FALCON_A2X
	bool enable;
	uint32_t mdio_stat_reg;

	if (eim_phy_autopoll_enable_get(port_idx, &enable) != 0)
		return ONU_STATUS_ERR;
	if (!enable)
		return ONU_STATUS_ERR;

	if (eim_phy_autopoll_status_get(port_idx, &mdio_stat_reg) != 0)
		return ONU_STATUS_ERR;
	/* PHY active Status & Link Status */
	if ( (mdio_stat_reg & (EIM_MDIO_STAT_PACT|EIM_MDIO_STAT_LSTAT)) ==
		(EIM_MDIO_STAT_PACT_ACTIVE|EIM_MDIO_STAT_LSTAT_UP)) {
		link_status->up = true;

		switch (mdio_stat_reg & EIM_MDIO_STAT_SPEED_MASK) {
		case EIM_MDIO_STAT_SPEED_M10:
			link_status->speed = LAN_MODE_SPEED_10;
			break;
		case EIM_MDIO_STAT_SPEED_M100:
			link_status->speed = LAN_MODE_SPEED_100;
			break;
		case EIM_MDIO_STAT_SPEED_G1:
			link_status->speed = LAN_MODE_SPEED_1000;
			break;
		default:
			link_status->speed = LAN_MODE_SPEED_AUTO;
			break;
		}
		if ((mdio_stat_reg & EIM_MDIO_STAT_FDUP) == 
			EIM_MDIO_STAT_FDUP_FULL)
			link_status->duplex = LAN_PHY_MODE_DUPLEX_FULL;
		else
			link_status->duplex = LAN_PHY_MODE_DUPLEX_HALF;
		}
#endif
	return ONU_STATUS_OK;
}

STATIC enum onu_errorcode lan_phy_status_get(struct onu_control *ctrl,
					     const uint8_t port_idx,
					     struct lan_link_status *link_status)
{
	int8_t phy_addr = phy_addr_get(ctrl, port_idx);

	/* use configured values as fallback */
	link_status->duplex = ctrl->lan_port_cfg[port_idx].duplex_mode;
	link_status->speed = ctrl->lan_port_cfg[port_idx].speed_mode;

	if (phy_addr == ONU_LAN_MDIO_ADDR_NULL) {
		link_status->up = true;
		return ONU_STATUS_OK;
	}

	if (is_falcon_chip_a1x())
		return lan_phy_status_get_a1x(ctrl, phy_addr, link_status);
	if (is_falcon_chip_a2x())
		return lan_phy_status_get_a2x(ctrl, port_idx, link_status);

	return ONU_STATUS_ERR;
}

enum onu_errorcode lan_phy_interrupt_enable_set(struct onu_control *ctrl,
						const uint8_t port_num,
						const uint16_t clear,
						const uint16_t set)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	int8_t phy_addr = phy_addr_get(ctrl, port_num & 0x3);

	/* read IMASK register*/
	ret = lan_mdio_access(ctrl, phy_addr, MDIO_IMASK, clear, set, NULL);
	if (ret != ONU_STATUS_OK)
		return ret;

	return ret;
}

STATIC enum onu_errorcode lan_phy_loop_enable_set(struct onu_control *ctrl,
		const int8_t phy_addr, const bool fe, const bool ne)
{
	enum onu_errorcode ret;

	uint16_t set = 0;
	
	if (ne == true && fe == true)
		return LAN_STATUS_NO_SUPPORT;
	if (fe == true)
		set = MDIO_PHY_CTL1_TLOOP_FETL;
	if (ne == true)
#ifdef STD_PHY_NE_LOOP
		return lan_mdio_access(ctrl, phy_addr, MDIO_PHY_MODE_CTRL,
					MDIO_PHY_MODE_CTRL_LOOPBACK,
					MDIO_PHY_MODE_CTRL_LOOPBACK,
					NULL);
	else
		return  lan_mdio_access(ctrl, phy_addr, MDIO_PHY_MODE_CTRL,
					MDIO_PHY_MODE_CTRL_LOOPBACK, 0, NULL);
#else
		set = MDIO_PHY_CTL1_TLOOP_NETL;
#endif
	ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_CTL1,
		MDIO_PHY_CTL1_TLOOP_MASK, set, NULL);
	if (ret != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("MDIO(%d) PHYCTL1 register modify failed!",
				phy_addr);
	}

	return ret;
}

STATIC enum onu_errorcode lan_phy_mode_control_set(struct onu_control *ctrl,
						   const int8_t phy_addr,
						   const enum lan_mode_speed
						   speed,
						   const enum lan_mode_duplex
						   duplex)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	uint16_t clear = 0, set = 0;

	if (speed == LAN_MODE_SPEED_AUTO && duplex == LAN_PHY_MODE_DUPLEX_AUTO) {
		/* enable auto-negotiation */
		set |= MDIO_PHY_MODE_CONTROL_AUTONEG_ENABLE;
	} else {
		/* disable auto-negotiation */
		clear |= MDIO_PHY_MODE_CONTROL_AUTONEG_ENABLE;
		/* clear speed settings */
		clear |= MDIO_PHY_MODE_CONTROL_SPEED;
		switch (speed) {
		case LAN_MODE_SPEED_10:
			/* |= 0x0*/
			break;
		case LAN_MODE_SPEED_100:
			set |= MDIO_PHY_MODE_CONTROL_SPEED_100MBPS;
			break;
		case LAN_MODE_SPEED_1000:
			set |= MDIO_PHY_MODE_CONTROL_SPEED_1000MBPS;
			break;
		default:
			return ONU_STATUS_ERR;
		}
		/* clear duplex mode settings */
		clear |= MDIO_PHY_MODE_CONTROL_DUPLEX;
		switch (duplex) {
		case LAN_PHY_MODE_DUPLEX_FULL:
			set |= MDIO_PHY_MODE_CONTROL_DUPLEX_FULL;
			break;
		case LAN_PHY_MODE_DUPLEX_HALF:
			/* |= 0x0*/
			break;
		default:
			return ONU_STATUS_ERR;
		}
	}
	ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_MODE_CTRL,
				clear, set, NULL);
	if (ret != 0) {
		ONU_DEBUG_ERR("MDIO(%d) mode control register modify failed!",
			      phy_addr);
		return ret;
	}

	if (phy_is_lantiq(ctrl, phy_addr) == ONU_STATUS_OK) {
		/* According to errata sheet, Revision 1.3, 2011-12-07,
		Chapter 14 Slave Mode Link-Up:
		Set bit "Master slave port type" to multiport to overcome
		link problems ("fails to train up with some link partners
		in 1000BASE-T mode") */
		ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_MODE_GCTRL,
			0, 0x400, NULL);
		/* Set PSCL to 0. This is helping to improve the slave
		   training. Some IOP partners are sensitive to the way we are
		   scaling down power */
		if (ret == 0)
			ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_CTL2,
				0x04, 0x0, NULL);
	}

	return ret;
}

STATIC enum onu_errorcode lan_phy_fw_ver_get(struct onu_control *ctrl,
					     const int8_t phy_addr,
					     struct gphy_fw_version *fw_ver)
{
	enum onu_errorcode ret = ONU_STATUS_OK;

	ret = lan_mdio_access(ctrl, phy_addr, MDIO_FWV, 0, 0,
			      (uint16_t *)fw_ver);
	if (ret != ONU_STATUS_OK) {
		ONU_DEBUG_ERR("MDIO(%d) FW version register get failed!",
			      phy_addr);
		return ret;
	}

	return ret;
}

STATIC enum onu_errorcode lan_phy_wol_cfg_apply(struct onu_control *ctrl,
						const uint8_t port_num)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	int8_t phy_addr = phy_addr_get(ctrl, port_num & 0x3);
	uint8_t i, check;
	struct wol_cfg *wol_cfg;
	uint16_t wol_ctrl;

	if((port_num & 0x3) >= ONU_GPE_MAX_ETH_UNI)
		return ONU_STATUS_ERR;

	wol_cfg = &ctrl->lan_wol_cfg[port_num & 0x3];

	check = 0;
	for (i = 0; i < ARRAY_SIZE(wol_cfg->wol_addr); i++) {
		check |= wol_cfg->wol_addr[i];
	}
	/* if not configured, exit! */
	if (check == 0)
		return ret;

	if (phy_addr == ONU_LAN_MDIO_ADDR_NULL)
		return ret;

	/* configure MAC address*/
	for (i = 0; i < ARRAY_SIZE(wol_cfg->wol_addr); i++ ) {
		ret = lan_mmd_access(ctrl, phy_addr,
				     MMD_WOL_SEL, MMD_ADDR_WOLAD0 + i,
				     0xFFFF, (uint16_t)wol_cfg->wol_addr[i],
				     NULL);
		if (ret != ONU_STATUS_OK)
			return ret;
	}
	/* configure WOL password*/
	for (i = 0; i < ARRAY_SIZE(wol_cfg->wol_password); i++ ) {
		ret = lan_mmd_access(ctrl, phy_addr,
				     MMD_WOL_SEL, MMD_WOLPW0 + i,
				     0xFFFF,
				     wol_cfg->wol_password_en ?
					(uint16_t)wol_cfg->wol_password[i] : 0,
				     NULL);
		if (ret != ONU_STATUS_OK)
			return ret;
	}

	/* configure WOL interrupt*/
	ret = lan_phy_interrupt_enable_set(
			ctrl, port_num,
			wol_cfg->wol_interrupt_en ? 0x0 : MDIO_IMASK_WOL,
			wol_cfg->wol_interrupt_en ? MDIO_IMASK_WOL : 0x0);
	if (ret != ONU_STATUS_OK)
		return ret;

	/* set WOL control register*/
	wol_ctrl  = MMD_WOLCTRL_EN;
	wol_ctrl |= wol_cfg->wol_password_en ? MMD_WOLCTRL_SPWD_EN : 0;

	ret = lan_mmd_access(ctrl, phy_addr,
			     MMD_WOL_SEL, MMD_ADDR_WOLCTRL,
			     0xFFFF, wol_ctrl,
			     NULL);
	if (ret != ONU_STATUS_OK)
		return ret;

	return ret;
}

STATIC enum onu_errorcode lan_phy_settings_update(struct onu_control *ctrl,
						  const uint8_t port_num)
{
	enum onu_errorcode ret = ONU_STATUS_OK;
	int8_t phy_addr = phy_addr_get(ctrl, port_num & 0x3);
	struct lan_port_cfg *lan_port_cfg;
	struct lan_port_capability_cfg *lan_port_capability_cfg;
	uint16_t data, cnt = 300;

	if((port_num & 0x3) >= ONU_GPE_MAX_ETH_UNI)
		return ONU_STATUS_ERR;

	if (phy_addr == ONU_LAN_MDIO_ADDR_NULL)
		return ret;

	lan_port_cfg = &ctrl->lan_port_cfg[port_num & 0x3];
	lan_port_capability_cfg = &ctrl->lan_port_capability_cfg[port_num & 0x3];

	/* let the PHY boot up */
	onu_udelay (1500);
	do {
		lan_mdio_access (ctrl, phy_addr, MDIO_PHY_MODE_CTRL, 
			0, 0, &data);
		if (cnt-- == 0) {
			ONU_DEBUG_ERR("PHY not ready");
			break;
		}
		onu_udelay (20);
	}
	while (data == 0xffff);
	ret = lan_phy_mode_control_set(ctrl, phy_addr,
		lan_port_cfg->speed_mode, lan_port_cfg->duplex_mode);
	if (ret != ONU_STATUS_OK)
		return ret;

	ret = phy_lpi_rxckst_enable(ctrl, phy_addr, lan_port_cfg->lpi_enable);
	if (ret != ONU_STATUS_OK)
		return ret;

	ret = lan_phy_wol_cfg_apply(ctrl, port_num);
	if (ret != ONU_STATUS_OK)
		return ret;

	if (lan_port_cfg->speed_mode == LAN_MODE_SPEED_AUTO && 
		lan_port_cfg->duplex_mode == LAN_PHY_MODE_DUPLEX_AUTO) {
		ret = lan_phy_capability_cfg_apply(ctrl, phy_addr,
					   lan_port_capability_cfg);
		if (ret != ONU_STATUS_OK)
			return ret;

		/* restart auto-negotiation */
		ret = lan_mdio_access(ctrl, phy_addr, MDIO_PHY_MODE_CTRL,
			      0, MDIO_PHY_MODE_CONTROL_AUTONEG_RESTART, NULL);
	}

	return ret;
}

/** Watchdog polls the PHYs and OCTRLLs in the background in order to detect a
    downstream stuck. Upon expiry, the watchdog must produce a printout and 
    then reboot the chip.

    \remarks
	The following conditions persist for more than 1s:

    - The PHY link is up AND
    - The OCTRLL indicates "SyncFifo full" (OCTRLLx.STATE.TXFIFOFULL=1) AND
    - the OCTRLL indicates that there are packets to send (OCTRLLx.STATE.EPFILLED=1)AND
    - The OCTRLL Tx Packet counter does not increase (OCTRLLx.TXPCNT).
*/
enum onu_errorcode lan_traffic_watchdog (struct onu_control *ctrl)
{
	int i;
	uint32_t val;
	uint16_t gphy_err;
#if 0	
	static uint32_t last_tx_pcnt[ONU_GPE_MAX_ETH_UNI] = { 0 };
	static uint32_t err_cnt[ONU_GPE_MAX_ETH_UNI] = { 0 };
	uint32_t txpcnt;
#endif	
	static uint32_t last_rx_pcnt[ONU_GPE_MAX_ETH_UNI] = { 0 };
	static uint32_t last_mac_err[ONU_GPE_MAX_ETH_UNI] = { 0 };
	static uint32_t gphy_err_cnt [ONU_GPE_MAX_ETH_UNI] = { 0 };

	for (i = 0; i < 1; i++) {
		if (!ctrl->lan_port_sts_fct[i])
			continue;
		if (ctrl->lan_link_status[i].up == false) {
			continue;
		}
		if (is_falcon_chip_a2x()) {
			bool toolong, ig_ovfl;
			/* check for upstream stuck, if counter is not 0 and
			   the same from before */
			if (last_rx_pcnt[i] != 0 &&
				last_rx_pcnt[i] == ictrll_pcnt_get (i)) {
 				ONU_DEBUG_ERR ("LAN upstream traffic stuck!");
				/* reboot via watchdog! */
				while(1);
			}
			eim_mac_err_status_get (i, &toolong, &ig_ovfl);
			/* if both set, remember counter and fire next time
			   when counters haven't changed */
			if (toolong && ig_ovfl && last_rx_pcnt[i] == 0) {
				last_rx_pcnt[i] = ictrll_pcnt_get (i);
				/* clear bits is done in status call */
			}
			else
				/* do not check for the counter */
				last_rx_pcnt[i] = 0;
		}
#if 0
		/* monitoring for downstream stuck disabled */
		octrll_state_get (i, &val, &txpcnt);
		if ((val & OCTRLL_STATE_TXFIFOFULL) == 0 || 
			(val & OCTRLL_STATE_EPFILLED) == 0) {
			err_cnt[i] = 0;
		} else {
			/* check for first update or equal to last value */
			if (last_tx_pcnt [i] != 0 && last_tx_pcnt [i] == txpcnt) {
				err_cnt [i] ++;
				if (err_cnt[i] >= 2)
					/* we are polling every 1000 ms, 
					so traffic stucked for 2 seconds */
					ONU_DEBUG_ERR ("LAN downstream traffic stuck!");
					return LAN_STATUS_TRAFFIC_STUCK;
			}
			else
				err_cnt[i] = 0;
		}
		last_tx_pcnt[i] = txpcnt;
#endif		
		/* check for GPHY stuck.
		   upon 5 consecutive readouts, we need to see consistently at least 
		   one additional Macerror or at least more than 127 SSD errors each time.
		   Only in this case we restart the link */
		if (i < 2 && ctrl->lan_port_cfg[i].speed_mode ==
			LAN_MODE_SPEED_AUTO && 
			ctrl->lan_port_cfg[i].duplex_mode ==
			LAN_PHY_MODE_DUPLEX_AUTO) {
			lan_mdio_access(ctrl, phy_addr_get(ctrl, i), MDIO_PHY_ERRCNT,
				0, 0x300, &gphy_err);
			ictrll_macerr_get (i, &val);
			if ((last_mac_err[i] != val) || 
				((gphy_err & 0xff) > 127)) {
				gphy_err_cnt[i]++;
				if (gphy_err_cnt[i] > 2) {
					ONU_DEBUG_ERR ("GPHY#%d MAC errors (SSDERR=%d)!", i, gphy_err & 0xff);
					if (ctrl->lan_mux_mode == LAN_MUX_UNDEFINED ||
						ctrl->lan_port_en_fct[i] == NULL) {
						ctrl->lan_port_en_fct[i](ctrl, i, true);
					}
					else
						/* restart auto-negotiation */
						lan_mdio_access(ctrl,
							phy_addr_get(ctrl, i), 
							MDIO_PHY_MODE_CTRL, 0, 
							MDIO_PHY_MODE_CONTROL_AUTONEG_RESTART,
							NULL);
					gphy_err_cnt[i] = 0;
				}
			}
			else {
				gphy_err_cnt[i] = 0;
			}
			last_mac_err[i] = val;
		}
	}
	
	return ONU_STATUS_OK;
}

int net_pdu_info_get(const uint8_t cpu_egress_port, struct onu_pdu_info *info)
{
	uint8_t vuni_epn[ONU_GPE_MAX_VUNI] = {	ONU_GPE_EPN_VUNI0,
						ONU_GPE_EPN_VUNI1,
						ONU_GPE_EPN_VUNI2,
						ONU_GPE_EPN_VUNI3};
	if (cpu_egress_port >= ONU_GPE_MAX_EGRESS_CPU_PORT)
		return -1;

	if (!onu_is_initialized())
		return -1;

	return ssb_egress_info_read(vuni_epn[cpu_egress_port], info);
}

STATIC bool net_is_port_up(const uint8_t netdev_port)
{
	bool ret = false;

	switch (netdev_port) {
	case ONU_NET_NETDEV_WAN_PORT:
		ret = onu_gpon_link_status_get() == 0 ? false : true;
		break;

	case ONU_NET_NETDEV_LAN0_PORT:
	case ONU_NET_NETDEV_LAN1_PORT:
	case ONU_NET_NETDEV_LAN2_PORT:
	case ONU_NET_NETDEV_LAN3_PORT:
		if (onu_mac_link_status_get(net_uni_get(netdev_port)) == 0)
			break;
		ret = true;
		break;
	case ONU_NET_NETDEV_EXC_PORT:
		ret = true;
		break;
	default:
		break;
	}
	return ret;
}

int net_pdu_write(const uint8_t netdev_port, const uint32_t plen,
		  const uint8_t *data)
{
	int ret = 0;
	ssb_write_t ssb_write;
	uint8_t qid, pix = 0xFF;
	union u_onu_exception_pkt_hdr *hdr;
	const uint8_t *pkt = data;
	uint32_t len = plen, hdr_len;

	if(data == NULL || plen == 0)
		return -1;

	if (!onu_is_initialized())
		return -1;

	switch (netdev_port) {
	case ONU_NET_NETDEV_WAN_PORT:
		/* assuming that the IP Host was connected by pseudo LAN 4*/
		pix = 4;
		qid = ONU_GPE_INGRESS_QUEUE_CPU_US;
		ssb_write = ssb_iqueue_write;
		break;

	case ONU_NET_NETDEV_LAN0_PORT:
	case ONU_NET_NETDEV_LAN1_PORT:
	case ONU_NET_NETDEV_LAN2_PORT:
	case ONU_NET_NETDEV_LAN3_PORT:
		qid = net_uni_get(netdev_port) * 8 + 0x80;
		ssb_write = ssb_equeue_write;
		break;

	case ONU_NET_NETDEV_EXC_PORT:
		if (plen <= sizeof(union u_onu_exception_pkt_hdr)) {
			ret = -1;
			break;
		}

		hdr = (union u_onu_exception_pkt_hdr *)pkt;

		hdr_len = hdr->ext.ext_bytes ?
				sizeof(*hdr) :
				sizeof(*hdr) - sizeof(hdr->raw.e);

		pkt += hdr_len;
		len -= hdr_len;

		if (hdr->ext.ex_dir == 0) {
			pix = hdr->byte.gpix;
			qid  = hdr->byte.egress_qid;
			ssb_write = ssb_equeue_write;
		} else {
			if (hdr->ext.ex_side == 1) {
				/* LAN side*/
				pix = hdr->ext.lan_port_idx;
				qid  = ONU_GPE_INGRESS_QUEUE_CPU_US;
			} else {
				/* WAN side*/
				pix = hdr->byte.gpix;
				qid  = ONU_GPE_INGRESS_QUEUE_CPU_DS;
			}

			ssb_write = ssb_iqueue_write;
		}
		break;

	default:
		ret = -1;
		break;
	}

	if (ret == 0 && net_is_port_up(netdev_port))
		ret = ssb_write(qid, pix, GPE_PDU_TYPE_ETH, len, pkt);

	return ret;
}

int net_pdu_read(const struct onu_pdu_info *info, uint8_t *data)
{
	return ssb_egress_data_read(info, data);
}

int net_egress_cpu_port_get(const uint8_t netdev_port)
{
	switch (netdev_port) {
	case ONU_NET_NETDEV_WAN_PORT:
		return 0;
	case ONU_NET_NETDEV_LAN0_PORT:
	case ONU_NET_NETDEV_LAN1_PORT:
	case ONU_NET_NETDEV_LAN2_PORT:
	case ONU_NET_NETDEV_LAN3_PORT:
		return 1;
	case ONU_NET_NETDEV_EXC_PORT:
		return 2;
	default:
		return -1;
	}
}

int net_port_get(const uint8_t uni)
{
	int port = 0;

	if (uni >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	switch (uni) {
	case 0:
		port = ONU_NET_NETDEV_LAN0_PORT;
		break;
	case 1:
		port = ONU_NET_NETDEV_LAN1_PORT;
		break;
	case 2:
		port = ONU_NET_NETDEV_LAN2_PORT;
		break;
	case 3:
		port = ONU_NET_NETDEV_LAN3_PORT;
		break;
	}

	return port;
}

int net_uni_get(const uint8_t netdev_port)
{
	switch (netdev_port) {
	case ONU_NET_NETDEV_LAN0_PORT:
		return 0;
	case ONU_NET_NETDEV_LAN1_PORT:
		return 1;
	case ONU_NET_NETDEV_LAN2_PORT:
		return 2;
	case ONU_NET_NETDEV_LAN3_PORT:
		return 3;
	default:
		return -1;
	}
}

int net_rx_enable(const uint8_t netdev_port, const bool enable)
{
	int egress_cpu_port;

	if (!onu_is_initialized())
		return -1;

	if (!sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET))
		return -1;

	egress_cpu_port = net_egress_cpu_port_get(netdev_port);
	if (egress_cpu_port < 0)
		return -1;

	if (enable)
		tmu_interrupt_enable_set(0, TMU_IRNEN_EPFC0 << egress_cpu_port);
	else
		tmu_interrupt_enable_set(TMU_IRNEN_EPFC0 << egress_cpu_port, 0);

	return 0;
}

int net_cb_list_register(const uint8_t netdev_port, struct net_cb *list)
{
	if (netdev_port >= ONU_NET_MAX_NETDEV_PORT)
		return -1;
	memcpy(	&(onu_control[0].net_cb_list[netdev_port]),
		list, sizeof(struct net_cb));
	return 0;
}

int net_dev_register(struct net_dev *dev)
{
	memcpy(	&(onu_control[0].net_dev), dev, sizeof(struct net_dev));
	return 0;
}

int net_lan_mac_set(const uint8_t *mac)
{
	if (!onu_is_initialized())
		return -1;

	return (int)gpe_sce_constant_mac_set(&onu_control[0], mac);
}

uint8_t net_lan_max_port_get(void)
{
	struct gpe_capability cap;

	if (gpe_device_capability_get(&cap) != ONU_STATUS_OK)
		return 0;
	else
		return cap.max_eth_uni;
}

const struct onu_entry lan_function_table[] = {
	TE0(FIO_LAN_INIT, lan_init),

	TE1in(FIO_LAN_CFG_SET,
		sizeof(struct lan_cfg),
		lan_cfg_set),
	TE1out(FIO_LAN_CFG_GET,
		sizeof(struct lan_cfg),
		lan_cfg_get),

	TE1in(FIO_LAN_PORT_CFG_SET,
		sizeof(struct lan_port_cfg),
		lan_port_cfg_set),
	TE2(FIO_LAN_PORT_CFG_GET,
		sizeof(struct lan_port_index),
		sizeof(struct lan_port_cfg),
		lan_port_cfg_get),

	TE1in(FIO_LAN_PORT_ENABLE,
		sizeof(struct lan_port_index),
		lan_port_enable),
	TE1in(FIO_LAN_PORT_DISABLE,
		sizeof(struct lan_port_index),
		lan_port_disable),

	TE1in(FIO_LAN_LOOP_CFG_SET,
		sizeof(struct lan_loop_cfg),
		lan_loop_cfg_set),
	TE2(FIO_LAN_LOOP_CFG_GET,
		sizeof(struct lan_port_index),
		sizeof(struct lan_loop_cfg),
		lan_loop_cfg_get),

	TE2(FIO_LAN_PORT_STATUS_GET,
		sizeof(struct lan_port_index),
		sizeof(struct lan_port_status),
		lan_port_status_get),

	TE2(FIO_LAN_COUNTER_GET,
		sizeof(struct lan_cnt_interval),
		sizeof(struct lan_counters),
		lan_counter_get),
	TE1in(FIO_LAN_COUNTER_RESET,
		sizeof(struct lan_cnt_interval),
		lan_counter_reset),
	TE1in(FIO_LAN_COUNTER_THRESHOLD_SET,
		sizeof(struct lan_cnt_threshold),
		lan_counter_threshold_set),
	TE2(FIO_LAN_COUNTER_THRESHOLD_GET,
		sizeof(struct lan_port_index),
		sizeof(struct lan_cnt_threshold),
		lan_counter_threshold_get),
	TE2(FIO_LAN_TCA_GET,
		sizeof(struct uni_port_id),
		sizeof(struct lan_cnt_val),
		lan_tca_get),

	TE1in(FIO_WOL_CFG_SET,
		sizeof(struct wol_cfg),
		wol_cfg_set),
	TE2(FIO_WOL_CFG_GET,
		sizeof(struct lan_port_index),
		sizeof(struct wol_cfg),
		wol_cfg_get),
	TE2(FIO_WOL_STATUS_GET,
		sizeof(struct lan_port_index),
		sizeof(struct wol_status),
		wol_status_get),

	TE2(FIO_MDIO_DATA_READ,
		sizeof(struct mdio),
		sizeof(struct mdio_read),
		mdio_data_read),
	TE1in(FIO_MDIO_DATA_WRITE,
		sizeof(struct mdio_write),
		mdio_data_write),

	TE1in(FIO_MDIO_ENABLE,
		sizeof(struct mdio_en),
		mdio_enable),
	TE1in(FIO_MDIO_DISABLE,
		sizeof(struct mdio_dis),
		mdio_disable),

	TE1in_opt(FIO_LAN_GPHY_FIRMWARE_DOWNLOAD,
		sizeof(struct lan_gphy_fw),
		lan_gphy_firmware_download),

	TE2(FIO_MMD_DATA_READ,
		sizeof(struct mmd),
		sizeof(struct mmd_read),
		mmd_data_read),
	TE1in(FIO_MMD_DATA_WRITE,
		sizeof(struct mmd_write),
		mmd_data_write),

	TE1in(FIO_LAN_PORT_CAPABILITY_CFG_SET,
		sizeof(struct lan_port_capability_cfg),
		lan_port_capability_cfg_set),
	TE2(FIO_LAN_PORT_CAPABILITY_CFG_GET,
		sizeof(struct lan_port_index),
		sizeof(struct lan_port_capability_cfg),
		lan_port_capability_cfg_get),

};

const unsigned int lan_function_table_size = ARRAY_SIZE(lan_function_table);

/*! @} */

/*! @} */
