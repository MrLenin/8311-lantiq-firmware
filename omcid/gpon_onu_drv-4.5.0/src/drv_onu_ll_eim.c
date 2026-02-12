/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_lan_api.h"
#include "drv_onu_register.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_ll_eim.h"

/* time to wait for disabling phy auto-polling */
#define AUTOPOLL_DISABLE_TIME 20

/* The eim_mdio_data_read function provides read access to an external or
   internal Ethernet PHY.
*/
/** Hardware Programming Details
   Parameter list:
   - addr_dev: selected device address
   - addr_reg: selected register address
   - data      : read data

   Trigger a read access by writing to the MDIO control register (MAC_HEADER):
   MAC_HEADER.TA = 00
   MAC_HEADER.REGADR   = addr_dev
   MAC_HEADER.PHYAD    = addr_reg
   MAC_HEADER.OP       = 10           - this is a read access
   MAC_HEADER.ST       = 01           - always the same
   MAC_HEADER.RW       =  1           - this is a read access
   MAC_HEADER.START_TX =  1           - start the access

   Wait until the data word is available:
   while(ISTAT.INT_MAC == 0) {};

   Read the received 16-bit data word:
   data = MAC_DATA.DATA[15:0]
*/
int eim_mdio_data_read(const uint8_t addr_dev, const uint8_t addr_reg,
		       uint16_t *data)
{
	uint32_t cnt;
	if (is_falcon_chip_a1x()) {

		uint32_t cfg = EIM_MAC_HEADER_RW_READ | EIM_MAC_HEADER_START_TX;
		uint32_t val;

		set_val(cfg, 1, EIM_MAC_HEADER_ST_MASK, EIM_MAC_HEADER_ST_OFFSET);
		set_val(cfg, 2, EIM_MAC_HEADER_OP_MASK, EIM_MAC_HEADER_OP_OFFSET);
		set_val(cfg, addr_dev, EIM_MAC_HEADER_PHYAD_MASK,
			EIM_MAC_HEADER_PHYAD_OFFSET);
		set_val(cfg, addr_reg, EIM_MAC_HEADER_REGAD_MASK,
			EIM_MAC_HEADER_REGAD_OFFSET);

		cnt = 100;
		eim_a1x_w32(EIM_ISTAT_INT_MAC, mdio_mac_pdi.istat);
		while (cnt
		       && ((eim_a1x_r32(mdio_mac_pdi.istat) & EIM_ISTAT_INT_MAC) ==
			   EIM_ISTAT_INT_MAC)) {
			cnt--;
			onu_udelay(10);
		}
		if (cnt == 0)
			return -1;

		cnt = 100;
		eim_a1x_w32(cfg, mdio_mac_pdi.mac_header);
		while (cnt && ((eim_a1x_r32(mdio_mac_pdi.istat) &
				EIM_ISTAT_INT_MAC) == 0)) {
			cnt--;
			onu_udelay(10);
		}
		if (cnt == 0)
			return -2;

		/* *data = (eim_a1x_r32(mdio_mac_pdi.mac_data) & EIM_MAC_DATA_DATA_MASK); */
		val = eim_a1x_r32(mdio_mac_pdi.startup);
		if ((addr_dev != get_val(val, EIM_STARTUP_PRTAD_MASK,
						EIM_STARTUP_PRTAD_OFFSET)) ||
			(addr_reg != get_val(val, EIM_STARTUP_DEVAD_MASK,
						EIM_STARTUP_DEVAD_OFFSET)) ) {
			ONU_DEBUG_ERR("MDIO Bus Error: sent %X/%X, read %X/%X",
				addr_dev, addr_reg,
				get_val(val, EIM_STARTUP_PRTAD_MASK,
					EIM_STARTUP_PRTAD_OFFSET),
				get_val(val, EIM_STARTUP_DEVAD_MASK,
					EIM_STARTUP_DEVAD_OFFSET) );
		}
		*data = get_val(val, EIM_STARTUP_DATA_MASK, EIM_STARTUP_DATA_OFFSET);
	} else if (is_falcon_chip_a2x()) {
		cnt = 100;
		while (cnt && eim_a2x_r32(mdio_pdi.mdio_ctrl) & EIM_MDIO_CTRL_MBUSY) {
			cnt--;
			onu_udelay(10);
		}
		if (cnt == 0)
			return -1;
		eim_a2x_w32(EIM_MDIO_CTRL_OP_RD | EIM_MDIO_CTRL_MBUSY_BUSY |
			((addr_dev << EIM_MDIO_CTRL_PHYAD_OFFSET) & EIM_MDIO_CTRL_PHYAD_MASK) |
			((addr_reg << EIM_MDIO_CTRL_REGAD_OFFSET) & EIM_MDIO_CTRL_REGAD_MASK),
			mdio_pdi.mdio_ctrl);
		cnt = 100;
		while (cnt && eim_a2x_r32(mdio_pdi.mdio_ctrl) & EIM_MDIO_CTRL_MBUSY) {
			cnt--;
    			onu_udelay(10);
		}
		if (cnt == 0)
			return -1;

		*data = eim_a2x_r32(mdio_pdi.mdio_read) & EIM_MDIO_READ_RDATA_MASK;
	} else
		return -1;
	return 0;
}

/**
   Write MDIO register.
*/
int eim_mdio_data_write(const uint8_t addr_dev, const uint8_t addr_reg,
			const uint16_t data)
{
	uint32_t cnt;
	if (is_falcon_chip_a1x()) {
		uint32_t cfg = EIM_MAC_HEADER_START_TX;
		uint32_t val;

		set_val(cfg, 1, EIM_MAC_HEADER_ST_MASK, EIM_MAC_HEADER_ST_OFFSET);
		set_val(cfg, 1, EIM_MAC_HEADER_OP_MASK, EIM_MAC_HEADER_OP_OFFSET);
		set_val(cfg, addr_dev, EIM_MAC_HEADER_PHYAD_MASK,
			EIM_MAC_HEADER_PHYAD_OFFSET);
		set_val(cfg, addr_reg, EIM_MAC_HEADER_REGAD_MASK,
			EIM_MAC_HEADER_REGAD_OFFSET);

		eim_a1x_w32(data, mdio_mac_pdi.mac_data);
		/*eim_a1x_w32(data, mdio_mac_pdi.startup); */

		cnt = 100;
		eim_a1x_w32(EIM_ISTAT_INT_MAC, mdio_mac_pdi.istat);
		while (cnt
		       && ((eim_a1x_r32(mdio_mac_pdi.istat) & EIM_ISTAT_INT_MAC) ==
			   EIM_ISTAT_INT_MAC)) {
			cnt--;
			onu_udelay(10);
		}
		if (cnt == 0)
			return -1;

		eim_a1x_w32(cfg, mdio_mac_pdi.mac_header);
		while (cnt && ((eim_a1x_r32(mdio_mac_pdi.istat) &
				EIM_ISTAT_INT_MAC) == 0)) {
			cnt--;
			onu_udelay(10);
		}
		if (cnt == 0)
			return -2;

		val = eim_a1x_r32(mdio_mac_pdi.startup);
		if ((addr_dev != get_val(val, EIM_STARTUP_PRTAD_MASK,
						EIM_STARTUP_PRTAD_OFFSET)) ||
			(addr_reg != get_val(val, EIM_STARTUP_DEVAD_MASK,
						EIM_STARTUP_DEVAD_OFFSET)) ) {
			ONU_DEBUG_ERR("MDIO Bus Error: sent %X/%X, read %X/%X",
				addr_dev, addr_reg,
				get_val(val, EIM_STARTUP_PRTAD_MASK,
					EIM_STARTUP_PRTAD_OFFSET),
				get_val(val, EIM_STARTUP_DEVAD_MASK,
					EIM_STARTUP_DEVAD_OFFSET) );
		}
	} else if (is_falcon_chip_a2x()) {
		cnt = 100;
		while (cnt && eim_a2x_r32(mdio_pdi.mdio_ctrl) & EIM_MDIO_CTRL_MBUSY) {
			cnt--;
			onu_udelay(10);
		}
		if (cnt == 0)
			return -1;
		eim_a2x_w32(data & EIM_MDIO_WRITE_WDATA_MASK, mdio_pdi.mdio_write);
		eim_a2x_w32(EIM_MDIO_CTRL_OP_WR | EIM_MDIO_CTRL_MBUSY_BUSY |
			((addr_dev << EIM_MDIO_CTRL_PHYAD_OFFSET) & EIM_MDIO_CTRL_PHYAD_MASK) |
			((addr_reg << EIM_MDIO_CTRL_REGAD_OFFSET) & EIM_MDIO_CTRL_REGAD_MASK),
			mdio_pdi.mdio_ctrl);
		cnt = 100;
		while (cnt && eim_a2x_r32(mdio_pdi.mdio_ctrl) & EIM_MDIO_CTRL_MBUSY) {
			cnt--;
    			onu_udelay(10);
		}
		if (cnt == 0)
			return -1;
	} else
		return -1;

	return 0;
}

/* the phy_id is matching the first 4 gmac_mux_mode values! */
void eim_gphy_cfg_addr_set(const uint8_t phy_id, const uint8_t phy_addr)
{
	static const uint32_t mask[] = {EIM_GPHY_CFG_ADDR_PHYADR1_MASK,
					EIM_GPHY_CFG_ADDR_PHYADR2_MASK,
					EIM_GPHY_CFG_ADDR_PHYADR1_MASK,
					EIM_GPHY_CFG_ADDR_PHYADR2_MASK};
	static const uint8_t offset[] = {EIM_GPHY_CFG_ADDR_PHYADR1_OFFSET,
					EIM_GPHY_CFG_ADDR_PHYADR2_OFFSET,
					EIM_GPHY_CFG_ADDR_PHYADR1_OFFSET,
					EIM_GPHY_CFG_ADDR_PHYADR2_OFFSET};

	if (phy_id >= 4)
		return;
	eim_w32_mask (mask[phy_id],
			phy_addr << offset[phy_id],
			top_pdi.gphy_cfg_addr[phy_id >> 1]);
}

uint8_t eim_gphy_cfg_addr_get(const uint8_t phy_id)
{
	static const uint8_t offset[] = {EIM_GPHY_CFG_ADDR_PHYADR1_OFFSET,
					EIM_GPHY_CFG_ADDR_PHYADR2_OFFSET,
					EIM_GPHY_CFG_ADDR_PHYADR1_OFFSET,
					EIM_GPHY_CFG_ADDR_PHYADR2_OFFSET};
	if (phy_id >= 4)
		return (uint8_t)ONU_LAN_MDIO_ADDR_NULL;

	return (uint8_t)((eim_r32(top_pdi.gphy_cfg_addr[phy_id >> 1]) >>
			offset[phy_id]) & EIM_GPHY_CFG_ADDR_PHYADR1_MASK);
}

void eim_phy_addr_set(const uint8_t uni_port_id, const uint8_t phy_addr)
{
#ifdef CONFIG_WITH_FALCON_A2X
	if (is_falcon_chip_a2x()) {
		eim_a2x_w32_mask(EIM_PHY_ADDR_ADDR_MASK, phy_addr,
			mdio_pdi.phy_addr[uni_port_id]);
	}
#endif
}

int eim_phy_autopoll_enable_set(const uint8_t uni_port_id, const bool enable)
{
#ifdef CONFIG_WITH_FALCON_A2X
	uint32_t cfg;

	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	if (is_falcon_chip_a2x()) {
		cfg = EIM_MDC_CFG_0_PEN_0 << uni_port_id;
		eim_a2x_w32_mask(cfg, enable ? cfg : 0, mdio_pdi.mdc_cfg_0);
	}
#endif
	return 0;
}

int eim_phy_autopoll_enable_get(const uint8_t uni_port_id, bool *enable)
{
#ifdef CONFIG_WITH_FALCON_A2X
	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	if (is_falcon_chip_a2x()) {
		*enable = eim_a2x_r32(mdio_pdi.mdc_cfg_0) &
			(EIM_MDC_CFG_0_PEN_0<< uni_port_id) ? true : false;
		return 0;
	} else
		return -1;
#else
	return -1;
#endif
}

#ifdef CONFIG_WITH_FALCON_A2X
int eim_phy_autopoll_force_current(const uint8_t phy_addr, uint8_t *port_id,
							   uint32_t *restore)
{
	uint8_t id;
	uint32_t mdio_stat_reg, phy_addr_reg;

	if (!is_falcon_chip_a2x() || !port_id || !restore)
		return -1;

	for (id=0; id < ONU_GPE_MAX_ETH_UNI; id++) {
		/* check if polling is active */
		if (!(eim_a2x_r32(mdio_pdi.mdc_cfg_0) & (EIM_MDC_CFG_0_PEN_0 << id)))
			continue;
		phy_addr_reg = eim_a2x_r32(mdio_pdi.phy_addr[id]);
		/* check for address to be polled */
		if ((phy_addr_reg & EIM_PHY_ADDR_ADDR_MASK) != phy_addr)
			continue;
		*port_id = id;
		*restore = phy_addr_reg;
		mdio_stat_reg = eim_a2x_r32(mdio_pdi.mdio_stat[id]);
		/* PHY active Status */
		if ( (mdio_stat_reg & EIM_MDIO_STAT_PACT) ==
				      EIM_MDIO_STAT_PACT_ACTIVE) {
			unsigned temp=0;
			/* Link Status */
			if ( (mdio_stat_reg & EIM_MDIO_STAT_LSTAT) ==
					      EIM_MDIO_STAT_LSTAT_UP) {
				phy_addr_reg &= EIM_PHY_ADDR_ADDR_MASK;
				phy_addr_reg |= EIM_PHY_ADDR_LNKST_UP;
				temp = ( (mdio_stat_reg & EIM_MDIO_STAT_SPEED_MASK) 
						>> EIM_MDIO_STAT_SPEED_OFFSET);
				phy_addr_reg |= (temp << EIM_PHY_ADDR_SPEED_OFFSET)
						& EIM_PHY_ADDR_SPEED_MASK;
				if ((mdio_stat_reg & EIM_MDIO_STAT_FDUP) ==
						     EIM_MDIO_STAT_FDUP_FULL)
					phy_addr_reg |= EIM_PHY_ADDR_FDUP_EN;
				else 
					phy_addr_reg |= EIM_PHY_ADDR_FDUP_DIS;
				if ((mdio_stat_reg & EIM_MDIO_STAT_RXPAUEN) ==
						     EIM_MDIO_STAT_RXPAUEN_EN)
					phy_addr_reg |= EIM_PHY_ADDR_FCONRX_EN;
				else
					phy_addr_reg |= EIM_PHY_ADDR_FCONRX_DIS;
				if ((mdio_stat_reg & EIM_MDIO_STAT_TXPAUEN) ==
						     EIM_MDIO_STAT_TXPAUEN_EN)
					phy_addr_reg |= EIM_PHY_ADDR_FCONTX_EN;
				else
					phy_addr_reg |= EIM_PHY_ADDR_FCONTX_DIS;
				eim_a2x_w32(phy_addr_reg, mdio_pdi.phy_addr[id]);
			}
		}
		/* disable auto-polling */
		eim_a2x_w32_mask(EIM_MDC_CFG_0_PEN_0 << id, 0, mdio_pdi.mdc_cfg_0);
		onu_udelay(AUTOPOLL_DISABLE_TIME);
		return 0;
	}
	return -1;
}

void eim_phy_autopoll_restore_settings(uint8_t port_id, uint32_t restore)
{
	if (is_falcon_chip_a2x()) {
		/* enable auto-polling */
		eim_a2x_w32_mask(0, EIM_MDC_CFG_0_PEN_0 << port_id,
			mdio_pdi.mdc_cfg_0);
		eim_a2x_w32(restore, mdio_pdi.phy_addr[port_id]);
	}
}

int eim_phy_autopoll_status_get(uint8_t port_id, uint32_t *mdio_stat)
{
	if (port_id >= ONU_GPE_MAX_ETH_UNI || !mdio_stat)
		return -1;

	*mdio_stat = eim_a2x_r32(mdio_pdi.mdio_stat[port_id]);
	return 0;
}
#endif /* CONFIG_WITH_FALCON_A2X */

int eim_short_preamble_enable_set(const uint8_t uni_port_id, const bool enable)
{
	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	eim_w32_mask(EIM_MAC_CTRL_1_SHORTPRE,
		     enable ? 1 : 0,
		     mac_pdi[uni_port_id].ctrl_1);
	return 0;
}

int eim_short_preamble_enable_get(const uint8_t uni_port_id, bool *enable)
{
	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	*enable = eim_r32(mac_pdi[uni_port_id].ctrl_1) &
			  EIM_MAC_CTRL_1_SHORTPRE ? true : false;

	return 0;
}

int eim_flow_ctrl_set(const uint8_t port_id,
		      const enum lan_mode_flow_control mode)
{
	uint32_t cfg;

	if (port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	if (is_falcon_chip_a1x()) {
		switch (mode) {
		case LAN_FLOW_CONTROL_MODE_AUTO:
			cfg = EIM_MAC_CTRL_0_FCON_AUTO;
			break;
		case LAN_FLOW_CONTROL_MODE_RX:
			cfg = EIM_MAC_CTRL_0_FCON_RX;
			break;
		case LAN_FLOW_CONTROL_MODE_TX:
			cfg = EIM_MAC_CTRL_0_FCON_TX;
			break;
		case LAN_FLOW_CONTROL_MODE_RXTX:
			cfg = EIM_MAC_CTRL_0_FCON_RXTX;
			break;
		case LAN_FLOW_CONTROL_MODE_NONE:
			cfg = EIM_MAC_CTRL_0_FCON_NONE;
			break;
		default:
			return -1;
		}

		eim_w32_mask(EIM_MAC_CTRL_0_FCON_MASK, cfg, mac_pdi[port_id].ctrl_0);
	}

	if (is_falcon_chip_a2x()) {
		switch (mode) {
		case LAN_FLOW_CONTROL_MODE_AUTO:
			cfg = EIM_PHY_ADDR_FCONTX_AUTO | EIM_PHY_ADDR_FCONRX_AUTO;
			break;
		case LAN_FLOW_CONTROL_MODE_RX:
			cfg = EIM_PHY_ADDR_FCONTX_DIS | EIM_PHY_ADDR_FCONRX_EN;
			break;
		case LAN_FLOW_CONTROL_MODE_TX:
			cfg = EIM_PHY_ADDR_FCONTX_EN | EIM_PHY_ADDR_FCONRX_DIS;
			break;
		case LAN_FLOW_CONTROL_MODE_RXTX:
			cfg = EIM_PHY_ADDR_FCONTX_EN | EIM_PHY_ADDR_FCONRX_EN;
			break;
		case LAN_FLOW_CONTROL_MODE_NONE:
			cfg = EIM_PHY_ADDR_FCONTX_DIS | EIM_PHY_ADDR_FCONRX_DIS;
			break;
		default:
			return -1;
		}
		eim_a2x_w32_mask(EIM_PHY_ADDR_FCONTX_MASK |
				 EIM_PHY_ADDR_FCONRX_MASK,
				 cfg,
				 mdio_pdi.phy_addr[port_id]);
	}

	return 0;
}

int eim_duplex_mode_set(const uint8_t port_id, const enum lan_mode_duplex mode)
{
	uint32_t cfg;

	if (port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	if (is_falcon_chip_a1x()) {
		switch (mode) {
		case LAN_PHY_MODE_DUPLEX_AUTO:
			cfg = EIM_MAC_CTRL_0_FDUP_AUTO;
			break;
		case LAN_PHY_MODE_DUPLEX_FULL:
			cfg = EIM_MAC_CTRL_0_FDUP_EN;
			break;
		case LAN_PHY_MODE_DUPLEX_HALF:
			cfg = EIM_MAC_CTRL_0_FDUP_DIS;
			break;
		default:
			return -1;
		}
		eim_w32_mask(EIM_MAC_CTRL_0_FDUP_MASK, cfg, mac_pdi[port_id].ctrl_0);
	}

	if (is_falcon_chip_a2x()) {
		switch (mode) {
		case LAN_PHY_MODE_DUPLEX_AUTO:
			cfg = EIM_PHY_ADDR_FDUP_AUTO;
			break;
		case LAN_PHY_MODE_DUPLEX_FULL:
			cfg = EIM_PHY_ADDR_FDUP_EN;
			break;
		case LAN_PHY_MODE_DUPLEX_HALF:
			cfg = EIM_PHY_ADDR_FDUP_DIS;
			break;
		default:
			return -1;
		}
		eim_a2x_w32_mask(EIM_PHY_ADDR_FDUP_MASK, cfg,
				mdio_pdi.phy_addr[port_id]);
	}
	return 0;
}

void eim_duplex_mode_get(const uint8_t port_id, enum lan_mode_duplex *mode)
{
	uint32_t reg;

	reg = eim_r32(mac_pdi[port_id & 0x3].pstat);

	*mode = reg & EIM_MAC_PSTAT_FDUP_FULL ? LAN_PHY_MODE_DUPLEX_FULL:
						LAN_PHY_MODE_DUPLEX_HALF;
}

int eim_speed_mode_set(const uint8_t port_id, const enum lan_mode_speed mode)
{
	uint32_t cfg;

	if (port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	if (is_falcon_chip_a2x()) {
		switch (mode) {
		case LAN_MODE_SPEED_AUTO:
			cfg  = EIM_PHY_ADDR_SPEED_AUTO;
			break;
		case LAN_MODE_SPEED_10:
			cfg = EIM_PHY_ADDR_SPEED_M10;
			break;
		case LAN_MODE_SPEED_100:
			cfg = EIM_PHY_ADDR_SPEED_M100;
			break;
		case LAN_MODE_SPEED_1000:
			cfg = EIM_PHY_ADDR_SPEED_G1;
			break;
		case LAN_MODE_SPEED_200:
		case LAN_MODE_SPEED_2500:
			/* ignore without non-error */
			return 0;
		default:
			return -1;
		}
		eim_a2x_w32_mask(EIM_PHY_ADDR_SPEED_MASK, cfg,
				mdio_pdi.phy_addr[port_id]);
	}
	return 0;
}


int eim_fcs_enable(const uint8_t port_id, const bool enable)
{
	if (port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	eim_w32_mask(EIM_MAC_CTRL_0_FCS,
		     enable ? EIM_MAC_CTRL_0_FCS_EN : 0,
		     mac_pdi[port_id].ctrl_0);
	return 0;
}

int eim_gmii_mode_set(const uint8_t port_id, const enum eim_gmii_mode mode)
{
	uint32_t val = 0;

	if (port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	set_val(val, (uint32_t)mode,
		EIM_MAC_CTRL_0_GMII_MASK, EIM_MAC_CTRL_0_GMII_OFFSET);

	eim_w32_mask(EIM_MAC_CTRL_0_GMII_MASK, val, mac_pdi[port_id].ctrl_0);

	return 0;
}

int eim_gmii_mode_get(const uint8_t port_id, enum eim_gmii_mode *mode)
{
	uint32_t val = 0;

	if (port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	val = eim_r32(mac_pdi[port_id].ctrl_0);
	val = ((val >> EIM_MAC_CTRL_0_GMII_OFFSET) & EIM_MAC_CTRL_0_GMII_MASK);

	*mode = (enum eim_gmii_mode)val;

	return 0;
}

void eim_xmii_enable(const uint8_t xmii_idx, const bool enable)
{
	eim_w32_mask(EIM_MII_CFG_EN, enable ? EIM_MII_CFG_EN : 0,
		     mii_pdi[xmii_idx & 0x1].mii_cfg);
}

void eim_xmii_reset(const uint8_t xmii_idx, const bool on)
{
	eim_w32_mask(EIM_MII_CFG_RES, on ? EIM_MII_CFG_RES_ON : 0,
		     mii_pdi[xmii_idx & 0x1].mii_cfg);
}

void eim_xmii_mode_set(const uint8_t xmii_idx, const enum eim_xmii_mode mode)
{
	eim_w32_mask(EIM_MII_CFG_MIIMODE_MASK, (uint32_t)mode,
		     mii_pdi[xmii_idx & 0x1].mii_cfg);
}

void eim_xmii_jitter_buf_enable(const uint8_t xmii_idx, const bool rxb,
				const bool txb)
{
	eim_w32_mask(EIM_BUFF_RXB_EN, rxb ? EIM_BUFF_RXB_EN : 0,
		     mii_pdi[xmii_idx & 0x1].buff);
	eim_w32_mask(EIM_BUFF_TXB_EN, txb ? EIM_BUFF_TXB_EN : 0,
		     mii_pdi[xmii_idx & 0x1].buff);
}

void eim_xmii_clk_rate_set(const uint8_t xmii_idx,
			   const enum eim_xmii_clk_rate val)
{
	eim_w32_mask(EIM_MII_CFG_MIIRATE_MASK,
		     (uint32_t)(val << EIM_MII_CFG_MIIRATE_OFFSET),
		     mii_pdi[xmii_idx & 0x1].mii_cfg);
}

void eim_xmii_clk_dly_set(const uint8_t xmii_idx, const uint8_t tx_dly,
			  const uint8_t rx_dly)
{
	eim_w32_mask(EIM_PCDU_TXDLY_MASK,
		     (tx_dly << EIM_PCDU_TXDLY_OFFSET) & EIM_PCDU_TXDLY_MASK,
		     mii_pdi[xmii_idx & 0x1].pcdu);
	eim_w32_mask(EIM_PCDU_RXDLY_MASK,
		     (rx_dly << EIM_PCDU_RXDLY_OFFSET) & EIM_PCDU_RXDLY_MASK,
		     mii_pdi[xmii_idx & 0x1].pcdu);
}

void eim_mac_loop_enable(const uint8_t port_id, const bool en)
{
	eim_w32_mask(EIM_MAC_TESTEN_LOOP, en ? EIM_MAC_TESTEN_LOOP_EN : 0,
		     mac_pdi[port_id & 0x3].testen);
}

void eim_mii_loop_enable(const uint8_t xmii_idx, const bool en)
{
	eim_w32_mask(EIM_MII_CFG_LPBK, en ? EIM_MII_CFG_LPBK_EN: 0,
		     mii_pdi[xmii_idx & 0x1].mii_cfg);
}

void eim_sgmii_loop_enable(const bool en)
{
	sxgmii_w32_mask(CFG_LPB, en ? CFG_LPB_LOOP : 0, s_sgmii_pcs_pdi_cfg);
}

void eim_central_interrupt_enable_set(const uint32_t clear, const uint32_t set)
{
	eim_w32_mask(clear, set, top_pdi.eim_ier);
}

uint32_t eim_central_interrupt_enable_get(void)
{
	return eim_r32(top_pdi.eim_ier);
}

void eim_mac_cnt_get(const uint8_t idx, struct mac_counter *cnt)
{
	const uint8_t port = idx & 0x3;

	memset(cnt, 0x0, sizeof(struct mac_counter));

	cnt->rx_fcs_err = (uint64_t)eim_r32(top_pdi.eim_mib_fcser[port]);
	cnt->tx_jabber_frames = (uint64_t)eim_r32(top_pdi.eim_mib_ovsz[port]);
	cnt->algn_err = (uint64_t)eim_r32(top_pdi.eim_mib_algn[port]);
	cnt->late_col = (uint64_t)eim_r32(top_pdi.eim_mib_late_col[port]);
	cnt->exc_col = (uint64_t)eim_r32(top_pdi.eim_mib_exc_col[port]);
	cnt->sgl_col = (uint64_t)eim_r32(top_pdi.eim_mib_sgl_col[port]);
	cnt->mul_col = (uint64_t)eim_r32(top_pdi.eim_mib_mul_col[port]);
	cnt->def_trans = (uint64_t)eim_r32(top_pdi.eim_mib_def_trans[port]);
}

void eim_mac_lpi_enable(const uint8_t port_id, const bool en)
{
	eim_w32_mask(EIM_MAC_CTRL_4_LPIEN, en ? EIM_MAC_CTRL_4_LPIEN : 0,
		     mac_pdi[port_id & 0x3].ctrl_4);
}

void eim_mac_frame_length_set(const uint16_t val)
{
	eim_w32(val & EIM_MAC_FLEN_LEN_MASK, macs_top_pdi.mac_flen);
}

uint16_t eim_mac_frame_length_get(void)
{
	return eim_r32(macs_top_pdi.mac_flen) & EIM_MAC_FLEN_LEN_MASK;
}

void eim_mac_err_status_get(const uint8_t port_id, bool *toolong, bool *ig_ovfl)
{
	*toolong = (eim_r32(mac_pdi[port_id].pisr) & EIM_MAC_PISR_TOOLONG) == 0 ? false : true;
	if (is_falcon_chip_a1x())
		*ig_ovfl = (eim_r32(top_pdi.eim_isr) &
			(EIM_EIM_IER_A1X_LAN_IG_OVFL_0 << port_id)) == 0 ?
			false : true;
	else
		*ig_ovfl = (eim_r32(top_pdi.eim_isr) &
			(EIM_EIM_IER_A2X_LAN_IG_OVFL_0 << port_id)) == 0 ?
			false : true;
	eim_w32_mask (EIM_MAC_PISR_TOOLONG, 0, mac_pdi[port_id].pisr);
	eim_w32_mask ((EIM_EIM_IER_A2X_LAN_IG_OVFL_0 << port_id), 0, top_pdi.eim_isr);
}

#if defined(INCLUDE_DUMP)

const char *vsc8201_mdio_reg_name[32] = {
/* 00 */	"Mode Control",
/* 01 */	"Mode Status",
/* 02 */	"Ident 1",
/* 03 */	"Ident 2",
/* 04 */	"Autonegotiation Advertisement",
/* 05 */	"Autonegotiation Link Partner Availibility",
/* 06 */	"Autonegotiation Expansion",
/* 07 */	"Autonegotiation Next-Page Transmit",
/* 08 */	"Autonegotiation Link Partner Next Page",
/* 09 */	"1000BASE-T Control",
/* 0A */	"1000BASE-T Status",
/* 0B */	"",
/* 0C */	"",
/* 0D */	"MMD Access Control Register",
/* 0E */	"MMD Access Data Register",
/* 0F */	"1000BASE-T Status Extension #1",
/* 10 */	"Physical Layer Performance Status",
/* 11 */	"Physical Layer Status 1",
/* 12 */	"Physical Layer Status 2",
/* 13 */	"Physical Layer Control 1",
/* 14 */	"Physical Layer Control 2",
/* 15 */	"Error Counter",
/* 16 */	"EEPROM Control Register",
/* 17 */	"Media-Independent Interface Control",
/* 18 */	"Media-Independent Interface Status",
/* 19 */	"Interrupt Mask",
/* 1A */	"Interrupt Status",
/* 1B */	"Parallel LED Control",
/* 1C */	"Test-Packet Generator Control",
/* 1D */	"Test-Packet Generator Data",
/* 1E */	"Firmware Version Register",
/* 1F */	""
};

void eim_dump(struct seq_file *s)
{
	uint32_t i, m;
	uint16_t data;

	seq_printf(s, "     ier,     isr\n");
	seq_printf(s, "%08x,", eim_r32(top_pdi.eim_ier));
	seq_printf(s, "%08x\n", eim_r32(top_pdi.eim_isr));
	seq_printf(s, "     mac,   pstat,    pisr,   ctrl0,   ctrl1"
			      ",   ctrl2,   ctrl3,   ctrl4,   ctrl5%s\n",
		   is_falcon_chip_a1x()?",   ctrl6":"");
	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		seq_printf(s, "%08x,", i);
		seq_printf(s, "%08x,",
			   (unsigned int)(is_falcon_chip_a1x() ?
				&eim->a1x.mac_pdi[i].pstat:
				&eim->a2x.mac_pdi[i].pstat));
		seq_printf(s, "%08x,",
			   (unsigned int)(is_falcon_chip_a1x() ?
				&eim->a1x.mac_pdi[i].pisr:
				&eim->a2x.mac_pdi[i].pisr));
		seq_printf(s, "%08x,", eim_r32(mac_pdi[i].ctrl_0));
		seq_printf(s, "%08x,", eim_r32(mac_pdi[i].ctrl_1));
		seq_printf(s, "%08x,", eim_r32(mac_pdi[i].ctrl_2));
		seq_printf(s, "%08x,", eim_r32(mac_pdi[i].ctrl_3));
		seq_printf(s, "%08x,", eim_r32(mac_pdi[i].ctrl_4));
		seq_printf(s, "%08x,", eim_r32(mac_pdi[i].ctrl_5));
		if (is_falcon_chip_a1x())
			seq_printf(s, "%08x", eim_a1x_r32(mac_pdi[i].ctrl_6));
		seq_printf(s, "\n");
	}
	for (m = 0; m <= 31; m++) {
		if (eim_mdio_data_read(m, i, &data) != 0)
			continue;
		if (data == 0xffff)
			continue;
		seq_printf(s, "MDIO device %d\n", m);
		for (i = 0; i <= 31; i++) {
			if (vsc8201_mdio_reg_name[i][0] == 0)
				continue;
			if (eim_mdio_data_read(m, i, &data) != 0)
				continue;
			seq_printf(s, "%02X: %04x - %s\n", i, data,
				vsc8201_mdio_reg_name[i]);
		}
	}
}

#endif
