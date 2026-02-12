/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_reg_sys_eth.h"
#include "drv_onu_reg_sys_gpe.h"
#include "drv_onu_reg_sys1.h"

void sys_eth_ext_phy(bool enable, uint16_t clock)
{
	uint32_t val = clock & 0x7;

	if (enable)
		val |= SYS_ETH_EXTPHYC_CLKEN;
	sys_eth_w32(val, extphyc);
}

int sys_eth_mdio_clock_rate_set(enum mdio_mode_speed val)
{
	uint32_t set;

	/* only on A1x chip */
	if (is_falcon_chip_a1x()) {
		switch (val) {
		case MDIO_MODE_SPEED_2M5:
			set = SYS_ETH_DRC_MDC_F2M44;
			break;
		case MDIO_MODE_SPEED_5M:
			set = SYS_ETH_DRC_MDC_F4M88;
			break;
		case MDIO_MODE_SPEED_10M:
			set = SYS_ETH_DRC_MDC_F9M77;
			break;
		case MDIO_MODE_SPEED_20M:
			set = SYS_ETH_DRC_MDC_F19M5;
			break;
		default:
			return -1;
		}
		sys_eth_w32_mask(SYS_ETH_DRC_MDC_MASK, set, drc);
	}
	return 0;
}

int sys_eth_xmii_data_rate_set(const uint8_t xmii_idx,
			       const enum lan_mode_speed speed)
{
	uint32_t set;
	uint8_t idx = xmii_idx & 0x1;

	switch (speed) {
	case LAN_MODE_SPEED_10:
		set = SYS_ETH_DRC_xMII0_DR10;
		break;
	case LAN_MODE_SPEED_100:
		set = idx ? SYS_ETH_DRC_xMII1_DR100:
				 SYS_ETH_DRC_xMII0_DR100;
		break;
	case LAN_MODE_SPEED_200:
		set = idx ? SYS_ETH_DRC_xMII1_DR200 :
				 SYS_ETH_DRC_xMII0_DR200;
		break;
	case LAN_MODE_SPEED_1000:
		set = idx ? SYS_ETH_DRC_xMII1_DR1000 :
				 SYS_ETH_DRC_xMII0_DR1000;
		break;
	default:
		return -1;
	}

	sys_eth_w32_mask(idx ? SYS_ETH_DRC_xMII1_MASK : SYS_ETH_DRC_xMII0_MASK,
			 set, drc);

	return 0;
}

int sys_eth_gphy_data_rate_set(const uint8_t gphy_idx,
			       const enum lan_mode_speed speed)
{
	uint32_t set;
	uint8_t idx = gphy_idx & 0x1;

	switch (speed) {
	case LAN_MODE_SPEED_10:
		set = SYS_ETH_DRC_GPHY0_GMII_DR10;
		break;
	case LAN_MODE_SPEED_100:
		set = idx ? SYS_ETH_DRC_GPHY1_GMII_DR100:
			    SYS_ETH_DRC_GPHY0_GMII_DR100;
		break;
	case LAN_MODE_SPEED_1000:
		set = idx ? SYS_ETH_DRC_GPHY1_GMII_DR1000 :
			    SYS_ETH_DRC_GPHY0_GMII_DR1000;
		break;
	default:
		return -1;
	}

	sys_eth_w32_mask(idx ? SYS_ETH_DRC_GPHY1_GMII_MASK :
			       SYS_ETH_DRC_GPHY0_GMII_MASK,
			 set, drc);

	return 0;
}

int sys_eth_sgmii_data_rate_set(const enum lan_mode_speed speed)
{
	uint32_t set;

	switch (speed) {
	case LAN_MODE_SPEED_10:
		set = SYS_ETH_DRC_SGMII_DR10;
		break;
	case LAN_MODE_SPEED_100:
		set = SYS_ETH_DRC_SGMII_DR100;
		break;
	case LAN_MODE_SPEED_1000:
		set = SYS_ETH_DRC_SGMII_DR1000;
		break;
	case LAN_MODE_SPEED_2500:
		set = SYS_ETH_DRC_SGMII_DR2500;
		break;
	default:
		return -1;
	}

	sys_eth_w32_mask(SYS_ETH_DRC_SGMII_MASK, set, drc);

	return 0;
}

enum mdio_mode_speed sys_eth_mdio_clock_rate_get(void)
{
	uint32_t drc;

	/* only on A1x chip */
	if (is_falcon_chip_a1x()) {
		drc = sys_eth_r32(drc) & SYS_ETH_DRC_MDC_MASK;
		switch(drc) {
		case SYS_ETH_DRC_MDC_F2M44:
			return MDIO_MODE_SPEED_2M5;
		case SYS_ETH_DRC_MDC_F4M88:
			return MDIO_MODE_SPEED_5M;
		case SYS_ETH_DRC_MDC_F9M77:
			return MDIO_MODE_SPEED_10M;
		case SYS_ETH_DRC_MDC_F19M5:
			return MDIO_MODE_SPEED_20M;
		}
	}
	return MDIO_MODE_SPEED_UNDEFINED;
}

bool sys_eth_mdio_is_active(void)
{
	return (sys_eth_r32(acts) & SYS_ETH_ACTS_MDIO) ? true : false;
}

int sys_eth_gmac_mux_set(uint8_t num, enum gmac_mux_mode mux_mode)
{
	uint32_t mask[GMAC_MAX_NUM]  = {SYS_ETH_GMUXC_GMAC0_MASK,
					SYS_ETH_GMUXC_GMAC1_MASK,
					SYS_ETH_GMUXC_GMAC2_MASK,
					SYS_ETH_GMUXC_GMAC3_MASK};
	uint8_t offset[GMAC_MAX_NUM] = {SYS_ETH_GMUXC_GMAC0_OFFSET,
					SYS_ETH_GMUXC_GMAC1_OFFSET,
					SYS_ETH_GMUXC_GMAC2_OFFSET,
					SYS_ETH_GMUXC_GMAC3_OFFSET};

	if (num >= GMAC_MAX_NUM)
		return -1;

	sys_eth_w32_mask(mask[num], mux_mode << offset[num], gmuxc);

	return 0;
}

int sys_eth_gmac_mux_get(uint8_t num, enum gmac_mux_mode *mux_mode)
{
	uint8_t offset[GMAC_MAX_NUM] = {SYS_ETH_GMUXC_GMAC0_OFFSET,
					SYS_ETH_GMUXC_GMAC1_OFFSET,
					SYS_ETH_GMUXC_GMAC2_OFFSET,
					SYS_ETH_GMUXC_GMAC3_OFFSET};

	if (num >= GMAC_MAX_NUM)
		return -1;

	*mux_mode = (enum gmac_mux_mode)((sys_eth_r32(gmuxc) >> offset[num]) &
						      SYS_ETH_GMUXC_GMAC0_MASK);

	return 0;
}

void sys_eth_gphy_reboot(uint8_t phyno)
{
	uint32_t ier, isr;

	if (phyno == 0) {
		if (is_falcon_chip_a1x()) {
			ier = EIM_EIM_IER_A1X_GPHY0_IEN_EN;
			isr = EIM_EIM_ISR_A1X_GPHY0_IRQ;
		} else {
			ier = EIM_EIM_IER_A2X_GPHY0_IEN_EN;
			isr = EIM_EIM_ISR_A2X_GPHY0_IRQ;
		}
	} else {
		if (is_falcon_chip_a1x()) {
			ier = EIM_EIM_IER_A1X_GPHY1_IEN_EN;
			isr = EIM_EIM_ISR_A1X_GPHY1_IRQ;
		} else {
			ier = EIM_EIM_IER_A2X_GPHY1_IEN_EN;
			isr = EIM_EIM_ISR_A2X_GPHY1_IRQ;
		}
	}
	sys_eth_hw_activate_or_reboot((phyno == 0) ? SYS_ETH_ACT_GPHY0 :
						     SYS_ETH_ACT_GPHY1);
	/* enable the interrupt for gphy */
	eim_w32_mask(0, ier, top_pdi.eim_ier);

	sys_eth_w32((phyno == 0) ? SYS_ETH_RBT_GPHY0_TRIG :
				   SYS_ETH_RBT_GPHY1_TRIG, rbt);

	/* wait for interrupt */
	while ((eim_r32(top_pdi.eim_isr) & isr) == 0)
	{};
	/* disable interrupt */
	eim_w32_mask(ier, 0, top_pdi.eim_ier);
	/* acknowledge interrupt */
	eim_w32_mask(isr, 0, top_pdi.eim_isr);
}

void sys_eth_gphy_boot_addr_set(uint8_t phyno, uint32_t gphy_fw_addr)
{
	if (phyno == 0)
		sbs0ctrl_w32(gphy_fw_addr & SBS0CTRL_GPHY0IMG_ADDRV_MASK,
			     gphy0img);
	else
		sbs0ctrl_w32(gphy_fw_addr & SBS0CTRL_GPHY1IMG_ADDRV_MASK,
			     gphy1img);
}

void sys_gpe_merger_reboot(void)
{
	sys_gpe_w32(SYS_GPE_RBT_MRG_TRIG, rbt);
}

int sys_eth_gmac_data_rate_get(uint8_t num, enum lan_mode_speed *speed)
{
	uint32_t reg;
	enum lan_mode_speed speed_map[] = {
		LAN_MODE_SPEED_10,
		LAN_MODE_SPEED_100,
		LAN_MODE_SPEED_1000,
		LAN_MODE_SPEED_AUTO, /* just to indicate an unhandled value*/
		LAN_MODE_SPEED_2500,
		LAN_MODE_SPEED_200
	};

	reg  = sys_eth_r32(drs) >> ((num & 0x3)*SYS_ETH_DRS_GMAC1_OFFSET);
	reg &= SYS_ETH_DRS_GMAC0_MASK;

	*speed = speed_map[reg];

	return *speed != LAN_MODE_SPEED_AUTO ? 0 : -1;
}

void status_chipid_get(uint32_t *chipid, uint32_t *config)
{
	*chipid = status_r32(chipid);
	*config = status_r32(config);
}

void status_fuses_get(uint32_t *analog, uint32_t *fuse0)
{
	*analog = status_r32(analog);
	*fuse0 = status_r32(fuse0);
}

void sys_gpe_tmu_reboot(void)
{
	sys_gpe_w32(SYS_GPE_RBT_TMU_TRIG, rbt);
}

void sys_gpe_sleep_cfg_set(uint32_t sscfg, uint32_t sdset)
{
	sys_gpe_w32(sscfg, sscfg);
	sys_gpe_w32(sdset, sdset);
}

void sys1_clko_enable(bool enable)
{
	sys1_w32_mask(CLKOC_OEN, enable ? CLKOC_OEN : 0, clkoc);
}

/**
 * Retrieve activation status of the selected hardware module(s)
 *
 * \param[in]   mask    bitmask of module(s), as for registers SYS_ETH.RBT
 * \return int 1 - if hardware module(s) is activated (including clock)
 */
int sys_eth_hw_is_activated(uint32_t mask)
{
	if ((sys_eth_r32(clks) & mask) != mask)
		return 0;

	return ((sys_gpe_r32(acts) & mask) == mask);
}


#if defined(INCLUDE_DUMP)

const char *sys_eth_names[32] = {
	"GMAC0", "GMAC1", "GMAC2", "GMAC3",
	NULL, NULL, NULL, "MDIO",
	"GPHY0", "GPHY1", "SGMII", "xMII",
	NULL, NULL, NULL, NULL,
	"GPIO0", "GPIO2", NULL, NULL,
	"PAD0", "PAD2", NULL, NULL,
	"GPHY0MII2", "GPHY1MII2", NULL, NULL,
	NULL, NULL, NULL, NULL
};

const char *sys_gpe_names[32] = {
	"LAN0", "LAN1", "LAN2", "LAN3",
	"GPONI", "GPONE", "CPUI", "CPUE",
	"IQM", "DISP", "MRG", "TMU",
	"FSQM", "ARB", NULL, NULL,
	"PE0", "PE1", "PE2", "PE3",
	"PE4", "PE5", NULL, NULL,
	"COP0", "COP1", "COP2", "COP3",
	"COP4", "COP5", "COP6", "COP7"
};

const char *sys_gpe_sscfg_names[32] = {
	"LAN0I", "LAN1I", "LAN2I", "LAN3I",
	"GPONI", NULL, NULL, NULL,
	"LAN0E", "LAN1E", "LAN2E", "LAN3E",
	"GPONE", "GPONT", NULL, "FSQM",
	NULL, "CPU", NULL, NULL,
	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL
};

void sys_dump(struct seq_file *s)
{
	uint32_t clks, acts, sds, sscfg, sdset;
	static const char *space="          ";
	int i;
	acts = sys_eth_r32(acts);
	clks = sys_eth_r32(clks);

	seq_printf(s, "sys_eth\t");
	for (i=0; i<32; i++)
		if (sys_eth_names[i] != NULL)
			seq_printf(s, "%s ", sys_eth_names[i]);

	seq_printf(s, "\nacts\t ");
	for (i=0; i<32; i++)
		if (sys_eth_names[i] != NULL)
			seq_printf(s, "%c%s", (acts & 1<<i) ? 'X':' ',
				(space+(10-strlen(sys_eth_names[i]))));
	seq_printf(s, "\nclks\t ");
	for (i=0; i<32; i++)
		if (sys_eth_names[i] != NULL)
			seq_printf(s, "%c%s", (clks & 1<<i) ? 'X':' ',
				(space+(10-strlen(sys_eth_names[i]))));

	if (sys_gpe_hw_is_activated(0)) {
		acts = sys_gpe_r32(acts);
		clks = sys_gpe_r32(clks);
		sds = sys_gpe_r32(sds);
		sscfg = sys_gpe_r32(sscfg);
		sdset = sys_gpe_r32(sdset);
		seq_printf(s, "\nsys_gpe\t");
		for (i=0; i<32; i++)
			if (sys_gpe_names[i] != NULL)
				seq_printf(s, "%s ", sys_gpe_names[i]);

		seq_printf(s, "\nacts\t ");
		for (i=0; i<32; i++)
			if (sys_gpe_names[i] != NULL)
				seq_printf(s, "%c%s", (acts & 1<<i) ? 'X':' ',
					(space+(10-strlen(sys_gpe_names[i]))));
		seq_printf(s, "\nclks\t ");
		for (i=0; i<32; i++)
			if (sys_gpe_names[i] != NULL)
				seq_printf(s, "%c%s", (clks & 1<<i) ? 'X':' ',
					(space+(10-strlen(sys_gpe_names[i]))));
		seq_printf(s, "\nsds\t ");
		for (i=0; i<32; i++)
			if (sys_gpe_names[i] != NULL)
				seq_printf(s, "%c%s", (sds & 1<<i) ? 'X':' ',
					(space+(10-strlen(sys_gpe_names[i]))));
		seq_printf(s, "\nsdset\t ");
		for (i=0; i<32; i++)
			if (sys_gpe_names[i] != NULL)
				seq_printf(s, "%c%s", (sdset & 1<<i) ? 'X':' ',
					(space+(10-strlen(sys_gpe_names[i]))));
		seq_printf(s, "\nsys_gpe_sscfg\t");
		for (i=0; i<32; i++)
			if (sys_gpe_sscfg_names[i] != NULL)
				seq_printf(s, "%s ", sys_gpe_sscfg_names[i]);
		seq_printf(s, "\nsscfg\t ");
		for (i=0; i<32; i++)
			if (sys_gpe_sscfg_names[i] != NULL)
				seq_printf(
					s, "%c%s", (sscfg & 1<<i) ? 'X':' ',
					   (space + (10 -
					      strlen(sys_gpe_sscfg_names[i]))));
	}

	seq_printf(s, "\n");
}

#endif
