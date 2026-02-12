/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_sys_h
#define _drv_onu_sys_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_SYS System Control Low-level Functions

   Low-level functions to access system control settings.
   @{
*/
#if defined(ONU_LIBRARY)
#include <sysctrl.h>
#else
#if defined(LINUX) && defined(__KERNEL__)
#include <falcon/sysctrl.h>
#else
static inline void sys1_hw_activate(uint32_t mask) { (void) mask; }
static inline void sys1_hw_deactivate(uint32_t mask) { (void) mask; }
static inline void sys1_hw_clk_enable(uint32_t mask) { (void) mask; }
static inline void sys1_hw_clk_disable(uint32_t mask) { (void) mask; }
static inline void sys1_hw_activate_or_reboot(uint32_t mask) { (void) mask; }
static inline void sys_eth_hw_activate(uint32_t mask) { (void) mask; }
static inline void sys_eth_hw_deactivate(uint32_t mask) { (void) mask; }
static inline void sys_eth_hw_clk_enable(uint32_t mask) { (void) mask; }
static inline void sys_eth_hw_clk_disable(uint32_t mask) { (void) mask; }
static inline void sys_eth_hw_activate_or_reboot(uint32_t mask) { (void) mask; }
static inline void sys_gpe_hw_activate(uint32_t mask) {(void) mask; }
static inline void sys_gpe_hw_deactivate(uint32_t mask) { (void) mask; }
static inline void sys_gpe_hw_clk_enable(uint32_t mask) { (void) mask; }
static inline void sys_gpe_hw_clk_disable(uint32_t mask) { (void) mask; }
static inline void sys_gpe_hw_activate_or_reboot(uint32_t mask) { (void) mask; }
static inline int sys_gpe_hw_is_activated(uint32_t mask) { (void) mask; return 0; }
#endif
#endif

/** clock defines for \ref sys_eth_ext_phy() */
#define F25    1 /**< 25 MHz */
#define F50    5 /**< 50 MHz */
#define F125   2 /**< 125 MHz */

#define GMAC_MAX_NUM    4

enum gmac_mux_mode {
	/** GMAC connects to GPHY0_GMII interface */
	GMAC_GPHY0_GMII = 0,
	/** GMAC connects to GPHY0_MII2 interface */
	GMAC_GPHY0_MII2 = 1,
	/** GMAC connects to GPHY1_GMII interface */
	GMAC_GPHY1_GMII = 2,
	/** GMAC connects to GPHY1_MII2 interface */
	GMAC_GPHY1_MII2 = 3,
	/** GMAC connects to SGMII interface */
	GMAC_SGMII = 4,
	/** GMAC connects to xMII0 interface */
	GMAC_xMII0 = 5,
	/** GMAC connects to xMII1 interface */
	GMAC_xMII1 = 6
};

/**
   Configure the ETH output driver

   \param enable Enables the output driver of the PHY_CLKO pin.
   \param clock Selects the frequency of the PHY_CLKO pin.
*/
void sys_eth_ext_phy(bool enable, uint16_t clock);

/**
   Set MDIO clock rate

   \param val Selects the frequency of the MDIO interface.
*/
int sys_eth_mdio_clock_rate_set(enum mdio_mode_speed val);

/**
   Get MDIO clock rate
*/
enum mdio_mode_speed sys_eth_mdio_clock_rate_get(void);

/**
   Get MDIO activation status
*/
bool sys_eth_mdio_is_active(void);

/**
   Set GMAC Multiplexer Mode

   \param num GMAC number.
   \param mux_mode GMAC Multiplexer Mode.
*/
int sys_eth_gmac_mux_set(uint8_t num, enum gmac_mux_mode mux_mode);

/**
   Get GMAC Multiplexer Mode

   \param num GMAC number.
   \param mux_mode GMAC Multiplexer Mode.
*/
int sys_eth_gmac_mux_get(uint8_t num, enum gmac_mux_mode *mux_mode);

/**
   Set xMII interface datarate

   \param xmii_idx GMAC number.
   \param speed xMII speed.
*/
int sys_eth_xmii_data_rate_set(const uint8_t xmii_idx,
			       const enum lan_mode_speed speed);

/**
   Set GPHYx interface datarate

   \param gphy_idx GMAC number.
   \param speed xMII speed.
*/
int sys_eth_gphy_data_rate_set(const uint8_t gphy_idx,
			       const enum lan_mode_speed speed);

/**
   Set SGMII interface datarate

   \param speed SGMII speed
*/
int sys_eth_sgmii_data_rate_set(const enum lan_mode_speed speed);

/**
   Reboot GPHYx module

   \param phyno GPHY number (0 or 1)
*/
void sys_eth_gphy_reboot(uint8_t phyno);

/**
   Set boot address for GPHYx module

   \param phyno        GPHY number (0 or 1)
   \param gphy_fw_addr Address of GPHY FW
*/
void sys_eth_gphy_boot_addr_set(uint8_t phyno, uint32_t gphy_fw_addr);

/**
   Reboot MERGER module
*/
void sys_gpe_merger_reboot(void);

/**
   Get GMACx Data Rate Status

   \param num GMAC number (0..3)
   \param speed GMAC data rate status
*/
int sys_eth_gmac_data_rate_get(uint8_t num, enum lan_mode_speed *speed);

/**
   Get CHIP ID

   \param chipid Chip identification
   \param config Configuration fuses
*/
void status_chipid_get(uint32_t *chipid, uint32_t *config);

/** Get fuses configuration

   \param analog Fuses for analog modules
   \param fuse0 SPARE fuse register 0
*/
void status_fuses_get(uint32_t *analog, uint32_t *fuse0);

/**
   Set sleep mode configuration

   \param sscfg SSCFG register
   \param sdset SDSET register
*/
void sys_gpe_sleep_cfg_set(uint32_t sscfg, uint32_t sdset);

/**
   Reboot TMU module
*/
void sys_gpe_tmu_reboot(void);

/**
   Enables/disables the output driver of the CLKO pad

   \param enable Enable/Disable the output driver of the CLKO pad
*/
void sys1_clko_enable(bool enable);

/**
 * Retrieve activation status of the selected hardware module(s)
 *
 * \param[in]   mask    bitmask of module(s), as for registers SYS_ETH.RBT
 * \return int 1 - if hardware module(s) is activated (including clock)
 */
int sys_eth_hw_is_activated(uint32_t mask);

#if defined(INCLUDE_DUMP)

/**
   Dump the SYS information.
*/
void sys_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
