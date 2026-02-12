/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_lan_api.h
*/
#ifndef _drv_onu_drv_lan_api_h
#define _drv_onu_drv_lan_api_h

#include "drv_onu_std_defs.h"
#include "drv_onu_lan_interface.h"

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_LAN_INTERNAL Ethernet Interface
   @{
*/
extern const struct onu_entry lan_function_table[];
extern const unsigned int lan_function_table_size;

enum onu_errorcode lan_gphy_firmware_download(struct onu_device *p_dev,
					      const struct lan_gphy_fw *param);

enum onu_errorcode lan_init(struct onu_device *p_dev);

enum onu_errorcode lan_cfg_set(struct onu_device *p_dev,
			       const struct lan_cfg *param);

enum onu_errorcode lan_cfg_get(struct onu_device *p_dev, struct lan_cfg *param);

enum onu_errorcode lan_port_cfg_set(struct onu_device *p_dev,
				    const struct lan_port_cfg *param);

enum onu_errorcode lan_port_cfg_get(struct onu_device *p_dev,
				    const struct lan_port_index *in,
				    struct lan_port_cfg *out);

enum onu_errorcode lan_port_enable(struct onu_device *p_dev,
				   const struct lan_port_index *param);

enum onu_errorcode lan_port_disable(struct onu_device *p_dev,
				    const struct lan_port_index *param);

enum onu_errorcode lan_loop_cfg_set(struct onu_device *p_dev,
				    const struct lan_loop_cfg *param);

enum onu_errorcode lan_loop_cfg_get(struct onu_device *p_dev,
				    const struct lan_port_index *in,
				    struct lan_loop_cfg *out);

enum onu_errorcode lan_port_status_get(struct onu_device *p_dev,
				       const struct lan_port_index *in,
				       struct lan_port_status *out);

enum onu_errorcode lan_counter_get(struct onu_device *p_dev,
				   const struct lan_cnt_interval *in,
				   struct lan_counters *out);
enum onu_errorcode lan_counter_reset(struct onu_device *p_dev,
				     const struct lan_cnt_interval *param);

enum onu_errorcode
lan_counter_threshold_set(struct onu_device *p_dev,
			  const struct lan_cnt_threshold *param);

enum onu_errorcode lan_counter_threshold_get(struct onu_device *p_dev,
					     const struct lan_port_index *in,
					     struct lan_cnt_threshold *out);
enum onu_errorcode lan_tca_get(struct onu_device *p_dev,
			       const struct uni_port_id *in,
			       struct lan_cnt_val *out);

enum onu_errorcode wol_cfg_set(struct onu_device *p_dev,
			       const struct wol_cfg *param);

enum onu_errorcode wol_cfg_get(struct onu_device *p_dev,
			       const struct lan_port_index *in,
			       struct wol_cfg *out);

enum onu_errorcode wol_status_get(struct onu_device *p_dev,
				  const struct lan_port_index *in,
				  struct wol_status *out);

enum onu_errorcode mdio_data_read(struct onu_device *p_dev,
				  const struct mdio *in,
				  struct mdio_read *out);

enum onu_errorcode mdio_data_write(struct onu_device *p_dev,
				   const struct mdio_write *param);

enum onu_errorcode mdio_enable(struct onu_device *p_dev,
			       const struct mdio_en *param);

enum onu_errorcode mdio_disable(struct onu_device *p_dev,
				const struct mdio_dis *param);

enum onu_errorcode mmd_data_read(struct onu_device *p_dev,
				 const struct mmd *in,
				 struct mmd_read *out);

enum onu_errorcode mmd_data_write(struct onu_device *p_dev,
				  const struct mmd_write *param);

#ifndef SWIG

/**
   IEEE802.3 Standard Registers
*/

/** MDIO Control register address*/
#define MDIO_PHY_MODE_CTRL				(0)
/** MDIO Status register address*/
#define MDIO_PHY_STATUS					(1)
/** MDIO PHY Identifier 1 register address*/
#define MDIO_PHY_PHYID1					(2)
/** MDIO PHY Identifier 2 register address*/
#define MDIO_PHY_PHYID2					(3)
/** MDIO Auto-Negotiation Advertisement register address*/
#define MDIO_PHY_AN_ADV					(4)
/** MDIO Auto-Negotiation Link-Partner Ability register address*/
#define MDIO_PHY_AN_LPA					(5)
/** MDIO gigabit control register address*/
#define MDIO_PHY_MODE_GCTRL				(9)
/** MDIO MMD Control register*/
#define MDIO_PHY_MMD_CTRL				(13)
/** MDIO MMD Address/Data register*/
#define MDIO_PHY_MMD_DATA				(14)
/** MDIO Physical Layer Control 1 register address*/
#define MDIO_PHY_CTL1					(19)
/** MDIO Physical Layer Control 2 register address*/
#define MDIO_PHY_CTL2					(20)
/** Error counter register */
#define MDIO_PHY_ERRCNT					(21)
/** MDIO Interrupt Mask register address*/
#define MDIO_IMASK					(25)
/** MDIO Interrupt Status register address*/
#define MDIO_ISTAT					(26)
/** MDIO Firmware Version register address*/
#define MDIO_FWV					(30)
/** MDIO Gigabit Status register address*/
#define MDIO_PHY_GSTAT					(10)

#define MDIO_PHY_MODE_CTRL_LOOPBACK			(0x4000)
#define MDIO_PHY_MODE_CTRL_LOOPBACK_ENABLE		(0x4000)

#define MDIO_PHY_MODE_CONTROL_SPEED			(0x2040)
#define MDIO_PHY_MODE_CONTROL_SPEED_10MBPS		(0x0)
#define MDIO_PHY_MODE_CONTROL_SPEED_100MBPS		(0x2000)
#define MDIO_PHY_MODE_CONTROL_SPEED_1000MBPS		(0x40)

#define MDIO_PHY_MODE_CONTROL_AUTONEG_RESTART		(1 << 9)

#define MDIO_PHY_MODE_CONTROL_AUTONEG			(0x1000)
#define MDIO_PHY_MODE_CONTROL_AUTONEG_ENABLE		(1 << 12)
#define MDIO_PHY_MODE_CONTROL_AUTONEG_DISABLE		(0x0)

#define MDIO_PHY_MODE_CONTROL_PWR_DOWN			(0x800)
#define MDIO_PHY_MODE_CONTROL_PWR_DOWN_ENABLE		(0x800)
#define MDIO_PHY_MODE_CONTROL_PWR_DOWN_DISABLE		(0x0)

#define MDIO_PHY_MODE_CONTROL_DUPLEX			(0x100)
#define MDIO_PHY_MODE_CONTROL_DUPLEX_FULL		(0x100)
#define MDIO_PHY_MODE_CONTROL_DUPLEX_HALF		(0x0)

#define MDIO_PHY_PHYID1_OUI				(0xFFFF)
#define MDIO_PHY_PHYID1_OUI_OFFSET			(0)

#define MDIO_PHY_PHYID2_OUI				(0xFC00)
#define MDIO_PHY_PHYID2_OUI_OFFSET			(10)

#define MDIO_PHY_LTQ_OUI				(0x969AAC)

/** MDIO Status register LINK field*/
#define MDIO_PHY_STATUS_LS	    			(1 << 2)
#define MDIO_PHY_STATUS_ANOK		   		(1 << 5)

#define MDIO_PHY_CTL1_TLOOP_MASK			(0xE000)
#define MDIO_PHY_CTL1_TLOOP_FETL			(0x4000)
#define MDIO_PHY_CTL1_TLOOP_NETL			(0x2000)

#define MDIO_IMASK_WOL		 			(0x8000)

#define MDIO_GSTAT_MBTHD				(1 << 10)
#define MDIO_GSTAT_MBTFD				(1 << 11)

#define MDIO_PHY_AN_LPA_XBT_HDX				(0x1 << 5)
#define MDIO_PHY_AN_LPA_XBT_FDX				(0x2 << 5)
#define MDIO_PHY_AN_LPA_DBT_HDX				(0x4 << 5)
#define MDIO_PHY_AN_LPA_DBT_FDX				(0x8 << 5)

#define MDIO_PHY_AN_ADV_XBT_HDX				(0x1 << 5)
#define MDIO_PHY_AN_ADV_XBT_FDX				(0x2 << 5)
#define MDIO_PHY_AN_ADV_DBT_HDX				(0x4 << 5)
#define MDIO_PHY_AN_ADV_DBT_FDX				(0x8 << 5)
#define MDIO_PHY_AN_ADV_PS_ASYM				(0x20 << 5)
#define MDIO_PHY_AN_ADV_PS_SYM				(0x40 << 5)
#define MDIO_PHY_AN_ADV_TAF_MASK			(0xFF << 5)

#define MDIO_PHY_MODE_GCTRL_MBTHD			(0x1 << 8)
#define MDIO_PHY_MODE_GCTRL_MBTFD			(0x2 << 8)

/**
   FALCON GPHY Specific MMD Registers
*/
/** MMD EEE Control Register 1 address*/
#define MMD_EEE_CTRL1					(0x0000)
/** MMD EEE Auto-Negotiation Advertisement Register address*/
#define MMD_EEE_AN_ADV					(0x003C)

/** MMD LED common configuration register address, (high part)*/
#define MMD_LEDC_HIGH					(0x01E0)
/** MMD LED common configuration register address, (low part)*/
#define MMD_LEDC_LOW					(0x01E1)
/** MMD LED0 configuration register address, (high part)*/
#define MMD_LED0_HIGH					(0x01E2)
/** MMD LED0 configuration register address, (low part)*/
#define MMD_LED0_LOW					(0x01E3)
/** MMD LED1 configuration register address, (high part)*/
#define MMD_LED1_HIGH					(0x01E4)
/** MMD LED1 configuration register address, (low part)*/
#define MMD_LED1_LOW					(0x01E5)
/** MMD LED2 configuration register address, (high part)*/
#define MMD_LED2_HIGH					(0x01E6)
/** MMD LED2 configuration register address, (low part)*/
#define MMD_LED2_LOW					(0x01E7)
/** MMD LED3 configuration register address, (high part)*/
#define MMD_LED3_HIGH					(0x01E8)
/** MMD LED3 configuration register address, (low part)*/
#define MMD_LED3_LOW					(0x01E9)

/** MMD Wake-On-LAN control register address*/
#define MMD_ADDR_WOLCTRL				(0x077B)
/** MMD Wake-On-LAN Address Byte 0 register address*/
#define MMD_ADDR_WOLAD0					(0x077D)
/** MMD Wake-On-LAN Address Byte 1 register address*/
#define MMD_ADDR_WOLAD1					(0x077E)
/** MMD Wake-On-LAN Address Byte 2 register address*/
#define MMD_ADDR_WOLAD2					(0x077F)
/** MMD Wake-On-LAN Address Byte 3 register address*/
#define MMD_ADDR_WOLAD3					(0x0780)
/** MMD Wake-On-LAN Address Byte 4 register address*/
#define MMD_ADDR_WOLAD4					(0x0781)
/** MMD Wake-On-LAN Address Byte 5 register address*/
#define MMD_ADDR_WOLAD5					(0x0782)
/** MMD Wake-On-LAN SecureON Password Byte 0 register address*/
#define MMD_WOLPW0					(0x0783)
/** MMD Wake-On-LAN SecureON Password Byte 1 register address*/
#define MMD_WOLPW1					(0x0784)
/** MMD Wake-On-LAN SecureON Password Byte 2 register address*/
#define MMD_WOLPW2					(0x0785)
/** MMD Wake-On-LAN SecureON Password Byte 3 register address*/
#define MMD_WOLPW3					(0x0786)
/** MMD Wake-On-LAN SecureON Password Byte 4 register address*/
#define MMD_WOLPW4					(0x0787)
/** MMD Wake-On-LAN SecureON Password Byte 5 register address*/
#define MMD_WOLPW5					(0x0788)

/** MMD Device selection to access WOL registers*/
#define MMD_WOL_SEL					(0x1F)
/** MMD Device selection to access EEE registers*/
#define MMD_EEE_SEL					(0x03)
/** MMD Device selection to access ANEG registers*/
#define MMD_ANEG_SEL					(0x07)

/** MMD Device selection to access LED registers*/
#define MMD_LED_SEL					(0x1F)

/** MMD EEE Control Register 1 bits*/
#define MMD_EEE_CTRL1_RXCKST_EN				(1 << 10)

/** MMD LED common configuration register bits*/
#define MMD_LEDC_HIGH_NACS_NONE				(0 << 0)
#define MMD_LEDC_HIGH_NACS_LINK				(1 << 0)
#define MMD_LEDC_HIGH_SBF_F02HZ				(0 << 4)
#define MMD_LEDC_HIGH_SBF_F04HZ				(1 << 4)
#define MMD_LEDC_HIGH_FBF_F02HZ				(0 << 6)
#define MMD_LEDC_HIGH_FBF_F04HZ				(1 << 6)
#define MMD_LEDC_HIGH_FBF_F08HZ				(2 << 6)
#define MMD_LEDC_HIGH_FBF_F16HZ				(3 << 6)
#define MMD_LEDC_LOW_CBLINK_NONE			(0 << 0)
#define MMD_LEDC_LOW_CBLINK_LINK			(1 << 0)
#define MMD_LEDC_LOW_SCAN_NONE				(0 << 4)
#define MMD_LEDC_LOW_SCAN_LINK				(1 << 4)
/** MMD LED pin specific configuration register bits*/
#define MMD_LEDX_HIGH_BLINKF_NONE			(0 << 0)
#define MMD_LEDX_HIGH_BLINKF_LINK10			(1 << 0)
#define MMD_LEDX_HIGH_BLINKF_LINK100			(2 << 0)
#define MMD_LEDX_HIGH_CON_NONE				(0 << 4)
#define MMD_LEDX_HIGH_CON_LINK10			(1 << 4)
#define MMD_LEDX_HIGH_CON_LINK100			(2 << 4)
#define MMD_LEDX_HIGH_CON_LINK10X			(3 << 4)
#define MMD_LEDX_HIGH_CON_LINK1000			(4 << 4)
#define MMD_LEDX_HIGH_CON_LINK10_0			(5 << 4)
#define MMD_LEDX_HIGH_CON_LINK100X			(6 << 4)
#define MMD_LEDX_HIGH_CON_LINK10XX			(7 << 4)
#define MMD_LEDX_LOW_PULSE_NONE				(0 << 0)
#define MMD_LEDX_LOW_PULSE_TXACT			(1 << 0)
#define MMD_LEDX_LOW_PULSE_RXACT			(2 << 0)
#define MMD_LEDX_LOW_PULSE_COL				(4 << 0)
#define MMD_LEDX_LOW_BLINKS_NONE			(0 << 4)
#define MMD_LEDX_LOW_BLINKS_LINK10			(1 << 4)
#define MMD_LEDX_LOW_BLINKS_LINK100			(2 << 4)
#define MMD_LEDX_LOW_BLINKS_LINK10X			(3 << 4)
#define MMD_LEDX_LOW_BLINKS_LINK1000			(4 << 4)
#define MMD_LEDX_LOW_BLINKS_LINK10_0			(5 << 4)
#define MMD_LEDX_LOW_BLINKS_LINK100X			(6 << 4)
#define MMD_LEDX_LOW_BLINKS_LINK10XX			(7 << 4)

/** MMD Wake-On-LAN control register bits*/
#define MMD_WOLCTRL_EN					(1 << 0)
#define MMD_WOLCTRL_SPWD_EN				(1 << 2)

/** MMD EEE Auto-Negotiation Advertisement register bits*/
#define MMD_EEE_AN_ADV_MASK				(0x7E)
#define MMD_EEE_AN_ADV_EEE_100BTX			(0x1 << 1)
#define MMD_EEE_AN_ADV_EEE_1000BT			(0x2 << 1)

#define GPHY_FW_MAJOR_NUM_WOL_SUPPORT			(0x3)
#define GPHY_FW_MAJOR_NUM_LED_SUPPORT			(0x3)

/** GPHY 11G firmware base ROM address*/
#define GPHY_11G_FIRMWARE_A11_ROM_ADDR			(0xBF020000)
#define GPHY_11G_FIRMWARE_A12_ROM_ADDR			(0xBF018000)
/** GPHY 22F firmware base ROM address*/
#define GPHY_22F_FIRMWARE_A11_ROM_ADDR			(0xBF028000)
#define GPHY_22F_FIRMWARE_A12_ROM_ADDR			(0xBF024000)

/** Structure to identify GPHY firmware version.

    \remark 
    Please note that this part of the code is endianess-aware.
    Switching to a little-endian operation system or to a different
    processor core or compiler needs adaptation of the bit definitions.*/
struct gphy_fw_version {
	/**
	Indicates either a test or a release version.
	Constants
	0 - TEST Indicates a test version
	1 - RELEASE Indicates a released version*/
	uint16_t release : 1;
	/**
	Specifies the verison release number of the Firmware.*/
	uint16_t major   : 7;
	/**
	Specifies the subversion release number of the MAJOR Firmware
	release.*/
	uint16_t minor   : 8;
};

/** Structure to specify GPHY LED register init
*/
struct gphy_led_reg_init {
	/** LED register address */
	uint16_t reg_addr;
	/** LED register data */
	uint16_t reg_data;
};

enum onu_errorcode lan_cnt_update(struct onu_control *ctrl,
				  const uint8_t index,
				  const uint64_t reset_mask,
				  const bool curr,
				  void *p_data);

/** MDIO read/write access function*/
enum onu_errorcode lan_mdio_access(struct onu_control *ctrl,
				   const int8_t a_dev,
				   const uint8_t a_reg,
				   uint16_t mask_clear,
				   uint16_t mask_set,
				   uint16_t *data);

enum onu_errorcode lan_mmd_access(struct onu_control *ctrl,
				   const int8_t a_dev,
				   const uint8_t mmd_sel,
				   const uint16_t mmd_addr,
				   uint16_t mask_clear,
				   uint16_t mask_set,
				   uint16_t *data);

enum onu_errorcode lan_phy_interrupt_enable_set(struct onu_control *ctrl,
						const uint8_t port_num,
						const uint16_t clear,
						const uint16_t set);
enum onu_errorcode lan_traffic_watchdog (struct onu_control *ctrl);

#endif /* #ifndef SWIG*/

enum onu_errorcode lan_port_capability_cfg_set(struct onu_device *p_dev,
					       const struct
					       lan_port_capability_cfg *param);
enum onu_errorcode lan_port_capability_cfg_get(struct onu_device *p_dev,
					       const struct lan_port_index *in,
					       struct
					       lan_port_capability_cfg *out);


/*! @} */

/*! @} */

EXTERN_C_END
#endif
