/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "ifxos_memory_alloc.h"
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_ani_g.h"

#include <math.h>

/** \addtogroup OMCI_API_ME_ANI_G

   @{
*/

/*
 * ============================================================================
 *  v7.5.1 kernel-specific struct and ioctl definitions.
 *
 *  The shipping mod_optic.ko (v7.5.1) has different struct sizes than the
 *  v4.5.0 SDK headers.  Since we're building a replacement binary for this
 *  exact kernel, define the correct layouts locally.
 * ============================================================================
 */

/*
 * BOSA TX status — 24 bytes in v7.5.1 (was 9 in v4.5.0).
 * tx_enable widened from bool(1) to uint32_t(4), new fields inserted.
 * Layout from Ghidra decompilation of shipping mod_optic.ko.
 */
struct bosa_tx_status {
	uint32_t tx_enable;
	uint16_t bias_current;		/* [mA] << FLOAT2INTSHIFT_CURRENT (8) */
	uint16_t modulation_current;	/* [mA] << FLOAT2INTSHIFT_CURRENT (8) */
	uint32_t _reserved1;
	uint16_t laser_threshold;	/* [mA] << FLOAT2INTSHIFT_CURRENT (8) */
	uint16_t slope_efficiency;	/* [uW/mA] << FLOAT2INTSHIFT_SLOPEEFF */
	uint8_t  _reserved2[8];
};

#define FIO_BOSA_TX_STATUS_GET_751 \
	_IOR(OPTIC_BOSA_MAGIC, 13, struct bosa_tx_status)

/*
 * Supply voltage — new in v7.5.1, ioctl #10 in MM block.
 * Not present in v4.5.0 SDK.  Single uint32_t value.
 */
struct mm_supply_voltage {
	uint32_t voltage_val;		/* [V] << FLOAT2INTSHIFT_VOLTAGE_FINE (14) */
};

#define FIO_MM_SUPPLY_VOLTAGE_GET \
	_IOR(OPTIC_MM_MAGIC, 10, struct mm_supply_voltage)


/** GOI power check interval */
#define OMCI_API_ANIG_GOI_POWER_CHECK_INTERVAL                         1

enum omci_api_return omci_api_ani_g_destroy(struct omci_api_ctx *ctx,
					    uint16_t me_id)
{
	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_ani_g_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t gem_block_len,
					   uint8_t sf_threshold,
					   uint8_t sd_threshold,
					   uint8_t lower_optic_threshold,
					   uint8_t upper_optic_threshold,
					   uint8_t lower_tx_power_threshold,
					   uint8_t upper_tx_power_threshold)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gtc_cfg gtc_cfg, gtc_cfg_old;
	struct gpe_cfg gpe_cfg, gpe_cfg_old;
#if 0
	struct goi_cfg_t goi_cfg;
#endif

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   gem_block_len=%u\n"
		  "   sf_threshold=%u\n"
		  "   sd_threshold=%u\n"
		  "   lower_optic_threshold=%u\n"
		  "   upper_optic_threshold=%u\n"
		  "   lower_tx_power_threshold=%u\n"
		  "   upper_tx_power_threshold=%u\n",
		  __FUNCTION__,
		  me_id, gem_block_len, sf_threshold, sd_threshold,
		  lower_optic_threshold, upper_optic_threshold,
		  lower_tx_power_threshold, upper_tx_power_threshold));

	/* GTC */
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GTC_CFG_GET, &gtc_cfg, sizeof(gtc_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	memcpy(&gtc_cfg_old, &gtc_cfg, sizeof(gtc_cfg));

	gtc_cfg.sf_threshold = sf_threshold;
	gtc_cfg.sd_threshold = sd_threshold;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GTC_CFG_SET, &gtc_cfg, sizeof(gtc_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* GPE */
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_CFG_GET, &gpe_cfg, sizeof(gpe_cfg));
	if (ret != OMCI_API_SUCCESS)
		goto restore;

	memcpy(&gpe_cfg_old, &gpe_cfg, sizeof(gpe_cfg));

	gpe_cfg.gem_blk_len = gem_block_len;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_CFG_SET, &gpe_cfg, sizeof(gpe_cfg));
	if (ret != OMCI_API_SUCCESS)
		goto restore;

#if 0
	/* GOI */
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GOI_CFG_GET,
					     &GOI_cfg, sizeof(GOI_cfg));
	if (ret != OMCI_API_SUCCESS)
		goto GPE_Restore;

	GOI_cfg.nRxOpticalPowerUpperLimit = lower_optic_threshold;
	GOI_cfg.nRxOpticalPowerLowerLimit = upper_optic_threshold;
	GOI_cfg.nTxOpticalPowerUpperLimit = lower_tx_power_threshold;
	GOI_cfg.nTxOpticalPowerLowerLimit = upper_tx_power_threshold;

	GOI_cfg.nOpticalPowerCheckInterval =
	    OMCI_API_ANIG_GOI_POWER_CHECK_INTERVAL;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GOI_CFG_SET,
					     &GOI_cfg, sizeof(GOI_cfg));
	if (ret != OMCI_API_SUCCESS)
		goto GPE_Restore;

	return ret;

GPE_Restore:
	(void)dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_CFG_SET, &gpe_cfg_old,
		      sizeof(gpe_cfg_old));
#endif

	return ret;

restore:
	(void)dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GTC_CFG_SET, &gtc_cfg_old, sizeof(gtc_cfg_old));
	(void)dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_CFG_SET, &gpe_cfg_old, sizeof(gpe_cfg_old));

	return ret;
}

enum omci_api_return omci_api_ani_g_sr_indication_get(struct omci_api_ctx *ctx,
						      uint16_t me_id,
						      uint8_t *sr_indication)
{
	*sr_indication = 1;
	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_ani_g_total_tcon_num_get(struct omci_api_ctx *ctx,
						       uint16_t me_id,
						       uint16_t *total_tcon_num)
{
	/* one T-CONT is always used by OMCI */
	*total_tcon_num = ONU_GPE_MAX_TCONT - 1;
	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_ani_g_response_time_get(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 uint16_t *ont_response_time)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gtc_cfg gtc_cfg;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GTC_CFG_GET, &gtc_cfg, sizeof(gtc_cfg));
	if (ret == OMCI_API_SUCCESS)
		*ont_response_time = gtc_cfg.onu_response_time * 206;
	else
		DBG(OMCI_API_MSG,
			("omci_api_ani_g_response_time_get failed\n"));

	return ret;
}

static float optic_uin16t_to_float(const uint16_t val,
				   const uint16_t shift)
{
	return ((float)val)/(1 << shift);
}

enum omci_api_return
omci_api_ani_g_optical_signal_level_get(struct omci_api_ctx *ctx,
					uint16_t me_id,
					int16_t *optical_signal_level)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct optic_bosa_rx_status status;
	float pwr_mw;

	ret = dev_ctl(ctx->remote, ctx->goi_fd,
		      FIO_BOSA_RX_STATUS_GET, &status, sizeof(status));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("omci_api_ani_g_optical_signal_level_get failed\n"));
		return ret;
	}

	if (status.meas_power_1490_rssi == 0) {
		*optical_signal_level = 0;
	} else {
		pwr_mw = optic_uin16t_to_float(status.meas_power_1490_rssi,
					       OPTIC_FLOAT2INTSHIFT_POWER);

		*optical_signal_level =
			(int16_t)(10.0 * log10(pwr_mw) / 0.002);
	}

	return ret;
}

enum omci_api_return
omci_api_ani_g_laser_bias_current_get(struct omci_api_ctx *ctx,
				      uint16_t me_id,
				      uint16_t *laser_bias_current)
{
	enum omci_api_return ret;
	struct bosa_tx_status status;

	memset(&status, 0, sizeof(status));
	ret = dev_ctl(ctx->remote, ctx->goi_fd,
		      FIO_BOSA_TX_STATUS_GET_751, &status, sizeof(status));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("omci_api_ani_g_laser_bias_current_get failed\n"));
		return ret;
	}

	/* G.988 Table 9.2.1: laser bias current in units of 2 uA.
	   bias_current is fixed-point [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT (8).
	   raw / 256 = mA, mA / 0.002 = units of 2 uA.
	   So: (raw * 500) >> 8.  Clamp to uint16_t max. */
	{
		uint32_t val = ((uint32_t)status.bias_current * 500) >> 8;
		*laser_bias_current = (val > 0xFFFF) ? 0xFFFF : (uint16_t)val;
	}

	return ret;
}

enum omci_api_return
omci_api_ani_g_laser_temperature_get(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     int16_t *temperature)
{
	enum omci_api_return ret;
	struct optic_temperature temp;

	memset(&temp, 0, sizeof(temp));
	ret = dev_ctl(ctx->remote, ctx->goi_fd,
		      FIO_MM_LASER_TEMPERATURE_GET, &temp, sizeof(temp));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("omci_api_ani_g_laser_temperature_get failed\n"));
		return ret;
	}

	/* G.988 Table 9.2.1: temperature in units of 1/256 degree C.
	   optic_temperature is in Kelvin, 0xFFFF = invalid.
	   Convert: (K - 273) * 256.  Invalid → -128 (0xFF80). */
	if (temp.temperature == 0xFFFF)
		*temperature = (int16_t)-128;
	else
		*temperature = (int16_t)((temp.temperature - 273) * 256);

	return ret;
}

enum omci_api_return
omci_api_ani_g_supply_voltage_get(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t *supply_voltage)
{
	enum omci_api_return ret;
	struct mm_supply_voltage volt;

	memset(&volt, 0, sizeof(volt));
	ret = dev_ctl(ctx->remote, ctx->goi_fd,
		      FIO_MM_SUPPLY_VOLTAGE_GET, &volt, sizeof(volt));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("omci_api_ani_g_supply_voltage_get failed\n"));
		return ret;
	}

	/* G.988 Table 9.2.1: supply voltage in units of 20 mV.
	   voltage_val is [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE (14).
	   raw / 16384 = V, V / 0.020 = units of 20 mV.
	   So: (raw * 50 + 10) >> 14.  +10 for rounding. */
	*supply_voltage =
		(uint16_t)((volt.voltage_val * 50 + 10) >> 14);

	return ret;
}

enum omci_api_return
omci_api_ani_g_gem_block_len_get(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 uint16_t *gem_block_len)
{
	enum omci_api_return ret;
	struct gpe_cfg gpe_cfg;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_CFG_GET, &gpe_cfg, sizeof(gpe_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("omci_api_ani_g_gem_block_len_get failed\n"));
		return ret;
	}

	*gem_block_len = gpe_cfg.gem_blk_len;
	return ret;
}

enum omci_api_return
omci_api_ani_g_tx_optical_level_get(struct omci_api_ctx *ctx,
				    uint16_t me_id,
				    int16_t *tx_optical_level)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct bosa_tx_status status;
	float pwr_mw, bias_current, modulation_current, laser_threshold,
	      slope_efficiency;

	memset(&status, 0, sizeof(status));
	ret = dev_ctl(ctx->remote, ctx->goi_fd,
		      FIO_BOSA_TX_STATUS_GET_751, &status, sizeof(status));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_MSG,
			("omci_api_ani_g_tx_optical_level_get failed\n"));
		return ret;
	}

	bias_current =
		optic_uin16t_to_float(status.bias_current,
				      OPTIC_FLOAT2INTSHIFT_CURRENT);
	modulation_current =
		optic_uin16t_to_float(status.modulation_current,
				      OPTIC_FLOAT2INTSHIFT_CURRENT);
	laser_threshold =
		optic_uin16t_to_float(status.laser_threshold,
				      OPTIC_FLOAT2INTSHIFT_CURRENT);
	slope_efficiency =
		optic_uin16t_to_float(status.slope_efficiency,
				      OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY);

	pwr_mw = slope_efficiency * ((bias_current + modulation_current) / 2
							- laser_threshold);
	/* slope_efficiency [uW], so [uW] -> [mW] */
	pwr_mw *= 0.001;

	*tx_optical_level = (pwr_mw == 0) ?
				0 : (int16_t)(10.0 * log10(pwr_mw) / 0.002);

	return ret;
}

/** @} */
