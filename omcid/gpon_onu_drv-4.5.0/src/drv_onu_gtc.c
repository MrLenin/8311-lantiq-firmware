/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_gtc.c
   This is the GPON GTC program file, used for Lantiq's FALCON GPON Modem
   driver.
*/

#include "ifxos_time.h"
#include "drv_onu_api.h"
#include "drv_onu_ploam_api.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_ll_gtc.h"
#include "drv_onu_gtc_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_octrlg.h"
#include "drv_onu_ll_ictrlg.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_event_interface.h"

#define UNUSED_PARAM_DEV (void)p_dev
#define UNUSED_PARAM (void)param

extern void ploam_fsm_state_set(struct ploam_context *ploam_ctx,
				enum ploam_state new_state);

/** GPON power saving modes */
enum gtc_power_saving_mode gpon_op_mode;

/** \defgroup ONU_MAPI_REFERENCE ONU Driver Reference
   @{
*/

/** \addtogroup ONU_GTC
   @{
*/

/** The gtc_init function is called upon GPON startup to provide initial
    settings for the GTC hardware module.
*/
enum onu_errorcode gtc_init(struct onu_device *p_dev,
			    const struct gtc_init_data *param)
{
	if (gtc_ll_init(p_dev->ploam_ctx, param) != 0)
		return ONU_STATUS_ERR;

	return ONU_STATUS_OK;
}

/** The gtc_cfg_set function is used to provide basic configurations of the
    GTC hardware module.
*/
/** Hardware Programming Details
    - nGEM_BlockLength
      This variable defines the counting unit for GEM blocks, given in number
      of bytes. This is used, for example, to calculate the number of received
      or transmitted blocks from the number of received and transmitted bytes.
      The hardware uses this value for DBRu report generation.
      The default value is 48.
      The register that holds the GEM block size in FDMA is OCTRLG.CFG0.IBS.

    - gem_payload_size_max
      This variable defines the global limit for the GEM frames that are sent
      in upstream direction. In downstream direction, there is no hardware
      limit.
      The register that holds the global GEM frame size limit in
      the FDMA module is OCTRLG.CFG1.GEMPLSIZE.
      The hardware setting is global in the FDMA. If different values are
      configured through OMCI for different GEM-Port-IDs, the smallest
      value of all enabled GEM Port-IDs shall be selected and programmed.

   - \todo ploam_plsu_Enable, ploam_plsu_pattern, ploam_plsu_pattern_len
     If true, a PLSu-like pattern is appended to the serial number PLOAMu
     message. The pattern is programmed in GTCPMAIF.LTSDATA0...19,
     GTCPMAIF.LTSC.LEN, and the function is enabled by GTCPMAIF.LTSC.EN = 1
     Each time a serial number PLOAMu is written to the PLOAM FIFO, the pattern
     must be enabled and then disabled again once the message has been sent.
     -- this function is not available in the FPGA --

   - \todo serial_number_request_threshold
     Defines how many Serial Number responses are sent without receiving an
     ONU ID before the power level is changed (typical value: 10).
     This is not a hardware configuration but controls the PLOAM state machine.
*/
enum onu_errorcode gtc_cfg_set(struct onu_device *p_dev,
			       const struct gtc_cfg *param)
{
	enum onu_errorcode ret = ONU_STATUS_OK;

	if (gtc_bip_interval_set(param->bip_error_interval) != 0)
		ret = GTC_STATUS_VALUE_RANGE_WARN;

	/* nResponseTime
	   This value defines the hardware response time of the ONU, given in
	   units of one microsecond. This shall be configurable in a
	   range of 34 to 36. The related hardware register is GTC_RTIME_3.MRT.
	   The register accepts values in units of 32 byte,
	   which is 205.7613 ns at 1.244 Gbit/s upstream data rate. */
	gtc_w32(param->onu_response_time, upstr_gtc_rtime_3);

	memcpy(&p_dev->ploam_ctx->password[0],
	       &param->password[0], PLOAM_FIELD_PASSWORD_LEN);

	p_dev->ploam_ctx->sf_threshold = param->sf_threshold;
	p_dev->ploam_ctx->sd_threshold = param->sd_threshold;

	gtc_threshold_set(param->sf_threshold, param->sd_threshold);

	gtc_rogue_set(param->rogue_msg_id, param->rogue_msg_rpt,
		      param->rogue_msg_enable);

	p_dev->ploam_ctx->ploam_timeout_1 = param->ploam_timeout_1;
	p_dev->ploam_ctx->ploam_timeout_2 = param->ploam_timeout_2;

	p_dev->ploam_ctx->emergency_stop_state = param->emergency_stop_state;

	return ONU_STATUS_OK;
}

/** The gtc_cfg_get function is used to read back the basic configuration of
    the GTC hardware module.
*/
/*  \remark gtc_cfg_get hardware programming details:
    See gtc_cfg_set.
*/
enum onu_errorcode gtc_cfg_get(struct onu_device *p_dev, struct gtc_cfg *param)
{
	memset(param, 0, sizeof(struct gtc_cfg));

	gtc_ll_cfg_get(&param->bip_error_interval, &param->onu_response_time);

	param->sf_threshold = p_dev->ploam_ctx->sf_threshold;
	param->sd_threshold = p_dev->ploam_ctx->sd_threshold;

	memcpy(&param->password[0], &p_dev->ploam_ctx->password[0], 10);

	gtc_rogue_get(&param->rogue_msg_id, &param->rogue_msg_rpt,
		      &param->rogue_msg_enable);

	param->ploam_timeout_1 = p_dev->ploam_ctx->ploam_timeout_1;
	param->ploam_timeout_2 = p_dev->ploam_ctx->ploam_timeout_2;

	param->emergency_stop_state = p_dev->ploam_ctx->emergency_stop_state;

	return ONU_STATUS_OK;
}

/** The gtc_us_header_cfg_get function reads back the header pattern that is
    used for upstream data transmission.
*/
enum onu_errorcode gtc_us_header_cfg_get(struct onu_device *p_dev,
					 struct gtc_us_header_cfg *param)
{
	uint32_t *data = (uint32_t *)&param->us_pattern[0];
	(void)p_dev;

	memset(param, 0, sizeof(struct gtc_us_header_cfg));

	/* Read the actual length of the header
	   us_header_len = GTC_USHL.LEN (in number of bytes) */
	param->us_header_len = gtc_ll_us_header_cfg_get(data);

	return ONU_STATUS_OK;
}

void gtc_total_berr_update(struct onu_control *ctrl)
{
	ctrl->gtc_total_berr += (uint64_t)gtc_bip_value_get();
}

uint64_t gtc_total_berr_get(struct onu_control *ctrl)
{
	return ctrl->gtc_total_berr;
}

#define GTC_COUNTER_UPDATE(name, val) \
	onu_counter_value_update( \
		&ctrl->gtc_counter[k][ONU_COUNTER_ACC].name, \
		ctrl->gtc_counter[0][ONU_COUNTER_THRESHOLD].name, \
		&ctrl->gtc_counter[1][ONU_COUNTER_THRESHOLD].name, \
		&ctrl->gtc_counter[k][ONU_COUNTER_SHADOW].name, \
		val)

/** Hardware Programming Details
   Read the counter values from the following hardware registers and add the
   difference since the last read to the counter variables:

   All HW counters are of wrap-around type, this must be taken into account
   when adding up. Check GTC_DSCNTRSTAT to find out if a counter overflow has
   happened. Report an error, if the range of a counter has been exceeded
   (counter overflow).

   \remarks There are some GEM-port related counters that are not provided by
            the GTC hardware module.
            These counters are accessed by the gpe_gem_counter_get function.
*/
enum onu_errorcode gtc_counter_update(	struct onu_control *ctrl,
					const uint64_t reset_mask,
					const bool curr,
					void *data)
{
	int ret = 0;
	struct gpe_cnt_octrlg_val octrlg_counter;
	struct gpe_cnt_ictrlg_val ictrlg_counter;
	uint64_t *dest, *tca;
	uint8_t i, k;
	uint32_t gem_herr_1, gem_herr_2, gem_bwmcerr, gem_bwmuerr,
		 gtc_frcbcnt, gtc_fcerrcnt, gtc_fuerrcnt, gtc_frcnt, gem_rxfcnt,
		 alloc_total, alloc_lost;

	if (curr)
		k = ctrl->current_counter ? 1 : 0;
	else
		k = ctrl->current_counter ? 0 : 1;

	if (curr) {
		octrlg_counter_get(&octrlg_counter);
		ictrlg_counter_get(&ictrlg_counter);

		gtc_cnt_get(&gem_herr_1,
			    &gem_herr_2,
			    &gem_bwmcerr,
			    &gem_bwmuerr,
			    &gtc_frcbcnt,
			    &gtc_fcerrcnt,
			    &gtc_fuerrcnt,
			    &gtc_frcnt,
			    &gem_rxfcnt,
			    &alloc_total,
			    &alloc_lost);

		ret |= GTC_COUNTER_UPDATE(bip, gtc_total_berr_get(ctrl));
		ret |= GTC_COUNTER_UPDATE(hec_error_corr, gem_herr_1);
		ret |= GTC_COUNTER_UPDATE(hec_error_uncorr, gem_herr_2);
		ret |= GTC_COUNTER_UPDATE(bwmap_error_corr, gem_bwmcerr);
		ret |= GTC_COUNTER_UPDATE(bwmap_error_uncorr, gem_bwmuerr);
		ret |= GTC_COUNTER_UPDATE(fec_error_corr, gtc_frcbcnt);
		ret |= GTC_COUNTER_UPDATE(fec_words_corr, gtc_fcerrcnt);
		ret |= GTC_COUNTER_UPDATE(fec_words_uncorr, gtc_fuerrcnt);
		ret |= GTC_COUNTER_UPDATE(fec_words_total, gtc_frcnt);
		ret |= GTC_COUNTER_UPDATE(rx_gem_frames_total, gem_rxfcnt);
		ret |= GTC_COUNTER_UPDATE(rx_gem_frames_dropped, gem_herr_2);
		ret |= GTC_COUNTER_UPDATE(rx_oversized_frames,
					  ictrlg_counter.rx_oversized_frames);
		ret |= GTC_COUNTER_UPDATE(omci_drop, ictrlg_counter.omci_drop);
		ret |= GTC_COUNTER_UPDATE(drop, ictrlg_counter.drop);
		ret |= GTC_COUNTER_UPDATE(tx_gem_bytes_total,
					  octrlg_counter.tx_gem_bytes_total);
		ret |= GTC_COUNTER_UPDATE(tx_gem_frames_total,
					  octrlg_counter.tx_gem_frames_total);
		ret |= GTC_COUNTER_UPDATE(tx_gem_idle_frames_total,
					  octrlg_counter.
						      tx_gem_idle_frames_total);
		ret |= GTC_COUNTER_UPDATE(allocations_total, alloc_total);
		ret |= GTC_COUNTER_UPDATE(allocations_lost, alloc_lost);
		if (ret)
			event_add(ctrl, ONU_EVENT_GTC_TCA, NULL, 0);
	}

	if (data)
		memcpy(data, &ctrl->gtc_counter[k][ONU_COUNTER_ACC],
		       sizeof(struct gtc_cnt_value));

	if (curr) {
		dest = (uint64_t *) &ctrl->
				gtc_counter[k][ONU_COUNTER_ACC];
		tca = (uint64_t *) &ctrl->
				gtc_counter[1][ONU_COUNTER_THRESHOLD];
		for (i = 0; i < sizeof(struct gtc_cnt_value) / sizeof(uint64_t);
									  i++) {
			if (reset_mask & (1 << i)) {
				dest[i] = 0;
				tca[i] = 0;
			}
		}
	}

	return ret ? ONU_STATUS_TCA : ONU_STATUS_OK;
}

/** The GTC_ThresholdSet function writes the counter thresholds that are related
    to the GPON TC layer.
*/
enum onu_errorcode gtc_counter_threshold_set(struct onu_device *p_dev,
					     const struct gtc_cnt_value *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	onu_locked_memcpy(&ctrl->cnt_lock,
			  &ctrl->gtc_counter[1][ONU_COUNTER_THRESHOLD], param,
			  sizeof(struct gtc_cnt_value));

	return ONU_STATUS_OK;
}

/** The GTC_ThresholdGet function read back the counter thresholds that are
    related to the GPON TC layer.
*/
enum onu_errorcode gtc_counter_threshold_get(struct onu_device *p_dev,
					     struct gtc_cnt_value *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	memcpy(param, &ctrl->gtc_counter[0][ONU_COUNTER_THRESHOLD],
	       sizeof(struct gtc_cnt_value));

	return ONU_STATUS_OK;
}

/** The GTC_ThresholdGet function read back the counter thresholds that are
    related to the GPON TC layer.
*/
enum onu_errorcode gtc_tca_get(struct onu_device *p_dev,
			       struct gtc_cnt_value *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	onu_locked_memcpy(&ctrl->cnt_lock,
			  param, &ctrl->gtc_counter[1][ONU_COUNTER_THRESHOLD],
			  sizeof(struct gtc_cnt_value));

	return ONU_STATUS_OK;
}

/** The gtc_counter_get function read back the counter set that is related to
    the GPON TC layer.
*/
enum onu_errorcode gtc_counter_get(struct onu_device *p_dev,
				   const struct gtc_cnt_interval *in,
				   struct gtc_counters *out)
{
	struct onu_control *ctrl = p_dev->ctrl;

	onu_interval_counter_update(ctrl, 0, GTC_COUNTER,
				    (uint64_t)in->reset_mask, in->curr,
				    &out->val);

	memcpy(&out->interval, in, sizeof(struct gtc_cnt_interval));

	return ONU_STATUS_OK;
}

/** The gtc_counter_reset function is used to reset the GTC counters to 0.
*/
enum onu_errorcode gtc_counter_reset(struct onu_device *p_dev,
				     const struct gtc_cnt_interval *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	onu_interval_counter_update(ctrl, 0, GTC_COUNTER,
				    (uint64_t)param->reset_mask, param->curr,
				    NULL);

	return ONU_STATUS_OK;
}

/** The gtc_status_get function provides a summary of status information that
    is available for the GPON TC layer hardware.
*/
enum onu_errorcode gtc_status_get(struct onu_device *p_dev,
				  struct gtc_status *param)
{
	struct onu_control *ctrl = p_dev->ctrl;
	struct ploam_context *ploam_ctx =
	    (struct ploam_context *)&ctrl->ploam_ctx;

	gtc_ll_status_get(param);

	/* Physical Equipment Error (PEE) received from OLT through PLOAMd */
	param->ds_physical_equipment_error = ploam_ctx->ds_pee;

	return ONU_STATUS_OK;
}

/** The gtc_alarm_get function provides a summary of alarm information that
    is available for the GPON TC layer hardware.
*/
enum onu_errorcode gtc_alarm_get(struct onu_device *p_dev,
				 struct gtc_alarm *param)
{
	uint32_t dsstat, dsistat, usistat;

	(void)p_dev;

	gtc_ll_alarm_get(&dsstat, &dsistat, NULL, &usistat);

	memset(param, 0, sizeof(struct gtc_alarm));

	param->sig_fail = (dsstat & GTC_DSSTAT_1_SF) ? true : false;
	param->sig_degrade = (dsstat & GTC_DSSTAT_1_SD) ? true : false;
	param->loss_of_signal = (dsstat & GTC_DSSTAT_1_DLOS) ? true : false;
	param->loss_of_gtc_frame =
	    (dsstat & GTC_DSSTAT_1_STATE_MASK) == 0 ? true : false;
	param->loss_of_gtc_superframe =
	    (dsstat & GTC_DSSTAT_1_SFSTATE_MASK) == 0 ? true : false;
	param->ploam_rx_error = (dsstat & GTC_DSSTAT_1_RXCRCE) ? true : false;
	param->ploam_rx_buffer_error =
	    (dsstat & GTC_DSSTAT_1_RXOFL) ? true : false;
	param->plen_warning =
	    (dsstat & GTC_DSSTAT_1_PLSTAT_MASK) == GTC_DSSTAT_1_PLSTAT_WARN ?
	    true : false;
	param->plen_error =
	    (dsstat & GTC_DSSTAT_1_PLSTAT_MASK) == GTC_DSSTAT_1_PLSTAT_ERR ?
	    true : false;

	/** \todo check for register to indicate upstream counter
	    overflow indication in GPE */
	param->counter_overflow =
			(dsistat & GTC_DSISTAT_1_CNTOFL) ? true : false;
	param->loss_of_gem_frame =
			(dsistat & GTC_DSISTAT_1_GEMLOF) ? true : false;
	param->gem_frame_starvation =
			(dsistat & GTC_DSISTAT_1_GEMSTV) ? true : false;
	/* clear GTC DS interrupt status register */
	gtc_ll_dsistat_set(dsistat & (GTC_DSISTAT_1_CNTOFL |
				      GTC_DSISTAT_1_GEMLOF |
				      GTC_DSISTAT_1_GEMSTV));

	param->ploam_tx_buffer_error =
	    (usistat & GTC_USISTAT_TXOFL) ? true : false;

	/* clear GTC US interrupt status register */
	gtc_ll_usistat_set(usistat & GTC_USISTAT_TXOFL);

	/* Get GTC BW-Map Interrupt Status Register */
	param->loss_of_allocation = gtc_ll_bwmstat_get();
	/** \note  we either use the bwm trace (with interrupt cleraring
	the bits) or we just observe the alarm status by calling this
	function
	*/
	/* ... and clear it */
	gtc_ll_bwmstat_set(param->loss_of_allocation);

	/* this flag is set if any of the below flags is set */
	if (param->sig_fail | param->sig_degrade | param->loss_of_signal |
	    param->loss_of_gtc_frame | param->loss_of_gtc_superframe |
	    param->ploam_rx_error | param->ploam_rx_buffer_error |
	    param->plen_warning | param->plen_error | param->counter_overflow |
	    param->loss_of_gem_frame | param->gem_frame_starvation |
	    param->ploam_tx_buffer_error | param->loss_of_allocation) {
		param->alarm = true;
	} else {
		param->alarm = true;
	}

	return ONU_STATUS_OK;
}

/** The gtc_ranging_get function is used to read back the equalization delay
    values that are negotiated between OLT and ONU during ONU startup.
*/
enum onu_errorcode gtc_ranging_get(struct onu_device *p_dev,
				   struct gtc_ranging_val *param)
{
	(void)p_dev;

	param->random_delay = gtc_random_delay_get();
	param->preassigned_delay = gtc_preassigned_delay_get();
	param->ranged_delay = gtc_ranged_delay_get();
	param->ranged_delay_enable = gtc_ranged_delay_is_enable();

	return ONU_STATUS_OK;
}

/** The gtc_dying_gasp_cfg_set function is used to define the contents of the
    "Dying Gasp" PLOAMu message that is automatically generated by hardware and
    to enable the hardware-controlled message generation.
*/
enum onu_errorcode gtc_dying_gasp_cfg_set(struct onu_device *p_dev,
					  const struct gtc_dgasp_msg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	memcpy(&ctrl->dying_gasp_msg[0], &param->dying_gasp_msg[0], 12);

	if (gtc_dying_gasp_message_set(param) != 0)
		return ONU_STATUS_ERR;

	return ONU_STATUS_OK;
}

/** The gtc_dying_gasp_cfg_get function is used to read back the "Dying Gasp"
    message configuration. It delivers the information, if the automatic mode is
    selected and the message contents.
*/
enum onu_errorcode gtc_dying_gasp_cfg_get(struct onu_device *p_dev,
					  struct gtc_dgasp_msg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	param->dying_gasp_auto =
	    gtc_r32(upstr_gtc_uscon) & GTC_USCON_EN_DG_EN ? true : false;

	memcpy(&param->dying_gasp_msg[0], &ctrl->dying_gasp_msg[0], 12);

	return ONU_STATUS_OK;
}

/** The gtc_no_message_cfg_set function is used to define the contents of the
    "No Message" PLOAMu message that is automatically generated by hardware.
    By default, an all-zero message text is sent.
*/
enum onu_errorcode gtc_no_message_cfg_set(struct onu_device *p_dev,
					  const struct gtc_no_msg_msg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	memcpy(&ctrl->no_msg, &param->no_msg[0], 12);

	/* unscrambled message option */
	if (param->no_msg_is_scrambled == false) {
		/* xor the message payload bytes with the scrambling pattern
		   (no change for byte 0 and 1). See ITU-T G.984.3,
		   chapter A4. */
		ctrl->no_msg[2] ^= 0xFE;
		ctrl->no_msg[3] ^= 0x04;
		ctrl->no_msg[4] ^= 0x18;
		ctrl->no_msg[5] ^= 0x51;
		ctrl->no_msg[6] ^= 0xE4;
		ctrl->no_msg[7] ^= 0x59;
		ctrl->no_msg[8] ^= 0xD4;
		ctrl->no_msg[9] ^= 0xFA;
		ctrl->no_msg[10] ^= 0x1C;
		ctrl->no_msg[11] ^= 0x49;
	}

	if (gtc_no_message_set((union ploam_up_msg *)&ctrl->no_msg[0]) != 0)
		return ONU_STATUS_ERR;

	return ONU_STATUS_OK;
}

/** The gtc_no_message_cfg_get function is used to read back the "No Message"
    message configuration.
*/
enum onu_errorcode gtc_no_message_cfg_get(struct onu_device *p_dev,
					  struct gtc_no_msg_msg *param)
{
	struct onu_control *ctrl = p_dev->ctrl;

	param->no_msg_is_scrambled = ctrl->no_msg_is_scrambled;
	memcpy(&param->no_msg[0], &ctrl->no_msg, 12);

	return ONU_STATUS_OK;
}

/** The gtc_power_saving_mode_set function is used to select one of multiple
    power saving modes.
*/
enum onu_errorcode gtc_power_saving_mode_set(struct onu_device *p_dev,
					     const struct gtc_op_mode *param)
{
	UNUSED_PARAM_DEV;

	switch (param->gpon_op_mode) {
	case GPON_POWER_SAVING_MODE_OFF:
		gtc_dozing_enable(false);
		gtc_tx_enable(true);
		gtc_ploam_request_only_enable(false);
		gpon_op_mode = param->gpon_op_mode;
		break;

	case GPON_POWER_SAVING_DEEP_SLEEP:
		gtc_tx_enable(false);
		gpon_op_mode = param->gpon_op_mode;
		break;

	case GPON_POWER_SAVING_FAST_SLEEP:
		/* reserved, currently not supported */
		return GTC_STATUS_NO_SUPPORT;

	case GPON_POWER_SAVING_DOZING:
		gtc_dozing_enable(true);
		gtc_tx_enable(true);
		gtc_ploam_request_only_enable(false);
		gpon_op_mode = param->gpon_op_mode;
		break;

	case GPON_POWER_SAVING_POWER_SHEDDING:
		/* reserved, currently not supported */
		return GTC_STATUS_NO_SUPPORT;
	}

	return ONU_STATUS_OK;
}

/** The gtc_power_saving_mode_get function is used to read back the selected
    power saving mode.
*/
enum onu_errorcode gtc_power_saving_mode_get(struct onu_device *p_dev,
					     struct gtc_op_mode *param)
{
	UNUSED_PARAM_DEV;

	param->gpon_op_mode = gpon_op_mode;

	return ONU_STATUS_OK;
}

/** The gtc_ploam_send function accepts the contents of a PLOAM upstream
    message and places it in the send buffer. A repetition factor can be
    assigned to send the message multiple times. If the send buffer is already
    full, an error is reported.

    \todo this ioctl makes problems: PLOAM state machine will send own messages
          --> this function is intended to be used either by the PLOAM SM itself
              or for debugging purposes, no collision should occur during normal
              operation

*/
enum onu_errorcode gtc_ploam_send(struct onu_device *p_dev,
				  const struct gtc_ploamu *param)
{
	union ploam_up_msg m;

	UNUSED_PARAM_DEV;

	m.message.msg_id = param->msg_id;
	m.message.onu_id = param->onu_id;
	memcpy(&m.message.content[0], &param->data[0], 10);

	if (gtc_ploam_wr(&m, param->repeat) != 0)
		return ONU_STATUS_ERR;

	return ONU_STATUS_OK;
}

/** The gtc_ploam_receive functions reads the PLOAMd receive buffer and
    delivers the message contents. If the receive buffer is empty or a receive
    buffer overflow has been detected, an error is reported.

    \todo this ioctl makes problems: PLOAM state machine should read out
          message an put in buffer --> see above
*/
enum onu_errorcode gtc_ploam_receive(struct onu_device *p_dev,
				     struct gtc_ploamd *param)
{
	struct ploam_msg m;

	UNUSED_PARAM_DEV;

	if (gtc_ploam_rd(&m, NULL, NULL) <= 0) {
		memset(param, 0x00, sizeof(struct gtc_ploamd));
		return ONU_STATUS_ERR;
	}

	param->onu_id = m.onu_id;
	param->msg_id = m.msg_id;
	memcpy(&param->data[0], &m.content[0], 10);

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_serial_number_set(struct onu_device *p_dev,
					 const struct gtc_serial_num *param)
{
	struct ploam_context *ploam_ctx = p_dev->ploam_ctx;

	memcpy(&ploam_ctx->vendor_sn[0],
	       &param->serial_number[0], PLOAM_FIELD_SN_LEN);

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_serial_number_get(struct onu_device *p_dev,
					 struct gtc_serial_num *param)
{
	struct ploam_context *ploam_ctx = p_dev->ploam_ctx;

	memcpy(&param->serial_number[0],
	       &ploam_ctx->vendor_sn[0], PLOAM_FIELD_SN_LEN);

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_password_set(struct onu_device *p_dev,
				    const struct gtc_password *param)
{
	struct ploam_context *ploam_ctx = p_dev->ploam_ctx;

	memcpy(&ploam_ctx->password[0],
	       &param->password[0], PLOAM_FIELD_PASSWORD_LEN);

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_password_get(struct onu_device *p_dev,
				    struct gtc_password *param)
{
	struct ploam_context *ploam_ctx = p_dev->ploam_ctx;

	memcpy(&param->password[0],
	       &ploam_ctx->password[0], PLOAM_FIELD_PASSWORD_LEN);

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_forced_alloc_set(struct onu_device *p_dev,
					const struct gtc_forced_alloc *param)
{
	uint32_t val;

	UNUSED_PARAM_DEV;

	if (param->start_time > 19438)
		return ONU_STATUS_ERR;

	if ((param->stop_time < param->start_time) ||
	    (param->stop_time > 19438))
		return ONU_STATUS_ERR;

	if (param->alloc_id > 4095)
		return ONU_STATUS_ERR;

	if (param->enable) {
		gtc_w32_mask(0, GTC_USTEST_BWMOD_SW, upstr_gtc_ustest);

		val = param->stop_time & GTC_BWMAPWL_SSTOP_MASK;
		val |= ((param->start_time << GTC_BWMAPWL_SSTART_OFFSET) &
			GTC_BWMAPWL_SSTART_MASK);
		gtc_w32(val, upstr_gtc_bwmapwl);

		val = param->flags & GTC_BWMAPWH_FLAGS_MASK;
		val |= ((param->alloc_id << GTC_BWMAPWH_ALLOCID_OFFSET) &
			GTC_BWMAPWH_ALLOCID_MASK);
		gtc_w32(val, upstr_gtc_bwmapwh);
	} else {
		gtc_w32_mask(GTC_USTEST_BWMOD_SW, 0, upstr_gtc_ustest);
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_forced_alloc_get(struct onu_device *p_dev,
					struct gtc_forced_alloc *param)
{
	uint32_t val;

	UNUSED_PARAM_DEV;

	param->enable = gtc_r32(upstr_gtc_ustest) &
	    GTC_USTEST_BWMOD_SW ? true : false;

	val = gtc_r32(upstr_gtc_bwmapwl);
	param->stop_time = val & GTC_BWMAPWL_SSTOP_MASK;
	param->start_time = ((val & GTC_BWMAPWL_SSTART_MASK) >>
			     GTC_BWMAPWL_SSTART_OFFSET);

	val = gtc_r32(upstr_gtc_bwmapwh);
	param->flags = val & GTC_BWMAPWH_FLAGS_MASK;
	param->alloc_id = ((val & GTC_BWMAPWH_ALLOCID_MASK) >>
			   GTC_BWMAPWH_ALLOCID_OFFSET);

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_bwmt_cfg_set(struct onu_device *p_dev,
				    const struct gtc_bwmt_cfg *param)
{
	uint32_t mask = 0;

	if (param->overhead_size_enable)
		mask |= GTC_BWMMASK_OVH_SZ;
	if (param->data_size_enable)
		mask |= GTC_BWMMASK_DAT_SZ;
	if (param->parity_size_enable)
		mask |= GTC_BWMMASK_PAR_SZ;
	if (param->start_time_enable)
		mask |= GTC_BWMMASK_START;
	if (param->stop_time_enable)
		mask |= GTC_BWMMASK_STOP;
	if (param->start_stop_enable)
		mask |= GTC_BWMMASK_MIN_TC;
	if (param->plou_enable)
		mask |= GTC_BWMMASK_PLOGAP;
	if (param->overlap_enable)
		mask |= GTC_BWMMASK_TCOVLP;
	if (param->no_gem_enable)
		mask |= GTC_BWMMASK_NO_GEM;
	if (param->sw_trigger)
		mask |= GTC_BWMMASK_SWT;

	gtc_w32(mask, upstr_gtc_bwmmask);

	if (param->trace_enable) {
		gtc_w32_mask(0, GTC_BWMT_CTRL_TRACE_EN, upstr_gtc_bwmt_ctrl);
		gtc_w32(p_dev->ploam_ctx->usimask | GTC_USIMASK_TRACE,
			upstr_gtc_usimask);
	} else {
		gtc_w32_mask(GTC_BWMT_CTRL_TRACE_EN, 0, upstr_gtc_bwmt_ctrl);
		gtc_w32(p_dev->ploam_ctx->usimask, upstr_gtc_usimask);
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_bwmt_cfg_get(struct onu_device *p_dev,
				    struct gtc_bwmt_cfg *param)
{
	uint32_t mask = 0;

	UNUSED_PARAM_DEV;

	mask = gtc_r32(upstr_gtc_bwmt_ctrl);
	param->trace_enable = (mask & GTC_BWMT_CTRL_TRACE_EN) ? true : false;

	mask = gtc_r32(upstr_gtc_bwmmask);
	param->overhead_size_enable =
	    (mask & GTC_BWMMASK_OVH_SZ) ? true : false;
	param->data_size_enable = (mask & GTC_BWMMASK_DAT_SZ) ? true : false;
	param->parity_size_enable = (mask & GTC_BWMMASK_PAR_SZ) ? true : false;
	param->start_time_enable = (mask & GTC_BWMMASK_START) ? true : false;
	param->stop_time_enable = (mask & GTC_BWMMASK_STOP) ? true : false;
	param->start_stop_enable = (mask & GTC_BWMMASK_MIN_TC) ? true : false;
	param->plou_enable = (mask & GTC_BWMMASK_PLOGAP) ? true : false;
	param->overlap_enable = (mask & GTC_BWMMASK_TCOVLP) ? true : false;
	param->no_gem_enable = (mask & GTC_BWMMASK_NO_GEM) ? true : false;
	param->sw_trigger = (mask & GTC_BWMMASK_SWT) ? true : false;

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_bwmt_next(struct onu_device *p_dev,
				 const struct gtc_bwmt_next_data *param)
{
	UNUSED_PARAM_DEV;

	if (param->trace_start == true) {
		/* trace off */
		gtc_w32_mask(GTC_BWMT_CTRL_TRACE_EN | GTC_BWMT_CTRL_SWT_YES, 0,
			     upstr_gtc_bwmt_ctrl);
		/* release trace buffer */
		gtc_w32_mask(0, GTC_BWMT_CTRL_REL, upstr_gtc_bwmt_ctrl);
		gtc_w32_mask(GTC_BWMT_CTRL_REL, 0, upstr_gtc_bwmt_ctrl);
		/* trace on */
		gtc_w32_mask(0, GTC_BWMT_CTRL_TRACE_EN, upstr_gtc_bwmt_ctrl);
	} else {
		/* software triggered stop */
		gtc_w32_mask(0, GTC_BWMT_CTRL_SWT_YES, upstr_gtc_bwmt_ctrl);
	}

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_us_handle(struct onu_control *ctrl)
{
	struct ploam_context *ploam_ctx = &ctrl->ploam_ctx;
	vuint32_t upstr_gtc_usistat;
	vuint32_t upstr_gtc_frm_range;
	uint16_t sstop_max;
	uint16_t sstart_min;
	uint16_t offset_o5_new = 0xFFFF;

	upstr_gtc_frm_range = gtc_r32(upstr_gtc_frm_range);
	upstr_gtc_usistat = gtc_r32(upstr_gtc_usistat);

	sstop_max = upstr_gtc_frm_range & GTC_FRM_RANGE_MAX_MASK;
	sstart_min = upstr_gtc_frm_range >> GTC_FRM_RANGE_MIN_OFFSET;

	if (upstr_gtc_usistat & GTC_USISTAT_REQE) {
		if(ploam_ctx->sn_mode) {
			if(ploam_ctx->onu_id == ONU_ID_VALUE_BROADCAST) {
				ploam_ctx->rand_delay = onu_random_get(0, 0xF3);
				gtc_random_delay_set(ploam_ctx->rand_delay);
			} else {
				ploam_ctx->rand_delay = 0;
				gtc_random_delay_set(0);
			}
			onu_serial_number_send(ploam_ctx, 1);
		}
	}

	if (upstr_gtc_usistat & GTC_USISTAT_TRACE) {
		ploam_ctx->bwmstat = gtc_r32(upstr_gtc_bwmstat);

		ONU_DEBUG_MSG("GTC_BWMSTAT %08x", ploam_ctx->bwmstat);
		if (gtc_trace_enabled()) {
			event_add(ctrl, ONU_EVENT_BWMAP_TRACE,
					&ploam_ctx->bwmstat, sizeof(uint32_t));
		} else {
			if (ploam_ctx->bwmstat & GTC_BWMSTAT_STOP) {
				ONU_DEBUG_MSG("GTC_BWMSTAT.STOP");
				if (ploam_ctx->curr_state == PLOAM_STATE_O5) {
					if (sstop_max == 65535)
						/* Special case for some OLTs with non-standard
							BWMaps*/
						offset_o5_new = 0;
					else if (sstop_max <= 19439 && (19439 - sstop_max) <= GTC_START_OFFSET_OFFSET_MASK)
						offset_o5_new = 19439 - sstop_max;
					else {
						gtc_w32_mask(0, GTC_BWMT_CTRL_RST_MAX, upstr_gtc_bwmt_ctrl);
						ONU_DEBUG_MSG("GTC_FRM_RANGE.MAX = %d, ignored, offset unchanged.", sstop_max);
					}
					if (offset_o5_new != 0xFFFF) {
						ONU_DEBUG_ERR("Re-range because of new max sstop time %d (new offset %d)",
										sstop_max, offset_o5_new);
						ploam_ctx->offset_o5 = offset_o5_new;
						ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O2);
						onu_ploam_state_change(ctrl,
												  PLOAM_STATE_O2,
												  PLOAM_STATE_O5,
												  ploam_ctx->elapsed_msec);
					}
				} else {
					ONU_DEBUG_MSG("Ignore GTC_BWMSTAT.STOP in state O%d", ploam_ctx->curr_state);
				}
			}
			gtc_w32(0xFFFFFFFF, upstr_gtc_bwmstat);
		}
	}

#ifdef INCLUDE_DEBUG_SUPPORT
	if (upstr_gtc_usistat & GTC_USISTAT_TXFUL_INT)
		ONU_DEBUG_MSG(
			"GTC_USISTAT_TXFUL_INT");

	if (upstr_gtc_usistat & GTC_USISTAT_TXOFL)
		ONU_DEBUG_MSG(
			"GTC_USISTAT_TXOFL");

	if (upstr_gtc_usistat & GTC_USISTAT_MINSST)
		ONU_DEBUG_MSG(
			"GTC_USISTAT_MINSST (OFFSET does not match SSTART)");
#endif

	if (upstr_gtc_usistat & GTC_USISTAT_EMPTY)
		gtc_ploam_wr(NULL, 0);

	if (upstr_gtc_usistat & GTC_USISTAT_RANGE) {
		/* Exclude some special cases */
		if (sstop_max == 65535 && sstart_min == 65535) {
			ONU_DEBUG_MSG("GTC_USISTAT_RANGE %d/%d (Ignore)",
			   sstart_min, sstop_max);
		} else if (sstop_max >= 19439 && sstart_min == 0) {
			ONU_DEBUG_MSG("GTC_USISTAT_RANGE %d/%d (Ignore)",
			   sstart_min, sstop_max);
		} else {
			if (ploam_ctx->sstart_min > sstart_min) {
				ploam_ctx->sstart_min = sstart_min;
				ONU_DEBUG_MSG("GTC_USISTAT_RANGE %d/%d, "
					      "sstart_min changed",
							ploam_ctx->sstart_min,
							sstop_max);
			} else {
				ONU_DEBUG_MSG("GTC_USISTAT_RANGE %d/%d, "
					      "sstart_min unchanged",
							sstart_min, sstop_max);
			}
		}
	}

	gtc_w32(upstr_gtc_usistat & gtc_r32(upstr_gtc_usimask),
		upstr_gtc_usistat);

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_bwmt_status_get(struct onu_device *p_dev,
				       struct gtc_bwmt_status *param)
{
	uint32_t mask = p_dev->ploam_ctx->bwmstat;

	param->overhead_size_enable =
	    (mask & GTC_BWMSTAT_OVH_SZ) ? true : false;
	param->data_size_enable = (mask & GTC_BWMSTAT_DAT_SZ) ? true : false;
	param->parity_size_enable = (mask & GTC_BWMSTAT_PAR_SZ) ? true : false;
	param->start_time_enable = (mask & GTC_BWMSTAT_START) ? true : false;
	param->stop_time_enable = (mask & GTC_BWMSTAT_STOP) ? true : false;
	param->start_stop_enable = (mask & GTC_BWMSTAT_MIN_TC) ? true : false;
	param->plou_enable = (mask & GTC_BWMSTAT_PLOGAP) ? true : false;
	param->overlap_enable = (mask & GTC_BWMSTAT_TCOVLP) ? true : false;
	param->no_gem_enable = (mask & GTC_BWMSTAT_NO_GEM) ? true : false;
	param->sw_trigger = (mask & GTC_BWMMASK_SWT) ? true : false;

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_last_change_time_get(struct onu_device *p_dev,
					    struct gtc_last_change_time *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	struct ploam_context *ploam_ctx =
				(struct ploam_context *)&ctrl->ploam_ctx;

	param->time =
		ploam_ctx->previous_state != PLOAM_STATE_O0 ?
		   onu_elapsed_time_sec_get(ploam_ctx->o5_change_elapsed_sec) :
		   0;

	return ONU_STATUS_OK;
}

enum onu_errorcode gtc_pon_id_get(struct onu_device *p_dev,
				  struct gtc_pon_id *param)
{
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
	struct ploam_context *ploam_ctx =
				(struct ploam_context *)&ctrl->ploam_ctx;

	param->reach_extender_present =
	  ploam_ctx->pon_id.type & 0x80 ? 1 : 0;
	param->odn_class =
	  (ploam_ctx->pon_id.type >> 4) & 0x07;
	memcpy(&param->olt_tx_power, &ploam_ctx->pon_id.olt_tx_power, 2);
	memcpy(&param->pon_id[0], &ploam_ctx->pon_id.id[0], 7);

	return ONU_STATUS_OK;
}

const struct onu_entry gtc_func_tbl[] = {
	TE1in(FIO_GTC_INIT,
	      sizeof(struct gtc_init_data),
	      gtc_init),
	TE1in(FIO_GTC_CFG_SET,
	      sizeof(struct gtc_cfg),
	      gtc_cfg_set),
	TE1out(FIO_GTC_CFG_GET,
	       sizeof(struct gtc_cfg),
	       gtc_cfg_get),
	TE1out(FIO_GTC_US_HEADER_CFG_GET,
	       sizeof(struct gtc_us_header_cfg),
	       gtc_us_header_cfg_get),
	TE1out(FIO_GTC_STATUS_GET,
	       sizeof(struct gtc_status),
	       gtc_status_get),
	TE1out(FIO_GTC_ALARM_GET,
	       sizeof(struct gtc_alarm),
	       gtc_alarm_get),
	TE1out(FIO_GTC_RANGING_GET,
	       sizeof(struct gtc_ranging_val),
	       gtc_ranging_get),
	TE1in(FIO_GTC_DYING_GASP_CFG_SET,
	      sizeof(struct gtc_dgasp_msg),
	      gtc_dying_gasp_cfg_set),
	TE1out(FIO_GTC_DYING_GASP_CFG_GET,
	       sizeof(struct gtc_dgasp_msg),
	       gtc_dying_gasp_cfg_get),
	TE1in(FIO_GTC_NO_MESSAGE_CFG_SET,
	      sizeof(struct gtc_no_msg_msg),
	      gtc_no_message_cfg_set),
	TE1out(FIO_GTC_NO_MESSAGE_CFG_GET,
	       sizeof(struct gtc_no_msg_msg),
	       gtc_no_message_cfg_get),
	TE1in(FIO_GTC_POWER_SAVING_MODE_SET,
	      sizeof(struct gtc_op_mode),
	      gtc_power_saving_mode_set),
	TE1out(FIO_GTC_POWER_SAVING_MODE_GET,
	       sizeof(struct gtc_op_mode),
	       gtc_power_saving_mode_get),
	TE1in_opt(FIO_GTC_PLOAM_SEND,
	      sizeof(struct gtc_ploamu),
	      gtc_ploam_send),
	TE1out_opt(FIO_GTC_PLOAM_RECEIVE,
	       sizeof(struct gtc_ploamd),
	       gtc_ploam_receive),
	TE2(FIO_GTC_COUNTER_GET,
		sizeof(struct gtc_cnt_interval),
		sizeof(struct gtc_cnt_value),
		gtc_counter_get),
	TE1in(FIO_GTC_COUNTER_THRESHOLD_SET,
	      sizeof(struct gtc_cnt_value),
	      gtc_counter_threshold_set),
	TE1out(FIO_GTC_COUNTER_THRESHOLD_GET,
	       sizeof(struct gtc_cnt_value),
	       gtc_counter_threshold_get),
	TE1out(FIO_GTC_TCA_GET,
	       sizeof(struct gtc_cnt_value),
	       gtc_tca_get),
	TE1in(FIO_GTC_COUNTER_RESET,
		sizeof(struct gtc_cnt_interval),
		gtc_counter_reset),
	TE1in(FIO_GTC_SERIAL_NUMBER_SET,
	      sizeof(struct gtc_serial_num),
	      gtc_serial_number_set),
	TE1out(FIO_GTC_SERIAL_NUMBER_GET,
	       sizeof(struct gtc_serial_num),
	       gtc_serial_number_get),
	TE1in(FIO_GTC_PASSWORD_SET,
	      sizeof(struct gtc_password),
	      gtc_password_set),
	TE1out(FIO_GTC_PASSWORD_GET,
	       sizeof(struct gtc_password),
	       gtc_password_get),
	TE1in(FIO_GTC_FORCED_ALLOC_SET,
	      sizeof(struct gtc_forced_alloc),
	      gtc_forced_alloc_set),
	TE1out(FIO_GTC_FORCED_ALLOC_GET,
	       sizeof(struct gtc_forced_alloc),
	       gtc_forced_alloc_get),
	TE1in(FIO_GTC_BWMT_CFG_SET,
	      sizeof(struct gtc_bwmt_cfg),
	      gtc_bwmt_cfg_set),
	TE1out(FIO_GTC_BWMT_CFG_GET,
	       sizeof(struct gtc_bwmt_cfg),
	       gtc_bwmt_cfg_get),
	TE1in(FIO_GTC_BWMT_NEXT,
	      sizeof(struct gtc_bwmt_next_data),
	      gtc_bwmt_next),
	TE1out(FIO_GTC_BWMT_STATUS_GET,
	       sizeof(struct gtc_bwmt_status),
	       gtc_bwmt_status_get),
	TE1out(FIO_GTC_LAST_CHANGE_TIME_GET,
	       sizeof(struct gtc_last_change_time),
	       gtc_last_change_time_get),
	TE1out(FIO_GTC_PON_ID_GET,
	       sizeof(struct gtc_pon_id),
	       gtc_pon_id_get)
};

const unsigned int gtc_func_tbl_size = ARRAY_SIZE(gtc_func_tbl);

/*! @} */

/*! @} */
