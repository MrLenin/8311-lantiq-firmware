/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "ifxos_time.h"
#include "drv_onu_api.h"
#include "drv_onu_ploam_api.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_ll_gtc.h"
#include "drv_onu_timer.h"
#include "drv_onu_gtc_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_iqm.h"
#include "drv_onu_ll_octrlg.h"
#include "drv_onu_ll_fsqm.h"
#include "drv_onu_ll_ictrlg.h"
#include "drv_onu_ll_ictrll.h"

extern int gem_port_remove(const uint16_t gem_port_id);
void ploam_fsm_state_set(struct ploam_context *ploam_ctx,
				enum ploam_state new_state);
STATIC void ploam_fsm_cleanup(struct ploam_context *ploam_ctx);
int optic_ll_tx_laserdelay_set ( const uint8_t bitdelay );
int optic_powerlevel_set ( const uint8_t powerlevel );
int goi_lts_trigger ( void );
void optic_tx_enable (bool enable);

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \addtogroup PLOAM_INTERNAL
   @{
*/

/**
   Compare own serial number with given

   \return true if equal
   \return false otherwise
*/
STATIC int onu_sn_equal(const uint8_t *sn1, const uint8_t *sn2)
{
	return memcmp(sn1, sn2, PLOAM_FIELD_SN_LEN) == 0 ? true : false;
}

/**
   Send acknowledge to given message

   \param msg The message to acknowledge

   \return 0
*/
int ploam_ack_send(union ploam_dn_msg *msg)
{
	union ploam_up_msg msg_up;

	ONU_DEBUG_MSG("Send ack on msg_id=0x%04x", msg->message.msg_id);

	msg_up.ack.msg_id = PLOAM_UP_ACKNOWLEDGE;
	msg_up.ack.onu_id = msg->message.onu_id;
	msg_up.ack.dm_id = msg->message.msg_id;

	/* copy part of the ds message to the ack bufffer */
	memcpy(msg_up.ack.dm_byte, &msg->message, 9);

	onu_ploam_log(ONU_EVENT_PLOAM_US, &msg_up, sizeof(msg_up));

	gtc_ploam_wr(&msg_up, 1);

	return 0;
}

int onu_serial_number_send(struct ploam_context *ploam_ctx,
					const uint8_t repeat)
{
	union ploam_up_msg msg_up;

	memset(&msg_up, 0, sizeof(union ploam_up_msg));
	msg_up.sn.msg_id = PLOAM_UP_SERIAL_NUMBER_ONU;
	msg_up.sn.onu_id = ploam_ctx->onu_id;
	memcpy(&msg_up.sn.vendor_id[0], &ploam_ctx->vendor_sn[0], 4);
	memcpy(&msg_up.sn.vendor_sn[0], &ploam_ctx->vendor_sn[4], 4);
	msg_up.sn.random_delay[0] = (ploam_ctx->rand_delay >> 4) & 0xFF;
	/* GEM supported, medium power */
	msg_up.sn.random_delay[1] = (ploam_ctx->rand_delay << 4) | 0x04 | 0x01;

	ONU_DEBUG_MSG("onu_serial_number_send %02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x",
			 msg_up.sn.vendor_id[0],
			 msg_up.sn.vendor_id[1],
			 msg_up.sn.vendor_id[2],
			 msg_up.sn.vendor_id[3],
			 msg_up.sn.vendor_sn[0],
			 msg_up.sn.vendor_sn[1],
			 msg_up.sn.vendor_sn[2],
			 msg_up.sn.vendor_sn[3] );

	onu_ploam_log(ONU_EVENT_PLOAM_US,
			&msg_up,
			sizeof(msg_up));

	goi_lts_trigger();
	gtc_ploam_wr(&msg_up, repeat);

	return 0;
}

STATIC INLINE int onu_rei_send(struct ploam_context *ploam_ctx)
{
	union ploam_up_msg msg_up;
	uint32_t val = gtc_bip_value_get();

	memset(&msg_up, 0, sizeof(union ploam_up_msg));
	msg_up.rei.msg_id = PLOAM_UP_REI;
	msg_up.rei.onu_id = ploam_ctx->onu_id;
	msg_up.rei.err_count[0] = (val >> 24) & 0xFF;
	msg_up.rei.err_count[1] = (val >> 16) & 0xFF;
	msg_up.rei.err_count[2] = (val >> 8) & 0xFF;
	msg_up.rei.err_count[3] = (val >> 0) & 0xFF;
	msg_up.rei.seq_num = ploam_ctx->rei_seq_num++;

	onu_ploam_log(ONU_EVENT_PLOAM_US, &msg_up, sizeof(msg_up));

	gtc_ploam_wr(&msg_up, 1);

	return 0;
}

/**
   The ONU sets the pre-assigned delay

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o2_us_oh_handle(struct ploam_context *ploam_ctx,
				      union ploam_dn_msg *msg)
{
	ONU_DEBUG_MSG("FSM O2 - creation of Upstream Header");

	ploam_ctx->guard_bits = msg->up_overhead.num_guard_bits;
	ploam_ctx->t1_bits = msg->up_overhead.num_t1_preamble_bits;
	ploam_ctx->t2_bits = msg->up_overhead.num_t2_preamble_bits;
	ploam_ctx->t3_pattern = msg->up_overhead.t3_preamble_pattern;

	ploam_ctx->t3_pre_ranged_bits = ploam_ctx->t3_ranged_bits =
	    (96 -
	     msg->up_overhead.num_guard_bits -
	     msg->up_overhead.num_t1_preamble_bits -
	     msg->up_overhead.num_t2_preamble_bits - 24 /* delimiter size */ );

	ONU_DEBUG_MSG("FSM O2 - t3_pre_ranged_bits %d / t3_ranged_bits %d",
		      ploam_ctx->t3_pre_ranged_bits, ploam_ctx->t3_ranged_bits);

	ploam_ctx->delimiter[0] = msg->up_overhead.delimiter_byte1;
	ploam_ctx->delimiter[1] = msg->up_overhead.delimiter_byte2;
	ploam_ctx->delimiter[2] = msg->up_overhead.delimiter_byte3;

	if (msg->up_overhead.flags & 0x20) {
		ploam_ctx->padelay =
		    msg->up_overhead.eql_delay[0] << 8 | msg->up_overhead.
		    eql_delay[1];
	} else {
		ploam_ctx->padelay = 0;
	}

	ploam_ctx->onu_id = ONU_ID_VALUE_BROADCAST;
	ploam_ctx->omci_port_id = ONU_ID_VALUE_BROADCAST;
	ploam_ctx->rand_delay = onu_random_get(0, 0xF3);
	gtc_random_delay_set(ploam_ctx->rand_delay);
	gtc_preassigned_delay_set(ploam_ctx->padelay);
	optic_ll_tx_laserdelay_set( 0 );
	ploam_ctx->fine_ranged_delay = 0xffffffff;
	ONU_DEBUG_MSG("FSM O2 using random delay = 0x%x",
		      ploam_ctx->rand_delay);
	ONU_DEBUG_MSG("FSM O2 using pre-assigned delay = 0x%x",
		      ploam_ctx->padelay);

	gtc_ranged_delay_enable(false);

	ploam_ctx->powerlevel = 0;
	switch (msg->up_overhead.flags & PLOAM_POWER_LEVEL_MODE_MASK) {
	case PLOAM_POWER_LEVEL_MODE_NORMAL:
		ONU_DEBUG_MSG("FSM O2 - using normal power level mode");
		break;
	case PLOAM_POWER_LEVEL_MODE_NORMAL_3DB:
		ONU_DEBUG_MSG("FSM O2 using -3db power level mode");
		ploam_ctx->powerlevel = 1;
		break;
	case PLOAM_POWER_LEVEL_MODE_NORMAL_6DB:
		ONU_DEBUG_MSG("FSM O2 using -6db power level mode");
		ploam_ctx->powerlevel = 2;
		break;
	case PLOAM_POWER_LEVEL_MODE_NORMAL_RES:
		ONU_DEBUG_WRN("FSM O2 - using reserved power level mode");
		break;
	}
	optic_powerlevel_set( ploam_ctx->powerlevel );

	gtc_threshold_set(ploam_ctx->sf_threshold, ploam_ctx->sd_threshold);

	gtc_onu_id_set(0xFF);

	octrlg_tcont_set(OMCI_TCIX, 0xFE);
	gtc_tcont_set(OMCI_TCIX, 0xFE);

	ploam_ctx->offset_curr = 0;
	ploam_ctx->offset_corr = 0;

	gtc_tx_enable(false);

	if (gtc_upstream_header_create(ploam_ctx->guard_bits,
				       ploam_ctx->t1_bits,
				       ploam_ctx->t2_bits,
				       ploam_ctx->t3_pre_ranged_bits,
				       ploam_ctx->t3_pattern,
				       ploam_ctx->delimiter) != 0) {
		ONU_DEBUG_ERR("FSM O2 - creation of Upstream Header failed");
		return -1;
	}

	gtc_offset_set(ploam_ctx->guard_bits +
		       ploam_ctx->t1_bits +
		       ploam_ctx->t2_bits +
		       ploam_ctx->t3_pre_ranged_bits + 24,
		       ploam_ctx->sstart_min, &ploam_ctx->offset_curr);

	gtc_delay_adjust(false);

	gtc_ploam_request_only_enable(true);
	gtc_tx_enable(true);

	onu_serial_number_send(ploam_ctx, 1);

	ploam_ctx->sn_mode = true;
	onu_timer_start(ONU_TIMER_TO1, ploam_ctx->ploam_timeout_1);
	ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O3);

	return 0;
}

/**
   Disable option: Moves the ONU to the Emergency Stop state. The ONU
   cannot respond to upstream bandwidth allocations.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return 0 If message was handled
*/
STATIC INLINE int fsm_o2_dis_ser_num_handle(struct ploam_context *ploam_ctx,
					    union ploam_dn_msg *msg)
{
	if ((onu_sn_equal(ploam_ctx->vendor_sn, msg->disable_sn.serial_number)
	     && msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ONE)
	    || msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ALL) {

		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O7);

	}

	return 0;
}

/**
   The ONU with this serial number sets its ONU-ID and also its Default
   Alloc-ID

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o3_assign_onu_id_handle(struct ploam_context *ploam_ctx,
					      union ploam_dn_msg *msg)
{
	if (ploam_ctx->ds_repeat_count) {
		ONU_DEBUG_MSG
		    ("FSM O3 assign ONU-ID message, repeated - ignored");
		return 0;
	}

	ONU_DEBUG_MSG("FSM O3 - received Assign_ONU-ID "
		      "message with ONU-ID = 0x%x",
		      msg->assign_onu_id.assign_onu_id);

	if (onu_sn_equal(ploam_ctx->vendor_sn,
				msg->assign_onu_id.serial_number) == false) {
		ONU_DEBUG_MSG("FSM O3 - received Assign_ONU-ID "
			      "message with wrong serial number");
		return -1;
	}

	/* check received ONU-ID */
	if (msg->assign_onu_id.assign_onu_id > 253) {
		ONU_DEBUG_MSG("FSM O3 - received Assign_ONU-ID "
			      "message with wrong ONU-ID = 0x%x",
			      msg->assign_onu_id.assign_onu_id);
		return -1;
	}

	gtc_ploam_flush();

	ploam_ctx->onu_id = msg->assign_onu_id.assign_onu_id;

	gtc_onu_id_set(ploam_ctx->onu_id);

	ploam_ctx->rand_delay = 0;
	gtc_random_delay_set(0);

	onu_serial_number_send(ploam_ctx, 1);

	octrlg_tcont_set(OMCI_TCIX, ploam_ctx->onu_id);
	gtc_tcont_set(OMCI_TCIX, ploam_ctx->onu_id);

	octrlg_w32_table(ploam_ctx->onu_id, gpixtable, OMCI_GPIX);

	gtc_offset_set(ploam_ctx->guard_bits +
		       ploam_ctx->t1_bits +
		       ploam_ctx->t2_bits +
		       ploam_ctx->t3_pre_ranged_bits + 24,
		       ploam_ctx->sstart_min, &ploam_ctx->offset_curr);

	ONU_DEBUG_MSG("FSM O3 assign ONU-ID = 0x%02x", ploam_ctx->onu_id);
	ONU_DEBUG_MSG("FSM O3->O4 received Assign_ONU-ID message");

	ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O4);

	return 0;
}

/**
   Disable option: Moves the ONU to the Emergency Stop state. The ONU
   cannot respond to upstream bandwidth allocations.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return 0 If message was handled
*/
STATIC INLINE int fsm_o3_dis_ser_num_handle(struct ploam_context *ploam_ctx,
					    union ploam_dn_msg *msg)
{
	if (ploam_ctx->ds_repeat_count)
		return 0;

	if ((onu_sn_equal(ploam_ctx->vendor_sn, msg->disable_sn.serial_number)
	     && msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ONE)
	    || msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ALL) {

		onu_timer_stop(ONU_TIMER_TO1);
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O7);

	}

	return 0;
}

/**
   The ONU sets the type 3 preamble length.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o3_ext_burst_len_handle(struct ploam_context *ploam_ctx,
					      union ploam_dn_msg *msg)
{
	uint16_t val_max;

	if (ploam_ctx->ds_repeat_count)
		return 0;

	val_max = ploam_ctx->t3_pre_ranged_bits =
	    msg->extended_burst_len.num_t3_pb_preranged * 8;
	ploam_ctx->t3_ranged_bits =
	    msg->extended_burst_len.num_t3_pb_ranged * 8;
	if (ploam_ctx->t3_ranged_bits > val_max)
		val_max = ploam_ctx->t3_ranged_bits;

	ONU_DEBUG_MSG("FSM O3 - t3_pre_ranged_bits %d / t3_ranged_bits %d",
		      ploam_ctx->t3_pre_ranged_bits, ploam_ctx->t3_ranged_bits);

	gtc_tx_enable(false);

	/* Recalculate upstream header pattern */
	if (gtc_upstream_header_create(ploam_ctx->guard_bits,
				       ploam_ctx->t1_bits,
				       ploam_ctx->t2_bits,
				       ploam_ctx->t3_pre_ranged_bits,
				       ploam_ctx->t3_pattern,
				       ploam_ctx->delimiter) != 0) {

		ONU_DEBUG_ERR("FSM O3 - creation of Upstream Header failed");
		return -1;
	}

	gtc_offset_set(ploam_ctx->guard_bits +
		       ploam_ctx->t1_bits +
		       ploam_ctx->t2_bits +
		       val_max + 24,
		       ploam_ctx->sstart_min, &ploam_ctx->offset_curr);

	gtc_delay_adjust(false);
	gtc_tx_enable(true);

	return 0;
}

/**
   The ONU fills in the equalization delay register with this value.
   The protection path EqD is not supported.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o4_rng_time_handle(struct ploam_context *ploam_ctx,
					 union ploam_dn_msg *msg)
{
	uint16_t tmp_off;

	onu_timer_stop(ONU_TIMER_TO1);

	ploam_ctx->ranged_delay = msg->ranging_time.delay[0] << 24 |
	    msg->ranging_time.delay[1] << 16 |
	    msg->ranging_time.delay[2] << 8 | msg->ranging_time.delay[3];

	gtc_ranged_delay_set(ploam_ctx->ranged_delay);
	gtc_ranged_delay_enable(true);
	ploam_ctx->sn_mode = false;

	ONU_DEBUG_MSG("FSM O4 using RangedDelay=0x%x (corrected 0x%x)",
			      ploam_ctx->ranged_delay, ploam_ctx->ranged_delay);

	ONU_DEBUG_MSG("FSM O4->O5 enable upstream transmission");
	ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O5);

	gtc_tx_enable(false);
	if (ploam_ctx->t3_pre_ranged_bits != ploam_ctx->t3_ranged_bits) {

		/* Recalculate upstream header pattern */
		if (gtc_upstream_header_create(ploam_ctx->guard_bits,
					       ploam_ctx->t1_bits,
					       ploam_ctx->t2_bits,
					       ploam_ctx->t3_ranged_bits,
					       ploam_ctx->t3_pattern,
					       ploam_ctx->delimiter) != 0) {

			ONU_DEBUG_ERR
			    ("FSM O4 - creation of Upstream Header failed");
			return -1;
		}
		gtc_delay_adjust(false);

	}

	tmp_off = ploam_ctx->offset_curr;

	if (ploam_ctx->offset_o5 == 0xFFFF) {
		gtc_offset_set(ploam_ctx->guard_bits +
					ploam_ctx->t1_bits +
					ploam_ctx->t2_bits +
					ploam_ctx->t3_ranged_bits + 24,
					ploam_ctx->sstart_min,
					&ploam_ctx->offset_curr);
	} else {
		/* Here we use a forced START_OFFSET value for State O5.
		 * It was learned from a previous ranging when a need
		 * to change the OFFSET arose. */
		ploam_ctx->offset_curr = ploam_ctx->offset_o5;
		gtc_w32(ploam_ctx->offset_o5, upstr_gtc_start_offset);
		ONU_DEBUG_MSG("Forced O5 OFFSET: %d", ploam_ctx->offset_o5);
	}

	if (ploam_ctx->offset_curr != tmp_off) {
		ploam_ctx->offset_corr = (tmp_off - ploam_ctx->offset_curr) * 8;

		gtc_ranged_delay_set(ploam_ctx->ranged_delay +
						ploam_ctx->offset_corr);

		ONU_DEBUG_MSG("FSM O4 using corrected RangedDelay=0x%x",
						ploam_ctx->ranged_delay +
							ploam_ctx->offset_corr);
	}

	gtc_tx_enable(true);
	gtc_ploam_request_only_enable(false);

	return 0;
}

/**
   The ONU with this ONU-ID switches off the laser; the ONU-ID, OMCI
   Port-ID, and all Alloc-ID, assignments are discarded. ONU moves to the
   Standby state.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o4_deact_onu_id_handle(struct ploam_context *ploam_ctx,
					     union ploam_dn_msg *msg)
{
	(void)msg;
	onu_timer_stop(ONU_TIMER_TO1);
	ONU_DEBUG_WRN("FSM O4->O2 received Deactivate_ONUID message");
	ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O2);
	return 0;
}

/**
   Disable option: Moves the ONU to the Emergency Stop state. The ONU
   cannot respond to upstream bandwidth allocations.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return 0 If message was handled
*/
STATIC INLINE int fsm_o4_dis_ser_num_handle(struct ploam_context *ploam_ctx,
					    union ploam_dn_msg *msg)
{
	if ((onu_sn_equal(ploam_ctx->vendor_sn, msg->disable_sn.serial_number)
	     && msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ONE)
	    || msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ALL) {

		onu_timer_stop(ONU_TIMER_TO1);
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O7);

	}

	return 0;
}

/**
   ONU adjusts its transmitted power level accordingly.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o4_change_pwr_lvl_handle(struct ploam_context *ploam_ctx,
					       union ploam_dn_msg *msg)
{
	if (msg->chg_pow_lvl.ctrl == PLOAM_CPL_INCREASE) {
		ONU_DEBUG_MSG("FSM O4 increasing power level");
		if(ploam_ctx->powerlevel > 0)
			ploam_ctx->powerlevel--;
	} else if (msg->chg_pow_lvl.ctrl == PLOAM_CPL_DECREASE) {
		ONU_DEBUG_MSG("FSM O4 decreasing power level");
		if(ploam_ctx->powerlevel < 2)
			ploam_ctx->powerlevel++;
	} else {
		ONU_DEBUG_WRN("FSM O4 no action (CPL ctrl=0x%04x)",
			      msg->chg_pow_lvl.ctrl);
		return 0;
	}

	optic_powerlevel_set ( ploam_ctx->powerlevel );

	return 0;
}

/**
   The ONU fills in the equalization delay register with this value.
   The protection path EqD is not supported.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_rng_time_handle(struct ploam_context *ploam_ctx,
					 union ploam_dn_msg *msg)
{
	uint32_t dif = 0;
	uint32_t tmp = msg->ranging_time.delay[0] << 24 |
	    msg->ranging_time.delay[1] << 16 |
	    msg->ranging_time.delay[2] << 8 | msg->ranging_time.delay[3];
	uint32_t val = ploam_ctx->ranged_delay + ploam_ctx->offset_corr;

	if (tmp > ploam_ctx->ranged_delay) {
		dif = tmp - ploam_ctx->ranged_delay;
	} else {
		dif = ploam_ctx->ranged_delay - tmp;
	}
	ONU_DEBUG_MSG("FSM O5 old RangedDelay=0x%x old "
		      "RangedDelay=0x%x diff=%d", ploam_ctx->ranged_delay,
						  tmp, dif);
	ploam_ctx->ranged_delay = tmp;

	if (dif < 5) {
		if (ploam_ctx->fine_ranged_delay == 0xffffffff)
			ploam_ctx->fine_ranged_delay = tmp;
		else
			ploam_ctx->fine_ranged_delay =
				      (ploam_ctx->fine_ranged_delay + tmp) >> 1;

		ONU_DEBUG_MSG("FSM O5 using fine RangedDelay=0x%x",
					ploam_ctx->fine_ranged_delay +
							ploam_ctx->offset_corr);

		gtc_ranged_delay_set(ploam_ctx->fine_ranged_delay +
							ploam_ctx->offset_corr);
	} else {
		ONU_DEBUG_MSG("FSM O5 using RangedDelay=0x%x", val);
		gtc_ranged_delay_set(val);
	}
	gtc_ranged_delay_enable(true);

	ONU_DEBUG_MSG("FSM O5 received Ranging_Time message");
	return 0;
}

/**
   The ONU with this ONU-ID switches off the laser; the ONU-ID, OMCI
   Port-ID, and all Alloc-ID, assignments are discarded. ONU moves to the
   Standby state.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_deact_onu_id_handle(struct ploam_context *ploam_ctx,
					     union ploam_dn_msg *msg)
{
	(void)msg;
	ONU_DEBUG_MSG("FSM O5->O2 received Deactivate_ONUID message");
	ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O2);
	return 0;
}

/**
   Disable option: Moves the ONU to the Emergency Stop state. The ONU
   cannot respond to upstream bandwidth allocations.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_dis_ser_num_handle(struct ploam_context *ploam_ctx,
					    union ploam_dn_msg *msg)
{
	if ((onu_sn_equal(ploam_ctx->vendor_sn, msg->disable_sn.serial_number)
	     && msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ONE)
	    || msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ALL) {

		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O7);

	}

	return 0;
}

/**
   Mark/Unmark this channel as encrypted.  Send 1 acknowledge after each
   correctly received message.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_encr_port_id_handle(struct ploam_context *ploam_ctx,
					     union ploam_dn_msg *msg)
{
	ONU_DEBUG_MSG("FSM O5 received Encrypted_Port-ID message");

	ploam_ack_send(msg);

	if (ploam_ctx->ds_repeat_count)
		return 0;

	/* ignore message with ctrl b==0 (xxxxxxba) */
	if ((msg->enc_portid.ctrl & 0x02) == 0) {
		ONU_DEBUG_WRN("FSM O5 Encrypted_Port-ID message is ignored");
		return 0;
	}

	ONU_DEBUG_MSG("FSM O5 %s Port-ID=0x%03x",
		      (msg->enc_portid.ctrl &
		       PLOAM_ENC_CTRL_ENABLE) ? "encrypt" : "decrypt",
		      (msg->enc_portid.port_id[0] << 8 |
		       msg->enc_portid.port_id[1]) >> 4);

	if (gtc_port_id_encryption_set((msg->enc_portid.port_id[0] << 8 |
					msg->enc_portid.port_id[1]) >> 4,
				       (msg->enc_portid.ctrl &
					PLOAM_ENC_CTRL_ENABLE) ? true :
				       false) != 0) {

		ONU_DEBUG_ERR("FSM O5 - encrypt/decrypt Port-ID failed");
		return -1;
	}

	return 0;
}

/**
   Send the password message 3 times.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_req_pwd_handle(struct ploam_context *ploam_ctx,
					union ploam_dn_msg *msg)
{
	union ploam_up_msg msg_up;

	(void)msg;

	ONU_DEBUG_MSG("FSM O5 received Request_password message");

	memset(&msg_up, 0, sizeof(union ploam_up_msg));
	msg_up.password.msg_id = PLOAM_UP_PASSWORD;
	msg_up.password.onu_id = ploam_ctx->onu_id;

	memcpy(&msg_up.password.data[0], &ploam_ctx->password[0],
	       PLOAM_FIELD_PASSWORD_LEN);

	onu_ploam_log(ONU_EVENT_PLOAM_US,
			&msg_up,
			sizeof(msg_up));

	gtc_ploam_wr(&msg_up, 3);

	return 0;
}

/**
   Send 1 acknowledge after each correctly received message. The ONU shall
   respond to the bandwidth allocations with the specified Alloc- ID. Until
   a T-CONT is properly mapped to the Alloc-ID, the idle GEM frames shall
   be sent.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_assign_alloc_id_handle(struct ploam_context *ploam_ctx,
						union ploam_dn_msg *msg)
{
	uint16_t alloc_id;
	uint32_t repn, pepn;
	uint32_t tcont;

	ploam_ack_send(msg);

	if (ploam_ctx->ds_repeat_count) {
		ONU_DEBUG_MSG
		    ("FSM O5 assign Alloc-ID message, repeated - ignored");
		return 0;
	}

	alloc_id = (msg->assign_alloc_id.alloc_id[0] << 8 |
		    msg->assign_alloc_id.alloc_id[1]) >> 4;

	ONU_DEBUG_MSG("FSM O5 - received Alloc-ID = 0x%03x, type %x", alloc_id,
		      msg->assign_alloc_id.type);

	if (alloc_id >= ONU_GPE_MAX_ALLOCATION_ID) {
		ONU_DEBUG_ERR("FSM O5 - received Alloc-ID = 0x%03x invalid",
			      alloc_id);
		return -1;
	}
	if(alloc_id == 0xff || alloc_id == 0xffff)
		return 0;

	switch (msg->assign_alloc_id.type) {
	case 0x01:
		/* 0x01 = GEM-encapsulated payload (Assign) */
		if (alloc_id == ploam_ctx->onu_id) {
			ONU_DEBUG_MSG("FSM O5 - set OMCI alloc ID");
			if (octrlg_tcont_set(OMCI_TCIX, alloc_id) != 0) {
				ONU_DEBUG_ERR
				    ("FSM O5 - can't assign Alloc-ID "
				     "(== ONU-ID)");
				return -1;
			}

			if (gtc_tcont_set(OMCI_TCIX, alloc_id) != 0) {
				ONU_DEBUG_ERR
				    ("FSM O5 - can't assign Alloc-ID "
				     "(== ONU-ID)");
				return -1;
			}

			ONU_DEBUG_MSG
			    ("FSM O5 - assign Alloc-ID = 0x%03x / "
			     "Tcont Idx 0x%03x (OMCI)", alloc_id, OMCI_TCIX);

		} else {
			uint32_t tmp = 0xffff;
			bool used;
			for (tcont=0; tcont<ONU_GPE_MAX_TCONT; tcont++) {
				if (gtc_tcont_get(tcont, &tmp, &used) == 0) {
					if (tmp != alloc_id)
						continue;
					if (octrlg_tcont_get(tcont,
							     &tmp) != 0) {
						tmp = 0xffff;
					}
					break;
				}
			}

			if (tmp == alloc_id) {
				ONU_DEBUG_ERR("FSM O5 - re-use Alloc-Id 0x%03x /"
				" Tcont Idx 0x%03x", alloc_id, tcont);
			} else {
				if (gtc_tcont_alloc_id_find(&tcont) != 0) {
					ONU_DEBUG_ERR(
					      "FSM O5 - can't find free TCONT");
					return -1;
				}
				if (octrlg_tcont_set(tcont, alloc_id) != 0) {
					ONU_DEBUG_ERR(
					      "FSM O5 - can't assign Alloc-ID");
					return -1;
				}
				if (gtc_tcont_set(tcont, alloc_id) != 0) {
					ONU_DEBUG_ERR(
					      "FSM O5 - can't assign Alloc-ID");
					return -1;
				}
				ONU_DEBUG_MSG(
				         "FSM O5 - assign Alloc-ID = 0x%03x / "
					 "Tcont Idx 0x%03x", alloc_id, tcont);
				if (octrlg_epn_get(tcont, &repn, &pepn) != 0)
					break;
				if (repn == 127)
					break;
				gpe_enqueue_enable(ploam_ctx->ctrl, repn, true);
			}
		}
		break;

	/* 0xff = De-assign this Alloc-ID */
	case 0xff:
		ONU_DEBUG_MSG("FSM O5 - remove traffic alloc ID %d", alloc_id);
		if (alloc_id == ploam_ctx->onu_id)
			break;
		if (octrlg_tcont_alloc_id_get(alloc_id, &tcont) != 0)
			break;
		ONU_DEBUG_MSG("FSM O5 - TCONT index %d", tcont);
		if (octrlg_epn_get(tcont, &repn, &pepn) != 0)
			break;
		if (repn == 127)
			break;
		gpe_enqueue_enable(ploam_ctx->ctrl, repn, false);
		gtc_tcont_alloc_id_remove(alloc_id);
		octrlg_tcont_alloc_id_delete(alloc_id);
		break;
	default:
		ONU_DEBUG_ERR("FSM O5 - Alloc-ID with type field = 0x%02x",
			      msg->assign_alloc_id.type);
		return -1;
	}

	return 0;
}

/**
   Send the Encryption Key message three times.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_req_key_handle(struct ploam_context *ploam_ctx,
					union ploam_dn_msg *msg)
{
	union ploam_up_msg msg_up;
	uint32_t tmp[4], i;

	(void)msg;

	ONU_DEBUG_MSG("FSM O5 received Request_Key message");

	memset(&msg_up, 0, sizeof(union ploam_up_msg));
	msg_up.encrypt_key.msg_id = PLOAM_UP_ENCRYPTION_KEY;
	msg_up.encrypt_key.onu_id = ploam_ctx->onu_id;

	msg_up.encrypt_key.frag_index = 0;

	for (i=0;i<4;i++)
		tmp[i] = onu_random_get(0, 0xFFFFFFFF);

	msg_up.encrypt_key.key[3] = tmp[0] & 0xFF;
	msg_up.encrypt_key.key[2] = (tmp[0] >> 8) & 0xFF;
	msg_up.encrypt_key.key[1] = (tmp[0] >> 16) & 0xFF;
	msg_up.encrypt_key.key[0] = (tmp[0] >> 24) & 0xFF;
	msg_up.encrypt_key.key[7] = tmp[1] & 0xFF;
	msg_up.encrypt_key.key[6] = (tmp[1] >> 8) & 0xFF;
	msg_up.encrypt_key.key[5] = (tmp[1] >> 16) & 0xFF;
	msg_up.encrypt_key.key[4] = (tmp[1] >> 24) & 0xFF;

	msg_up.encrypt_key.frag_index = 0;

	onu_ploam_log(ONU_EVENT_PLOAM_US, &msg_up, sizeof(msg_up));
	gtc_ploam_wr(&msg_up, 3);

	msg_up.encrypt_key.key[3] = tmp[2] & 0xFF;
	msg_up.encrypt_key.key[2] = (tmp[2] >> 8) & 0xFF;
	msg_up.encrypt_key.key[1] = (tmp[2] >> 16) & 0xFF;
	msg_up.encrypt_key.key[0] = (tmp[2] >> 24) & 0xFF;
	msg_up.encrypt_key.key[7] = tmp[3] & 0xFF;
	msg_up.encrypt_key.key[6] = (tmp[3] >> 8) & 0xFF;
	msg_up.encrypt_key.key[5] = (tmp[3] >> 16) & 0xFF;
	msg_up.encrypt_key.key[4] = (tmp[3] >> 24) & 0xFF;

	msg_up.encrypt_key.frag_index = 1;

	onu_ploam_log(ONU_EVENT_PLOAM_US, &msg_up, sizeof(msg_up));

	gtc_ploam_wr(&msg_up, 3);

	gtc_key_set(tmp[3], tmp[2], tmp[1], tmp[0]);

	return 0;
}

/**
   Logical Management port is assigned with the Port-ID. Send 1 acknowledge
   after each correctly received message.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_cfg_port_id_handle(struct ploam_context *ploam_ctx,
					    union ploam_dn_msg *msg)
{
	int error;

	ONU_DEBUG_MSG("FSM O5 received Configure Port-ID message");

	ploam_ack_send(msg);

	if (ploam_ctx->ds_repeat_count) {
		ONU_DEBUG_MSG(
		      "FSM O5 received Configure Port-ID message, "
		     "repeated - ignored");
		return 0;
	}

	if (msg->config_port_id.ctrl & ~0x01) {
		ONU_DEBUG_ERR("FSM O5 - Configure Port-ID with "
			      "ctrl field = 0x%x", msg->config_port_id.ctrl);
		return -1;
	}

	error = 0;
	/* activate */
	if (msg->config_port_id.ctrl & 0x01) {
		/* terminate old OMCI connection if any */
		if (ploam_ctx->omci_port_id != ONU_ID_VALUE_BROADCAST)
			error |= gem_port_remove(ploam_ctx->omci_port_id);

		/* set new OMCI connection */
		ploam_ctx->omci_port_id = (msg->config_port_id.port_id[0] << 8 |
					 msg->config_port_id.port_id[1]) >> 4;

		error |= gtc_port_id_type_set(ploam_ctx->omci_port_id,
					 GTC_RXPID_WR_FT_0_OMCI);
		error |= gtc_port_id_enable(ploam_ctx->omci_port_id, true);
		error |= ictrlg_gem_port_set(ploam_ctx->omci_port_id,
					   true,
					   false,
					   OMCI_GPIX,
					   GPE_DIRECTION_BIDIRECTIONAL);
		error |= octrlg_gem_port_set(ploam_ctx->omci_port_id, OMCI_GPIX,
					   GPE_DIRECTION_BIDIRECTIONAL);

		ONU_DEBUG_MSG("FSM O5 set new OMCI connection %d",
			      ploam_ctx->omci_port_id);
	} else { /* deactivate */
		ONU_DEBUG_MSG("FSM O5 deactivate OMCI connection");
		error |= gem_port_remove(ploam_ctx->omci_port_id);
		ploam_ctx->omci_port_id = ONU_ID_VALUE_BROADCAST;
	}

	if (error != 0) {
		ONU_DEBUG_ERR("FSM O5 - activate/deactivate Port-ID failed");
		return -1;
	}

	return 0;
}

/**
   PEE Alarm is asserted at the ONU.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_phy_eqpmnt_err_handle(struct ploam_context *ploam_ctx,
					       union ploam_dn_msg *msg)
{
	(void)msg;

	ONU_DEBUG_MSG("FSM O5 received PEE message");

	ploam_ctx->ds_pee = true;
	ploam_ctx->ds_count_pee = 0;

/*
   Set software alarm indication.  Clear after 1 s unless another message
   of this type is received. This information is supposed to be used by
   higher layer application software.
*/

	return 0;
}

/**
   ONU adjusts its transmitted power level accordingly.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_change_pwr_lvl_handle(struct ploam_context *ploam_ctx,
					       union ploam_dn_msg *msg)
{
	if (msg->chg_pow_lvl.ctrl == PLOAM_CPL_INCREASE) {
		ONU_DEBUG_MSG("FSM O5 increasing power level");
		if (ploam_ctx->powerlevel < 2)
			ploam_ctx->powerlevel++;
	} else if (msg->chg_pow_lvl.ctrl == PLOAM_CPL_DECREASE) {
		ONU_DEBUG_MSG("FSM O5 decreasing power level");
		if (ploam_ctx->powerlevel > 0)
			ploam_ctx->powerlevel--;
	} else {
		ONU_DEBUG_WRN("FSM O5 no action (CPL ctrl=0x%04x)",
			      msg->chg_pow_lvl.ctrl);
		return 0;
	}

	optic_powerlevel_set ( ploam_ctx->powerlevel );

	return 0;
}

/**
   ONU checks link number, and acts upon APS commands.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int onu_fsm_o5_psthandle(struct ploam_context *ploam_ctx,
				       union ploam_dn_msg *msg)
{
	union ploam_up_msg msg_up;
	(void)ploam_ctx;

	ONU_DEBUG_MSG("FSM O5 received PST message");

	memset(&msg_up, 0, sizeof(union ploam_up_msg));
	msg_up.pst.msg_id = PLOAM_UP_PST;
	msg_up.pst.onu_id = ploam_ctx->onu_id;
	msg_up.pst.k1_byte = msg->pst.k1_byte;
	msg_up.pst.k2_byte = msg->pst.k2_byte;

	onu_ploam_log(ONU_EVENT_PLOAM_US, &msg_up, sizeof(msg_up));

	gtc_ploam_wr(&msg_up, 1);

	return 0;
}

/**
   The ONU starts a timer, and accumulates the downstream errors. An
   acknowledge is sent for each correct message.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_ber_interval_handle(struct ploam_context *ploam_ctx,
					     union ploam_dn_msg *msg)
{
	uint32_t val;

	ploam_ack_send(msg);

	if (ploam_ctx->ds_repeat_count) {
		ONU_DEBUG_MSG(
		     "FSM O5 received BER interval message, "
		     "repeated - ignored");
		return 0;
	}

	val = msg->ber_int.interval[0] << 24 |
	    msg->ber_int.interval[1] << 16 |
	    msg->ber_int.interval[2] << 8 | msg->ber_int.interval[3];

	ONU_DEBUG_MSG("FSM O5 received BER interval message (0x%08x)", val);

	gtc_bip_interval_set(val);
	ploam_ctx->dsimask |= GTC_DSIMASK_1_BERINTV;
	gtc_downstream_imask_set(ploam_ctx->dsimask);

	return 0;
}

/**
   ONU prepares to switch the key at the indicated time. Send 1 acknowledge
   after each correctly received message.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o5_key_switch_time_handle(struct ploam_context *ploam_ctx,
						union ploam_dn_msg *msg)
{
	ONU_DEBUG_MSG("FSM O5 received Key switching Time message");

	ploam_ack_send(msg);

	if (ploam_ctx->ds_repeat_count)
		return 0;

	gtc_switching_time_set(msg->key_switch_time.frame_counter[0] << 24 |
			       msg->key_switch_time.frame_counter[1] << 16 |
			       msg->key_switch_time.frame_counter[2] << 8 |
			       msg->key_switch_time.frame_counter[3]);

	return 0;
}

/**
   The ONU with this ONU-ID switches off the laser; the ONU-ID, OMCI
   Port-ID, and all Alloc-ID, assignments are discarded. ONU moves to the
   Standby state.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o6_deact_onu_id_handle(struct ploam_context *ploam_ctx,
					     union ploam_dn_msg *msg)
{
	(void)msg;

	onu_timer_stop(ONU_TIMER_TO2);
	ONU_DEBUG_MSG("FSM O6->O2 received Deactivate_ONUID message");
	ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O2);

	return 0;
}

/**
   Disable option: Moves the ONU to the Emergency Stop state. The ONU
   cannot respond to upstream bandwidth allocations.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return 0 If message was handled
*/
STATIC INLINE int fsm_o6_dis_ser_num_handle(struct ploam_context *ploam_ctx,
					    union ploam_dn_msg *msg)
{
	if ((onu_sn_equal(ploam_ctx->vendor_sn, msg->disable_sn.serial_number)
	     && msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ONE)
	    || msg->disable_sn.ctrl == PLOAM_DSN_DISABLE_ALL) {

		onu_timer_stop(ONU_TIMER_TO2);
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O7);

	}

	return 0;
}

/**
   The ONU moves to Ranging state (O4), or to Operation state (O5).

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o6_popup_handle(struct ploam_context *ploam_ctx,
				      union ploam_dn_msg *msg)
{
	/* Broadcast POPUP message (PLOAMd = POPUP; with ONU-ID = 0xFF) is
	   received */
	if (msg->message.onu_id == ONU_ID_VALUE_BROADCAST) {
		onu_timer_stop(ONU_TIMER_TO2);
		onu_timer_start(ONU_TIMER_TO1, ploam_ctx->ploam_timeout_1);
		/* Recalculate upstream header pattern with T3PreRanged */
		if (gtc_upstream_header_create(ploam_ctx->guard_bits,
					       ploam_ctx->t1_bits,
					       ploam_ctx->t2_bits,
					       ploam_ctx->t3_pre_ranged_bits,
					       ploam_ctx->t3_pattern,
					       ploam_ctx->delimiter) != 0) {

			ONU_DEBUG_ERR
			    ("FSM O6 - creation of Upstream Header failed");
			return -1;
		}
		gtc_delay_adjust(false);
		gtc_tx_enable(true);
		gtc_ploam_request_only_enable(false);
		ONU_DEBUG_MSG("FSM O6->O4 received broadcast POPUP message");
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O4);
		return 0;
	} else { /* Directed POPUP message (PLOAMd = POPUP;
		    with ONU-ID = ID of ONU) is received */
		onu_timer_stop(ONU_TIMER_TO2);
		gtc_tx_enable(true);
		gtc_ploam_request_only_enable(false);
		ONU_DEBUG_MSG("FSM O5 enable upstream transmission");
		ONU_DEBUG_MSG("FSM O6->O5 received directed POPUP message");
		gtc_delay_adjust(false);
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O5);
		return 0;
	}
}

/**
   Enable option: Moves the ONU to the Standby state. The ONU restarts the
   activation process, as specified in Clause 10.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_o7_dis_ser_num_handle(struct ploam_context *ploam_ctx,
					    union ploam_dn_msg *msg)
{
	if ((msg->disable_sn.ctrl == PLOAM_DSN_ENABLE_ONE &&
	     onu_sn_equal(ploam_ctx->vendor_sn,
				      msg->disable_sn.serial_number) == true)
	    || (msg->disable_sn.ctrl == PLOAM_DSN_ENABLE_ALL)) {
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O2);
		return 0;
	}

	ONU_DEBUG_MSG("FSM O7 "
		      "received Disable_Serial_Number message with "
		      "Disable or SN doesn't match");
	return -1;
}

/**
   Incorrect message handler for O5 state

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1
*/
STATIC INLINE int fsm_o5_incorrect_msg_handle(struct ploam_context *ploam_ctx,
					      union ploam_dn_msg *msg)
{
	(void)ploam_ctx;
	(void)msg;

	return -1;
}

/**
   PON-ID message received.

   \param ploam_ctx The ONU context pointer
   \param msg PLOAMd message pointer to handle

   \return -1 If message was not handled
   \return 0 If message was handled
*/
STATIC INLINE int fsm_pon_id_handle(struct ploam_context *ploam_ctx,
				    union ploam_dn_msg *msg)
{
	memcpy(&ploam_ctx->pon_id, &msg->pon_id, sizeof(struct ploam_dn_pon_id));
	return 0;
}

/**
   O5 state PLOAMd Handler definition
*/
typedef int (*ploam_handler_t) (struct ploam_context *ploam_ctx,
				union ploam_dn_msg *msg);

/**
   O5 state PLOAMd Handler array
*/
ploam_handler_t ploam_o5_handlers[0x14 + 1] = {
	/* 0x00 .. 0x03 not allowed in the O5 state */
	fsm_o5_incorrect_msg_handle,
	fsm_o5_incorrect_msg_handle,
	fsm_o5_incorrect_msg_handle,
	fsm_o5_incorrect_msg_handle,
	/* 0x04 */
	fsm_o5_rng_time_handle,
	/* 0x05 */
	fsm_o5_deact_onu_id_handle,
	/* 0x06 */
	fsm_o5_dis_ser_num_handle,
	/* 0x07 not allowed in the O5 state */
	fsm_o5_incorrect_msg_handle,
	/* 0x08 */
	fsm_o5_encr_port_id_handle,
	/* 0x09 */
	fsm_o5_req_pwd_handle,
	/* 0x0a */
	fsm_o5_assign_alloc_id_handle,
	/* 0x0b not allowed in the O5 state */
	fsm_o5_incorrect_msg_handle,
	/* 0x0c not allowed in the O5 state */
	fsm_o5_incorrect_msg_handle,
	/* 0x0d */
	fsm_o5_req_key_handle,
	/* 0x0e */
	fsm_o5_cfg_port_id_handle,
	/* 0x0f */
	fsm_o5_phy_eqpmnt_err_handle,
	/* 0x10 */
	fsm_o5_change_pwr_lvl_handle,
	/* 0x11 */
	onu_fsm_o5_psthandle,
	/* 0x12 */
	fsm_o5_ber_interval_handle,
	/* 0x13 */
	fsm_o5_key_switch_time_handle,
	/* 0x14 not allowed in the O5 state */
	fsm_o5_incorrect_msg_handle
};

STATIC int fsm_o0(struct ploam_context *ploam_ctx);
STATIC int fsm_o1(struct ploam_context *ploam_ctx);
STATIC int fsm_o2(struct ploam_context *ploam_ctx);
STATIC int fsm_o3(struct ploam_context *ploam_ctx);
STATIC int fsm_o4(struct ploam_context *ploam_ctx);
STATIC int fsm_o5(struct ploam_context *ploam_ctx);
STATIC int fsm_o6(struct ploam_context *ploam_ctx);
STATIC int fsm_o7(struct ploam_context *ploam_ctx);

/**
   The Finite State Machine Handler definition.
*/
typedef int (*onu_fsm_handler_t) (struct ploam_context *ploam_ctx);

/**
   Finite State Machine Handler array.
*/
STATIC onu_fsm_handler_t ploam_fsm_handler[8] = {
	fsm_o0, fsm_o1, fsm_o2, fsm_o3, fsm_o4, fsm_o5, fsm_o6, fsm_o7
};

/**
   ONU Power Up Handler.
   In case that last operational state (before powerdown) was equal O7
   then goto state O7 else to state O1.
   \see 10.2.4 ONU Functional Transitions
*/
STATIC int fsm_o0(struct ploam_context *ploam_ctx)
{
	if (ploam_ctx->emergency_stop_state) {
		ONU_DEBUG_MSG("FSM O0->O7 prev state was O7");
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O7);
	} else {
		ONU_DEBUG_MSG("FSM O0->O1 prev state was not O7");
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O1);
		onu_timer_stop(ONU_TIMER_TO0);
		onu_timer_start(ONU_TIMER_TO0, ONU_TIMER_SYNC_VALUE);
	}

	return 0;
}

/**
   Initial State Handler.
   ONU is switched on and is waiting for downstream frames.
*/
STATIC int fsm_o1(struct ploam_context *ploam_ctx)
{
	/* kill the timer for safety reason */
	onu_timer_stop(ONU_TIMER_TO1);
	onu_timer_stop(ONU_TIMER_TO2);

	gtc_delay_adjust(true);

	/* ONU achieves PSync synchronization */
	if (ploam_ctx->event & PLOAM_GTC_FRAME_SYNC) {
		ONU_DEBUG_MSG("FSM O1->O2 achieved PSync");

		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O2);

		ploam_ctx->event &=
		    ~(PLOAM_GTC_FRAME_SYNC | PLOAM_LOS | PLOAM_LOF);

		if (ploam_ctx->event)
			ONU_DEBUG_ERR("FSM O1 state handle failed %x",
			      ploam_ctx->event);
		return 0;
	}

	ONU_DEBUG_MSG("FSM O1 - no sync yet");

	return -1;
}

STATIC void fsm_los_lof_print(struct ploam_context *ploam_ctx)
{
	if (ploam_ctx->event & PLOAM_LOS)
		ONU_DEBUG_WRN("FSM detected LOS");
	if (ploam_ctx->event & PLOAM_LOF)
		ONU_DEBUG_WRN("FSM detected LOF");
}

/**
   Standby State Handler.
   ONU waits for network parameters.
*/
STATIC int fsm_o2(struct ploam_context *ploam_ctx)
{
	if (ploam_ctx->event & PLOAM_LOS || ploam_ctx->event & PLOAM_LOF) {
		fsm_los_lof_print(ploam_ctx);
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O1);
		ploam_ctx->event &= ~(PLOAM_LOS | PLOAM_LOF);
		return 0;
	}

	if (ploam_ctx->event & PLOAM_MSG_RECEIVED) {
		ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;
		switch (ploam_ctx->ds_msg.msg_id) {

		case PLOAM_DN_UPSTREAM_OVERHEAD:
			return fsm_o2_us_oh_handle(ploam_ctx,
						   (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);

		case PLOAM_DN_DISABLE_SERIAL_NUM:
			return fsm_o2_dis_ser_num_handle(ploam_ctx,
							 (union ploam_dn_msg *)
							    &ploam_ctx->ds_msg);
			return 0;

		case PLOAM_DN_NO_MESSAGE:
			ONU_DEBUG_MSG("FSM O3 PLOAM_DN_NO_MESSAGE ignored");
			return 0;

		case PLOAM_DN_DEACTIVE_ONU_ID:
			ONU_DEBUG_MSG
			    ("FSM O2 PLOAM_DN_DEACTIVE_ONU_ID ignored");
			return 0;

		default:
			ONU_DEBUG_ERR("FSM O2: message id %x not handled",
				      ploam_ctx->ds_msg.msg_id);
		}
	}

	if (ploam_ctx->event)
		ONU_DEBUG_ERR("FSM O2 state handle failed %x",
			      ploam_ctx->event);

	return -1;
}

/**
   Serial Number State Handler.
   ONU waits for Serial Number Request.
*/
STATIC int fsm_o3(struct ploam_context *ploam_ctx)
{
	/* ONU detects LOS or LOF */
	if (ploam_ctx->event & PLOAM_LOS || ploam_ctx->event & PLOAM_LOF) {
		onu_timer_stop(ONU_TIMER_TO1);
		fsm_los_lof_print(ploam_ctx);
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O1);
		ploam_ctx->event &= ~(PLOAM_LOS | PLOAM_LOF);
		return 0;
	}

	/* Timer TO1 expires */
	if (ploam_ctx->event & PLOAM_TO1_EXPIRED) {
		ONU_DEBUG_MSG("FSM O3->O2 TO1 expired");
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O2);
		ploam_ctx->event &= ~PLOAM_TO1_EXPIRED;
		return 0;
	}

	/* BER expired */
	if (ploam_ctx->event & PLOAM_BER_EXPIRED) {
		ploam_ctx->event &= ~PLOAM_BER_EXPIRED;
	}

	if (ploam_ctx->event & PLOAM_MSG_RECEIVED) {
		ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;

		if (ploam_ctx->ds_msg.msg_id == PLOAM_DN_EXTENDED_BURST_LEN)
			fsm_o3_ext_burst_len_handle(ploam_ctx,
						    (union ploam_dn_msg*)
							& ploam_ctx->ds_msg);
		else if (ploam_ctx->ds_msg.msg_id == PLOAM_DN_ASSIGN_ONU_ID)
			fsm_o3_assign_onu_id_handle(ploam_ctx,
						    (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
		else if (ploam_ctx->ds_msg.msg_id ==
			   PLOAM_DN_DISABLE_SERIAL_NUM)
			fsm_o3_dis_ser_num_handle(ploam_ctx,
						  (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
		else if (ploam_ctx->ds_msg.msg_id ==
			   PLOAM_DN_UPSTREAM_OVERHEAD) {
			ONU_DEBUG_MSG
			    ("FSM O3 PLOAM_DN_UPSTREAM_OVERHEAD ignored");
		} else if (ploam_ctx->ds_msg.msg_id == PLOAM_DN_NO_MESSAGE)
			ONU_DEBUG_MSG("FSM O3 PLOAM_DN_NO_MESSAGE ignored");
	}

	if (ploam_ctx->event)
		ONU_DEBUG_ERR("FSM O3 state handle failed %x",
			      ploam_ctx->event);

	return 0;
}

/**
   Ranging State Handler.
   ONU waits for Ranging Request.
*/
STATIC int fsm_o4(struct ploam_context *ploam_ctx)
{
	/* ONU detects LOS or LOF */
	if (ploam_ctx->event & PLOAM_LOS || ploam_ctx->event & PLOAM_LOF) {
		onu_timer_stop(ONU_TIMER_TO1);
		fsm_los_lof_print(ploam_ctx);
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O1);
		ploam_ctx->event &= ~(PLOAM_LOS | PLOAM_LOF);
		return 0;
	}

	/* Timer TO1 expires */
	if (ploam_ctx->event & PLOAM_TO1_EXPIRED) {
		ONU_DEBUG_MSG("FSM O4->O2 TO1 expired");
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O2);
		ploam_ctx->event &= ~PLOAM_TO1_EXPIRED;
		return 0;
	}

	/* BER expired */
	if (ploam_ctx->event & PLOAM_BER_EXPIRED) {
		ploam_ctx->event &= ~PLOAM_BER_EXPIRED;
		ONU_DEBUG_MSG("FSM O4 REI");
		gtc_refresh_rdi();
		onu_rei_send(ploam_ctx);
	}

	/* PLOAMd message received */
	if (ploam_ctx->event & PLOAM_MSG_RECEIVED) {
		ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;

		switch (ploam_ctx->ds_msg.msg_id) {
			/* The ONU receives a Change_Power_Level message */
		case PLOAM_DN_CHANGE_POWER_LEVEL:
			fsm_o4_change_pwr_lvl_handle(ploam_ctx,
						    (union ploam_dn_msg *)
							& ploam_ctx->ds_msg);
			break;

		/* The ONU receives its Equalization Delay
		   (PLOAMd = Ranging_Time) */
		case PLOAM_DN_RANGING_TIME:
			ploam_ctx->sn_mode = false;
			gtc_ploam_flush();
			fsm_o4_rng_time_handle(ploam_ctx,
					       (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
			break;

		/* The ONU receives Deactivation message
		   (PLOAMd = Deactivate_ONUID) */
		case PLOAM_DN_DEACTIVE_ONU_ID:
			fsm_o4_deact_onu_id_handle(ploam_ctx,
						   (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
			break;

		/* The ONU receives Disable message
		   (PLOAMd = Disable_Serial_Number) with Disable */
		case PLOAM_DN_DISABLE_SERIAL_NUM:
			fsm_o4_dis_ser_num_handle(ploam_ctx,
						  (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
			break;

		case PLOAM_DN_ASSIGN_ONU_ID:
			ONU_DEBUG_MSG("FSM O4 PLOAM_DN_ASSIGN_ONU_ID ignored");
			break;

		default:
			ONU_DEBUG_WRN("FSM O4 PLOAM msg %x ignored",
				      ploam_ctx->ds_msg.msg_id);
			break;
		}
	}

	if (ploam_ctx->event)
		ONU_DEBUG_ERR("FSM O4 state handle failed %x",
			      ploam_ctx->event);

	return 0;
}

/**
   Operation State Handler.
   ONU receives and transmits data.
*/
STATIC int fsm_o5(struct ploam_context *ploam_ctx)
{
	/* ONU detects LOS or LOF */
	if (ploam_ctx->event & PLOAM_LOS || ploam_ctx->event & PLOAM_LOF) {
		gtc_tx_enable(false);
		onu_timer_start(ONU_TIMER_TO2, ploam_ctx->ploam_timeout_2);
		ONU_DEBUG_MSG("FSM O5 disable upstream transmission");
		fsm_los_lof_print(ploam_ctx);
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O6);
		ploam_ctx->event &= ~(PLOAM_LOS | PLOAM_LOF);
		return 0;
	}

	/* BER expired */
	if (ploam_ctx->event & PLOAM_BER_EXPIRED) {
		ploam_ctx->event &= ~PLOAM_BER_EXPIRED;
		ONU_DEBUG_MSG("FSM O5 REI");
		gtc_refresh_rdi();
		onu_rei_send(ploam_ctx);
	}

	/* PLOAMd message received */
	if (ploam_ctx->event & PLOAM_MSG_RECEIVED) {
		ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;

      /** The ONU received:
         - Change_Power_Level message
         - its Equalization Delay (PLOAMd = Ranging_Time)
         - Deactivation message (PLOAMd = Deactivate_ONUID)
         - Encrypted_Port-ID message
         - Request_password message
         - Assign_Alloc-ID message
         - Request_Key message
         - Configure Port-ID message
         - PEE message
         - PST message
         - BER interval message
         - Key switching Time message
         - Disable message (PLOAMd = Disable_Serial_Number) with Disable */

		/* note! The bounds are checked in the gtc_ploam_rd;
		   this check is used to shut up the klocwork */
		ONU_DEBUG_MSG("FSM O5 received message %d",
			      ploam_ctx->ds_msg.msg_id);
		if (ploam_ctx->ds_msg.msg_id > 0
		    && ploam_ctx->ds_msg.msg_id < 21) {
			ploam_o5_handlers[ploam_ctx->ds_msg.msg_id](ploam_ctx,
				(union ploam_dn_msg *) &ploam_ctx->ds_msg);
		}
	}

	if (ploam_ctx->event)
		ONU_DEBUG_ERR("FSM O5 state handle failed %x",
			      ploam_ctx->event);

	return 0;
}

/**
   POPUP State Handler.
   ONU asserts LOS/LOF.
*/
STATIC int fsm_o6(struct ploam_context *ploam_ctx)
{
	if (ploam_ctx->event & PLOAM_LOS || ploam_ctx->event & PLOAM_LOF)
		ploam_ctx->event &= ~(PLOAM_LOS | PLOAM_LOF);
		/* nothing to do - we are already in state 6 */

	/* Timer TO2 expires */
	if (ploam_ctx->event & PLOAM_TO2_EXPIRED) {
		ONU_DEBUG_MSG("FSM O6->O1 TO2 expired");
		ploam_fsm_state_set(ploam_ctx, PLOAM_STATE_O1);
		ploam_ctx->event &= ~PLOAM_TO2_EXPIRED;
		ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;
		return 0;
	}

	/* BER expired */
	if (ploam_ctx->event & PLOAM_BER_EXPIRED) {
		ploam_ctx->event &= ~PLOAM_BER_EXPIRED;
		ONU_DEBUG_MSG("FSM O6 REI");
		gtc_refresh_rdi();
		onu_rei_send(ploam_ctx);
	}

	/* PLOAMd message received */
	if (ploam_ctx->event & PLOAM_MSG_RECEIVED) {
		ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;

		/* The ONU receives Deactivation message
		   (PLOAMd = Deactivate_ONUID) */
		if (ploam_ctx->ds_msg.msg_id == PLOAM_DN_DEACTIVE_ONU_ID) {
			fsm_o6_deact_onu_id_handle(ploam_ctx,
						   (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
		}

		/* POPUP message (PLOAMd = POPUP with ONU-ID = 0xFF)
		   is received */
		if (ploam_ctx->ds_msg.msg_id == PLOAM_DN_POPUP) {
			fsm_o6_popup_handle(ploam_ctx,
					    (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
		}

		/* The ONU receives Disable message
		   (PLOAMd = Disable_Serial_Number) with Disable */
		if (ploam_ctx->ds_msg.msg_id == PLOAM_DN_DISABLE_SERIAL_NUM) {
			fsm_o6_dis_ser_num_handle(ploam_ctx,
						  (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
		}
	}

	if (ploam_ctx->event)
		ONU_DEBUG_ERR("FSM O6 state handle failed %x",
			      ploam_ctx->event);

	return 0;
}

/**
   Emergency Stop State Handler.
   ONU stops transmitting data in U/S until enabled by OLT.
*/
STATIC int fsm_o7(struct ploam_context *ploam_ctx)
{
	if (ploam_ctx->event & PLOAM_LOS || ploam_ctx->event & PLOAM_LOF) {
		/* nothing to do - we are already in state 7 */
		ploam_ctx->event &= ~(PLOAM_LOS | PLOAM_LOF);
	}

	/* BER expired */
	if (ploam_ctx->event & PLOAM_BER_EXPIRED) {
		ploam_ctx->event &= ~PLOAM_BER_EXPIRED;
		ONU_DEBUG_MSG("FSM O7 REI");
	}

	/* PLOAMd message received */
	if (ploam_ctx->event & PLOAM_MSG_RECEIVED) {

		ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;

		/* The ONU receives Disable message
		   (PLOAMd = Disable_Serial_Number) with Enable */
		if (ploam_ctx->ds_msg.msg_id == PLOAM_DN_DISABLE_SERIAL_NUM)
			fsm_o7_dis_ser_num_handle(ploam_ctx,
						  (union ploam_dn_msg *)
							&ploam_ctx->ds_msg);
	}

	if (ploam_ctx->event)
		ONU_DEBUG_ERR("FSM O7 state handle failed %x",
			      ploam_ctx->event);

	return 0;
}

int ploam_context_init(void *onu_ctrl)
{
	struct onu_control *ctrl = (struct onu_control *)onu_ctrl;

	memset(&ctrl->ploam_ctx, 0x00, sizeof(struct ploam_context));
	ctrl->ploam_ctx.ctrl = ctrl;

	if (onu_fifo_init(&ctrl->nfc_fifo, "ploam") != 0)
		return -1;

	ctrl->nfc_fifo.mask = 0xFFFFFFFF;

	ctrl->ploam_ctx.onu_id = ONU_ID_VALUE_BROADCAST;
	ctrl->ploam_ctx.omci_port_id = ONU_ID_VALUE_BROADCAST;

	ctrl->ploam_ctx.rand_delay = onu_random_get(0, 0xF3);
	gtc_random_delay_set(ctrl->ploam_ctx.rand_delay);

	ctrl->ploam_ctx.ploam_timeout_1 = ONU_DEFAULT_TIMER_TO1_VALUE;
	ctrl->ploam_ctx.ploam_timeout_2 = ONU_DEFAULT_TIMER_TO2_VALUE;

	ctrl->ploam_ctx.previous_state = PLOAM_STATE_O0;
	ctrl->ploam_ctx.curr_state = PLOAM_STATE_O0;

	return 0;
}

/*
   see header
*/
int ploam_context_free(void *onu_ctrl)
{
	struct onu_control *ctrl = (struct onu_control *)onu_ctrl;

	onu_fifo_delete(&ctrl->nfc_fifo);
	return 0;
}

int ploam_fsm(struct ploam_context *ploam_ctx)
{
	int ret = 0;
	int cnt = 0;
	enum ploam_state old_state;

	do {
		old_state = ploam_ctx->curr_state;

		if (ploam_ctx->event & PLOAM_MSG_RECEIVED &&
			ploam_ctx->ds_msg.msg_id == PLOAM_DN_PON_ID) {
			ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;
			fsm_pon_id_handle(ploam_ctx,
				 (union ploam_dn_msg *) &ploam_ctx->ds_msg);
		}

		ret = ploam_fsm_handler[ploam_ctx->curr_state] (ploam_ctx);
		if (ret != 0)
			return PLOAM_FSM_ERROR;

		if (old_state != ploam_ctx->curr_state) {
			ONU_DEBUG_MSG("PLOAM_FSM_STATE_CHANGED from %d to %d",
				      old_state, ploam_ctx->curr_state);
			ret |= PLOAM_FSM_STATE_CHANGED;
		}
		if (++cnt > 10)
			break;
	} while (ploam_ctx->event);

	if (ploam_ctx->event) {
		ONU_DEBUG_WRN("ploam_fsm: event not handled - %x",
				ploam_ctx->event);
		ONU_DEBUG_WRN("ploam_fsm: event not handled - %x in state %d",
				ploam_ctx->event, old_state);
		ploam_ctx->event = 0;
		ret |= PLOAM_FSM_ERROR_EVENT_NOT_HANDLED;
	}

	return ret;
}

STATIC void ploam_fsm_cleanup(struct ploam_context *ploam_ctx)
{
	int i, cnt=0;
	int tcont_ret[ONU_GPE_MAX_TCONT];
	bool forceO0 = gtc_trace_enabled();
	uint32_t repn, pepn;

	ploam_ctx->event &= ~PLOAM_MSG_RECEIVED;
	ploam_ctx->event &= ~PLOAM_BER_EXPIRED;
	ploam_ctx->dsimask &= ~GTC_DSIMASK_1_BERINTV;
	gtc_downstream_imask_set(ploam_ctx->dsimask);

	if (forceO0 == false) {
		/* don't disable the framer to keep the trace data valid */
		gtc_tx_enable(false);
	}

	if (ploam_ctx->curr_state == PLOAM_STATE_O1 ||
			ploam_ctx->curr_state == PLOAM_STATE_O2) {
		for (i = 0; i < ONU_GPE_MAX_TCONT; i++) {
			tcont_ret[i] = gtc_tcont_delete(i);
			if (tcont_ret[i])
				continue;
			cnt++;
			if (octrlg_epn_get(i, &repn, &pepn) != 0)
				continue;
			if (repn == 127)
				continue;
			gpe_enqueue_enable(ploam_ctx->ctrl, repn, false);
		}
		if(cnt) {
			onu_udelay(5000);
			for (i = 0; i < ONU_GPE_MAX_TCONT; i++) {
				if (tcont_ret[i])
					continue;
				octrlg_tcont_delete(i);
			}
		}
		if (ploam_ctx->omci_port_id != ONU_ID_VALUE_BROADCAST)
			gem_port_remove(ploam_ctx->omci_port_id);
	}
	if (forceO0 == true) {
		if (ploam_ctx->previous_state != PLOAM_STATE_O0)
			ONU_DEBUG_ERR("forced O0 state because of trace stop");
		ploam_ctx->curr_state = PLOAM_STATE_O0;
	}
	ploam_ctx->sn_mode = false;
	gtc_ploam_flush();
}

void link_data_request(const uint8_t idx);

void ploam_fsm_state_set(struct ploam_context *ploam_ctx,
			 enum ploam_state new_state)
{
	ONU_DEBUG_MSG("FSM: state %d -> %d", ploam_ctx->curr_state, new_state);

	if (new_state && new_state == ploam_ctx->curr_state) {
		ONU_DEBUG_WRN
		    ("ploam_fsm_state_set: ERROR current state is already %d",
		     new_state);
		return;
	}
	ploam_ctx->previous_state = ploam_ctx->curr_state;
	ploam_ctx->curr_state = new_state;
	ploam_ctx->elapsed_msec = IFXOS_ElapsedTimeMSecGet(0);

	if ((ploam_ctx->curr_state == PLOAM_STATE_O5 &&
		ploam_ctx->previous_state != PLOAM_STATE_O5) ||
	    (ploam_ctx->curr_state != PLOAM_STATE_O5 &&
		ploam_ctx->previous_state == PLOAM_STATE_O5))
		ploam_ctx->o5_change_elapsed_sec = onu_elapsed_time_sec_get(0);
	/* activate laser in optic driver at leaving O7 */
	if (new_state != PLOAM_STATE_O7 &&
		ploam_ctx->previous_state == PLOAM_STATE_O7)
		optic_tx_enable (true);

	switch (ploam_ctx->curr_state) {
	case PLOAM_STATE_O5:
		link_data_request(1);
		break;
	case PLOAM_STATE_O7:
		gtc_tx_enable(false);
		ploam_ctx->sn_mode = false;
		gtc_ploam_flush();
		optic_tx_enable (false);
		break;
	case PLOAM_STATE_O1:
	case PLOAM_STATE_O0:
		ploam_ctx->sstart_min = 0xFFFF;
	case PLOAM_STATE_O2:
		ploam_fsm_cleanup(ploam_ctx);
		break;
	default:
		break;
	}
}

enum onu_errorcode ploam_state_get(struct onu_device *p_dev,
				   struct ploam_state_data_get *param)
{
	param->curr_state = p_dev->ploam_ctx->curr_state;
	param->previous_state = p_dev->ploam_ctx->previous_state;
	param->elapsed_msec = p_dev->ploam_ctx->elapsed_msec;
	return ONU_STATUS_OK;
}

enum onu_errorcode ploam_state_set(struct onu_device *p_dev,
				   const struct ploam_state_data_set *param)
{
	ploam_fsm_state_set(p_dev->ploam_ctx, param->state);
	return ONU_STATUS_OK;
}

enum onu_errorcode ploam_ds_extract(struct onu_device *p_dev,
				    struct ploam_message *param)
{
	(void)p_dev;
	(void)param;
	return ONU_STATUS_NOT_IMPLEMENTED;
}

enum onu_errorcode ploam_us_insert(struct onu_device *p_dev,
				   const struct ploam_message *param)
{
	(void)p_dev;
	(void)param;
	return ONU_STATUS_NOT_IMPLEMENTED;
}

enum onu_errorcode ploam_us_extract(struct onu_device *p_dev,
				    struct ploam_message *param)
{
	(void)p_dev;
	(void)param;
	return ONU_STATUS_NOT_IMPLEMENTED;
}

enum onu_errorcode ploam_init (struct onu_device *p_dev)
{
	struct onu_control* p_ctrl = (struct onu_control*)p_dev->ctrl;

	if (ploam_context_init(p_ctrl) != 0) {
		ONU_DEBUG_ERR("can't init PLOAM context");
		return ONU_STATUS_ERR;
	}
#ifndef ONU_LIBRARY
	p_ctrl->run_worker = true;
	event_queue_init(p_ctrl);
	if (IFXOS_ThreadInit(&p_ctrl->worker_ctx,
			     "onu",
			     onu_worker_thread,
			     ONU_WORKER_THREAD_STACK_SIZE,
			     ONU_WORKER_THREAD_PRIO,
			     (ulong_t) p_ctrl,
			     0) != IFX_SUCCESS) {
		ONU_DEBUG_ERR("can't start worker thread");
		return ONU_STATUS_ERR;
	}
#endif /* ONU_LIBRARY */
	return ONU_STATUS_OK;
}

const struct onu_entry ploam_function_table[] = {
	TE1in_opt(FIO_PLOAM_DS_INSERT,
		sizeof(struct ploam_message), ploam_ds_insert),
	TE1out_opt(FIO_PLOAM_DS_EXTRACT,
		sizeof(struct ploam_message), ploam_ds_extract),
	TE1in_opt(FIO_PLOAM_US_INSERT,
		sizeof(struct ploam_message), ploam_us_insert),
	TE1out_opt(FIO_PLOAM_US_EXTRACT,
		sizeof(struct ploam_message), ploam_us_extract),
	TE1out(FIO_PLOAM_STATE_GET,
		sizeof(struct ploam_state_data_get), ploam_state_get),
	TE1in(FIO_PLOAM_STATE_SET,
		sizeof(struct ploam_state_data_set), ploam_state_set),
	TE0 (FIO_PLOAM_INIT, ploam_init)
};

const unsigned int ploam_function_table_size = ARRAY_SIZE(ploam_function_table);

/*! @} */

/*! @} */
