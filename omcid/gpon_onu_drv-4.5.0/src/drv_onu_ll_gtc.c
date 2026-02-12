/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_ploam_api.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_ll_gtc.h"
#include "drv_onu_ll_octrlg.h"
#include "drv_onu_gtc_api.h"
#include "drv_onu_register.h"



int optic_ll_tx_fifo_set(const uint16_t delay_enable,
			 const uint16_t delay_disable,
			 const uint16_t size_fifo );
int optic_ll_tx_fifo_get(uint16_t *delay_enable,
			 uint16_t *delay_disable,
			 uint16_t *size_fifo );
int optic_ll_tx_laserdelay_set(const uint8_t bitdelay );

#define MAX_PLOAM_TX_FIFO 128

struct ploam_fifo_entry {
	uint32_t data[3];
	uint8_t repeat_factor;
};

struct ploam_fifo_entry tx_fifo[MAX_PLOAM_TX_FIFO];

static uint8_t tx_num = 0;
static uint8_t rx_num = 0;
static uint8_t tx_full = 0;

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \addtogroup PLOAM_INTERNAL
   @{
*/

/* GPON_GTC_GTC_INIT gtc_init Hardware Programming Details
      Set the thresholds to the default value of 10E-5/10E-6
      - GTC.GTC_SFWIN.WSIZE  = 0x0400 (128 ms)
      - GTC.GTC_SFTHR.DETECT = 0x0CB9 (10E-5)
      - GTC.GTC_SFTHR.CLEAR  = 0x0145 (10E-6)
      Set the thresholds to the default value of 10E-9/10E-10
      - GTC.GTC_SDWIN.WSIZE  = 0xFFFF (8.19 s)
      - GTC.GTC_SDTHR.DETECT = 0x0015 (10E-9)
      - GTC.GTC_SDTHR.CLEAR  = 0x0002 (10E-10)
      - GTC.GTC_BERRINTV = 0x0036 EE80
      Enable the GTC hardware modules:
      - SYS_GPON.ACT.PMATX = SET
      - SYS_GPON.ACT.GPEIF = SET
      - SYS_GPON.ACT.GTCRXPDI = SET
      - SYS_GPON.ACT.GTCRX = SET
      - SYS_GPON.ACT.GTCTXPDI = SET
      - SYS_GPON.ACT.GTCTX = SET
*/
int gtc_ll_init(struct ploam_context *ploam_ctx,
		const struct gtc_init_data *param)
{
	volatile uint32_t val;
	uint32_t i;
	struct gtc_dgasp_msg dgasp;

	/** Laser timing: Laser enable start extension */
	uint8_t laser_en_start_ext = param->laser_en_start_ext;	/* 0 */

	/** Laser timing: Laser enable end extension */
	uint8_t laser_en_end_ext = param->laser_en_end_ext;	/* 8 */

	/** Laser timing: Laser timing offset */
	uint8_t laser_offset = param->laser_offset;	/* 0 */

	/** Laser timing: Laser-off minimum timing gap */
	/*uint8_t laser_gap = param->laser_gap;*/

	/** Digital Loss of Signal (DLOS) initialization */
	/*struct gtc_dlos_mode dlos = param->dlos;*/

	/** Enable module clock, release reset. This is mandatory before
	    accessing module's registers. All GTC related activations
	    ar in the optic driver.
	*/

	/* Disable upstream data transmission */
	gtc_w32(GTC_USCON_LOCKDIS, upstr_gtc_uscon);

	gtc_w32_mask(0, GTC_USCON_PLSUD_MASK &
		     (0x5555 << GTC_USCON_PLSUD_OFFSET), upstr_gtc_uscon);

	/* FEC set to automatic operation */
	gtc_w32_mask(0, GTC_USTEST_USFEC_AUTO, upstr_gtc_ustest);
	gtc_w32_mask(0, GTC_DSCON_1_DSFEC_AUTO, downstr_gtc_dscon_1);

	/* DLOS - set the loss of signal detection parameters
	   - GTC_DLOS.THR = 0x013000
	   - GTC_DLOS.WIN = 125 (0b001)
	   - GTC_DLOS.INV = ZERO (0b0) */
	gtc_w32(0x013000 /** \todo | GTC_DLOS_WIN_125*/ , downstr_gtc_dlos);

	/* Signal Fail detection - set the thresholds to the default
	   value of 10E-5/10E-6 */
	/* Signal Degrade detection: - set the thresholds to the default
	   value of 10E-9/10E-10 */
	ploam_ctx->sf_threshold = 5;
	ploam_ctx->sd_threshold = 9;
	gtc_threshold_set(5, 9);

	/* BIP error interval - set to the maximum value of 1 h */
	gtc_w32(0x0036EE80, downstr_gtc_berrintv);

	/* Downstream synchronization - set the parameters of the
	   synchronization state machines
	   - GTC_SCON.M1 = 0b010
	   - GTC_SCON.M2 = 0b010
	   - GTC_SCON.N1 = 0b010
	   - GTC_SCON.N2 = 0b010 */
	gtc_w32((0x2 << 10) | (0x2 << 7) | (0x2 << 3) | (0x2),
		downstr_gtc_scon);

	/* Port-ID configuration - Clear all Port IDs
	   - GTC_DSTEST_1.PID_SEL    = NONE (0b000)
	   - GTC_DSTEST_1.PID_STB_INIT = INIT (0b1)
	   - wait until GTC_DSTEST_2 indicates that the RAM has been
	   initialized. */
	val = gtc_r32(downstr_gtc_dstest_1);
	val &= ~GTC_DSTEST_1_PID_SEL_MASK;
	gtc_w32(val | GTC_DSTEST_1_PID_STB_INIT, downstr_gtc_dstest_1);
	i = 0;
	while (gtc_r32(downstr_gtc_dstest_2) & GTC_DSTEST_2_SW_RAM_BUSY) {
		i++;
		if (i > 100000) {
			ONU_DEBUG_ERR("PLOAM port id flush failed "
				      "(GTC_DSTEST_2_SW_RAM_BUSY_BUSY)");
			break;
		}
	}
	gtc_w32(val, downstr_gtc_dstest_1);

	ploam_ctx->sn_mode = false;
	gtc_ploam_flush();

	/* GTC ID - set the default ONU ID value ("unused") */
	gtc_w32(0xFE, downstr_gtc_id);

	/* Disable all interrupts
	   GTC_DSIMASK_1 = 0x0000 0000
	   GTC_USIMASK_1 = 0x0000 0000 */
	gtc_w32(0x00, downstr_gtc_dsimask_1);
	gtc_w32(0x00, upstr_gtc_usimask);

	/* Clear all interrupt status registers
	   - GTC_DSISTAT_1 = 0xFFFF FFFF
	   - GTC_USISTAT = 0xFFFF FFFF */
	gtc_w32(0xFFFFFFFF, downstr_gtc_dsistat_1);
	gtc_w32(0xFFFFFFFF, upstr_gtc_usistat);

	/* Clear the counter status register
	   - GTC_DSCNTRSTAT = 0xFFFF FFFF */
	gtc_w32(0xFFFFFFFF, downstr_gtc_dscntrstat);

	/* Minimum response time - set to the default value of 35E-06 s
	   - GTC_RTIME_3 = 0x0000 00AA */
	gtc_w32(0x000000AA, upstr_gtc_rtime_3);

	/* Clear status registers that are clear-on-read by reading each once
	   - GTC_USESTAT
	   - GTC_USSTAT */
	val = gtc_r32(upstr_gtc_usestat);
	val = gtc_r32(upstr_gtc_usstat);

	/* Laser timing control - adjust the laser timing according to the
	   application's hardware reqirements
	   - GTC_LASER.LPO_GAP = laser_gap
	   - GTC_LASER.OFFS    = laser_offset
	   - GTC_LASER.EXTE    = laser_en_end_ext
	   - GTC_LASER.EXTS    = laser_en_start_ext */
	gtc_w32_mask((GTC_LASER_LE_EXTS_MASK | GTC_LASER_LE_EXTE_MASK |
		      GTC_LASER_LPU_OFFS_MASK),
		     (GTC_LASER_LE_EXTS_MASK &
		      (laser_en_start_ext << GTC_LASER_LE_EXTS_OFFSET)) |
		     (GTC_LASER_LE_EXTE_MASK &
		      (laser_en_end_ext << GTC_LASER_LE_EXTE_OFFSET)) |
		     (GTC_LASER_LPU_OFFS_MASK &
		      (laser_offset << GTC_LASER_LPU_OFFS_OFFSET)),
		     upstr_gtc_laser);

	/*gtc_w32_mask(0, GTC_LASER_LPO_DIS, upstr_gtc_laser); */

	/* Disable all upstream test modes
	   - GTC_USTEST = 0x0008 007F */
	/*gtc_w32(0x0048007F | GTC_USTEST_PLOAMU_AUTO, upstr_gtc_ustest); */
	/*gtc_w32(0x0008007F | GTC_USTEST_PLOAMU_AUTO, upstr_gtc_ustest); */
	gtc_w32(0x0008007F | GTC_USTEST_PLSU_REQE, upstr_gtc_ustest);

	/* Start offset
	   - GTC_START_OFFSET = 0x0000 0008
	   (44 bit preamble + 20 bit delimiter = 64 bit = 8 byte)
	   - Clear all Allocation IDs
	   - GTC_TCONT_0..31 = 0x0000 00FF */

	gtc_random_delay_set(ploam_ctx->rand_delay);

	ploam_ctx->sstart_min = 0xFFFF;
	ploam_ctx->offset_curr = 0;
	ploam_ctx->offset_corr = 0;
	ploam_ctx->offset_o5 = 0xFFFF;

	ploam_ctx->usimask = GTC_USIMASK_TRACE | GTC_USIMASK_MINSST |
	    GTC_USIMASK_RANGE | GTC_USIMASK_EMPTY | GTC_USIMASK_REQE;
	gtc_w32(ploam_ctx->usimask, upstr_gtc_usimask);

	ploam_ctx->bwmmask = GTC_BWMMASK_STOP;
	gtc_w32(ploam_ctx->bwmmask, upstr_gtc_bwmmask);

	ploam_ctx->dsimask = GTC_DSIMASK_1_RXDAT | GTC_DSIMASK_1_RXFUL |
	    GTC_DSIMASK_1_RXOFL | GTC_DSIMASK_1_GTCLOF |
	    GTC_DSIMASK_1_GTCLSF | GTC_DSIMASK_1_DLOS |
	    GTC_DSIMASK_1_SF;

	gtc_w32(ploam_ctx->dsimask, downstr_gtc_dsimask_1);

	/* enable automatic dying gasp notification */
	memset(&dgasp, 0x00, sizeof(dgasp));
	dgasp.dying_gasp_auto = 1;
	/* gtc_dying_gasp_message_set(&dgasp); */

	return 0;
}

int gtc_ploam_flush(void)
{
	/* PLOAMu transmit buffer - clear all pending messages (if any)
	   - GTC_MTX_CTRL.FLUSH = FLUSH (0b1) */
	gtc_w32_mask(0, GTC_MTX_CTRL_FLUSH | GTC_MTX_CTRL_REPEAT_MASK,
		     upstr_gtc_mtx_ctrl);

	gtc_w32_mask(GTC_MTX_CTRL_FLUSH | GTC_MTX_CTRL_REPEAT_MASK, 0,
		     upstr_gtc_mtx_ctrl);

	tx_num = 0;
	rx_num = 0;
	tx_full = 0;

	return 0;
}

union ploam_msg_u {
	struct ploam_msg msg;
	struct {
		uint32_t data0;
		uint32_t data1;
		uint32_t data2;
	} data;
};

int gtc_ploam_rd(struct ploam_msg *msg_curr, struct ploam_msg *msg_prev,
		 uint8_t *ds_repeat_count)
{
	uint32_t reg;
	union ploam_msg_u dest;
	union ploam_msg_u prev;

	/*
	   - onu_id     : GTC_MRX_1.ONUID
	   This value is equal to the assigned ONU ID or equal to the
	   broadcast ONU ID (0xFF), other messages are not accepted.
	   - msg_id : GTC_MRX_1.MESID
	   Identification code of the specific message.
	   All codes are accepted, no plausibility or error check is done.
	   - data[0]   : GTC_MRX_1.MB0
	   - data[1]   : GTC_MRX_1.MB1
	   - data[2]   : GTC_MRX_2.MB2
	   - data[3]   : GTC_MRX_2.MB3
	   - data[4]   : GTC_MRX_2.MB4
	   - data[5]   : GTC_MRX_2.MB5
	   - data[6]   : GTC_MRX_3.MB6
	   - data[7]   : GTC_MRX_3.MB7
	   - data[8]   : GTC_MRX_3.MB8
	   - data[9]   : GTC_MRX_3.MB9
	   Data value(s) that have been received, the contents format
	   depends on the message type. */
	/* while FIFO is not empty */
	reg = gtc_r32(downstr_gtc_dsstat_1);

	if (reg & GTC_DSSTAT_1_RXOFL)
		ONU_DEBUG_ERR("PLOAM Rx - message lost");

	if ((reg & GTC_DSSTAT_1_RXDAT) == 0)
		return -2;

	/* read PLOAMd */
	/* GTC_MRX_3 .. 1 */
	dest.data.data0 = gtc_r32(downstr_gtc_mrx_1);
	dest.data.data1 = gtc_r32(downstr_gtc_mrx_2);
	dest.data.data2 = gtc_r32(downstr_gtc_mrx_3);
	*msg_curr = dest.msg;

	/* ONU_DEBUG_ERR("PLOAM Rx: message %d", msg_curr->msg_id); */

	if (msg_prev) {
		prev.msg = *msg_prev;

		if ((dest.data.data0 == prev.data.data0) &&
		    (dest.data.data1 == prev.data.data1) &&
		    (dest.data.data2 == prev.data.data2)) {
			/* ONU_DEBUG_MSG("PLOAM Rx: message %d - repeated",
			   msg_curr->msg_id); */
			*ds_repeat_count = *ds_repeat_count + 1;
		} else {
			*ds_repeat_count = 0;
		}

		*msg_prev = dest.msg;
	}

#if defined(ONU_SIMULATION)
	/* clear fifo after read the last register */
	gtc_w32_mask(GTC_DSSTAT_1_RXDAT, 0, downstr_gtc_dsstat_1);
	gtc_w32_mask(GTC_DSISTAT_1_RXDAT, 0, downstr_gtc_dsistat_1);

	/* clear GTC_MRX_1 .. 3 registers */
	gtc_w32(0, downstr_gtc_mrx_1);
	gtc_w32(0, downstr_gtc_mrx_2);
	gtc_w32(0, downstr_gtc_mrx_3);
#endif

	if ((msg_curr->onu_id == 0xFF) ||
	    (msg_curr->onu_id == gtc_r32(downstr_gtc_id))) {
		ONU_DEBUG_MSG("PLOAM RX - %08x %08x %08x",
			      dest.data.data0,
			      dest.data.data1,
			      dest.data.data2);
		return 0;
	}

	ONU_DEBUG_ERR("PLOAM Read error: wrong ONU ID %x", msg_curr->onu_id);

	return -1;
}

int gtc_ploam_wr(union ploam_up_msg *msg, uint8_t repeat_factor)
{
	int ret = 0;
	uint8_t i;

	if (msg == NULL) {
		tx_full = 0;
		while (rx_num != tx_num) {
			ONU_DEBUG_MSG("PLOAM TX - %08x %08x %08x",
				      tx_fifo[rx_num].data[0],
				      tx_fifo[rx_num].data[1],
				      tx_fifo[rx_num].data[2]);
			gtc_w32(tx_fifo[rx_num].data[2], upstr_gtc_mtx_3);
			gtc_w32(tx_fifo[rx_num].data[1], upstr_gtc_mtx_2);
			gtc_w32(tx_fifo[rx_num].data[0], upstr_gtc_mtx_1);
			gtc_w32_mask(GTC_MTX_CTRL_REPEAT_MASK,
				     tx_fifo[rx_num].repeat_factor,
				     upstr_gtc_mtx_ctrl);
			rx_num++;
			if (gtc_r32(upstr_gtc_usistat) &
						      (GTC_USISTAT_TXFUL_INT)) {
				gtc_w32(GTC_USISTAT_TXFUL_INT,
					upstr_gtc_usistat);
				tx_full = 1;
				return 0;
			}
		}
		return 0;
	}

	if (tx_full || (rx_num != tx_num)) {
		i = tx_num;
		/* add to fifo & leave */
		tx_fifo[i].data[2] = msg->data[2];
		tx_fifo[i].data[1] = msg->data[1];
		tx_fifo[i].data[0] = msg->data[0];
		tx_fifo[i].repeat_factor = repeat_factor;
		i++;
		if (i >= MAX_PLOAM_TX_FIFO)
			i = 0;
		if (i == rx_num) {
			ONU_DEBUG_ERR("Can't send PLOAMu, TXFIFO full");
			ret = -1;
			goto err;
		}
		tx_num = i;
		return 0;
	}

	ONU_DEBUG_MSG("PLOAM TX - %08x %08x %08x",
		      msg->data[0],
		      msg->data[1],
		      msg->data[2]);
	gtc_w32(msg->data[2], upstr_gtc_mtx_3);
	gtc_w32(msg->data[1], upstr_gtc_mtx_2);
	gtc_w32(msg->data[0], upstr_gtc_mtx_1);
	gtc_w32_mask(GTC_MTX_CTRL_REPEAT_MASK, repeat_factor,
		     upstr_gtc_mtx_ctrl);

	if (gtc_r32(upstr_gtc_usistat) & (GTC_USISTAT_TXFUL_INT)) {
		gtc_w32(GTC_USISTAT_TXFUL_INT, upstr_gtc_usistat);
		tx_full = 1;
		return 0;
	}

	return 0;

err:
	ONU_DEBUG_ERR("PLOAM TX(%d) - %08x %08x %08x", repeat_factor,
		      msg->data[0], msg->data[1], msg->data[2]);

	return ret;
}

int gtc_no_message_set(union ploam_up_msg *msg)
{
	gtc_w32(msg->data[2], upstr_gtc_mtx_3);
	gtc_w32(msg->data[1], upstr_gtc_mtx_2);
	gtc_w32(msg->data[0], upstr_gtc_mtx_1);
	gtc_w32_mask(GTC_MTX_CTRL_REPEAT_MASK, GTC_MTX_CTRL_NM_WR,
		     upstr_gtc_mtx_ctrl);
	gtc_w32_mask(GTC_MTX_CTRL_NM_WR, 0, upstr_gtc_mtx_ctrl);

	return 0;
}

int gtc_dying_gasp_message_set(const struct gtc_dgasp_msg *msg)
{
	gtc_w32(msg->dying_gasp_msg[2], upstr_gtc_mtx_3);
	gtc_w32(msg->dying_gasp_msg[1], upstr_gtc_mtx_2);
	gtc_w32(msg->dying_gasp_msg[0], upstr_gtc_mtx_1);
	gtc_w32_mask(GTC_MTX_CTRL_REPEAT_MASK, GTC_MTX_CTRL_DG_WR,
		     upstr_gtc_mtx_ctrl);
	gtc_w32_mask(GTC_MTX_CTRL_DG_WR, 0, upstr_gtc_mtx_ctrl);

	if (msg->dying_gasp_auto == true)
		gtc_w32_mask(0, GTC_USCON_EN_DG_EN, upstr_gtc_uscon);
	else
		gtc_w32_mask(GTC_USCON_EN_DG_EN, 0, upstr_gtc_uscon);

	return 0;
}

/** Configure ONU ID. The value is checked against
    PLOAM_ID_VALUE_ASSIGNABLE define.
*/
int gtc_onu_id_set(const uint32_t onu_id)
{
	/*if (onu_id > PLOAM_ID_VALUE_ASSIGNABLE) {
	   ONU_DEBUG_ERR("invalid onu_id=0x%x", onu_id));
	   return -1;
	   } */

	ONU_DEBUG_MSG("onu_id = 0x%x", onu_id);

	/* onu_id
	   This variable defined the ONU's ID. The related hardware register
	   GTC_ID accepts an 8-bit value on bit positions 7:0. */
	gtc_w32(onu_id, downstr_gtc_id);

	return 0;
}

/** Hardware Programming Details
  - Return the index (tcont_idx) of the T-CONT that has been added
  - If the given value of alloc_id is larger than ONU_GPE_MAX_ALLOCATION_ID,
    an error code is
  - The index values tcont_idx of all configured T-CONTs shall be stored
    and made available to the OMCI software for further configuration of the
    GPE.
*/
int gtc_tcont_set(const uint32_t tcont_idx, const uint32_t alloc_id)
{
	ONU_DEBUG_MSG("set TCONT %d - alloc_id=0x%x\n",
		      tcont_idx, alloc_id);

	if (tcont_idx >= ONU_GPE_MAX_TCONT) {
		ONU_DEBUG_ERR("invalid TCONT index=0x%x", tcont_idx);
		return -1;
	}

	if (alloc_id >= ONU_GPE_MAX_ALLOCATION_ID) {
		ONU_DEBUG_ERR("invalid alloc_id=0x%x", alloc_id);
		return -2;
	}

	gtc_w32(alloc_id | GTC_TCONT_USED, upstr_gtc_tcont[tcont_idx]);

	return 0;
}

int gtc_tcont_alloc_id_add(const uint32_t alloc_id, uint32_t *tcont)
{
	int i;
	uint32_t val;

	ONU_DEBUG_MSG("add alloc_id=0x%x", alloc_id);

	if (alloc_id >= ONU_GPE_MAX_ALLOCATION_ID) {
		ONU_DEBUG_ERR("invalid alloc_id=0x%x", alloc_id);
		return -1;
	}

	for (i = 0; i < ONU_GPE_MAX_TCONT; i++) {
		val = gtc_r32(upstr_gtc_tcont[i]);
		if (val & GTC_TCONT_USED)
			continue;

		gtc_w32(alloc_id | GTC_TCONT_USED, upstr_gtc_tcont[i]);
		*tcont = i;
		return 0;
	}

	ONU_DEBUG_ERR("can't add alloc_id=0x%x", alloc_id);

	return -2;
}

int gtc_tcont_alloc_id_find(uint32_t *tcont)
{
	uint8_t i;
	uint32_t val;

	for (i = 0; i < ONU_GPE_MAX_TCONT; i++) {
		val = gtc_r32(upstr_gtc_tcont[i]);
		if (val & GTC_TCONT_USED)
			continue;

		*tcont = i;
		return 0;
	}

	return -1;
}

int gtc_tcont_alloc_id_remove(const uint32_t alloc_id)
{
	int i;
	uint32_t val;

	ONU_DEBUG_MSG("remove alloc_id=0x%x", alloc_id);

	if (alloc_id >= ONU_GPE_MAX_ALLOCATION_ID) {
		ONU_DEBUG_ERR("invalid alloc_id=0x%x", alloc_id);
		return -1;
	}
	for (i = 0; i < ONU_GPE_MAX_TCONT; i++) {
		val = gtc_r32(upstr_gtc_tcont[i]);
		if ((val & GTC_TCONT_USED) == 0)
			continue;
		if ((val & GTC_TCONT_ALLOCID_MASK) == alloc_id) {
			/* Reset only USED bit here */
			gtc_w32(alloc_id, upstr_gtc_tcont[i]);
			return i;
		}
	}
	ONU_DEBUG_ERR("can't remove alloc_id=0x%x", alloc_id);

	return -2;
}
int gtc_tcont_get(const uint32_t tcont_idx, uint32_t *alloc_id, bool *used)
{
	uint32_t val;
	val = gtc_r32(upstr_gtc_tcont[tcont_idx]);
	*alloc_id = val & GTC_TCONT_ALLOCID_MASK;
	*used = val & GTC_TCONT_USED;
	ONU_DEBUG_MSG("get alloc_id=0x%x", *alloc_id);
	return 0;
}

int gtc_tcont_delete(const uint32_t tcont_idx)
{
	uint32_t val;

	val = gtc_r32(upstr_gtc_tcont[tcont_idx]);
	if ((val & GTC_TCONT_USED) == 0)
		return -1;
	gtc_w32(val & GTC_TCONT_ALLOCID_MASK, upstr_gtc_tcont[tcont_idx]);
	ONU_DEBUG_MSG("Delete alloc_id at TCONT 0x%x", tcont_idx);
	return 0;
}

void gtc_tcont_clean(void)
{
	int i;
	ONU_DEBUG_MSG("Delete all AllocIDs");
	for (i = 0; i < ONU_GPE_MAX_TCONT; i++)
		gtc_w32_mask(GTC_TCONT_USED, 0, upstr_gtc_tcont[i]);
}
int gtc_random_delay_set(const uint32_t delay)
{
	/*ONU_DEBUG_ERR("gtc_random_delay_set %x", delay); */
	gtc_w32_mask(GTC_RTIME_1_RANDEL_MASK,
		     delay << GTC_RTIME_1_RANDEL_OFFSET, upstr_gtc_rtime_1);

	return 0;
}

uint32_t gtc_random_delay_get(void)
{
	return (gtc_r32(upstr_gtc_rtime_1) & GTC_RTIME_1_RANDEL_MASK) >>
	    GTC_RTIME_1_RANDEL_OFFSET;
}

int gtc_ranged_delay_set(const uint32_t delay)
{
	gtc_w32(delay, upstr_gtc_rtime_2);
	optic_ll_tx_laserdelay_set( delay & 0x3 );
	return 0;
}

uint32_t gtc_ranged_delay_get(void)
{
	return gtc_r32(upstr_gtc_rtime_2);
}

uint8_t gtc_psync_delay_get(void)
{
	return (uint8_t)(gtc_r32(downstr_gtc_dsdelstat) &
						GTC_DSDELSTAT_PSDEL_MASK);
}

int gtc_ranged_delay_enable(const uint32_t enable)
{
	/*ONU_DEBUG_ERR("gtc_ranged_delay_enable %d", enable); */
	if (!enable)
		gtc_w32_mask(0, GTC_RTIME_1_USE_PRE, upstr_gtc_rtime_1);
	else
		gtc_w32_mask(GTC_RTIME_1_USE_PRE, 0, upstr_gtc_rtime_1);

	return 0;
}

int gtc_ranged_delay_is_enable(void)
{
	return gtc_r32(upstr_gtc_rtime_1) & GTC_RTIME_1_USE_PRE ? false : true;
}

int gtc_preassigned_delay_set(const uint32_t delay)
{
	if (delay > GTC_RTIME_1_PADEL_MASK)
		return -1;

	/*ONU_DEBUG_ERR("gtc_preassigned_delay_set %x", delay); */
	gtc_w32_mask(GTC_RTIME_1_PADEL_MASK, delay, upstr_gtc_rtime_1);

	return 0;
}

uint32_t gtc_preassigned_delay_get(void)
{
	return gtc_r32(upstr_gtc_rtime_1) & GTC_RTIME_1_PADEL_MASK;
}

STATIC void gtc_buffer_bit_set(uint8_t *buf, const uint32_t bit_start,
			       const uint32_t bit_length)
{
	uint32_t byte_pos = bit_start / 8;
	uint32_t bit_pos = bit_start % 8;
	uint8_t i, mask = 1 << (bit_pos % 8);

	ONU_DEBUG_MSG("gtc_buffer_bit_set bit_start %d, "
		      "bit_length %d, bit_pos %d",
		      bit_start, bit_length, bit_pos);

	for (i = 0; i < bit_length; i++) {
		buf[byte_pos] |= mask;
		bit_pos++;
		mask = 1 << (bit_pos % 8);
		if (mask == 0x01)
			byte_pos++;
	}
}

STATIC void gtc_buffer_value_set(uint8_t *buf, const uint32_t bit_start,
				 const uint8_t *value, const uint32_t val_len,
				 const uint32_t bit_len)
{
	uint32_t byte_pos = bit_start / 8;
	uint32_t bit_pos = bit_start % 8;
	uint32_t byte_len = bit_len / 8;
	uint32_t repeat = bit_len / val_len;

	if (bit_pos)
		ONU_DEBUG_ERR("gtc_buffer_value_set - Invalid start position");

	ONU_DEBUG_MSG("gtc_buffer_value_set bit_start %d, byte_pos %d, "
		      "bit_pos %d, byte_len %d, repeat %d, val0 %d",
		      bit_start, byte_pos, bit_pos, byte_len, repeat, value[0]);

	if (repeat > 1)
		memset(&buf[byte_pos], value[0], repeat);
	else
		memcpy(&buf[byte_pos], &value[0], byte_len);
}

uint8_t gtc_upstream_header_len_get(void)
{
	/* FIXME: A21 has other mask (>uint8!) */
	return (uint8_t)((gtc_r32(upstr_gtc_ushdl) & GTC_USHDL_LEN_MASK) >>
							GTC_USHDL_LEN_OFFSET);
}

int gtc_upstream_header_create(const uint32_t guard_bits,
			       const uint32_t t1_bits,
			       const uint32_t t2_bits,
			       const uint32_t t3_bits,
			       const uint8_t t3_pattern,
			       const uint8_t *delimiter)
{
	uint32_t i, pos = 0;
	uint32_t header[32];
	uint32_t t3_bits_override = t3_bits;

	ONU_DEBUG_MSG("gtc_upstream_header_create using guard_bits=%d, "
		      "t1_bits=%d, t2_bits=%d, t3_bits=%d, "
		      "t3_pattern=0x%08x, delimiter=%02x %02x %02x",
		      guard_bits,
		      t1_bits, t2_bits, t3_bits,
		      t3_pattern, delimiter[0], delimiter[1], delimiter[2]);

	if (guard_bits + t1_bits + t2_bits + t3_bits == 0) {
		ONU_DEBUG_MSG("GTC_UpstreamHeaderCreate - Invalid parameter");
		return -1;
	}

	if (guard_bits + t1_bits + t2_bits + t3_bits + 24 > 1024) {
		t3_bits_override = 1024 - guard_bits - t1_bits - t2_bits - 24;
		ONU_DEBUG_MSG("GTC_UpstreamHeaderCreate - set t3 bits to %d",
							      t3_bits_override);
	}

	memset(&header[0], 0x00, sizeof(header));

	/* BufferBitClear(header, pos, guard_bits);
	pos += guard_bits; */
	if (t1_bits) {
		gtc_buffer_bit_set((uint8_t *)&header[0], pos, t1_bits);
		pos += t1_bits;
	}
	if (t2_bits) {
		/*BufferBitClear(header, pos, t2_bits); */
		pos += t2_bits;
	}
	if (t3_bits_override) {
		gtc_buffer_value_set((uint8_t *)&header[0], pos, &t3_pattern,
				     8, t3_bits_override);
		pos += t3_bits_override;
	}
	gtc_buffer_value_set((uint8_t *)&header[0], pos, delimiter, 24, 24);
	pos += 24;

	gtc_w32(0, upstr_gtc_ushdrc_ad);
	for (i = 0; i < 32; i++)
		gtc_w32(header[i], upstr_gtc_ushdrc_wd);

	/* FIXME: different mask for A21! */
	gtc_w32(pos / 8, upstr_gtc_ushdl);

	return 0;
}

void gtc_offset_set(const uint16_t hdrlength, const uint16_t sstart_min,
		    uint16_t *offset_max)
{
	uint16_t offset, bytes;

	bytes = hdrlength / 8;
	bytes += 3;		/* BIP, ONU-ID and indication byte */

	ONU_DEBUG_MSG("hdrlength:%d sstart_min:%d bytes:%d", hdrlength,
							     sstart_min, bytes);

	/* here we use a global sstart_min value and calculate
	   the offset. */
	if (sstart_min == 0xffff) {
		ONU_DEBUG_MSG("OFFSET: %d (init)", bytes);
		*offset_max = bytes;
		/* FIXME: A21 has other range! */
		gtc_w32(bytes, upstr_gtc_start_offset);
	} else {
		if (sstart_min <= bytes)
			offset = bytes - sstart_min;
		else
			offset = 0;
		ONU_DEBUG_MSG("OFFSET: %d", offset);
		*offset_max = offset;
		/* FIXME: A21 has other range! */
		gtc_w32(offset, upstr_gtc_start_offset);
	}
}

int gtc_tx_enable(const uint32_t enable)
{
	ONU_DEBUG_MSG("TxEnable - %s", enable ? "on" : "off");

	if (enable)
		gtc_w32_mask(0, GTC_USCON_USEN_RUN, upstr_gtc_uscon);
	else {
		gtc_ploam_request_only_enable(true);
		onu_udelay(1000);
		gtc_w32_mask(GTC_USCON_USEN_RUN, 0, upstr_gtc_uscon);
	}

	return 0;
}

int gtc_tx_is_enable(void)
{
	return gtc_r32(upstr_gtc_uscon) & GTC_USCON_USEN_RUN ? true : false;
}

int gtc_dozing_enable(const uint32_t enable)
{
	if (enable)
		gtc_w32_mask(0, GTC_USCON_DOZE_EN, upstr_gtc_uscon);
	else
		gtc_w32_mask(GTC_USCON_DOZE_EN, 0, upstr_gtc_uscon);

	return 0;
}

int gtc_dozing_is_enable(void)
{
	return gtc_r32(upstr_gtc_uscon) & GTC_USCON_DOZE_EN ? true : false;
}

/** Hardware Programming Details
     This function reads only the downstream GEM port configuration.
     Upstream GEM ports are handled by the GPE_GemPortIdGet function.

     To read the GEM port ID downstream hardware table, the following
     hardware registers are used:
     - GTC_RXPID_ADDR.ADDR  = gem_port_id / 8, selects the internal memory
			      address
     - GTC_RXPID_ADDR.WRITE = RD, we need read access
     - GTC_RXPID_RD.FT_x    = NORM, it's a normal Ethernet payload path or
                              OMCI, it's an OMCI path
     - GTC_RXPID_RD.CR_x    = NO, it's not encrypted or
                              YES, it's encrypted
     - GTC_RXPID_RD.VAL_x   = NO, it's disabled or
                              YES, it's enabled
       x = gem_port_id mod 8
*/
int gtc_port_id_get(const uint16_t port_id, uint32_t *valid,
		    uint32_t *decryption_en)
{
	int ret = 0;
	uint32_t gtc_rxpid_rd;
	uint32_t group = port_id / 8;
	uint32_t idx = (port_id % 8) * 4;

	if (port_id >= ONU_GPE_MAX_GEM_PORT_ID)
		return -1;

	gtc_w32(group, downstr_gtc_rxpid_addr);
	gtc_rxpid_rd = gtc_r32(downstr_gtc_rxpid_rd);

	*valid = (gtc_rxpid_rd & (GTC_RXPID_WR_VAL_0_YES << idx)) ?
								true : false;

	*decryption_en = (gtc_rxpid_rd & (GTC_RXPID_WR_CR_0_YES << idx)) ?
								true : false;

	return ret;
}

int gtc_port_id_enable(const uint16_t port_id, const uint32_t act)
{
	uint32_t gtc_rxpid_rd;
	uint32_t group = port_id / 8;
	uint32_t idx = (port_id % 8) * 4;

	if (port_id >= ONU_GPE_MAX_GEM_PORT_ID) {
		ONU_DEBUG_ERR("invalid Port-ID=0x%x", port_id);
		return -1;
	}

	gtc_w32(group, downstr_gtc_rxpid_addr);
	while ((gtc_r32(downstr_gtc_dstest_2) &
		GTC_DSTEST_2_SW_RAM_Q_VALID_RDY) == 0) {
	}

	gtc_rxpid_rd = gtc_r32(downstr_gtc_rxpid_rd);
	if (act == true)
		gtc_rxpid_rd |= (GTC_RXPID_WR_VAL_0_YES << idx);
	else
		gtc_rxpid_rd &= ~(GTC_RXPID_WR_VAL_0_YES << idx);

	gtc_w32(gtc_rxpid_rd, downstr_gtc_rxpid_wr);
	gtc_w32(group | GTC_RXPID_ADDR_WRITE_WR, downstr_gtc_rxpid_addr);
	gtc_w32(group, downstr_gtc_rxpid_addr);
	while ((gtc_r32(downstr_gtc_dstest_2) &
		GTC_DSTEST_2_SW_RAM_Q_VALID_RDY) == 0) {
	}

	return 0;
}

int gtc_port_id_is_active(const uint16_t port_id, uint32_t *valid)
{
	uint32_t gtc_rxpid_rd;
	uint32_t group = port_id / 8;
	uint32_t idx = (port_id % 8) * 4;

	if (port_id >= ONU_GPE_MAX_GEM_PORT_ID) {
		ONU_DEBUG_ERR("invalid Port-ID=0x%x", port_id);
		return -1;
	}

	gtc_w32(group, downstr_gtc_rxpid_addr);
	gtc_rxpid_rd = gtc_r32(downstr_gtc_rxpid_rd);

	*valid = (gtc_rxpid_rd & (GTC_RXPID_RD_VAL_0_YES << idx)) ?
								true : false;

	return 0;
}

int gtc_port_id_type_set(const uint16_t port_id, const uint8_t type)
{
	uint32_t gtc_rxpid_rd;
	uint32_t group = port_id / 8;
	uint32_t idx = (port_id % 8) * 4;

	if (port_id >= ONU_GPE_MAX_GEM_PORT_ID) {
		ONU_DEBUG_ERR("invalid Port-ID=0x%x", port_id);
		return -1;
	}

	ONU_DEBUG_MSG("set Port-ID type=0x%x", type);

	gtc_w32(group, downstr_gtc_rxpid_addr);
	gtc_rxpid_rd = gtc_r32(downstr_gtc_rxpid_rd);

	gtc_w32_mask(GTC_RXPID_WR_FT_0_MASK << idx,
		     (type & GTC_RXPID_WR_FT_0_MASK) << idx,
		     downstr_gtc_rxpid_wr);
	gtc_w32(group | GTC_RXPID_ADDR_WRITE_WR, downstr_gtc_rxpid_addr);

	gtc_w32(group, downstr_gtc_rxpid_addr);

	return 0;
}

int gtc_port_id_encryption_set(const uint16_t port_id,
			       const uint32_t decryption_en)
{
	uint32_t gtc_rxpid_rd;
	uint32_t group = port_id / 8;
	uint32_t idx = (port_id % 8) * 4;

	if (port_id >= ONU_GPE_MAX_GEM_PORT_ID) {
		ONU_DEBUG_ERR("invalid Port-ID=0x%x", port_id);
		return -1;
	}

	ONU_DEBUG_MSG("Port-ID[%d] decryption: %s", port_id,
		      (decryption_en == true) ? "yes" : "no");

	gtc_w32(group, downstr_gtc_rxpid_addr);
	gtc_rxpid_rd = gtc_r32(downstr_gtc_rxpid_rd);

	if (decryption_en == true)
		gtc_w32(gtc_rxpid_rd | (GTC_RXPID_WR_CR_0_YES << idx),
			downstr_gtc_rxpid_wr);
	else
		gtc_w32(gtc_rxpid_rd & ~(GTC_RXPID_WR_CR_0_YES << idx),
			downstr_gtc_rxpid_wr);

	gtc_w32(group | GTC_RXPID_ADDR_WRITE_WR, downstr_gtc_rxpid_addr);

	gtc_w32(group, downstr_gtc_rxpid_addr);

	return 0;
}

int gtc_switching_time_set(const uint32_t frame_cnt)
{
	/* &~0xc0000000 - clear reserved bits */
	gtc_w32(frame_cnt & ~0xc0000000, downstr_aes_key_switch);

	return 0;
}

int gtc_key_set(const uint32_t key1, const uint32_t key2,
		const uint32_t key3, const uint32_t key4)
{
	gtc_w32(key1, downstr_aes_dekey[0]);
	gtc_w32(key2, downstr_aes_dekey[1]);
	gtc_w32(key3, downstr_aes_dekey[2]);
	gtc_w32(key4, downstr_aes_dekey[3]);

	return 0;
}

int gtc_bip_interval_set(const uint32_t err_interval)
{
	/* err_interval
	   This variable defines the BIP error counter update interval in units
	   of 1 ms. The related hardware register GTC_BERRINTV needs a 25-bit
	   value in units of 125E-6 s. Bit positions 31:25 shall be set to
	   zero.
	   If a value larger than 0x0036EE80 = 3600000 ms = 1 h is received,
	   an warning message (value out of range) shall be returned and this
	   maximum value shall be programmed. */
	ONU_DEBUG_MSG("BIP interval = 0x%x", err_interval);
	if (err_interval > 0x0036EE80 * 8) {
		gtc_w32(0x0036EE80 * 8, downstr_gtc_berrintv);
		return -1;
	} else {
		gtc_w32(err_interval, downstr_gtc_berrintv);
		return 0;
	}
}

struct onu_threshold_value {
	uint32_t window;
	uint32_t detect_fec_off;
	uint32_t detect_fec_on;
	uint32_t clear_fec_off;
	uint32_t clear_fec_on;
};

STATIC struct onu_threshold_value threshold_value[8] = {
	{0x0014, 0xF300, 0xE3C1, 0x184D, 0x16C6},
	{0x003F, 0x4C8C, 0x47BE, 0x07A8, 0x072D},
	{0x03FF, 0x7C4B, 0x747F, 0x0C6E, 0x0BA6},
	{0x0FFF, 0x31C1, 0x2EA2, 0x04FA, 0x04AA},
	{0xFFFF, 0x4FA0, 0x4AA1, 0x07F6, 0x0777},
	{0xFFFF, 0x07F6, 0x0777, 0x00CC, 0x00BF},
	{0xFFFF, 0x00CC, 0x00BF, 0x0014, 0x0013},
	{0xFFFF, 0x0014, 0x0013, 0x0002, 0x0002}
};

int gtc_threshold_set(const uint8_t sf_thrhld, const uint8_t sd_thrhld)
{
	uint32_t detect, clear, interval;
	uint32_t fec_enable =
	    gtc_r32(upstr_gtc_usstat) & GTC_DSSTAT_1_DSFEC ? true : false;
	/*
	   - sf_thrhld
	   This variable defines the error threshold that is used to
	   declare a Signal Fail alarm. The value is given as the negative
	   exponent to a base of 10 (for example, a value of 5 means 10E-5).
	   The threshold to clear the alarm shall be at an order of magnitude
	   below (for the given example at 10E-6).
	   There are two hardware values to be configured, one holds an upper
	   threshold to declare the alarm and another holds a lower threshold
	   to release the alarm. Furthermore an observation window size needs
	   to be defined.
	   GTC_SFWIN.WSIZE: Observation window size in multiples of 125E-6 s.
	   Set to a default value of 0x0400 (128 ms).

	   GTC_SFTHR.DETECT: Minimum number of BIP errors within
	   the observation window to declare SF alarm.
	   To be calculated based on the given window size.
	   For the default value of 10E-5 use 0x0C71 if
	   downstream FEC is disabled and 0x0BA9 if FEC
	   is enabled.
	   GTC_SFTHR.CLEAR:  Maximum number of BIB errors within
	   the observation window to clear SF alarm.
	   To be calculated based on the given window size.
	   For the default value of 10E-6 use 0x013F
	   if downstream FEC is disabled and 0x012B if FEC
	   is enabled. */
	if (sf_thrhld < 2 || sf_thrhld > 9)
		return -1;

	if (sd_thrhld < 2 || sd_thrhld > 9)
		return -1;

	interval = threshold_value[sf_thrhld - 2].window;
	if (fec_enable) {
		detect = threshold_value[sf_thrhld - 2].detect_fec_on;
		clear = threshold_value[sf_thrhld - 2].clear_fec_on;
	} else {
		detect = threshold_value[sf_thrhld - 2].detect_fec_off;
		clear = threshold_value[sf_thrhld - 2].clear_fec_off;
	}

	gtc_w32(interval, downstr_gtc_sfwin);
	gtc_w32(((clear << GTC_SFTHR_CLEAR_OFFSET) & GTC_SFTHR_CLEAR_MASK) |
		(detect & GTC_SFTHR_DETECT_MASK), downstr_gtc_sfthr);

	/*
	   - sd_thrhld
	   This variable defines the error threshold that is used to declare
	   and to clear a Signal Degrade alarm.
	   There are two hardware values to be configured, one holds an upper
	   threshold to declare the alarm and another holds a lower threshold
	   to release the alarm. Furthermore an observation window size needs
	   to be defined.
	   GTC_SDWIN.WSIZE: Observation window size in multiples of 125E-6 s.
	   For the default value of 10E-9 use 0xFFFF (8.19 s).
	   GTC_SDTHR.DETECT: Minimum number of BIP errors within the
	   observation window to declare SD alarm.
	   For the default value of 10E-9 use 0x0014 if
	   downstream FEC is disabled and 0x013 if FEC
	   is enabled.
	   GTC_SDTHR.CLEAR: Maximum number of BIP errors within the observation
	   window to clear SD alarm.
	   For the default value of 10E-10 use 0x0002
	   (regardless of downstream FEC). */
	interval = threshold_value[sd_thrhld - 2].window;
	if (fec_enable) {
		detect = threshold_value[sd_thrhld - 2].detect_fec_on;
		clear = threshold_value[sd_thrhld - 2].clear_fec_on;
	} else {
		detect = threshold_value[sd_thrhld - 2].detect_fec_off;
		clear = threshold_value[sd_thrhld - 2].clear_fec_off;
	}

	gtc_w32(interval, downstr_gtc_sdwin);
	gtc_w32(((clear << GTC_SDTHR_CLEAR_OFFSET) & GTC_SDTHR_CLEAR_MASK) |
		(detect & GTC_SDTHR_DETECT_MASK), downstr_gtc_sdthr);

	return 0;
}

void gtc_ll_status_get(struct gtc_status *param)
{
	uint32_t stat = gtc_r32(downstr_gtc_dsstat_1);
	param->us_fec_enable =
	    gtc_r32(upstr_gtc_usstat) & GTC_USSTAT_USFEC ? true : false;
	param->ds_fec_enable = stat & GTC_DSSTAT_1_DSFEC ? true : false;
	param->ds_ploam_waiting = stat & GTC_DSSTAT_1_RXDAT ? true : false;

	switch (stat & GTC_DSSTAT_1_STATE_MASK) {
		/* (default) searching for preamble. */
	case 0:		/* GTC_DSSTAT_1_STATE_HUNT */
		param->ds_state = GPON_STATE_HUNT;
		break;
		/*  initial preamble(s) found. */
	case GTC_DSSTAT_1_STATE_PSYNC:
		param->ds_state = GPON_STATE_PRESYNC;
		break;
		/* reserved, this value is not used. */
	case GTC_DSSTAT_1_STATE_RES:
		/* synchronous state. */
	case GTC_DSSTAT_1_STATE_SYNC:
		param->ds_state = GPON_STATE_SYNC;
		break;
	}

	switch (stat & GTC_DSSTAT_1_SFSTATE_MASK) {
		/* (default) searching for preamble. */
	case 0:		/* GTC_DSSTAT_1_SFSTATE_SF_HUNT */
		param->ds_sf_state = GPON_SF_STATE_HUNT;
		break;
		/*  initial preamble(s) found. */
	case GTC_DSSTAT_1_SFSTATE_SF_PSYNC:
		param->ds_sf_state = GPON_SF_STATE_PRESYNC;
		break;
		/* reserved, this value is not used. */
	case GTC_DSSTAT_1_SFSTATE_RES:
		/* synchronous state. */
	case GTC_DSSTAT_1_SFSTATE_SF_SYNC:
		param->ds_sf_state = GPON_SF_STATE_SYNC;
		break;
	}

	param->onu_id = gtc_r32(downstr_gtc_id);
	/* PLOAMd message waiting in buffer */
	param->ds_ploam_waiting =
	    (stat & GTC_DSSTAT_1_RXDAT_DATA) ? true : false;
	/* PLOAMd message buffer overflow */
	param->ds_ploam_overflow = (stat & GTC_DSSTAT_1_RXOFL) ? true : false;

	param->gtc_ds_delay = gtc_psync_delay_get();
}

void gtc_ploam_request_only_enable(const uint32_t enable)
{
	if (enable)
		gtc_w32_mask(GTC_RTIME_1_O5_POST, 0, upstr_gtc_rtime_1);
	else
		gtc_w32_mask(0, GTC_RTIME_1_O5_POST, upstr_gtc_rtime_1);
}

uint32_t gtc_bip_value_get(void)
{
	return gtc_r32(downstr_gtc_berrcnt);
}

uint32_t gtc_trace_enabled(void)
{
	return (gtc_r32(upstr_gtc_bwmt_ctrl) & GTC_BWMT_CTRL_TRACE_EN) ?
		true : false;
}

/** Enable / disable downstream GTC interrupts
*/
void gtc_downstream_imask_set(const uint32_t dsimask)
{
	gtc_w32(dsimask, downstr_gtc_dsimask_1);
}

void gtc_delay_adjust(uint32_t reset)
{
	uint16_t delay_enable = 0;
	uint16_t delay_disable = 0;
	uint16_t size_fifo = 0, size_fifo_mean;
	uint8_t psdel;

	/* GPONSW-924:
	 * LDD Power Save truncates end of burst in extended burst
	 * length mode against ALU OLT
	 */
	if(is_falcon_chip_a2x())
		size_fifo_mean = 2048; /* bits -> 512 nibbles */
	else /* A12 */
		size_fifo_mean = 436; /* bits -> 109 nibbles */

	if (optic_ll_tx_fifo_get(&delay_enable, &delay_disable,
				 &size_fifo ) == 0) {
		if (reset) {
			size_fifo = size_fifo_mean;
		} else {
			/* psdel is a bit value */
			psdel = gtc_r32(downstr_gtc_dsdelstat) &
						       GTC_DSDELSTAT_PSDEL_MASK;
			/* A12: max value would be +8 nibbles -> 117 nibbles
			 * A22: max value is dont care, fifo is big enough */
			size_fifo = psdel + size_fifo_mean;
		}
		/* nibble calculation is done inside function */
		optic_ll_tx_fifo_set(delay_enable, delay_disable, size_fifo);
	}
}

uint32_t gtc_gem_rxbcnt_get(void)
{
	return gtc_r32(downstr_gem_rxbcnt);
}

uint32_t gtc_gem_rxfcnt_get(void)
{
	return gtc_r32(downstr_gem_rxfcnt);
}

uint32_t gtc_gem_fuerrcnt_get(void)
{
	return (gtc_r32(downstr_gtc_fuerrcnt) & GTC_FUERRCNT_UERR_MASK) >>
						GTC_FUERRCNT_UERR_OFFSET;
}

void gtc_refresh_rdi(void)
{
	if ((gtc_r32(downstr_gtc_dsstat_1) & GTC_DSSTAT_1_SF))
		gtc_w32_mask(GTC_USCON_IND5_YES, GTC_USCON_IND5_YES, upstr_gtc_uscon);
	else
		gtc_w32_mask(GTC_USCON_IND5_YES, 0, upstr_gtc_uscon);
}

void gtc_cnt_get(uint32_t *gem_herr_1,
		 uint32_t *gem_herr_2,
		 uint32_t *gem_bwmcerr,
		 uint32_t *gem_bwmuerr,
		 uint32_t *gtc_frcbcnt,
		 uint32_t *gtc_fcerrcnt,
		 uint32_t *gtc_fuerrcnt,
		 uint32_t *gtc_frcnt,
		 uint32_t *gem_rxfcnt,
		 uint32_t *alloc_total,
		 uint32_t *alloc_lost)
{
	*gem_herr_1 = gtc_r32(downstr_gem_herr_1);
	*gem_herr_2 = gtc_r32(downstr_gem_herr_2);
	*gem_bwmcerr = gtc_r32(downstr_gem_bwmcerr);
	*gem_bwmuerr = gtc_r32(downstr_gem_bwmuerr);
	*gtc_frcbcnt = gtc_r32(downstr_gtc_frcbcnt);
	*gtc_fcerrcnt = gtc_r32(downstr_gtc_fcerrcnt);
	*gtc_fuerrcnt = gtc_r32(downstr_gtc_fuerrcnt);
	*gtc_frcnt = gtc_r32(downstr_gtc_frcnt);
	*gem_rxfcnt = gtc_r32(downstr_gem_rxfcnt);
	*alloc_total = gtc_r32(upstr_gtc_all_tc);
	*alloc_lost = gtc_r32(upstr_gtc_rej_tc);
}

uint8_t gtc_ll_us_header_cfg_get(uint32_t data[32])
{
	uint32_t i;
	gtc_w32(0, upstr_gtc_ushdrc_ad);

	for (i = 0; i < 32; i++)
		data[i] = gtc_r32(upstr_gtc_ushdrc_rd);

	return gtc_r32(upstr_gtc_ushdl);
}

void gtc_ll_alarm_get(uint32_t *dsstat, uint32_t *dsistat,
		      uint32_t *usstat, uint32_t *usistat)
{
	if (dsstat)
		*dsstat = gtc_r32(downstr_gtc_dsstat_1);
	if (dsistat)
		*dsistat = gtc_r32(downstr_gtc_dsistat_1);

	if (usstat)
		*usstat = gtc_r32(upstr_gtc_usstat);
	if (usistat)
		*usistat = gtc_r32(upstr_gtc_usistat);
}

void gtc_ll_dsistat_set(uint32_t val)
{
	gtc_w32(val, downstr_gtc_dsistat_1);
}

void gtc_ll_usistat_set(uint32_t val)
{
	gtc_w32(val, upstr_gtc_usistat);
}

uint32_t gtc_ll_bwmstat_get(void)
{
	return gtc_r32(upstr_gtc_bwmstat);
}

void gtc_ll_bwmstat_set(uint32_t val)
{
	gtc_w32(val, upstr_gtc_bwmstat);
}

void gtc_ll_cfg_get(uint32_t *berrintv, uint32_t *rtime)
{
	*berrintv = gtc_r32(downstr_gtc_berrintv);
	*rtime = gtc_r32(upstr_gtc_rtime_3);
}

void gtc_rogue_set(const uint32_t msg_id, const uint32_t msg_rpt,
                  const uint32_t msg_enable)
{
	uint32_t val = msg_id;
	val |= ((msg_rpt << GTC_RST_ROGUE_RPT_USRST_OFFSET) & GTC_RST_ROGUE_RPT_USRST_MASK);
	if(msg_enable)
		val |= GTC_RST_ROGUE_EN;
	gtc_w32(val, downstr_gtc_rst_rogue);
}

void gtc_rogue_get(uint32_t *msg_id, uint32_t *msg_rpt,
                  uint32_t *msg_enable)
{
	uint32_t val;
	val = gtc_r32(downstr_gtc_rst_rogue);
	*msg_id = val & 0xff;
	*msg_rpt = (val & GTC_RST_ROGUE_RPT_USRST_MASK) >> GTC_RST_ROGUE_RPT_USRST_OFFSET;
	if(val & GTC_RST_ROGUE_EN)
		*msg_enable = true;
	else
		*msg_enable = false;
}


#if defined(INCLUDE_DUMP)

#ifdef INCLUDE_DEBUG_SUPPORT
struct bwm_entry {
	uint32_t addr, read, ptr;
};

#define MAX_BWM_ENTRIES 1024
static struct bwm_entry bwm_entries[MAX_BWM_ENTRIES];
static uint32_t bwm_len = 0;
#endif

void gtc_dump(struct seq_file *s)
{
	uint32_t i = 0;
	uint32_t addr, read, ptr;

	seq_printf(s, "gtc_dsstat_1,"
			"gtc_dsdelstat,"
			"gtc_dlos,"
			"gtc_sfwin\n");
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_dsstat_1));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_dsdelstat));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_dlos));
	seq_printf(s, "%08x\n", gtc_r32(downstr_gtc_sfwin));

	seq_printf(s, "gtc_sdwin,"
			"gtc_sfthr,"
			"gtc_sdthr,"
			"gtc_berrintv\n");
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_sdwin));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_sfthr));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_sdthr));
	seq_printf(s, "%08x\n", gtc_r32(downstr_gtc_berrintv));

	seq_printf(s, "gtc_gemstintv,"
			"gtc_pltout,"
			"gem_rstat,"
			"gtc_dstest_1\n");
	seq_printf(s, "%08x", gtc_r32(downstr_gtc_gemstintv));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_pltout));
	seq_printf(s, "%08x,", gtc_r32(downstr_gem_rstat));
	seq_printf(s, "%08x\n", gtc_r32(downstr_gtc_dstest_1));

	seq_printf(s, "gtc_dstest_2,"
			"gtc_scon,"
			"gtc_dscon_1,"
			"gtc_sfcnt\n");
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_dstest_2));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_scon));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_dscon_1));
	seq_printf(s, "%08x\n", gtc_r32(downstr_gtc_sfcnt));

	seq_printf(s, "aes_dekey[0],"
			"aes_dekey[1],"
			"aes_dekey[2],"
			"aes_dekey[3]\n");
	seq_printf(s, "%08x,", gtc_r32(downstr_aes_dekey[0]));
	seq_printf(s, "%08x,", gtc_r32(downstr_aes_dekey[1]));
	seq_printf(s, "%08x,", gtc_r32(downstr_aes_dekey[2]));
	seq_printf(s, "%08x\n", gtc_r32(downstr_aes_dekey[3]));

	seq_printf(s, "gtc_id,"
			"gtc_dsistat_1,"
			"gtc_dsimask_1,"
			"gtc_dscntrstat\n");
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_id));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_dsistat_1));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_dsimask_1));
	seq_printf(s, "%08x\n", gtc_r32(downstr_gtc_dscntrstat));

	seq_printf(s, "gtc_berrcnt,"
			"gem_herr_1,"
			"gem_herr_2,"
			"gem_bwmcerr\n");
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_berrcnt));
	seq_printf(s, "%08x,", gtc_r32(downstr_gem_herr_1));
	seq_printf(s, "%08x,", gtc_r32(downstr_gem_herr_2));
	seq_printf(s, "%08x\n", gtc_r32(downstr_gem_bwmcerr));

	seq_printf(s, "gem_bwmuerr,"
			"gem_rxfcnt,"
			"gem_rxbcnt,"
			"gtc_fcerrcnt\n");
	seq_printf(s, "%08x,", gtc_r32(downstr_gem_bwmuerr));
	seq_printf(s, "%08x,", gtc_r32(downstr_gem_rxfcnt));
	seq_printf(s, "%08x,", gtc_r32(downstr_gem_rxbcnt));
	seq_printf(s, "%08x\n", gtc_r32(downstr_gtc_fcerrcnt));

	seq_printf(s, "gtc_fuerrcnt,"
			"gtc_frcnt,"
			"gtc_frcbcnt,"
			"gtc_rst_rogue\n");
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_fuerrcnt));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_frcnt));
	seq_printf(s, "%08x,", gtc_r32(downstr_gtc_frcbcnt));
	seq_printf(s, "%08x\n", gtc_r32(downstr_gtc_rst_rogue));

	seq_printf(s, "gtc_rtime_1,"
			"gtc_rtime_2,"
			"gtc_rtime_3,"
			"gtc_usstat\n");
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_rtime_1));
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_rtime_2));
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_rtime_3));
	seq_printf(s, "%08x\n", gtc_r32(upstr_gtc_usstat));

	seq_printf(s, "gtc_usestat,"
			"gtc_uscon,"
			"gtc_ushdl,"
			"gtc_usistat,"
			"gtc_usimask\n");
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_usestat));
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_uscon));
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_ushdl));
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_usistat));
	seq_printf(s, "%08x\n", gtc_r32(upstr_gtc_usimask));

	seq_printf(s, "gtc_laser,"
			"gtc_ustest,"
			"gtc_usfetch,"
			"gtc_start_offset\n");
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_laser));
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_ustest));
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_usfetch));
	seq_printf(s, "%08x\n", gtc_r32(upstr_gtc_start_offset));

	seq_printf(s, "gtc_frm_range,"
			"gtc_all_tc,"
			"gtc_rej_tc\n");
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_frm_range));
	seq_printf(s, "%08x,", gtc_r32(upstr_gtc_all_tc));
	seq_printf(s, "%08x\n", gtc_r32(upstr_gtc_rej_tc));

#ifdef INCLUDE_DEBUG_SUPPORT
	seq_printf(s, "upstr_gtc_bwmaprh, upstr_gtc_bwmaprl\n");
	for (i = 0; i < 32; i++) {
		seq_printf(s, "%08x-", gtc_r32(upstr_gtc_bwmaprh[i]));
		seq_printf(s, "%08x\n", gtc_r32(upstr_gtc_bwmaprl[i]));
	}

	addr = gtc_r32(upstr_gtc_bwmb_ad) & GTC_BWMB_AD_ADDR_MASK;
	ptr = gtc_r32(upstr_gtc_bwmptr_act) & GTC_BWMPTR_ACT_RD_MASK;

	if (addr != ptr) {
		seq_printf(s, "bwmap dump\n");
		/* new data available, read first into buffer */
		bwm_len = 0;
		while (addr != ptr) {
			read = gtc_r32(upstr_gtc_bwmb_rd);
			bwm_entries[bwm_len].addr = addr;
			bwm_entries[bwm_len].ptr = ptr;
			bwm_entries[bwm_len].read = read;
			addr = gtc_r32(upstr_gtc_bwmb_ad) &
			    GTC_BWMB_AD_ADDR_MASK;
			ptr = gtc_r32(upstr_gtc_bwmptr_act) &
			    GTC_BWMPTR_ACT_RD_MASK;
			bwm_len++;
			if (bwm_len >= MAX_BWM_ENTRIES)
				break;
		}
	}

	for (i = 0; i < bwm_len; i++)
		seq_printf(s, "%08x %08x %08x\n", bwm_entries[i].addr,
						  bwm_entries[i].ptr,
						  bwm_entries[i].read);
#endif
}

#endif

/*! @} */

/*! @} */
