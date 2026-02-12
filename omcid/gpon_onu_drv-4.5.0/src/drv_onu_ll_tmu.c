/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_tmu.h"
#include "drv_onu_reg_tmu.h"

STATIC void tmu_basic_init(void);
STATIC void tmu_egress_queue_table_init(void);
STATIC void tmu_egress_port_table_init(void);
STATIC void tmu_sched_blk_in_table_init(void);
STATIC void tmu_sched_blk_out_table_init(void);
STATIC void tmu_token_bucket_shaper_table_init(void);
STATIC void tmu_packet_pointer_table_init(void);

STATIC uint32_t tmu_tbs_tbu_conversion(uint32_t);
STATIC uint32_t tmu_tbs_srm_conversion(uint32_t);
STATIC uint32_t tmu_tbs_rate_conversion(uint32_t, uint32_t);

extern onu_lock_t tmu_lock;

void tmu_enable(bool act)
{
	tmu_w32_mask(TMU_CTRL_ACT_EN, act ? TMU_CTRL_ACT_EN : 0, ctrl);
}

bool tmu_is_enabled(void)
{
	return (tmu_r32(ctrl) & TMU_CTRL_ACT_EN) ? true : false;
}

void tmu_init(void)
{
	struct tmu_equeue_drop_params thx;

	/*
	  Enable module clock, release reset. This is mandatory before
	  accessing module's registers.
	*/
	sys_gpe_hw_activate_or_reboot(	SYS_GPE_ACT_TMU_SET |
					SYS_GPE_ACT_CPUE_SET);
	tmu_basic_init();
	tmu_egress_queue_table_init();
	tmu_egress_port_table_init();
	tmu_sched_blk_in_table_init();
	tmu_sched_blk_out_table_init();
	tmu_token_bucket_shaper_table_init();
	tmu_packet_pointer_table_init();

	/* OMCI setup - should be fixed */
	tmu_create_flat_egress_path(1,  /* num_ports */
				    ONU_GPE_OMCI_EGRESS_PORT, /* epn */
				    ONU_GPE_SCHEDULER_INDEX_OMCI_US, /* sbid */
				    ONU_GPE_QUEUE_INDEX_OMCI_HI_US, /* qid */
				    1); /* qid_per_sb */

	tmu_equeue_drop_params_get(ONU_GPE_QUEUE_INDEX_OMCI_HI_US, &thx);
	thx.math0 = 8; /* 4096 byte queue length */
	thx.math1 = 8; /* 4096 byte queue length */
	thx.qrth  = 4; /* 2048 byte guaranteed reservation, one maximum size OMCI message */
	tmu_equeue_drop_params_set(ONU_GPE_QUEUE_INDEX_OMCI_HI_US, &thx);
}

STATIC void tmu_basic_init(void)
{
	uint32_t i;

	/*
	   - state machine frozen
	   - state machine de-activated */
	tmu_enable(false);

	/*
	   FPL settings are covered in PacketPointerTableInit as they they
	   belong functionally to PPT issues:
	   FPL.TFPP
	   FPL.HFPP */

	tmu_w32(PACKET_POINTER_TABLE_INDEX_MAX, fpcr);

	/* free pointer threshold: 0 = all pointers can be used */
	tmu_w32(0, fpthr);

	/* elapsed time since last token accumulation */
	tmu_w32(0, timer);

	/* random number */
	tmu_w32(1, lfsr);

	/* WRED crawler period (1024 clocks): 0 = disabled */
	tmu_w32(0x10, cpr);

	/* current value WRED crawler counter, last queue id served */
	tmu_w32(0, csr);

	/* global fill level (segments) */
	tmu_w32(0, goccr);

	/* all IRN irq acknowledged */
	tmu_w32(0, irncr);
	/* all IRN irq not set */
	tmu_w32(0, irnicr);
	/* all IRN irq disabled */
	tmu_w32(0, irnen);

	for (i = 0; i < 4; i++) {
		/* global occupancy threshold n (color n discard), set to total
		   SSB == 18432 segments */
		tmu_w32(0x3000, gothr[i]);
		tmu_w32(0, gpdcr[i]);
		tmu_w32(0, lpic[i]);
		tmu_w32(0, lpit[i]);
	}

	/* queue fill status for queues 0..31, 0: all queues not filled */
	/* ... */
	/* queue fill status for queues 224..255, 0: all queues not filled */
	for (i = 0; i < 8; i++)
		tmu_w32(0, qfill[i]);

	/* egress port fill status for queues  0..31, 0: all queues not
	   filled */
	/* ... */
	/* egress port fill status for queues 64..71, 0: all queues not
	   filled */
	for (i = 0; i < 3; i++)
		tmu_w32(0, epfr[i]);

	tmu_w32(0, tbidcr);
	/* QID 254 (OMCI upstream) only */
	tmu_w32_mask (TMU_QOCT0_QRTH_MASK, 0x100, qoct0);

	/* enable pipeline */
	tmu_relog_sequential(true);

	tmu_token_accumulation_disable(false);

	tmu_max_token_bucket_set(TOKEN_BUCKET_MAX);

	/* random number */
	tmu_random_number_set(0x0815);

	/* set default reset value */
	tmu_crawler_period_set(TMU_WRED_CRAWLER_PERIOD_DEFAULT);

	/* Enqueue Request Delay */
	tmu_enqueue_delay_set(TMU_ENQUEUE_REQUEST_DELAY_DEFAULT);

	/* token accumulation period, set to as fast as possible */
	tmu_tacc_period_set(TMU_TOKEN_ACC_PERIOD_DEFAULT);
}

void tmu_qemt_write(const uint32_t qid, const uint32_t epn)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(epn, qemt);
	tmu_w32(TMU_QMTC_QEW | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QEV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qemt_read(const uint32_t qid, uint32_t *epn)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_QMTC_QER | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QEV) == 0) {
	}
	*epn = tmu_r32(qemt);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qsmt_write(const uint32_t qid, const uint32_t sbin)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(sbin, qsmt);
	tmu_w32(TMU_QMTC_QSW | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QSV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qsmt_read(const uint32_t qid, uint32_t *sbin)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_QMTC_QSR | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QSV) == 0) {
	}
	*sbin = tmu_r32(qsmt);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qtht_write(const uint32_t qid, const uint32_t *qtht)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(qtht[0], qtht0);
	tmu_w32(qtht[1], qtht1);
	tmu_w32(qtht[2], qtht2);
	tmu_w32(qtht[3], qtht3);
	tmu_w32(qtht[4], qtht4);
	tmu_w32(TMU_QMTC_QTW | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QTV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qtht_read(const uint32_t qid, uint32_t *qtht)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_QMTC_QTR | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QTV) == 0) {
	}
	qtht[0] = tmu_r32(qtht0);
	qtht[1] = tmu_r32(qtht1);
	qtht[2] = tmu_r32(qtht2);
	qtht[3] = tmu_r32(qtht3);
	qtht[4] = tmu_r32(qtht4);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qoct_write(const uint32_t qid, const uint32_t wq,
		    const uint32_t qrth, const uint32_t qocc,
		    const uint32_t qavg)
{
	uint32_t tmp = ((wq << TMU_QOCT0_WQ_OFFSET) & TMU_QOCT0_WQ_MASK) |
			(qrth & TMU_QOCT0_QRTH_MASK);

	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(tmp, qoct0);
	tmu_w32(qocc & TMU_QOCT1_QOCC_MASK, qoct1);
	tmu_w32(qavg & TMU_QOCT2_QAVG_MASK, qoct2);
	tmu_w32(TMU_QMTC_QOW | qid, qmtc);

	while ((tmu_r32(qmtc) & TMU_QMTC_QOV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qoct_read(const uint32_t qid, uint32_t *wq, uint32_t *qrth,
		   uint32_t *qocc, uint32_t *qavg)
{
	uint32_t tmp;

	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_QMTC_QOR | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QOV) == 0) {
	}

	tmp = tmu_r32(qoct0);
	*wq = (tmp & TMU_QOCT0_WQ_MASK) >> TMU_QOCT0_WQ_OFFSET;
	*qrth = tmp & TMU_QOCT0_QRTH_MASK;
	*qocc = tmu_r32(qoct1) & TMU_QOCT1_QOCC_MASK;
	*qavg = tmu_r32(qoct2) & TMU_QOCT2_QAVG_MASK;
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qdct_write(const uint32_t qid, const uint32_t *qdc)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(qdc[0], qdct0);
	tmu_w32(qdc[1], qdct1);
	tmu_w32(qdc[2], qdct2);
	tmu_w32(qdc[3], qdct3);
	tmu_w32(TMU_QMTC_QDW | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QDV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qdct_read(const uint32_t qid, uint32_t *qdc)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_QMTC_QDR | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QDV) == 0) {
	}
	qdc[0] = tmu_r32(qdct0);
	qdc[1] = tmu_r32(qdct1);
	qdc[2] = tmu_r32(qdct2);
	qdc[3] = tmu_r32(qdct3);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qfmt_write(const uint32_t qid, const uint32_t *qfm)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(qfm[0], qfmt0);
	tmu_w32(qfm[1], qfmt1);
	tmu_w32(qfm[2], qfmt2);
	tmu_w32(TMU_QMTC_QFW | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QFV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_qfmt_read(const uint32_t qid, uint32_t *qfm)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_QMTC_QFR | qid, qmtc);
	while ((tmu_r32(qmtc) & TMU_QMTC_QFV) == 0) {
	}
	qfm[0] = tmu_r32(qfmt0);
	qfm[1] = tmu_r32(qfmt1);
	qfm[2] = tmu_r32(qfmt2);
	onu_spin_lock_release(&tmu_lock, flags);
}

/**
   Egress Queue Table (EQT) comprises the following tables:
   QEMT: Queue Egress Mapping Table
   QSMT: Queue Scheduler Mapping Table
   QTHT: Queue Manager and Threshold Table
   QOCT: Queue Occupancy Table
   QDCT: Queue Discard Table
   QFMT: Queue FIFO Manager Table

   all egress queues are considered unused (inactive) after initialization
   an egress queue must be explicitely "created" with
   \ref tmu_egress_queue_create in order to participate in the data path
   all unused egress queues are connected to SB Input
   \ref NULL_SCHEDULER_INPUT_ID, which is considered reserved
   all egress queues are initially disabled
*/
STATIC void tmu_egress_queue_table_init(void)
{
	uint32_t i;
	uint32_t qtht[5];
	uint32_t qdc[4] = { 0, 0, 0, 0 };
	uint32_t qfm[3] = { 0, 0x3FFF3FFF, 0 };

	/* queue disabled, no admission of packets
	   dropping mode = tail drop
	   color 3 (red) mapped to Threshold Index 1 (QTTH1)
	   color 2 (yellow) mapped to Threshold Index 3 (MATH1)
	   color 1 (green) mapped to Threshold Index 2 (MATH0)
	   color 0 (unassigned) mapped to Threshold Index 0 (QTTH0) */
	qtht[0] = 0x00001320;
	/* minimum threshold for WRED curve 0/1:
	   in units of 8 segments, 0x900 = 2304, 2304*8=18432 is total SSB */
	qtht[1] = 0x09000900;
	/* maximum threshold for WRED curve 0/1:
	   in units of 8 segments, 0x900 = 2304, 2304*8=18432 is total SSB */
	qtht[2] = 0x09000900;
	/* slope of WRED curve 0/1: set to max */
	qtht[3] = 0x0fff0fff;
	/* tail drop threshold 0/1, in units of 8 segments, set to total SSB */
	qtht[4] = 0x09000900;

	for (i = 0; i < EGRESS_QUEUE_ID_MAX; i++) {
		tmu_qemt_write(i, EPNNULL_EGRESS_PORT_ID);

		/* write QSMT table, assign to reserved scheduler input */
		tmu_qsmt_write(i, NULL_SCHEDULER_INPUT_ID);

		/* write QTHT table */
		tmu_qtht_write(i, &qtht[0]);

		/*  write QOCT table */
		/* Weight, used for WRED average calc: 2**(-WQ)
		   queue reservation threshold: no reservation */
		/* queue occupancy, in units of segments, initially empty */
		/* queue average fill level of WRED, in units of segments,
		   initially empty */
		tmu_qoct_write(i, 10, 0, 0, 0);

		/*  write QDCT table */
		/* queue discard counter for color 0/1/2/3, counts PDUs,
		   initially zero discards */
		tmu_qdct_write(i, &qdc[0]);

		/*  write QFMT table */
		/* queue filled indication, is initially 0
		   queue occupancy, in units of packets, initially empty = 0 */
		/* tail queue packet pointer, 3FFF=NIL
		   (0x3fff > 9215 = 0x23FF = PACKET_POINTER_TABLE_INDEX_MAX)
		   head queue packet pointer, 3FFF=NIL */
		/* read only, QOS length used for scheduling and shaping
		   PDU color, set to unassigned = 0
		   PDU length in segments, initially set to 0 */
		tmu_qfmt_write(i, &qfm[0]);
	}
}

void tmu_epmt_write(const uint32_t epn, const uint32_t epe,
		    const uint32_t sbid)
{
	uint32_t tmp = sbid & TMU_EPMT_SBID_MASK;
	unsigned long flags = 0;

	if (epe)
		tmp |= TMU_EPMT_EPE;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(tmp, epmt);
	tmu_w32(TMU_EPMTC_EMW | epn, epmtc);
	while ((tmu_r32(epmtc) & TMU_EPMTC_EMV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_epmt_read(const uint32_t epn, uint32_t *epe, uint32_t *sbid)
{
	uint32_t tmp;
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_EPMTC_EMR | epn, epmtc);
	while ((tmu_r32(epmtc) & TMU_EPMTC_EMV) == 0) {
	}
	tmp = tmu_r32(epmt);
	onu_spin_lock_release(&tmu_lock, flags);

	*sbid = tmp & TMU_EPMT_SBID_MASK;
	*epe = (tmp & TMU_EPMT_EPE) ? 1 : 0;
}

void tmu_epot_write(const uint32_t epn, const uint32_t *epoc)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(epoc[0], epot0);
	tmu_w32(epoc[1], epot1);
	tmu_w32(TMU_EPMTC_EOW | epn, epmtc);
	while ((tmu_r32(epmtc) & TMU_EPMTC_EOV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_epot_read(const uint32_t epn, uint32_t *epoc)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_EPMTC_EOR | epn, epmtc);
	while ((tmu_r32(epmtc) & TMU_EPMTC_EOV) == 0) {
	}
	epoc[0] = tmu_r32(epot0);
	epoc[1] = tmu_r32(epot1);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_eptt_write(const uint32_t epn, const uint32_t *ept)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(ept[0], eptt0);
	tmu_w32(ept[1], eptt1);
	tmu_w32(TMU_EPMTC_ETW | epn, epmtc);
	while ((tmu_r32(epmtc) & TMU_EPMTC_ETV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_eptt_read(const uint32_t epn, uint32_t *ept)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_EPMTC_ETR | epn, epmtc);
	while ((tmu_r32(epmtc) & TMU_EPMTC_ETV) == 0) {
	}
	ept[0] = tmu_r32(eptt0);
	ept[1] = tmu_r32(eptt1);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_epdt_write(const uint32_t epn, const uint32_t *epd)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(epd[0], epdt0);
	tmu_w32(epd[1], epdt1);
	tmu_w32(epd[2], epdt2);
	tmu_w32(epd[3], epdt3);
	tmu_w32(TMU_EPMTC_EDW | epn, epmtc);
	while ((tmu_r32(epmtc) & TMU_EPMTC_EDV) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_epdt_read(const uint32_t epn, uint32_t *epd)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_EPMTC_EDR | epn, epmtc);
	while ((tmu_r32(epmtc) & TMU_EPMTC_EDV) == 0) {
	}
	epd[0] = tmu_r32(epdt0);
	epd[1] = tmu_r32(epdt1);
	epd[2] = tmu_r32(epdt2);
	epd[3] = tmu_r32(epdt3);
	onu_spin_lock_release(&tmu_lock, flags);
}

/**
   Egress Port Table (EPT) comprises the following tables:
   EPMT: Egress Port Mapping Table
   EPOT: Egress Port Occupancy Table
   EPTT: Egress Port Threshold Table
   EPDT: Egress Port Discard Table

   an egress port must be explicitely "created" in order to participate
   in the data path
   all egress ports are initially disabled for transmission
   each egress port has the reserved scheduler block 127 attached
*/
STATIC void tmu_egress_port_table_init(void)
{
	uint32_t i;
	uint32_t epoc[2] = { 0, 0 };
	uint32_t ept[2] = { 0x9000900, 0x9000900 };
	uint32_t epd[4] = { 0, 0, 0, 0 };

	for (i = 0; i < EGRESS_PORT_ID_MAX; i++) {
		/* egress port mapping table, all port disabled scheduler
		   block ID = NULL_SCHEDULER_BLOCK_ID */
		tmu_epmt_write(i, 0, NULL_SCHEDULER_BLOCK_ID);

		/* egress port fill level for color 0/1/2/3, initially empty */
		tmu_epot_write(i, &epoc[0]);

		/* egress port discard threshold for color 0/1/2/3, set to
		   max = total SSB */
		tmu_eptt_write(i, &ept[0]);

		/* number of discarded PDUs for color 0/1/2/3 set to 0 */
		tmu_epdt_write(i, &epd[0]);
	}
}

/**
   Scheduler Block Input Table (SBIT)
   all inputs disabled
   no shapers enabled
   default configuration: every scheduler block input has "reserved"
   queue 255 attached.
*/
STATIC void tmu_sched_blk_in_table_init(void)
{
	uint32_t i;
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	for (i = 0; i < SCHEDULER_BLOCK_INPUT_ID_MAX; i++) {
		/* input disabled
		   inverse WFQ weight: 0 = strict priority
		   (smaller values for higher prio)
		   queue type: 0 = queue */
		tmu_w32(0xFF, sbitr0);

		/* token bucket disabled, no shaping */
		tmu_w32(255, sbitr1);
		tmu_w32(0, sbitr2);
		tmu_w32(0, sbitr3);

		tmu_w32(TMU_SBITC_RW_W | TMU_SBITC_SEL | i, sbitc);
		while ((tmu_r32(sbitc) & TMU_SBITC_VAL) == 0) {
		}
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

/**
   Scheduler Block Output Table (SBOT)
   all 128 SB are unused (inactive) after initialization
   all outputs disabled
*/
STATIC void tmu_sched_blk_out_table_init(void)
{
	uint32_t i;
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	for (i = 0; i < SCHEDULER_BLOCK_ID_MAX; i++) {
		/* output disabled
		   hierarchy level of the SB: 0 (numbered from ingress side).
		   Note: typically max level is 3. Theoretically max is 8,
		   but this may cause performance problems with high bandwidth.
		   output is connected reserved egress port 72 */
		tmu_w32(EPNNULL_EGRESS_PORT_ID, sbotr0);

		/* output initially not filled default winner
		   leaf (local SB input 0..7)) NIL winner QID */
		tmu_w32(0xFF, sbotr1);

		tmu_w32(TMU_SBOTC_RW | TMU_SBOTC_SEL | i, sbotc);
		while ((tmu_r32(sbotc) & TMU_SBOTC_VAL) == 0) {
		}
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

/**
   Token Bucket Shaper Table (TBST)
   all TB disabled
   color blind
   NIL Scheduler Block Input ID (SBIN)
*/
STATIC void tmu_token_bucket_shaper_table_init(void)
{
	uint32_t i;
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	for (i = 0; i <= TOKEN_BUCKET_MAX; i++) {
		/* color blind token bucket attached to reserved scheduler
		   input 1023 */
		tmu_w32(NULL_SCHEDULER_INPUT_ID, tbstr0);
		/* all buckets disabled
		   64 bytes max time between accumulations (lowest rate) */
		tmu_w32(0xFFFF, tbstr1);
		tmu_w32(0xFFFF, tbstr2);
		/* bucket 0/1: max size of bucket in bytes,
		   0 will block (lowest rate) */
		tmu_w32(0, tbstr3);
		tmu_w32(0, tbstr4);
		/* status values ... */
		tmu_w32(0, tbstr5);
		tmu_w32(0, tbstr6);
		tmu_w32(0, tbstr7);
		tmu_w32(0, tbstr8);
		tmu_w32(0, tbstr9);
		tmu_w32(0, tbstr10);

		tmu_w32(TMU_TBSTC_RW | TMU_TBSTC_SEL | i, tbstc);
		while ((tmu_r32(tbstc) & TMU_TBSTC_VAL) == 0) {
		}
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

/**
   Packet Pointer Table (PPT)
   set up linked list
*/
STATIC void tmu_packet_pointer_table_init(void)
{
	uint32_t i, tmp;
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	/* loop over all PPT entries */
	for (i = 0; i < PACKET_POINTER_TABLE_INDEX_MAX; i++) {
		tmp = (i + 1) % (PACKET_POINTER_TABLE_INDEX_MAX);
		tmu_w32((tmp << TMU_PPT0_PNEXT_OFFSET) & TMU_PPT0_PNEXT_MASK,
			ppt0);
		tmu_w32(0, ppt1);
		tmu_w32(0, ppt2);
		tmu_w32(0, ppt3);

		tmu_w32(TMU_PPTC_RW | i, pptc);
		while ((tmu_r32(pptc) & TMU_PPTC_VAL) == 0) {
		}
	}
	onu_spin_lock_release(&tmu_lock, flags);

	tmu_w32(((PACKET_POINTER_TABLE_INDEX_MAX-1) << TMU_FPL_TFPP_OFFSET)
		& TMU_FPL_TFPP_MASK, fpl);
}

void tmu_equeue_enable(const uint32_t qid, bool ena)
{
/*
   QTHT[qid].QE = ena;
*/
	uint32_t qtht[5];

	tmu_qtht_read(qid, &qtht[0]);
	if (ena == true)
		qtht[0] |= TMU_QTHT0_QE_EN;
	else
		qtht[0] &= ~TMU_QTHT0_QE_EN;
	tmu_qtht_write(qid, &qtht[0]);
}

bool tmu_is_equeue_enabled(const uint32_t qid)
{
	uint32_t qtht[5];

	tmu_qtht_read(qid, &qtht[0]);

	return (qtht[0] & TMU_QTHT0_QE_EN) ? true : false;
}

void tmu_equeue_link_set(const uint32_t qid, struct tmu_equeue_link *equeue_link)
{
/*
   QEMT[qid].EPN  = equeue_link->epn;
   QSMT[qid].SBID = equeue_link->sbid;
*/
	uint32_t qemt;
	uint32_t qsmt;

	tmu_qemt_read(qid, &qemt);
	tmu_qsmt_read(qid, &qsmt);

	set_val(qemt, equeue_link->epn, TMU_QEMT_EPN_MASK, TMU_QEMT_EPN_OFFSET);
	set_val(qsmt, equeue_link->sbin, TMU_QSMT_SBIN_MASK, TMU_QSMT_SBIN_OFFSET);

	tmu_qemt_write(qid, qemt);
	tmu_qsmt_write(qid, qsmt);
}

void tmu_equeue_link_get(const uint32_t qid, struct tmu_equeue_link *equeue_link)
{
/*
   equeue_link->qe   = QTHT[qid].QE;
   equeue_link->epn  = QEMT[qid].EPN;
   equeue_link->sbid = QSMT[qid].SBID;
*/
	uint32_t qemt;
	uint32_t qsmt;

	tmu_qemt_read(qid, &qemt);
	tmu_qsmt_read(qid, &qsmt);

	equeue_link->qe = tmu_is_equeue_enabled(qid);
	equeue_link->epn = get_val(qemt, TMU_QEMT_EPN_MASK, TMU_QEMT_EPN_OFFSET);
	equeue_link->sbin = get_val(qsmt, TMU_QSMT_SBIN_MASK, TMU_QSMT_SBIN_OFFSET);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_equeue_color_thr_map_set(const uint32_t qid,
				  struct tmu_equeue_drop_params *map)
{
/*
   QTHT[qid].COL0 = map->col[0];
   QTHT[qid].COL1 = map->col[1];
   QTHT[qid].COL2 = map->col[2];
   QTHT[qid].COL3 = map->col[3];
*/
	uint32_t qtht[5];

	tmu_qtht_read(qid, &qtht[0]);

	set_val(qtht[0], map->col[0], TMU_QTHT0_COL0_MASK,
		TMU_QTHT0_COL0_OFFSET);
	set_val(qtht[0], map->col[1], TMU_QTHT0_COL1_MASK,
		TMU_QTHT0_COL1_OFFSET);
	set_val(qtht[0], map->col[2], TMU_QTHT0_COL2_MASK,
		TMU_QTHT0_COL2_OFFSET);
	set_val(qtht[0], map->col[3], TMU_QTHT0_COL3_MASK,
		TMU_QTHT0_COL3_OFFSET);

	tmu_qtht_write(qid, &qtht[0]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_equeue_color_thr_map_get(const uint32_t qid,
				  struct tmu_equeue_drop_params *map)
{
/*
   map->col[0]  QTHT[qid].COL0;
   map->col[1]  QTHT[qid].COL1;
   map->col[2]  QTHT[qid].COL2;
   map->col[3]  QTHT[qid].COL3;
*/
	uint32_t qtht[5];

	tmu_qtht_read(qid, &qtht[0]);

	map->col[0] = get_val(qtht[0], TMU_QTHT0_COL0_MASK,
			      TMU_QTHT0_COL0_OFFSET);
	map->col[1] = get_val(qtht[0], TMU_QTHT0_COL1_MASK,
			      TMU_QTHT0_COL1_OFFSET);
	map->col[2] = get_val(qtht[0], TMU_QTHT0_COL2_MASK,
			      TMU_QTHT0_COL2_OFFSET);
	map->col[3] = get_val(qtht[0], TMU_QTHT0_COL3_MASK,
			      TMU_QTHT0_COL3_OFFSET);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_equeue_drop_params_set(uint32_t qid,
				struct tmu_equeue_drop_params *thx)
{
/*
   QOCT[qid].WQ =    thx->wq;
   QOCT[qid].QRTH =  thx->qrth;

   QTHT[qid].QE =    thx->qe;
   QTHT[qid].DMOD =  thx->dmod;
   QTHT[qid].COL0 =  thx->col[0];
   QTHT[qid].COL1 =  thx->col[1];
   QTHT[qid].COL2 =  thx->col[2];
   QTHT[qid].COL3 =  thx->col[3];
   QTHT[qid].MITH0 = thx->mith0 >> 3;
   QTHT[qid].MITH1 = thx->mith1 >> 3;
   QTHT[qid].MATH0 = thx->math0 >> 3;
   QTHT[qid].MATH1 = thx->math1 >> 3;
   QTHT[qid].SLOPE0 = thx->maxp0<<4;
   QTHT[qid].SLOPE1 = thx->maxp1<<4;
   QTHT[qid].QTHT0 = thx->qtht0 >> 3;
   QTHT[qid].QTHT1 = thx->qtht1 >> 3;
*/
	uint32_t qtht[5] = { 0 };
	uint32_t slope0, slope1;
	uint32_t wq, qrth, qocc, qavg;

	tmu_qoct_read(qid, &wq, &qrth, &qocc, &qavg);

	if (thx->qe == true)
		qtht[0] |= TMU_QTHT0_QE_EN;
	else
		qtht[0] &= ~TMU_QTHT0_QE_EN;

	if (thx->dmod == 1)
		qtht[0] |= TMU_QTHT0_DMOD_WR;
	else
		qtht[0] &= ~TMU_QTHT0_DMOD_WR;


	set_val(qtht[0], thx->col[0], TMU_QTHT0_COL0_MASK,
		TMU_QTHT0_COL0_OFFSET);
	set_val(qtht[0], thx->col[1], TMU_QTHT0_COL1_MASK,
		TMU_QTHT0_COL1_OFFSET);
	set_val(qtht[0], thx->col[2], TMU_QTHT0_COL2_MASK,
		TMU_QTHT0_COL2_OFFSET);
	set_val(qtht[0], thx->col[3], TMU_QTHT0_COL3_MASK,
		TMU_QTHT0_COL3_OFFSET);

	set_val(qtht[1], thx->mith0 >> 3, TMU_QTHT1_MITH0_MASK,
		TMU_QTHT1_MITH0_OFFSET);
	set_val(qtht[1], thx->mith1 >> 3, TMU_QTHT1_MITH1_MASK,
		TMU_QTHT1_MITH1_OFFSET);

	set_val(qtht[2], thx->math0 >> 3, TMU_QTHT2_MATH0_MASK,
		TMU_QTHT2_MATH0_OFFSET);
	set_val(qtht[2], thx->math1 >> 3, TMU_QTHT2_MATH1_MASK,
		TMU_QTHT2_MATH1_OFFSET);
	if (thx->math0 != thx->mith0) {
		slope0 = (thx->maxp0 << 7) / (thx->math0 - thx->mith0);
		if (slope0 > 0xfff)
			slope0 = 0xfff;
	} else {
		slope0 = 0xfff;
	}
	if (thx->math1 != thx->mith1) {
		slope1 = (thx->maxp1 << 7) / (thx->math1 - thx->mith1);
		if (slope1 > 0xfff)
			slope1 = 0xfff;
	} else {
		slope1 = 0xfff;
	}
	set_val(qtht[3], slope0, TMU_QTHT3_SLOPE0_MASK,
		TMU_QTHT3_SLOPE0_OFFSET);
	set_val(qtht[3], slope1, TMU_QTHT3_SLOPE1_MASK,
		TMU_QTHT3_SLOPE1_OFFSET);

	set_val(qtht[4], thx->qtth0 >> 3, TMU_QTHT4_QTTH0_MASK,
		TMU_QTHT4_QTTH0_OFFSET);
	set_val(qtht[4], thx->qtth1 >> 3, TMU_QTHT4_QTTH1_MASK,
		TMU_QTHT4_QTTH1_OFFSET);

	tmu_qoct_write(qid, thx->wq, thx->qrth, qocc, qavg);
	tmu_qtht_write(qid, &qtht[0]);
}

void tmu_equeue_drop_params_get(uint32_t qid,
				struct tmu_equeue_drop_params *thx)
{
/*
   thx->wq    = QOCT[qid].WQ;
   thx->qrth  = QOCT[qid].QRTH;

   thx->qe    = QTHT[qid].QE;
   thx->dmod  = QTHT[qid].DMOD;
   thx->col[0]= QTHT[qid].COL0;
   thx->col[1]= QTHT[qid].COL1;
   thx->col[2]= QTHT[qid].COL2;
   thx->col[3]= QTHT[qid].COL3;
   thx->mith0 = QTHT[qid].MITH0 << 3;
   thx->mith1 = QTHT[qid].MITH1 << 3;
   thx->math0 = QTHT[qid].MATH0 << 3;
   thx->math1 = QTHT[qid].MATH1 << 3;
   thx->maxp0 = QTHT[qid].SLOPE0 >> 4;
   thx->maxp1 = QTHT[qid].SLOPE1 >> 4;
   thx->qtht0 = QTHT[qid].QTHT0 << 3;
   thx->qtht1 = QTHT[qid].QTHT1 << 3;
*/
	uint32_t wq, qocc, qavg;
	uint32_t qtht[5];
	uint32_t slope0, slope1;

	tmu_qoct_read(qid, &wq, &thx->qrth, &qocc, &qavg);
	tmu_qtht_read(qid, &qtht[0]);

	thx->wq = (uint8_t)wq;

	thx->qe = (qtht[0] & TMU_QTHT0_QE_EN) ? true : false;
	thx->dmod = (qtht[0] & TMU_QTHT0_DMOD_WR) ? 1 : 0;

	thx->col[0] = get_val(qtht[0], TMU_QTHT0_COL0_MASK,
			      TMU_QTHT0_COL0_OFFSET);
	thx->col[1] = get_val(qtht[0], TMU_QTHT0_COL1_MASK,
			      TMU_QTHT0_COL1_OFFSET);
	thx->col[2] = get_val(qtht[0], TMU_QTHT0_COL2_MASK,
			      TMU_QTHT0_COL2_OFFSET);
	thx->col[3] = get_val(qtht[0], TMU_QTHT0_COL3_MASK,
			      TMU_QTHT0_COL3_OFFSET);

	thx->mith0 = get_val(qtht[1], TMU_QTHT1_MITH0_MASK,
			     TMU_QTHT1_MITH0_OFFSET);
	thx->mith1 = get_val(qtht[1], TMU_QTHT1_MITH1_MASK,
			     TMU_QTHT1_MITH1_OFFSET);
	thx->math0 = get_val(qtht[2], TMU_QTHT2_MATH0_MASK,
			     TMU_QTHT2_MATH0_OFFSET);
	thx->math1 = get_val(qtht[2], TMU_QTHT2_MATH1_MASK,
			     TMU_QTHT2_MATH1_OFFSET);

	slope0 = get_val(qtht[3], TMU_QTHT3_SLOPE0_MASK,
			 TMU_QTHT3_SLOPE0_OFFSET);
	slope1 = get_val(qtht[3], TMU_QTHT3_SLOPE1_MASK,
			 TMU_QTHT3_SLOPE1_OFFSET);

	thx->maxp0 = (slope0  * (thx->math0 - thx->mith0)) >> 4;
	thx->maxp1 = (slope1  * (thx->math1 - thx->mith1)) >> 4;

	thx->qtth0 = get_val(qtht[4], TMU_QTHT4_QTTH0_MASK,
			     TMU_QTHT4_QTTH0_OFFSET);
	thx->qtth1 = get_val(qtht[4], TMU_QTHT4_QTTH1_MASK,
			     TMU_QTHT4_QTTH1_OFFSET);
	thx->mith0 <<= 3;
	thx->mith1 <<= 3;
	thx->math0 <<= 3;
	thx->math1 <<= 3;
	thx->qtth0 <<= 3;
	thx->qtth1 <<= 3;
}

void tmu_equeue_fill_status_get(uint32_t *qfill)
{
	int reg;

	for (reg = 0; reg < 8; reg++)
		qfill[reg] = tmu_r32(qfill[reg]);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_equeue_seg_occupancy_get(uint32_t qid, uint32_t *qocc)
{
	uint32_t wq, qrth, qavg;

	tmu_qoct_read(qid, &wq, &qrth, qocc, &qavg);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_equeue_pdu_occupancy_get(uint32_t qid, uint32_t *pocc)
{
	uint32_t qfm[3];

	tmu_qfmt_read(qid, &qfm[0]);

	*pocc = get_val(qfm[0], TMU_QFMT0_POCC_MASK, TMU_QFMT0_POCC_OFFSET);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_equeue_average_get(uint32_t qid, uint32_t *qavg)
{
	uint32_t wq, qrth, qocc;

	tmu_qoct_read(qid, &wq, &qrth, &qocc, qavg);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_equeue_discard_counters_set(uint32_t qid, uint32_t *qdc)
{
	tmu_qdct_write(qid, qdc);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_equeue_discard_counters_get(uint32_t qid, uint32_t *qdc)
{
	tmu_qdct_read(qid, qdc);
}

void tmu_eport_discard_counters_get(const uint32_t epn, uint32_t *epd)
{
	tmu_epdt_read(epn, epd);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_equeue_status_get(const uint32_t qid,
			   struct tmu_equeue_status *eqstatus)
{
	uint32_t qfm[3];
	uint32_t wq, qrth;
	uint32_t qfill_reg;
	uint32_t qfill_bit;

	tmu_qoct_read(qid, &wq, &qrth, &eqstatus->qocc, &eqstatus->qavg);
	tmu_qfmt_read(qid, &qfm[0]);

	qfill_reg = qid / 32;
	qfill_bit = 1 << (qid % 32);

	eqstatus->qf = tmu_r32(qfill[qfill_reg]) & qfill_bit ? true : false;
	eqstatus->pocc = get_val(qfm[0], TMU_QFMT0_POCC_MASK,
			       TMU_QFMT0_POCC_OFFSET);
	eqstatus->hqpp = get_val(qfm[1], TMU_QFMT1_HQPP_MASK,
			       TMU_QFMT1_HQPP_OFFSET);
	eqstatus->tqpp = get_val(qfm[1], TMU_QFMT1_TQPP_MASK,
			       TMU_QFMT1_TQPP_OFFSET);
	eqstatus->qosl = get_val(qfm[2], TMU_QFMT2_QOSL_MASK,
			       TMU_QFMT2_QOSL_OFFSET);
	eqstatus->col = get_val(qfm[2], TMU_QFMT2_COL_MASK, TMU_QFMT2_COL_OFFSET);
	eqstatus->segl = get_val(qfm[2], TMU_QFMT2_SEGL_MASK,
			       TMU_QFMT2_SEGL_OFFSET);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_cfgcmd_write(const uint32_t cfgcmd)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(cfgcmd, cfgcmd);
	while ((tmu_r32(cfgcmd) & TMU_CFGCMD_VAL) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_cfgcmd_read(uint32_t *cfgcmd)
{
	*cfgcmd = tmu_r32(cfgcmd);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_sbit_write(const uint32_t sbin, const uint32_t *sbit)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(sbit[0], sbitr0);
	tmu_w32(sbit[1], sbitr1);
	tmu_w32(sbit[2], sbitr2);
	tmu_w32(sbit[3], sbitr3);
	tmu_w32(TMU_SBITC_RW_W | TMU_SBITC_SEL | sbin, sbitc);
	while ((tmu_r32(sbitc) & TMU_SBITC_VAL) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_sbit_read(const uint32_t sbin, uint32_t *sbit)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_SBITC_SEL | sbin, sbitc);
	while ((tmu_r32(sbitc) & TMU_SBITC_VAL) == 0) {
	}
	sbit[0] = tmu_r32(sbitr0);
	sbit[1] = tmu_r32(sbitr1);
	sbit[2] = tmu_r32(sbitr2);
	sbit[3] = tmu_r32(sbitr3);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_sbot_write(const uint32_t sbid, const uint32_t *sbot)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(sbot[0], sbotr0);
	tmu_w32(sbot[1], sbotr1);
	tmu_w32(TMU_SBOTC_RW_W | TMU_SBOTC_SEL | sbid, sbotc);
	while ((tmu_r32(sbotc) & TMU_SBOTC_VAL) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_sbot_read(const uint32_t sbid, uint32_t *sbot)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_SBOTC_SEL | sbid, sbotc);
	while ((tmu_r32(sbotc) & TMU_SBOTC_VAL) == 0) {
	}
	sbot[0] = tmu_r32(sbotr0);
	sbot[1] = tmu_r32(sbotr1);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_sbot_write_cfg(const uint32_t sbid, const uint32_t *sbot)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(sbot[0], sbotr0);
	tmu_w32(TMU_SBOTC_RW_W | sbid, sbotc);
	while ((tmu_r32(sbotc) & TMU_SBOTC_VAL) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_sbot_read_cfg(const uint32_t sbid, uint32_t *sbot)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32( sbid, sbotc);
	while ((tmu_r32(sbotc) & TMU_SBOTC_VAL) == 0) {
	}
	sbot[0] = tmu_r32(sbotr0);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_tbst_write(const uint32_t tbid, const uint32_t *tbst)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(tbst[0], tbstr0);
	tmu_w32(tbst[1], tbstr1);
	tmu_w32(tbst[2], tbstr2);
	tmu_w32(tbst[3], tbstr3);
	tmu_w32(tbst[4], tbstr4);
	tmu_w32(tbst[5], tbstr5);
	tmu_w32(tbst[6], tbstr6);
	tmu_w32(tbst[7], tbstr7);
	tmu_w32(tbst[8], tbstr8);
	tmu_w32(tbst[9], tbstr9);
	tmu_w32(tbst[10], tbstr10);
	tmu_w32(TMU_TBSTC_RW_W | TMU_TBSTC_SEL | tbid, tbstc);
	while ((tmu_r32(tbstc) & TMU_TBSTC_VAL) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_tbst_read(const uint32_t tbid, uint32_t *tbst)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(TMU_TBSTC_SEL | tbid, tbstc);
	while ((tmu_r32(tbstc) & TMU_TBSTC_VAL) == 0) {
	}
	tbst[0] = tmu_r32(tbstr0);
	tbst[1] = tmu_r32(tbstr1);
	tbst[2] = tmu_r32(tbstr2);
	tbst[3] = tmu_r32(tbstr3);
	tbst[4] = tmu_r32(tbstr4);
	tbst[5] = tmu_r32(tbstr5);
	tbst[6] = tmu_r32(tbstr6);
	tbst[7] = tmu_r32(tbstr7);
	tbst[8] = tmu_r32(tbstr8);
	tbst[9] = tmu_r32(tbstr9);
	tbst[10] = tmu_r32(tbstr10);
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_tbst_write_cfg(const uint32_t tbid, const uint32_t *tbst)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(tbst[0], tbstr0);
	tmu_w32(tbst[1], tbstr1);
	tmu_w32(tbst[2], tbstr2);
	tmu_w32(tbst[3], tbstr3);
	tmu_w32(tbst[4], tbstr4);
	tmu_w32(TMU_TBSTC_RW_W | tbid, tbstc);
	while ((tmu_r32(tbstc) & TMU_TBSTC_VAL) == 0) {
	}
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_tbst_read_cfg(const uint32_t tbid, uint32_t *tbst)
{
	unsigned long flags = 0;

	onu_spin_lock_get(&tmu_lock, &flags);
	tmu_w32(tbid, tbstc);
	while ((tmu_r32(tbstc) & TMU_TBSTC_VAL) == 0) {
	}
	tbst[0] = tmu_r32(tbstr0);
	tbst[1] = tmu_r32(tbstr1);
	tbst[2] = tmu_r32(tbstr2);
	tbst[3] = tmu_r32(tbstr3);
	tbst[4] = tmu_r32(tbstr4);
	tbst[5] = -1;
	tbst[6] = -1;
	tbst[7] = -1;
	tbst[8] = -1;
	tbst[9] = -1;
	tbst[10] = -1;
	onu_spin_lock_release(&tmu_lock, flags);
}

void tmu_egress_port_enable(const uint32_t epn, bool ena)
{
/*
   EPMT[epn].EPE = ena;

   Implementation requirement
   Must do both writes below in the given sequence:
   1.
   EPMTR  = 1 << TMU_EPMT_EPE;
   EPMTR |= (SBID & TMU_EPMT_SBID__MSK ) << TMU_EPMT_SBID;
   TMU_REG_WR(EPMT,EPMTR);
   TMU_REG_WR(EPMTC,(0x1 << TMU_EPMTC_EMW) | EPN );

   2.
   CFGCMD = (TMU_CFGCMD_CMD_EP_on__VAL & TMU_CFGCMD_CMD__MSK)<<TMU_CFGCMD_CMD;
   CFGCMD |= (EPN & TMU_CFGEPN_EPN__MSK) << TMU_CFGEPN_EPN;
   TMU_REG_WR(CFGCMD, CFGCMD);

   Direct write of EPMT[epn].EPE is not recommended during operation
*/
	uint32_t cfgcmd = 0;
	uint32_t old_epe, sbid;

	cfgcmd |= ena ? TMU_CFGCMD_CMD_EP_on : TMU_CFGCMD_CMD_EP_off;

	set_val(cfgcmd, epn, TMU_CFGEPN_EPN_MASK, TMU_CFGEPN_EPN_OFFSET);

	tmu_epmt_read(epn, &old_epe, &sbid);
	tmu_epmt_write(epn, ena, sbid);
	tmu_cfgcmd_write(cfgcmd);
}

bool tmu_is_egress_port_enabled(const uint32_t epn)
{
	uint32_t epe, sbid;

	tmu_epmt_read(epn, &epe, &sbid);

	return epe ? true : false;
}

void tmu_egress_port_link_set(const uint32_t epn, uint32_t sbid)
{
/*
   EPMT[epn].SBID = sbid;
*/
	uint32_t epe, old_sbid;

	tmu_epmt_read(epn, &epe, &old_sbid);
	tmu_epmt_write(epn, epe, sbid);
}

void tmu_egress_port_link_get(const uint32_t epn, struct tmu_eport_link *eport_link)
{
/*
*/
	uint32_t epe, sbid;

	tmu_epmt_read(epn, &epe, &sbid);

	eport_link->epe = epe;
	eport_link->sbid = sbid;
}

void tmu_egress_port_tail_drop_thr_set(uint32_t epn,
				       struct tmu_egress_port_thr *epth)
{
/*
   EPTT[epn].EPTH0 = thx->epth0 >> 3;
   EPTT[epn].EPTH1 = thx->epth1 >> 3;
   EPTT[epn].EPTH2 = thx->epth2 >> 3;
   EPTT[epn].EPTH3 = thx->epth3 >> 3;
*/
	uint32_t ept[2] = { 0, 0 };

	set_val(ept[0], epth->epth[0] >> 3, TMU_EPTT0_EPTH0_MASK,
		TMU_EPTT0_EPTH0_OFFSET);

	set_val(ept[0], epth->epth[1] >> 3, TMU_EPTT0_EPTH1_MASK,
		TMU_EPTT0_EPTH1_OFFSET);

	set_val(ept[1], epth->epth[2] >> 3, TMU_EPTT1_EPTH2_MASK,
		TMU_EPTT1_EPTH2_OFFSET);

	set_val(ept[1], epth->epth[3] >> 3, TMU_EPTT1_EPTH3_MASK,
		TMU_EPTT1_EPTH3_OFFSET);

	tmu_eptt_write(epn, &ept[0]);
}

void tmu_egress_port_tail_drop_thr_get(uint32_t epn,
				       struct tmu_egress_port_thr *epth)
{
/*
   thx->epth0 = EPTT[epn].EPTH0 << 3;
   thx->epth1 = EPTT[epn].EPTH1 << 3;
   thx->epth2 = EPTT[epn].EPTH2 << 3;
   thx->epth3 = EPTT[epn].EPTH3 << 3;
*/
	uint32_t ept[2];

	tmu_eptt_read(epn, &ept[0]);

	epth->epth[0] = get_val(ept[0], TMU_EPTT0_EPTH0_MASK,
				TMU_EPTT0_EPTH0_OFFSET);
	epth->epth[0] <<= 3;

	epth->epth[1] = get_val(ept[0], TMU_EPTT0_EPTH1_MASK,
				TMU_EPTT0_EPTH1_OFFSET);
	epth->epth[1] <<= 3;

	epth->epth[2] = get_val(ept[1], TMU_EPTT1_EPTH2_MASK,
				TMU_EPTT1_EPTH2_OFFSET);
	epth->epth[2] <<= 3;

	epth->epth[3] = get_val(ept[1], TMU_EPTT1_EPTH3_MASK,
				TMU_EPTT1_EPTH3_OFFSET);
	epth->epth[3] <<= 3;
}

void tmu_egress_port_fill_status_get(uint32_t *epfill)
{
	uint32_t i;

	for (i = 0; i < 3; i++)
		epfill[i] = tmu_r32(epfr[i]);
}

void tmu_egress_port_seg_occupancy_get(uint32_t epn, uint32_t *epoc)
{
	uint32_t epot[2];

	tmu_epot_read(epn, &epot[0]);

	epoc[0] = get_val(epot[0], TMU_EPOT0_EPOC0_MASK,
			  TMU_EPOT0_EPOC0_OFFSET);
	epoc[1] = get_val(epot[0], TMU_EPOT0_EPOC1_MASK,
			  TMU_EPOT0_EPOC1_OFFSET);
	epoc[2] = get_val(epot[1], TMU_EPOT1_EPOC2_MASK,
			  TMU_EPOT1_EPOC2_OFFSET);
	epoc[3] = get_val(epot[1], TMU_EPOT1_EPOC3_MASK,
			  TMU_EPOT1_EPOC3_OFFSET);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_egress_port_status_get(uint32_t epn,
				struct tmu_egress_port_status *epstatus)
{
	uint32_t epn_reg;
	uint32_t epn_bit;

	epn_reg = epn / 32;
	epn_bit = 1 << (epn % 32);

	epstatus->epfilled = tmu_r32(epfr[epn_reg]) & epn_bit ? true :
								    false;
	tmu_egress_port_seg_occupancy_get(epn, &epstatus->epoc[0]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_sched_blk_in_enable(const uint32_t sbin, bool ena)
{
/*
   SBIT[sbin].SIE = ena;

   Implementation requirement
   MUST use CMD opcode 0 in CFGCMD to do this
   Direct write of SBIT[sbin].SIE is not recommended during operation
*/
	uint32_t cfgcmd = 0;

	cfgcmd |= ena ? TMU_CFGCMD_CMD_SB_input_on :
			TMU_CFGCMD_CMD_SB_input_off;

	set_val(cfgcmd, sbin, TMU_CFGSBIN_SBIN_MASK,
		TMU_CFGSBIN_SBIN_OFFSET);

	tmu_cfgcmd_write(cfgcmd);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
bool tmu_is_sched_blk_in_enabled(const uint32_t sbin)
{
	uint32_t sbit[4];

	tmu_sbit_read(sbin, &sbit[0]);

	return (sbit[0] & TMU_SBITR0_SIE_EN) ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_sched_blk_in_link_set(const uint32_t sbin,
			       struct tmu_sched_blk_in_link *ilink)
{
	uint32_t sbit[4];

	tmu_sbit_read(sbin, &sbit[0]);

	if (ilink->sie == 1)
		sbit[0] |= TMU_SBITR0_SIE_EN;
	else
		sbit[0] &= ~TMU_SBITR0_SIE_EN;

	if (ilink->sit == 1)
		sbit[0] |= TMU_SBITR0_SIT_SBID;
	else
		sbit[0] &= ~TMU_SBITR0_SIT_SBID;

	set_val(sbit[0], ilink->iwgt, TMU_SBITR0_IWGT_MASK,
		TMU_SBITR0_IWGT_OFFSET);
	set_val(sbit[0], ilink->qsid, TMU_SBITR0_QSID_MASK,
		TMU_SBITR0_QSID_OFFSET);

	tmu_sbit_write(sbin, &sbit[0]);
}

void tmu_sched_blk_in_link_get(const uint32_t sbin,
			       struct tmu_sched_blk_in_link *ilink)
{
	uint32_t sbit[4];

	tmu_sbit_read(sbin, &sbit[0]);

	ilink->sie = (sbit[0] & TMU_SBITR0_SIE_EN) ? 1 : 0;
	ilink->sit = (sbit[0] & TMU_SBITR0_SIT_SBID) ? 1 : 0;

	ilink->iwgt = get_val(sbit[0], TMU_SBITR0_IWGT_MASK,
			     TMU_SBITR0_IWGT_OFFSET);
	ilink->qsid = get_val(sbit[0], TMU_SBITR0_QSID_MASK,
			     TMU_SBITR0_QSID_OFFSET);
}

void tmu_sched_blk_in_weight_set(uint32_t sbin,
				  uint16_t weight)
{
/*
	   Implementation recommendation
	   First set CMDARG0.IWGT = weight
	   Then use CMD opcode 2 in CFGCMD to do this
	   Direct write of SBIT[sbin].IWGT is possible, but not recommended
	   during operation
*/
	uint32_t cfgarg0;
	uint32_t cfgcmd;

	cfgarg0 = 0;
	set_val(cfgarg0, weight, TMU_CFGARG0_IWGT_MASK,
		TMU_CFGARG0_IWGT_OFFSET);
	tmu_w32(cfgarg0, cfgarg0);

	cfgcmd = 0;
	cfgcmd |= TMU_CFGCMD_CMD_SB_input_weight;
	set_val(cfgcmd, sbin, TMU_CFGSBIN_SBIN_MASK,
		TMU_CFGSBIN_SBIN_OFFSET);

	tmu_w32(cfgcmd, cfgcmd);
}

void tmu_sched_blk_in_weight_get(uint32_t sbin,
				  uint16_t *weight)
{
	uint32_t sbit[4];
	tmu_sbit_read(sbin, &sbit[0]);

	*weight = get_val(sbit[0], TMU_SBITR0_IWGT_MASK,
			  TMU_SBITR0_IWGT_OFFSET);
}

void tmu_sched_blk_in_weights_set(uint32_t sbid,
				  struct tmu_sched_blk_in_weights *weights)
{
	uint32_t leaf;
	uint32_t sbin;

	for (leaf = 0; leaf < 8; leaf++) {
		sbin = (sbid << 3) + leaf;
		tmu_sched_blk_in_weight_set(sbin, weights->iwgt[leaf]);
	}
}

void tmu_sched_blk_in_weights_get(uint32_t sbid,
				  struct tmu_sched_blk_in_weights *weights)
{
	uint32_t leaf;
	uint32_t sbin;
	uint16_t weight;

	for (leaf = 0; leaf < 8; leaf++) {
		sbin = (sbid << 3) + leaf;
		tmu_sched_blk_in_weight_get(sbin, &weight);
		weights->iwgt[leaf] = weight;
	}
}

void tmu_sched_blk_in_shaper_assign_set(const uint32_t sbin,
					struct tmu_sched_blk_in_tbs *tbs)
{
/*
   static configuration before activation:

   SBIT[sbin].TBE =  tbs->tbe;
   SBIT[sbin].TBID = tbs->tbid;

   dynamic configuration after activation:

   First set CMDARG1.TBID = tbid
   Then use CMD opcode 3 in CFGCMD to do this
*/
	uint32_t cmdcfg = 0;
	uint32_t cfgarg1 = 0;

	set_val(cfgarg1, tbs->tbid, TMU_CFGARG1_TBID_MASK,
		TMU_CFGARG1_TBID_OFFSET);
	tmu_w32(cfgarg1, cfgarg1);

	cmdcfg |= TMU_CFGCMD_CMD_SB_input_bucket_set;
	set_val(cmdcfg, sbin, TMU_CFGSBIN_SBIN_MASK, TMU_CFGSBIN_SBIN_OFFSET);

	tmu_cfgcmd_write(cmdcfg);

	cmdcfg = 0;
	cmdcfg |= tbs->tbe ? TMU_CFGCMD_CMD_SB_input_bucket_on :
			     TMU_CFGCMD_CMD_SB_input_bucket_off;

	set_val(cmdcfg, sbin, TMU_CFGSBIN_SBIN_MASK, TMU_CFGSBIN_SBIN_OFFSET);

	tmu_cfgcmd_write(cmdcfg);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_sched_blk_in_shaper_assign_get(const uint32_t sbin,
					struct tmu_sched_blk_in_tbs *tbs)
{
/*
   tbs->tbe =  SBIT[sbin].TBE;
   tbs->tbid = SBIT[sbin].TBID;
*/
	uint32_t sbit[4];

	tmu_sbit_read(sbin, &sbit[0]);

	tbs->tbe = (sbit[1] & TMU_SBITR1_TBE_EN) ? 1 : 0;
	tbs->tbid = get_val(sbit[1], TMU_SBITR1_TBID_MASK,
			    TMU_SBITR1_TBID_OFFSET);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_sched_blk_in_shaper_enable(const uint32_t sbin, bool ena)
{
/*
   SBIT[sbin].TBE = ena;

   Implementation requirement
   MUST use CMD opcode 4 in CFGCMD to do this
   Direct write of SBIT[sbin].TBE is not recommended during operation
*/
	uint32_t cmdcfg = 0;

	cmdcfg |= ena == true ? TMU_CFGCMD_CMD_SB_input_bucket_on :
				TMU_CFGCMD_CMD_SB_input_bucket_off;

	set_val(cmdcfg, sbin, TMU_CFGSBIN_CMDSBIN_MASK,
		TMU_CFGSBIN_CMDSBIN_OFFSET);

	tmu_cfgcmd_write(cmdcfg);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
bool tmu_is_sched_blk_in_shaper_enabled(const uint32_t sbin)
{
/*
   ena = SBIT[sbin].TBE;
*/
	uint32_t sbit[4];

	tmu_sbit_read(sbin, &sbit[0]);

	return (sbit[1] & TMU_SBITR1_TBE) ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_sched_blk_in_status_get(const uint32_t sbin,
				 struct tmu_sched_blk_in_status *istatus)
{
/*
   t.b.d.

*/
	uint32_t sbit[4];

	tmu_sbit_read(sbin, &sbit[0]);

	istatus->sif = (sbit[2] & TMU_SBITR2_SIF_FIL) ? true : false;
	istatus->sip = (sbit[2] & TMU_SBITR2_SIP_SIP_1) ? true : false;
	istatus->vdt = get_val(sbit[2], TMU_SBITR2_VDT_MASK,
			      TMU_SBITR2_VDT_OFFSET);
	istatus->col = get_val(sbit[3], TMU_SBITR3_COL_MASK,
			      TMU_SBITR3_COL_OFFSET);
	istatus->qosl = get_val(sbit[3], TMU_SBITR3_QOSL_MASK,
			       TMU_SBITR3_QOSL_OFFSET);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_sched_blk_out_enable(const uint32_t sbid, bool ena)
{
/*
   SBOT[sbid].SOE = ena;

   Implementation requirement
   MUST use CMD opcode 6 in \ref cfgcmd to do this
   Direct write of SBOT[sbid].SOE is not recommended during operation
*/

/*	following code does not work:
	uint32_t cmdcfg = 0;

	if (ena == true)
		cmdcfg |= TMU_CFGCMD_CMD_SB_output_on;
	else
		cmdcfg |= TMU_CFGCMD_CMD_SB_output_off;

	set_val(cmdcfg, sbid, TMU_CFGSBIN_SBIN_MASK,
		TMU_CFGSBIN_SBIN_OFFSET);

	tmu_cfgcmd_write(cmdcfg);
*/

	/* above code replaced by direct SBOT write: */
	uint32_t sbot[1];

	tmu_sbot_read_cfg(sbid, &sbot[0]);

	if (ena == 1)
		sbot[0] |= TMU_SBOTR0_SOE_EN;
	else
		sbot[0] &= ~TMU_SBOTR0_SOE_EN;

	tmu_sbot_write_cfg(sbid, &sbot[0]);

}

bool tmu_is_sched_blk_out_enabled(const uint32_t sbid)
{
/*
   ena = SBOT[sbid].SOE;
*/
	uint32_t sbot[2];

	tmu_sbot_read(sbid, &sbot[0]);

	return (sbot[0] & TMU_SBOTR0_SOE_EN) ? true : false;
}

void tmu_sched_blk_out_link_set(const uint32_t sbid,
				struct tmu_sched_blk_out_link *olink)
{
	uint32_t sbot[2];

	tmu_sbot_read_cfg(sbid, &sbot[0]);

	if (olink->soe == 1)
		sbot[0] |= TMU_SBOTR0_SOE_EN;
	else
		sbot[0] &= ~TMU_SBOTR0_SOE_EN;

	if (olink->v == 1)
		sbot[0] |= TMU_SBOTR0_V_SBIN;
	else
		sbot[0] &= ~TMU_SBOTR0_V_SBIN;

	set_val(sbot[0], olink->lvl,
		TMU_SBOTR0_LVL_MASK, TMU_SBOTR0_LVL_OFFSET);
	set_val(sbot[0], olink->omid, TMU_SBOTR0_OMID_MASK,
		TMU_SBOTR0_OMID_OFFSET);

	tmu_sbot_write_cfg(sbid, &sbot[0]);
}

void tmu_sched_blk_out_link_get(const uint32_t sbid,
				struct tmu_sched_blk_out_link *olink)
{
	uint32_t sbot[2];

	tmu_sbot_read_cfg(sbid, &sbot[0]);

	olink->soe = (sbot[0] & TMU_SBOTR0_SOE_EN) ? true : false;
	olink->v = (sbot[0] & TMU_SBOTR0_V_SBIN) ? true : false;

	olink->lvl = get_val(sbot[0], TMU_SBOTR0_LVL_MASK,
			     TMU_SBOTR0_LVL_OFFSET);
	olink->omid = get_val(sbot[0], TMU_SBOTR0_OMID_MASK,
			      TMU_SBOTR0_OMID_OFFSET);
}

void tmu_sched_blk_out_status_get(const uint32_t sbid,
				  struct tmu_sched_blk_out_status *ostatus)
{
	uint32_t sbot[2];

	tmu_sbot_read(sbid, &sbot[0]);

	ostatus->sof = (sbot[1] & TMU_SBOTR1_SOF_FIL) ? true : false;;
	ostatus->wl = get_val(sbot[1], TMU_SBOTR1_WL_MASK, TMU_SBOTR1_WL_OFFSET);
	ostatus->wqid = get_val(sbot[1], TMU_SBOTR1_WQID_MASK,
			        TMU_SBOTR1_WQID_OFFSET);
}

void tmu_token_bucket_shaper_link_set(const uint32_t tbid,
				     const uint32_t sbin)
{
	uint32_t tbst[11] = { 0 };

	tmu_tbst_read(tbid, &tbst[0]);
	set_val(tbst[0], sbin, TMU_TBSTR0_SBIN_MASK, TMU_TBSTR0_SBIN_OFFSET);
	tmu_tbst_write(tbid, &tbst[0]);
}

void tmu_token_bucket_shaper_link_get(const uint32_t tbid,
				      uint32_t *sbin)
{
	uint32_t tbst[11] = { 0 };

	tmu_tbst_read(tbid, &tbst[0]);

	*sbin = get_val(tbst[0], TMU_TBSTR0_SBIN_MASK, TMU_TBSTR0_SBIN_OFFSET);
}

void tmu_token_bucket_shaper_cfg_set(const uint32_t tbid,
				     struct tmu_token_bucket_shaper_params
				     *para)
{
/*
   TBST[tbid].MOD  =  para->mod;

   TBST[tbid].TBE0 =  para->tbe0;

   TBST[tbid].TBU0 =  tmu_tbs_tbu_conversion (para->cir);
   TBST[tbid].SRM0 =  tmu_tbs_srm_conversion (para->cir);

   TBST[tbid].TBE1 =  para->tbe1;

   TBST[tbid].TBU1 =  tmu_tbs_tbu_conversion (para->pir);
   TBST[tbid].SRM1 =  tmu_tbs_srm_conversion (para->pir);

   TBST[tbid].MBS0 =  para->cbs;
   TBST[tbid].MBS1 =  para->pbs;
*/
	uint32_t tbst[11] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t tbu0, tbu1, srm0, srm1;

	tmu_tbst_read_cfg(tbid, &tbst[0]);

	set_val(tbst[0], para->mod, TMU_TBSTR0_MOD_MASK, TMU_TBSTR0_MOD_OFFSET);

	if (para->tbe0)
		tbst[1] |= TMU_TBSTR1_TBE0_EN;
	else
		tbst[1] &= ~(TMU_TBSTR1_TBE0_EN);

	tbu0 = tmu_tbs_tbu_conversion(para->cir);
	set_val(tbst[1], tbu0, TMU_TBSTR1_TBU0_MASK, TMU_TBSTR1_TBU0_OFFSET);

	srm0 = tmu_tbs_srm_conversion(para->cir);
	set_val(tbst[1], srm0, TMU_TBSTR1_SRM0_MASK, TMU_TBSTR1_SRM0_OFFSET);

	if (para->tbe1)
		tbst[2] |= TMU_TBSTR2_TBE1_EN;
	else
		tbst[2] &= ~(TMU_TBSTR2_TBE1_EN);

	tbu1 = tmu_tbs_tbu_conversion(para->pir);
	set_val(tbst[2], tbu1, TMU_TBSTR2_TBU1_MASK, TMU_TBSTR2_TBU1_OFFSET);

	srm1 = tmu_tbs_srm_conversion(para->pir);
	set_val(tbst[2], srm1, TMU_TBSTR2_SRM1_MASK, TMU_TBSTR2_SRM1_OFFSET);

	set_val(tbst[3], para->cbs, TMU_TBSTR3_MBS0_MASK,
		TMU_TBSTR3_MBS0_OFFSET);
	set_val(tbst[4], para->pbs, TMU_TBSTR4_MBS1_MASK,
		TMU_TBSTR4_MBS1_OFFSET);

	tmu_tbst_write_cfg(tbid, &tbst[0]);
}

void tmu_token_bucket_shaper_cfg_get(const uint32_t tbid,
				     struct tmu_token_bucket_shaper_params
				     *para)
{
	uint32_t tbst[11];
	uint32_t tbu0, tbu1, srm0, srm1;

	tmu_tbst_read_cfg(tbid, &tbst[0]);

	tbu0 = get_val(tbst[1], TMU_TBSTR1_TBU0_MASK, TMU_TBSTR1_TBU0_OFFSET);
	tbu1 = get_val(tbst[2], TMU_TBSTR2_TBU1_MASK, TMU_TBSTR2_TBU1_OFFSET);

	srm0 = get_val(tbst[1], TMU_TBSTR1_SRM0_MASK, TMU_TBSTR1_SRM0_OFFSET);
	srm1 = get_val(tbst[2], TMU_TBSTR2_SRM1_MASK, TMU_TBSTR2_SRM1_OFFSET);

	para->mod = get_val(tbst[0], TMU_TBSTR0_MOD_MASK,
			    TMU_TBSTR0_MOD_OFFSET);
	para->tbe0 = (tbst[1] & TMU_TBSTR1_TBE0_EN) ? true : false;
	para->cir = tmu_tbs_rate_conversion(tbu0, srm0);
	para->cbs = get_val(tbst[3], TMU_TBSTR3_MBS0_MASK,
			    TMU_TBSTR3_MBS0_OFFSET);
	para->tbe1 = (tbst[2] & TMU_TBSTR2_TBE1_EN) ? true : false;
	para->pir = tmu_tbs_rate_conversion(tbu1, srm1);
	para->pbs = get_val(tbst[4], TMU_TBSTR4_MBS1_MASK,
			    TMU_TBSTR4_MBS1_OFFSET);
}

uint32_t tmu_tbs_tbu_conversion(uint32_t byterate)
{
	uint32_t kbitrate = (byterate << 3) / 1000;

	if (kbitrate <= 500)
		return 0;
	else if (kbitrate <= 8000)
		return 1;
	else if (kbitrate <= 128000)
		return 2;
	else
		return 3;
}

uint32_t tmu_tbs_srm_conversion(uint32_t byterate)
{
	uint32_t tbu;
	uint32_t tbu_exp;
	uint32_t kbitrate = (byterate << 3) / 1000;

	tbu = tmu_tbs_tbu_conversion(byterate);

	switch (tbu) {
	case 0:
		tbu_exp = 1;
		break;
	case 1:
		tbu_exp = 16;
		break;
	case 2:
		tbu_exp = 256;
		break;
	case 3:
		tbu_exp = 1024;
		break;
	default:
		tbu_exp = 256;
		break;
	}

	return (1000*TMU_CORECLOCK*tbu_exp) / (kbitrate<<1);
}

uint32_t tmu_tbs_rate_conversion(uint32_t tbu, uint32_t srm)
{
	uint32_t tbu_exp;
	uint32_t kbitrate;

	switch (tbu) {
	case 0:
		tbu_exp = 1;
		break;
	case 1:
		tbu_exp = 16;
		break;
	case 2:
		tbu_exp = 256;
		break;
	case 3:
		tbu_exp = 1024;
		break;
	default:
		tbu_exp = 256;
		break;
	}

	kbitrate = (1000*TMU_CORECLOCK*tbu_exp) / (srm<<1);

	return (kbitrate * 1000) >> 3;
}

void
tmu_token_bucket_shaper_status_get(const uint32_t tbid,
				   struct tmu_token_bucket_shaper_status *sts)
{
	uint32_t tbst[11];

	tmu_tbst_read(tbid, &tbst[0]);

	sts->pass0 = (tbst[7] & TMU_TBSTR7_PASS0) ? true : false;
	sts->src0 = get_val(tbst[5], TMU_TBSTR5_SRC0_MASK,
			    TMU_TBSTR5_SRC0_OFFSET);
	sts->tbc0 = get_val(tbst[7], TMU_TBSTR7_TBC0_MASK,
			    TMU_TBSTR7_TBC0_OFFSET);

	sts->pass1 = (tbst[8] & TMU_TBSTR8_PASS1) ? true : false;
	sts->src1 = get_val(tbst[6], TMU_TBSTR6_SRC1_MASK,
			    TMU_TBSTR6_SRC1_OFFSET);
	sts->tbc1 = get_val(tbst[8], TMU_TBSTR8_TBC1_MASK,
			    TMU_TBSTR8_TBC1_OFFSET);

	sts->qosl = get_val(tbst[9], TMU_TBSTR9_QOSL_MASK,
			    TMU_TBSTR9_QOSL_OFFSET);
	sts->col = get_val(tbst[9], TMU_TBSTR9_COL_MASK,
			   TMU_TBSTR9_COL_OFFSET);
}

void tmu_global_tail_drop_thr_set(struct tmu_global_thr *thx)
{
	uint32_t i;
	for (i = 0; i < 4; i++)
		tmu_w32(thx->goth[i], gothr[i]);
}

void tmu_global_tail_drop_thr_get(struct tmu_global_thr *thx)
{
	uint32_t i;
	for (i = 0; i < 4; i++)
		thx->goth[i] = tmu_r32(gothr[i]);
}

void tmu_token_accumulation_disable(bool dta)
{
	tmu_w32_mask(TMU_CTRL_DTA_DTA1, dta ? TMU_CTRL_DTA_DTA1 : 0, ctrl);
}

bool tmu_is_token_accumulation_disabled(void)
{
	return (tmu_r32(ctrl) & TMU_CTRL_DTA_DTA1) ? true : false;
}

void tmu_relog_sequential(bool rps)
{
	tmu_w32_mask(TMU_CTRL_RPS_RPS1, rps ? TMU_CTRL_RPS_RPS1 : 0, ctrl);
}

bool tmu_is_relog_sequential(void)
{
	return (tmu_r32(ctrl) & TMU_CTRL_RPS_RPS1) ? true : false;
}

void tmu_max_token_bucket_set(uint32_t maxtb)
{
	uint32_t ctrl;

	ctrl = tmu_r32(ctrl);

	set_val(ctrl, maxtb, TMU_CTRL_MAXTB_MASK, TMU_CTRL_MAXTB_OFFSET);

	tmu_w32(ctrl, ctrl);
}

void tmu_max_token_bucket_get(uint32_t *maxtb)
{
	uint32_t ctrl;

	ctrl = tmu_r32(ctrl);

	*maxtb = get_val(ctrl, TMU_CTRL_MAXTB_MASK, TMU_CTRL_MAXTB_OFFSET);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_free_pointer_counter_set(uint32_t fpc)
{
	uint32_t fpcr;

	fpcr = tmu_r32(fpcr);

	set_val(fpcr, fpc, TMU_FPCR_FPC_MASK, TMU_FPCR_FPC_OFFSET);

	tmu_w32(fpcr, fpcr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_free_pointer_counter_get(uint32_t *fpc)
{
	uint32_t fpcr;

	fpcr = tmu_r32(fpcr);

	*fpc = get_val(fpcr, TMU_FPCR_FPC_MASK, TMU_FPCR_FPC_OFFSET);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_free_pointer_thr_set(uint32_t fpth)
{
	uint32_t fpthr;

	fpthr = tmu_r32(fpthr);

	set_val(fpthr, fpth, TMU_FPTHR_FPTH_MASK, TMU_FPTHR_FPTH_OFFSET);

	tmu_w32(fpthr, fpthr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_free_pointer_thr_get(uint32_t *fpth)
{
	uint32_t fpthr;

	fpthr = tmu_r32(fpthr);

	*fpth = get_val(fpthr, TMU_FPTHR_FPTH_MASK, TMU_FPTHR_FPTH_OFFSET);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_crawler_period_set(uint32_t cp)
{
	uint32_t cpr;

	cpr = tmu_r32(cpr);

	set_val(cpr, cp, TMU_CPR_CP_MASK, TMU_CPR_CP_OFFSET);

	tmu_w32(cpr, cpr);
}

void tmu_crawler_period_get(uint32_t *cp)
{
	uint32_t cpr;

	cpr = tmu_r32(cpr);

	*cp = get_val(cpr, TMU_CPR_CP_MASK, TMU_CPR_CP_OFFSET);
}

void tmu_random_number_set(uint32_t rn)
{
	uint32_t lfsr;

	lfsr = tmu_r32(lfsr);

	set_val(lfsr, rn, TMU_LFSR_RN_MASK, TMU_LFSR_RN_OFFSET);

	tmu_w32(lfsr, lfsr);
}

void tmu_random_number_get(uint32_t *rn)
{
	uint32_t lfsr;

	lfsr = tmu_r32(lfsr);

	*rn = get_val(lfsr, TMU_LFSR_RN_MASK, TMU_LFSR_RN_OFFSET);
}

void tmu_enqueue_delay_set(uint32_t erd)
{
	uint32_t erdr;

	erdr = tmu_r32(erdr);

	set_val(erdr, erd, TMU_ERDR_ERD_MASK, TMU_ERDR_ERD_OFFSET);

	tmu_w32(erdr, erdr);
}

void tmu_enqueue_delay_get(uint32_t *erd)
{
	uint32_t erdr;

	erdr = tmu_r32(erdr);

	*erd = get_val(erdr, TMU_ERDR_ERD_MASK, TMU_ERDR_ERD_OFFSET);
}

void tmu_tacc_period_set(uint32_t tacp)
{
	uint32_t tacper;

	tacper = tmu_r32(tacper);

	set_val(tacper, tacp, TMU_TACPER_TACP_MASK, TMU_TACPER_TACP_OFFSET);

	tmu_w32(tacper, tacper);
}

void tmu_tacc_period_get(uint32_t *tacp)
{
	uint32_t tacper;

	tacper = tmu_r32(tacper);

	*tacp = get_val(tacper, TMU_TACPER_TACP_MASK, TMU_TACPER_TACP_OFFSET);
}


#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_global_occupancy_set(uint32_t gocc)
{
	uint32_t goccr;

	goccr = tmu_r32(goccr);

	set_val(goccr, gocc, TMU_GOCCR_GOCC_MASK, TMU_GOCCR_GOCC_OFFSET);

	tmu_w32(goccr, goccr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_global_occupancy_get(uint32_t *gocc)
{
	uint32_t goccr;

	goccr = tmu_r32(goccr);

	*gocc = get_val(goccr, TMU_GOCCR_GOCC_MASK, TMU_GOCCR_GOCC_OFFSET);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_global_discard_counters_set(uint32_t *gpdc)
{
	uint32_t i;
	for (i = 0; i < 4; i++)
		tmu_w32(gpdc[i], gpdcr[i]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void tmu_global_discard_counters_get(uint32_t *gpdc)
{
	uint32_t i;
	for (i = 0; i < 4; i++)
		gpdc[i] = tmu_r32(gpdcr[i]);
}

void tmu_low_power_idle_cfg_set(const uint8_t lanport,
				struct tmu_low_pwr_idle_params *lpi)
{
/*
   switch(lanport) {
   case 0:  LPIC0.THX = lpi->thx;
            LPIC0.TOF = (10000*lpi->tof)>>16;
            LPIC0.TON = (10000*lpi->tof)>>16;
            break;
   case 1:  LPIC1.THX = lpi->thx;
            LPIC1.TOF = (10000*lpi->tof)>>16;
            LPIC1.TON = (10000*lpi->tof)>>16;
            break;
   case 2:  LPIC2.THX = lpi->thx;
            LPIC2.TOF = (10000*lpi->tof)>>16;
            LPIC2.TON = (10000*lpi->tof)>>16;
            break;
   case 3:  LPIC3.THX = lpi->thx;
            LPIC3.TOF = (10000*lpi->tof)>>16;
            LPIC3.TON = (10000*lpi->tof)>>16;
            break;
   }
*/
	uint32_t tof, ton;
	uint32_t lpic = 0;

	tof = (10000 * lpi->tof) >> 16;
	ton = (10000 * lpi->ton) >> 16;

	set_val(lpic, lpi->thx, TMU_LPIC0_THX_MASK, TMU_LPIC0_THX_OFFSET);
	set_val(lpic, tof, TMU_LPIC0_TOF_MASK, TMU_LPIC0_TOF_OFFSET);
	set_val(lpic, ton, TMU_LPIC0_TON_MASK, TMU_LPIC0_TON_OFFSET);

	switch (lanport) {
	case 0:
	case 1:
	case 2:
	case 3:
		tmu_w32(lpic, lpic[lanport]);
		break;
	}
}

void tmu_low_power_idle_cfg_get(const uint8_t lanport,
				struct tmu_low_pwr_idle_params *lpi)
{
	uint32_t tox;
	uint32_t lpic;

	lpic = tmu_r32(lpic[lanport]);

	lpi->thx = get_val(lpic, TMU_LPIC0_THX_MASK, TMU_LPIC0_THX_OFFSET);
	tox = get_val(lpic, TMU_LPIC0_TOF_MASK, TMU_LPIC0_TOF_OFFSET);
	lpi->tof = (tox << 16) / 10000;
	tox = get_val(lpic, TMU_LPIC0_TON_MASK, TMU_LPIC0_TON_OFFSET);
	lpi->ton = (tox << 16) / 10000;
}

void tmu_low_power_idle_status_get(const uint8_t lanport,
				   struct tmu_low_pwr_idle_status *lpistatus)
{
	uint32_t lpit;

	lpit = tmu_r32(lpit[lanport]);

	lpistatus->lpstate = (lpit & TMU_LPIT0_LPSTATE_ON) ? true : false;
	lpistatus->lpireq = (lpit & TMU_LPIT0_LPIREQ) ? true : false;
	lpistatus->lptimer = get_val(lpit, TMU_LPIT0_LPTIMER_MASK,
				  TMU_LPIT0_LPTIMER_OFFSET);
}

void tmu_interrupt_enable_set(const uint32_t mask_clr, const uint32_t mask_set)
{
	tmu_w32_mask(mask_clr, mask_set, irnen);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
uint32_t tmu_interrupt_enable_get(void)
{
	return tmu_r32(irnen);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_interrupt_control_set(const uint32_t ctrl)
{
	tmu_w32(ctrl, irnicr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_interrupt_control_get(uint32_t *ctrl)
{
	*ctrl = tmu_r32(irnicr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_interrupt_capture_set(const uint32_t capt)
{
	tmu_w32(capt, irncr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void tmu_interrupt_capture_get(uint32_t *capt)
{
	*capt = tmu_r32(irncr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/*
   =============================================================
   High Level Functions
   =============================================================
*/

void tmu_sched_blk_create(const uint32_t sbid, const uint8_t lvl,
			  const uint32_t omid, const uint8_t v,
			  const uint16_t weight)
{
/*
   This function accesses
   SBOT[sbid]
   SBIT[omid] or EPMT[omid] depending on v
*/

	struct tmu_sched_blk_out_link olink;
	struct tmu_sched_blk_in_link  ilink;

	olink.soe  = 1;			/* enable scheduler output */
	olink.lvl  = lvl;
	olink.omid = omid;
	olink.v    = v;
	tmu_sched_blk_out_link_set(sbid, &olink);

	if (v == 0) {
		tmu_egress_port_link_set(omid, sbid);
	} else {
		ilink.sie  = 1;		/* enable next level input */
		ilink.sit  = 1;
		ilink.qsid = sbid;
		ilink.iwgt = weight;
		tmu_sched_blk_in_link_set(omid, &ilink);
	}
}


void tmu_egress_queue_create(const uint32_t qid, const uint32_t sbin,
			     const uint32_t epn)
{
/*
   QEMT[qid].EPN  = epn;
   QSMT[qid].SBIN = sbin;
   QTHT[qid].QE   = 1;
   SBIT[sbin].SIE = 1;
*/
	struct tmu_equeue_link equeue_link;
	struct tmu_sched_blk_in_link sblink;

	equeue_link.sbin = sbin;
	equeue_link.epn  = epn;
	tmu_equeue_link_set(qid, &equeue_link);

	tmu_equeue_enable(qid, 1);
	tmu_sched_blk_in_enable(sbin, 1);

	sblink.qsid = qid;
	sblink.iwgt = 0;
	sblink.sie  = 1;
	sblink.sit  = 0;
	tmu_sched_blk_in_link_set(sbin, &sblink);
}

void tmu_token_bucket_shaper_create(const uint32_t tbid, const uint32_t sbin)
{
/*
   This function accesses
   TBST[tbid].SBIN
   SBIT[sbin].TBE
   SBIT[sbin].TBID
*/

	struct tmu_sched_blk_in_tbs tbs;

	tmu_token_bucket_shaper_link_set(tbid, sbin);

	tbs.tbe  = 1;
	tbs.tbid = tbid;
	tmu_sched_blk_in_shaper_assign_set(sbin, &tbs);

}

void tmu_token_bucket_shaper_delete(const uint32_t tbid, const uint32_t sbin)
{
/*
   This function accesses
   TBST[tbid].SBIN
   SBIT[sbin].TBE
   SBIT[sbin].TBID
*/
	uint32_t tbst[11] = { 0 };
	uint32_t sbit[4] = { 0 };

	set_val(tbst[0], 0x3F, TMU_TBSTR0_SBIN_MASK, TMU_TBSTR0_SBIN_OFFSET);

	tmu_sbit_read(sbin, &sbit[0]);
	sbit[1] &= (~TMU_SBITR1_TBE_EN);
	set_val(sbit[1], 0xFF, TMU_SBITR1_TBID_MASK, TMU_SBITR1_TBID_OFFSET);

	tmu_tbst_write(tbid, &tbst[0]);
	tmu_sbit_write(sbin, &sbit[0]);
}

void tmu_create_flat_egress_path(const uint16_t num_ports,
				 const uint16_t base_epn,
				 const uint16_t base_sbid,
				 const uint16_t base_qid,
				 const uint16_t qid_per_sb)
{
	uint16_t epn;
	uint16_t qid;

	for (epn = 0; epn < num_ports; epn++) {
		tmu_sched_blk_create(base_sbid + epn, 0, base_epn + epn, 0, 0);
		tmu_egress_port_enable(base_epn + epn, true);
		for (qid = epn*qid_per_sb; qid < epn*qid_per_sb + qid_per_sb;
		     qid++) {
			tmu_egress_queue_create(base_qid + qid,
						((base_sbid + epn) << 3) +
								      (qid % 8),
						base_epn + epn);
		}
	}
}

#if defined(INCLUDE_DUMP)

void dumps8(struct seq_file *s, const char *s0, const char *s1, const char *s2,
	    const char *s3, const char *s4, const char *s5, const char *s6,
	    const char *s7)
{
	seq_printf(s, "%8s,%8s,%8s,%8s,%8s,%8s,%8s,%8s\n",
			s0, s1, s2, s3, s4, s5, s6, s7);
}

void dumpx8(struct seq_file *s, const uint32_t v0, const uint32_t v1,
	    const uint32_t v2, const uint32_t v3, const uint32_t v4,
	    const uint32_t v5, const uint32_t v6, const uint32_t v7)
{
	seq_printf(s, "%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
			v0, v1, v2, v3, v4, v5, v6, v7);
}

void dumps4(struct seq_file *s, const char *s0, const char *s1, const char *s2,
	    const char *s3)
{
	seq_printf(s, "%8s,%8s,%8s,%8s\n", s0, s1, s2, s3);
}

void dumpx4(struct seq_file *s, const uint32_t v0, const uint32_t v1,
	    const uint32_t v2, const uint32_t v3)
{
	seq_printf(s, "%08x,%08x,%08x,%08x\n", v0, v1, v2, v3);
}

void tmu_dump(struct seq_file *s)
{
	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET) == 0) {
		seq_printf(s, "TMU not activated\n");
		return;
	}

	dumps8(s, "ctrl","fpcr","fpthr","timer","lfsr","cpr","csr","goccr");
	dumpx8(s, tmu_r32(ctrl), tmu_r32(fpcr), tmu_r32(fpthr), tmu_r32(timer),
		  tmu_r32(lfsr), tmu_r32(cpr), tmu_r32(csr), tmu_r32(goccr));

	dumps4(s, "gothr0","gothr1","gothr2","gothr3");
	dumpx4(s, tmu_r32(gothr[0]), tmu_r32(gothr[1]),
		  tmu_r32(gothr[2]), tmu_r32(gothr[3]));

	dumps4(s, "gpdcr0","gpdcr1","gpdcr2","gpdcr3");
	dumpx4(s, tmu_r32(gpdcr[0]), tmu_r32(gpdcr[1]),
		  tmu_r32(gpdcr[2]), tmu_r32(gpdcr[3]));

	dumps4(s, "lpic0","lpic1","lpic2","lpic3");
	dumpx4(s, tmu_r32(lpic[0]), tmu_r32(lpic[1]),
		  tmu_r32(lpic[2]), tmu_r32(lpic[3]));

	dumps4(s, "lpit0","lpit1","lpit2","lpit3");
	dumpx4(s, tmu_r32(lpit[0]), tmu_r32(lpit[1]),
		  tmu_r32(lpit[2]), tmu_r32(lpit[3]));

	dumps8(s, "qfill0","qfill1","qfill2","qfill3","qfill4",
		  "qfill5","qfill6","qfill7");
	dumpx8(s, tmu_r32(qfill[0]), tmu_r32(qfill[1]),
		  tmu_r32(qfill[2]), tmu_r32(qfill[3]),
		  tmu_r32(qfill[4]), tmu_r32(qfill[5]),
		  tmu_r32(qfill[6]), tmu_r32(qfill[7]));

	dumps4(s, "epfr0","epfr1","epfr2","tbidcr");
	dumpx4(s, tmu_r32(epfr[0]), tmu_r32(epfr[1]),
		  tmu_r32(epfr[2]), tmu_r32(tbidcr));
}

void tmu_eqt_dump(struct seq_file *s)
{
	uint32_t i;
	bool valid;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET) == 0) {
		seq_printf(s, "TMU not activated\n");
		return;
	}

	seq_printf(s, "Egress Queue Table (EQT)\n");
	seq_printf(s, "no ,epn     ,sbin    ,wq      ,qrth    ,qocc    "
								     ",qavg\n");
	seq_printf(s, "no ,qtht0   ,qtht1   ,qtht2   ,qtht3   ,qtht4\n");
	seq_printf(s, "no ,qdc0    ,qdc1    ,qdc2    ,qdc3    ,qfmt0   "
							     ",qfmt1   ,qfmt2");
	for (i = 0; i < EGRESS_QUEUE_ID_MAX; i++) {
		uint32_t tmp[18], k;

		tmu_qemt_read(i, &tmp[0]);
		tmu_qsmt_read(i, &tmp[1]);
		tmu_qoct_read(i, &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
		tmu_qtht_read(i, &tmp[6]);
		tmu_qdct_read(i, &tmp[11]);
		tmu_qfmt_read(i, &tmp[15]);

		if (tmp[0] == EPNNULL_EGRESS_PORT_ID &&
		    tmp[1] == NULL_SCHEDULER_INPUT_ID)
			valid = false;
		else
			valid = true;

		seq_printf(s, "\n%03d", i);
		for (k = 0; k < 6; k++)
			seq_printf(s, ",%08x", tmp[k]);

		if (valid)
			seq_printf(s, "          V");

		seq_printf(s, "\n%03d", i);
		for (; k < 11; k++)
			seq_printf(s, ",%08x", tmp[k]);

		if (valid)
			seq_printf(s, "                   V");

		seq_printf(s, "\n%03d", i);
		for (; k < 18; k++)
			seq_printf(s, ",%08x", tmp[k]);

		if (valid)
			seq_printf(s, " V");

		seq_printf(s, "\n");
	}
}

void tmu_ept_dump(struct seq_file *s)
{
	uint32_t i;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET) == 0) {
		seq_printf(s, "TMU not activated\n");
		return;
	}

	seq_printf(s, "Egress Port Table (EPT)\n");
	seq_printf(s, "no ,epe     ,sbid    ,epoc0   ,epoc1   ,ept0    ,");
	seq_printf(s, "ept1    ,epd0    ,epd1    ,epd2    ,epd3\n");
	for (i = 0; i < EGRESS_PORT_ID_MAX; i++) {
		uint32_t tmp[10], k;

		tmu_epmt_read(i, &tmp[0], &tmp[1]);
		tmu_epot_read(i, &tmp[2]);
		tmu_eptt_read(i, &tmp[4]);
		tmu_epdt_read(i, &tmp[6]);

		seq_printf(s, "%03d", i);
		for (k = 0; k < 10; k++)
			seq_printf(s, ",%08x", tmp[k]);
		seq_printf(s, "\n");
	}
}

void tmu_sbit_dump(struct seq_file *s)
{
	uint32_t i;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET) == 0) {
		seq_printf(s, "TMU not activated\n");
		return;
	}

	seq_printf(s, "Scheduler Block Input Table (SBIT)\n");
	seq_printf(s, "no ,sbitr0  ,sbitr1  ,sbitr2  ,sbitr3\n");
	for (i = 0; i < SCHEDULER_BLOCK_INPUT_ID_MAX; i++) {
		uint32_t tmp[4], k;

		tmu_w32(TMU_SBITC_SEL | i, sbitc);
		while ((tmu_r32(sbitc) & TMU_SBITC_VAL) == 0) {
		}

		tmp[0] = tmu_r32(sbitr0);
		tmp[1] = tmu_r32(sbitr1);
		tmp[2] = tmu_r32(sbitr2);
		tmp[3] = tmu_r32(sbitr3);

		seq_printf(s, "%03d", i);
		for (k = 0; k < 4; k++)
			seq_printf(s, ",%08x", tmp[k]);
		seq_printf(s, "\n");
	}
}

void tmu_sbot_dump(struct seq_file *s)
{
	uint32_t i;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET) == 0) {
		seq_printf(s, "TMU not activated\n");
		return;
	}

	seq_printf(s, "Scheduler Block Output Table (SBOT)\n");
	seq_printf(s, "no ,sbotr0  ,sbotr1\n");
	for (i = 0; i < SCHEDULER_BLOCK_ID_MAX; i++) {
		uint32_t tmp[2];

		tmu_w32(TMU_SBOTC_SEL | i, sbotc);
		while ((tmu_r32(sbotc) & TMU_SBOTC_VAL) == 0) {
		}

		tmp[0] = tmu_r32(sbotr0);
		tmp[1] = tmu_r32(sbotr1);

		seq_printf(s, "%03d,%08x,%08x\n", i, tmp[0], tmp[1]);
	}
}

void tmu_tbst_dump(struct seq_file *s)
{
	uint32_t i,k;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET) == 0) {
		seq_printf(s, "TMU not activated\n");
		return;
	}

	seq_printf(s, "Token Bucket Shaper Table (TBST)\n");
	seq_printf(s, "no ");
	for (k = 0; k < 11; k++)
		seq_printf(s, ",tbstr%03d", k);
	seq_printf(s, "\n");
	for (i = 0; i <= TOKEN_BUCKET_MAX; i++) {
		uint32_t tmp[11];

		tmu_w32(TMU_TBSTC_SEL | i, tbstc);
		while ((tmu_r32(tbstc) & TMU_TBSTC_VAL) == 0) {
		}

		tmp[0] = tmu_r32(tbstr0);
		tmp[1] = tmu_r32(tbstr1);
		tmp[2] = tmu_r32(tbstr2);
		tmp[3] = tmu_r32(tbstr3);
		tmp[4] = tmu_r32(tbstr4);
		tmp[5] = tmu_r32(tbstr5);
		tmp[6] = tmu_r32(tbstr6);
		tmp[7] = tmu_r32(tbstr7);
		tmp[8] = tmu_r32(tbstr8);
		tmp[9] = tmu_r32(tbstr9);
		tmp[10] = tmu_r32(tbstr10);

		seq_printf(s, "%03d", i);
		for (k = 0; k < 11; k++)
			seq_printf(s, ",%08x", tmp[k]);
		seq_printf(s, "\n");
	}
}

int tmu_ppt_dump_start(void)
{
	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET) == 0)
		return 0;

	return (tmu_r32(fpl) & TMU_FPL_HFPP_MASK) >> TMU_FPL_HFPP_OFFSET;
}

int tmu_ppt_dump(struct seq_file *s, int pos)
{
	static uint32_t loopcnt;
	uint32_t ppt[4];
	uint32_t fpl, fplen, tfpp, hfpp;
	uint32_t pnext, offs, hdrl;
	uint32_t qosl, pdut, segl;
	uint32_t col, gpix, bdyl;
	uint32_t hlsa, tlsa;
	int ret;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_TMU_SET) == 0) {
		seq_printf(s, "TMU not activated\n");
		return -1;
	}

	fpl = tmu_r32(fpl);
	fplen = tmu_r32(fpcr);
	tfpp = (fpl & TMU_FPL_TFPP_MASK) >> TMU_FPL_TFPP_OFFSET;
	hfpp = (fpl & TMU_FPL_HFPP_MASK) >> TMU_FPL_HFPP_OFFSET;

	if (pos == (int)hfpp) {
		seq_printf(s, "Packet Pointer Table (PPT) Free List\n");
		seq_printf(s, "Length = %4u TFPP = 0x%04x HFPP = 0x%04x\n",
			   fplen, tfpp, hfpp);
		seq_printf(s, "line - pcurr  pnext  offs hdrl qosl  pdut segl "
			   "col  gpix bdyl  hlsa   tlsa  \n");
		loopcnt = 0;
	}

	tmu_w32(pos, pptc);
	while ((tmu_r32(pptc) & TMU_PPTC_VAL) == 0) {
	}

	ppt[0] = tmu_r32(ppt0);
	ppt[1] = tmu_r32(ppt1);
	ppt[2] = tmu_r32(ppt2);
	ppt[3] = tmu_r32(ppt3);
	pnext	= (ppt[0] & TMU_PPT0_PNEXT_MASK) >> TMU_PPT0_PNEXT_OFFSET;
	offs	= (ppt[0] & TMU_PPT0_OFFS_MASK) >> TMU_PPT0_OFFS_OFFSET;
	hdrl	= (ppt[0] & TMU_PPT0_HDRL_MASK) >> TMU_PPT0_HDRL_OFFSET;
	qosl	= (ppt[1] & TMU_PPT1_QOSL_MASK) >> TMU_PPT1_QOSL_OFFSET;
	pdut	= (ppt[1] & TMU_PPT1_PDUT_MASK) >> TMU_PPT1_PDUT_OFFSET;
	segl	= (ppt[1] & TMU_PPT1_SEGL_MASK) >> TMU_PPT1_SEGL_OFFSET;
	col		= (ppt[2] & TMU_PPT2_COL_MASK) >> TMU_PPT2_COL_OFFSET;
	gpix	= (ppt[2] & TMU_PPT2_GPIX_MASK) >> TMU_PPT2_GPIX_OFFSET;
	bdyl	= (ppt[2] & TMU_PPT2_BDYL_MASK) >> TMU_PPT2_BDYL_OFFSET;
	hlsa	= (ppt[3] & TMU_PPT3_HLSA_MASK) >> TMU_PPT3_HLSA_OFFSET;
	tlsa	= (ppt[3] & TMU_PPT3_TLSA_MASK) >> TMU_PPT3_TLSA_OFFSET;

	ret = seq_printf(s, "%04u - 0x%04x 0x%04x %4u %4u %5u %4u %4u %4u %4u "
			 "%5u 0x%04x 0x%04x\n",
			 loopcnt + 1, pos, pnext, offs, hdrl, qosl,
			 pdut, segl, col, gpix, bdyl, hlsa, tlsa);
	if (ret < 0)
		return pos;

	loopcnt++;

	if (pos != (int)hfpp && pnext == hfpp)
		return -1;

	if (pos == (int)tfpp)
		return -1;

	return pnext;
}

#endif
