/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_resource_gpe.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_iqm.h"

#define IQM_SSB_SIZE     0x400

#define MAX_QUEUE          9

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_IQM_INTERNAL GPE - IQM Interface
   @{
*/

/** Number of Ingress Packet Pointers */
#define NUM_IPP 3072

STATIC void iqm_iqt_write(const uint16_t queue_idx,
			  const struct iqm_iqt_entry *entry)
{
	uint32_t iqtr;

	iqtr = 0;
	if (entry->qe)
		iqtr |= IQM_IQT00_QE;
	set_val(iqtr, entry->qrth, IQM_IQT00_QRTH_MASK, IQM_IQT00_QRTH_OFFSET);
	set_val(iqtr, entry->qdth, IQM_IQT00_QDTH_MASK, IQM_IQT00_QDTH_OFFSET);
	iqm_w32(iqtr, iqt[queue_idx].iqt0);

	iqtr = 0;
	if (entry->qb)
		iqtr |= IQM_IQT01_QB;
	set_val(iqtr, entry->qbth, IQM_IQT01_QBTH_MASK, IQM_IQT01_QBTH_OFFSET);
	set_val(iqtr, entry->qbtl, IQM_IQT01_QBTL_MASK, IQM_IQT01_QBTL_OFFSET);
	iqm_w32(iqtr, iqt[queue_idx].iqt1);

	iqtr = 0;
	if (entry->qf)
		iqtr |= IQM_IQT02_QF;
	if (entry->bp)
		iqtr |= IQM_IQT02_BP;
	set_val(iqtr, entry->pocc, IQM_IQT02_POCC_MASK, IQM_IQT02_POCC_OFFSET);
	set_val(iqtr, entry->qocc, IQM_IQT02_QOCC_MASK, IQM_IQT02_QOCC_OFFSET);
	iqm_w32(iqtr, iqt[queue_idx].iqt2);

	iqtr = 0;
	set_val(iqtr, entry->qdc, IQM_IQT03_QDC_MASK, IQM_IQT03_QDC_OFFSET);
	iqm_w32(iqtr, iqt[queue_idx].iqt3);

	iqm_w32(entry->tmask, iqt[queue_idx].iqt5);
}

void iqm_enable(bool act)
{
	iqm_w32_mask(IQM_CTRL_ACT_EN, act ? IQM_CTRL_ACT_EN : 0, ctrl);
}

bool iqm_is_enabled(void)
{
	return (iqm_r32(ctrl) & IQM_CTRL_ACT_EN) ? true : false;
}

/**
    - Disable and clear all ingress queues
     IQM.IQT[n]0.QE = EN, [n] = 0 ... number of ingress queues - 1
     IQM.IQT[n]1.QB = EN,  [n] = 0 ... number of ingress queues - 1

      \todo to be clarified if ingress queues must be cleared during operation.
      SW concept yet missing

*/
void iqm_init(void)
{
	/* initialization such that all queues are enabled and blocked
	   all discard thresholds set to max, no reservation
	   all 36 WRR slots allocated
	   all queues can transmit to all threads
	 */
	int i;
	uint16_t queue_idx;
	struct iqm_iqt_entry iqt_entry;
	static const uint32_t qid[5] = {
		0x76543210,
		0x65432108,
		0x54321087,
		0x43210876,
		0x32108765,
	};

	/*
	  Enable module clock, release reset. This is mandatory before
	  accessing module's registers.
	*/
	sys_gpe_hw_activate_or_reboot(SYS_GPE_ACT_IQM_SET | SYS_GPE_ACT_CPUI);
	iqm_w32(0, irncr);
	iqm_w32(0, irnicr);

	iqm_w32(IQM_CTRL_FRZ, ctrl);
	iqm_w32(IQM_IRNCR_QF7, irnen);

	/* for all ingress queues write default start table entry */
	iqt_entry.qe = 1;	/* queue enable */
	/* queue discard threshold (2304 lowest value such that queue
	   occupies complete SSB) */
	iqt_entry.qdth = 0x30;
	iqt_entry.qrth = 0;	/* queue reservation threshold */
	iqt_entry.qb = 1;	/* queue blocked */
	/* queue backpressure threshold high (no backpressure) */
	iqt_entry.qbth = 0x30;
	/* queue backpressure threshold low (no backpressure) */
	iqt_entry.qbtl = 0;
	iqt_entry.qf = 0;	/* status bit set to 0 */
	iqt_entry.bp = 0;	/* status bit set to 0 */
	iqt_entry.pocc = 0;	/* PDU occupancy counter */
	iqt_entry.qocc = 0;	/* queue occupancy counter */
	iqt_entry.qdc = 0;	/* queue PDU discard counter */
	iqt_entry.tmask = 0;

	for (queue_idx = 0; queue_idx < MAX_QUEUE; queue_idx++) {
		switch (queue_idx) {
		case ONU_GPE_INGRESS_QUEUE_LAN_0:
		case ONU_GPE_INGRESS_QUEUE_CPU_DS:
		case ONU_GPE_INGRESS_QUEUE_CPU_US:
		case ONU_GPE_INGRESS_QUEUE_GEM_UC:
			/* enable all FW threads */
			iqt_entry.tmask = 0x3ffff;
			/* forward to hardware/SCI */
			iqt_entry.qb = 0;
			break;
		case ONU_GPE_INGRESS_QUEUE_LAN_1:
		case ONU_GPE_INGRESS_QUEUE_LAN_2:
		case ONU_GPE_INGRESS_QUEUE_LAN_3:
		case ONU_GPE_INGRESS_QUEUE_GEM_MC:
			/* enable all FW threads */
			iqt_entry.tmask = 0x3ffff;
			iqt_entry.qb = 0;
			break;
		case ONU_GPE_INGRESS_QUEUE_OMCI:
			/* enable link1 */
			iqt_entry.tmask = (1 << 19);
			iqt_entry.qb = 0;
			iqt_entry.qdth = 0x30;
			break;
		default:
			break;
		}
		iqm_iqt_write(queue_idx, &iqt_entry);
	}

	iqm_w32(NUM_IPP, fpcr);
	iqm_w32(0, gocc);
	iqm_w32(0, gpdc);
	iqm_w32(0, ts);
	
	/*  total SSB capacity in Segments (=4096) */
	iqm_w32(IQM_SSB_SIZE, goth);	
	iqm_w32(36, wrrc);	/*  36 slots in WRR used */

	for (i = 0; i < 5; i++)
		/*  all queues treated equally */
		iqm_w32(qid[i], wrrq[i]);

	/* sfreeX shouldn't be initialized */
	iqm_w32(0, drc);

	iqm_w32_mask(IQM_CTRL_FRZ, 0, ctrl);

	/* Set the timestamp prescaler to (module clock) / (2**4) */
	iqm_w32_mask(IQM_CTRL_TSPRESCALE_MASK, 4 << IQM_CTRL_TSPRESCALE_OFFSET, ctrl);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_global_occupancy_set(uint32_t gocc)
{
	iqm_w32(gocc & IQM_GOCC_GOCC_MASK, gocc);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void iqm_global_occupancy_get(uint32_t *gocc)
{
	*gocc = iqm_r32(gocc);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_global_discard_counter_set(uint32_t gpdc)
{
	iqm_w32(gpdc & IQM_GPDC_GPDC_MASK, gocc);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void iqm_global_discard_counter_get(uint32_t *gpdc)
{
	*gpdc = iqm_r32(gpdc);
}

void iqm_global_tail_drop_thr_set(uint32_t goth)
{
	iqm_w32(goth & IQM_GOTH_GOTH_MASK, goth);
}

void iqm_global_tail_drop_thr_get(uint32_t *goth)
{
	*goth = iqm_r32(goth);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_timestamp_get(uint32_t *ts)
{
	*ts = iqm_r32(ts);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void iqm_wrr_sched_cfg_set(struct iqm_wrr_cfg *cfg)
{
	uint32_t wrrq, i, k=0;

	iqm_w32(cfg->per & IQM_WRRC_PER_MASK, wrrc);

	for (i = 0; i < 4; i++) {
		wrrq = 0;
		set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ0_WRRQ0_MASK,
			IQM_WRRQ0_WRRQ0_OFFSET);
		set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ0_WRRQ1_MASK,
			IQM_WRRQ0_WRRQ1_OFFSET);
		set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ0_WRRQ2_MASK,
			IQM_WRRQ0_WRRQ2_OFFSET);
		set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ0_WRRQ3_MASK,
			IQM_WRRQ0_WRRQ3_OFFSET);
		set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ0_WRRQ4_MASK,
			IQM_WRRQ0_WRRQ4_OFFSET);
		set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ0_WRRQ5_MASK,
			IQM_WRRQ0_WRRQ5_OFFSET);
		set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ0_WRRQ6_MASK,
			IQM_WRRQ0_WRRQ6_OFFSET);
		set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ0_WRRQ7_MASK,
			IQM_WRRQ0_WRRQ7_OFFSET);
		iqm_w32(wrrq, wrrq[i]);
	}

	wrrq = 0;
	set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ4_WRRQ32_MASK,
		IQM_WRRQ4_WRRQ32_OFFSET);
	set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ4_WRRQ33_MASK,
		IQM_WRRQ4_WRRQ33_OFFSET);
	set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ4_WRRQ34_MASK,
		IQM_WRRQ4_WRRQ34_OFFSET);
	set_val(wrrq, cfg->wrrq[k++], IQM_WRRQ4_WRRQ35_MASK,
		IQM_WRRQ4_WRRQ35_OFFSET);
	iqm_w32(wrrq, wrrq[i]);
}

void iqm_wrr_sched_cfg_get(struct iqm_wrr_cfg *cfg)
{
	uint32_t wrrq, i, k=0;

	cfg->per = iqm_r32(wrrc);

	for (i = 0; i < 4; i++) {
		wrrq = iqm_r32(wrrq[i]);
		cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ0_WRRQ0_MASK,
					 IQM_WRRQ0_WRRQ0_OFFSET);
		cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ0_WRRQ1_MASK,
					 IQM_WRRQ0_WRRQ1_OFFSET);
		cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ0_WRRQ2_MASK,
					 IQM_WRRQ0_WRRQ2_OFFSET);
		cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ0_WRRQ3_MASK,
					 IQM_WRRQ0_WRRQ3_OFFSET);
		cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ0_WRRQ4_MASK,
					 IQM_WRRQ0_WRRQ4_OFFSET);
		cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ0_WRRQ5_MASK,
					 IQM_WRRQ0_WRRQ5_OFFSET);
		cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ0_WRRQ6_MASK,
					 IQM_WRRQ0_WRRQ6_OFFSET);
		cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ0_WRRQ7_MASK,
					 IQM_WRRQ0_WRRQ7_OFFSET);
	}

	wrrq = iqm_r32(wrrq[i]);
	cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ4_WRRQ32_MASK,
				IQM_WRRQ4_WRRQ32_OFFSET);
	cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ4_WRRQ33_MASK,
				IQM_WRRQ4_WRRQ33_OFFSET);
	cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ4_WRRQ34_MASK,
				IQM_WRRQ4_WRRQ34_OFFSET);
	cfg->wrrq[k++] = get_val(wrrq, IQM_WRRQ4_WRRQ35_MASK,
				IQM_WRRQ4_WRRQ35_OFFSET);
}

void iqm_sfree_get(uint32_t * sfree0, uint32_t * sfree1)
{
	*sfree0 = iqm_r32(sfree0);
	*sfree1 = iqm_r32(sfree1);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_dequeue_respond_get(struct iqm_dequeue_res *resp)
{
	uint32_t drp;

	drp = iqm_r32(drp0);
	resp->ts = get_val(drp, IQM_DRP0_TS_MASK, IQM_DRP0_TS_OFFSET);

	drp = iqm_r32(drp1);
	resp->nlsa = get_val(drp, IQM_DRP1_NLSA_MASK, IQM_DRP1_NLSA_OFFSET);
	resp->pdut = get_val(drp, IQM_DRP1_PDUT_MASK, IQM_DRP1_PDUT_OFFSET);
	resp->ipn  = get_val(drp, IQM_DRP1_IPN_MASK, IQM_DRP1_IPN_OFFSET);
	resp->tick = get_val(drp, IQM_DRP1_TICK_MASK, IQM_DRP1_TICK_OFFSET);

	drp = iqm_r32(drp2);
	resp->gpix = get_val(drp, IQM_DRP2_GPIX_MASK, IQM_DRP2_GPIX_OFFSET);
	resp->plen = get_val(drp, IQM_DRP2_PLEN_MASK, IQM_DRP2_PLEN_OFFSET);

	drp = iqm_r32(drp3);
	resp->tlsa = get_val(drp, IQM_DRP3_TLSA_MASK, IQM_DRP3_TLSA_OFFSET);
	resp->hlsa = get_val(drp, IQM_DRP3_HLSA_MASK, IQM_DRP3_HLSA_OFFSET);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_interrupt_enable_set(const uint32_t mask)
{
	iqm_w32(mask, irnen);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_interrupt_enable_get(uint32_t *mask)
{
	*mask = iqm_r32(irnen);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_interrupt_control_set(const uint32_t ctrl)
{
	iqm_w32(ctrl, irnicr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_interrupt_control_get(uint32_t *ctrl)
{
	*ctrl = iqm_r32(irnicr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_interrupt_capture_set(const uint32_t capt)
{
	iqm_w32(capt, irncr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_interrupt_capture_get(uint32_t *capt)
{
	*capt = iqm_r32(irncr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_iqueue_enable_set(const uint32_t qid, bool ena)
{
	/*
	   separate write of field QE
	*/
	iqm_w32_mask(IQM_IQT00_QE_EN, ena ? IQM_IQT00_QE_EN : 0, iqt[qid].iqt0);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_iqueue_enable_get(const uint32_t qid, bool *ena)
{
	/*
	   separate read of field QE
	*/
	*ena = (iqm_r32(iqt[qid].iqt0) & IQM_IQT00_QE_EN) ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_iqueue_blk_set(const uint32_t qid, bool block)
{
	/*
	   separate write of field QB
	*/
	iqm_w32_mask(IQM_IQT01_QB_BL, block ? IQM_IQT01_QB_BL : 0, iqt[qid].iqt1);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_iqueue_blk_get(const uint32_t qid, bool *block)
{
	/*
	   separate read of field QB
	*/
	*block = (iqm_r32(iqt[qid].iqt1) & IQM_IQT01_QB_BL) ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void iqm_iqueue_cfg_set(const uint32_t qid, struct iqm_iqt_entry *cfg)
{
	/*
	   write of all 7 configuration fields of iqm_iqt_entry:

	   IQT[qid][0].QE   = cfg->qe;
	   IQT[qid][0].QDTH = cfg->qdth;
	   IQT[qid][0].QRTH = cfg->qrth;
	   IQT[qid][1].QB   = cfg->qb;
	   IQT[qid][1].QBTH = cfg->qbth;
	   IQT[qid][1].QBTL = cfg->qbtl;
	   IQT[qid][5].TMASK= cfg->tmask;
	*/
	uint32_t iqt;

	iqt = 0;
	iqt |= (cfg->qe) ? IQM_IQT00_QE_EN : 0;
	set_val(iqt, cfg->qdth, IQM_IQT00_QDTH_MASK, IQM_IQT00_QDTH_OFFSET);
	set_val(iqt, cfg->qrth, IQM_IQT00_QRTH_MASK, IQM_IQT00_QRTH_OFFSET);
	iqm_w32(iqt, iqt[qid].iqt0);

	iqt = 0;
	iqt |= (cfg->qb) ? IQM_IQT01_QB_BL : 0;
	set_val(iqt, cfg->qbth, IQM_IQT01_QBTH_MASK, IQM_IQT01_QBTH_OFFSET);
	set_val(iqt, cfg->qbtl, IQM_IQT01_QBTL_MASK, IQM_IQT01_QBTL_OFFSET);
	iqm_w32(iqt, iqt[qid].iqt1);

	iqt = cfg->tmask;
	iqm_w32(iqt, iqt[qid].iqt5);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void iqm_iqueue_discard_counter_set(uint32_t qid, uint32_t qdc)
{
	/*
	   IQT[qid][3].QDC = qdc;
	*/
	uint32_t val = 0;

	set_val(val, qdc, IQM_IQT03_QDC_MASK, IQM_IQT03_QDC_OFFSET);
	iqm_w32_mask(IQM_IQT03_QDC_MASK, val, iqt[qid].iqt3);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

uint32_t iqm_iqueue_discard_counter_get(uint32_t qid)
{
	/*
	   qdc  = IQT[qid][3].QDC;
	*/
	uint32_t iqt03;

	iqt03 = iqm_r32(iqt[qid].iqt3);
	return get_val(iqt03, IQM_IQT03_QDC_MASK, IQM_IQT03_QDC_OFFSET);
}

void iqm_iqueue_cfg_get(const uint32_t qid, struct iqm_iqt_entry *cfg)
{
	/*
	   read of all 7 configuration fields of iqm_iqt_entry:

	   cfg->qe   = IQT[qid][0].QE;
	   cfg->qdth = IQT[qid][0].QDTH;
	   cfg->qrth = IQT[qid][0].QRTH;
	   cfg->qb   = IQT[qid][1].QB;
	   cfg->qbth = IQT[qid][1].QBTH;
	   cfg->qbtl = IQT[qid][1].QBTL;
	   cfg->tmask= IQT[qid][5].TMASK;

	*/
	uint32_t iqt;

	iqt = iqm_r32(iqt[qid].iqt0);
	cfg->qe = (iqt & IQM_IQT00_QE_EN) ? 1 : 0;
	cfg->qdth = get_val(iqt, IQM_IQT00_QDTH_MASK, IQM_IQT00_QDTH_OFFSET);
	cfg->qrth = get_val(iqt, IQM_IQT00_QRTH_MASK, IQM_IQT00_QRTH_OFFSET);

	iqt = iqm_r32(iqt[qid].iqt1);
	cfg->qb = (iqt & IQM_IQT01_QB_BL) ? 1 : 0;
	cfg->qbth = get_val(iqt, IQM_IQT01_QBTH_MASK, IQM_IQT01_QBTH_OFFSET);
	cfg->qbtl = get_val(iqt, IQM_IQT01_QBTL_MASK, IQM_IQT01_QBTL_OFFSET);

	iqt = iqm_r32(iqt[qid].iqt5);
	cfg->tmask = iqt;
}

void iqm_iqueue_status_get(const uint32_t qid, struct iqm_iqt_entry *cfg)
{
	/*
	   read of all 7 status fields of iqm_iqt_entry:

	   cfg->qf   = IQT[qid][2].QF;
	   cfg->bp   = IQT[qid][2].BP;
	   cfg->qpsf = IQT[qid][2].QPSF;
	   cfg->pocc = IQT[qid][2].POCC;
	   cfg->qocc = IQT[qid][2].QOCC;
	   cfg->qdc  = IQT[qid][3].QDC;
	   cfg->tick = IQT[qid][4].TICK;

	*/
	uint32_t iqt;

	iqt = iqm_r32(iqt[qid].iqt2);
	cfg->qf = (iqt & IQM_IQT02_QF) ? 1 : 0;
	cfg->bp = (iqt & IQM_IQT02_BP) ? 1 : 0;
	cfg->pocc = get_val(iqt, IQM_IQT02_POCC_MASK, IQM_IQT02_POCC_OFFSET);
	cfg->qocc = get_val(iqt, IQM_IQT02_QOCC_MASK, IQM_IQT02_QOCC_OFFSET);

	iqt = iqm_r32(iqt[qid].iqt3);
	cfg->qdc = get_val(iqt, IQM_IQT03_QDC_MASK, IQM_IQT03_QDC_OFFSET);

	iqt = iqm_r32(iqt[qid].iqt4);
	cfg->tick = get_val(iqt, IQM_IQT04_TICK_MASK, IQM_IQT04_TICK_OFFSET);
}

bool iqm_is_backpressure_asserted(const uint8_t qid)
{
	return iqm_r32(iqt[qid].iqt2) & IQM_IQT02_BP ? true : false;
}

#if defined(INCLUDE_DUMP)

void iqm_dump(struct seq_file *s)
{
	uint32_t i, k;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_IQM_SET) == 0) {
		seq_printf(s, "iqm not activated\n");
		return;
	}
	seq_printf(s, "    ctrl,    fpcr,    gocc,    gpdc,"
			"      ts,    goth,    wrrc,     drc,  irnicr\n");
	seq_printf(s, "%08x,", iqm_r32(ctrl));
	seq_printf(s, "%08x,", iqm_r32(fpcr));
	seq_printf(s, "%08x,", iqm_r32(gocc));
	seq_printf(s, "%08x,", iqm_r32(gpdc));
	seq_printf(s, "%08x,", iqm_r32(ts));
	seq_printf(s, "%08x,", iqm_r32(goth));
	seq_printf(s, "%08x,", iqm_r32(wrrc));
	seq_printf(s, "%08x,", iqm_r32(drc));
	seq_printf(s, "%08x\n", iqm_r32(irnicr));

	seq_printf(s, "wrrq table\n");
	for (i = 0; i < 5;) {
		seq_printf(s, "%08x:  ", (unsigned int)&iqm->wrrq[i]);
		for (k = 0; k < 16 && i < 5; k++, i++)
			seq_printf(s, "%08x ", iqm_r32(wrrq[i]));
		seq_printf(s, "\n");
	}

	seq_printf(s, "iqt table\n");
	for (i = 0; i < MAX_QUEUE; i++) {
		seq_printf(s, "%08x:  ", (unsigned int)&iqm->iqt[i].iqt0);
		seq_printf(s, "%08x %08x %08x ", iqm_r32(iqt[i].iqt0),
			   iqm_r32(iqt[i].iqt1),
			   iqm_r32(iqt[i].iqt2));
		seq_printf(s, "%08x %08x %08x ", iqm_r32(iqt[i].iqt3),
			   iqm_r32(iqt[i].iqt4),
			   iqm_r32(iqt[i].iqt5));
		seq_printf(s, "\n");
	}
}

#endif

/*! @} */

/*! @} */
