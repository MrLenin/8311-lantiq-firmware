/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_fsqm.h"
#include "drv_onu_resource_gpe.h"	/* ONU_GPE_LLT_NIL */

#define HEAD_TAIL_SUPERVISION

#ifdef HEAD_TAIL_SUPERVISION
static uint16_t initial_tail;
static uint16_t initial_head;
#endif

static bool fsqm_init_done=0;

STATIC void fsqm_basic_init(void);
STATIC void fsqm_llt_init(struct fsq *p_fsq);

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_ifsq_read(struct fsq *fsq)
{
	uint32_t reg = 0;

	if (is_falcon_chip_a1x())
		reg = fsqm_r32(ifsq_a1x);

	fsq->head = (reg & FSQM_IFSQ_A1X_HEAD_MASK) >> FSQM_IFSQ_A1X_HEAD_OFFSET;
	fsq->tail = (reg & FSQM_IFSQ_A1X_TAIL_MASK) >> FSQM_IFSQ_A1X_TAIL_OFFSET;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void fsqm_ofsq_read(struct fsq *fsq)
{
	uint32_t reg;

	reg = fsqm_r32(ofsq);
	fsq->head = (reg & FSQM_OFSQ_HEAD_MASK) >> FSQM_OFSQ_HEAD_OFFSET;
	fsq->tail = (reg & FSQM_OFSQ_TAIL_MASK) >> FSQM_OFSQ_TAIL_OFFSET;
#ifdef HEAD_TAIL_SUPERVISION
	if (fsq->head > initial_tail) {
		ONU_DEBUG_ERR(	"fsqm_ofsq_read: head %x exceeds "
				"(initial head %x)", fsq->head, initial_tail);
	}
	if (fsq->tail < initial_head) {
		ONU_DEBUG_ERR(	"fsqm_ofsq_read: tail %x underrun "
				"(initial tail %x)", fsq->tail, initial_head);
	}
#endif
}

void fsqm_enable(bool act)
{
	fsqm_w32_mask(FSQM_CTRL_ACT_EN, act ? FSQM_CTRL_ACT_EN : 0, ctrl);
}

bool fsqm_is_enabled(void)
{
	if (fsqm_init_done == 0)
		return false;
	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_FSQM_SET) == 0)
		return false;
	return fsqm_r32(ctrl) & FSQM_CTRL_ACT_EN ? true : false;
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_reset_set(bool res)
{
	fsqm_w32_mask(FSQM_CTRL_RES, res ? FSQM_CTRL_RES : 0, ctrl);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_reset_get(bool *res)
{
	*res = fsqm_r32(ctrl) & FSQM_CTRL_RES ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_prio_set(struct fsqm_prio * prio)
{
	uint32_t reg_val;

	if (is_falcon_chip_a1x()) {
		/* Get PRIO register */
		reg_val = fsqm_r32(prio_a1x);

		/* Set Priority number for CPU */
		set_val(reg_val, prio->pcpu, FSQM_PRIO_A1X_PCPU_MASK,
			FSQM_PRIO_A1X_PCPU_OFFSET);
		/* Set Priority number for ICTRL (GPE_IN) */
		set_val(reg_val, prio->pictrl, FSQM_PRIO_A1X_PICTRL_MASK,
			FSQM_PRIO_A1X_PICTRL_OFFSET);
		/* Set Priority number for PCTRL (GPE_KERNEL) */
		set_val(reg_val, prio->ppctrl, FSQM_PRIO_A1X_PPCTRL_MASK,
			FSQM_PRIO_A1X_PPCTRL_OFFSET);
		/* Set Priority number for OCTRL (GPE_OUT) */
		set_val(reg_val, prio->poctrl, FSQM_PRIO_A1X_POCTRL_MASK,
			FSQM_PRIO_A1X_POCTRL_OFFSET);
		/* Set Priority number for IQM (GPE_KERNEL) */
		set_val(reg_val, prio->piqm, FSQM_PRIO_A1X_PIQM_MASK,
			FSQM_PRIO_A1X_PIQM_OFFSET);

		/* Enable/disable round-robin of priorities */
		reg_val |= prio->rr ? FSQM_PRIO_A1X_RR_EN : 0;

		/* Set PRIO register */
		fsqm_w32(reg_val, prio_a1x);
	}
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_prio_get(struct fsqm_prio * prio)
{
	uint32_t reg_val;

	/* Get PRIO register */
	if (is_falcon_chip_a1x())
		reg_val = fsqm_r32(prio_a1x);
	else
		reg_val = 0;

	prio->pcpu = get_val(reg_val, FSQM_PRIO_A1X_PCPU_MASK,
			     FSQM_PRIO_A1X_PCPU_OFFSET);
	prio->pictrl = get_val(reg_val, FSQM_PRIO_A1X_PICTRL_MASK,
			       FSQM_PRIO_A1X_PICTRL_OFFSET);
	prio->ppctrl = get_val(reg_val, FSQM_PRIO_A1X_PPCTRL_MASK,
			       FSQM_PRIO_A1X_PPCTRL_OFFSET);
	prio->poctrl = get_val(reg_val, FSQM_PRIO_A1X_POCTRL_MASK,
			       FSQM_PRIO_A1X_POCTRL_OFFSET);
	prio->piqm = get_val(reg_val, FSQM_PRIO_A1X_PIQM_MASK,
			     FSQM_PRIO_A1X_PIQM_OFFSET);

	prio->rr = reg_val & FSQM_PRIO_A1X_RR ? 1 : 0;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/**
   Init FSQM
*/
void fsqm_init(struct fsq *p_fsq)
{
	uint32_t tail_max;

	tail_max = (ONU_SBS0RAM_SIZE / ONU_GPE_BUFFER_SEGMENT_SIZE);
	tail_max -= (sbs0ctrl_r32(bar1) & SBS0CTRL_BAR1_BA1V_MASK) /
			ONU_GPE_BUFFER_SEGMENT_SIZE;
	if (p_fsq->tail > tail_max)
		p_fsq->tail = tail_max;

	if (p_fsq->head == 0 && p_fsq->tail == 0) {
		ONU_DEBUG_MSG("fsqm_init: Max. values used");
		p_fsq->head = 0;
		p_fsq->tail = tail_max;
	} else {
		ONU_DEBUG_MSG(	"fsqm_init: User values used "
				"(head=0x%04x, tail=0x%04x)",
					p_fsq->head, p_fsq->tail);
	}

	/*
	  Enable module clock, release reset. This is mandatory before
	  accessing module's registers.
	*/
	sys_gpe_hw_activate_or_reboot(SYS_GPE_ACT_FSQM_SET);

	if ((p_fsq->tail > ONU_GPE_LLT_MAX) || (p_fsq->tail > tail_max)) {
		p_fsq->tail = tail_max;
		ONU_DEBUG_WRN("fsqm_init: tail reduced to max val (0x%04x)",
			p_fsq->tail);
	}

	/* point to the last usable entry */
	p_fsq->tail--;

	/*
	   - SW reset brings module into defined HW state
	   - initializes all registers
	   - builds linked list
	   - and then activates FSQM
	 */
	fsqm_w32_mask(0, FSQM_CTRL_RES_EN, ctrl);
	fsqm_w32_mask(FSQM_CTRL_RES_EN, 0, ctrl);

	fsqm_basic_init();
	fsqm_llt_init(p_fsq);

	fsqm_w32_mask(0, 0x0, io_buf_rd);
	fsqm_w32_mask(0, 0x0, io_buf_wr);

	/*fsqm_w32_mask(0, FSQM_CTRL_ACT_EN, ctrl);*/

	fsqm_init_done = true;
}

/*
- FSQM deactivated
- IO buffer disabled
- all pause thresholds deasserted
- all interrupts disabled
- same prio for all masters, except CPU (highest prio)
- enable round robin
*/
STATIC void fsqm_basic_init(void)
{
	fsqm_w32(0, ctrl);

	if (is_falcon_chip_a1x()) {
		uint32_t reg;
		reg = 0x0;
		reg |= FSQM_PRIO_A1X_RR_EN;
		reg |= (4 << FSQM_PRIO_A1X_PIQM_OFFSET);
		reg |= (3 << FSQM_PRIO_A1X_POCTRL_OFFSET);
		reg |= (2 << FSQM_PRIO_A1X_PPCTRL_OFFSET);
		reg |= (1 << FSQM_PRIO_A1X_PICTRL_OFFSET);
		reg |= (5 << FSQM_PRIO_A1X_PCPU_OFFSET);
		fsqm_w32(reg, prio_a1x);

		fsqm_w32(0, imq_a1x);
		fsqm_w32(0, ifsc_a1x);
	}

	/* Disable all interrupts */
	fsqm_w32(0, irncr);
	fsqm_w32(0, irnicr);
	fsqm_w32(0, irnen);

	fsqm_w32(0, ofsc);
	fsqm_w32(0, fsqt0);
	fsqm_w32(0, fsqt1);
	fsqm_w32(0, fsqt2);
	fsqm_w32(0, fsqt3);
	fsqm_w32(0, fsqt4);
	fsqm_w32(0, omq);
}

/*
   \param nb_of_elements   Number of memory elements that will be put into
                           the initial Free Segment Queue (FSQ).
                           A Linked List Table (LLT) will be built up starting
                           from first_element to last_element.
*/
STATIC void fsqm_llt_init(struct fsq *p_fsq)
{
	uint32_t i = p_fsq->head;
	int wdata;

	while (i < (p_fsq->tail)) {
		wdata = i + 1;
		fsqm_w32(wdata, ram[i]);
		fsqm_w32(RCNT_INIT, rcnt[i]);
		i++;
	}

	fsqm_w32(ONU_GPE_LLT_NIL, ram[i]);
	fsqm_w32(RCNT_INIT, rcnt[i]);

	/* ofsq - is used */
	/* init in queue head & tail */
	wdata = p_fsq->head << FSQM_OFSQ_HEAD_OFFSET;
	wdata |= p_fsq->tail << FSQM_OFSQ_TAIL_OFFSET;
	fsqm_w32(wdata, ofsq);

	/* init in queue counter */
	fsqm_w32((p_fsq->tail - p_fsq->head) + 1, ofsc);

	if (is_falcon_chip_a1x()) {
		/* ifsq - is not used */
		/* init out queue head & tail */
		wdata = ONU_GPE_LLT_NIL << FSQM_IFSQ_A1X_HEAD_OFFSET;
		wdata |= ONU_GPE_LLT_NIL << FSQM_IFSQ_A1X_TAIL_OFFSET;
		fsqm_w32(wdata, ifsq_a1x);

		/* init out queue counter */
		fsqm_w32(0, ifsc_a1x);
	}

#ifdef HEAD_TAIL_SUPERVISION
	i = fsqm_r32(ofsq);
	initial_head = (i & FSQM_OFSQ_HEAD_MASK) >> FSQM_OFSQ_HEAD_OFFSET;
	initial_tail = (i & FSQM_OFSQ_TAIL_MASK) >> FSQM_OFSQ_TAIL_OFFSET;
#endif
}

uint16_t fsqm_llt_read(const uint16_t idx)
{
	return fsqm_r32(ram[idx]);
}

void fsqm_llt_write(const uint16_t idx, const uint32_t val)
{
	fsqm_w32(val, ram[idx]);
}

void fsqm_free_segment_threshold_set(const uint32_t threshold[5])
{
	fsqm_w32(threshold[0] & FSQM_FSQT0_FSQT_MASK, fsqt0);
	fsqm_w32(threshold[1] & FSQM_FSQT1_FSQT_MASK, fsqt1);
	fsqm_w32(threshold[2] & FSQM_FSQT2_FSQT_MASK, fsqt2);
	fsqm_w32(threshold[3] & FSQM_FSQT3_FSQT_MASK, fsqt3);
	fsqm_w32(threshold[4] & FSQM_FSQT4_FSQT_MASK, fsqt4);
}

void fsqm_free_segment_threshold_get(uint32_t threshold[5])
{
	threshold[0] = fsqm_r32(fsqt0);
	threshold[1] = fsqm_r32(fsqt1);
	threshold[2] = fsqm_r32(fsqt2);
	threshold[3] = fsqm_r32(fsqt3);
	threshold[4] = fsqm_r32(fsqt4);
}

uint16_t fsqm_segment_alloc(void)
{
	uint16_t hlsa;

	hlsa = (fsqm_r32(omq[0]) >> FSQM_OMQ_HLSA_OFFSET)
	    & FSQM_OMQ_HLSA_MASK;

	if (hlsa == ONU_GPE_LLT_NIL) {
		ONU_DEBUG_ERR("ooops, can't get enough segments");
		return hlsa;
	}

#ifdef HEAD_TAIL_SUPERVISION
	if (hlsa > initial_tail) {
		ONU_DEBUG_ERR(	"fsqm_segment_alloc: head %x exceeds "
				"(initial tail %x)", hlsa, initial_tail);
	}
#endif

	fsqm_w32(1, rcnt[hlsa]);

	return hlsa;
}

void fsqm_segment_free(const uint16_t tlsa, const uint16_t hlsa,
						const uint16_t seg_len, const uint16_t hdr_seg_len)
{
	uint16_t header_tlsa = ONU_GPE_LLT_NIL;
	uint16_t body_hlsa = ONU_GPE_LLT_NIL;
	uint16_t body_seg_len = seg_len - hdr_seg_len;
	uint16_t cnt;

	if (tlsa == ONU_GPE_LLT_NIL || hlsa == ONU_GPE_LLT_NIL ||
			seg_len == 0 || body_seg_len == 0)
		return;

#ifdef HEAD_TAIL_SUPERVISION
	if (hlsa > initial_tail) {
		ONU_DEBUG_ERR(	"fsqm_segment_free: head %x exceeds "
				"(initial tail %x)", hlsa, initial_tail);
	}
	if (tlsa > initial_tail) {
		ONU_DEBUG_ERR(	"fsqm_segment_free: tail %x exceeds "
				"(initial tail %x)", tlsa, initial_tail);
	}
#endif

	switch (hdr_seg_len) {
		case 0:
		break;
		case 1:
		header_tlsa = hlsa;
		break;
		case 2:
		header_tlsa = fsqm_llt_read(hlsa);
		break;
		default:
		break;
	}

	if (header_tlsa != ONU_GPE_LLT_NIL) {
		body_hlsa = fsqm_llt_read(header_tlsa);
		if (body_hlsa != ONU_GPE_LLT_NIL) {
			cnt = fsqm_r32(rcnt_incdec[body_hlsa]) & 0x7;
			if(cnt == 1) {
				fsqm_w32((tlsa << FSQM_OMQ_TLSA_OFFSET) | body_hlsa, omq[body_seg_len]);
			}
		}
		fsqm_w32((header_tlsa << FSQM_OMQ_TLSA_OFFSET) | hlsa, omq[hdr_seg_len]);
	} else {
		fsqm_w32((tlsa << FSQM_OMQ_TLSA_OFFSET) | hlsa, omq[seg_len]);
	}
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_interrupt_enable_set(const uint32_t mask)
{
	fsqm_w32(mask, irnen);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_interrupt_enable_get(uint32_t *mask)
{
	*mask = fsqm_r32(irnen);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_interrupt_control_set(const uint32_t ctrl)
{
	fsqm_w32(ctrl, irnicr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_interrupt_control_get(uint32_t *ctrl)
{
	*ctrl = fsqm_r32(irnicr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_fsqm_interrupt_capture_set(const uint32_t capt)
{
	fsqm_w32(capt, irncr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void fsqm_fsqm_interrupt_capture_get(uint32_t *capt)
{
	*capt = fsqm_r32(irncr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#if !defined(ONU_LIBRARY)
static bool touched[ONU_GPE_LLT_MAX];

bool fsqm_check(uint16_t len)
{
	bool pass;
	uint16_t reg;
	uint16_t cnt;
	struct fsq fsq;
	uint16_t head, tail, next;

	pass = true;

	memset(&touched[0], 0x00, sizeof(touched));

	/* check: free segment queue is back at its original length */
	reg = fsqm_r32(ofsc);
	if (reg == len) {
		ONU_DEBUG_WRN("pass: OFSC is back at its expected value");
	} else {
		ONU_DEBUG_WRN(	"error: OFSC is NOT back "
				"at its original length = %d", reg);
		pass = false;
	}

	/* check: free segment queue is not corrupt
	step through the free segment queue, starting from the head LSA,
	and follow the next pointers until the tail LSA is reached.
	In an array, mark all LSAs which were touched while stepping through.
	If the FSQ touches the same LSA twice, the FSQ is corrupt. */
	for (cnt = 0; cnt < ONU_GPE_LLT_MAX; cnt++)
		touched[cnt] = false;

	fsqm_ofsq_read(&fsq);	/* get head LSA */
	head = fsq.head;
	tail = fsq.tail;
	ONU_DEBUG_WRN("start with head: 0x%x tail: 0x%x", head, tail);
	touched[head] = true;

	for (cnt = 0; cnt < (len-1); cnt++) {
		next =  fsqm_llt_read(head);
		ONU_DEBUG_WRN("[%5d] llt addr: 0x%04x llt data: 0x%04x",
				cnt, head, next);
		/* ONU_DEBUG_MSG("info: cnt: %d", cnt); */

		if (next == ONU_GPE_LLT_NIL) {
			ONU_DEBUG_WRN(	"warning: LLT end received too early "
					"(NIL value detected)");
			head = next;
			pass = false;
			cnt++;
			break;
		}

		if (next == tail && cnt != (len-2)) {
			ONU_DEBUG_WRN(	"warning: TAIL received (too early) "
					"(tail = 0x%04x)", next);
			head = next;
			pass = false;
			cnt++;
			break;
		}

		if (next >= ONU_GPE_LLT_MAX) {
			ONU_DEBUG_WRN(	"warning: LLT next pointer out of "
					"range 0x0..0x47ff is 0x04%x", next);
			head = next;
			pass = false;
			cnt++;
			break;
		}

		if (touched[next] == false) {
			/*ONU_DEBUG_WRN("pass: FSQ check next LSA: 0x%x", next);*/
			touched[next] = true;
		} else {
			ONU_DEBUG_WRN("error: FSQ touches the same LSA twice, "
				      "the FSQ is corrupt");
			pass = false;
		}

		head = next;
	}

	next =  fsqm_llt_read(head);
	ONU_DEBUG_WRN("[%5d] llt addr: 0x%04x llt data: 0x%04x", cnt, head,
								 next);

	tail = fsq.tail;
	if (tail == head) {
		ONU_DEBUG_WRN("pass: FSQ tail LSA is equal to last next LSA!");
	} else {
		ONU_DEBUG_WRN("error: FSQ tail LSA: 0x%x does not match last "
			      "next LSA: 0x%x", tail, head);
		pass =false;
	}

	return pass;
}
#endif /* ONU_LIBRARY */

#if defined(INCLUDE_DUMP)

void fsqm_dump(struct seq_file *s)
{
	uint32_t llt_max;

	llt_max = (ONU_SBS0RAM_SIZE / ONU_GPE_BUFFER_SEGMENT_SIZE) -
			((sbs0ctrl_r32(bar1) & SBS0CTRL_BAR1_BA1V_MASK) /
						   ONU_GPE_BUFFER_SEGMENT_SIZE);

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_FSQM_SET) == 0) {
		seq_printf(s, "fsqm not activated\n");
		return;
	}

#define dump_reg(reg) \
	seq_printf(s, "%-14s = 0x%08x\n", # reg, fsqm_r32(reg))

	dump_reg(ctrl);
	seq_printf(s, "%-14s = 0x%08x\n", "llt_max", llt_max);
	if (is_falcon_chip_a1x()) {
		dump_reg(prio_a1x);
	}
	dump_reg(ofsq);
	dump_reg(ofsc);
	dump_reg(fsqt0);
	dump_reg(fsqt1);
	dump_reg(fsqt2);
	dump_reg(fsqt3);
	dump_reg(fsqt4);
	dump_reg(irnicr);
#undef dump_reg
}

int fsqm_llt(struct seq_file *s, int pos)
{
	uint32_t llt_max;
	int ret;

	llt_max = (ONU_SBS0RAM_SIZE / ONU_GPE_BUFFER_SEGMENT_SIZE) -
			((sbs0ctrl_r32(bar1) & SBS0CTRL_BAR1_BA1V_MASK) /
						   ONU_GPE_BUFFER_SEGMENT_SIZE);

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_FSQM_SET) == 0) {
		seq_printf(s, "fsqm not activated\n");
		return -1;
	}

	ret = seq_printf(s, "0x%08x :  "
			 "0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x "
			 "0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x "
			 "0x%08x 0x%08x\n",
				 (unsigned int)&fsqm->ram[pos],
				 fsqm_r32(ram[pos +  0]),
				 fsqm_r32(ram[pos +  1]),
				 fsqm_r32(ram[pos +  2]),
				 fsqm_r32(ram[pos +  3]),
				 fsqm_r32(ram[pos +  4]),
				 fsqm_r32(ram[pos +  5]),
				 fsqm_r32(ram[pos +  6]),
				 fsqm_r32(ram[pos +  7]),
				 fsqm_r32(ram[pos +  8]),
				 fsqm_r32(ram[pos +  9]),
				 fsqm_r32(ram[pos + 10]),
				 fsqm_r32(ram[pos + 11]),
				 fsqm_r32(ram[pos + 12]),
				 fsqm_r32(ram[pos + 13]),
				 fsqm_r32(ram[pos + 14]),
				 fsqm_r32(ram[pos + 15]));
	if (ret != 0)
		return pos;

	if (pos + 16 >= (int)llt_max)
		return -1;
	else
		return pos + 16;
}

int fsqm_rcnt(struct seq_file *s, int pos)
{
	uint32_t llt_max;
	int ret;

	llt_max = (ONU_SBS0RAM_SIZE / ONU_GPE_BUFFER_SEGMENT_SIZE) -
			((sbs0ctrl_r32(bar1) & SBS0CTRL_BAR1_BA1V_MASK) /
						  ONU_GPE_BUFFER_SEGMENT_SIZE);

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_FSQM_SET) == 0) {
		seq_printf(s, "fsqm not activated\n");
		return -1;
	}

	ret = seq_printf(s, "0x%08x :  "
			 "0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x "
			 "0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x "
			 "0x%08x 0x%08x\n",
				 (unsigned int)&fsqm->rcnt[pos],
				 fsqm_r32(rcnt[pos +  0]),
				 fsqm_r32(rcnt[pos +  1]),
				 fsqm_r32(rcnt[pos +  2]),
				 fsqm_r32(rcnt[pos +  3]),
				 fsqm_r32(rcnt[pos +  4]),
				 fsqm_r32(rcnt[pos +  5]),
				 fsqm_r32(rcnt[pos +  6]),
				 fsqm_r32(rcnt[pos +  7]),
				 fsqm_r32(rcnt[pos +  8]),
				 fsqm_r32(rcnt[pos +  9]),
				 fsqm_r32(rcnt[pos + 10]),
				 fsqm_r32(rcnt[pos + 11]),
				 fsqm_r32(rcnt[pos + 12]),
				 fsqm_r32(rcnt[pos + 13]),
				 fsqm_r32(rcnt[pos + 14]),
				 fsqm_r32(rcnt[pos + 15]));
	if (ret != 0)
		return pos;

	if (pos + 16 >= (int)llt_max)
		return -1;
	else
		return pos + 16;
}

#endif
