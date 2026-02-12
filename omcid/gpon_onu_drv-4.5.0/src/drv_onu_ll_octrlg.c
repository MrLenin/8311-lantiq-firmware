/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_octrlg.h"

STATIC int octrlg_basic_init(void);
STATIC void octrlg_tcont_map_init(void);
STATIC void octrlg_tcont_table_init(void);
STATIC void octrlg_gpix_table_init(void);

int octrlg_init(void)
{
	uint32_t i;

	/*
	  Enable module clock, release reset. This is mandatory before
	  accessing module's registers.
	*/
	sys_gpe_hw_activate_or_reboot(SYS_GPE_ACT_GPONE_SET);

	if (octrlg_basic_init() != 0)
		return -1;
	/*
	   OCTRLG.TCMAP[0..1023]    = 0x0000 0000
	   OCTRLG.TCTABLE[0..15]    = 0xFFFF FFFF
	   OCTRLG.GPIXTABLE[0..127] = 0x0000 0000
	 */
	octrlg_tcont_map_init();
	octrlg_tcont_table_init();
	octrlg_gpix_table_init();

	/* Initialization of counter memories */
	for (i = 0; i < GPIXTABLE_LEN; i++) {
		octrlg_w32(0, txpcnt[i]);
		octrlg_w32(0, txbcntl[i]);
	}

	return 0;
}

/*
   nGemBlockLength: configure in OCTRLG, OCTRLG.CFG0.IBS = 2^15/gem_block_len
   gem_payload_sz_max: configure in OCTRLG, OCTRLG.CFG1.GEMPLSIZE
*/
int octrlg_config_set(const uint32_t gem_block_len,
		      const uint32_t gem_payload_sz_max)
{
	if (gem_block_len == 0)
		return -1;

	octrlg_w32_mask(OCTRLG_CFG0_IBS_MASK,
			(((1 << 15) / gem_block_len) & OCTRLG_CFG0_IBS_MASK),
			cfg0);
	octrlg_w32_mask(OCTRLG_CFG1_GEMPLSIZE_MASK,
			((gem_payload_sz_max << OCTRLG_CFG1_GEMPLSIZE_OFFSET) &
			 OCTRLG_CFG1_GEMPLSIZE_MASK), cfg1);
	return 0;
}

int octrlg_config_get(uint32_t *gem_block_len, uint32_t *gem_payload_sz_max)
{
	if (octrlg_r32(cfg0) & OCTRLG_CFG0_IBS_MASK)
		*gem_block_len =
		    (1 << 15) / (octrlg_r32(cfg0) & OCTRLG_CFG0_IBS_MASK);

	*gem_payload_sz_max =
	    (octrlg_r32(cfg1) & OCTRLG_CFG1_GEMPLSIZE_MASK) >>
	    OCTRLG_CFG1_GEMPLSIZE_OFFSET;

	return 0;
}

void octrlg_dbru_mode_dbg_set(const uint32_t act)
{
	octrlg_w32_mask(OCTRLG_CFG1_DBRUDBG_EN,
			act ? OCTRLG_CFG1_DBRUDBG_EN : 0, cfg1);
}

void octrlg_dbru_mode_dbg_get(uint32_t *act)
{
	*act = (octrlg_r32(cfg1) & OCTRLG_CFG1_DBRUDBG_EN) ? true : false;
}

void octrlg_dbru_debug_set(const uint32_t mode2y,
			   const uint32_t mode2g,
			   const uint32_t mode1)
{
	octrlg_w32_mask(OCTRLG_DBRUDBG_DBRU2Y_MASK |
			OCTRLG_DBRUDBG_DBRU2G_MASK |
			OCTRLG_DBRUDBG_DBRU1_MASK,
			(mode2y << OCTRLG_DBRUDBG_DBRU2Y_OFFSET) |
			(mode2g << OCTRLG_DBRUDBG_DBRU2G_OFFSET) |
			(mode1 << OCTRLG_DBRUDBG_DBRU1_OFFSET),
			dbrudbg);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrlg_dbru_debug_get(uint32_t *mode2y, uint32_t *mode2g, uint32_t *mode1)
{
	uint32_t reg;

	reg = octrlg_r32(dbrudbg);

	*mode2y = (reg & OCTRLG_DBRUDBG_DBRU2Y_MASK) >>
						OCTRLG_DBRUDBG_DBRU2Y_OFFSET;
	*mode2g = (reg & OCTRLG_DBRUDBG_DBRU2G_MASK) >>
						OCTRLG_DBRUDBG_DBRU2G_OFFSET;
	*mode1  = (reg & OCTRLG_DBRUDBG_DBRU1_MASK)  >>
						OCTRLG_DBRUDBG_DBRU1_OFFSET;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void octrlg_dbru_mode_get(uint32_t *mode)
{
	*mode = (octrlg_r32(tcreq) & OCTRLG_TCREQ_DBRU_MASK) >>
							OCTRLG_TCREQ_DBRU_OFFSET;
}

/**
   OCTRLG.TCTABLE[n].REPN[n] = egress_port_idx, with n = tcont_idx
*/
int octrlg_epn_set(const uint32_t tcont_idx, const uint32_t egress_port_idx,
		   const uint32_t prempted_epn_idx)
{
	if (tcont_idx >= ONU_GPE_MAX_TCONT)
		return -1;

	octrlg_w32_mask(OCTRLG_TCTABLE0_REPN0_MASK,
			((egress_port_idx << OCTRLG_TCTABLE0_REPN0_OFFSET) &
				OCTRLG_TCTABLE0_REPN0_MASK),
			tctable[tcont_idx]);

	octrlg_w32_mask(OCTRLG_TCTABLE0_PEPN0_MASK,
			((prempted_epn_idx << OCTRLG_TCTABLE0_PEPN0_OFFSET) &
				OCTRLG_TCTABLE0_PEPN0_MASK),
			tctable[tcont_idx]);
	return 0;
}

int octrlg_epn_get(const uint32_t tcont_idx, uint32_t *egress_port_idx,
		   uint32_t *prempted_epn_idx)
{
	if (tcont_idx >= ONU_GPE_MAX_TCONT) {
		*egress_port_idx = 0;
		*prempted_epn_idx = 0;
		return -1;
	}

	*egress_port_idx =
		(octrlg_r32(tctable[tcont_idx]) & OCTRLG_TCTABLE0_REPN0_MASK)
			>> OCTRLG_TCTABLE0_REPN0_OFFSET;
	*prempted_epn_idx =
		(octrlg_r32(tctable[tcont_idx]) & OCTRLG_TCTABLE0_PEPN0_MASK)
			>> OCTRLG_TCTABLE0_PEPN0_OFFSET;

	return 0;
}

/** Hardware Programming Details
    The following hardware functions must be configured:
    - tcont_idx: selects the table entry
    - alloc_id : Allocation ID of the T-CONT
    - valid    : true indicates that the Alloc Id has been assigned and is
		 valid.

    The T-CONT Table is addressed by the 12-bit alloc_id value, the
    tcont_idx is written as the data value to the selected table location,
    together with the valid indication being set (0b1).

    OCTRLG(OCTRLG), TCMAP[n].TCIX[n]: write a free T-CONT index value
				      (tcont_idx)
                                     into the location that is defined by
				     n = alloc_id.
    OCTRLG(OCTRLG), TCMAP[n].V[n]   : enable T-CONT index value
				     at the location that is defined by
				     n = alloc_id, by setting the related valid
				     bit.
*/
int octrlg_tcont_set(const uint32_t tcont_idx, const uint32_t alloc_id)
{
	octrlg_w32((tcont_idx & OCTRLG_TCMAP0_TCIX0_MASK) |
		   OCTRLG_TCMAP0_V0, tcmap[alloc_id]);
	return 0;
}

/** Hardware Programming Details
    The following hardware functions must be handled:

    The T-CONT mapping table is read at the location given by the Allocation ID.

    If the valid flag is set, the index value is returned with valid = true.
    If the valid is not set, the index value is returned with valid = false.

    The hardware table is located in OCTRLG (TCMAP),
    TCMAP[n].TCIX[n], n = Allocation ID
    TCMAP[n].V[n],    n = Allocation ID
*/
int octrlg_tcont_get(const uint32_t tcont_idx, uint32_t *alloc_id)
{
	uint32_t i, val;
	for (i = 0; i < TCMAP_LEN; i++) {
		val = octrlg_r32(tcmap[i]);
		if ((val & OCTRLG_TCMAP0_V0) == 0)
			continue;
		if (tcont_idx == (val & OCTRLG_TCMAP0_TCIX0_MASK)) {
			*alloc_id = i;
			return 0;
		}
	}
	*alloc_id = 0;
	return -1;
}

/** Hardware Programming Details
    The following hardware functions must be handled:

    The T-CONT mapping table is searched for an entry that matches the
    tcont_idx with the valid bit being set. If the given tcont_idx value is
    out of range (>= ONU_GPE_MAX_TCONT), an error code is returned
    (GPE_STATUS_VALUE_RANGE_ERR).

    If found, the table entry is set to "invalid".

    If no match is found within the table (the table address range (Allocation
    ID value range) is from ONU_GPE_MIN_ALLOCATION_ID to
    ONU_GPE_MAX_ALLOCATION_ID), the return status is set
    to GPE_STATUS_NOT_AVAILABLE.

    The hardware table to be searched and modified is located in
    OCTRLG, TCMAP[n].V[n] = 0b0 (n = Allocation ID).
*/
int octrlg_tcont_delete(const uint32_t tcont_idx)
{
	uint32_t i, val;

	for (i = 0; i < TCMAP_LEN; i++) {
		val = octrlg_r32(tcmap[i]);
		if ((val & OCTRLG_TCMAP0_V0) == 0)
			continue;
		if (tcont_idx == (val & OCTRLG_TCMAP0_TCIX0_MASK)) {
			octrlg_w32(0, tcmap[i]);
			return 0;
		}
	}

	return -1;
}

/** Direct deletion of an entry in TCMAP table by TCONT ID
 	 - alloc_id: TCONT ID is an index of an entry to be deleted
*/
int octrlg_tcont_alloc_id_delete(const uint32_t alloc_id)
{
	if (alloc_id >= TCMAP_LEN)
		return -1;
	octrlg_w32(0, tcmap[alloc_id]);
	return 0;
}

int octrlg_tcont_alloc_id_get(const uint32_t alloc_id, uint32_t *tcont_idx)
{
	uint32_t val;

	val = octrlg_r32(tcmap[alloc_id]);
	if ((val & OCTRLG_TCMAP0_V0) == 0)
		return -1;
	*tcont_idx = val & OCTRLG_TCMAP0_TCIX0_MASK;
	return 0;
}

/**
   Read hardware counter.
   - gpix: selects the GEM port index (0..ONU_GPE_MAX_GPIX - 1)
   - tx_frames: OCTRLG.TXPCNT(gem_port_index)
   - tx_bytes:  OCTRLG.TXBCNTH(gem_port_index)*2^32 +
					OCTRLG.TXBCNTL(gem_port_index)
  
  Hardware Programming Details
    These are the counters that are provided by the OCTRLG blocks of the OCTRLG
    module. The counters wrap around an need to be checked regularly.
*/
int octrlg_gem_counter_get(const uint32_t gpix,
			   struct gpe_cnt_octrlg_gem_val *counter)
{
	uint32_t l, h;

	if (gpix >= ONU_GPE_MAX_GPIX)
		return -1;

	counter->tx_frames = (uint64_t)octrlg_r32(txpcnt[gpix]);

	/* First the Low and then the High Part has to be read. No overflow
	   checks are needed since the HW stores the high part on the low
	   part read access*/
	l  = octrlg_r32(txbcntl[gpix]);
	h  = octrlg_r32(txbcnth[gpix]);
	counter->tx_bytes = ((uint64_t)h << 32) | l;

	return 0;
}

/**
   Read hardware counters from OCTRLG:
   - tx_gem_idle_frames_total: OCTRLG.TXTICNT
   - tx_gem_frames_total:     OCTRLG.TXTPCNT
   - tx_gem_bytes_total:      OCTRLG.TXCNT
   - tx_tcont_total:         OCTRLG.TXTTCNT

  Hardware Programming Details
    These are the counters that are provided by the OCTRLG block of the OCTRLG
    module. The counters wrap around an need to be checked regularly.
*/
int octrlg_counter_get(struct gpe_cnt_octrlg_val *counter)
{
	uint32_t l, h;

	if (octrlg_is_enabled()) {
		counter->tx_gem_idle_frames_total = octrlg_r32(txticnt);
		counter->tx_gem_frames_total = octrlg_r32(txtpcnt);
		counter->tx_gem_bytes_total = octrlg_r32(txtcnt);
		counter->tx_tcont_total = octrlg_r32(txttcnt);

		/* First the Low and then the High Part has to be read. No
		   overflow checks are needed since the HW stores the high part
		   on the low part read access*/
		l  = octrlg_r32(txtbcntl);
		h  = octrlg_r32(txtbcnth);
		counter->tx_gem_pdu_bytes_total = ((uint64_t)h << 32) | l;
	} else {
		memset(counter, 0x00, sizeof(struct gpe_cnt_octrlg_val));
	}

	return 0;
}

int octrlg_gem_port_set(const uint32_t gem_port_id,
			const uint32_t gem_port_index,
			const enum gpe_direction data_direction)
{
	if ((uint32_t)data_direction & (uint32_t)GPE_DIRECTION_UPSTREAM)
		octrlg_w32(gem_port_id, gpixtable[gem_port_index]);

	return 0;
}

int octrlg_gpix_get(const uint32_t gem_port_id, uint32_t *gem_port_index)
{
	uint32_t i;

	for (i = 0; i < GPIXTABLE_LEN; i++) {
		if (octrlg_r32(gpixtable[i]) == gem_port_id) {
			*gem_port_index = i;
			return 0;
		}
	}

	return -1;
}

int octrlg_gem_port_delete(const uint32_t gem_port_index)
{
	octrlg_w32(0x0, gpixtable[gem_port_index]);
	return 0;
}

/*
   OCTRLG.CFG0.IDLELEN         = 4
   OCTRLG.CFG1.GEMPLSIZE       = 0x0FFF
   OCTRLG.IDLEFRAME0.IFB0      = 0xB6
   OCTRLG.IDLEFRAME0.IFB1      = 0xAB
   OCTRLG.IDLEFRAME0.IFB2      = 0x31
   OCTRLG.IDLEFRAME0.IFB3      = 0xE0
   OCTRLG.IDLEFRAME1.IFB4      = 0x55
*/
STATIC int octrlg_basic_init(void)
{
	uint32_t cfg;

	octrlg_w32(0, ctrl);

	cfg = 0x0;
	/* set FIFO watermarks
	 * Set value of 4 - this results in the ability to serve single 
	   T-Cont Requests down to 16 bytes.
	 */
	set_val(cfg, 4, OCTRLG_CFG0_GTCFIFOTHRES_MASK,
		OCTRLG_CFG0_GTCFIFOTHRES_OFFSET);
	set_val(cfg, 4, OCTRLG_CFG0_IDLELEN_MASK, OCTRLG_CFG0_IDLELEN_OFFSET);
	octrlg_w32(cfg, cfg0);

	if (octrlg_config_set(48, 4095) != 0)
		return -1;

	octrlg_w32(OCTRLG_DCTRL_FQ_Q1, dctrl);

	/* Registers IDLEFRAME0...15 are left in reset state, which
	   is the standardized idle frame header followed by all zeroes.
	 */
	/* Make OCTRLG counter count per packet, not per GEM frame */
	octrlg_w32(OCTRLG_CFG1_GEMPLSIZE_MASK, cfg1);

	/* reset register-based counters */
	octrlg_w32(0, txtpcnt);
	octrlg_w32(0, txtbcnth);
	octrlg_w32(0, txtbcntl);
	octrlg_w32(0, txticnt);
	octrlg_w32(0, txtcnt);
	octrlg_w32(0, txttcnt);

	return 0;
}

/*
   tcmap[alloc_id] = tcont_index | valid bit
*/
STATIC void octrlg_tcont_map_init(void)
{
	/* All T-Cont IDs invalid */
	uint32_t i;

	for (i = 0; i < TCMAP_LEN; i++)
		octrlg_w32(0x0, tcmap[i]);
}

/*
   tctable[tcont_index] = epn
*/
STATIC void octrlg_tcont_table_init(void)
{
	uint32_t i;

	for (i = 0; i < ONU_GPE_MAX_TCONT; i++)
		octrlg_w32(0xFFFFFFFF, tctable[i]);

	octrlg_epn_set(OMCI_TCIX, 127, ONU_GPE_OMCI_EGRESS_PORT);
}

/*
   gpixtable[gpix] = gpid
*/
STATIC void octrlg_gpix_table_init(void)
{
	/* all GPIXs translate into GPID=0 */
	uint32_t i;

	for (i = 0; i < GPIXTABLE_LEN; i++)
		octrlg_w32(0x0, gpixtable[i]);
}

void octrlg_enable(const uint32_t act)
{
	/* enable/disable the module */
	octrlg_w32_mask(OCTRLG_CTRL_ACT_EN, act ? OCTRLG_CTRL_ACT_EN : 0, ctrl);
}

uint32_t octrlg_is_enabled(void)
{
	return (octrlg_r32(ctrl) & OCTRLG_CTRL_ACT_EN) ? true : false;
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrlg_gtc_fifo_threshold_set(const uint32_t value)
{
	octrlg_w32_mask(value, OCTRLG_CFG0_GTCFIFOTHRES_MASK, cfg0);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrlg_gtc_fifo_threshold_get(uint32_t *value)
{
	*value = (octrlg_r32(cfg0) & OCTRLG_CFG0_GTCFIFOTHRES_MASK)
			>> OCTRLG_CFG0_GTCFIFOTHRES_OFFSET;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
int octrlg_idle_len_set(const uint32_t value)
{
	uint32_t reg = 0, val;

	if (value == 0)
		return -1;

	val = (uint32_t)(value - 1);

	set_val(reg, val, OCTRLG_CFG0_IDLELEN_MASK, OCTRLG_CFG0_IDLELEN_OFFSET);

	octrlg_w32_mask(value, OCTRLG_CFG0_IDLELEN_MASK, cfg0);

	return 0;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

uint32_t octrlg_idle_len_get(void)
{
	uint32_t val;

	val = (octrlg_r32(cfg0) & OCTRLG_CFG0_IDLELEN_MASK)
			>> OCTRLG_CFG0_IDLELEN_OFFSET;
	return (uint32_t)(val + 1);
}

#ifdef ONU_LIBRARY
/** Reads total transmitted bytes counter and recalculate
    laser life time. 

    \remarks This function is used by optic library and
	is  called at least each 27 seconds
*/
void octrlg_laser_ageupdate ( uint32_t *seconds )
{
	uint32_t reg, diff;
	static uint32_t reg_old = 0;
	static uint32_t last = 0;

	reg = octrlg_r32 (txtcnt);
	if (reg > reg_old)
		diff = reg - reg_old;
	else
		diff = 0xFFFFFFFF - reg_old + reg + 1;
	/* not clear on read */
	reg_old = reg;
	/* counter = 19440 in 125 us */
	*seconds = diff / (0x9450C00);
	last += (diff % (0x9450C00));
	if (last > 0x9450C00) {
		(*seconds) ++;
		last -= 0x9450C00;
	}
}
#endif

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrlg_interrupt_mask_set(const uint32_t value)
{
	octrlg_w32(value, irnen);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrlg_interrupt_set(const uint32_t value)
{
	octrlg_w32(value, irnicr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrlg_interrupt_get(uint32_t *value)
{
	*value = octrlg_r32(irncr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#if defined(INCLUDE_DUMP)

void octrlg_dump(struct seq_file *s)
{
	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_GPONE_SET) == 0) {
		seq_printf(s, "octrlg not activated\n");
		return;
	}

#define dump_reg(reg) \
	seq_printf(s, "%-14s = 0x%08x\n", # reg, octrlg_r32(reg))

	dump_reg(ctrl);
	dump_reg(cfg0);
	dump_reg(cfg1);
	dump_reg(dctrl);
	dump_reg(txtpcnt);
	dump_reg(txttcnt);
	dump_reg(txticnt);
	dump_reg(txtcnt);
	dump_reg(txtbcntl);
	dump_reg(txtbcnth);
	dump_reg(txbcntl);
	dump_reg(tcreq);
	dump_reg(tcstate);
	dump_reg(irnicr);
#undef dump_reg
}

void octrlg_table_dump(struct seq_file *s)
{
	uint32_t i, k;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_GPONE_SET) == 0) {
		seq_printf(s, "octrlg not activated\n");
		return;
	}
	seq_printf(s, "tcmap table\n");
	for (i = 0; i < TCMAP_LEN;) {
		seq_printf(s, "%08x:  ", octrlg_adr_table(tcmap, i));
		for (k = 0; k < 16 && i < TCMAP_LEN; k++, i++)
			seq_printf(s, "%08x ", octrlg_r32(tcmap[i]));
		seq_printf(s, "\n");
	}

	seq_printf(s, "tcont table\n");
	for (i = 0; i < ONU_GPE_MAX_TCONT;) {
		seq_printf(s, "%08x:  ", octrlg_adr_table(tctable, i));
		for (k = 0; k < 16 && i < ONU_GPE_MAX_TCONT; k++, i++)
			seq_printf(s, "%08x ", octrlg_r32(tctable[i]));
		seq_printf(s, "\n");
	}

	seq_printf(s, "gpix table\n");
	for (i = 0; i < GPIXTABLE_LEN;) {
		seq_printf(s, "%08x:  ", octrlg_adr_table(gpixtable, i));
		for (k = 0; k < 16 && i < GPIXTABLE_LEN; k++, i++)
			seq_printf(s, "%08x ", octrlg_r32(gpixtable[i]));
		seq_printf(s, "\n");
	}

	seq_printf(s, "txpcnt table\n");
	for (i = 0; i < GPIXTABLE_LEN;) {
		seq_printf(s, "%08x:  ", octrlg_adr_table(txpcnt, i));
		for (k = 0; k < 16 && i < GPIXTABLE_LEN; k++, i++)
			seq_printf(s, "%08x ", octrlg_r32(txpcnt[i]));
		seq_printf(s, "\n");
	}

	seq_printf(s, "dptr table\n");
	for (i = 0; i < DPTRTABLE_LEN;) {
		seq_printf(s, "%08x:  ", octrlg_adr_table(dptr, i));
		for (k = 0; k < 16 && i < GPIXTABLE_LEN; k++, i++)
			seq_printf(s, "%08x ", octrlg_r32(dptr[i]));
		seq_printf(s, "\n");
	}

	seq_printf(s, "dcontext table\n");
	for (i = 0; i < DPTRTABLE_LEN;) {
		seq_printf(s, "%08x:  ", octrlg_adr_table(dcontext, i));
		for (k = 0; k < 16 && i < GPIXTABLE_LEN; k++, i++)
			seq_printf(s, "%08x ", octrlg_r32(dcontext[i]));
		seq_printf(s, "\n");
	}
}

#endif
