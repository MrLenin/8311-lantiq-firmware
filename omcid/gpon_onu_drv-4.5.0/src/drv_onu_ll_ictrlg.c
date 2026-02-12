/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_ictrlg.h"
//#include "drv_onu_ll_octrlg.h"
#include "drv_onu_resource_gpe.h"
#include "drv_onu_types.h"

static void ictrlg_basic_init(void);
static void ictrlg_gpt_init(void);

static uint16_t free_gpix[ONU_GPE_MAX_GPIX];

void ictrlg_init(void)
{
	uint32_t i;

	/*
	  Enable module clock, release reset. This is mandatory before
	  accessing module's registers.
	*/
	sys_gpe_hw_activate_or_reboot(SYS_GPE_ACT_GPONI_SET);
	/* initializes all registers and tables */
	ictrlg_basic_init();

	for (i = 0; i < ONU_GPE_MAX_GPIX; i++) {
		free_gpix[i] = 0;
		ictrlg_w32(0, gpix_cfg[i]);
		/* Received and accepted frames counter = 0 */
		ictrlg_w32(0, gpix_rxfcnt[i]);
		/* Received good bytes counter (upper half) = 0 */
		ictrlg_w32(0, gpix_rxbcnth[i]);
		/* Received good bytes counter (lower half) = 0 */
		ictrlg_w32(0, gpix_rxbcntl[i]);
	}
	/* reserved for OMCI */
	free_gpix[OMCI_GPIX] = 3;

	ictrlg_gpt_init();

	/* activate the module after all static settings */
	/*ictrlg_enable(true);*/
}

int ictrlg_gpix_config_set(const uint32_t gpix, const uint32_t iqn,
		    const enum gpe_pdu_type pdu_type)
{
	uint32_t cfg;
	static const uint8_t map[] = { 0, 0, 0, 0, 0, 0, 1, 2 };

	if (iqn < 5 || iqn > 7)
		return -1;

	cfg = 0x0;
	/* IQN = 5 for all GPIX, set the two bits = 01 (MSB always 1) */
	set_val(cfg, map[iqn], ICTRLG_GPIX_CFG_IQN_MASK,
		ICTRLG_GPIX_CFG_IQN_OFFSET);
	/* PDU Type = Ethernet for all GPIX */
	set_val(cfg, pdu_type, ICTRLG_GPIX_CFG_PDUT_MASK,
		ICTRLG_GPIX_CFG_PDUT_OFFSET);
	ictrlg_w32(cfg, gpix_cfg[gpix]);

	return 0;
}

void ictrlg_gpix_config_get(const uint32_t gpix, uint8_t *iqn,
		     enum gpe_pdu_type *pdu_type)
{
	uint32_t cfg = ictrlg_r32(gpix_cfg[gpix]);
	static const uint8_t map[] = { 5, 6, 7, 7 };

	*iqn =
	    map[(cfg & ICTRLG_GPIX_CFG_IQN_MASK) >> ICTRLG_GPIX_CFG_IQN_OFFSET];
	*pdu_type =
	    (enum gpe_pdu_type) (cfg & ICTRLG_GPIX_CFG_PDUT_MASK) >>
	    ICTRLG_GPIX_CFG_PDUT_OFFSET;
}

/*
   pdu_sz_max[8]: configure in ICTRLG, ICTRLG.MAXSIZE[n], n = 0...7
*/
void ictrlg_pdu_size_set(const uint32_t pdu_sz_max[8])
{
	int i;

	for (i = 0; i < 8; i++)
		ictrlg_w32(pdu_sz_max[i] & ICTRLG_MAXSIZE0_SIZE_MASK,
				 maxsize[i]);
}

void ictrlg_pdu_size_get(uint32_t pdu_sz_max[8])
{
	int i;

	for (i = 0; i < 8; i++)
		pdu_sz_max[i] = ictrlg_r32(maxsize[i]) &
						ICTRLG_MAXSIZE0_SIZE_MASK;
}

/** Hardware Programming Details
    These are the counters that are provided by the ICTRLG block of the ICTRLG
    module. The counters wrap around an need to be checked regularly.

    gpix: defines the GEM Port Index (0..ONU_GPE_MAX_GPIX - 1)

    nCntDrop: GTC.GEM_HERR_2 + ICTRLG.UNDSIZE + ICGTRLG.OVRSIZE +
              ICTRLG.FCSERR + ICTRLG.REASSERR
              This is a value that is not related to a specific GEM Port ID and
              delivered always, regardless of the selected gem_port_id.
*/
int ictrlg_gem_counter_get(const uint32_t gpix,
			   struct gpe_cnt_ictrlg_gem_val *counter)
{
	uint32_t l, h;

	if (gpix >= ONU_GPE_MAX_GPIX)
		return -1;

	counter->rx_frames = (uint64_t)ictrlg_r32(gpix_rxfcnt[gpix]);

	/* First the Low and then the High Part has to be read. No overflow
	   checks are needed since the HW stores the high part on the low
	   part read access*/
	l  = ictrlg_r32(gpix_rxbcntl[gpix]);
	h  = ictrlg_r32(gpix_rxbcnth[gpix]);
	counter->rx_bytes = ((uint64_t)h << 32) | l;

	return 0;
}

int ictrlg_counter_get(struct gpe_cnt_ictrlg_val *counter)
{
	if (ictrlg_is_enabled()) {
		counter->fcserror = ictrlg_r32(fcserr);
		counter->undersize_error = ictrlg_r32(undsize);
		counter->rx_gem_frames_total = ictrlg_r32(rxtpcnt);
		counter->rx_oversized_frames = ictrlg_r32(ovrsize);
		counter->omci_drop = ictrlg_r32(badomci);
		counter->drop = gtc_r32(downstr_gem_herr_2) +
				counter->rx_oversized_frames +
				ictrlg_r32(fcserr) + ictrlg_r32(reasserr);
	} else {
		memset(counter, 0x00, sizeof(struct gpe_cnt_ictrlg_val));
	}

	return 0;
}

int ictrlg_gpix_get(const uint32_t gem_port_id, uint16_t *gem_port_index)
{
	*gem_port_index = ictrlg_r32(gpt[gem_port_id]);
	if (*gem_port_index & ICTRLG_GPT_VALID) {
		*gem_port_index &= ICTRLG_GPT_GPIX_MASK;
		if(*gem_port_index >= ONU_GPE_MAX_GPIX)
			return -2;
		return 0;
	}
	return -1;
}

/** Hardware Programming Details
    For a given gem_port_id, the following information is returned:
    The followig data is returned:
    - gem_port_index        : read from SDMA/ICTRLG.GPT
    - nGEM_PortIngressQueue : read from SDMA/ICTRLG.GPIX_CFG.IQN
    - eGEM_PortEnable       : read from SDMA/ICTRLG.GPT
    - tcont_idx          :
    - data_direction - downstream GTC, upstream GPE

    If eGEM_PortEnable == false, gem_port_index and nGEM_PortIngressQueue are
    invalid and shall be ignored (set to 0).
*/
int ictrlg_gem_port_get(const uint32_t gem_port_id,
			uint32_t *gem_port_enable, uint32_t *gem_port_is_omci,
			uint32_t *gem_port_is_mc, uint32_t *gem_port_index,
			enum gpe_direction *data_direction)
{
	enum gpe_pdu_type pdu_type;
	uint8_t iqn;
	uint16_t gpix;

	*gem_port_index = 0;
	*gem_port_is_mc = false;
	*gem_port_is_omci = false;
	*data_direction = 0;
	*gem_port_enable = false;

	if (ictrlg_gpix_get(gem_port_id, &gpix) != 0)
		return -1;

	*gem_port_enable = true;
	*gem_port_index = gpix;
	*data_direction = free_gpix[gpix];

	ictrlg_gpix_config_get(gpix, &iqn, &pdu_type);
	if (pdu_type == GPE_PDU_TYPE_IP || pdu_type == GPE_PDU_TYPE_OMCI) {
		*gem_port_is_omci = true;
	} else {
		if (iqn == ONU_GPE_INGRESS_QUEUE_GEM_MC)
			*gem_port_is_mc = true;
	}

	return 0;
}

int ictrlg_gem_port_set(const uint32_t gem_port_id,
			const uint32_t gem_port_is_omci,
			const uint32_t gem_port_is_mc,
			const uint32_t gem_port_index,
			const enum gpe_direction data_direction)
{
	free_gpix[gem_port_index] = (uint16_t)data_direction;

	if (((uint8_t)data_direction &
				(uint8_t)GPE_DIRECTION_DOWNSTREAM) == 0)
		/* the entry in gpt is essential for delete & get operation */
		return -1;

	if ((uint8_t)data_direction & (uint8_t)GPE_DIRECTION_DOWNSTREAM) {
		if (gem_port_is_omci == true) {
			if(is_falcon_chip_a2x()) {
				ictrlg_gpix_config_set( gem_port_index,
						ONU_GPE_INGRESS_QUEUE_OMCI,
						GPE_PDU_TYPE_OMCI);
			} else {
				ictrlg_gpix_config_set( gem_port_index,
						ONU_GPE_INGRESS_QUEUE_OMCI,
						GPE_PDU_TYPE_IP);
			}
		} else {
			ictrlg_gpix_config_set(gem_port_index,
				gem_port_is_mc == true ?
					ONU_GPE_INGRESS_QUEUE_GEM_MC :
					ONU_GPE_INGRESS_QUEUE_GEM_UC,
				GPE_PDU_TYPE_ETH);
		}

		/* the entry in gpt is essential for
		   delete & get operation */
		ictrlg_w32(gem_port_index | ICTRLG_GPT_VALID,
				 gpt[gem_port_id]);
	}

	return 0;
}

/*
   Mark the GEM Port ID invalid in the GEM Port table (ICTRLG.GPT.VALID)
   Set the GEM Port ID to 0 in the GPIX table (OCTRLG.GPIXTABLE[n].GPID[n])
*/
int ictrlg_gem_port_delete(const uint32_t gem_port_id)
{
	uint16_t gpix = 0;

	if (ictrlg_gpix_get(gem_port_id, &gpix) != 0)
		return -1;

	if (gpix >= ONU_GPE_MAX_GPIX)
		return -1;

	ictrlg_w32_mask(ICTRLG_GPT_VALID, 0, gpt[gem_port_id]);
	/** \todo the OCTRLG should be deleted at correct place not here */
	free_gpix[gpix] = 0;

	return 0;
}

/*
   ICTRLG.MAXSIZE0             = ONU_GPE_MAX_ETHERNET_FRAME_LENGTH
   ICTRLG.MAXSIZE1             = ONU_GPE_MAX_IP_FRAME_LENGTH
   ICTRLG.MAXSIZE2             = ONU_GPE_MAX_MPLS_FRAME_LENGTH
   ICTRLG.MAXSIZE3             = 1984
   ICTRLG.MAXSIZE4             = 0 (reserved)
   ICTRLG.MAXSIZE5             = 0 (reserved)
   ICTRLG.MAXSIZE6             = 0 (reserved)
   ICTRLG.MAXSIZE7             = 0 (reserved)
   ICTRLG.GPT.VALID[0..4096]   = 0b0
   ICTRLG.GPT.GPIX[0..4096]    = 0x00
   ICTRLG.TIMEOUT.LIMIT        = ONU_GPE_DEFAULT_REASSEMBLY_TIMEOUT_VALUE
*/
STATIC void ictrlg_basic_init(void)
{
	uint32_t cfg;

	const uint32_t pdu_size_max[8] = { ONU_GPE_MAX_ETHERNET_FRAME_LENGTH,
		ONU_GPE_MAX_IP_FRAME_LENGTH,
		ONU_GPE_MAX_MPLS_FRAME_LENGTH,
		1984,
		0, 0, 0, 0
	};

	/*
	   - RAW mode disabled
	   - CRC enabled
	   - Soft reset disabled
	   - ICTRLG block disabled
	 */
	ictrlg_w32(ICTRLG_CTRL_CRC_EN, ctrl);

	/*
	   - Queue for Alloc commands = 1
	   - Queue for Free commands = 1
	 */
	cfg = ICTRLG_DMAW_CFG_ALLOCQ | ICTRLG_DMAW_CFG_FREEQ;
	/* 32 wait cycles */
	set_val(cfg, 0x20, ICTRLG_DMAW_CFG_LSARLMT_MASK,
		ICTRLG_DMAW_CFG_LSARLMT_OFFSET);
	ictrlg_w32(cfg, dmaw_cfg);

	/* Reassembly Timeout = 10ms */
	cfg = 0;
	set_val(cfg, 0x2F9B80, ICTRLG_TIMEOUT_LIMIT_MASK,
		ICTRLG_TIMEOUT_LIMIT_OFFSET);
	ictrlg_w32(cfg, timeout);

	ictrlg_pdu_size_set(&pdu_size_max[0]);

	/* Upper Half of Received Bytes Counter = 0 */
	ictrlg_w32(0, rxbcnth);

	/* Lower Half of Received Bytes Counter = 0 */
	ictrlg_w32(0, rxbcntl);

	/* Number of oversized PDUs = 0 */
	ictrlg_w32(0, ovrsize);

	/* Number of errors from DMAW = 0 */
	ictrlg_w32(0, dmawerr);

	/* Number of discarded OMCI messages = 0 */
	ictrlg_w32(0, badomci);

	/* Number of FCS errors = 0 */
	ictrlg_w32(0, fcserr);

	/* Number of reassembly errors = 0 */
	ictrlg_w32(0, reasserr);

	/* Disable all interrupts */
	ictrlg_w32(0, irncr);
	ictrlg_w32(0, irnicr);
	ictrlg_w32(0, irnen);
}

STATIC void ictrlg_gpt_init(void)
{
	uint32_t i;

	for (i = 0; i < GPT_LEN; i++)
		ictrlg_w32(0, gpt[i]);
}

uint16_t ictrlg_gpix_free_get(void)
{
	uint32_t i;

	for (i = 0; i < ONU_GPE_MAX_GPIX; i++)
		if (free_gpix[i] == 0)
			return i;

	return ONU_GPE_MAX_GPIX;
}

void ictrlg_enable(const uint32_t act)
{
	/* enable/disable the module */
	ictrlg_w32_mask(ICTRLG_CTRL_ACT_EN, act ? ICTRLG_CTRL_ACT_EN : 0, ctrl);
}

uint32_t ictrlg_is_enabled(void)
{
	return (ictrlg_r32(ctrl) & ICTRLG_CTRL_ACT_EN) ? true : false;
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrlg_debug_mode_set(const uint32_t act)
{
	ictrlg_w32_mask(act, ICTRLG_CTRL_DBG_EN, ctrl);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrlg_debug_mode_get(uint32_t *act)
{
	*act = (ictrlg_r32(ctrl) & ICTRLG_CTRL_DBG_EN) ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrlg_crc_check_set(const uint32_t act)
{
	ictrlg_w32_mask(act, ICTRLG_CTRL_CRC_EN, ctrl);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrlg_crc_check_get(uint32_t *act)
{
	*act = (ictrlg_r32(ctrl) & ICTRLG_CTRL_CRC_EN) ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrlg_interrupt_mask_set(const uint32_t mask)
{
	ictrlg_w32(mask, irnen);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrlg_interrupt_set(const uint32_t val)
{
	ictrlg_w32(val, irnicr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrlg_interrupt_get(uint32_t *val)
{
	*val = ictrlg_r32(irncr);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#if defined(INCLUDE_DUMP)

void ictrlg_dump(struct seq_file *s)
{
	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_GPONI_SET) == 0) {
		seq_printf(s, "ictrlg not activated\n");
		return;
	}

#define dump_reg(reg) \
	seq_printf(s, "%-14s = 0x%08x\n", # reg, ictrlg_r32(reg))

	dump_reg(ctrl);
	dump_reg(dmaw_cfg);
	dump_reg(timeout);
	dump_reg(ovrsize);
	dump_reg(dmawerr);
	dump_reg(badomci);
	dump_reg(fcserr);
	dump_reg(reasserr);
	dump_reg(undsize);
	dump_reg(pdc);
	dump_reg(rxtpcnt);
	dump_reg(irnicr);
#undef dump_reg
}

void ictrlg_table_dump(struct seq_file *s)
{
	uint32_t i, k;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_GPONI_SET) == 0) {
		seq_printf(s, "ictrlg not activated\n");
		return;
	}

	seq_printf(s, "max_size table\n");
	for (i = 0; i < 8;) {
		seq_printf(s, "%08x:  ", (unsigned int)&ictrlg->maxsize[i]);
		for (k = 0; k < 16 && i < 8; k++, i++)
			seq_printf(s, "%08x ", ictrlg_r32(maxsize[i]));
		seq_printf(s, "\n");
	}

	seq_printf(s, "gpt table\n");
	for (i = 0; i < GPT_LEN;) {
		seq_printf(s, "%08x:  ", (unsigned int)&ictrlg->gpt[i]);
		for (k = 0; k < 16 && i < GPT_LEN; k++, i++)
			seq_printf(s, "%08x ", ictrlg_r32(gpt[i]));
		seq_printf(s, "\n");
	}

	seq_printf(s, "gpix_cfg table\n");
	for (i = 0; i < ONU_GPE_MAX_GPIX;) {
		seq_printf(s, "%08x:  ", (unsigned int)&ictrlg->gpix_cfg[i]);
		for (k = 0; k < 16 && i < ONU_GPE_MAX_GPIX; k++, i++)
			seq_printf(s, "%08x ", ictrlg_r32(gpix_cfg[i]));

		seq_printf(s, "\n");
	}

	seq_printf(s, "gpix_rxfcnt table\n");
	for (i = 0; i < ONU_GPE_MAX_GPIX;) {
		seq_printf(s, "%08x:  ", (unsigned int)&ictrlg->gpix_rxfcnt[i]);
		for (k = 0; k < 16 && i < ONU_GPE_MAX_GPIX; k++, i++)
			seq_printf(s, "%08x ", ictrlg_r32(gpix_rxfcnt[i]));

		seq_printf(s, "\n");
	}

	seq_printf(s, "free_gpix table\n");
	for (i = 0; i < ONU_GPE_MAX_GPIX;) {
		for (k = 0; k < 16 && i < ONU_GPE_MAX_GPIX; k++, i++)
			seq_printf(s, "%01x ", free_gpix[i]);

		seq_printf(s, "\n");
	}
}

#endif
