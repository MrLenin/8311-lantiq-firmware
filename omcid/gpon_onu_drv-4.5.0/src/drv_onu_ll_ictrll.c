/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_ictrll.h"

STATIC void ictrll_basic_init(const uint32_t uni_port_id);
static const uint32_t port_offset[4] = { 0, 128, 256, 384 };

void ictrll_init(const uint16_t port_id)
{
	static const uint32_t lan_act_en[4] = {SYS_GPE_ACT_LAN0_SET,
					       SYS_GPE_ACT_LAN1_SET,
					       SYS_GPE_ACT_LAN2_SET,
					       SYS_GPE_ACT_LAN3_SET};
	/*
	  Enable module clock, release reset. This is mandatory before
	  accessing module's registers.
	*/
	sys_gpe_hw_activate_or_reboot(lan_act_en[port_id]);

	/* initialize all registers */
	ictrll_basic_init(port_id);
}

uint32_t ictrll_pcnt_get(const uint8_t uni_port_id)
{
	return ictrll_r32_table(rxpcnt, port_offset[uni_port_id]);
}

uint32_t ictrll_pdc_get(const uint8_t uni_port_id)
{
	return ictrll_r32_table(pdc, port_offset[uni_port_id]);
}

/**
   Read hardware counter.
*/
/** Hardware Programming Details
    These are the counters that are provided by the ICTRL blocks of the SDMA
    modules. The counters wrap around an need to be checked regularly.
*/
int ictrll_counter_get(const uint8_t uni_port_id,
		       struct ictrll_counter *counter)
{
	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	counter->rx_bytes =
			 (uint64_t)ictrll_r32_table(rxbcntl,
						    port_offset[uni_port_id]);
	counter->rx_bytes |=
			(((uint64_t)ictrll_r32_table(rxbcnth,
					port_offset[uni_port_id])) << 32);

	counter->rx_oversized_frames =
			  (uint64_t)ictrll_r32_table(ovrsize,
						     port_offset[uni_port_id]);
	counter->rx_frames =
			  (uint64_t)ictrll_r32_table(rxpcnt,
						     port_offset[uni_port_id]);
	counter->rx64   = (uint64_t)ictrll_r32_table(rxp64cnt,
						     port_offset[uni_port_id]);
	counter->rx65   = (uint64_t)ictrll_r32_table(rxp65cnt,
						     port_offset[uni_port_id]);
	counter->rx128  = (uint64_t)ictrll_r32_table(rxp128cnt,
						     port_offset[uni_port_id]);
	counter->rx256  = (uint64_t)ictrll_r32_table(rxp256cnt,
						     port_offset[uni_port_id]);
	counter->rx512  = (uint64_t)ictrll_r32_table(rxp512cnt,
						     port_offset[uni_port_id]);
	counter->rx1024 = (uint64_t)ictrll_r32_table(rxp1024cnt,
						     port_offset[uni_port_id]);
	counter->rx1519 = (uint64_t)ictrll_r32_table(rxp1519cnt,
						     port_offset[uni_port_id]);
	counter->rx_undersized_frames =
			  (uint64_t)ictrll_r32_table(undsize,
						     port_offset[uni_port_id]);

	counter->dma_write_error =
			  (uint64_t)ictrll_r32_table(dmawerr,
						     port_offset[uni_port_id]);
	counter->mac_error =
			  (uint64_t)ictrll_r32_table(macerr,
						     port_offset[uni_port_id]);

	return 0;
}

int ictrll_macerr_get(const uint8_t uni_port_id,
		       uint32_t *mac_error)
{
	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	*mac_error = ictrll_r32_table(macerr, port_offset[uni_port_id]);

	return 0;
}

/*
   ICTRL0.MAXSIZE0 = ONU_GPE_MAX_ETHERNET_FRAME_LENGTH
   ICTRL1.MAXSIZE0 = ONU_GPE_MAX_ETHERNET_FRAME_LENGTH
   ICTRL2.MAXSIZE0 = ONU_GPE_MAX_ETHERNET_FRAME_LENGTH
   ICTRL3.MAXSIZE0 = ONU_GPE_MAX_ETHERNET_FRAME_LENGTH
*/
STATIC void ictrll_basic_init(const uint32_t i)
{
	uint32_t cfg;

	/*
	   Register CTRL
	   - RAW mode disabled
	   - Broadcast Filter for Raw Mode disabled
	   - Debug Mode  disabled
	   - ICTRL disabled
	 */
	ictrll_w32_table(0, ctrl, port_offset[i]);

	/*
	   Register DMAW_CFG
	   - Queue for Alloc commands = 1
	   - Queue for Free commands = 1
	   - 32 wait cycles
	 */
	cfg = ICTRLL_DMAW_CFG_ALLOCQ | ICTRLL_DMAW_CFG_FREEQ;
	set_val(cfg, 0x20, ICTRLL_DMAW_CFG_LSARLMT_MASK,
		ICTRLL_DMAW_CFG_LSARLMT_OFFSET);
	ictrll_w32_table(cfg, dmaw_cfg, port_offset[i]);

	/* Ethernet DA (high adr) = 0 */
	ictrll_w32_table(0, rawda1, port_offset[i]);
	/* Ethernet DA (low adr) = 0 */
	ictrll_w32_table(0, rawda0, port_offset[i]);

	/* max size for Ethernet: ONU_GPE_MAX_ETHERNET_FRAME_LENGTH */
	ictrll_w32_table(ONU_GPE_MAX_ETHERNET_FRAME_LENGTH, maxsize,
			 port_offset[i]);

	/* Initialize all counters = 0 */
	ictrll_w32_table(0, rxbcnth, port_offset[i]);
	ictrll_w32_table(0, rxbcntl, port_offset[i]);
	ictrll_w32_table(0, ovrsize, port_offset[i]);
	ictrll_w32_table(0, dmawerr, port_offset[i]);
	ictrll_w32_table(0, macerr, port_offset[i]);
	ictrll_w32_table(0, rxpcnt, port_offset[i]);
	ictrll_w32_table(0, rxp64cnt, port_offset[i]);
	ictrll_w32_table(0, rxp65cnt, port_offset[i]);
	ictrll_w32_table(0, rxp128cnt, port_offset[i]);
	ictrll_w32_table(0, rxp256cnt, port_offset[i]);
	ictrll_w32_table(0, rxp512cnt, port_offset[i]);
	ictrll_w32_table(0, rxp1024cnt, port_offset[i]);
	ictrll_w32_table(0, rxp1519cnt, port_offset[i]);
	ictrll_w32_table(0, undsize, port_offset[i]);

	/* Disable all interrupts */
	ictrll_w32_table(0, irncr, port_offset[i]);
	ictrll_w32_table(0, irnicr, port_offset[i]);
	ictrll_w32_table(0, irnen, port_offset[i]);
}

void ictrll_enable(const uint16_t port_id, const bool value)
{
	ictrll_w32_table_mask(	ICTRLL_CTRL_ACT_EN,
				value ? ICTRLL_CTRL_ACT_EN : 0,
				ctrl, port_offset[port_id]);
}

bool ictrll_is_enabled(const uint16_t port_id)
{
	return (ictrll_r32_table(ctrl,
				 port_offset[port_id]) & ICTRLL_CTRL_ACT_EN) ?
		true : false;
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrll_debug_mode_set(const uint16_t port_id, const bool value)
{
	ictrll_w32_table_mask(ICTRLL_CTRL_DBG_EN,
			      value ? ICTRLL_CTRL_DBG_EN : 0, ctrl,
			      port_offset[port_id]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrll_debug_mode_get(const uint16_t port_id, bool *value)
{
	*value = (ictrll_r32_table(ctrl, port_offset[port_id]) &
				ICTRLL_CTRL_DBG_EN) ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrll_bc_mode_set(const uint16_t port_id, const bool value)
{
	ictrll_w32_table_mask(ICTRLL_CTRL_BC_EN, 
			      value ? ICTRLL_CTRL_BC_EN : 0, ctrl,
			      port_offset[port_id]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrll_bc_mode_get(const uint16_t port_id, bool *value)
{
	*value = (ictrll_r32_table(ctrl, port_offset[port_id]) &
				ICTRLL_CTRL_BC_EN) ? true : false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void ictrll_max_size_pdu_type0_set(const uint16_t port_id, const uint16_t value)
{
	ictrll_w32_table(value, maxsize, port_offset[port_id]);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrll_max_size_pdu_type0_get(const uint16_t port_id, uint16_t *value)
{
	*value =
	    (ictrll_r32_table(maxsize, port_offset[port_id]) &
	     ICTRLL_MAXSIZE0_SIZE_MASK) >> ICTRLL_MAXSIZE0_SIZE_OFFSET;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrll_interrupt_mask_set(const uint16_t port_id, const uint32_t value)
{
	ictrll_w32_table(value, irnen, port_offset[port_id]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrll_interrupt_set(const uint16_t port_id, const uint32_t value)
{
	ictrll_w32_table(value, irnicr, port_offset[port_id]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void ictrll_interrupt_get(const uint16_t port_id, uint32_t *value)
{
	*value = ictrll_r32_table(irncr, port_offset[port_id]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#if defined(INCLUDE_DUMP)

void ictrll_dump(struct seq_file *s)
{
	uint32_t i;

	seq_printf(s, "  ictrll,    ctrl,dmaw_cfg,  rxpcnt, maxsize, "
			  "ovrsize, undsize, dmawerr,  macerr,     pdc,  "
			  "rxpcnt,  irnicr\n");
	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		if (sys_gpe_hw_is_activated(SYS_GPE_ACT_LAN0_SET << i) == 0) {
			seq_printf(s, "ictrll%d not activated\n", i);
			continue;
		}
		seq_printf(s, "%08x,", ictrll_adr_table(ctrl, port_offset[i]));
		seq_printf(s, "%08x,", ictrll_r32_table(ctrl, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(dmaw_cfg, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(rxpcnt, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(maxsize, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(ovrsize, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(undsize, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(dmawerr, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(macerr, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(pdc, port_offset[i]));
		seq_printf(s, "%08x,",
			   ictrll_r32_table(rxpcnt, port_offset[i]));
		seq_printf(s, "%08x\n",
			   ictrll_r32_table(irnicr, port_offset[i]));
	}
}

#endif
