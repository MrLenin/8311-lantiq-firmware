/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_octrll.h"

static const uint32_t port_offset[4] = { 0, 64, 128, 192 };

void octrll_init(const uint32_t port_id)
{
	/*
	   - assigned EPN: 0, 1, 2, 3
	   - timeout enabled: 1s
	   - FSQM queue 1 selected (LSA freeing)
	   - all counters set = 0
	   - module OCTRLL activated
	 */
	static const uint32_t lan_act_en[4] = {SYS_GPE_ACT_LAN0_SET,
					       SYS_GPE_ACT_LAN1_SET,
					       SYS_GPE_ACT_LAN2_SET,
					       SYS_GPE_ACT_LAN3_SET};
	/*
	  Enable module clock, release reset. This is mandatory before
	  accessing module's registers.
	*/
	sys_gpe_hw_activate_or_reboot(lan_act_en[port_id]);

	/* timeout 1 s */
	octrll_w32_table(0x6d, toutcfg, port_offset[port_id]);
	/* Egress  port (0...71) but fixed 64...67   LAN (UNI) */
	octrll_w32_table(64 + port_id, cfg, port_offset[port_id]);

	/* register RAWCTRL: Cmd bit only, no init */

	/* registers RAWCFG0, 1: Cmd metadata, no init */

	octrll_w32_table(OCTRLL_DCTRL_FQ_Q1, dctrl, port_offset[port_id]);

	/* reset counter */
	octrll_w32_table(0, txbcntl, port_offset[port_id]);
	octrll_w32_table(0, txbcnth, port_offset[port_id]);
	octrll_w32_table(0, txpcnt, port_offset[port_id]);
	octrll_w32_table(0, txp64cnt, port_offset[port_id]);
	octrll_w32_table(0, txp65cnt, port_offset[port_id]);
	octrll_w32_table(0, txp128cnt, port_offset[port_id]);
	octrll_w32_table(0, txp256cnt, port_offset[port_id]);
	octrll_w32_table(0, txp512cnt, port_offset[port_id]);
	octrll_w32_table(0, txp1024cnt, port_offset[port_id]);
	octrll_w32_table(0, txp1519cnt, port_offset[port_id]);

	/* Registers DPTR and DCONTEXT: Read-only for debugging
	   purposes, no init */

	/* Activation should be the last step because setting of Egress
	   Port Number
	   Note: Modify only when CTRL.ACT is disabled!
	 */
	octrll_w32_table_mask(OCTRLL_CTRL_ACT_EN, OCTRLL_CTRL_TOUTEN_EN,
						ctrl, port_offset[port_id]);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
/*
   lan_port_timeout: configure in OCTRLL(n),OCTRLL(n).TOUTCFG.TOUTVALUE
                      (same value for n=0...3), 0xFFFF = 10 min)
   lan_port_timeout_en[4]: configure in OCTRLL(n),OCTRLL(n).CTRL.TOUTEN
*/
void octrll_port_timeout_set(const uint32_t lan_port_timeout,
			     const bool lan_port_timeout_en[4])
{
	uint32_t i;

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		octrll_w32_table(lan_port_timeout, toutcfg,
				 port_offset[i]);

		octrll_w32_table_mask(OCTRLL_CTRL_TOUTEN_EN,
				      lan_port_timeout_en[i] ?
						OCTRLL_CTRL_TOUTEN_EN : 0,
				      ctrl, port_offset[i]);
	}
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrll_port_timeout_get(uint32_t *lan_port_timeout,
			     bool lan_port_timeout_en[4])
{
	uint32_t i;

	*lan_port_timeout = octrll_r32_table(toutcfg, port_offset[0]);

	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++)
		lan_port_timeout_en[i] =
			(octrll_r32_table(ctrl, port_offset[0]) &
				OCTRLL_CTRL_TOUTEN_EN) ? true : false;

	for (; i < 4; i++)
		lan_port_timeout_en[i] = false;
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

/*
   OCTRLL[n].CFG.EPN = eport_idx, with n = nUNI_PortIndex

   Note: Modify only when CTRL.ACT is disabled! This is a static configuration.
*/
int octrll_port_set(const uint32_t uni_port_id, const uint32_t eport_idx)
{
	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	octrll_w32_table_mask(OCTRLL_CFG_EPN_MASK,
			      (eport_idx & OCTRLL_CFG_EPN_MASK), cfg,
			      port_offset[uni_port_id]);

	return 0;
}

int octrll_port_get(const uint32_t uni_port_id, uint32_t *eport_idx)
{
	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI) {
		*eport_idx = 0;
		return -1;
	}

	*eport_idx =
	    octrll_r32_table(cfg,
			     port_offset[uni_port_id]) & OCTRLL_CFG_EPN_MASK;

	return 0;
}

int octrll_write(const uint32_t uni_port_id, const uint32_t max_len,
		 const uint32_t hlsa, const uint32_t tlsa)
{
	uint32_t hdrl, bdyl, cfg;
	(void)tlsa;

	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	if (max_len > ONU_GPE_BUFFER_SEGMENT_SIZE) {
		hdrl = ONU_GPE_BUFFER_SEGMENT_SIZE;
		bdyl = max_len - ONU_GPE_BUFFER_SEGMENT_SIZE;
	} else {
		hdrl = max_len;
		bdyl = 0;
	}
	octrll_w32_table(hlsa, rawcfg0, port_offset[uni_port_id]);
	cfg = 0;
	cfg |= (hdrl << OCTRLL_RAWCFG1_HDRL_OFFSET) & OCTRLL_RAWCFG1_HDRL_MASK;
	cfg |= (bdyl << OCTRLL_RAWCFG1_BDYL_OFFSET) & OCTRLL_RAWCFG1_BDYL_MASK;
	octrll_w32_table(cfg, rawcfg1, port_offset[uni_port_id]);
	octrll_w32_table(OCTRLL_RAWCTRL_RAWTX, rawctrl,
			 port_offset[uni_port_id]);

	return 0;
}

uint32_t octrll_pcnt_get(const uint32_t uni_port_id)
{
	return octrll_r32_table(txpcnt, port_offset[uni_port_id]);
}

/**
   Read hardware counter.
*/
/** Hardware Programming Details
    These are the counters that are provided by the OCTRLL blocks of the OCTRLL
    module. The counters wrap around an need to be checked regularly.
*/
int octrll_counter_get(const uint32_t uni_port_id,
		       struct octrll_counter *counter)
{
	if (uni_port_id >= ONU_GPE_MAX_ETH_UNI)
		return -1;

	counter->tx_bytes =
		(uint64_t) octrll_r32_table(txbcntl, port_offset[uni_port_id]);
	counter->tx_bytes |=
		((uint64_t) (octrll_r32_table(txbcnth,
					      port_offset[uni_port_id])) << 32);
	counter->tx_frames =
			(uint64_t) octrll_r32_table(txpcnt,
						    port_offset[uni_port_id]);

	counter->tx64   = (uint64_t) octrll_r32_table(txp64cnt,
						      port_offset[uni_port_id]);
	counter->tx65   = (uint64_t) octrll_r32_table(txp65cnt,
						      port_offset[uni_port_id]);
	counter->tx128  = (uint64_t) octrll_r32_table(txp128cnt,
						      port_offset[uni_port_id]);
	counter->tx256  = (uint64_t) octrll_r32_table(txp256cnt,
						      port_offset[uni_port_id]);
	counter->tx512  = (uint64_t) octrll_r32_table(txp512cnt,
						      port_offset[uni_port_id]);
	counter->tx1024 = (uint64_t) octrll_r32_table(txp1024cnt,
						      port_offset[uni_port_id]);
	counter->tx1519 = (uint64_t) octrll_r32_table(txp1519cnt,
						      port_offset[uni_port_id]);

	return 0;
}

/*
    "SyncFifo full" (OCTRLLx.STATE.TXFIFOFULL=1) AND
    indicates that there are packets to send (OCTRLLx.STATE.EPFILLED=1)AND
    Tx Packet counter does not increase (OCTRLLx.TXPCNT).
*/
void octrll_state_get (const uint32_t uni_port_id,
		      uint32_t* state, uint32_t* txpcnt)
{
	*txpcnt = octrll_r32_table(txpcnt, port_offset[uni_port_id]);
	*state = octrll_r32_table(state, port_offset[uni_port_id]);
}

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrll_interrupt_mask_set(const uint32_t port_id, const uint32_t value)
{
	octrll_w32_table(value, irnen, port_offset[port_id]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrll_interrupt_set(const uint32_t port_id, const uint32_t value)
{
	octrll_w32_table(value, irnicr, port_offset[port_id]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

#ifdef INCLUDE_UNUSED_LL_FUNCTIONS
void octrll_interrupt_get(const uint32_t port_id, uint32_t *value)
{
	*value = octrll_r32_table(irncr, port_offset[port_id]);
}
#endif /* #ifdef INCLUDE_UNUSED_LL_FUNCTIONS*/

void octrll_enable(const uint32_t port_id, const bool value)
{
	octrll_w32_table_mask(	OCTRLL_CTRL_ACT_EN,
				value ? OCTRLL_CTRL_ACT_EN : 0, ctrl,
				port_offset[port_id]);
}

bool octrll_is_enabled(const uint32_t port_id)
{
	return (octrll_r32_table(ctrl,
				 port_offset[port_id]) & OCTRLL_CTRL_ACT_EN) ?
		true : false;
}

#if defined(INCLUDE_DUMP)

void octrll_dump(struct seq_file *s)
{
	uint32_t i;

	seq_printf(s, "  octrll,    ctrl,   dctrl, toutcfg,     "
			  "cfg,txp64cnt,"
			  "txp65cnt,txp128cnt,txp256cnt,txp512cnt,"
			  "txp1024cnt,txp1519cnt,  txpcnt,  irnicr,    "
			  "dptr,dcontext\n");
	for (i = 0; i < ONU_GPE_MAX_ETH_UNI; i++) {
		if (sys_gpe_hw_is_activated(SYS_GPE_ACT_LAN0_SET << i) == 0) {
			seq_printf(s, "octrll%d not activated\n", i);
			continue;
		}
		seq_printf(s, "%08x,", octrll_adr_table(ctrl, port_offset[i]));
		seq_printf(s, "%08x,", octrll_r32_table(ctrl, port_offset[i]));
		seq_printf(s, "%08x,", octrll_r32_table(dctrl, port_offset[i]));
		seq_printf(s, "%08x,",
			   octrll_r32_table(toutcfg, port_offset[i]));
		seq_printf(s, "%08x,", octrll_r32_table(cfg, port_offset[i]));
		seq_printf(s, "%08x,",
			   octrll_r32_table(txp64cnt, port_offset[i]));
		seq_printf(s, "%08x,",
			   octrll_r32_table(txp65cnt, port_offset[i]));
		seq_printf(s, " %08x,",
			   octrll_r32_table(txp128cnt, port_offset[i]));
		seq_printf(s, " %08x,",
			   octrll_r32_table(txp256cnt, port_offset[i]));
		seq_printf(s, " %08x,",
			   octrll_r32_table(txp512cnt, port_offset[i]));
		seq_printf(s, "  %08x,",
			   octrll_r32_table(txp1024cnt, port_offset[i]));
		seq_printf(s, "  %08x,",
			   octrll_r32_table(txp1519cnt, port_offset[i]));
		seq_printf(s, "%08x,",
			   octrll_r32_table(txpcnt, port_offset[i]));
		seq_printf(s, "%08x,",
			   octrll_r32_table(irnicr, port_offset[i]));
		seq_printf(s, "%08x,",
			   octrll_r32_table(dptr, port_offset[i]));
		seq_printf(s, "%08x\n",
			   octrll_r32_table(dcontext, port_offset[i]));
	}
}

#endif
