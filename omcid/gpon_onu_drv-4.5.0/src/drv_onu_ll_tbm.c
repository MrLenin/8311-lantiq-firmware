/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_resource_gpe.h"
#include "drv_onu_ll_tbm.h"

STATIC void tbm_mrm_conversion(uint32_t tsprescale, uint32_t byterate,
			       struct tbm_tbmt_entry * tbmt);
STATIC void tbm_rate_conversion(struct tbm_tbmt_entry * tbmt,
			        uint32_t * byterate);

#define TBMCLOCK_HZ 625000000
/* A21 The coreclock fractional part for TS */
#define TS_SCALING 4
#define TBM_MRE_INIT 22
#define TBM_MRM_MAX 4095
#define TBM_MRE_MAX 31
/** set the default crawler period on A22 */
#define TBM_CPERIOD 12

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_TBM_INTERNAL GPE - TBM Interface
   @{
*/

/** Convert byterate into MRM and MRE parameter

	\param tsprescale must be aligned as follows:
	- if tbmt.tss = 0 tsprescale =  IQM.CTRL.TSPRESCALE,
	which is a new basic init parameter in the IQM CTRL register.
	- if tbmt.tss = 1 tsprescale =  TBM.CTRL.TSPRESCALE,
	which is a new basic init parameter in the TBM CTRL register.
	\param byterate byterate in [byte / s] as 
	defined in the OMCI standards. byterate ranges from 
	1000 till 125000000 which must be checked by the calling
	function
	\param tbmt returned \ref tbm_tbmt_entry
*/
STATIC void tbm_mrm_conversion(uint32_t tsprescale,
			       uint32_t byterate, struct tbm_tbmt_entry *tbmt)
{
	uint32_t mre_temp;
	uint64_t mrm_temp;


	mre_temp = 26;
	mrm_temp = (uint64_t)byterate << (tsprescale + TS_SCALING + mre_temp);

#ifdef __KERNEL__
        do_div(mrm_temp, TBMCLOCK_HZ);
#else
        mrm_temp = mrm_temp / TBMCLOCK_HZ;
#endif

/* scaling down mrm_temp to fit into 12-bit MRM field */
	while (mrm_temp >= 4096) {
		mrm_temp = mrm_temp>>1;
		mre_temp = mre_temp-1;
	}
	
	tbmt->mrm = (uint16_t)mrm_temp;
	tbmt->mre = (uint16_t)mre_temp;
}

STATIC void tbm_rate_conversion(struct tbm_tbmt_entry *tbmt, uint32_t *byterate)
{
        uint64_t rate_temp;

/* replace hard value of 5 with tsprescale parameter, similar to function tbm_mrm_conversion */

        rate_temp = ((uint64_t)tbmt->mrm * TBMCLOCK_HZ) >> (tbmt->mre + TS_SCALING + 5);
        *byterate = (uint32_t)rate_temp;
}


void tbm_enable(bool act)
{
	tbm_w32_mask(TBM_CTRL_ACT_EN, act ? TBM_CTRL_ACT_EN : 0, ctrl);
}

bool tbm_is_enabled(void)
{
	return tbm_r32(ctrl) & TBM_CTRL_ACT_EN ? true : false;
}

void tbm_init(void)
{
	uint32_t data;
	struct tbm_tbmt_entry tbmt;
	uint32_t tbid;

	/* No act and clken registers available for this module in SYS_GPE.*/

	/* todo add TBMT.TSE field initialization. Default = 4 */

	if (is_falcon_chip_a1x()) {
		tbm_w32(TBM_CTRL_A1X_INITSTART, ctrl);
		data = tbm_r32(ctrl); /* \todo add timeout value */
		do {
			data = tbm_r32(ctrl);
		} while ((data & TBM_CTRL_A1X_INITDONE) != TBM_CTRL_A1X_INITDONE);
	}
	else
		/* on A2x, initialize TBM.CTRL.CPERIOD to 12 */
		tbm_w32_mask (TBM_CTRL_CPERIOD_MASK, TBM_CPERIOD, ctrl);

	tbmt.tbe  = 0;
	tbmt.mod  = 0;
	tbmt.mrm  = 0;
	tbmt.mre  = 0;
	tbmt.mbs  = 0xFFFFFF; /* max value */
	tbmt.tbc  = 0xFFFFFF; /* max value */
	tbmt.lts  = 0;
	tbmt.ets  = 0;
	tbmt.vts  = 0;
	if (is_falcon_chip_a1x())
		tbmt.tss  = 0;
	else
		tbmt.tss  = 1;

	for (tbid = 0; tbid < ONU_GPE_MAX_TBM; tbid++) {
		tbmt.tbid = tbid;
		tbm_meter_set(&tbmt);
	}
}

void tbm_meter_register_set(const struct tbm_tbmt_entry *tbmt)
{
	uint32_t w_tbmtr0, w_tbmtr1, w_tbmtr2, w_tbmtr3;

	w_tbmtr0  = (tbmt->tbe) ? TBM_TBMTR0_TBE_EN : 0;
	w_tbmtr0 |= (tbmt->mod << TBM_TBMTR0_MOD_OFFSET);
	if (is_falcon_chip_a1x())
		w_tbmtr0 |= (tbmt->mrm << TBM_TBMTR0_A1X_MRM_OFFSET);
	else
		w_tbmtr0 |= (tbmt->mrm << TBM_TBMTR0_A2X_MRM_OFFSET);
	if(tbmt->tss) w_tbmtr0 |= TBM_TBMTR0_TSS;
	w_tbmtr0 |= tbmt->mre;
	tbm_w32(w_tbmtr0, tbmtr0);

	if (is_falcon_chip_a1x())
		w_tbmtr1 = (tbmt->mbs << TBM_TBMTR1_A1X_MBS_OFFSET) & TBM_TBMTR1_A1X_MBS_MASK;
	else
		w_tbmtr1 = (tbmt->mbs << TBM_TBMTR1_A2X_MBS_OFFSET) & TBM_TBMTR1_A2X_MBS_MASK;
	tbm_w32(w_tbmtr1, tbmtr1);

	w_tbmtr2 = tbmt->tbc;
	tbm_w32(w_tbmtr2, tbmtr2);

	w_tbmtr3  = (tbmt->vts) ? TBM_TBMTR3_VTS : 0;
	w_tbmtr3 |= (tbmt->ets << TBM_TBMTR3_ETS_OFFSET);
	w_tbmtr3 |= tbmt->lts;
	tbm_w32(w_tbmtr3, tbmtr3);
}

void tbm_meter_register_get(struct tbm_tbmt_entry *tbmt)
{
	uint32_t r_tbmtr0, r_tbmtr1, r_tbmtr2, r_tbmtr3;

	r_tbmtr0 = tbm_r32(tbmtr0);
	tbmt->tbe = ((r_tbmtr0 & TBM_TBMTR0_TBE) == TBM_TBMTR0_TBE_EN);
	tbmt->mod = (r_tbmtr0 & TBM_TBMTR0_MOD_MASK ) >> TBM_TBMTR0_MOD_OFFSET;
	if (is_falcon_chip_a1x()) {
		tbmt->mrm = (r_tbmtr0 & TBM_TBMTR0_A1X_MRM_MASK) >> TBM_TBMTR0_A1X_MRM_OFFSET;
		tbmt->mre = (r_tbmtr0 & TBM_TBMTR0_A1X_MRE_MASK) >> TBM_TBMTR0_MRE_OFFSET;
	} else {
		tbmt->mrm = (r_tbmtr0 & TBM_TBMTR0_A2X_MRM_MASK) >> TBM_TBMTR0_A2X_MRM_OFFSET;
		tbmt->mre = (r_tbmtr0 & TBM_TBMTR0_A2X_MRE_MASK) >> TBM_TBMTR0_MRE_OFFSET;
		tbmt->tss = (r_tbmtr0 & TBM_TBMTR0_TSS) ? 1 : 0;
	}

	r_tbmtr1 = tbm_r32(tbmtr1);
	if (is_falcon_chip_a1x())
		tbmt->mbs = (r_tbmtr1 & TBM_TBMTR1_A1X_MBS_MASK) >> TBM_TBMTR1_A1X_MBS_OFFSET;
	else
		tbmt->mbs = (r_tbmtr1 & TBM_TBMTR1_A2X_MBS_MASK) >> TBM_TBMTR1_A2X_MBS_OFFSET;

	r_tbmtr2 = tbm_r32(tbmtr2);
	tbmt->tbc = (r_tbmtr2 & TBM_TBMTR2_TBC_MASK) >> TBM_TBMTR2_TBC_OFFSET;

	r_tbmtr3 = tbm_r32(tbmtr3);
	tbmt->vts = ((r_tbmtr3 & TBM_TBMTR3_VTS) == TBM_TBMTR3_VTS);
	tbmt->ets = (r_tbmtr3 & TBM_TBMTR3_ETS_MASK) >> TBM_TBMTR3_ETS_OFFSET;
	tbmt->lts = (r_tbmtr3 & TBM_TBMTR3_LTS_MASK) >> TBM_TBMTR3_LTS_OFFSET;
}

void tbm_meter_set(const struct tbm_tbmt_entry *tbmt)
{
	uint32_t w_tbmtc;

	tbm_meter_register_set(tbmt);

	w_tbmtc = TBM_TBMTC_SEL_SELALL;
	w_tbmtc |= TBM_TBMTC_RW;
	w_tbmtc |= tbmt->tbid;
	tbm_w32(w_tbmtc, tbmtc);
}

void tbm_meter_get(struct tbm_tbmt_entry *tbmt)
{
	uint32_t w_tbmtc;

	ONU_DEBUG_MSG("tbid %i", tbmt->tbid);

	w_tbmtc = TBM_TBMTC_SEL_SELALL;
	w_tbmtc |= tbmt->tbid;
	tbm_w32(w_tbmtc, tbmtc);

	tbm_meter_register_get(tbmt);
}

void tbm_meter_cfg_set(const struct tbm_token_bucket_meter_params *tbmt)
{
	uint32_t w_tbmtc;
	struct tbm_tbmt_entry tbmtr;

	w_tbmtc = tbmt->tbid;
	tbm_w32(w_tbmtc, tbmtc);

	tbm_meter_register_get(&tbmtr);

	tbmtr.mod = tbmt->mod;
	tbmtr.tbe = tbmt->tbe;
	tbmtr.mbs = tbmt->mbs;
	if (is_falcon_chip_a1x())
		tbmtr.tss = 0; /* unused */
	else
		tbmtr.tss = 1; /* Use TBM internal timestamping */
	/**\todo Once the register definitions are available for A21
	replace 5 by 
	 IQM.CTRL.TSPRESCALE if tbmt->tss = 0
	 TBM.CTRL.TSPRESCALE if tbmt->tss = 1 */
	tbm_mrm_conversion(5, tbmt->rate, &tbmtr);

	tbm_meter_register_set(&tbmtr);

	w_tbmtc  = TBM_TBMTC_SEL_SELALL;
	w_tbmtc |= TBM_TBMTC_RW;
	w_tbmtc |= tbmt->tbid;
	tbm_w32(w_tbmtc, tbmtc);
}

void tbm_meter_cfg_get(struct tbm_token_bucket_meter_params *tbmt)
{
	uint32_t w_tbmtc;
	struct tbm_tbmt_entry tbmtr;

	ONU_DEBUG_MSG("tbid %i", tbmt->tbid);

	w_tbmtc = tbmt->tbid;
	tbm_w32(w_tbmtc, tbmtc);

	tbm_meter_register_get(&tbmtr);

	tbm_rate_conversion(&tbmtr, &(tbmt->rate));
	tbmt->mbs = tbmtr.mbs;
	tbmt->mod = tbmtr.mod;
	tbmt->tbe = tbmtr.tbe;

}

int16_t find_meter_mode(const struct gpe_meter_cfg *param)
{
	if (param->mode == GPE_METER_RFC4115 &&
		param->color_aware == false)
		return 0;

	if (param->mode == GPE_METER_RFC4115 &&
		param->color_aware == true)
		return 1;

	if (param->mode == GPE_METER_RFC2698 &&
		param->color_aware == false)
		return 2;

	if (param->mode == GPE_METER_RFC2698 &&
		param->color_aware == true)
		return 3;

	if (param->mode == GPE_METER_NONE &&
		param->color_aware == false)
		return 2;

	if (param->mode == GPE_METER_NONE &&
		param->color_aware == true)
		return 3;

	return -1;
}


#if defined(INCLUDE_DUMP)

void tbm_dump(struct seq_file *s)
{
	struct tbm_tbmt_entry tbmt;
	uint32_t tbid;

	for (tbid = 0; tbid < ONU_GPE_MAX_TBM; tbid++) {
		tbmt.tbid = tbid;
		tbm_meter_get(&tbmt);
		seq_printf(s, "[%03d] %d %d %d %d %d %d %d %d %d\n", tbid,
			tbmt.tbe,
			tbmt.mod,
			tbmt.mrm,
			tbmt.mre,
			tbmt.mbs,
			tbmt.tbc,
			tbmt.lts,
			tbmt.ets,
			tbmt.vts);
	}

}

#endif

/*! @} */

/*! @} */
