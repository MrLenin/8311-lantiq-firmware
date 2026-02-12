/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_resource_gpe.h"
#include "drv_onu_ll_tod.h"
#include "drv_onu_ll_tod_asc.h"

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_TOD_INTERNAL GPE - TOD Interface
   @{
*/

void tod_init(const uint16_t intdel, const uint16_t pw)
{
	uint32_t reg = 0;

	set_val(reg, intdel, TOD_CFG_INTDEL_MASK, TOD_CFG_INTDEL_OFFSET);
	set_val(reg, pw, TOD_CFG_PW_MASK, TOD_CFG_PW_OFFSET);

	tod_w32(reg, cfg);

	/* Enable delayed PPS interrupt */
	tod_interrupt_enable_set(TOD_IRNEN_PPS | TOD_IRNEN_PPSDEL,
				 TOD_IRNEN_PPSDEL);

	if (onu_asc1_init())
		ONU_DEBUG_ERR("can't initialize ASC1");
}

void tod_frm_enable(const bool enable)
{
	tod_w32_mask(TOD_CFG_FRM_EN, enable ? TOD_CFG_FRM_EN : 0, cfg);
}

void tod_sfcc_set(const uint32_t val)
{
	tod_w32(val, sfcc);
}

uint32_t tod_sfcc_get(void)
{
	return tod_r32(sfcc);
}

void tod_rlds_set(const uint32_t val)
{
	tod_w32(val, rlds);
}

uint32_t tod_rlds_get(void)
{
	return tod_r32(rlds);
}

void tod_rldns_set(const uint16_t high, const uint16_t low)
{
	tod_w32((((uint32_t)high << TOD_RLDNS_RLDNSHI_OFFSET) | (uint32_t)low),
		rldns);
}

uint32_t tod_rldns_get(void)
{
	return tod_r32(rldns);
}

uint32_t tod_rldns2nsec(const uint32_t rldns)
{
	uint32_t h, l;

	/* maximum value of h = 0x3fff (14 bits) */
	h = (rldns & TOD_RLDNS_RLDNSHI_MASK) >> TOD_RLDNS_RLDNSHI_OFFSET;

	/* maximum value of l = 0x7fff (15 bits) */
	l = (rldns & TOD_RLDNS_RLDNSLO_MASK) >> TOD_RLDNS_RLDNSLO_OFFSET;

	return h * TOD_RLDNS_HI_STEP + (l * TOD_RLDNS_LO_FREQ_SCALE) /
		TOD_RLDNS_LO_FREQ;
}

void tod_reload_get(const uint32_t sec, const uint32_t nsec,
		    const struct tod_corr *corr, struct tod_reload *rld)
{
	uint32_t sec_val, nsec_val = nsec, nsec_l_val, nsec_h_val, nsec_corr;

	nsec_corr = onu_round_div((uint32_t)((31 - corr->gtc_ds_delay) *
							  TOD_GTC_DS_DEL_SCALE),
				   TOD_GTC_DS_DEL_DIV);

	nsec_val += nsec_corr;

	sec_val   = sec + nsec_val/TOD_NSEC;
	nsec_val %= TOD_NSEC;

	nsec_h_val = nsec_val / TOD_RLDNS_HI_STEP;
	nsec_l_val = nsec_val % TOD_RLDNS_HI_STEP;

	nsec_l_val = onu_round_div((uint32_t)(nsec_l_val * TOD_RLDNS_LO_FREQ),
				   TOD_RLDNS_LO_FREQ_SCALE);

	rld->sec	= sec_val;
	rld->nsec_high	= nsec_h_val;
	rld->nsec_low	= nsec_l_val;
}

uint32_t tod_pps_get(void)
{
	return tod_r32(ppssec);
}

void tod_interrupt_enable_set(const uint32_t clear, const uint32_t set)
{
	tod_w32_mask(clear, set, irnen);
}

#define SEC_PER_DAY	(60 * 60 * 24)
#define SEC_PER_WEEK	(SEC_PER_DAY * 7)

static int is_leap(unsigned long year)
{
	return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static unsigned long sec_per_year(unsigned long year)
{
	return (is_leap(year) ? 366 : 365) * SEC_PER_DAY;
}

static unsigned long to_gps_sec(unsigned long tai_sec)
{
	return tai_sec -
		sec_per_year(1970) -
		sec_per_year(1971) -
		sec_per_year(1972) -
		sec_per_year(1973) -
		sec_per_year(1974) -
		sec_per_year(1975) -
		sec_per_year(1976) -
		sec_per_year(1977) -
		sec_per_year(1978) -
		sec_per_year(1979) -
		SEC_PER_DAY * 5 +
		19;
}

void tod_isr_handle(void)
{
	char buf[50];

	/* TAI: number of seconds since 1 Jan 1970 00:00:00 */
	unsigned long tai_sec;
	/* GPS: number of seconds since 6 Jan 1980 00:00:00 */
	unsigned long gps_sec;
	/* Number of GPS weeks */
	unsigned long gps_week;
	/* Number of seconds since last GPS week */
	unsigned long gps_week_sec;

	tai_sec = tod_pps_get();

	gps_sec = to_gps_sec(tai_sec);
	gps_week = gps_sec / SEC_PER_WEEK;
	gps_week_sec = gps_sec % SEC_PER_WEEK;

#if defined(LINUX) && defined(__KERNEL__)
	snprintf(buf, sizeof(buf), "jiffies_sec = %lu\n", jiffies / HZ);
	onu_asc1_puts(buf);

	snprintf(buf, sizeof(buf), "jiffies = %lu\n", jiffies);
	onu_asc1_puts(buf);
#endif

	onu_snprintf(buf, sizeof(buf), "tai_sec = %lu\n", tai_sec);
	onu_asc1_puts(buf);

	onu_snprintf(buf, sizeof(buf), "gps_sec = %lu\n", gps_sec);
	onu_asc1_puts(buf);

	onu_snprintf(buf, sizeof(buf), "gps_week = %lu\n", gps_week);
	onu_asc1_puts(buf);

	onu_snprintf(buf, sizeof(buf), "gps_week_sec = %lu\n", gps_week_sec);
	onu_asc1_puts(buf);
}

#if defined(LINUX) && defined(__KERNEL__)



void tod_dump(struct seq_file *s)
{
	seq_printf(s, "TOD Init Version 1.0\n");
}

#endif

/*! @} */

/*! @} */
