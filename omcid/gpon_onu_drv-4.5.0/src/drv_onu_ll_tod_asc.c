/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef HAVE_CONFIG_H
#  include "drv_onu_config.h"
#endif

#if defined(ONU_TOD_ASC1) && defined(LINUX) && defined(__KERNEL__)
#include <linux/io.h>
#include <linux/ioport.h>
#include <asm/mach-lantiq/falcon/lantiq_soc.h>

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"

#define ONU_ASC1_BASE			0x1E100B00
#define ONU_ASC1_SIZE			0x00000100

#define ONU_PADCTRL1_BASE		0x1E800400
#define ONU_PADCTRL1_SIZE		0x00000100

/* ASC input select (0 or 1) */
#define CONSOLE_TTY		0

#define ASC_TXFIFO_FL		1
#define ASC_RXFIFO_FL		1

/* CLC register's bits and bitfields */
#define ASCCLC_DISS		0x00000002
#define ASCCLC_RMCMASK		0x0000FF00
#define ASCCLC_RMCOFFSET	8

/* CON register's bits and bitfields */
#define ASCCON_M_8ASYNC		0x0
#define ASCCON_FDE		0x00000200
#define ASCCON_R		0x00008000
#define ASCCON_FEN		0x00020000
#define ASCCON_ROEN		0x00080000
#define ASCCON_TOEN		0x00100000

/* STATE register's bits and bitfields */
#define ASCSTATE_TOE		0x00100000

/* WHBSTATE register's bits and bitfields */
#define ASCWHBSTATE_SETREN	0x00000002
#define ASCWHBSTATE_CLRTOE	0x00000040

/* FDV register mask, offset and bitfields*/
#define ASCFDV_VALUE_MASK	0x000001FF

/* TXFCON register's bits and bitfields */
#define ASCTXFCON_TXFEN         0x0001
#define ASCTXFCON_TXFITLMASK    0x3F00
#define ASCTXFCON_TXFITLOFF     8

/* RXFCON register's bits and bitfields */
#define ASCRXFCON_RXFEN         0x0001
#define ASCRXFCON_RXFITLMASK    0x3F00
#define ASCRXFCON_RXFITLOFF     8

/* FSTAT register's bits and bitfields */
#define ASCFSTAT_TXFREEMASK     0x3F000000
#define ASCFSTAT_TXFREEOFF      24

#define asc_readl(reg) reg_r32(&asc->reg)
#define asc_writel(reg, value) reg_w32((value), &asc->reg)

#define SET_BIT(reg, mask)			asc_writel(reg, asc_readl(reg) | (mask))
#define CLEAR_BIT(reg, mask)			asc_writel(reg, asc_readl(reg) & (~mask))
#define SET_BITFIELD(reg, mask, off, val)	asc_writel(reg, (asc_readl(reg) & (~mask)) | (val << off) )

struct onu_reg_asc {
	unsigned long  asc_clc;                            /*0x0000*/
	unsigned long  asc_pisel;                          /*0x0004*/
	unsigned long  asc_id;                             /*0x0008*/
	unsigned long  asc_rsvd1[1];   /* for mapping */   /*0x000C*/
	unsigned long  asc_con;                            /*0x0010*/
	unsigned long  asc_state;                          /*0x0014*/
	unsigned long  asc_whbstate;                       /*0x0018*/
	unsigned long  asc_rsvd2[1];   /* for mapping */   /*0x001C*/
	unsigned long  asc_tbuf;                           /*0x0020*/
	unsigned long  asc_rbuf;                           /*0x0024*/
	unsigned long  asc_rsvd3[2];   /* for mapping */   /*0x0028*/
	unsigned long  asc_abcon;                          /*0x0030*/
	unsigned long  asc_abstat;     /* not used */      /*0x0034*/
	unsigned long  asc_whbabcon;                       /*0x0038*/
	unsigned long  asc_whbabstat;  /* not used */      /*0x003C*/
	unsigned long  asc_rxfcon;                         /*0x0040*/
	unsigned long  asc_txfcon;                         /*0x0044*/
	unsigned long  asc_fstat;                          /*0x0048*/
	unsigned long  asc_rsvd4[1];   /* for mapping */   /*0x004C*/
	unsigned long  asc_bg;                             /*0x0050*/
	unsigned long  asc_bg_timer;                       /*0x0054*/
	unsigned long  asc_fdv;                            /*0x0058*/
	unsigned long  asc_pmw;                            /*0x005C*/
	unsigned long  asc_modcon;                         /*0x0060*/
	unsigned long  asc_modstat;                        /*0x0064*/
	unsigned long  asc_rsvd5[2];   /* for mapping */   /*0x0068*/
	unsigned long  asc_sfcc;                           /*0x0070*/
	unsigned long  asc_rsvd6[3];   /* for mapping */   /*0x0074*/
	unsigned long  asc_eomcon;                         /*0x0080*/
	unsigned long  asc_rsvd7[26];   /* for mapping */  /*0x0084*/
	unsigned long  asc_dmacon;                         /*0x00EC*/
	unsigned long  asc_rsvd8[1];   /* for mapping */   /*0x00F0*/
	unsigned long  asc_irnen;                          /*0x00F4*/
	unsigned long  asc_irnicr;                         /*0x00F8*/
	unsigned long  asc_irncr;                          /*0x00FC*/
};

static struct onu_reg_asc *asc;

/*
 *             FDV            fASC
 * BaudRate = ----- * --------------------
 *             512    16 * (ReloadValue+1)
 */

/*
 *                  FDV          fASC
 * ReloadValue = ( ----- * --------------- ) - 1
 *                  512     16 * BaudRate
 */
static void serial_divs(u32 baudrate, u32 fasc, u32 *pfdv, u32 *preload)
{
	u32 clock = fasc / 16;

	u32 fdv; /* best fdv */
	u32 reload = 0; /* best reload */
	u32 diff; /* smallest diff */
	u32 idiff; /* current diff */
	u32 ireload; /* current reload */
	u32 i; /* current fdv */
	u32 result; /* current resulting baudrate */

	if (clock > 0x7FFFFF)
		clock /= 512;
	else
		baudrate *= 512;

	fdv = 512; /* start with 1:1 fraction */
	diff = baudrate; /* highest possible */

	/* i is the test fdv value -- start with the largest possible */
	for (i = 512; i > 0; i--) {
		ireload = (clock * i) / baudrate;
		if (ireload < 1)
			break; /* already invalid */
		result = (clock * i) / ireload;

		idiff = (result > baudrate) ? (result - baudrate) :
			(baudrate - result);
		if (idiff == 0) {
			fdv = i;
			reload = ireload;
			break; /* can't do better */
		} else if (idiff < diff) {
			fdv = i; /* best so far */
			reload = ireload;
			diff = idiff; /* update lowest diff*/
		}
	}

	*pfdv = (fdv == 512) ? 0 : fdv;
	*preload = reload - 1;
}

static void serial_setbrg(void)
{
	static const u32 baudrate = 9600;
	static const u32 ebu_speed = 100000000;
	u32 ReloadValue, fdv;

	serial_divs(baudrate, ebu_speed, &fdv, &ReloadValue);

	/* Disable Baud Rate Generator; BG should only be written when R=0 */
	CLEAR_BIT(asc_con, ASCCON_R);

	/* Enable Fractional Divider */
	SET_BIT(asc_con, ASCCON_FDE);	/* FDE = 1 */

	/* Set fractional divider value */
	asc_writel(asc_fdv, fdv & ASCFDV_VALUE_MASK);

	/* Set reload value in BG */
	asc_writel(asc_bg, ReloadValue);

	/* Enable Baud Rate Generator */
	SET_BIT(asc_con, ASCCON_R);	/* R = 1 */
}

#define MUXC_SIF_RX_PIN		(100 + 12)
#define MUXC_SIF_TX_PIN		(100 + 13)

int onu_asc1_init(void)
{
	sys1_hw_activate_or_reboot(1 << 11);

	if (ltq_gpio_request(MUXC_SIF_RX_PIN, 1, 1, 0, "asc1-rx"))
		return -1;

	if (ltq_gpio_request(MUXC_SIF_TX_PIN, 1, 1, 1, "asc1-tx"))
		return -1;

	asc = ioremap_nocache(ONU_ASC1_BASE, ONU_ASC1_SIZE);
	if (!asc) {
		release_mem_region(ONU_PADCTRL1_BASE, ONU_PADCTRL1_SIZE);

		return -1;
	}

	/* and we have to set CLC register*/
	CLEAR_BIT(asc_clc, ASCCLC_DISS);
	SET_BITFIELD(asc_clc, ASCCLC_RMCMASK, ASCCLC_RMCOFFSET, 0x0001);

	/* initialy we are in async mode */
	asc_writel(asc_con, ASCCON_M_8ASYNC);

	/* select input port */
	asc_writel(asc_pisel, CONSOLE_TTY & 0x1);

	/* TXFIFO's filling level */
	SET_BITFIELD(asc_txfcon, ASCTXFCON_TXFITLMASK,
		     ASCTXFCON_TXFITLOFF, ASC_TXFIFO_FL);
	/* enable TXFIFO */
	SET_BIT(asc_txfcon, ASCTXFCON_TXFEN);

	/* RXFIFO's filling level */
	SET_BITFIELD(asc_txfcon, ASCRXFCON_RXFITLMASK,
		     ASCRXFCON_RXFITLOFF, ASC_RXFIFO_FL);
	/* enable RXFIFO */
	SET_BIT(asc_rxfcon, ASCRXFCON_RXFEN);

	/* set baud rate */
	serial_setbrg();

	/* Set FIFO to single byte forward mode */
	asc_writel(asc_eomcon, 0x00010300);

	/* enable error signals &  Receiver enable  */
	SET_BIT(asc_whbstate,
		ASCWHBSTATE_SETREN | ASCCON_FEN | ASCCON_TOEN | ASCCON_ROEN);

	return 0;
}

static void onu_asc1_putc(const char c)
{
	u32 txFl = 0;
#ifdef __BIG_ENDIAN
	u8 * tbuf8 = ((u8 *)(&asc->asc_tbuf)) + 3;
#else
	u8 * tbuf8 = ((u8 *)(&asc->asc_tbuf));
#endif
	if (c == '\n')
		onu_asc1_putc ('\r');
	/* check do we have a free space in the TX FIFO */
	/* get current free level */
	do {
		txFl = ( asc_readl(asc_fstat) & ASCFSTAT_TXFREEMASK ) >>
							     ASCFSTAT_TXFREEOFF;
	}
	while ( txFl == 0 );

	/* write char to Transmit Buffer Register */
	__raw_writeb(c, tbuf8);

	/* check for errors */
	if ( asc_readl(asc_state) & ASCSTATE_TOE ) {
		SET_BIT(asc_whbstate, ASCWHBSTATE_CLRTOE);
		return;
	}
}

void onu_asc1_puts(const char *s)
{
	while (*s)
		onu_asc1_putc (*s++);
}
#endif
