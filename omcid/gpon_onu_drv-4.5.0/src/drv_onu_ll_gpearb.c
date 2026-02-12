/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_api.h"
#include "drv_onu_register.h"
#include "drv_onu_ll_sys.h"
#include "drv_onu_ll_gpearb.h"

enum gpe_arb_mode arbiter_mode = ARB_MODE_NA;

enum gpe_arb_mode gpearb_mode_get(void)
{
	return arbiter_mode;
}

void gpearb_init(enum gpe_arb_mode arb_mode)
{
	uint8_t i;
	static const uint32_t data_25g[16] = {
		0x05000b0a,
		0x07060907,
		0x090b0a04,
		0x0b060201,
		0x0a040900,
		0x0904050b,
		0x06090b0a,
		0x000b0a07,
		0x0b0a0905,
		0x07040906,
		0x0105090b,
		0x0509000a,
		0x0b090a06,
		0x090a0502,
		0x0a00070b,
		0x05040b09
	};
	static const uint32_t data_default[16] = {
		0x05000b0a,
		0x07060907,
		0x090b0a08,
		0x07060201,
		0x0a040300,
		0x0908050b,
		0x06080b0a,
		0x000b0a07,
		0x0b0a0905,
		0x0a080506,
		0x01050c0b,
		0x050b000a,
		0x0b070a06,
		0x080a0502,
		0x0a00090b,
		0x05040b03
	};

	/*
	  Enable module clock, release reset. This is mandatory before
	  accessing module's registers.
	*/
	if (arb_mode == ARB_MODE_GIG2_5 || arb_mode == ARB_MODE_DEFAULT)
		sys_gpe_hw_activate_or_reboot(SYS_GPE_ACT_ARB_SET);

	if (arb_mode == ARB_MODE_GIG2_5) {
		gpearb_w32(63, cntr);
		for (i = 0; i < 16; i++)
			gpearb_w32(data_25g[i], pid[i]);
	} else if (arb_mode == ARB_MODE_DEFAULT){  /* DEFAULT */
		gpearb_w32(63, cntr);
		for (i = 0; i < 16; i++)
			gpearb_w32(data_default[i], pid[i]);
	}

	arbiter_mode = arb_mode;
}

#if defined(INCLUDE_DUMP)

void gpearb_dump(struct seq_file *s)
{
	uint8_t i;

	if (sys_gpe_hw_is_activated(SYS_GPE_ACT_ARB_SET) == 0) {
		seq_printf(s, "gpearb not activated\n");
		return;
	}
	seq_printf(s, "    cntr");
	for (i = 0; i < 16; i++)
		seq_printf(s, ",   pid%02d", i);
	seq_printf(s, "\n");
	seq_printf(s, "%08x", gpearb_r32(cntr));
	for (i = 0; i < 16; i++)
		seq_printf(s, ",%08x", gpearb_r32(pid[i]));
	seq_printf(s, "\n");
}

#endif
