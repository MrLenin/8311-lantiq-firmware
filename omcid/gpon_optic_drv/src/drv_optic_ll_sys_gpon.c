/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, SYS_GPON Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_SYS_GPON_INTERNAL SYS_GPON Module - Internal
   @{
*/
#include "drv_optic_ll_sys_gpon.h"
#include "drv_optic_common.h"
#include "drv_optic_register.h"
#include "drv_optic_reg_sys_gpon.h"

#if defined(LINUX) && defined(__KERNEL__)
#include <falcon/sysctrl.h>
#endif

/**
   Activate Clocks.

   \return
   - OPTIC_STATUS_OK - no errors,
   - OPTIC_STATUS_ERR - error occurs
*/
enum optic_errorcode optic_ll_sys_gpon_clockenable ( void )
{
	uint32_t reg = 0;

	reg = SYS_GPON_CLKEN_PMATX_SET | SYS_GPON_CLKEN_TOD_SET |
	      SYS_GPON_CLKEN_GPEIF_SET | SYS_GPON_CLKEN_GTCRXPDI_SET |
	      SYS_GPON_CLKEN_GTCRX_SET | SYS_GPON_CLKEN_GTCTXPDI_SET |
	      SYS_GPON_CLKEN_GTCTX_SET;

	sys_gpon_w32(reg, clken);

	reg = SYS_GPON_ACT_PMATX_SET | SYS_GPON_ACT_TOD_SET |
	      SYS_GPON_ACT_GPEIF_SET | SYS_GPON_ACT_GTCRXPDI_SET |
	      SYS_GPON_ACT_GTCRX_SET | SYS_GPON_ACT_GTCTXPDI_SET |
	      SYS_GPON_ACT_GTCTX_SET;

	sys_gpon_w32(reg, act);

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP == ACTIVE))
	optic_ll_sys_gpon_dump ();
#endif
	/* GPE clocks needed */
#if defined(LINUX) && defined(__KERNEL__)
	sys_gpe_hw_activate (0);
#endif

	return OPTIC_STATUS_OK;
}

/**
   Deactivate Clocks.

   \return
   - OPTIC_STATUS_OK - no errors,
   - OPTIC_STATUS_ERR - error occurs
*/
enum optic_errorcode optic_ll_sys_gpon_clockdisable ( void )
{
	uint32_t reg = 0;


	reg = SYS_GPON_ACT_PMATX_SET;

	sys_gpon_w32(reg, rbt);

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_sys_gpon_dump ( void )
{
	uint32_t reg;

	reg = sys_gpon_r32(clks);
	OPTIC_DEBUG_WRN("SYS GPON CLKS: 0x%08X", reg);

	reg = sys_gpon_r32(acts);
	OPTIC_DEBUG_WRN("SYS GPON ACTS: 0x%08X", reg);

	return OPTIC_STATUS_OK;
}

/*! @} */
/*! @} */
