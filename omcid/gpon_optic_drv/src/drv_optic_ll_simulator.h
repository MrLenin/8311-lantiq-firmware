/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_ll_simulator_h
#define _drv_optic_ll_simulator_h

/** \defgroup OPTIC_SIMULATOR_INTERNAL Register Simulator Module
   @{
*/

extern int optic_ll_pma_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_pma_simwrite (ulong_t reg, uint32_t val);
extern int optic_ll_sys_gpon_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_sys_gpon_simwrite (ulong_t reg, uint32_t val);
extern int optic_ll_status_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_status_simwrite (ulong_t reg, uint32_t val);
extern int optic_ll_gtc_pma_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_gtc_pma_simwrite (ulong_t reg, uint32_t val);
extern int optic_ll_fcsi_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_fcsi_simwrite (ulong_t reg, uint32_t val);
extern int optic_ll_dcdc_apd_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_dcdc_apd_simwrite (ulong_t reg, uint32_t val);
extern int optic_ll_dcdc_core_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_dcdc_core_simwrite (ulong_t reg, uint32_t val);
extern int optic_ll_dcdc_ddr_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_dcdc_ddr_simwrite (ulong_t reg, uint32_t val);
extern int optic_ll_dcdc_sys1_simread (ulong_t reg, uint32_t *val);
extern int optic_ll_dcdc_sys1_simwrite (ulong_t reg, uint32_t val);

/*! @} */

EXTERN_C_END

#endif
