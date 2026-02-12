/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_onu_dyn_pwr_mngmt_ctrl_h
#define _omci_api_me_onu_dyn_pwr_mngmt_ctrl_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** Power reduction Doze mode mask*/
#define OMCI_API_ONU_DYN_PWR_MNGMT_CTRL_DOZE_MODE_MASK		0x1
/** Power reduction Cyclic sleep mode mask*/
#define OMCI_API_ONU_DYN_PWR_MNGMT_CTRL_CYCLIC_SLEEP_MODE_MASK	0x2

/** \defgroup OMCI_API_ME_ONU_DYN_PWR_MNGMT_CTRL ONU dynamic power management control

    This Managed Entity models the ONU’s ability to enter power conservation
    modes in cooperation with the OLT in a G.987 system. [ITU-T G.987.3]
    specifies two modes, doze and cyclic sleep.
    An ONU that supports power conservation modes automatically creates an
    instance of this Managed Entity. 

   @{
*/

/** Updates ONU dynamic power management control ME resources

   \param[in] ctx			OMCI API context pointer
   \param[in] me_id			Managed Entity identifier
   \param[in] pwr_reduction_mngmt_mode	Power reduction management mode
   \param[in] max_sleep_interval	Maximum sleep interval
   \param[in] min_aware_interval	Minimum aware interval
   \param[in] min_active_held_interval	Minimum active held interval
*/
enum omci_api_return
omci_api_onu_dyn_pwr_mngmt_ctrl_update(struct omci_api_ctx *ctx,
				       uint16_t me_id,
				       uint8_t pwr_reduction_mngmt_mode,
				       uint32_t max_sleep_interval,
				       uint32_t min_aware_interval,
				       uint16_t min_active_held_interval);

/** @} */

/** @} */

__END_DECLS

#endif
