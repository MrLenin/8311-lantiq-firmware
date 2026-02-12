/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_traffic_scheduler
#define _omci_api_me_traffic_scheduler

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_TRAFFIC_SCHEDULER Traffic Scheduler

   An instance of this Managed Entity represents a logical object that can
   control upstream GEM packets. A traffic scheduler can accommodate GEM
   packets after a priority queue or other traffic scheduler and transfer them
   toward the next traffic scheduler or T-CONT. Because T-CONTs and traffic
   schedulers are created autonomously by the ONU, the ONU vendor predetermines
   the most complex traffic handling model it is prepared to support; the OLT
   may use less than the ONU's full capabilities, but cannot ask for more.
   See Appendix III for more detail.

   After the ONU creates instances of T-CONT ME, it then autonomously creates
   instances of the Traffic Scheduler ME.

   @{
*/

enum omci_api_traffic_scheduler_policy {
	/* NULL */
	OMCI_API_TRAFFICSCHEDULERG_POLICY_HULL = 0,
	/* Head of Line */
	OMCI_API_TRAFFICSCHEDULERG_POLICY_HOL = 1,
	/* Weighted Round Robin */
	OMCI_API_TRAFFICSCHEDULERG_POLICY_WRR = 2
};

/** Enable Managed Entity identifier mapping to driver index and initialize
    corresponding driver structures

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] tcont_ptr             T-CONT pointer
   \param[in] traffic_scheduler_ptr Traffic scheduler pointer
   \param[in] policy                Policy
   \param[in] priority_weight       Priority/weight
*/
enum omci_api_return
omci_api_traffic_scheduler_create(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t tcont_ptr,
				  uint16_t traffic_scheduler_ptr,
				  uint8_t policy,
				  uint8_t priority_weight);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_traffic_scheduler_destroy(struct omci_api_ctx *ctx,
				   uint16_t me_id);

/** Update Traffic Scheduler ME resources

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] tcont_ptr             T-CONT pointer
   \param[in] traffic_scheduler_ptr Traffic scheduler pointer
   \param[in] policy                Policy
   \param[in] priority_weight       Priority/weight
*/
enum omci_api_return
omci_api_traffic_scheduler_update(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t tcont_ptr,
				  uint16_t traffic_scheduler_ptr,
				  uint8_t policy,
				  uint8_t priority_weight);

/** @} */

/** @} */

__END_DECLS

#endif
