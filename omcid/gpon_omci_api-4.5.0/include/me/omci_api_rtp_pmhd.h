/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_rtp_pmhd
#define _omci_api_rtp_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_RTP_PMHD RTP PMHD

   This Managed Entity collects performance monitoring data related to an RTP
   session.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the PPTP POTS UNI ME. */

/** Retrieve current value of RTP PMHD counters

   \param[in]  ctx				OMCI API context pointer
   \param[in]  me_id				Managed Entity identifier
   \param[out] rtp_errors			RTP errors
   \param[out] packet_loss			Packet loss
   \param[out] max_jitter			Maximum jitter
   \param[out] max_time_between_rtcp_packets	Max time between RTCP packets
   \param[out] buffer_underflows		Buffer undeflows
   \param[out] buffer_overflows			Buffer overflows
*/
enum omci_api_return
omci_api_rtp_pmhd_cnt_get(struct omci_api_ctx *ctx,
			  uint16_t me_id,
			  uint32_t *rtp_errors,
			  uint32_t *packet_loss,
			  uint32_t *max_jitter,
			  uint32_t *max_time_between_rtcp_packets,
			  uint32_t *buffer_underflows,
			  uint32_t *buffer_overflows);

/** @} */

/** @} */

__END_DECLS

#endif
