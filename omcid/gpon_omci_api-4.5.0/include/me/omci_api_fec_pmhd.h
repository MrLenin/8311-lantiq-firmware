/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_gal_fec_pmhd
#define _omci_api_me_gal_fec_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_FEC_PMHD FEC PMHD

   This Managed Entity collects performance monitoring data associated with FEC
   counters. Instances of this Managed Entity are created and deleted by the
   OLT.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the ANI-G. */

/** Retrieve current values of FEC PMHD counters

   \param[in]  ctx                        OMCI API context pointer
   \param[in]  me_id                      Managed Entity identifier
   \param[in]  reset_cnt                  Reset counters
   \param[in]  current                    15-min interval (true if current)
   \param[out] cnt_corrected_bytes        Corrected bytes
   \param[out] cnt_corrected_code_words   Corrected code words
   \param[out] cnt_uncorrected_code_words Uncorrectable code words
   \param[out] cnt_total_code_words       Total code words
   \param[out] cnt_fec_seconds            FEC seconds
*/
enum omci_api_return
omci_api_fec_pmhd_cnt_get(struct omci_api_ctx *ctx,
			  uint16_t me_id,
			  bool reset_cnt,
			  bool current,
			  uint32_t *cnt_corrected_bytes,
			  uint32_t *cnt_corrected_code_words,
			  uint32_t *cnt_uncorrected_code_words,
			  uint32_t *cnt_total_code_words,
			  uint16_t *cnt_fec_seconds);

/** Set counters thresholds

   \param[in] ctx                    OMCI API context pointer
   \param[in] me_id                  Managed Entity identifier
   \param[in] corrected_bytes        Corrected bytes
   \param[in] corrected_code_words   Corrected code words
   \param[in] uncorrected_code_words Uncorrectable code words
   \param[in] total_code_words       Total code words
   \param[in] fec_seconds            FEC seconds
*/
enum omci_api_return
omci_api_fec_pmhd_thr_set(struct omci_api_ctx *ctx,
			  uint16_t me_id,
			  uint32_t corrected_bytes,
			  uint32_t corrected_code_words,
			  uint32_t uncorrected_code_words,
			  uint32_t total_code_words,
			  uint32_t fec_seconds);

/** @} */

/** @} */

__END_DECLS

#endif
