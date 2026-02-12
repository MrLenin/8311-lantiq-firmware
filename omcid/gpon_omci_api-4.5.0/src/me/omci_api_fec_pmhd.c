/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_gal_ethernet_pmhd.h"

/** \addtogroup OMCI_API_ME_FEC_PMHD

   @{
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
			  uint16_t *cnt_fec_seconds)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gtc_status status;
	union gtc_counter_get_u param;
	
	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   current=%u\n"
		  "   reset_cnt=%u\n",
		  __FUNCTION__, me_id, current, reset_cnt));

	/* me_id is not used, because there is only one structure for all
	   entities in drv. */

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_STATUS_GET,
		      &status, sizeof(status));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (status.ds_fec_enable) {
		memset(&param, 0, sizeof(param));

		param.in.curr = current;
		param.in.reset_mask = reset_cnt ?
					(ONU_GTC_CNT_RST_MASK_FEC_ERR_CORR |
					 ONU_GTC_CNT_RST_MASK_FEC_WRD_CORR |
					 ONU_GTC_CNT_RST_MASK_FEC_WRD_UNCORR |
					 ONU_GTC_CNT_RST_MASK_FEC_WRD_TOTAL) :
					 0;

		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_COUNTER_GET,
			      &param, sizeof(param));
		if (ret != OMCI_API_SUCCESS)
			return ret;

		*cnt_corrected_bytes	    = (uint32_t)
						param.out.val.fec_error_corr;
		*cnt_corrected_code_words   = (uint32_t)
						param.out.val.fec_words_corr;
		*cnt_uncorrected_code_words = (uint32_t)
						param.out.val.fec_words_uncorr;
		*cnt_total_code_words	    = (uint32_t)
						param.out.val.fec_words_total;
		/** \todo add fec_seconds counter handling */
		*cnt_fec_seconds	    = 0;
	} else {
		*cnt_corrected_bytes 	    = 0;
		*cnt_corrected_code_words   = 0;
		*cnt_uncorrected_code_words = 0;
		*cnt_total_code_words 	    = 0;
		*cnt_fec_seconds 	    = 0;
	}

	return ret;
}

enum omci_api_return
omci_api_fec_pmhd_thr_set(struct omci_api_ctx *ctx,
			  uint16_t me_id,
			  uint32_t corrected_bytes,
			  uint32_t corrected_code_words,
			  uint32_t uncorrected_code_words,
			  uint32_t total_code_words,
			  uint32_t fec_seconds)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gtc_cnt_value param;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   corrected_bytes=%u\n"
		  "   corrected_code_words=%u\n"
		  "   uncorrected_code_words=%u\n"
		  "   total_code_words=%u\n"
		  "   fec_seconds=%u\n",
		  __FUNCTION__,
		  me_id,
		  corrected_bytes,
		  corrected_code_words,
		  uncorrected_code_words, total_code_words, fec_seconds));

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_COUNTER_THRESHOLD_GET,
		      &param, sizeof(param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	param.fec_error_corr   = (uint64_t)corrected_bytes;
	param.fec_words_corr   = (uint64_t)corrected_code_words;
	param.fec_words_uncorr = (uint64_t)uncorrected_code_words;
	param.fec_words_total  = (uint64_t)total_code_words;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_COUNTER_THRESHOLD_SET,
		      &param, sizeof(param));

	return ret;
}

/** @} */
