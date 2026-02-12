/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_bert.h
*/
#ifndef _drv_optic_ll_bert_h
#define _drv_optic_ll_bert_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"



EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_PMA_BERT_INTERNAL BERT Module - Internal
   @{
*/

enum optic_bert_cnt
{
	OPTIC_BERTCNT_RESET,
	OPTIC_BERTCNT_FREEZE,
	OPTIC_BERTCNT_RUN
};

enum optic_errorcode optic_ll_bert_init ( void );
enum optic_errorcode optic_ll_bert_analyzer_set ( const enum optic_activation mode );
enum optic_errorcode optic_ll_bert_analyzer_get ( enum optic_activation *mode );
void optic_ll_bert_sync ( void );
enum optic_errorcode optic_ll_bert_muxsel_set ( const uint8_t muxsel1,
                                                const uint8_t muxsel2,
                                                const uint8_t muxsel3,
                                                const uint8_t muxsel4 );
enum optic_errorcode optic_ll_bert_muxsel_get ( uint8_t *muxsel1,
                                                uint8_t *muxsel2,
                                                uint8_t *muxsel3,
                                                uint8_t *muxsel4 );
enum optic_errorcode optic_ll_bert_endcounter_set ( const uint8_t ecount1,
                                                    const uint8_t ecount2,
                                                    const uint8_t ecount3,
                                                    const uint8_t ecount4 );
enum optic_errorcode optic_ll_bert_endcounter_get ( uint8_t *ecount1,
                                                    uint8_t *ecount2,
                                                    uint8_t *ecount3,
                                                    uint8_t *ecount4 );
enum optic_errorcode optic_ll_bert_pattern_set ( const uint32_t pattern,
                                                 const uint8_t ecount1,
                                                 const uint8_t ecount2,
                                                 const uint8_t ecount3,
                                                 const uint8_t ecount4 );
enum optic_errorcode optic_ll_bert_pattern_get ( uint32_t *pattern,
                                                 uint8_t *ecount1,
                                                 uint8_t *ecount2,
                                                 uint8_t *ecount3,
                                                 uint8_t *ecount4 );
enum optic_errorcode optic_ll_bert_clk_set ( const uint8_t clk_period,
                                             const uint8_t clk_high );
enum optic_errorcode optic_ll_bert_clk_get ( uint8_t *clk_period,
                                             uint8_t *clk_high );
enum optic_errorcode optic_ll_bert_prbs_set ( const uint8_t prbs_type );
enum optic_errorcode optic_ll_bert_prbs_get ( uint8_t *prbs_type );
enum optic_errorcode optic_ll_bert_speed_set ( const bool speedrate_high_tx,
                                               const bool speedrate_high_rx );
enum optic_errorcode optic_ll_bert_speed_get ( bool *speedrate_high_tx,
                                               bool *speedrate_high_rx );
enum optic_errorcode optic_ll_bert_loop_set ( const enum optic_activation mode );
enum optic_errorcode optic_ll_bert_loop_get ( enum optic_activation *mode );
enum optic_errorcode optic_ll_bert_counter_get ( uint32_t *word_cnt,
						 uint32_t *error_cnt );
enum optic_errorcode optic_ll_bert_counter_config ( const enum optic_bert_cnt
						    mode );

/*! @} */

/*! @} */

EXTERN_C_END

#endif
