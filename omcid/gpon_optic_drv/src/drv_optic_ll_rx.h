/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_rx.h
*/
#ifndef _drv_optic_ll_rx_h
#define _drv_optic_ll_rx_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"
#include "drv_optic_interface.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_RX_INTERNAL Receiver Module - Internal
   @{
*/

#define OPTIC_RX_READ_CYCLES_LOL  8
#define OPTIC_RX_DSM_CTRL_OFFS  0xF1197C
#define OPTIC_RX_ASYN_CNT 20 /* check GTC status in 20*50ms = 1000ms raster */

enum optic_rx_type {
	OPTIC_RX_DATA_LOW,
	OPTIC_RX_DATA_HIGH,
	OPTIC_RX_EDGE_FALL,
	OPTIC_RX_EDGE_RISE,
	OPTIC_RX_MONITOR,
	OPTIC_RX_XTALK,
	OPTIC_RX_DFECTRL_OFF
};

enum optic_errorcode optic_ll_rx_cdr_init ( const bool bosa,
					    const bool dead_zone_elimination );
enum optic_errorcode optic_ll_rx_cdr_bpd ( const enum optic_activation mode );
enum optic_errorcode optic_ll_rx_lolalarm_thresh_set ( const uint8_t limit_low,
                                                       const uint8_t
							limit_high );
enum optic_errorcode optic_ll_rx_lolalarm_thresh_get ( uint8_t *limit_low,
                                                       uint8_t *limit_high );
enum optic_errorcode optic_ll_rx_flipinvert_set ( const enum optic_rx_type type,
                                                  const bool flip,
                                                  const bool invert );
enum optic_errorcode optic_ll_rx_flipinvert_get ( const enum optic_rx_type type,
                                                  bool *flip,
                                                  bool *invert );
enum optic_errorcode optic_ll_rx_afectrl_config ( const uint16_t rterm,
                                                  const uint8_t emp );
enum optic_errorcode optic_ll_rx_afectrl_set ( const enum optic_activation
                                               mode,
                                               const bool calibration );
enum optic_errorcode optic_ll_rx_dac_set ( const enum optic_rx_type type,
					   const bool positive,
                                           const uint8_t level_coarse,
                                           const uint8_t level_fine );
enum optic_errorcode optic_ll_rx_dac_get ( const enum optic_rx_type type,
					   bool *positive,
                                           uint8_t *level_coarse,
                                           uint8_t *level_fine );
enum optic_errorcode optic_ll_rx_dac_sel ( const enum optic_rx_type type );
enum optic_errorcode optic_ll_rx_lol_get ( bool *lol );
enum optic_errorcode optic_ll_rx_offset_cancel ( const enum optic_rx_type type,
						 int32_t *rx_offset );

enum optic_errorcode optic_ll_rx_dsm_reset (uint8_t lol_set, uint8_t lol_clear);
enum optic_errorcode optic_ll_rx_dsm_switch (const enum optic_activation mode);

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_RX == ACTIVE))
enum optic_errorcode optic_ll_rx_dump ( void );
#endif


/*! @} */

/*! @} */

EXTERN_C_END

#endif
