#ifndef _IFX_CRC_H
#define _IFX_CRC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Crc definitions and declarations.
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================= */
/* Includes                      */
/* ============================= */
#include "ifx_types.h"

/* ============================= */
/* Local Macros  Definitions    */
/* ============================= */

/* generate CRC tables dynamically or use static tables */
#undef DYNAMIC_CRC

/**
   IFX_FIFO data structure
*/

/* ============================= */
/* Global function declaration   */
/* ============================= */


extern IFX_uint16_t IFX_CalcChecksum (IFX_uint8_t* nBufferAddress, IFX_uint_t nCount);
extern IFX_uint16_t IFX_CalcChecksumCRC16 (const IFX_char_t* buf, IFX_uint_t length);
extern IFX_uint32_t IFX_CalcChecksumCRC32 (IFX_uint_t crc, const IFX_char_t* buf, IFX_uint_t len);
#ifdef __cplusplus
}
#endif

#endif
