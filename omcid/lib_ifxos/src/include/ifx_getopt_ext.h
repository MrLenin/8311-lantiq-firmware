#ifndef _IFXOS_GETOPT_EXT_H
#define _IFXOS_GETOPT_EXT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Extention to the getopt library.
*/

#ifdef __cplusplus
extern "C"
{
#endif

/* ==========================================================================
   Includes
   ========================================================================== */
#include "ifx_types.h"


/* ==========================================================================
   Defines and types
   ========================================================================== */

#define GET_OPT_EXT_MAX_INT_PARAMS           8
#define GET_OPT_EXT_MAX_STR_PARAMS           5 
#define GET_OPT_EXT_MAX_STR_LEN              80

/* ==========================================================================
   Types
   ========================================================================== */

/**
   Takes an integer argument and the set flag.
*/
typedef struct GetOptExt_IntArg_s
{
   IFX_int_t      intValue;
   IFX_boolean_t  bSet;
} GetOptExt_IntArg_t;


/**
   Takes an string argument and the set flag.
*/
typedef struct GetOptExt_StrArg_s
{
   IFX_char_t     strValue[GET_OPT_EXT_MAX_STR_LEN];
   IFX_boolean_t  bSet;
} GetOptExt_StrArg_t;


/* ==========================================================================
   Export Functions and Data
   ========================================================================== */


extern IFX_void_t GetOptExt_RequiredDigit(
                              IFX_char_t           *pOptArg, 
                              GetOptExt_IntArg_t   *pUserIntArg,
                              IFX_char_t           *pDesc);

extern IFX_void_t GetOptExt_RequiredStr(
                              IFX_char_t           *pOptArg,
                              GetOptExt_StrArg_t   *pUserStrArg,
                              IFX_char_t           *pDesc);

extern IFX_void_t GetOptExt_OptionalDigit(
                              IFX_char_t           *pOptArg, 
                              GetOptExt_IntArg_t   *pUserIntArg,
                              IFX_char_t           *pDesc);

extern IFX_int_t GetOptExt_TakeIntValues(
                              GetOptExt_IntArg_t   *pIntArgArry,
                              IFX_int_t            *pIntValueArray);

extern IFX_int_t GetOptExt_ParseArgString(
                              IFX_char_t  *pArgString,
                              IFX_char_t  *pArgArray[],
                              IFX_int_t   maxArgs);
#ifdef __cplusplus
/* extern "C" */
}
#endif

#endif      /* #define _IFXOS_GETOPT_EXT_H */

