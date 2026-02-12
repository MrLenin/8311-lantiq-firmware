#ifndef _lib_ini_access_h
#define _lib_ini_access_h
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   ini file access
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ===========================
   Includes
   =========================== */
#include "ifx_types.h"

/* ===========================
   Defines
   =========================== */
#define WRITE_SECTION(name)         fprintf(fileout, "[" #name "]\r\n")
#define WRITE_SECTION_NO(name, no)  fprintf(fileout, "[" #name "_%d]\r\n", (IFX_int32_t)(no))
#define WRITE_KEY(name, val)        fprintf(fileout,   #name "=%d\r\n", (IFX_int32_t)(val))
#define WRITE_KEY_STRING(name, val) fprintf(fileout,   #name "=%s\r\n", (IFX_char_t*)(val))


/* ===========================
   Function Declarations
   =========================== */
IFX_int32_t GetNextLine(IFX_char_t* pData, IFX_char_t* pRetLine, IFX_int32_t nLine);
IFX_int32_t GetKeyString(IFX_char_t* pSectionName, IFX_char_t* pKeyName, IFX_char_t* pDefault, IFX_char_t* pRetString, IFX_int32_t nSize, IFX_char_t* pFile);
IFX_int32_t GetKeyInt(IFX_char_t* pSectionName, IFX_char_t* pKeyName, IFX_int32_t nDefault, IFX_char_t* pFile);
IFX_int32_t GetSection(IFX_char_t *pSection, IFX_char_t *pBuffer, IFX_int32_t nBufferSize, IFX_char_t* filein);

#ifdef __cplusplus
}
#endif

#endif /*_lib_ini_access_h*/




