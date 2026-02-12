#ifndef _IFX_FIFO_H
#define _IFX_FIFO_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Fifo definitions and declarations.
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   Local Macros  Definitions
   ========================================================================= */

#define IFX_FIFO_PREFIX   "-->FIFO_Library: "

/**
   IFX_FIFO data structure
*/
typedef struct
{
   /** start pointer of IFX_FIFO buffer */
   IFX_ulong_t* pStart;
   /** end pointer of IFX_FIFO buffer */
   IFX_ulong_t* pEnd;
   /** read pointer of IFX_FIFO buffer */
   IFX_ulong_t* pRead;
   /** write pointer of IFX_FIFO buffer */
   IFX_ulong_t* pWrite;
   /** element size */
   IFX_ulong_t size;
   /** element count, changed on read and write: */
   IFX_vuint32_t count;
   /** maximum of IFX_FIFO elements (or maximum element size of IFX_VFIFO)*/
   IFX_uint32_t max_size;

   /** points to the internal system object - for debugging */
   IFX_void_t  *pSysObject;
} IFX_FIFO;

typedef IFX_FIFO IFX_VFIFO;


/* ============================================================================
   Global function declaration
   ========================================================================= */

extern IFX_return_t IFX_Fifo_Init (
                           IFX_FIFO*    pFifo, 
                           IFX_ulong_t* pStart, 
                           IFX_ulong_t* pEnd, 
                           IFX_uint32_t elSizeB);
extern IFX_void_t   IFX_Fifo_Clear (
                           IFX_FIFO *pFifo);
extern IFX_ulong_t* IFX_Fifo_readElement (
                           IFX_FIFO *pFifo);
extern IFX_ulong_t* IFX_Fifo_writeElement (
                           IFX_FIFO *pFifo);
extern IFX_void_t   IFX_Fifo_returnElement (
                           IFX_FIFO *pFifo);
extern IFX_int8_t   IFX_Fifo_isEmpty (
                           IFX_FIFO *pFifo);
extern IFX_int8_t   IFX_Fifo_isFull (
                           IFX_FIFO *pFifo);
extern IFX_uint32_t IFX_Fifo_getCount (
                           IFX_FIFO *pFifo);


extern IFX_return_t IFX_Var_Fifo_Init (
                           IFX_VFIFO* pFifo, 
                           IFX_ulong_t* pStart,
                           IFX_ulong_t* pEnd, 
                           IFX_uint32_t size);
extern IFX_void_t   IFX_Var_Fifo_Clear (
                           IFX_VFIFO *pFifo);
extern IFX_ulong_t* IFX_Var_Fifo_readElement (
                           IFX_VFIFO *pFifo, 
                           IFX_uint32_t *elSizeB);
extern IFX_ulong_t* IFX_Var_Fifo_peekElement (
                           IFX_VFIFO *pFifo, 
                           IFX_uint32_t *elSizeB);
extern IFX_ulong_t* IFX_Var_Fifo_writeElement (
                           IFX_VFIFO *pFifo, 
                           IFX_uint32_t elSizeB);
extern IFX_int8_t   IFX_Var_Fifo_isEmpty (
                           IFX_VFIFO *pFifo);
extern IFX_int8_t   IFX_Var_Fifo_isFull (
                           IFX_VFIFO *pFifo);
extern IFX_uint32_t IFX_Var_Fifo_getCount(
                           IFX_VFIFO *pFifo);

#ifdef __cplusplus
}
#endif

#endif
