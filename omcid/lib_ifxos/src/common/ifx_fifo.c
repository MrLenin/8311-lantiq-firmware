/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
      Initialize with Fifo_Init with previously allocated memory.
      The functions Fifo_writeElement and Fifo_readElement return a pointer
      to the next element to be written or read respectively.
      If empty Fifo_readElement returns IFX_NULL. If full Fifo_writeElement
      returns IFX_NULL.
*/


/* ============================= */
/* Includes                      */
/* ============================= */

#include "ifx_fifo.h"
#include "ifxos_debug.h"

#include "ifxos_memory_alloc.h"

#ifdef LINUX
#ifdef __KERNEL__
#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#endif
#endif

#include "ifxos_sys_show.h"

/* ============================= */
/* Local Macros  Definitions    */
/* ============================= */

/* Element size header is 1 long int. */
#define SIZE_HEADER          1
/* Element trailer is 1 long int */
#ifndef SIZE_TRAILER
#  define SIZE_TRAILER       1
#endif
#define SIZE_TRAILER_VALUE   0xDEADBEEF

/** increment IFX_FIFO index */
#define INCREMENT_INDEX(p)       \
{                                \
   if ((p) == pFifo->pEnd)         \
      (p) = pFifo->pStart;         \
   else                          \
      (p) = (p) + pFifo->size; \
}

/** decrement IFX_FIFO index */
#define DECREMENT_INDEX(p)     \
{                              \
   if ((p) == pFifo->pStart)   \
      (p) = pFifo->pEnd;       \
   else                        \
      (p) = (p) - pFifo->size; \
}

#define TO_ULONG_SIZE(esz)    \
      ((esz)/sizeof(IFX_ulong_t) + ((esz)%sizeof(IFX_ulong_t) > 0))

/* ============================= */
/* Global variable definition    */
/* ============================= */
IFXOS_PRN_USR_MODULE_CREATE(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH);

/* ============================= */
/* Local function declaration    */
/* ============================= */

/* ============================= */
/* Local variable definition     */
/* ============================= */

/* ============================= */
/* Local function definition     */
/* ============================= */

/* ============================= */
/* Global function definition    */
/* ============================= */


/**
   Initializes the fifo structure
   \param *pFifo - Pointer to the Fifo structure
   \param *pStart - Pointer to the fifo first element (IFX_ulong_t aligned)
   \param *pEnd - Pointer to the fifo last element (IFX_ulong_t aligned)
   \param elSizeB - size of each element in bytes (the same for all elements)
   \return
   Always zero, otherwise error
*/
IFX_return_t IFX_Fifo_Init (IFX_FIFO* pFifo, IFX_ulong_t* pStart, IFX_ulong_t* pEnd, IFX_uint32_t elSizeB)
{
   /* Check if pStart and pEnd are word aligned pointers */
   {
      if ((IFX_ulong_t)pStart % sizeof(IFX_ulong_t) != 0)
      {
         IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,
               (IFX_FIFO_PREFIX"ERROR - pStart is not unsigned long aligned (0x%lX)!!" IFXOS_CRLF,
               (IFX_ulong_t)pStart));
         return IFX_ERROR;
      }
      if ((IFX_ulong_t)pEnd % sizeof(IFX_ulong_t) != 0)
      {
         IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,
               (IFX_FIFO_PREFIX"ERROR - pEnd is not unsigned long aligned (0x%lX)!!" IFXOS_CRLF,
               (IFX_ulong_t)pEnd));
         return IFX_ERROR;
      }
   }

   pFifo->pEnd   = pEnd;
   pFifo->pStart = pStart;
   pFifo->pRead  = pStart;
   pFifo->pWrite = pStart;
   pFifo->size   = TO_ULONG_SIZE(elSizeB);
   pFifo->count  = 0;

   if ((pFifo->pEnd - pFifo->pStart) % TO_ULONG_SIZE(elSizeB) != 0)
   {
      /* element size must be a multiple of fifo memory */
      return IFX_ERROR;
   }
   pFifo->max_size = 1 + (pFifo->pEnd - pFifo->pStart) / pFifo->size;

   return IFX_SUCCESS;
}

/**
   Clear the fifo
   \param *pFifo - Pointer to the Fifo structure
*/
IFX_void_t IFX_Fifo_Clear (IFX_FIFO *pFifo)
{
   pFifo->pRead  = pFifo->pStart;
   pFifo->pWrite = pFifo->pStart;
   pFifo->count = 0;
}

/**
   Get the next element to read from
   \param *pFifo - Pointer to the Fifo structure
   \return Returns the element address to read from (IFX_ulong_t aligned),
           or IFX_NULL if no element available or an error occured
   \remark
   Error occurs if fifo is empty
*/
IFX_ulong_t* IFX_Fifo_readElement (IFX_FIFO *pFifo)
{
   IFX_ulong_t *ret = IFX_NULL;

   if (pFifo->count == 0)
   {
      return IFX_NULL;
   }
   ret = pFifo->pRead;

   INCREMENT_INDEX(pFifo->pRead);
   pFifo->count--;

   return ret;
}

/**
   Delivers empty status
   \param *pFifo - Pointer to the Fifo structure
   \return
   Returns TRUE if empty (no data available)
   \remark
   No change on fifo!
*/
IFX_int8_t IFX_Fifo_isEmpty (IFX_FIFO *pFifo)
{
   return (pFifo->count == 0);
}

/**
   Get the next element to write to
   \param *pFifo - Pointer to the Fifo structure
   \return
   Returns the element address (IFX_ulong_t aligned) to write to, or IFX_NULL in case of error
   \remark
   Error occurs if the write pointer reaches the read pointer, meaning
   the fifo if full and would otherwise overwrite the next element.
*/
IFX_ulong_t* IFX_Fifo_writeElement (IFX_FIFO *pFifo)
{
   IFX_ulong_t* ret = IFX_NULL;

   if (IFX_Fifo_isFull(pFifo))
      return IFX_NULL;
   else
   {
      /* get the next entry of the Fifo */
      ret = pFifo->pWrite;
      INCREMENT_INDEX(pFifo->pWrite);
      pFifo->count++;

      return ret;
   }
}

/**
   Delivers full status
   \param *pFifo - Pointer to the Fifo structure
   \return
   TRUE if full (overflow on next write)
   \remark
   No change on fifo!
*/
IFX_int8_t IFX_Fifo_isFull (IFX_FIFO *pFifo)
{
   return (pFifo->count >= pFifo->max_size);
}

/**
   Returns the last element taken back to the fifo
   \param *pFifo - Pointer to the Fifo structure
   \remark
   Makes an undo to a previosly Fifo_writeElement
*/
IFX_void_t IFX_Fifo_returnElement (IFX_FIFO *pFifo)
{
   DECREMENT_INDEX(pFifo->pWrite);
   pFifo->count--;
}

/**
   Get the number of stored elements
   \param *pFifo - Pointer to the Fifo structure
   \return
   Number of containing elements
*/
IFX_uint32_t IFX_Fifo_getCount(IFX_FIFO *pFifo)
{
   return pFifo->count;
}

#ifdef INCLUDE_SYS_FIFO_TEST
/**
   test routine
*/
IFX_void_t IFX_FifoTest(IFX_void_t)
{
   IFX_uint16_t buf [3];
   IFX_uint16_t tst = 1;
   IFX_uint16_t *entry = IFX_NULL;
   IFX_FIFO fifo;

   Fifo_Init (&fifo, &buf[0], &buf[2], sizeof (IFX_uint16_t));

   entry = Fifo_writeElement (&fifo);
   if (entry != IFX_NULL)
      *entry = 1;
   entry = Fifo_writeElement (&fifo);
   if (entry != IFX_NULL)
   {
      *entry = 2;
      Fifo_returnElement (&fifo);
   }
   entry = Fifo_readElement (&fifo);
   if (entry != IFX_NULL)
      tst = *entry;
   entry = Fifo_readElement (&fifo);
   if (entry != IFX_NULL)
      tst = *entry;
}
#endif /* INCLUDE_SYS_FIFO_TEST */

/**
   Initializes the variable-sized fifo structure
   \param *pFifo - Pointer to the IFX_VFIFO structure
   \param *pStart - Pointer to the fifo first element (IFX_ulong_t aligned)
   \param *pEnd - Pointer to the first address beyond the last fifo element (IFX_ulong_t aligned)
   \param maxElSize - maximum allowed size of an element in bytes
   \return
   Always zero, otherwise error
*/
IFX_return_t IFX_Var_Fifo_Init (IFX_VFIFO* pFifo, IFX_ulong_t* pStart,
                          IFX_ulong_t* pEnd, IFX_uint32_t maxElSize)
{
   if (pFifo == IFX_NULL)
      return IFX_ERROR;

   /* Check if pStart and pEnd are word aligned pointers */
   {
      if ((IFX_ulong_t)pStart % sizeof(IFX_ulong_t) != 0)
      {
         IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
               (IFX_FIFO_PREFIX"ERROR - pStart is not unsigned long aligned (0x%lX)!!" IFXOS_CRLF,
               (IFX_ulong_t)pStart));
         return IFX_ERROR;
      }
      if ((IFX_ulong_t)pEnd % sizeof(IFX_ulong_t) != 0)
      {
         IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
               (IFX_FIFO_PREFIX"ERROR - pEnd is not unsigned long aligned (0x%lX)!!" IFXOS_CRLF,
               (IFX_ulong_t)pEnd));
         return IFX_ERROR;
      }
   }

   pFifo->pEnd   = pEnd;
   pFifo->pStart = pStart;
   pFifo->pRead  = pStart;
   pFifo->pWrite = pStart;
   pFifo->size   = TO_ULONG_SIZE(maxElSize);
   pFifo->count  = 0;
   pFifo->max_size = 0;

   pFifo->pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_FIFO);
   IFXOS_SYS_FIFO_PARAMS_SET(pFifo->pSysObject, pFifo);
   IFXOS_SYS_FIFO_INIT_COUNT_INC(pFifo->pSysObject);

   return IFX_SUCCESS;
}

/**
   Clears the variable-sized fifo
   \param *pFifo - Pointer to the Fifo structure
*/
IFX_void_t IFX_Var_Fifo_Clear (IFX_VFIFO *pFifo)
{
   pFifo->pRead  = pFifo->pStart;
   pFifo->pWrite = pFifo->pStart;
   pFifo->count = 0;
}

/**
   Get the next element to read from variable-sized fifo
   \param *pFifo - Pointer to the Fifo structure
   \return Returns the element address (IFX_ulong_t aligned) to read from,
           or IFX_NULL if no element available or an error occured
   \remark Error occurs if fifo is empty
*/
IFX_ulong_t* IFX_Var_Fifo_readElement (IFX_VFIFO *pFifo, IFX_uint32_t *elSizeB)
{
   IFX_ulong_t *ret = IFX_NULL;
   IFX_ulong_t elSizeUL;

   IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(pFifo->pSysObject);

   if (elSizeB)
      *elSizeB = 0;

   if ( (pFifo->pRead < pFifo->pStart) || (pFifo->pRead > pFifo->pEnd))
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - enter var read: pRead: 0x%lX out of range pStart: 0x%lX, pEnd: 0x%lX, !!" IFXOS_CRLF,
            (IFX_ulong_t)pFifo->pRead, (IFX_ulong_t)pFifo->pStart, (IFX_ulong_t)pFifo->pEnd ));

      return IFX_NULL;
   }

   if (pFifo->count == 0)
   {
      IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pFifo->pSysObject);
      return IFX_NULL;
   }

   if ((pFifo->pRead[0] == (IFX_ulong_t)~0) ||
       ((pFifo->pEnd - pFifo->pRead) <= (SIZE_HEADER + SIZE_TRAILER)))
   {
      pFifo->pRead = pFifo->pStart;
   }

   elSizeUL = TO_ULONG_SIZE(pFifo->pRead[0]);

   if ( (pFifo->pRead + (SIZE_HEADER + SIZE_TRAILER) + elSizeUL) > pFifo->pEnd)
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - var read: overflow, pRead: 0x%lX, pEnd: 0x%lX, elSize: 0x%08lX (+ 0x%X) !!" IFXOS_CRLF,
            (IFX_ulong_t)pFifo->pRead, (IFX_ulong_t)pFifo->pEnd, elSizeUL, (SIZE_HEADER + SIZE_TRAILER)));

      IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pFifo->pSysObject);
      return IFX_NULL;
   }

#if (SIZE_TRAILER == 1)
   if (pFifo->pRead[elSizeUL + SIZE_HEADER] != SIZE_TRAILER_VALUE)
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - var read: overwrite occured: 0x%lX, pEnd: 0x%lX, elSize: 0x%08lX (+ 0x%X) !!" IFXOS_CRLF,
            (IFX_ulong_t)pFifo->pRead, (IFX_ulong_t)pFifo->pEnd, elSizeUL, (SIZE_HEADER + SIZE_TRAILER)));

      pFifo->pRead[elSizeUL + SIZE_HEADER] = (IFX_ulong_t)~0;
   }
#endif

   if (elSizeB)
      *elSizeB = (IFX_uint32_t)(pFifo->pRead[0]);

   ret = pFifo->pRead + SIZE_HEADER;
   pFifo->pRead += (SIZE_HEADER + SIZE_TRAILER) + elSizeUL;

   pFifo->count--;

   if ( (pFifo->pRead < pFifo->pStart) || (pFifo->pRead > pFifo->pEnd))
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - leave var read: pRead: 0x%lX out of range pStart: 0x%lX, pEnd: 0x%lX, !!" IFXOS_CRLF,
            (IFX_ulong_t)pFifo->pRead, (IFX_ulong_t)pFifo->pStart, (IFX_ulong_t)pFifo->pEnd ));

      return IFX_NULL;
   }

   IFXOS_SYS_FIFO_RD_ELEM_COUNT_INC(pFifo->pSysObject);
   IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pFifo->pSysObject);
   return ret;
}

/**
   Peek the next element to read from variable-sized fifo
   \remark To free the element use the corresponding read function.

   \param *pFifo - Pointer to the Fifo structure
   \return Returns the element address (IFX_ulong_t aligned) to read from,
           or IFX_NULL if no element available or an error occured
   \remark Error occurs if fifo is empty
*/
IFX_ulong_t* IFX_Var_Fifo_peekElement (IFX_VFIFO *pFifo, IFX_uint32_t *elSizeB)
{
   IFX_ulong_t *ret = IFX_NULL, *pPeekRead = pFifo->pRead;
   IFX_ulong_t elSizeUL;

   IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(pFifo->pSysObject);

   if (elSizeB)
      *elSizeB = 0;

   if ( (pFifo->pRead < pFifo->pStart) || (pFifo->pRead > pFifo->pEnd))
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - enter var peek: pRead: 0x%lX out of range pStart: 0x%lX, pEnd: 0x%lX, !!" IFXOS_CRLF,
            (IFX_ulong_t)pFifo->pRead, (IFX_ulong_t)pFifo->pStart, (IFX_ulong_t)pFifo->pEnd ));

      return IFX_NULL;
   }

   if (pFifo->count == 0)
   {
      IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pFifo->pSysObject);
      return IFX_NULL;
   }

   if ((pPeekRead[0] == (IFX_ulong_t)~0) ||
       ((pFifo->pEnd - pPeekRead) <= (SIZE_HEADER + SIZE_TRAILER)))
   {
      pPeekRead = pFifo->pStart;
   }

   elSizeUL = TO_ULONG_SIZE(pPeekRead[0]);

   if ( (pPeekRead + (SIZE_HEADER + SIZE_TRAILER) + elSizeUL) > pFifo->pEnd)
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - var peek: overflow, pRead: 0x%lX, pEnd: 0x%lX, elSize: 0x%08lX (+ 0x%X) !!" IFXOS_CRLF,
            (IFX_ulong_t)pPeekRead, (IFX_ulong_t)pFifo->pEnd, elSizeUL, (SIZE_HEADER + SIZE_TRAILER)));

      IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pFifo->pSysObject);
      return IFX_NULL;
   }

#if (SIZE_TRAILER == 1)
   if (pPeekRead[elSizeUL + SIZE_HEADER] != SIZE_TRAILER_VALUE)
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - var peek: overwrite occured: 0x%lX, pEnd: 0x%lX, elSize: 0x%08lX (+ 0x%X) !!" IFXOS_CRLF,
            (IFX_ulong_t)pPeekRead, (IFX_ulong_t)pFifo->pEnd, elSizeUL, (SIZE_HEADER + SIZE_TRAILER)));

      pPeekRead[elSizeUL + SIZE_HEADER] = (IFX_ulong_t)~0;
   }
#endif

   if (elSizeB)
      *elSizeB = (IFX_uint32_t)(pPeekRead[0]);

   ret = pPeekRead + SIZE_HEADER;

   if ( (pFifo->pRead < pFifo->pStart) || (pFifo->pRead > pFifo->pEnd))
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - leave var peek: pRead: 0x%lX out of range pStart: 0x%lX, pEnd: 0x%lX, !!" IFXOS_CRLF,
            (IFX_ulong_t)pFifo->pRead, (IFX_ulong_t)pFifo->pStart, (IFX_ulong_t)pFifo->pEnd ));

      return IFX_NULL;
   }

   IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pFifo->pSysObject);
   return ret;
}


/**
   Delivers empty status
   \param *pFifo - Pointer to the IFX_VFIFO structure
   \return Returns TRUE if empty (no data available)
   \remark No change on fifo!
*/
IFX_int8_t IFX_Var_Fifo_isEmpty (IFX_VFIFO *pFifo)
{
   return (pFifo->count == 0);
}

/**
 * Returns size of free room in the variable-sized IFX_FIFO.
 *    \param *pFifo - Pointer to the Fifo structure
 *    \return
 *    The size of free room in the IFX_FIFO, in IFX_ulong_t integers.
 */
IFX_uint32_t IFX_Var_Fifo_getRoom (IFX_VFIFO *pFifo)
{
   IFX_long_t diff = pFifo->pWrite - pFifo->pRead;
   IFX_long_t headRoom, tailRoom;

   if (diff == 0)
   {
      if (pFifo->count)
         return 0;
      else
      {
         return (pFifo->pEnd - pFifo->pStart - (SIZE_HEADER + SIZE_TRAILER));
      }
   }
   if (diff > 0)
   {
      tailRoom = pFifo->pEnd  - pFifo->pWrite - (SIZE_HEADER + SIZE_TRAILER);
      headRoom = pFifo->pRead - pFifo->pStart - (SIZE_HEADER + SIZE_TRAILER);

      return (headRoom > tailRoom) ? headRoom : tailRoom;
   }
   else
   {
      if ((-diff) <= (SIZE_HEADER + SIZE_TRAILER) )
         return 0;
      else
         return ((-diff) - (SIZE_HEADER + SIZE_TRAILER) );
   }
}

/**
   Get the next element to write to
   \param *pFifo - Pointer to the Fifo structure
   \param size - Size of a new element to be written in bytes
   \return
   Returns the element address to write to (IFX_ulong_t aligned), or IFX_NULL in case of error
   \remark
   Error occurs if the write pointer reaches the read pointer, meaning
   the fifo if full and would otherwise overwrite the next element.
*/
IFX_ulong_t* IFX_Var_Fifo_writeElement (IFX_VFIFO *pFifo, IFX_uint32_t elSizeB)
{
   IFX_ulong_t* ret = IFX_NULL;
   IFX_ulong_t elSizeUL = TO_ULONG_SIZE (elSizeB);

   IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(pFifo->pSysObject);
   IFXOS_SYS_FIFO_REQ_ELEM_COUNT_INC(pFifo->pSysObject);

   if ( (pFifo->pWrite < pFifo->pStart) || (pFifo->pWrite >= pFifo->pEnd))
   {
      IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
            (IFX_FIFO_PREFIX "ERROR - enter var write: pWrite: 0x%lX out of range pStart: 0x%lX, pEnd: 0x%lX, !!" IFXOS_CRLF,
            (IFX_ulong_t)pFifo->pWrite, (IFX_ulong_t)pFifo->pStart, (IFX_ulong_t)pFifo->pEnd ));

      return IFX_NULL;
   }

   if (elSizeUL > IFX_Var_Fifo_getRoom (pFifo) || elSizeUL > pFifo->size)
   {
      IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pFifo->pSysObject);
      return IFX_NULL;
   }
   else
   {
      if (pFifo->pWrite >= pFifo->pRead &&
         (elSizeUL + SIZE_HEADER + SIZE_TRAILER) > (IFX_ulong_t)(pFifo->pEnd - pFifo->pWrite))
      {
         if ((pFifo->pEnd - pFifo->pWrite) >= SIZE_HEADER)
         {
            pFifo->pWrite[0] = (IFX_ulong_t)~0;
         }
         pFifo->pWrite = pFifo->pStart;
      }

      pFifo->pWrite[0] = elSizeB;
#if (SIZE_TRAILER == 1)
      pFifo->pWrite[elSizeUL + SIZE_HEADER] = SIZE_TRAILER_VALUE;
#endif

      ret              = pFifo->pWrite + SIZE_HEADER;

      pFifo->pWrite   += elSizeUL + (SIZE_HEADER + SIZE_TRAILER);
      if (pFifo->pWrite == pFifo->pEnd)
         pFifo->pWrite = pFifo->pStart;


      if ( (pFifo->pWrite < pFifo->pStart) || (pFifo->pWrite >= pFifo->pEnd))
      {
         IFXOS_PRN_USR_ERR_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_ERR,
               (IFX_FIFO_PREFIX "ERROR - leave var write: pWrite: 0x%lX out of range pStart: 0x%lX, pEnd: 0x%lX, !!" IFXOS_CRLF,
               (IFX_ulong_t)pFifo->pWrite, (IFX_ulong_t)pFifo->pStart, (IFX_ulong_t)pFifo->pEnd ));

         return IFX_NULL;
      }

      pFifo->count++;
      IFXOS_SYS_FIFO_WR_ELEM_COUNT_INC(pFifo->pSysObject);
      IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pFifo->pSysObject);
      return ret;
   }
}

/**
   Delivers full status
   The IFX_FIFO is full if there is not enough space
   for one element of maxiumum size defined in Var_Fifo_Init() call.
   \param *pFifo - Pointer to the Fifo structure
   \return
   TRUE if full (overflow on next write)
   \remark
   No change on fifo!
*/
IFX_int8_t IFX_Var_Fifo_isFull (IFX_VFIFO *pFifo)
{
   return (IFX_Var_Fifo_getRoom(pFifo) < pFifo->size);
}

/**
   Get the number of stored elements
   \param *pFifo - Pointer to the Fifo structure
   \return
   Number of containing elements
*/
IFX_uint32_t IFX_Var_Fifo_getCount(IFX_VFIFO *pFifo)
{
   return pFifo->count;
}

#ifdef INCLUDE_SYS_FIFO_TEST
IFX_void_t IFX_Var_Fifo_Test(IFX_void_t)
{
#define VFIFOSIZE       256
#define ELEM_START_SIZE 41
   IFX_ulong_t *fifoMem;
   IFX_ulong_t *element;
   IFX_VFIFO testFifo;
   IFX_int32_t i;

   /* 1. Allocate FIFO memoery */
   fifoMem = IFXOS_MemAlloc(VFIFOSIZE * sizeof(*fifoMem));
   if (fifoMem == IFX_NULL)
   {
      IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": cannot allocate var FIFO mem" IFXOS_CRLF));
      return;
   }

   IFX_Var_Fifo_Init (&testFifo, fifoMem, fifoMem + VFIFOSIZE, 100);

   for (i = 0; i < 100; i++)
   {
      element = IFX_Var_Fifo_writeElement(&testFifo, ELEM_START_SIZE-i);

      if (element == IFX_NULL)
      {
         IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": write element == NULL" IFXOS_CRLF));
         IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": Fifo size %u" IFXOS_CRLF, IFX_Var_Fifo_getCount(&testFifo)));
         break;
      }
      else
         IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": write element == %p (size %u)" IFXOS_CRLF, element, ELEM_START_SIZE-i));
   }

   IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": Fifo size %u" IFXOS_CRLF, IFX_Var_Fifo_getCount(&testFifo)));

   for (i = 0; i < 100; i++)
   {
      IFX_uint32_t elSizeB;
      element = IFX_Var_Fifo_readElement(&testFifo, &elSizeB);

      if (element == IFX_NULL)
      {
         IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": read element == NULL" IFXOS_CRLF));
         IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": Fifo size %u" IFXOS_CRLF, IFX_Var_Fifo_getCount(&testFifo)));
         break;
      }
      else
      {
         IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": read element == %p (size %u)" IFXOS_CRLF, element, elSizeB));
      }
   }

   IFXOS_PRN_USR_DBG_NL(FIFO_MODULE, IFXOS_PRN_LEVEL_HIGH,(IFX_FIFO_PREFIX": Fifo size %u" IFXOS_CRLF, IFX_Var_Fifo_getCount(&testFifo)));
}


#endif /*INCLUDE_SYS_FIFO_TEST*/

#if defined(LINUX) && defined(__KERNEL__) && defined(MODULE)
EXPORT_SYMBOL(IFX_Fifo_Init);
EXPORT_SYMBOL(IFX_Fifo_Clear);
EXPORT_SYMBOL(IFX_Fifo_readElement);
EXPORT_SYMBOL(IFX_Fifo_isEmpty);
EXPORT_SYMBOL(IFX_Fifo_writeElement);
EXPORT_SYMBOL(IFX_Fifo_isFull);
EXPORT_SYMBOL(IFX_Fifo_getCount);
EXPORT_SYMBOL(IFX_Var_Fifo_Init);
EXPORT_SYMBOL(IFX_Var_Fifo_Clear);
EXPORT_SYMBOL(IFX_Var_Fifo_readElement);
EXPORT_SYMBOL(IFX_Var_Fifo_peekElement);
EXPORT_SYMBOL(IFX_Var_Fifo_isEmpty);
EXPORT_SYMBOL(IFX_Var_Fifo_getRoom);
EXPORT_SYMBOL(IFX_Var_Fifo_writeElement);
EXPORT_SYMBOL(IFX_Var_Fifo_isFull);
EXPORT_SYMBOL(IFX_Var_Fifo_getCount);
#ifdef INCLUDE_SYS_FIFO_TEST
EXPORT_SYMBOL(IFX_Var_Fifo_Test);
#endif
#endif
