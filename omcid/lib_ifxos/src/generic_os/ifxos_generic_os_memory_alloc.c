/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains the IFXOS Layer implementation for 
   GENERIC_OS Memory Allocation.
*/

/* ============================================================================
   IFX GENERIC_OS Adaptation Frame - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_memory_alloc.h"

#include "ifxos_sys_show.h"

/* ============================================================================
   IFX GENERIC_OS Adaptation Frame - memory handling, malloc
   ========================================================================= */

/** \addtogroup IFXOS_MEM_ALLOC_GENERIC_OS 
@{ */

#if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) )
/**
   GENERIC_OS - Allocate a continious memory block of the given size [byte]

\par Implementation
   - Allocates a memory block with the function "malloc"

\param
   memSize_byte   Size of the requested memory block [byte]

\return
   IFX_NULL in case of error, else
   pointer to the allocated memory block.

*/
IFX_void_t *IFXOS_BlockAlloc(
               IFX_size_t memSize_byte)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         return (IFX_void_t *)malloc((size_t)memSize_byte);
   */


   IFXOS_RETURN_IF_ARG_LE_ZERO(memSize_byte, IFX_NULL);
   
   return (IFX_NULL);
}

/**
   GENERIC_OS - Free the given memory block.

\par Implementation
   Free a memory block with the function "free"

\param
   pMemBlock   Points to the memory block to free.

\return
   NONE
*/
IFX_void_t IFXOS_BlockFree(
               IFX_void_t *pMemBlock)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         free((void*)pMemBlock);
   */

   IFXOS_RETURN_VOID_IF_POINTER_NULL(pMemBlock, IFX_ERROR);

   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) ) */


#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
/**
   GENERIC_OS - Allocate Memory Space from the OS

\par Implementation
   Allocates a memory block with the function "malloc"

\param
   memSize_byte   Size of the requested memory block [byte]

\return
   IFX_NULL in case of error, else
   pointer to the allocated memory block.
*/
IFX_void_t *IFXOS_MemAlloc(
               IFX_size_t memSize_byte)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         return (IFX_void_t *)malloc((size_t)memSize_byte);
   */


   IFXOS_RETURN_IF_ARG_LE_ZERO(memSize_byte, IFX_NULL);
   IFXOS_SYS_MEM_ALLOC_COUNT_INC(IFX_NULL);

   return (IFX_NULL);
}

/**
   GENERIC_OS - Free Memory Space

\par Implementation
   Free a memory block with the function "free"

\param
   pMemBlock   Points to the memory block to free.

\return
   NONE
*/
IFX_void_t IFXOS_MemFree(
               IFX_void_t *pMemBlock)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         free((void*)pMemBlock);
   */

   IFXOS_RETURN_VOID_IF_POINTER_NULL(pMemBlock, IFX_ERROR);
   IFXOS_SYS_MEM_FREE_COUNT_INC(IFX_NULL);

   return;
}

#endif      /* #if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) ) */

/** @} */

#endif      /* #ifdef GENERIC_OS */

