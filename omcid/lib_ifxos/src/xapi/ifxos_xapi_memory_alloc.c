/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains the IFXOS Layer implementation for XAPI 
   Memory Allocation.
*/

/* ============================================================================
   IFX XAPI adaptation - Global Includes
   ========================================================================= */

#include <xapi.h>

#include "ifx_types.h"
#include "ifxos_memory_alloc.h"


/* ============================================================================
   IFX XAPI adaptation - memory handling, malloc
   ========================================================================= */

/** \addtogroup IFXOS_MEM_ALLOC_XAPI 
@{ */

#if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) )
/**
   XAPI - Allocate a continious memory block of the given size [byte]

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
   IFX_void_t *pMemBlock = IFX_NULL;

   if(memSize_byte)
      xm_alloc("IFM", XM_CHIP_MEM, memSize_byte, (void *) &pMemBlock);
   
   return (pMemBlock);
}

/**
   XAPI - Free the given memory block.

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
   if (pMemBlock)
   {
      xm_dealloc(pMemBlock);
   }

   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) ) */


#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
/**
   XAPI - Allocate Memory Space from the OS

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
   IFX_void_t *pMemBlock = IFX_NULL;

   xm_alloc("IFM", XM_CHIP_MEM, memSize_byte, (IFX_void_t *) &pMemBlock);

   return (pMemBlock);
}

/**
   XAPI - Free Memory Space

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
   if (pMemBlock)
   {
      xm_dealloc(pMemBlock);
   }

   return;
}

#endif      /* #if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) ) */

/** @} */

#endif      /* #ifdef XAPI */

