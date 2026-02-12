/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Sun OS adaptation - Memory Allocation (User Space)
   ========================================================================= */

#if defined(SUN_OS) && !defined(_KERNEL)

/** \file
   This file contains the IFXOS Layer implementation for 
   Sun OS User Space Memory Allocation.
*/

/* ============================================================================
   IFX Sun OS adaptation - Global Includes
   ========================================================================= */
#include <stdlib.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_memory_alloc.h"

#include "ifxos_sys_show.h"

/* ============================================================================
   IFX Sun OS adaptation - Application Space, memory handling
   ========================================================================= */

/** \addtogroup IFXOS_MEM_ALLOC_SUN_OS_APPL
@{ */


#if defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1)
/**
   Sun OS Application - Allocate Memory Space from the OS

\par Implementation
   Allocates a memory block with the standard function "malloc"

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

   if(memSize_byte)
   {
      pMemBlock = (IFX_void_t*)malloc((size_t)memSize_byte);
      IFXOS_SYS_MEM_ALLOC_COUNT_INC(IFX_NULL);
   }

   return (pMemBlock);
}

/**
   Sun OS Application - Free Memory Space

\par Implementation
   Free a memory block with the standard function "free"

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
      free((void*)pMemBlock);
      IFXOS_SYS_MEM_FREE_COUNT_INC(IFX_NULL);
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN, 
         ("WARNING - Cannot <free> NULL pointer" IFXOS_CRLF));
   }

   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) ) */

/** @} */

#endif      /* #if defined(SUN_OS) && !defined(_KERNEL) */

