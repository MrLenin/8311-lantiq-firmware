/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(WIN32) && !defined(NUCLEUS_PLUS)

/** \file
   This file contains the IFXOS Layer implementation for Win32 - 
   Memory Allocation.
*/

/* ============================================================================
   IFX Win32 adaptation - Global Includes
   ========================================================================= */
#include <stdlib.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "ifx_types.h"
#include "ifxos_memory_alloc.h"

#include "ifxos_sys_show.h"

IFX_ulong_t gAllocs=0;
IFX_int_t bInit = 0;
CRITICAL_SECTION CriticalSection; 

/* ============================================================================
   IFX Win32 adaptation - memory handling, malloc
   ========================================================================= */

/** \addtogroup IFXOS_MEM_ALLOC_WIN32
@{ */

#if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) )
/**
   Win32 - Allocate a continious memory block of the given size [byte]

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

   pMemBlock = (IFX_void_t *)malloc((size_t)memSize_byte + sizeof(IFX_ulong_t));
   if (pMemBlock == IFX_NULL)
	   return IFX_NULL;

   *((IFX_ulong_t*)(pMemBlock)) = memSize_byte;
   
   if(bInit==0) {
      InitializeCriticalSection(&CriticalSection);
      bInit = 1;
   }

   EnterCriticalSection(&CriticalSection); 
   gAllocs += memSize_byte;
   LeaveCriticalSection(&CriticalSection);

   return (((IFX_uint8_t*)(pMemBlock)) + sizeof(IFX_ulong_t));
}

/**
   Win32 - Free the given memory block.

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
      EnterCriticalSection(&CriticalSection); 
      gAllocs -= *( (IFX_ulong_t*)(((IFX_uint8_t*)(pMemBlock)) - sizeof(IFX_ulong_t)) );
      LeaveCriticalSection(&CriticalSection);

      free((void*)(((IFX_uint8_t*)(pMemBlock)) - sizeof(IFX_ulong_t)));
   }

   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) ) */


#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
/**
   Win32 - Allocate Memory Space from the OS

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

   pMemBlock = (IFX_void_t*)malloc((size_t)memSize_byte + sizeof(IFX_ulong_t));
   if (pMemBlock == IFX_NULL)
	   return IFX_NULL;

   *((IFX_ulong_t*)(pMemBlock)) = memSize_byte;

   if(bInit==0) {
      InitializeCriticalSection(&CriticalSection);
      bInit = 1;
   }
   
   EnterCriticalSection(&CriticalSection); 
   IFXOS_SYS_MEM_ALLOC_COUNT_INC(IFX_NULL);
   gAllocs += memSize_byte;
   LeaveCriticalSection(&CriticalSection);

   return ((((IFX_uint8_t*)(pMemBlock)) + sizeof(IFX_ulong_t)));
}

/**
   Win32 - Free Memory Space

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
      EnterCriticalSection(&CriticalSection); 
      IFXOS_SYS_MEM_FREE_COUNT_INC(IFX_NULL);
      gAllocs -= *((IFX_ulong_t*)(((IFX_uint8_t*)(pMemBlock)) - sizeof(IFX_ulong_t)));
      LeaveCriticalSection(&CriticalSection);

      free((void*)(((IFX_uint8_t*)(pMemBlock)) - sizeof(IFX_ulong_t)));
   }

   return;
}

#endif      /* #if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) ) */

/** @} */

#endif      /* #ifdef WIN32 */

