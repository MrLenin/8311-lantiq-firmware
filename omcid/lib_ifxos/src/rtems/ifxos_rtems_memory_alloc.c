/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains the IFXOS Layer implementation for
   RTEMS Memory Allocation.
*/

/* ============================================================================
   RTEMS Adaptation Frame - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_debug.h"


/* ============================================================================
   RTEMS Adaptation Frame - memory handling, malloc
   ========================================================================= */

/** \addtogroup IFXOS_MEM_ALLOC_RTEMS
@{ */

#if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) )

static unsigned int memName = 0;

/**
   RTEMS - Allocate a continious memory block of the given size [byte]

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
#ifdef DSL_USE_MEM_POOL

   void *memory_ptr = NULL;
   IFXOS_RETURN_IF_ARG_LE_ZERO(memSize_byte, IFX_NULL);
   xm_getmem (memSize_byte,&memory_ptr);
   return (IFX_void_t *) memory_ptr;


#else

   void *memory_ptr;
   char name[4];
   IFXOS_RETURN_IF_ARG_LE_ZERO(memSize_byte, IFX_NULL);
   xt_entercritical();
   memName++;
   xt_exitcritical();
   sprintf(name, "%x", memName);
   xm_alloc( name, XM_USER_UNDEF_MEM, (size_t)memSize_byte,&memory_ptr);
   return (IFX_void_t *) memory_ptr;

#endif
}

/**
   RTEMS - Free the given memory block.

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
#ifdef DSL_USE_MEM_POOL
   unsigned long error;
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pMemBlock, IFX_ERROR);
   error = xm_retmem(pMemBlock);
   return;


#else

   //xfree((void*)pMemBlock);
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pMemBlock, IFX_ERROR);
   xm_dealloc(pMemBlock);
   return;

#endif
}
#endif      /* #if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) ) */


#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
/**
   RTEMS - Allocate Memory Space from the OS

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
#ifdef DSL_USE_MEM_POOL
   void *memory_ptr = NULL;
   IFXOS_RETURN_IF_ARG_LE_ZERO(memSize_byte, IFX_NULL);
   //xm_alloc( name, XM_USER_UNDEF_MEM, (size_t)memSize_byte,&memory_ptr);
   xm_getmem (memSize_byte,&memory_ptr);
   return (IFX_void_t *) memory_ptr;
#else

   void *memory_ptr;
   char name[4];
   IFXOS_RETURN_IF_ARG_LE_ZERO(memSize_byte, IFX_NULL);
   xt_entercritical();
   memName++;
   xt_exitcritical();
   sprintf(name, "%x", memName);
   xm_alloc( name, XM_USER_UNDEF_MEM, (size_t)memSize_byte,&memory_ptr);
   return (IFX_void_t *) memory_ptr;

#endif

}

/**
   RTEMS - Free Memory Space

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

#ifdef DSL_USE_MEM_POOL


   unsigned long error;
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pMemBlock, IFX_ERROR);
   error = xm_retmem(pMemBlock);
   return;

#else

   IFXOS_RETURN_VOID_IF_POINTER_NULL(pMemBlock, IFX_ERROR);
    xm_dealloc(pMemBlock);
   return;

#endif
}

#endif      /* #if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) ) */

/** @} */

#endif      /* #ifdef RTEMS */

