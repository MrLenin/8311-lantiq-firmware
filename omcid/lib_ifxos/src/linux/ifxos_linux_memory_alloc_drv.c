/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - memory allocation (Kernel Space)
   ========================================================================= */

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel 
   Memory Allocation.
*/

#ifndef IFXOS_LOCAL_CHECK
#  define IFXOS_LOCAL_CHECK               0
#else
#  undef  IFXOS_LOCAL_CHECK
#  define IFXOS_LOCAL_CHECK               1
#endif

/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */

#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "ifx_types.h"
#include "ifxos_linux_drv.h"
#include "ifxos_debug.h"
#include "ifxos_memory_alloc.h"

#if (IFXOS_LOCAL_CHECK == 1)
#  if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
#     include <linux/hardirq.h>
#  else
#     include <asm/hardirq.h>
#  endif
#endif


/* ============================================================================
   IFX Linux adaptation - Kernel memory handling, malloc
   ========================================================================= */

/** \addtogroup IFXOS_MEM_ALLOC_LINUX_DRV
@{ */

#if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) )

/**
   LINUX Kernel - Allocate a continious memory block of the given size [byte]
\par Implementation
   - Allocates a continious memory block with the kernel function "kmalloc"
   - The option "GFP_KERNEL" is used for normal kernel allocation (may sleep)
   - This implementaion is not allowded on interrupt level (may sleep)

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

#if (IFXOS_LOCAL_CHECK == 1)
   if (in_interrupt())
   {
      IFXOS_PRN_INT_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
         ("ERROR - kmalloc call within interrupt" IFXOS_CRLF));
      return (pMemBlock);
   }
#endif

   if(memSize_byte)
      pMemBlock = (IFX_void_t *)kmalloc((unsigned int)memSize_byte, GFP_KERNEL);

   return (pMemBlock);
}

/**
   LINUX Kernel - Free the given memory block.
\par Implementation
   Free a continious memory block with the kernel function "kfree"

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
      kfree((void*)pMemBlock);
   }
   else
   {
      IFXOS_PRN_INT_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
         ("WARNING - Cannot free NULL pointer" IFXOS_CRLF));
   }

   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_BLOCK_ALLOC) && (IFXOS_HAVE_BLOCK_ALLOC == 1) ) */


#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
/**
   LINUX Kernel - Allocate Memory Space from the OS

\par Implementation
   Allocates a memory block with the kernel function "vmalloc"

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
      pMemBlock = (IFX_void_t*)vmalloc((unsigned long)memSize_byte);

   return (pMemBlock);
}

/**
   LINUX Kernel - Free Memory Space
\par Implementation
   Free a memory block with the kernel function "vfree"

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
      vfree((void*)pMemBlock);
   }
   else
   {
      IFXOS_PRN_INT_ERR_NL(IFXOS, IFXOS_PRN_LEVEL_WRN, 
         ("WARNING - Cannot vfree NULL pointer" IFXOS_CRLF));
   }

   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) ) */

/** @} */

#ifdef MODULE
EXPORT_SYMBOL(IFXOS_BlockAlloc);
EXPORT_SYMBOL(IFXOS_BlockFree);
EXPORT_SYMBOL(IFXOS_MemAlloc);
EXPORT_SYMBOL(IFXOS_MemFree);
#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */

