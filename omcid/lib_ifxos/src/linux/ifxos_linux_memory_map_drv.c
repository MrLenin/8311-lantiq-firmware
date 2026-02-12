/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation, Linux Kernel memory mapping
   ========================================================================= */

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel 
   Physical to Virtual Memory Mapping.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */

#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#include <linux/ioport.h>
#include <asm/io.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_memory_map.h"


/* ============================================================================
   IFX Linux adaptation - Kernel memory map handling
   ========================================================================= */

/** \addtogroup IIFXOS_DRV_MEMORY_MAP_LINUX
@{ */

/**
   LINUX Kernel - Map the physical address to a virtual memory space.
   For virtual memory management this is required.

\par Implementation
   - check if the given physical memory region is free (see "check_mem_region")
   - reserve the given physical memory region (see "request_mem_region")
   - map the given physical memory region - no cache (see "ioremap_nocache")

\attention
   This sequence will reserve the requested memory region, so no following user 
   can remap the same area after this.
\attention
   Other users (driver) which have map the area before (without reservation)
   will still have access to the area.

\param
   physicalAddr         The physical address for mapping [I]
\param
   addrRangeSize_byte   Range of the address space to map [I]
\param
   pName                The name of the address space, for administration [I]
\param
   ppVirtAddr           Returns the pointer to the virtual mapped address [O]

\return
   IFX_SUCCESS if the mapping was successful and the ppVirtAddr is set, else
   IFX_ERROR   if something was wrong.

*/
IFX_int32_t IFXOS_Phy2VirtMap(
               IFX_ulong_t    physicalAddr,
               IFX_ulong_t    addrRangeSize_byte,
               IFX_char_t     *pName,
               IFX_uint8_t    **ppVirtAddr)
{
   IFX_uint8_t *pVirtAddr = IFX_NULL;

   IFXOS_RETURN_IF_POINTER_NULL(ppVirtAddr, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NOT_NULL(*ppVirtAddr, IFX_ERROR);
   IFXOS_RETURN_IF_ARG_LE_ZERO(addrRangeSize_byte, IFX_ERROR);

   if ( check_mem_region(physicalAddr, addrRangeSize_byte) )
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
         ("IFXOS: ERROR Phy2Virt map, region check - addr 0x%08lX (size 0x%lX) not free" IFXOS_CRLF,
           physicalAddr, addrRangeSize_byte));

      return IFX_ERROR;
   }

   /* can't fail */
   request_mem_region(physicalAddr, addrRangeSize_byte, pName);

   /* remap memory (not cache able): physical --> virtual */
   pVirtAddr = (IFX_uint8_t *)ioremap_nocache( physicalAddr,
                                               addrRangeSize_byte );
   if (pVirtAddr == IFX_NULL)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
         ("IFXOS: ERROR Phy2Virt map failed - addr 0x%08lX (size 0x%lX)" IFXOS_CRLF,
           physicalAddr, addrRangeSize_byte));

      release_mem_region(physicalAddr, addrRangeSize_byte);
      return IFX_ERROR;
   }


   IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW,
      ("IFXOS: Phy2Virt map - phy 0x%08lX --> virt 0x%p, size = 0x%lX" IFXOS_CRLF, 
        physicalAddr, pVirtAddr, addrRangeSize_byte ));

   *ppVirtAddr = pVirtAddr;

   return IFX_SUCCESS;
}

/**
   LINUX Kernel - Release the virtual memory range of a mapped physical address.
   For virtual memory management this is required.

\par Implementation
   - unmap the given physical memory region (see "iounmap")
   - release the given physical memory region (see "release_mem_region")

\param
   pPhysicalAddr        Points to the physical address for release mapping [IO]
                        (Cleared if success)
\param
   addrRangeSize_byte   Range of the address space to map [I]
\param
   ppVirtAddr           Provides the pointer to the virtual mapped address [IO]
                        (Cleared if success)

\return
   IFX_SUCCESS if the release was successful. The physicalAddr and the ppVirtAddr 
               pointer is cleared, else
   IFX_ERROR   if something was wrong.
*/
IFX_int32_t IFXOS_Phy2VirtUnmap(
               IFX_ulong_t    *pPhysicalAddr,
               IFX_ulong_t    addrRangeSize_byte,
               IFX_uint8_t    **ppVirtAddr)
{
   /* unmap the virtual address */
   if ( (ppVirtAddr != IFX_NULL) && (*ppVirtAddr != IFX_NULL) )
   {
      IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW,
         ("IFXOS: Phy2Virt Unmap - unmap virt 0x%p, size = 0x%lX" IFXOS_CRLF, 
           (*ppVirtAddr), addrRangeSize_byte ));

      iounmap((void *)(*ppVirtAddr));
      *ppVirtAddr = IFX_NULL;
   }

   /* release the memory region */
   if ( (pPhysicalAddr != IFX_NULL)  && (*pPhysicalAddr != 0) )
   {
      IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW,
         ("IFXOS: Phy2Virt Unmap - release region 0x%08lX size = 0x%lX" IFXOS_CRLF, 
           (*pPhysicalAddr), addrRangeSize_byte ));

      release_mem_region( (unsigned long)(*pPhysicalAddr), addrRangeSize_byte );
      *pPhysicalAddr = 0;
   }

   return IFX_SUCCESS;
}

/** @} */

#ifdef MODULE
EXPORT_SYMBOL(IFXOS_Phy2VirtMap);
EXPORT_SYMBOL(IFXOS_Phy2VirtUnmap);
#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */

