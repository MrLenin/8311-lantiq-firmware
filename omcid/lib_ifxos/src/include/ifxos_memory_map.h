#ifndef _IFXOS_DRV_MEMORY_MAP_H
#define _IFXOS_DRV_MEMORY_MAP_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for memory mapping between phsyical and virtual
   address space.
*/

/** \defgroup IFXOS_IF_DRV_MEMORY_MAP Physical and Virtual Address Mapping.

   Because some operating system use a virual memory management we introduce this
   functions for compatibility. The goal is to make a physical memory block (like a 
   HW interface) visible within the OS.
   From functional point of view the mapping of physical to virtual space is similar
   to the memory allocation with the difference that no "real memory" have to 
   be allocated. Only the administration has to be done like add an entry into 
   the memory management tables and so on.

\note
   This issue is mostly HW related, so this functionality is related 
   to the driver code

\ingroup IFXOS_IF_MEMORY
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Global Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - copy between user and driver space.
   ========================================================================= */

/** \addtogroup IFXOS_IF_DRV_MEMORY_MAP
@{ */

/**
   Map the physical address to a virtual memory space.
   For virtual memory management this is required.

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

\remark
   This function depends on the used OS and also the used controller.
*/
IFX_int32_t IFXOS_Phy2VirtMap(
               IFX_ulong_t    physicalAddr,
               IFX_ulong_t    addrRangeSize_byte,
               IFX_char_t     *pName,
               IFX_uint8_t    **ppVirtAddr);

/**
   Release the virtual memory range of a mapped physical address.
   For virtual memory management this is required.

\param
   pPhysicalAddr        Points to the physical address for release mapping [IO]
                        (Cleared if success)
\param
   addrRangeSize_byte   Range of the address space to map [I]
\param
   ppVirtAddr           Provides the pointer to the virtual mapped address [IO]
                        (Cleared if success)

\return
   IFX_SUCCESS if the release was successful. 
               The physicalAddr and the ppVirtAddr pointer is cleared, else
   IFX_ERROR   if something was wrong.
*/
IFX_int32_t IFXOS_Phy2VirtUnmap(
               IFX_ulong_t    *pPhysicalAddr,
               IFX_ulong_t    addrRangeSize_byte,
               IFX_uint8_t    **ppVirtAddr);

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_DRV_MEMORY_MAP_H */

