#ifndef _IFXOS_ECOS_MEM_ALLOC_H
#define _IFXOS_ECOS_MEM_ALLOC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for Memory handling.
*/

/** \defgroup IFXOS_MEMORY_ECOS Memory Handling (eCos)

   This Group contains the eCos memory allocation and mapping definitions and  
   function. 

   Here we have to differ between:\n
   - memory handling on application space.
   - memory handling on driver space.

\par Driver Space
   There are several special memory handling functions which makes only sence
   in driver space.
   - Allocation of an continious memory block (HW interfaces).
   - Physical to virtual address mapping.
   - Data exchange between user and driver space (copy from/to user).

\note
   This split comes up with the LINUX OS. Under LINUX the user and Kernel space are 
   independant. 
   Further it makes sence to handle driver related fucntions seperatly.

\ingroup IFXOS_LAYER_ECOS
*/

/** \defgroup IFXOS_MEM_ALLOC_ECOS Memory Allocation (eCos).

   This Group contains the eCos Memory Allocation definitions.

\par Implementation - Memory allocation
   Within eCos there is no special handling for allocation a continious 
   memory block. So the standard malloc function is used for all adaptations.

\ingroup IFXOS_MEMORY_ECOS
*/


/** \defgroup IFXOS_CPY_USER_SPACE_ECOS_DRV Data Exchange, Driver and User Space (eCos).

   This Group contains the eCos definitions for data exchange between 
   driver and application.

\par Implementation
   Under eCos no special handling for Data Exchange between driver and user
   space is required. But such a border makes sence we provide the corresponding 
   IFXOS Layer functions for compatibility.

   For data exchange the standard memcpy function is used.

\ingroup IFXOS_MEMORY_ECOS
*/

/** \defgroup IFXOS_MEMORY_MAP_ECOS_DRV Physical to Virtual Address Mapping (eCos).

   This Group contains the eCos definitions for Physical to 
   Virtual Address Mapping.

\par Implementation
   Under eCos no special handling for Physical to Virtual Address Mapping is 
   required (no Virtual Memory Management).
   To keep the compatibility wihtin the driver code we provide the corresponding 
   IFXOS Layer functions.
   For the mapping the phsyical address is simply assigned.

\ingroup IFXOS_MEMORY_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - support "mem alloc" */
#ifndef IFXOS_HAVE_BLOCK_ALLOC
#  define IFXOS_HAVE_BLOCK_ALLOC                   1
#endif

/** IFX eCos adaptation - support "virtual mem alloc" */
#ifndef IFXOS_HAVE_MEM_ALLOC
#  define IFXOS_HAVE_MEM_ALLOC                     1
#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_MEM_ALLOC_H */


