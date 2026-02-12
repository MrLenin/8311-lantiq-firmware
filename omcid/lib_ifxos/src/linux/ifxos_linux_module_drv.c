/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX OS adaptation, Linux Kernel copy form and to user
   ========================================================================= */

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel 
   Basic module setup and module load.
*/

#ifdef IFXOS_DEBUG
#  define IFXOS_STATIC
#else
#  define IFXOS_STATIC   static
#endif

/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */

#ifdef __KERNEL__
#  include <linux/kernel.h>
#endif
#ifdef MODULE
#  include <linux/module.h>
#endif

#include <linux/version.h>
#include <linux/init.h>

#include "ifxos_debug.h"

#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
#  include "ifxos_sys_show.h"
#endif

/* ============================================================================
   IFX Linux adaptation - module handling
   ========================================================================= */

IFXOS_STATIC int __init IFXOS_ModuleInit (void);
IFXOS_STATIC void __exit IFXOS_ModuleExit (void);


/* install parameter debug_level: LOW (1), NORMAL (2), HIGH (3), OFF (4) */
#if (    (IFXOS_USE_DEBUG_USR_PRINT == 1) \
      || (IFXOS_USE_ERROR_USR_PRINT == 1) \
      || (IFXOS_USE_DEBUG_INT_PRINT == 1) \
      || (IFXOS_USE_ERROR_INT_PRINT == 1) )

IFXOS_STATIC IFX_uint8_t debug_level = IFXOS_PRN_LEVEL_HIGH;
#else
IFXOS_STATIC IFX_uint8_t debug_level = IFXOS_PRN_LEVEL_OFF;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
MODULE_PARM(debug_level, "b");
#else
module_param(debug_level, byte, 0);
#endif
MODULE_PARM_DESC(debug_level, "set to get more (1) or fewer (4) debug outputs");

const char IFXOS_WHATVERSION[] = IFXOS_WHAT_STR;

/** \addtogroup IFXOS_IF_LINUX_DRV
@{ */

/**
   Initialize the module
 
\return
   Error code or 0 on success
\remark
   Called by the kernel.
*/
IFXOS_STATIC int __init IFXOS_ModuleInit (void)
{
   printk(KERN_INFO "%s (c) Copyright 2009, Lantiq Deutschland GmbH" IFXOS_CRLF, &IFXOS_WHATVERSION[4]);

   IFXOS_PRN_USR_LEVEL_SET(IFXOS, debug_level);
   IFXOS_PRN_INT_LEVEL_SET(IFXOS, debug_level);

   /*
      If required do the basic init here
   */

#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
   IFXOS_SYS_OBJECT_SETUP(0);
#endif

   return 0;
}

/**
   Clean up the module if unloaded.
 
   \remark
   Called by the kernel.
*/
IFXOS_STATIC void __exit IFXOS_ModuleExit (void)
{
   /*
      If required do the basic cleanup here
   */

#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
   IFXOS_SYS_OBJECT_CLEANUP(0);
#endif

   return;
}


/** @} */


/*
   register module init and exit
*/
module_init (IFXOS_ModuleInit);
module_exit (IFXOS_ModuleExit);

#if ( (IFXOS_USE_DEBUG_USR_PRINT == 1) || (IFXOS_USE_ERROR_USR_PRINT == 1) )
EXPORT_SYMBOL(IFXOS_PRN_USR_MODULE_NAME(IFXOS));
#endif

#if ( (IFXOS_USE_DEBUG_INT_PRINT == 1) || (IFXOS_USE_ERROR_INT_PRINT == 1) )
EXPORT_SYMBOL(IFXOS_PRN_INT_MODULE_NAME(IFXOS));
#endif


/****************************************************************************/

MODULE_AUTHOR("www.lantiq.com");
MODULE_DESCRIPTION("IFX - OS abstraction layer");
MODULE_LICENSE("Dual BSD/GPL");

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */

