/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFXOS - version handling
   ========================================================================= */

/* ============================================================================
   Includes
   ========================================================================= */
#include "ifx_types.h"
#include "ifxos_version.h"

/* ============================================================================
   IFXOS - Version handling
   ========================================================================= */

/**
   Return IFX OS version information.

   \param
    revisionNum   - revision number to be checked
\param
    featureNum    - feature number to be checked
\param
    stepNum       - step number to be checked

   \remark
   Called by the kernel.
*/
IFX_void_t IFXOS_versionGet(
                     IFX_uint8_t *pRevision, 
                     IFX_uint8_t *pFeature, 
                     IFX_uint8_t *pStep)
{
   if (pRevision)
      *pRevision = IFXOS_VERSION_REVISION;

   if (pFeature)
      *pFeature = IFXOS_VERSION_FEATURE;

   if (pStep)
      *pStep = IFXOS_VERSION_STEP;

   return;
}

/**
   This function checks if the IFXOS Version is the same like the given version.
   
\param
    revisionNum   - revision number to be checked
\param
    featureNum    - feature number to be checked
\param
    stepNum       - step number to be checked

\return
   IFX_TRUE    the IFXOS Version is the same like the given version.
   IFX_FALSE   the IFXOS Version is not the same like the given version.
*/
IFX_boolean_t  IFXOS_versionCheck_equal(
                     IFX_uint8_t revisionNum,
                     IFX_uint8_t featureNum,
                     IFX_uint8_t stepNum)
{
   if (    (IFXOS_VERSION_REVISION == revisionNum)
        && (IFXOS_VERSION_FEATURE  == featureNum)
        && (IFXOS_VERSION_STEP     == stepNum) )
   {
      return IFX_TRUE;
   }

   return IFX_FALSE;
}

/**
   This function checks if the IFXOS Version is the equal/greater than the given version.
   
\param
    revisionNum   - revision number to be checked
\param
    featureNum    - feature number to be checked
\param
    stepNum       - step number to be checked

\return
   IFX_TRUE    the IFXOS Version is equal/greater than the given version.
   IFX_FALSE   the IFXOS Version is less than the given version.
*/
IFX_boolean_t  IFXOS_versionCheck_egThan(
                     IFX_uint8_t revisionNum,
                     IFX_uint8_t featureNum,
                     IFX_uint8_t stepNum)
{
   if (    (IFXOS_VERSION_REVISION == revisionNum)
        && (    (IFXOS_VERSION_FEATURE >  featureNum) 
             || ((IFXOS_VERSION_FEATURE == featureNum) && (IFXOS_VERSION_STEP >= stepNum)) ))
   {
      return IFX_TRUE;
   }

   return IFX_FALSE;
}

/**
   This function checks if the IFXOS Version is less than the given version.
   
\param
    revisionNum   - revision number to be checked
\param
    featureNum    - feature number to be checked
\param
    stepNum       - step number to be checked

\return
   IFX_TRUE    the IFXOS Version is less than the given version.
   IFX_FALSE   the IFXOS Version is not less than the given version.
*/
IFX_boolean_t  IFXOS_versionCheck_lessThan(
                     IFX_uint8_t revisionNum,
                     IFX_uint8_t featureNum,
                     IFX_uint8_t stepNum)
{
   if (    (IFXOS_VERSION_REVISION <= revisionNum)
        && (    (IFXOS_VERSION_FEATURE <  featureNum) 
             || ((IFXOS_VERSION_FEATURE == featureNum) && (IFXOS_VERSION_STEP < stepNum)) ))
   {
      return IFX_TRUE;
   }

   return IFX_FALSE;
}


#if defined(LINUX) && defined(__KERNEL__) && defined(MODULE)
#  include <linux/kernel.h>
#  include <linux/module.h>

EXPORT_SYMBOL(IFXOS_versionGet);
EXPORT_SYMBOL(IFXOS_versionCheck_equal);
EXPORT_SYMBOL(IFXOS_versionCheck_egThan);
EXPORT_SYMBOL(IFXOS_versionCheck_lessThan);

#endif

