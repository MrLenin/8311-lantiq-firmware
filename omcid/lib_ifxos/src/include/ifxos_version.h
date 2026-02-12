/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _IFXOS_VERSION_H
#define _IFXOS_VERSION_H

/** \file
   This file contains the version and the corresponding check definitions for the IFX OS.

*/


/**
   The version of the IFXOS is seperated into 3 numbers:
   "<interface revision> . <feature step> . <build step>"


   - Interface Revision:
      The interface revision defines a IFXOS API version. The revision number
      will only change if the existing IFXOS API is changed and the functions are
      not anymore backward compatible.

      Example:
      An already existing function gets an new parameter.

      \attention
         If a new API function is added this requires no change of the revision
         number. Therefore the feature step will be incremented.

   - Feature Step:
      The number defines the current IFXOS API features. The number will change if
      new features have been added and the existing API is not changed.

      Example:
      Add additional socket functions - the available functions are unchenged.

   - Build Step:
      The build step is incremented for internal bugfixes and minor changes.
      Fixes and minor changes will have no influence to the IFXOS header files.
      No recompilation of the user applications required.


   Example Compile-Time:
      How to check for a required version (minimum 1.0.2) and then
      check the version (> 1.1.0) to decide which features are supported.

   \code

   #if defined(IFXOS_HAVE_VERSION_CHECK)
   #  if (!IFXOS_VERSION_CHECK_EG_THAN(1,0,2))
   #     error "IFXOS_VERSION_CHECK: requiere at least IFX OS version 1.2.0"
   #  endif
   #endif

   #if defined(IFXOS_HAVE_VERSION_CHECK)
   #  if (IFXOS_VERSION_CHECK_EG_THAN(1,1,0))
   #     define IFXOS_SUPPORTS_FIFO_PEEK                 1
   #  else
   #     define IFXOS_SUPPORTS_FIFO_PEEK                 0
   #  endif
   #endif

   \endcode

\ingroup IFXOS_COMMON

*/


#ifdef __cplusplus
   extern "C" {
#endif

/* ==========================================================================
   Includes
   ========================================================================== */
#include "ifx_types.h"


/* ==========================================================================
   IFXOS Version defs
   ========================================================================== */

/* versio check is available */
#define IFXOS_HAVE_VERSION_CHECK       1


#ifndef _MKSTR_1
#define _MKSTR_1(x)    #x
#define _MKSTR(x)      _MKSTR_1(x)
#endif

/** IFXOS version, base name */
#define IFXOS_BASE_NAME                "IFXOS"

/** IFXOS version - Interface revision */
#define IFXOS_VERSION_REVISION                1
/** IFXOS version - feature */
#define IFXOS_VERSION_FEATURE                 5
/** IFXOS version, build number - step */
#define IFXOS_VERSION_STEP                    19

/** IFXOS version as number */
#define IFXOS_VER_NUMBER \
            ((IFXOS_VERSION_REVISION << 16) || (IFXOS_VERSION_FEATURE << 8) || (IFXOS_VERSION_STEP))

/** IFXOS version as string */
#define IFXOS_VER_STR \
            _MKSTR(IFXOS_VERSION_REVISION) "." _MKSTR(IFXOS_VERSION_FEATURE) "." _MKSTR(IFXOS_VERSION_STEP)

/** IFXOS version, what string */
#define IFXOS_WHAT_STR "@(#)" IFXOS_BASE_NAME ", Version " IFXOS_VER_STR


/* ==========================================================================
   IFXOS Version checks
   ========================================================================== */
/**
   Version Check - equal with the given version
*/
#define IFXOS_VERSION_CHECK_EQ(revision, feature, step) \
               ((IFXOS_VERSION_REVISION == revision) && (IFXOS_VERSION_FEATURE == feature) && (IFXOS_VERSION_STEP == step) )

/**
   Version Check - less than given version
   - revison number must match and
     --> feature number must be less or
     --> step number must be less if feature is the same.
*/
#define IFXOS_VERSION_CHECK_L_THAN(revision, feature, step) \
               (     (IFXOS_VERSION_REVISION <= revision) \
                 &&  (   (IFXOS_VERSION_FEATURE < feature) \
                      || ((IFXOS_VERSION_FEATURE == feature) && (IFXOS_VERSION_STEP < step)) ))

/**
   Version Check - equal or greater than given version
   - revison number must match and
     --> feature number must be greater or
     --> step number must be greater if feature is the same.
*/
#define IFXOS_VERSION_CHECK_EG_THAN(revision, feature, step) \
               (     (IFXOS_VERSION_REVISION == revision) \
                 &&  (   (IFXOS_VERSION_FEATURE > feature) \
                      || ((IFXOS_VERSION_FEATURE == feature) && (IFXOS_VERSION_STEP >= step)) ))


/* ==========================================================================
   IFXOS Version - functions
   ========================================================================== */
IFX_void_t IFXOS_versionGet(
                     IFX_uint8_t *revision,
                     IFX_uint8_t *feature,
                     IFX_uint8_t *step);

IFX_boolean_t  IFXOS_versionCheck_equal(
                     IFX_uint8_t revisionNum,
                     IFX_uint8_t featureNum,
                     IFX_uint8_t stepNum);

IFX_boolean_t  IFXOS_versionCheck_egThan(
                     IFX_uint8_t revisionNum,
                     IFX_uint8_t featureNum,
                     IFX_uint8_t stepNum);

IFX_boolean_t  IFXOS_versionCheck_lessThan(
                     IFX_uint8_t revisionNum,
                     IFX_uint8_t featureNum,
                     IFX_uint8_t stepNum);


/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_VERSION_H */

