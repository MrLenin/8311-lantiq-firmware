/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_resource_device_psb98030.h
*/
#ifndef _drv_onu_resource_device_psb98030_h
#define _drv_onu_resource_device_psb98030_h

/** \addtogroup ONU_MAPI_REFERENCE
@{
*/

/** \addtogroup ONU_RESOURCE
@{
*/

/**
   This file holds the definitions that are provided to reflect the available
   hardware resources and other limit values that are related to the hardware.
   \remark Changing of any of the values will lead to hardware malfunction.
           These definitions must not be overwritten by other definition files.
*/

#undef ONU_GPE_MAX_GPIX
/** Maximum number of logical ports (GEM port index from 0 to 255)
   One GEM port index (#254) is reserved for OMCI.
   One GEM port index (#255) is reserved for host to lan communication.
*/
#define ONU_GPE_MAX_GPIX                    256

#undef ONU_GPE_MAX_METER
/** Number of available meters/traffic shapers */
#define ONU_GPE_MAX_METER                  256

/** Number of Ethernet UNI ports */
#if !defined(ONU_MAX_ETH_UNI) || (ONU_MAX_ETH_UNI > 4)
#define ONU_GPE_MAX_ETH_UNI                  4
#else
#define ONU_GPE_MAX_ETH_UNI ONU_MAX_ETH_UNI
#endif

#undef ONU_GPE_MAX_BRIDGE_PORT
/** Number of available bridge ports */
#define ONU_GPE_MAX_BRIDGE_PORT            126

#undef ONU_GPE_MAX_VOICE_UNI
/** Number of Voice UNI ports */
#define ONU_GPE_MAX_VOICE_UNI               0

/*! @} */

/* end ONU_RESOURCE */

/*! @} */

#endif
