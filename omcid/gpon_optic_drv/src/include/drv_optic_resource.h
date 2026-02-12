/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file "LICENSE" in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_resource.h
   This file contains common definitions that describe hardware resources
   used by the FALC(tm) ON Optic Driver.
*/
#ifndef _drv_optic_resource_h
#define _drv_optic_resource_h

/**
   This file holds the definitions that are provided to reflect the available
   resources and other limit values that are related to the implementation.
   \remark Changing of any of these values will lead to system malfunction if
           the hardware does not support the assigned value(s)!
*/

/** Device identification for PSB98010 */
#define OPTIC_DEVICE_PSB98010 10
/** Device identification for PSB98020 */
#define OPTIC_DEVICE_PSB98020 20
/** Device identification for PSB98030 */
#define OPTIC_DEVICE_PSB98030 30
/** Device identification for FPGA */
#define OPTIC_DEVICE_FPGA     99

/** Select one of the available device types that matches the target hardware:
   - PSB98010
   - PSB98020
   - PSB98030
   - FPGA

   \remark Selection of a device type that does not match the target hardware
           will lead to system malfunction.
*/
#ifndef OPTIC_DEVICE_PSB980xx
#define OPTIC_DEVICE_PSB980xx OPTIC_DEVICE_FPGA
#endif



/** Maximum number of ADCs,
    th eADCs are numbered 0 to OPTIC_GOI_MAX_ADC - 1 */
#ifndef OPTIC_GOI_MAX_ADC
#define OPTIC_GOI_MAX_ADC 10
#endif

/** Maximum number of weight factors for ADC filtering */
#ifndef OPTIC_GOI_ADC_WEIGHT_FACTORS
#define OPTIC_GOI_ADC_WEIGHT_FACTORS 16
#endif



#endif
