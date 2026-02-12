/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_status.h
*/
#ifndef _drv_optic_ll_status_h
#define _drv_optic_ll_status_h

#ifndef SYSTEM_SIMULATION
#include "drv_optic_api.h"
#include "drv_optic_common.h"
#else
#include "drv_optic_simu.h"
#endif


EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_STATUS_INTERNAL STATUS Module - Internal
   @{
*/

#define OPTIC_DEFAULT_FUSE_VCALMM20          32
#define OPTIC_DEFAULT_FUSE_VCALMM100         32
#define OPTIC_DEFAULT_FUSE_VCALMM400         32
#define OPTIC_DEFAULT_FUSE_RCALMM            128

#define OPTIC_DEFAULT_FUSE_TEMPMM            0
#define OPTIC_DEFAULT_FUSE_TBGP              4
#define OPTIC_DEFAULT_FUSE_VBGP              4
#define OPTIC_DEFAULT_FUSE_IREFBGP           8
#define OPTIC_DEFAULT_FUSE_GAINDRIVEDAC      8
#define OPTIC_DEFAULT_FUSE_GAINBIASDAC       8
#define OPTIC_DEFAULT_FUSE_GAINDRIVEDAC_A22  16
#define OPTIC_DEFAULT_FUSE_GAINBIASDAC_A22   16

#define OPTIC_DEFAULT_FUSE_DCDC_DDR_OFFSET   0
#define OPTIC_DEFAULT_FUSE_DCDC_DDR_GAIN     32
#define OPTIC_DEFAULT_FUSE_DCDC_1V0_OFFSET   0
#define OPTIC_DEFAULT_FUSE_DCDC_1V0_GAIN     32
#define OPTIC_DEFAULT_FUSE_DCDC_APD_OFFSET   0
#define OPTIC_DEFAULT_FUSE_DCDC_APD_GAIN     32

enum optic_errorcode optic_ll_status_fuses_get ( struct optic_fuses *fuses );
enum optic_errorcode optic_ll_status_chip_get ( enum optic_chip *chip );


/*! @} */

/*! @} */

EXTERN_C_END

#endif
