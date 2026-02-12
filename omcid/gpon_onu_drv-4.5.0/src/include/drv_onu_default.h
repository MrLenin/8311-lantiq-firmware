/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_default.h
*/
#ifndef _ifx_gpon_default_h
#define _ifx_gpon_default_h

/** \defgroup ONU_DEFAULT GPON Modem Default Values

    This chapter provides standard default values.
    These values are used if no application-specific defaults are defined.
@{
*/

/** GPON reassembly timeout limit */
#ifndef GPON_DEFAULT_REASSEMBLY_TIMEOUT_VALUE
#define GPON_DEFAULT_REASSEMBLY_TIMEOUT_VALUE       0
#endif

/** Maximum Ethernet frame size */
#ifndef GPON_DEFAULT_MAX_ETHERNET_FRAME_LENGTH
#define GPON_DEFAULT_MAX_ETHERNET_FRAME_LENGTH   1518
#endif

/** Maximum IP frame size */
#ifndef GPON_DEFAULT_MAX_IP_FRAME_LENGTH
#define GPON_DEFAULT_MAX_IP_FRAME_LENGTH        0xFFFF
#endif

/** Maximum MPLS frame size */
#ifndef GPON_DEFAULT_MAX_MPLS_FRAME_LENGTH
#define GPON_DEFAULT_MAX_MPLS_FRAME_LENGTH      0xFFFF
#endif

/*! @} */

/* end ONU_DEFAULT */

/*! @} */

#endif
