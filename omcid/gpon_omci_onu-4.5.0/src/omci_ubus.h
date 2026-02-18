/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_ubus_h
#define _omci_ubus_h

#include "omci_interface.h"

/** \defgroup OMCI_UBUS OMCI ubus integration
    @{
*/

/** Initialize ubus event monitoring.

    Connects to ubusd via dlopen'd libubus.so and registers for
    "network.interface" events. On ifup, triggers IP Host Config Data
    (ME 134) attribute refresh via omci_net_iface_state_cb.

    All library symbols are resolved at runtime via dlopen/dlsym.
    If libubus.so or libubox.so are not available, logs a warning
    and returns success (ubus integration silently disabled).

    \param[in] context OMCI context pointer

    \return OMCI_SUCCESS (always — failure is non-fatal)
*/
enum omci_error omci_ubus_init(struct omci_context *context);

/** Shut down ubus event monitoring.

    Stops the polling thread, drains the event queue, disconnects
    from ubusd, and unloads the dlopen'd libraries.

    \param[in] context OMCI context pointer
*/
void omci_ubus_exit(struct omci_context *context);

/** @} */

#endif
