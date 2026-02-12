/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_onu2_g_h
#define _omci_onu2_g_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_DOT1X_PORT_EXTENSION_PACKAGE Dot1X port extension package Managed Entity

    An instance of this managed entity represents a set of attributes that
    control a port’s 802.1X operation. It is created and deleted autonomously by
    the ONU upon creation or deletion of a PPTP that supports [IEEE 802.1X]
    authentication of CPE.
    Relationships:
    An instance of this managed entity is associated with a physical path
    termination point that performs IEEE 802.1X authentication of CPE (eg
    Ethernet or DSL).

    @{
*/

/** This structure holds the attributes of the Dot1X port extension package
    Managed Entity. */
struct omci_me_dot1x_port_ext_pkg {
	/** Dot1x enable.
	    If true, this boolean attribute forces the associated port to
	    authenticate via 802.1X as a precondition of normal service.
	    The default value false does not impose 802.1X authentication on the
	    associated port. (R, W) (mandatory) (1 byte) */
	uint8_t dot1x_enable;
	/** Action register.
	    This attribute defines a set of actions that can be performed on the
	    associated port. The act of writing to the register causes
	    the specified action.

		1 -  Force re-authentication – this opcode initiates an 802.1X
		     re- authentication conversation with the associated port.
		     The port remains in its current authorization state until
		     the conversation concludes.
		2 - Force unauthenticated – this opcode initiates an 802.1X
		    authentication conversation whose outcome is predestined to
		    fail, thereby disabling normal Ethernet service on the port.
		    The port’s provisioning is not changed, such that upon
		    re-initialization, a new 802.1X conversation may restore
		    service without prejudice.
		3 - Force authenticated – this opcode initiates an 802.1X
		    authentication conversation whose outcome is predestined to
		    succeed, thereby unconditionally enabling normal Ethernet
		    service on the port. The port’s provisioning is not changed,
		    such that upon re-initialization, a new 802.1X conversation
		    is required.
	    (W) (mandatory) (1 byte) */
	uint8_t action_register;
	/** Authenticator PAE state.
	    This attribute returns the value of the port’s PAE state. States are
	    further described in [IEEE 802.1X]. Values are coded as shown below. 
		0 - Initialize 
		1 - Disconnected 
		2 - Connecting 
		3 - Authenticating 
		4 - Authenticated 
		5 - Aborting 
		6 - Held 
		7 - Force auth 
		8 - Force unauth 
		9 - Restart 
	    (R) (optional) (1 byte) */
	uint8_t auth_pae_state;
	/** Backend authentication state.
	    This attribute returns the value of the port’s back-end
	    authentication state. States are further described in [IEEE 802.1X].
	    Values are coded as shown below. 
		0 - Request  
		1 - Response  
		2 - Success  
		3 - Fail  
		4 - Timeout  
		5 - Idle  
		6 - Initialize  
		7 - Ignore 
		(R) (optional) (1 byte) */
	uint8_t backend_auth_state;
	/** Admin controlled directions.
	    This attribute controls the directionality of the port’s
	    authentication requirement. The default value 0 indicates that
	    control is imposed in both directions. The value 1 indicates that
	    control is imposed only on traffic from the subscriber toward the
	    network. (R, W) (optional) (1 byte) */
	uint8_t admin_controlled_dirs;
	/** Operational controlled directions.
	    This attribute indicates the  directionality of the port’s
	    current authentication state. The value 0 indicates that control is
	    imposed in both directions. The value 1 indicates that control is
	    imposed only on traffic from the subscriber toward the network.
	    (R) (optional) (1 byte) */
	uint8_t op_controlled_dirs;
	/** Authenticator controlled port status.
	    This attribute indicates whether the controlled port is currently
	    authorized (1) or unauthorized (2). (R) (optional) (1 byte) */
	uint8_t auth_controlled_port_status;
	/** Quiet period.
	    This attribute specifies the interval between EAP request/identity
	    invitations sent to the peer. Other events such as carrier present
	    or EAPOL start frames from the peer may trigger an EAP
	    request/identity frame from the ONU at any time; this attribute
	    controls the ONU’s periodic behaviour in the absence of these other
	    inputs. It is expressed in seconds. (R, W) (optional) (2 bytes) */
	uint16_t quiet_period;
	/** Server timeout period.
	    This attribute specifies the time the ONU will wait for a response
	    from the radius server before timing out. Within this maximum
	    interval, the ONU may initiate several retransmissions with
	    exponentially increasing delay. Upon timeout, the ONU may try
	    another radius server if there is one, or invoke the fallback
	    policy, if no alternate radius servers are available. Server
	    timeout is expressed in seconds, with a default value of 30 and a
	    maximum value of 65535. (R, W) (optional) (2 bytes) */
	uint16_t server_timeout_period;
	/** Re-authentication period.
	    This attribute records the re-authentication interval specified by
	    the radius authentication server. It is expressed in seconds.
	    The attribute is only meaningful after a port has been
	    authenticated. (R) (optional) (2 bytes) */
	uint16_t re_auth_period;
	/** Re-authentication enabled.
	    This boolean attribute records whether the radius authentication
	    server has enabled re-authentication on this service (true) or not
	    (false). The attribute is only meaningful after a port has been
	    authenticated. (R) (optional) (1 byte) */
	uint8_t re_auth_enabled;
	/** Key transmission enabled.
	    This boolean attribute indicates whether key transmission is
	    enabled (true) or not (false). This feature is not required;
	    the parameter is listed here for completeness vis-à-vis 802.1X.
	    (R, W) (optional) (1 byte) */
	uint8_t key_tx_enabled;
} __PACKED__;

/** This enumerator holds the attribute numbers of the ONU2-G Managed Entity.
*/
enum {
	omci_me_dot1x_port_ext_pkg_dot1x_enable = 1,
	omci_me_dot1x_port_ext_pkg_action_register = 2,
	omci_me_dot1x_port_ext_pkg_auth_pae_state = 3,
	omci_me_dot1x_port_ext_pkg_backend_auth_state = 4,
	omci_me_dot1x_port_ext_pkg_admin_controlled_dirs = 5,
	omci_me_dot1x_port_ext_pkg_op_controlled_dirs = 6,
	omci_me_dot1x_port_ext_pkg_auth_controlled_port_status = 7,
	omci_me_dot1x_port_ext_pkg_quiet_period = 8,
	omci_me_dot1x_port_ext_pkg_server_timeout_period = 9,
	omci_me_dot1x_port_ext_pkg_re_auth_period = 10,
	omci_me_dot1x_port_ext_pkg_re_auth_enabled = 11,
	omci_me_dot1x_port_ext_pkg_key_tx_enabled = 12
};

/** @} */

/** @} */

__END_DECLS

#endif
