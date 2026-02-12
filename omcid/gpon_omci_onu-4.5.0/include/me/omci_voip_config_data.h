/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_voip_config_data_h
#define _omci_me_voip_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_VOIP_CONFIG_DATA VoIP Config Data Managed Entity

   The VoIP configuration data Managed Entity defines the configuration for
   VoIP in the ONU. The OLT uses this ME to discover the VoIP signalling
   protocols and configuration methods supported by this ONU. The OLT then
   uses this ME to select the desired signalling protocol and configuration
   method. The entity is conditionally required for ONUs that offer VoIP
   services.

   An ONU that supports VoIP services automatically creates an instance
   of this Managed Entity.

    @{
*/

/** This structure holds the attributes of the VoIP Config Data Managed Entity.
*/
struct omci_me_voip_config_data {
	/** Available signalling protocols
	    This attribute is a bit map that defines the VoIP signalling
	    protocols supported in the ONU. The bit value 1 specifies that the
	    ONU supports the associated protocol.
	*/
	uint8_t available_signalling_protocols;
	/** Signalling protocol used
	    This attribute specifies the VoIP signalling protocol to use. Only
	    one type of protocol is allowed at a time.
	*/
	uint8_t signalling_protocol_used;
	/** Available VoIP configuration methods
	    This attribute is a bit map that indicates the
	    capabilities of the ONU with regard to VoIP service configuration.
	    The bit value 1 specifies that the ONU supports the associated
	    capability.
	*/
	uint32_t available_voip_config_methods;
	/** VoIP configuration method used
	    Specifies which method is used to configure the ONU's
	    VoIP service.
	 */
	uint8_t voip_configuration_method_used;
	/** VoIP configuration address pointer
	    If this attribute is set to any value other than a null
	    pointer, it points to a network address Managed Entity, which
	    indicates the address of the server to contact using the method
	    indicated in the VoIP configuration method used attribute. This
	    attribute is only relevant for non-OMCI configuration methods.

	    If this attribute is set to a null pointer, no address is defined by
	    this attribute. However, the address may be defined by other
	    methods, such as deriving it from the ONU identifier attribute of
	    the IP host config data ME and using a well-known URI schema.
	 */
	uint16_t voip_config_address_ptr;
	/** VoIP configuration state
	    Indicates the status of the ONU VoIP service
	*/
	uint8_t voip_configuration_state;
	/** Retrieve profile
	    This attribute provides a means by which the ONU may be notified
	    that a new VoIP profile should be retrieved. By setting this
	    attribute, the OLT triggers the ONU to retrieve a new profile. The
	    actual value in the set action is ignored, because it is the action
	    of setting that is important.
	 */
	uint8_t retrieve_profile;
	/** Profile version
	    This attribute is a character string that identifies the version of
	    the last retrieved profile.
	 */
	uint8_t profile_version[25];
} __PACKED__;

/** @} */

/** @} */

__END_DECLS

#endif
