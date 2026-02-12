/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_pptp_lct_uni_h
#define _omci_pptp_lct_uni_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_PPTP_LCT_UNI PPTP LCT UNI Managed Entity

    This managed entity represents the local craft terminal UNI, where physical
    paths terminate and physical path level functions are performed.

    The ONT automatically creates an instance of this managed entity per port:
    - When the ONT has LCT ports built into its factory configuration
    - When a cardholder is provisioned to expect a circuit pack of LCT type
    - When a cardholder provisioned for plug and play is equipped with a circuit
      pack of LCT type. Note that the installation of a plug and play card
      may indicate the presence of LCT ports via equipment ID as well as its
      type, and indeed may cause the ONT to instantiate a port mapping package
      that specifies LCT ports.

    The ONT automatically deletes instances of this managed entity when a
    cardholder is neither provisioned to expect an LCT circuit pack, nor is it
    equipped with an LCT circuit pack.

    LCT instances are not reported during a MIB upload.

    @{
*/

/** This structure hold the attributes of the PPTP LCT UNI
    Managed Entity.
*/
struct omci_me_pptp_lct_uni {
	/** Administrative State

	    This attribute locks (0x01) and unlocks (0x00) the functions
	    performed by this Managed Entity. When the administrative state is
	    set to lock, all user functions of this UNI are blocked.

	    This value can be read and modified by the OLT.
	*/
	uint8_t admin_state;

} __PACKED__;

/** This enumerator holds the attribute numbers of the PPTP LCT UNI
    Managed Entity.
*/
enum {
	omci_me_pptp_lct_uni_admin_state = 1
};

/** @} */

/** @} */

__END_DECLS

#endif
