/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_sw_image_h
#define _omci_sw_image_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_SW_IMAGE Software Image Managed Entity

    The Software Image Managed Entity models an executable software image
    stored in the ONT.

    The ONT automatically creates two instances of this Managed Entity upon the
    creation of the ONT-G Managed Entity.

    @{
*/

/** The maximum time between two software download related actions is 15
   minute(s). After that time image data will be freed.

   This time is introduced because the OLT may stop transmission of the image
   and allocated memory will not be freed until the next request to the same
   software image instance.

   \note This is not standardized by the ITU!
*/
#define OMCI_SWIMAGE_DOWNLOAD_TIMEOUT                      (60 * 15 * 1000)

/** This structure holds the attributed of the Software Image Managed Entity. */
struct omci_me_sw_image {
	/** Software Version Code

	    This attribute identifies the version of the software.
	    It is read-only by the OLT.

	    The version is identified by an ASCII string, constructed such as:
	    "<string1>.<string2>.<string3>"

	    \todo The version naming convention needs to be clarified.
	*/
	char version[14];

	/** Software Committed State Indication

	    This attribute indicates whether the associated software image is
	    committed (OMCI_TRUE) or uncommitted (OMCI_FALSE).
	    By definition, the committed software image is loaded and executed
	    upon reboot of the ONT.  During normal operation, one software
	    image is always committed, while the other is uncommitted. Under no
	    circumstances are both software images allowed to be committed at
	    the same time.

	    This attribute is read-only by the OLT.
	*/
	bool is_committed;

	/** Software Active State Indication

	    This attribute indicates whether the associated software image is
	    active (OMCI_TRUE) or inactive (OMCI_FALSE). By definition,
	    the active software image is one that is currently loaded and
	    executing in the ONT. Under normal operation, one software image is
	    always active while the other is inactive. Under no circumstances
	    are both software images allowed to be active at the same time.

	    This attribute is read-only by the OLT.
	*/
	bool is_active;

	/** Software Valid State Indication

	    This attribute indicates whether the associated software image is
	    valid (OMCI_TRUE) or invalid (OMCI_FALSE). By definition, a
	    software image is valid if it has been verified to be an executable
	    code image. Upon ME instantiation, the ONT validates the associated
	    code image and sets this attribute according to the result.

	    This attribute is read-only by the OLT.
	*/
	bool is_valid;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Software Image Managed
   Entity.
*/
enum {
	omci_me_sw_image_version = 1,
	omci_me_sw_image_is_committed = 2,
	omci_me_sw_imagw_is_active = 3,
	omci_me_sw_image_is_valid = 4
};

/** @} */

/** @} */

__END_DECLS

#endif
