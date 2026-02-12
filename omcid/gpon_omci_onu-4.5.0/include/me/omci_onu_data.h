/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_onu_data_h
#define _omci_onu_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_ONU_DATA ONU Data Managed Entity

    This Managed Entity models the MIB (Managed Information Base) itself.

    The ONU automatically creates an instance of this Managed Entity, and
    updates the associated attributes according to data within the ONU itself.

    @{
*/

/** The maximum time between two GetAllAlarmsNext requests (in milliseconds).
   Please refer to the ITU-T G.984.4 */
#define OMCI_ONUDATA_GET_ALL_ALARMS_TIMEOUT                  (60 * 1000)

/** The maximum time between two MibUploadNext requests (in milliseconds).
   Please refer to the ITU-T G.984.4 */
#define OMCI_ONUDATA_MIB_UPLOAD_TIMEOUT                      (60 * 1000)

/** This structure holds the attributes of the ONU Data Managed Entity.
*/
struct omci_me_onu_data {
	/** MIB Data Sync

	    This attribute is used to check the alignment of the MIB of the ONU
	    with the corresponding MIB in the OLT. MIB data sync relies on this
	    attribute, which is a sequence number that can be checked by the OLT
	    to see if the MIB snapshots for the OLT and ONU match.

	    Upon ME instantiation, the ONU sets this attribute to 0x00.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t mib_data_sync;

} __PACKED__;

/** This enumerator holds the attribute numbers of the ONU Data Managed Entity.
*/
enum {
	omci_me_onu_data_mib_data_sync = 1
};

/** @} */

/** @} */

__END_DECLS

#endif
