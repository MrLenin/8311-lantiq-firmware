/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_onu_remote_debug_h
#define _omci_onu_remote_debug_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_REMOTE_DEBUG Remote Debug Managed Entity

    This Managed Entity is used to send vendor-specific debug commands to the
    ONU and receive vendor-specific replies back for processing on the OLT.
    This allows for the remote debugging of an ONU that may not be accessible
    by any other means. The command format may have two modes, one being text
    and the other free format. In text format, both the command and reply are
    ASCII strings. In free format, the content and format of command and reply
    are vendor specific.

    An ONU that supports remote debugging automatically creates an instance of
    this Managed Entity. It is not reported during a MIB upload.

    One instance of this Managed Entity is associated with the ONU Managed
    Entity.

    \remarks The implementation of this Managed Entity allows remote access to
             the Command Line Interface (CLI) of the ONU.

    @{
*/

/** This structure holds the attributes of the Remote Debug Managed Entity. */
struct omci_me_onu_remote_debug {
	/** Command Format

	    This attribute defines the format of the command and reply
	    attributes.  Value 0x00 defines ASCII string format, while 0x01
	    specifies free format.
	    The format to be used is application dependent.

	    This attribute is read-only for the OLT.
	*/
	uint8_t cmd_format;

	/** Command

	    This attribute is used to send a command to the ONU. The format of
	    the command is defined by the command format. If the format is ASCII
	    string, the command should be null terminated unless the string is
	    25 bytes long.  The action of setting this attribute should trigger
	    the ONU to discard any previously command reply information and
	    execute the current debugging command.

	    This attribute is write-only for the OLT.
	*/
	uint8_t cmd[25];

	/** Reply Table

	    This attribute is used to pass reply information back to the OLT.
	    Its format is defined by the command format attribute. The get, get
	    next action sequence must be used with this attribute, since its
	    size is unspecified. On a get action, the ONU returns the size of
	    the reply (per normal get next usage). If the size of the reply is
	    unknown at the time of the get, the ONU returns the
	    value 0xFFFF FFFF. The OLT then issues get next requests until the
	    ONU is exhausted of data, whereupon the ONU returns a parameter
	    error response. The OLT then terminates the get next process.

	    This attribute is read-only for the OLT.
	*/
	uint8_t reply_table;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Remote Debug Managed
   Entity.
*/
enum {
	omci_me_onu_remote_debug_cmd_format = 1,
	omci_me_onu_remote_debug_cmd = 2,
	omci_me_onu_remote_debug_reply_table = 3
};

/** @} */

/** @} */

__END_DECLS

#endif
