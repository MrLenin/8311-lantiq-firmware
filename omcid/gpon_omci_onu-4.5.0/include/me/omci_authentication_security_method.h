/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_authentication_h
#define _omci_authentication_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_AUTHENTICATION Authentication Managed Entity

   The authentication security method defines the user id/password
   configuration to establish a session between a client and server.
   This object may be used in the role of the client or server. An
   instance of this Managed Entity is created by the OLT if authenticated
   communication is necessary.

    @{
*/

/** This structure holds the attributes of the Authentication Managed Entity.
*/
struct omci_me_authentication {
	/** This attribute specifies the validation scheme used when the
	    ONU validates a challenge. Validation schemes are defined as
	    follows:
	    - 0 Validation disabled
	    - 1 Validate using MD5 digest authentication as defined in RFC2617
	      (recommended)
	    - 3 Validate using basic authentication as defined in RFC2617 */
	uint8_t validation_scheme;
	/** This string attribute is the user name. If the string is shorter
	    than 25 bytes, it must be null terminated (note). */
	uint8_t username_1[25];
	/** This string attribute is the user name. If the string is shorter
	    than 25 bytes, it must be null terminated. */
	uint8_t password[25];
	/** This string attribute specifies the realm used in digest
	    authentication. If the string is shorter than 25 bytes, it must be
	    null terminated. */
	uint8_t realm[25];
	/** This string attribute allows for continuation of the user name
	    beyond 25 characters (note). Its default value is a null string.

	    \note The total username is the concatenation of the username 1 and
	    username 2 attributes if and only if a) username 1 comprises 25
	    non-null characters, b) username 2 is supported by the ONU, and
	    c) username 2 contains a leading non-null character string.
	    Otherwise, the total username is simply the value of the
	    username 1 attribute. */
	uint8_t username_2[25];
} __PACKED__;


/** This enumerator holds the attribute numbers of the Authentication
    Managed Entity.
*/
enum {
	omci_me_authentication_validation_scheme = 1,
	omci_me_authentication_username_1 = 2,
	omci_me_authentication_password = 3,
	omci_me_authentication_realm = 4,
	omci_me_authentication_username_2 = 5
};

/** @} */

/** @} */

__END_DECLS

#endif
