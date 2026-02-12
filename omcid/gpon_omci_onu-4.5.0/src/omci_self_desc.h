/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_self_desc_h
#define _omci_self_desc_h

#ifdef HAVE_CONFIG_H
#  include "omci_config.h"
#endif

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION

/** \addtogroup OMCI_MIB

   @{
*/

/** \defgroup OMCI_SELF_DESC Optical Network Unit - OMCI Self Description

   @{
*/

/** Maximum name length */
#define DESC_MAX_NAME_LEN			25

/** Define Pointer attribute

   \param[in] NAME Name of the attribute.
              Name string should not exceed \ref DESC_MAX_NAME_LEN bytes!
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORT Support of the attribute
              (\ref attr_support).
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] LOWER_LIMIT Lower limit of the attribute.
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] UPPER_LIMIT Upper limit of the attribute.
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] OFFSET Offset of the attribute from the beginning of the
                     Managed Entity data.

   \param[in] SIZE Size of the attribute in bytes.

   \param[in] PROPERTIES Attributes properties
              (\ref omci_attr_prop).

   \param[in] GETHANDLER Attributes get handler
              (\ref me_get_handler).
*/
#define ATTR_PTR(NAME, \
		 SUPPORT, \
		 LOWER_LIMIT, \
		 UPPER_LIMIT, \
		 OFFSET, \
		 SIZE, \
		 PROPERTIES, \
		 GETHANDLER) \
{ \
	(OFFSET), \
	(SIZE), \
	(PROPERTIES), \
	(GETHANDLER), \
	OMCI_ATTR_TYPE_PTR, \
	(LOWER_LIMIT), \
	(UPPER_LIMIT), \
	0, \
	NULL, \
	0, \
	{ \
		NAME, \
		(SUPPORT) \
	} \
}

/** Define Unsigned Integer attribute

   \param[in] NAME Name of the attribute.
              Name string should not exceed \ref DESC_MAX_NAME_LEN bytes!
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORT Support of the attribute
              (\ref attr_support).
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] LOWER_LIMIT Lower limit of the attribute.

   \param[in] UPPER_LIMIT Upper limit of the attribute.

   \param[in] OFFSET Offset of the attribute from the beginning of the
                     Managed Entity data.

   \param[in] SIZE Size of the attribute in bytes.

   \param[in] PROPERTIES Attributes properties
              (\ref omci_attr_prop).

   \param[in] GETHANDLER Attributes get handler
              (\ref me_get_handler).
*/
#define ATTR_UINT(NAME, \
		  SUPPORT, \
		  LOWER_LIMIT, \
		  UPPER_LIMIT, \
		  OFFSET, \
		  SIZE, \
		  PROPERTIES, \
		  GETHANDLER) \
{ \
	(OFFSET), \
	(SIZE), \
	(PROPERTIES), \
	(GETHANDLER), \
	OMCI_ATTR_TYPE_UINT, \
	(LOWER_LIMIT), \
	(UPPER_LIMIT), \
	0, \
	NULL, \
	0, \
	{ \
		NAME, \
		(SUPPORT) \
	} \
}

/** Define Boolean attribute (internally represented as UNIT [0..1])

   \param[in] NAME Name of the attribute.
              Name string should not exceed \ref DESC_MAX_NAME_LEN bytes!
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORT Support of the attribute
              (\ref attr_support).
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] OFFSET Offset of the attribute from the beginning of the
                     Managed Entity data.

   \param[in] SIZE Size of the attribute in bytes.

   \param[in] PROPERTIES Attributes properties
              (\ref omci_attr_prop).

   \param[in] GETHANDLER Attributes get handler
              (\ref me_get_handler).
*/
#define ATTR_BOOL(NAME, \
		  SUPPORT, \
		  OFFSET, \
		  SIZE, \
		  PROPERTIES, \
		  GETHANDLER) \
{ \
	(OFFSET), \
	(SIZE), \
	(PROPERTIES), \
	(GETHANDLER), \
	OMCI_ATTR_TYPE_UINT, \
	0, \
	1, \
	0, \
	NULL, \
	0, \
	{ \
		NAME, \
		(SUPPORT) \
	} \
}

/** Define Signed Integer attribute

   \param[in] NAME Name of the attribute.
              Name string should not exceed \ref DESC_MAX_NAME_LEN bytes!
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORT Support of the attribute
              (\ref attr_support).
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] LOWER_LIMIT Lower limit of the attribute.

   \param[in] UPPER_LIMIT Upper limit of the attribute.

   \param[in] OFFSET Offset of the attribute from the beginning of the
                     Managed Entity data.

   \param[in] SIZE Size of the attribute in bytes.

   \param[in] PROPERTIES Attributes properties
              (\ref omci_attr_prop).

   \param[in] GETHANDLER Attributes get handler
              (\ref me_get_handler).
*/
#define ATTR_INT(NAME, \
		 SUPPORT, \
		 LOWER_LIMIT, \
		 UPPER_LIMIT, \
		 OFFSET, \
		 SIZE, \
		 PROPERTIES, \
		 GETHANDLER) \
{ \
	(OFFSET), \
	(SIZE), \
	(PROPERTIES), \
	(GETHANDLER), \
	OMCI_ATTR_TYPE_INT, \
	(LOWER_LIMIT), \
	(UPPER_LIMIT), \
	0, \
	NULL, \
	0, \
	{ \
		NAME, \
		(SUPPORT) \
	} \
}

/** Define String attribute

   \param[in] NAME Name of the attribute.
              Name string should not exceed \ref DESC_MAX_NAME_LEN bytes!
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORT Support of the attribute
              (\ref attr_support).
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] OFFSET Offset of the attribute from the beginning of the
                     Managed Entity data.

   \param[in] SIZE Size of the attribute in bytes.

   \param[in] PROPERTIES Attributes properties
              (\ref omci_attr_prop).

   \param[in] GETHANDLER Attributes get handler
              (\ref me_get_handler).
*/
#define ATTR_STR(NAME, \
		 SUPPORT, \
		 OFFSET, \
		 SIZE, \
		 PROPERTIES, \
		 GETHANDLER) \
{ \
	(OFFSET), \
	(SIZE), \
	(PROPERTIES) | OMCI_ATTR_PROP_NO_SWAP, \
	(GETHANDLER), \
	OMCI_ATTR_TYPE_STR, \
	0, \
	0, \
	0, \
	NULL, \
	0, \
	{ \
		NAME, \
		(SUPPORT) \
	} \
}

/** Define Enumeration attribute

   \param[in] NAME Name of the attribute.
              Name string should not exceed \ref DESC_MAX_NAME_LEN bytes!
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORT Support of the attribute
              (\ref attr_support).
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] CODE_POINTS Fixed array of the enumeration code points.

   \param[in] OFFSET Offset of the attribute from the beginning of the
                     Managed Entity data.

   \param[in] SIZE Size of the attribute in bytes.

   \param[in] PROPERTIES Attributes properties
              (\ref omci_attr_prop).

   \param[in] GETHANDLER Attributes get handler
              (\ref me_get_handler).
*/
#define ATTR_ENUM(NAME, \
		  SUPPORT, \
		  CODE_POINTS, \
		  OFFSET, \
		  SIZE, \
		  PROPERTIES, \
		  GETHANDLER) \
{ \
	(OFFSET), \
	(SIZE), \
	(PROPERTIES), \
	(GETHANDLER), \
	OMCI_ATTR_TYPE_ENUM, \
	0, \
	0, \
	0, \
	(CODE_POINTS), \
	sizeof((CODE_POINTS)) / sizeof((CODE_POINTS)[0]), \
	{ \
		NAME, \
		(SUPPORT) \
	} \
}

/** Define Bit Field attribute

   \param[in] NAME Name of the attribute.
              Name string should not exceed \ref DESC_MAX_NAME_LEN bytes!
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORT Support of the attribute
              (\ref attr_support).
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORTED_BITS Bit field with the supported bits.

   \param[in] OFFSET Offset of the attribute from the beginning of the
                     Managed Entity data.

   \param[in] SIZE Size of the attribute in bytes.

   \param[in] PROPERTIES Attributes properties
              (\ref omci_attr_prop).

   \param[in] GETHANDLER Attributes get handler
              (\ref me_get_handler).
*/
#define ATTR_BF(NAME, \
		SUPPORT, \
		SUPPORTED_BITS, \
		OFFSET, \
		SIZE, \
		PROPERTIES, \
		GETHANDLER) \
{ \
	(OFFSET), \
	(SIZE), \
	(PROPERTIES), \
	(GETHANDLER), \
	OMCI_ATTR_TYPE_BF, \
	0, \
	0, \
	(SUPPORTED_BITS), \
	NULL, \
	0, \
	{ \
		NAME, \
		(SUPPORT) \
	} \
}

/** Define Table attribute

   \param[in] NAME Name of the attribute.
              Name string should not exceed \ref DESC_MAX_NAME_LEN bytes!
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] SUPPORT Support of the attribute
              (\ref attr_support).
              <BR><B>Excluded when the OMCI Self Description is not defined!</B>

   \param[in] OFFSET Offset of the attribute from the beginning of the
                     Managed Entity data.

   \param[in] SIZE Size of the attribute in bytes.

   \param[in] PROPERTIES Attributes properties
              (\ref omci_attr_prop).

   \param[in] GETHANDLER Attributes get handler
              (\ref me_get_handler).
*/
#define ATTR_TBL(NAME, \
		 SUPPORT, \
		 OFFSET, \
		 SIZE, \
		 PROPERTIES, \
		 GETHANDLER) \
{ \
	(OFFSET), \
	(SIZE), \
	(PROPERTIES) | OMCI_ATTR_PROP_TABLE \
	| OMCI_ATTR_PROP_NO_UPLOAD \
	| OMCI_ATTR_PROP_NO_SWAP, \
	(GETHANDLER), \
	OMCI_ATTR_TYPE_TBL, \
	0, \
	0, \
	0, \
	NULL, \
	0, \
	{ \
		NAME, \
		(SUPPORT) \
	} \
}

/** Placeholder for the undefined attributes */
#define ATTR_NOT_DEF() \
{ \
	0, \
	0, \
	OMCI_ATTR_PROP_NONE, \
	NULL, \
	OMCI_ATTR_TYPE_UNKNOWN, \
	0, \
	0, \
	0, \
	NULL, \
	0, \
	{ \
		"", \
		ATTR_UNSUPPORTED \
	} \
}

/** The level of support of the attribute (please refer to ITU-T G.984.4
   9.12.10) */
enum attr_support {
	/** Fully supported (supported as defined in this object) */
	ATTR_SUPPORTED = 1,

	/** Unsupported (OMCI returns an error code if accessed) */
	ATTR_UNSUPPORTED = 2,

	/** Partially supported (some aspects of attribute supported) */
	ATTR_PARTIALLY_SUPPORTED = 3,

	/** Ignored (OMCI supported, but underlying function is not) */
	ATTR_IGNORED = 4
};

/** This enum represents who creates th Managed Entity (please refer to
   ITU-T G.984.4 9.12.9)*/
enum me_access {
	/** Created by the ONT */
	ME_CREATED_BY_ONT = 1,

	/** Created by the OLT */
	ME_CREATED_BY_OLT = 2,

	/** Created by both ONT and OLT */
	ME_CREATED_BY_BOTH = 3
};

/** This enum represents support capability of the Managed Entity in
   the ONT's implementation (please refer to ITU-T G.984.4 9.12.9) */
enum me_support {
	/** Fully supported (supported as defined in this object) */
	ME_SUPPORTED = 1,

	/** Unsupported (OMCI returns an error code if accessed) */
	ME_UNSUPPORTED = 2,

	/** Partially supported (some aspects of attribute supported) */
	ME_PARTIALLY_SUPPORTED = 3,

	/** Ignored (OMCI supported, but underlying function is not) */
	ME_IGNORED = 4
};

/** This structure describes additional information of the Managed Entity
   attribute */
struct me_attr_desc {
	/** A 25 byte mnemonic tag for the attribute */
	char name[DESC_MAX_NAME_LEN];

	/** The level of support of the attribute */
	enum attr_support support;
};

/** This structure describes additional information of the Managed Entity */
struct me_desc {
	/** Managed Entity class name */
	char name[DESC_MAX_NAME_LEN];

	/** Managed Entity access (who creates this entity) */
	enum me_access access;

	/** Managed Entity supported alarms */
	uint8_t *alarm_table;

	/** Number of items in the supported alarms table */
	size_t alarm_table_size;

	/** Managed Entity support */
	enum me_support support;
};

/** @} */

/** @} */

#endif

#endif
