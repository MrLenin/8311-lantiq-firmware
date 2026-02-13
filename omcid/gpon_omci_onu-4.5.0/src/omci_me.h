/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_h
#define _omci_me_h

#include "omci_msg.h"
#include "omci_self_desc.h"
#include "omci_pm.h"
#include "omci_os.h"

/** \defgroup OMCI_ME Optical Network Unit - Managed Entities

    This module contains ME related functionality.

    \section OMCI_ME_HANDLING ME handling

    Please use routines that are defined here to access ME data! There are
    many side effects because of changing ME attributes and those routines
    handle them, including:
    - Calling of GET handler for volatile attributes on attribute/data read
    - Send AVCs on write
    - Calling of thresholds set handler for PM MEs upon thresholds data
      attribute update

    They also print updated data to the console to make the debugging easy.

    \section OMCI_ME_LOCK ME locking

    Whenever you're dealing with the Managed Entity you have to lock it. None
    of the internal ME routines (\ref me_data_read, \ref me_data_write,
    \ref me_attr_read, \ref me_attr_write, etc) lock entities for you.

    When one of the ME handlers is executed (init, shutdown, update, tbl_copy,
    counters_get, thr_set) Managed Entity (the one that 'me' pointer points to)
    is already locked for you. The same is true for the action handlers:
    if the target ME (from the OMCI message) is found - it's locked.

    Thus you have to do ME locking yourself in the following places:
    - Timeout handlers
    - API routines
    - Callbacks
    - ME action handlers - only if you deal with other MEs that you find
      via \ref mib_me_find
    - Other non-generic threads which may be created for any particular task

    \remark ME locking is reentrant! This means that you can safely lock
	    Managed Entity several times within one thread (and hence release
	    the lock exactly the same number of times).

   @{ @}
*/

/** \addtogroup OMCI_MIB

   @{
*/

/** Number of actions

    This defines the number of actions that are provided. */
#define ACTIONS_NUM					29

#ifndef NDEBUG
/** Lock Managed Entity

   \warning If the Managed Entity can't be locked there is an outstanding
            error and we can't continue!
            Exit with abort().

   \param[in] CONTEXT      OMCI context pointer
   \param[in] ME           Managed Entity pointer
*/
#define me_lock(CONTEXT, ME) _me_lock((CONTEXT), (ME), __FILE__, __LINE__)
#else
#define me_lock(CONTEXT, ME) _me_lock((CONTEXT), (ME), "?", __LINE__)
#endif

/** Low level ME lock routine

   \param[in] context      OMCI context pointer
   \param[in] me           Managed Entity pointer
   \param[in] file         File
   \param[in] line         Line number

   \remark Don't use it directly, use \ref me_lock instead!
*/
void _me_lock(struct omci_context *context,
	      struct me *me,
	      const char *file,
	      int line);

#ifndef NDEBUG
/** Unlock Managed Entity

   \warning If the Managed Entity can't be unlocked there is an outstanding
            error and we can't continue!
            Exit with abort().

   \param[in] CONTEXT      OMCI context pointer
   \param[in] ME           Managed Entity pointer
*/
#define me_unlock(CONTEXT, ME) _me_unlock((CONTEXT), (ME), __FILE__, __LINE__)
#else
#define me_unlock(CONTEXT, ME) _me_unlock((CONTEXT), (ME), "?", __LINE__)
#endif

/** Low level ME unlock routine

   \param[in] context      OMCI context pointer
   \param[in] me           Managed Entity pointer
   \param[in] file         File
   \param[in] line         Line number

   \remark Don't use it directly, use \ref me_lock instead!
*/
void _me_unlock(struct omci_context *context,
		struct me *me,
		const char *file,
		int line);

/** Initialize Managed Entity lock */
enum omci_error me_lock_init(struct me *me);

/** Delete Managed Entity lock */
enum omci_error me_lock_delete(struct me *me);

#ifndef INCLUDE_OMCI_SELF_DESCRIPTION

/** Define Pointer attribute.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	0 \
}

/** Define Unsigned Integer attribute.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	0 \
}

/** Define Boolean attribute.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	0 \
}

/** Define Signed Integer attribute.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	0 \
}

/** Define String attribute.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	0 \
}

/** Define Enumeration attribute.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	sizeof((CODE_POINTS)) / sizeof((CODE_POINTS)[0]) \
}

/** Define Bit Field attribute.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	0 \
}

/** Define Table attribute.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	0 \
}

/** Placeholder for the undefined attributes.
   Please refer to the same definition in the omci_self_desc.h file for
   more details. */
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
	0 \
}
#endif

struct me;
struct tbl_copy_entry;

/** Managed Entity attribute get handler

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
typedef enum omci_error (me_get_handler) (struct omci_context *context,
					  struct me *me,
					  void *data,
					  size_t data_size);

/** Managed Entity action handler

   \param[in]  context OMCI context pointer
   \param[in]  me      Managed Entity pointer
   \param[in]  msg     Arrived OMCI message pointer
   \param[out] rsp     OMCI message response pointer
*/
typedef enum omci_error (me_action_handler) (struct omci_context
					     *context,
					     struct me *me,
					     const union omci_msg *msg,
					     union omci_msg *rsp);

/** Managed Entity instance initialize handler

   \param[in] context      OMCI context pointer
   \param[in] me           Managed Entity pointer
   \param[in] init_data    Managed Entity initial data
   \param[in] suppress_avc Suppress AVC for given attributes
*/
typedef enum omci_error (me_init_handler) (struct omci_context *context,
					   struct me *me,
					   void *init_data,
					   uint16_t suppress_avc);

/** Managed Entity instance shutdown handler

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
*/
typedef enum omci_error (me_shutdown_handler) (struct omci_context *context,
					       struct me *me);

/** Managed Entity table attribute copy handler

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
   \param[in] attr     Attribute position
   \param[in] tbl_copy Attribute copy pointer
*/
typedef enum omci_error (me_tbl_copy_handler) (struct omci_context *context,
					       struct me *me,
					       unsigned int attr,
					       struct tbl_copy_entry *tbl_copy);

/** Table SET operation

   \param[in] context   OMCI context pointer
   \param[in] me        Managed Entity pointer
   \param[in] data      Data to set
   \param[in] data_size Data size
*/
typedef enum omci_error (me_tbl_op_set)(struct omci_context *context,
					struct me *me,
					const void *data,
					uint16_t data_size);

/** Table GET operation

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled
   \param[in]  data_size Data size
   \param[in]  prev      Previous entry pointer (NULL for first)
*/
typedef enum omci_error (me_tbl_op_get)(struct omci_context *context,
					const struct me *me,
					void **data,
					uint16_t data_size,
					const void *prev);

/** Table SWAP handler

   \param[in] context   OMCI context pointer
   \param[in] me        Managed Entity pointer
   \param[in] data      Data to swap
   \param[in] data_size Data size
*/
typedef enum omci_error (me_tbl_op_swp)(struct omci_context *context,
					struct me *me,
					void *data,
					uint16_t data_size);

/** Table operations structure */
struct tbl_ops {
	/** Set handler */
	me_tbl_op_set *set;
	/** Get handler */
	me_tbl_op_get *get;
	/** Swap handler */
	me_tbl_op_swp *swap;
};

/** Managed Entity table attribute operations handler

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
   \param[in] attr     Attribute position

   \return Attribute operations pointer
*/
typedef const struct tbl_ops *(me_tbl_ops_handler)(struct omci_context *context,
						   struct me *me,
						   unsigned int attr);

/** Managed Entity attribute structure */
struct me_attr {
	/** Offset of the attribute from the beginning of the data (in bytes).
	    Must be 0 for non-supported Managed Entities. */
	size_t offset;

	/** Size of the attribute (in number of bytes).
	    For table attributes, this is a size of one table entry.
	    \note This value must be set for any attribute that is mentioned in
	    the ITU-T G.984.4! (even for optional attributes that are not
	    supported) */
	uint8_t size;

	/** Attribute properties */
	enum omci_attr_prop prop;

	/** Attribute get handler (NULL if unavailable).
	    If the GetHandler is presented it called each time the attribute is
	    read! (Volatile attribute) */
	me_get_handler *get;

	/** The Format of the attribute */
	enum omci_attr_type format;

	/** Attribute lower limit (for PTR, INT, UINT only) */
	uint64_t lower_limit;

	/** Attribute highest limit (for PTR, INT, UINT only) */
	uint64_t upper_limit;

	/** The mask of the supported bits in a bit field attribute. Valid for
	    bit field type only. A 1 in any position signifies that its code
	    point is supported, while 0 indicates not supported. For bit fields
	    smaller than 4 bytes, the attribute is aligned at the least
	    significant end of the mask. */
	uint32_t bit_field;

	/** The code points supported by an ENUM attribute */
	uint16_t *code_points;

	/** The number of code points */
	size_t code_points_num;

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	/** OMCI self description information */
	struct me_attr_desc desc;
#endif
};

struct me_class;

/** Managed Entity attributes (to be set) validate handler. All attributes
   are checked (all defined except non supported optional ones) except table
   ones.

   \param[in]  context   OMCI context pointer
   \param[in]  me_class  Managed Entity class pointer
   \param[out] exec_mask Returns mask with invalid attributes (not-null if any)
   \param[in]  data      Data to validate
*/
typedef enum omci_error (me_validate_handler) (struct omci_context *context,
					       const struct me_class *me_class,
					       uint16_t *exec_mask,
					       const void *data);

/** Managed Entity attributes update handler.

    Update handler is used for attributes update and table attributes
    validate/update actions. If table attribute validation is failed than it
    is clearly obvious because only one table attribute may be set during one
    set operation (message).

   \param[in] context   OMCI context pointer
   \param[in] me        Managed Entity pointer
   \param[in] data      Data to update
   \param[in] attr_mask Attributes to be set mask
*/
typedef enum omci_error (me_update_handler) (struct omci_context *context,
					     struct me *me,
					     void *data,
					     uint16_t attr_mask);

/** Managed Entity class structure */
struct me_class {
	/** Managed Entity class identifier */
	const uint16_t class_id;

	/** Managed Entity attributes table */
	const struct me_attr attrs[OMCI_ATTRIBUTES_NUM];

	/** Managed Entity actions array */
	me_action_handler *const actions[ACTIONS_NUM];

	/** Managed Entity instance initialize handler */
	me_init_handler *const init;

	/** Managed Entity instance shutdown handler */
	me_shutdown_handler *const shutdown;

	/** Managed Entity attributes validate handler */
	me_validate_handler *const validate;

	/** Managed Entity attributes update handler */
	me_update_handler *const update;

	/** Managed Entity table attribute copy handler*/
	me_tbl_copy_handler *const tbl_copy;

	/** Managed Entity table attribute operations handler*/
	me_tbl_ops_handler *const tbl_ops;

#ifdef INCLUDE_PM
	/** PM Managed Entity counters get handler */
	pm_counters_get_handler *const counters_get;

	/** PM Managed Entity thresholds set handler */
	pm_thr_set_handler *const thr_set;
#endif

	/** TCA mapping table for PM Managed Entities (NULL if non PM) */
	struct me_tca *const tca_table;

	/** Size of Managed Entity attributes (in bytes) */
	const uint16_t data_size;

	/** Managed Entity properties */
	const enum omci_me_prop prop;

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	/** OMCI self description information */
	const struct me_desc desc;
#endif

	/* the data below is dynamically calculated (on MIB correctness
	   check) */

	/** Invalid attributes mask */
	uint16_t inv_attr_mask;

	/** Unsupported optional attributes mask */
	uint16_t opt_attr_mask;

	/** Set-by-create attributes mask */
	uint16_t sbc_attr_mask;

	/** AVC mask */
	uint16_t avc_attr_mask;

	/** Writable attributes mask */
	uint16_t wr_attr_mask;

	/** Volatile attributes mask */
	uint16_t vol_attr_mask;
};

struct me_arc_context;

/** Managed Entity instance structure */
struct me {
	/** Managed Entity class pointer */
	const struct me_class *class;

	/** Managed Entity instance identifier */
	uint16_t instance_id;

	/** Managed Entity data pointer */
	void *data;

	/** Managed Entity internal data (not defined by the ITU) */
	void *internal_data;

	/** Managed Entity Alarms (NULL if the Managed Entity doesn't support
	    alarm reporting) */
	uint8_t *alarm_bitmap;

	/** Managed Entity ARC related data (NULL if the Managed Entity doesn't
	    support ARC */
	struct me_arc_context *arc_context;

#ifdef INCLUDE_PM
	/** PM Managed Entity data */
	struct pm_me_context *pm;
#endif

	/** Is Managed Entity initialized
	    (set after the execution of the Managed Entity initialize handler) */
	bool is_initialized;

	/** Managed Entity lock */
	struct recursive_lock lock;

	/** Use the ME implementation. If set to false just return true for
	    update / init routine (no access to hardware). */
	bool active;
};

/** Get attribute structure pointer

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Attribute structure pointer
*/
static inline
const struct me_attr *me_attr_get(const struct me_class *me_class,
				  unsigned int attr)
{
	return &me_class->attrs[attr - 1];
}

/** Get table attribute operations

   \param[in] context  OMCI context pointer
   \param[in] me       Managed Entity pointer
   \param[in] attr     Attribute position

   \return Table Attribute operations pointer
*/
static inline
const struct tbl_ops *me_tbl_ops_get(struct omci_context *context,
				     struct me *me, unsigned int attr)
{
	if (me->class->tbl_ops)
		return me->class->tbl_ops(context, me, attr);
	return NULL;
}

/** Get attribute size

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Attribute size

   \note For table attributes attr_size would be one entry size!
*/
static inline
size_t me_attr_size_get(const struct me_class *me_class,
			unsigned int attr)
{
	return me_attr_get(me_class, attr)->size;
}

/** Get attribute properties

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Attribute properties
*/
static inline
enum omci_attr_prop me_attr_prop_get(const struct me_class *me_class,
				     unsigned int attr)
{
	return me_attr_get(me_class, attr)->prop;
}

/** Get attribute data offset

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Attribute data offset
*/
static inline
unsigned int me_attr_offset_get(const struct me_class *me_class,
				unsigned int attr)
{
	return (unsigned int)me_attr_get(me_class, attr)->offset;
}

/** Get attribute "Get handler"

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Attribute "Get handler"
*/
static inline
me_get_handler *me_attr_get_handler_get(const struct me_class *me_class,
					unsigned int attr)
{
	return me_attr_get(me_class, attr)->get;
}

/** Get attribute code points

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Pointer to array of code points
*/
static inline
uint16_t *me_attr_code_points_get(const struct me_class *me_class,
				  unsigned int attr)
{
	return me_attr_get(me_class, attr)->code_points;
}

/** Get attribute code points number

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Number of code points
*/
static inline
size_t me_attr_code_points_num_get(const struct me_class *me_class,
				   unsigned int attr)
{
	return me_attr_get(me_class, attr)->code_points_num;
}

/** Get attribute supported bits mask

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Supported bits mask
*/
static inline
uint32_t me_attr_bf_supported_mask_get(const struct me_class *me_class,
				       unsigned int attr)
{
	return me_attr_get(me_class, attr)->bit_field;
}

/** Get attribute lower limit

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Lower limit
*/
static inline
uint64_t me_attr_lower_limit_get(const struct me_class *me_class,
				 unsigned int attr)
{
	return me_attr_get(me_class, attr)->lower_limit;
}

/** Get attribute upper limit

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Upper limit
*/
static inline
uint64_t me_attr_upper_limit_get(const struct me_class *me_class,
				 unsigned int attr)
{
	return me_attr_get(me_class, attr)->upper_limit;
}

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
/** Get attribute name

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Attribute name
*/
static inline
const char *me_attr_name_get(const struct me_class *me_class,
			     unsigned int attr)
{
	return me_attr_get(me_class, attr)->desc.name;
}
#endif

/** Get attribute type

   \param[in]  me_class Managed Entity pointer
   \param[in]  attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return Attribute type
*/
static inline
enum omci_attr_type me_attr_type_get(const struct me_class *me_class,
				     unsigned int attr)
{
	return me_attr_get(me_class, attr)->format;
}

/** Validate enumeration attribute value

   \param[out] exec_mask       Returns execution mask
   \param[in]  attr            Attributenumber
                               [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[in]  value           Value to validate
   \param[in]  code_points     Array of supported code points
   \param[in]  code_points_num Number of items in code_points
*/
static inline void enum_validate(uint16_t *exec_mask,
				 unsigned int attr,
				 unsigned int value,
				 uint16_t *code_points,
				 size_t code_points_num)
{
	unsigned int i;

	if (code_points == NULL) {
		*exec_mask |= omci_attr2mask(attr);
		return;
	}

	for (i = 0; i < code_points_num; i++) {
		if (value == code_points[i])
			return;
	}

	*exec_mask |= omci_attr2mask(attr);
}

/** Validate bit field attribute value

   \param[out] exec_mask Returns execution mask
   \param[in]  attr      Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[in]  value     Value to validate
   \param[in]  nSuppBits Mask of supported bits
*/
static inline void bf_validate(uint16_t *exec_mask,
			       unsigned int attr,
			       uint32_t value,
			       uint32_t nSuppBits)
{
	if (value & (~nSuppBits))
		*exec_mask |= omci_attr2mask(attr);
}

/** Validate numeric attribute value

   \param[out] exec_mask   Returns execution mask
   \param[in]  attr        Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[in]  value       Value to validate
   \param[in]  nLowerBound Lower bound of value
   \param[in]  nUpperBound Upper bound of value
*/
static inline void num_validate(uint16_t *exec_mask,
				unsigned int attr,
				unsigned int value,
				unsigned int nLowerBound,
				unsigned int nUpperBound)
{
	if (value < nLowerBound || value > nUpperBound)
		*exec_mask |= omci_attr2mask(attr);
}

/** Returns Managed Entity empty data updated with fetched attributes from data

   \param[in]  context      OMCI context pointer
   \param[in]  me_class     Managed Entity class pointer
   \param[in]  attr_mask    Which attributes should be fetched from data
   \param[in]  data         Attributes data pointer
   \param[in]  data_size    Attributes data size
   \param[out] fetched_data Returns fetched attributes
*/
enum omci_error me_class_data_fetch(struct omci_context *context,
				    const struct me_class* me_class,
				    uint16_t attr_mask,
				    const void *data,
				    size_t data_size,
				    void *fetched_data);

/** Returns Managed Entity data updated with fetched attributes from data

   \param[in]  context        OMCI context pointer
   \param[in]  me             Managed Entity pointer
   \param[in]  attr_mask      Which attributes should be fetched from data
   \param[in]  data           Attributes data pointer
   \param[in]  data_size      Attributes data size
   \param[in]  data_attr_mask Attributes which included in data
   \param[out] fetched_data   Returns fetched attributes
*/
enum omci_error me_data_fetch(struct omci_context *context,
			      struct me *me,
			      uint16_t attr_mask,
			      const void *data,
			      size_t data_size,
			      uint16_t data_attr_mask,
			      void *fetched_data);

/** Get action handler

   \param[in]  me_class          Managed Entity Class pointer
   \param[in]  action            Action identifier
   \param[out] me_action_handler Returns action handler
*/
enum omci_error me_action_handler_get(const struct me_class *me_class,
				      unsigned int action,
				      me_action_handler **me_action_handler);

/** Check if given attribute is presented in the Managed Entity

   \param[in] me_class Managed Entity pointer
   \param[in] attr     Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]

   \return true if attribute is presented
*/
bool is_me_attr_exist(const struct me_class *me_class, unsigned int attr);

/** Read value of the Managed Entity attribute with given PM interval

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[in]  attr      Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[out] buff      Pointer to the buffer which will be filled up with
                         the attribute value
   \param[in]  buff_size Buffer size in size
   \param[in]  interval  PM interval

   \note This is simple wrapper on \ref me_data_read so if you need to read
         multiple attributes of _one_ ME it's more efficient to use
	 \ref me_data_read.

   \note For PM managed entities current interval is used.
*/
enum omci_error me_attr_read_with_interval(struct omci_context *context,
					   struct me *me,
					   unsigned int attr,
					   void *buff,
					   size_t buff_size,
					   enum omci_pm_interval interval);

/** Read value of the Managed Entity attribute

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[in]  attr      Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
   \param[out] buff      Pointer to the buffer which will be filled up with
                         the attribute value
   \param[in]  buff_size Buffer size in size

   \note This is simple wrapper on \ref me_data_read so if you need to read
         multiple attributes of _one_ ME it's more efficient to use
	 \ref me_data_read.

   \note For PM managed entities current interval is used.
*/
enum omci_error me_attr_read(struct omci_context *context,
			     struct me *me,
			     unsigned int attr,
			     void *buff,
			     size_t buff_size);

/** Write value to the Managed Entity attribute

  \param[in] context      OMCI context pointer
  \param[in] me           Managed Entity pointer
  \param[in] attr         Attribute number [1 .. \ref OMCI_ATTRIBUTES_NUM]
  \param[in] buff         Attribute data to write
  \param[in] buff_size    Attribute data size in bytes
  \param[in] suppress_avc Suppress AVC for given attribute

   \note This is simple wrapper on \ref me_data_write so if you need to write
         multiple attributes of _one_ ME it's more efficient to use
	 \ref me_data_write.
*/
enum omci_error me_attr_write(struct omci_context *context,
			      struct me *const me,
			      unsigned int attr,
			      const void *buff,
			      size_t buff_size,
			      bool suppress_avc);

/** Read all attributes from the Managed Entity

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Returns attributes data
   \param[in]  data_size Data size in bytes
   \param[in]  interval  PM interval

   \note Table attributes contain garbage!
*/
enum omci_error me_data_read(struct omci_context *context,
			     struct me *me,
			     void *data,
			     size_t data_size,
			     enum omci_pm_interval interval);

/** Write all attributes to the Managed Entity

  \param[in] context      OMCI context pointer
  \param[in] me           Managed Entity pointer
  \param[in] data         Attributes data pointer (be aware! Update handler can
                          change attributes)
  \param[in] data_size    Data size in bytes
  \param[in] attr_mask    Attributes mask
  \param[in] suppress_avc Suppress AVC for given attributes
*/
enum omci_error me_data_write(struct omci_context *context,
			      struct me *const me,
			      void *data,
			      size_t data_size,
			      uint16_t attr_mask,
			      uint16_t suppress_avc);

/** Read table attribute from the Managed Entity

  \param[in]  context   OMCI context pointer
  \param[in]  me        Managed Entity pointer
  \param[in]  attr      Table attribute position
  \param[out] data      Attributes data pointer (be aware! Update handler can
                        change attributes)
  \param[out] data_size Data size in bytes

   \note Pointer returned in data should be freed by user!
*/
enum omci_error me_tbl_data_read(struct omci_context *context,
				 struct me *me,
				 unsigned int attr,
				 void **data,
				 size_t *data_size);

/** set/Clear Managed Entity instance alarm and increase alarm sequence number

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] alarm   Alarm number [0 .. \ref OMCI_ALARMS_NUM - 1]
   \param[in] active  Alarm status:
                       - true - Turn on alarm
                       - false - Turn off alarm
*/
enum omci_error me_alarm_set(struct omci_context *context,
			     struct me *me,
			     uint8_t alarm,
			     bool active);

/** get Managed Entity instance alarm

   \param[in]  context      OMCI context pointer
   \param[in]  me           Managed Entity pointer
   \param[in]  alarm        Alarm number [0 .. \ref OMCI_ALARMS_NUM - 1]
   \param[out] alarm_active Returns alarm status:
                            - true - Alarm is on
                            - false - Alarm is off
*/
enum omci_error me_alarm_get(struct omci_context *context,
			     struct me *me,
			     uint8_t alarm,
			     bool *alarm_active);

/** Print attributes state change

   \param[in] context         OMCI context pointer
   \param[in] me_class        Managed Entity pointer
   \param[in] instance_id     Managed Entity instance id
   \param[in] attr_mask       Which attributes are presented in the values
   \param[in] values          Pointer to attributes data
   \param[in] values_size     Size of the attributes data
   \param[in] prefix          Output prefix for each attribute output
   \param[in] attr_print_mask Which attributes should be printed
*/
void me_attr_update_print(struct omci_context *context,
			  const struct me_class *me_class,
			  uint16_t instance_id,
			  uint16_t attr_mask,
			  const void *values,
			  size_t values_size,
			  const char *prefix,
			  uint16_t attr_print_mask);

/** Check if the data was really updated (i.e. not set to the current value)

   \param[in]  context       OMCI context pointer
   \param[in]  me            Managed Entity pointer
   \param[in]  upd_data      Pointer to updated data
   \param[in]  attr_mask     Attributes which are presented in upd_data
   \param[out] upd_attr_mask Returns attribute mask which indicates what
                             attributes has been updated (may be NULL)

   \return
      - true  if data is not the same as current Managed Entity's data
*/
bool is_data_updated(struct omci_context *context,
		     const struct me *me,
		     const void *upd_data,
		     uint16_t attr_mask,
		     uint16_t *upd_attr_mask);

/** Call ME update handler to re-apply low level configration

   \param[in]  context       OMCI context pointer
   \param[in]  me            Managed Entity pointer
*/
enum omci_error me_refresh(struct omci_context *context,
			   struct me *me);

/** @} */

#endif
