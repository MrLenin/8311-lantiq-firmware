/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_debug_h
#define _omci_api_debug_h

#include <time.h>

#ifndef SWIG
#  include "ifxos_print.h"

#  define CRLF "\n"
#  undef ONU_CRLF
#  define ONU_CRLF CRLF
#endif

/** Debug Levels */
enum omci_api_dbg {
	/** Verbose outputs */
	OMCI_API_MSG = 0,

	/** Prints */
	OMCI_API_PRN = 1,

	/** Warnings */
	OMCI_API_WRN = 2,

	/** Errors */
	OMCI_API_ERR = 3,

	/** No output */
	OMCI_API_OFF = 4
};

/** \defgroup OMCI_API_DEBUG Optical Network Unit - Debug

   @{
*/

#ifndef OMCI_API_DEBUG_DISABLE

/** Debug printout macro */
#define DBG(LVL, MSG) \
	do { \
		if (dbg_api_module.level <= (LVL)) { \
			time_t now; \
			struct tm * tm_now; \
			time(&now); \
			tm_now = localtime(&now); \
			(void) omci_api_printf("[omcia] %02u:%02u:%02u %s   %s: ", \
					       tm_now->tm_hour, \
					       tm_now->tm_min, \
					       tm_now->tm_sec, \
					       dbg_api_module.name, \
					       dbg_api_levels[(LVL)]); \
			(void) omci_api_printf MSG; \
		} \
	} while (0)

/** Debug printout macro without prefix with custom module name */
#define DBG_NAKED(LVL, MSG) \
	do { \
		if (dbg_api_module.level <= (LVL)) { \
			(void) omci_api_printf MSG; \
		} \
	} while (0)

/** Debug module level structure */
struct dbg_module_level {
	/** Debug level */
	enum omci_api_dbg level;
	/** Debug level name */
	char *name;
};

extern struct dbg_module_level dbg_api_module;
extern const char *dbg_api_levels[OMCI_API_OFF+1];

/** printf wrapper */
void omci_api_printf(const char *fmt, ...);

#else

#ifdef DEBUG
#define DBG(LVL, MSG) \
	do { \
		time_t now; \
		struct tm * tm_now; \
		time(&now); \
		tm_now = localtime(&now); \
		(void) printf("[omcia] %02u:%02u:%02u: ", \
			      tm_now->tm_hour, \
			      tm_now->tm_min, \
			      tm_now->tm_sec); \
		(void) printf MSG; \
	} while (0)
#else
#define DBG(LVL, MSG)			/* empty */
#endif

#ifdef DEBUG
#define DBG_NAKED(LVL, MSG) \
	do { \
		(void) printf MSG; \
	} while (0)
#else
#define DBG_NAKED(LVL, MSG)		/* empty */
#endif

#endif

/** @} */

#endif
