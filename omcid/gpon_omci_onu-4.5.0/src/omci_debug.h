/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_debug_h
#define _omci_debug_h

#include <stdarg.h>
#include <time.h>
#ifdef LINUX
#include <sys/time.h>
#endif

struct me;

/** \defgroup OMCI_DEBUG Optical Network Unit - Debug

    OMCI ONU consists of several debug modules (\ref omci_dbg_module) and
    each module is assigned reporting level (\ref omci_dbg). Only messages
    with selected level or higher (see numeric values of \ref omci_dbg)
    will be printed. Routines like \ref dbg_msg, \ref dbg_prn, \ref dbg_wrn,
    \ref me_dbg_err (and so on) can be used to print debugging information on
    the appropriate debug level.

    Each file that includes omci_debug.h file in order to support debugging
    should define \ref OMCI_DBG_MODULE to appropriate module from
    \ref omci_dbg_module. This will lead to the definition of static variable
    called 'dbg_module' (see omci_common.h) which is used by the debugging
    rotuines.

    When debugging, it's usually overwhelming to see all messages for the
    debug module, so it's possible to place '\#define DEBUG' at the first
    line of the source file which will cause all dbg_xyz and me_dbg_xyz
    to print it's arguments, no matter what debug level is currently selected
    for module (this way you can switch off debugging for the whole
    module and see only printouts that you want from particular source files).
    Note, that this feature works only on per-file level, not per-routine!

   @{
*/

/** OMCI daemon prefix */
#define DBG_PREFIX         "[omcid] "

#if !defined(OMCI_DEBUG_DISABLE) && defined(OMCI_PRIVATE)

#ifndef OMCI_DBG_MODULE
#  error Please define OMCI_DBG_MODULE
#endif

/** Debug module level structure */
struct dbg_module_level {
	/** Debug level */
	enum omci_dbg level;
	/** Debug level name */
	char *name;
};

extern struct dbg_module_level dbg_modules[OMCI_DBG_MODULE_NUM];

extern char *dbg_levels[OMCI_DBG_LVL_NUM];

void omci_hook(void *context,
	       const char *cmd,
	       const uint32_t class_id,
	       const uint32_t instance_id);

static inline void dbg_vnaked(enum omci_dbg lvl, enum omci_dbg_module mod,
			      const char *fmt, va_list args)
{
#ifndef DEBUG
	if (dbg_modules[mod].level <= lvl)
#endif
		omci_vprintf(fmt, args);
}

static inline void dbg_naked(enum omci_dbg lvl, enum omci_dbg_module mod,
			     const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[mod].level > lvl)
		return;
#endif

	va_start(args, fmt);
	dbg_vnaked(lvl, mod, fmt, args);
	va_end(args);
}

static inline void vdbg(enum omci_dbg lvl, const char *fmt, va_list args)
{
#ifdef LINUX
	struct timeval tv;
#else
	time_t now;
	struct tm * tm_now;
#endif

#ifndef DEBUG
	if (dbg_modules[dbg_module].level <= lvl) {
#endif

#ifdef LINUX
		gettimeofday(&tv, NULL);

		omci_printf(DBG_PREFIX "%10u.%-10u %s %s: ",
			    tv.tv_sec,
			    tv.tv_usec,
			    dbg_modules[dbg_module].name,
			    dbg_levels[lvl]);

#else
		time(&now);
		tm_now = localtime(&now);

		omci_printf(DBG_PREFIX "%02u:%02u:%02u %s %s: ",
			    tm_now->tm_hour,
			    tm_now->tm_min,
			    tm_now->tm_sec,
			    dbg_modules[dbg_module].name,
			    dbg_levels[lvl]);
#endif

		omci_vprintf(fmt, args);
#ifndef DEBUG
	}
#endif
}

static inline void dbg(enum omci_dbg lvl, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vdbg(lvl, fmt, args);
	va_end(args);
}

static inline void dbg_in(const char *func, const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_MSG)
		return;
#endif

	dbg(OMCI_DBG_MSG, "IN  - %s(", func);

	va_start(args, fmt);
	dbg_vnaked(OMCI_DBG_MSG, dbg_module, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_MSG, dbg_module, ")\n");
}

static inline void dbg_out(const char *func)
{
#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_MSG)
		return;
#endif

	dbg(OMCI_DBG_MSG, "OUT - %s()\n", func);
}

static inline void dbg_out_ret(const char *func, enum omci_error status)
{
#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_MSG)
		return;
#endif

	dbg(OMCI_DBG_MSG, "OUT - %s(%d)\n", func, (int)status);
}

static inline void dbg_prn(const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_PRN)
		return;
#endif

	va_start(args, fmt);
	vdbg(OMCI_DBG_PRN, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_PRN, dbg_module, "\n");
}

static inline void dbg_msg(const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_MSG)
		return;
#endif

	va_start(args, fmt);
	vdbg(OMCI_DBG_MSG, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_MSG, dbg_module, "\n");
}

static inline void dbg_wrn(const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_WRN)
		return;
#endif

	va_start(args, fmt);
	vdbg(OMCI_DBG_WRN, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_WRN, dbg_module, "\n");
}

static inline void dbg_err(const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_ERR)
		return;
#endif

	va_start(args, fmt);
	vdbg(OMCI_DBG_ERR, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_ERR, dbg_module, "\n");
}


static inline void me_dbg_prn(const struct me *me, const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_PRN)
		return;
#endif

	dbg(OMCI_DBG_PRN, "%u@%u ",
	    me->class->class_id,
	    me->instance_id);

	va_start(args, fmt);
	dbg_vnaked(OMCI_DBG_PRN, dbg_module, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_PRN, dbg_module, "\n");
}

static inline void me_dbg_msg(const struct me *me, const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_MSG)
		return;
#endif

	dbg(OMCI_DBG_MSG, "%u@%u ",
	    me->class->class_id,
	    me->instance_id);

	va_start(args, fmt);
	dbg_vnaked(OMCI_DBG_MSG, dbg_module, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_MSG, dbg_module, "\n");
}

static inline void me_dbg_wrn(const struct me *me, const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_WRN)
		return;
#endif

	dbg(OMCI_DBG_WRN, "%u@%u ",
	    me->class->class_id,
	    me->instance_id);

	va_start(args, fmt);
	dbg_vnaked(OMCI_DBG_WRN, dbg_module, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_WRN, dbg_module, "\n");
}

static inline void me_dbg_err(const struct me *me, const char *fmt, ...)
{
	va_list args;

#ifndef DEBUG
	if (dbg_modules[dbg_module].level > OMCI_DBG_ERR)
		return;
#endif

	dbg(OMCI_DBG_ERR, "%u@%u ",
	    me->class->class_id,
	    me->instance_id);

	va_start(args, fmt);
	dbg_vnaked(OMCI_DBG_ERR, dbg_module, fmt, args);
	va_end(args);

	dbg_naked(OMCI_DBG_ERR, dbg_module, "\n");
}

#else

static inline void omci_hook(void *context,
			     const char *cmd,
			     const uint32_t class_id,
			     const uint32_t instance_id) { }
static inline void dbg_vnaked(enum omci_dbg lvl, enum omci_dbg_module mod,
			      const char *fmt, va_list args) { }
static inline void dbg_naked(enum omci_dbg lvl, enum omci_dbg_module mod,
			     const char *fmt, ...) { }
static inline void vdbg(enum omci_dbg lvl, const char *fmt, va_list args) { }
static inline void dbg(enum omci_dbg lvl, const char *fmt, ...) { }
static inline void dbg_in(const char *func, const char *fmt, ...) { }
static inline void dbg_out(const char *func) { }
static inline void dbg_out_ret(const char *func, enum omci_error status) { }
static inline void dbg_prn(const char *fmt, ...) { }
static inline void dbg_msg(const char *fmt, ...) { }
static inline void dbg_wrn(const char *fmt, ...) { }
static inline void dbg_err(const char *fmt, ...) { }
static inline void me_dbg_prn(const struct me *me, const char *fmt, ...) { }
static inline void me_dbg_msg(const struct me *me, const char *fmt, ...) { }
static inline void me_dbg_wrn(const struct me *me, const char *fmt, ...) { }
static inline void me_dbg_err(const struct me *me, const char *fmt, ...) { }

#endif

/** @} */

#endif
