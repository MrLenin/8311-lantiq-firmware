/******************************************************************************
 * omci_8311_log.h — 8311 mod debug logging macros
 *
 * DLOG(fmt, ...): Debug log to a per-component file in /tmp/.
 * DVLOG(fmt, ...): Verbose debug log (same mechanism, different name for
 *                  call sites that produce high-volume output).
 *
 * Logging is gated on the existence of /tmp/8311_debug. When the flag
 * file is absent, DLOG/DVLOG are effectively no-ops (a single access()
 * syscall per invocation). To enable:
 *
 *   touch /tmp/8311_debug
 *
 * To disable (immediate, no restart needed):
 *
 *   rm /tmp/8311_debug
 *
 * The flag is automatically cleared on reboot (tmpfs).
 *
 * Usage: define DLOG_FILE before including this header:
 *
 *   #define DLOG_FILE "/tmp/8311_api.log"
 *   #include "omci_8311_log.h"
 *
 ******************************************************************************/

#ifndef _OMCI_8311_LOG_H
#define _OMCI_8311_LOG_H

#include <stdio.h>
#include <unistd.h>

#define _8311_DEBUG_FLAG "/tmp/8311_debug"

#ifndef DLOG_FILE
#define DLOG_FILE "/tmp/8311_omcid.log"
#endif

#define DLOG(fmt, ...) do { \
	if (access(_8311_DEBUG_FLAG, F_OK) == 0) { \
		FILE *_f = fopen(DLOG_FILE, "a"); \
		if (_f) { fprintf(_f, fmt "\n", ##__VA_ARGS__); fclose(_f); } \
	} \
} while (0)

#define DVLOG(fmt, ...) DLOG(fmt, ##__VA_ARGS__)

#endif /* _OMCI_8311_LOG_H */
