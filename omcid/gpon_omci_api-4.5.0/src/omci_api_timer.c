/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <signal.h>
#include <assert.h>

#include "ifxos_memory_alloc.h"

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "omci_api_timer.h"

#ifdef LINUX

static struct omci_api_timer *signo2timer(struct omci_api_ctx *ctx,
					  int signo)
{
	return ctx->timer[signo - (SIGRTMIN + OMCI_API_TIMER_OFFSET)];
}

static int pos2signo(int pos)
{
	return SIGRTMIN + OMCI_API_TIMER_OFFSET + pos;
}

static void timer_signal_handler(int signo, siginfo_t *info, void *ucontext)
{
	struct omci_api_ctx *ctx = info->si_value.sival_ptr;
	struct omci_api_timer *timer;

	if (!ctx) {
		DBG(OMCI_API_WRN,
		    ("Received timer signal without context pointer\n"));
		return;
	}

	timer = signo2timer(ctx, signo);

	if (!timer) {
		DBG(OMCI_API_WRN,
		    ("Received signal (%d) for non-existing timer\n", signo));
		return;
	}

	timer->handler(timer->arg);
}

static
struct omci_api_timer *timer_create_with_signal(struct omci_api_ctx *ctx,
						int signo,
						omci_timer_handler_t *handler)
{
	struct sigevent sev = { 0 };
	timer_t timerid;
	struct sigaction sa;
	struct omci_api_timer *t;

	if (sigemptyset(&sa.sa_mask))
		return NULL;

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = timer_signal_handler;

	if (sigaction(signo, &sa, NULL))
		return NULL;

	sev.sigev_signo = signo;
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_value.sival_ptr = ctx;

	t = IFXOS_MemAlloc(sizeof(*t));
	if (!t)
		return NULL;

	memset(t, 0, sizeof(*t));

	if (timer_create(CLOCK_REALTIME, &sev, &timerid)) {
		IFXOS_MemFree(t);
		return NULL;
	}

	t->handler = handler;
	t->id = timerid;

	return t;
}

enum omci_api_return omci_api_timer_create(struct omci_api_ctx *ctx,
					   omci_timer_handler_t *handler,
					   struct omci_api_timer **timer)
{
	int i;

	assert(timer && handler);

	for (i = 0; i < OMCI_API_TIMER_MAX; i++) {
		if (ctx->timer[i])
			continue;

		ctx->timer[i] = timer_create_with_signal(ctx, pos2signo(i),
							 handler);
		*timer = ctx->timer[i];

		if (!ctx->timer[i]) {
			DBG(OMCI_API_WRN, ("Can't create POSIX timer\n"));
			return OMCI_API_NO_MEMORY;
		}

		return OMCI_API_SUCCESS;
	}

	return OMCI_API_NOT_AVAIL;
}

enum omci_api_return omci_api_timer_delete(struct omci_api_ctx *ctx,
					   struct omci_api_timer *timer)
{
	int i;

	assert(timer);

	for (i = 0; i < OMCI_API_TIMER_MAX; i++) {
		if (ctx->timer[i] != timer)
			continue;

		(void)omci_api_timer_stop(ctx, timer);

		if (timer_delete(timer->id))
			DBG(OMCI_API_WRN, ("Can't delete POSIX timer\n"));

		IFXOS_MemFree(ctx->timer[i]);
		ctx->timer[i] = NULL;

		return OMCI_API_SUCCESS;
	}

	return OMCI_API_NOT_FOUND;
}

enum omci_api_return omci_api_timer_start(struct omci_api_ctx *ctx,
					  struct omci_api_timer *timer,
					  bool periodic,
					  unsigned long period,
					  unsigned long arg)
{
	struct itimerspec ts;

	assert(timer);

	timer->arg = arg;

	ts.it_value.tv_sec = period / 1000;
	ts.it_value.tv_nsec = (period % 1000) * 1000000;

	if (periodic) {
		ts.it_interval = ts.it_value;
	} else {
		ts.it_interval.tv_sec = 0;
		ts.it_interval.tv_nsec = 0;
	}

	if (timer_settime(timer->id, 0, &ts, NULL))
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_timer_stop(struct omci_api_ctx *ctx,
					 struct omci_api_timer *timer)
{
	struct itimerspec ts;

	assert(timer);

	ts.it_value.tv_sec = 0;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;

	if (timer_settime(timer->id, 0, &ts, NULL))
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_timer_init(struct omci_api_ctx *ctx)
{
	int timers_available = SIGRTMAX - SIGRTMIN - OMCI_API_TIMER_OFFSET;

	if (timers_available < OMCI_API_TIMER_MAX) {
		DBG(OMCI_API_ERR,
		    ("Number of supported timers (%d) is lesser "
		    "than OMCI_API_TIMER_MAX (%d)\n", timers_available,
		    OMCI_API_TIMER_MAX));
		return OMCI_API_ERROR;
	}

	memset(ctx->timer, 0, sizeof(ctx->timer));

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_timer_shutdown(struct omci_api_ctx *ctx)
{
	int i;

	for (i = 0; i < OMCI_API_TIMER_MAX; i++)
		if (ctx->timer[i])
			if (omci_api_timer_delete(ctx, ctx->timer[i]) !=
			    OMCI_API_SUCCESS)
				DBG(OMCI_API_WRN,
				    ("Can't delete timer %d\n", i));

	return OMCI_API_SUCCESS;
}

#else

enum omci_api_return omci_api_timer_create(struct omci_api_ctx *ctx,
					   omci_timer_handler_t *handler,
					   struct omci_api_timer **timer)
{
	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_timer_delete(struct omci_api_ctx *ctx,
					   struct omci_api_timer *timer)
{
	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_timer_start(struct omci_api_ctx *ctx,
					  struct omci_api_timer *timer,
					  bool periodic,
					  unsigned long period,
					  unsigned long arg)
{
	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_timer_stop(struct omci_api_ctx *ctx,
					 struct omci_api_timer *timer)
{
	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_timer_init(struct omci_api_ctx *ctx)
{
	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_timer_shutdown(struct omci_api_ctx *ctx)
{
	return OMCI_API_SUCCESS;
}

#endif
