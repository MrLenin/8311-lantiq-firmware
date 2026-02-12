/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_timer_h
#define _omci_api_timer_h

#include <time.h>

/** Maximum number of supported timers */
#define OMCI_API_TIMER_MAX			16

/** Use realtime signals for timers starting from this offset */
#define OMCI_API_TIMER_OFFSET			3

/** Timer handler */
typedef void (omci_timer_handler_t)(unsigned long arg);

/** Timer descriptor */
struct omci_api_timer {
	/** Timer handler */
	omci_timer_handler_t *handler;
	/** Timer handler argument */
	unsigned long arg;
#ifdef LINUX
	/** POSIX timer id */
	timer_t id;
#endif
};

/** Create timer

   \param[in]  ctx     OMCI API context pointer
   \param[in]  handler Timer handler
   \param[out] timer   Returns timer descriptor
*/
enum omci_api_return omci_api_timer_create(struct omci_api_ctx *ctx,
					   omci_timer_handler_t *handler,
					   struct omci_api_timer **timer);

/** Delete timer

   \param[in] ctx   OMCI API context pointer
   \param[in] timer Timer descriptor
*/
enum omci_api_return omci_api_timer_delete(struct omci_api_ctx *ctx,
					   struct omci_api_timer *timer);

/** Start timer

   \param[in] ctx      OMCI API context pointer
   \param[in] timer    Timer descriptor
   \param[in] periodic One shoot (false) or periodic (true) timer
   \param[in] period   Delay for one shoot or period for periodic timer (ms)
   \param[in] arg      Timer handler argument
*/
enum omci_api_return omci_api_timer_start(struct omci_api_ctx *ctx,
					  struct omci_api_timer *timer,
					  bool periodic,
					  unsigned long period,
					  unsigned long arg);

/** Stop timer

   \param[in] ctx      OMCI API context pointer
   \param[in] timer    Timer descriptor
*/
enum omci_api_return omci_api_timer_stop(struct omci_api_ctx *ctx,
					 struct omci_api_timer *timer);

/** Initialize timers subsustem

   \param[in] ctx      OMCI API context pointer
*/
enum omci_api_return omci_api_timer_init(struct omci_api_ctx *ctx);

/** Shutdown timers subsustem

   \param[in] ctx      OMCI API context pointer
*/
enum omci_api_return omci_api_timer_shutdown(struct omci_api_ctx *ctx);

#endif
