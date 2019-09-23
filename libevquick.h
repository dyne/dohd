/*************************************************************
 *          Libevquick - event wrapper library
 *   (c) 2012 Daniele Lacamera <root@danielinux.net>
 *             see COPYING for more details
 */
#ifndef __LIBEVQUICK
#define __LIBEVQUICK
#include <sys/poll.h>
#define EVQUICK_EV_READ POLLIN
#define EVQUICK_EV_WRITE POLLOUT
#define EVQUICK_EV_RETRIGGER 0x4000

struct evquick_event;
struct evquick_timer;
typedef struct evquick_event evquick_event;
typedef struct evquick_timer evquick_timer;
typedef struct evquick_ctx * CTX;

#ifdef EVQUICK_PTHREAD
CTX evquick_init(void);
void evquick_loop(CTX ctx);
void evquick_fini(CTX ctx);
evquick_event *evquick_addevent(CTX ctx, int fd, short events,
                                void (*callback)
                                    (CTX ctx, int fd, short revents, void *arg),
                                void (*err_callback)
                                    (CTX ctx, int fd, short revents, void *arg),
                                void *arg);

void evquick_delevent(CTX ctx, evquick_event *e);
evquick_timer *evquick_addtimer(CTX ctx, unsigned long long interval, short flags,
                                void (*callback)(CTX ctx, void *arg),
                                void *arg);

void evquick_deltimer(CTX ctx, evquick_timer *t);

#else
/* Initialize evquick loop
 * =========
 * To be called before any other function.
 *
 * Returns: the Context CTX upon success, NULL otherwise.
 *          'errno' is set accordingly
 */
CTX evquick_init(void);

/* Main loop
 * =========
 *
 * This is your application main loop and
 * should never return.
 *
 */
void evquick_loop(void);

/* Deallocate event loop
 * ========
 *
 * To be called to clean up the resources used by your
 * event loop.
 *
 */
void evquick_fini(void);

/* Event wrapper for file fd.
 * ==========
 * Arguments:
 * fd: file descriptor to watch for events
 * events: type of event to monitor.
 *         Can be EVQUICK_EV_READ, EVQUICK_EV_WRITE or both, using "|"
 * callback: function called by the loop upon events
 * err_callback: function called by the loop upon errors
 * arg: extra argument passed to callbacks
 *
 * Returns:
 * A pointer to the event object created, or NULL if an error occurs,
 * and errno is set accordingly.
 *
 */
evquick_event *evquick_addevent(int fd, short events,
                                void (*callback)
                                    (int fd, short revents, void *arg),
                                void (*err_callback)
                                    (int fd, short revents, void *arg),
                                void *arg);

/* Delete event
 * ==========
 *
 * Delete a previously created event.
 */
void evquick_delevent(evquick_event *e);


/* Timer
 * ==========
 * Arguments:
 * interval: number of milliseconds until the timer expiration
 * flags: 0, or EVQUICK_EV_RETRIGGER to set automatic retriggering with the
 *        same interval
 * callback: function called upon expiration
 * arg: extra argument passed to the callback
 */
evquick_timer *evquick_addtimer(unsigned long long interval, short flags,
                                void (*callback)(void *arg),
                                void *arg);


/* Delete timer
 * ==========
 *
 * Delete a previously created timer.
 */
void evquick_deltimer(evquick_timer *t);


#endif /* No pthreads. */


#endif

