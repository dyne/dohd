/*************************************************************
 *          Libevquick - event wrapper library
 *   (c) 2012 Daniele Lacamera <root@danielinux.net>
 *             see COPYING for more details
 */

#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <errno.h>
#include "heap.h"
#include "libevquick.h"
#include <time.h>
#include <fcntl.h>
#include <assert.h>

/*
 * Maximum events returned per epoll_wait call.
 * This bounds the stack-allocated event array and determines batch size.
 * Higher values reduce syscall overhead under high load but use more stack.
 * 512 balances efficiency with typical ulimit stack sizes.
 */
#ifndef EVQUICK_MAX_EVENTS
#define EVQUICK_MAX_EVENTS 512
#endif



struct evquick_ctx;
#ifdef EVQUICK_PTHREAD
#include <pthread.h>
#else /* NO EVQUICK_PTHREAD defined */
static struct evquick_ctx *ctx;
#   define CTX_LIST (NULL)
#   define ctx_add(c) do{}while(0)
#   define ctx_del(c) do{}while(0)
#   define ctx_signal_dispatch() do{}while(0)
#   define evquick_get_min_timer() (NULL)
#endif


struct evquick_event
{
    int fd;
    short events;
    int valid;   /* Flag to mark event as still active */
#ifdef EVQUICK_PTHREAD
    void (*callback)(CTX ctx, int fd, short revents, void *arg);
    void (*err_callback)(CTX ctx, int fd, short revents, void *arg);
#else
    void (*callback)(int fd, short revents, void *arg);
    void (*err_callback)(int fd, short revents, void *arg);
#endif
    void *arg;
    struct evquick_event *next;
};

struct evquick_timer
{
    unsigned long long interval;
    int id;
    short flags;
#ifdef EVQUICK_PTHREAD
    void (*callback)(CTX ctx, void *arg);
#else
    void (*callback)(void *arg);
#endif
    void *arg;
};

struct evquick_timer_instance
{
    unsigned long long expire;
    int id;
    struct evquick_timer *ev_timer;
};
typedef struct evquick_timer_instance evquick_timer_instance;

DECLARE_HEAP(evquick_timer_instance, expire)

struct evquick_ctx
{
    int time_machine[2];
    int epfd;                    /* epoll file descriptor */
    int n_events;
    struct evquick_event *events;
    struct evquick_event *pending_free; /* Events to free after event batch */
    heap_evquick_timer_instance *timers;
    int giveup;
    timer_t timer_id;
#ifdef EVQUICK_PTHREAD
    struct evquick_ctx *next;
#endif
};

static void timer_new(CTX ctx)
{
    struct sigevent evp = {};
    evp.sigev_notify = SIGEV_SIGNAL;
    evp.sigev_signo = SIGALRM;
    timer_create(CLOCK_REALTIME, &evp, &ctx->timer_id);
}

static void timer_on(CTX ctx, unsigned long long interval)
{
    const struct itimerspec ival = { {0, 0} , {interval / 1000, (interval % 1000) * (1000 * 1000) }};
    timer_settime(ctx->timer_id, 0, &ival, NULL);
}

#ifdef EVQUICK_PTHREAD
static pthread_mutex_t ctx_list_mutex;
static struct evquick_ctx *CTX_LIST = NULL;

static void ctx_add(struct evquick_ctx *c) {
    pthread_mutex_lock(&ctx_list_mutex);
    c->next = CTX_LIST;
    CTX_LIST = c;
    pthread_mutex_unlock(&ctx_list_mutex);
}

static void ctx_del(struct evquick_ctx *delme) {
    struct evquick_ctx *p = NULL, *c  = CTX_LIST;
    while(c) {
        if (c == delme) {
            pthread_mutex_lock(&ctx_list_mutex);
            if (p)
                p->next = c->next;
            else
                CTX_LIST = NULL;
            pthread_mutex_unlock(&ctx_list_mutex);
            return;
        }
        p = c;
        c = c->next;
    }
}

static void ctx_signal_dispatch(void)
{
    struct evquick_ctx *c = CTX_LIST;
    char chr = 't';
    while (c) {
        if (write(c->time_machine[1], &chr, 1) < 0) {
            /* best-effort wakeup */
        }
        c = c->next;
    }
}
#endif


static void sig_alrm_handler(int signo)
{
    if (signo == SIGALRM) {
        ctx_signal_dispatch();
#ifndef EVQUICK_PTHREAD
        if (ctx) {
            char c = 't';
            if (write(ctx->time_machine[1], &c, 1) < 0) {
                /* best-effort wakeup */
            }
        }
#endif
    }
}


#define LOOP_BREAK() sig_alrm_handler(SIGALRM)


#ifdef EVQUICK_PTHREAD
evquick_event *evquick_addevent(CTX ctx, int fd, short events,
    void (*callback)(CTX ctx, int fd, short revents, void *arg),
    void (*err_callback)(CTX ctx, int fd, short revents, void *arg),
    void *arg)
#else
evquick_event *evquick_addevent(int fd, short events,
    void (*callback)(int fd, short revents, void *arg),
    void (*err_callback)(int fd, short revents, void *arg),
    void *arg)
#endif
{
    evquick_event *e;
    struct epoll_event ev;
    if (!ctx)
        return NULL;

    e = malloc(sizeof(evquick_event));
    if (!e)
        return e;
    e->fd = fd;
    e->events = events;
    e->valid = 1;
    e->callback = callback;
    e->err_callback = err_callback;
    e->arg = arg;

    /* Add to epoll */
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    if (events & EVQUICK_EV_WRITE)
        ev.events |= EPOLLOUT;
    ev.data.ptr = e;
    if (epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        free(e);
        return NULL;
    }

    e->next = ctx->events;
    ctx->events = e;
    ctx->n_events++;
    return e;
}

#ifdef EVQUICK_PTHREAD
void evquick_delevent(CTX ctx, evquick_event *e)
#else
void evquick_delevent(evquick_event *e)
#endif
{
    int deleted = 0;
    evquick_event *cur, *prev;
    if (!ctx || !e)
        return ;

    /* Mark as invalid first (for O(1) check in event loop) */
    e->valid = 0;

    /* Remove from epoll */
    epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, e->fd, NULL);

    cur = ctx->events;
    prev = NULL;
    while(cur) {
        if (cur == e) {
            if (!prev)
                ctx->events = e->next;
             else
                prev->next = e->next;
            /* Add to pending_free list instead of immediate free.
             * This avoids use-after-free if event is in current epoll batch. */
            e->next = ctx->pending_free;
            ctx->pending_free = e;
            deleted++;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    if (deleted) {
        ctx->n_events--;
    }
}

static void timer_trigger(CTX ctx, evquick_timer *t, unsigned long long now,
    unsigned long long expire)
{
    unsigned long long interval;
    evquick_timer_instance tev, *first;
    if (!ctx)
        return ;
    tev.ev_timer = t;
    tev.expire = expire;
    t->id = heap_insert(ctx->timers, &tev);
    first = heap_first(ctx->timers);
    if (first) {
        if (first->expire <= now)
            interval = 1;
        else
            interval = first->expire - now;
        timer_on(ctx, interval);
    }
}

static unsigned long long gettimeofdayms(void)
{
    struct timeval tv;
    unsigned long long ret;
    gettimeofday(&tv, NULL);
    ret = (unsigned long long)tv.tv_sec * 1000ULL;
    ret += (unsigned long long)tv.tv_usec / 1000ULL;
    return ret;
}




/*** PUBLIC API ***/
#ifdef EVQUICK_PTHREAD
evquick_timer *evquick_addtimer(CTX ctx,
    unsigned long long interval, short flags,
    void (*callback)(CTX ctx, void *arg),
    void *arg)
#else
evquick_timer *evquick_addtimer(
    unsigned long long interval, short flags,
    void (*callback)(void *arg),
    void *arg)
#endif
{
    unsigned long long now = gettimeofdayms();
    if (!ctx)
        return NULL;

    evquick_timer *t = malloc(sizeof(evquick_timer));
    if (!t)
        return t;
    t->interval = interval;
    t->flags = flags;
    t->callback = callback;
    t->arg = arg;
    timer_trigger(ctx, t, now, now + t->interval);

    return t;
}

#ifdef EVQUICK_PTHREAD
void evquick_deltimer(CTX ctx, evquick_timer *t)
#else
void evquick_deltimer(evquick_timer *t)
#endif
{
#ifdef EVQUICK_PTHREAD
    if (!ctx || !t)
        return;
    if (heap_delete(ctx->timers, t->id) == 0)
        free(t);
#else
    if (!t)
        return;
    if (heap_delete(ctx->timers, t->id) == 0)
        free(t);
#endif
}

CTX evquick_init(void)
{
    int yes = 1;
    struct sigaction act;
    struct epoll_event ev;
#ifdef EVQUICK_PTHREAD
    CTX ctx;
    pthread_mutex_init(&ctx_list_mutex, NULL);
#endif
    ctx = calloc(1, sizeof(struct evquick_ctx));
    if (!ctx)
        return NULL;
    ctx->giveup = 0;
    ctx->epfd = -1;
    ctx->time_machine[0] = -1;
    ctx->time_machine[1] = -1;

    ctx->timers = heap_init();
    if (!ctx->timers)
        goto fail;
    if(pipe(ctx->time_machine) < 0)
        goto fail;
    (void)yes;
    fcntl(ctx->time_machine[1], F_SETFL, O_NONBLOCK);

    /* Create epoll instance */
    ctx->epfd = epoll_create1(0);
    if (ctx->epfd < 0) {
        perror("epoll_create1");
        goto fail;
    }

    /* Add time_machine pipe to epoll for timer wakeups */
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;  /* NULL ptr indicates time_machine */
    if (epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->time_machine[0], &ev) < 0) {
        perror("epoll_ctl time_machine");
        goto fail;
    }

    ctx->n_events = 1;
    memset(&act, 0, sizeof(act));
    act.sa_handler = sig_alrm_handler;
    act.sa_flags = SA_NODEFER;
    if (sigaction(SIGALRM, &act, NULL) < 0) {
        perror("Setting alarm signal");
        goto fail;
    }
    ctx_add(ctx);
    timer_new(ctx);
    return ctx;

fail:
    if (ctx->epfd >= 0)
        close(ctx->epfd);
    if (ctx->time_machine[0] >= 0)
        close(ctx->time_machine[0]);
    if (ctx->time_machine[1] >= 0)
        close(ctx->time_machine[1]);
    if (ctx->timers)
        heap_destroy(ctx->timers);
    free(ctx);
    return NULL;
}



static void timer_check(CTX ctx)
{
    evquick_timer_instance t, *first;
    unsigned long long now = gettimeofdayms();

    first = heap_first(ctx->timers);
    while(first && (first->expire <= now)) {
        heap_peek(ctx->timers, &t);
        if (!t.ev_timer) {
            first = heap_first(ctx->timers);
            continue;
        } else if (t.ev_timer->flags & EVQUICK_EV_RETRIGGER) {
            timer_trigger(ctx, t.ev_timer, now, now + t.ev_timer->interval);
#ifdef EVQUICK_PTHREAD
            t.ev_timer->callback(ctx, t.ev_timer->arg);
#else
            t.ev_timer->callback(t.ev_timer->arg);
#endif
            /* Don't free the timer, reuse for next instance
             * that has just been scheduled.
             */
        } else {
            /* One shot, invoke callback,
             * then destroy the timer. */
#ifdef EVQUICK_PTHREAD
            t.ev_timer->callback(ctx, t.ev_timer->arg);
#else
            t.ev_timer->callback(t.ev_timer->arg);
#endif
            free(t.ev_timer);
        }
        first = heap_first(ctx->timers);
    }
    if (first) {
        unsigned long long interval = 1;
        if (first->expire > now)
            interval = first->expire - now;
        timer_on(ctx, interval);
    }
}

#ifdef EVQUICK_PTHREAD
void evquick_loop(CTX ctx)
#else
void evquick_loop(void)
#endif
{
    struct epoll_event ep_events[EVQUICK_MAX_EVENTS];
    int nfds, i;

    for(;;) {
        if (!ctx || ctx->giveup)
            break;

        nfds = epoll_wait(ctx->epfd, ep_events, EVQUICK_MAX_EVENTS, 3600 * 1000);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            /* Log error and continue instead of breaking */
            perror("epoll_wait");
            continue;
        }

        for (i = 0; i < nfds; i++) {
            evquick_event *e = ep_events[i].data.ptr;

            /* NULL ptr means time_machine pipe for timer wakeups */
            if (e == NULL) {
                char discard;
                if (read(ctx->time_machine[0], &discard, 1) < 0) {
                    if (errno != EINTR && errno != EAGAIN)
                        perror("time_machine read");
                }
                timer_check(ctx);
                continue;
            }

            /* O(1) check: skip if event was deleted by prior callback */
            if (!e->valid)
                continue;

            /* Handle error events */
            if ((ep_events[i].events & (EPOLLHUP | EPOLLERR)) && e->err_callback) {
#ifdef EVQUICK_PTHREAD
                e->err_callback(ctx, e->fd, ep_events[i].events, e->arg);
#else
                e->err_callback(e->fd, ep_events[i].events, e->arg);
#endif
            } else if (e->callback) {
                /* Call normal callback for read/write or if no err_callback */
#ifdef EVQUICK_PTHREAD
                e->callback(ctx, e->fd, ep_events[i].events, e->arg);
#else
                e->callback(e->fd, ep_events[i].events, e->arg);
#endif
            }
        }

        /* Free events that were deleted during this batch.
         * Note: Deferred freeing prevents use-after-free when events are
         * deleted from within callbacks. If many events are deleted in one
         * batch, memory is held until this point. This is acceptable for
         * typical workloads but could cause temporary memory spikes under
         * extreme conditions. */
        while (ctx->pending_free) {
            evquick_event *e = ctx->pending_free;
            ctx->pending_free = e->next;
            free(e);
        }
    } /* main loop */
    ctx_del(ctx);
    ctx = NULL;
}

#ifdef EVQUICK_PTHREAD
void evquick_fini(CTX ctx)
#else
void evquick_fini(void)
#endif
{
    ctx->giveup = 1;
    timer_on(ctx, 1000);
}
