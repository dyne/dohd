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
#include "heap.h"
#include "libevquick.h"
#include <time.h>
#include <fcntl.h>
#include <assert.h>



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
    int changed;
    int n_events;
    int last_served;
    struct pollfd *pfd;
    struct evquick_event *events;
    struct evquick_event *_array;
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
            timer_on(c, 1);
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
            if (write(ctx->time_machine[1], &c, 1) < 0)
                timer_on(ctx, 1);
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
    if (!ctx)
        return NULL;

    e = malloc(sizeof(evquick_event));
    if (!e)
        return e;
    e->fd = fd;
    e->events = events;
    e->callback = callback;
    e->err_callback = err_callback;
    e->arg = arg;

    ctx->changed = 1;

    e->next = ctx->events;
    ctx->events = e;
    ctx->n_events++;
    LOOP_BREAK();
    return e;
}

#ifdef EVQUICK_PTHREAD
void evquick_delevent(CTX ctx, evquick_event *e)
#else
void evquick_delevent(evquick_event *e)
#endif
{
    evquick_event *cur, *prev;
    if (!ctx)
        return ;
    ctx->changed = 1;
    cur = ctx->events;
    prev = NULL;
    while(cur) {
        if (cur == e) {
            if (!prev)
                ctx->events = e->next;
             else
                prev->next = e->next;
            free(e);
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    ctx->n_events--;
    LOOP_BREAK();
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

static void rebuild_poll(CTX ctx)
{
    int i = 1;
    evquick_event *e;
    void *ptr = NULL;
    if (!ctx)
        return ;
    e = ctx->events;

    if (ctx->pfd) {
        ptr = ctx->pfd;
        ctx->pfd = NULL;
        free(ptr);
    }
    if (ctx->_array) {
        ptr = ctx->_array;
        ctx->_array = NULL;
        free(ptr);
    }
    ctx->pfd = malloc(sizeof(struct pollfd) * (ctx->n_events + 1));
    ctx->_array = malloc(sizeof(evquick_event) * (ctx->n_events + 1));

    if ((!ctx->pfd) || (!ctx->_array)) {
        /* TODO: notify error, events are disabled.
         * perhaps provide a context-wide callback for errors.
         */
        perror("MEMORY");
        ctx->n_events = 1;
        ctx->changed = 0;
        return;
    }

    ctx->pfd[0].fd = ctx->time_machine[0];
    ctx->pfd[0].events = POLLIN;

    while((e) && (i <= ctx->n_events)) {
        memcpy(ctx->_array + i, e, sizeof(evquick_event));
        ctx->pfd[i].fd = e->fd;
        ctx->pfd[i++].events = (e->events & (POLLIN | POLLOUT)) | (POLLHUP | POLLERR);
        e = e->next;
    }
    ctx->last_served = 1;
    ctx->changed = 0;
}


static void serve_event(CTX ctx, int n)
{
    evquick_event *e = ctx->_array + n;
    if (!ctx)
        return ;
    if (n >= ctx->n_events)
        return;
    if (e) {
        ctx->last_served = n;
        if ((ctx->pfd[n].revents & (POLLHUP | POLLERR)) && e->err_callback)
#ifdef EVQUICK_PTHREAD
            e->err_callback(ctx, e->fd, ctx->pfd[n].revents, e->arg);
#else
            e->err_callback(e->fd, ctx->pfd[n].revents, e->arg);
#endif
        else {
#ifdef EVQUICK_PTHREAD
            e->callback(ctx, e->fd, ctx->pfd[n].revents, e->arg);
#else
            e->callback(e->fd, ctx->pfd[n].revents, e->arg);
#endif
        }
    }
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
    ctx->changed = 1;

    return t;
}

#ifdef EVQUICK_PTHREAD
void evquick_deltimer(CTX ctx, evquick_timer *t)
#else
void evquick_deltimer(evquick_timer *t)
#endif
{
    heap_delete(ctx->timers, t->id);
}

CTX evquick_init(void)
{
    int yes = 1;
    struct sigaction act;
#ifdef EVQUICK_PTHREAD
    CTX ctx;
    pthread_mutex_init(&ctx_list_mutex, NULL);
#endif
    ctx = calloc(1, sizeof(struct evquick_ctx));
    if (!ctx)
        return NULL;
    ctx->giveup = 0;
    ctx->timers = heap_init();
    if (!ctx->timers)
        return NULL;
    if(pipe(ctx->time_machine) < 0)
        return NULL;
    fcntl(ctx->time_machine[1], O_NONBLOCK, &yes);
    ctx->n_events = 1;
    ctx->changed = 1;
    memset(&act, 0, sizeof(act));
    act.sa_handler = sig_alrm_handler;
    act.sa_flags = SA_NODEFER;
    if (sigaction(SIGALRM, &act, NULL) < 0) {
        perror("Setting alarm signal");
        return NULL;
    }
    ctx_add(ctx);
    timer_new(ctx);
    return ctx;
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
    int pollret, i;
    for(;;) {
        if (!ctx || ctx->giveup)
            break;

        if (ctx->changed) {
            rebuild_poll(ctx);
            continue;
        }

        if (ctx->pfd == NULL) {
            sleep(3600);
            ctx->changed = 1;
            continue;
        }

        pollret = poll(ctx->pfd, ctx->n_events, 3600 * 1000);
        if (pollret <= 0)
            continue;

        if ((ctx->pfd[0].revents & POLLIN) == POLLIN) {
            char discard;
            read(ctx->time_machine[0], &discard, 1);
            timer_check(ctx);
            continue;
        }
        if (ctx->n_events < 2)
            continue;

        for (i = ctx->last_served +1; i < ctx->n_events; i++) {
            if (ctx->pfd[i].revents != 0) {
                serve_event(ctx, i);
                goto end_loop;
            }
        }
        for (i = 1; i <= ctx->last_served; i++) {
            if (ctx->pfd[i].revents != 0) {
                serve_event(ctx, i);
                goto end_loop;
            }
        }
    end_loop:
        continue;

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
