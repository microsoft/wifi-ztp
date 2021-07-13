
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "event_loop.h"
#include "time_utils.h"
#include "ztp_log.h"

/**
 * @brief Allocates and initializes a new sd_event_source_list_item
 *
 * @return struct sd_event_source_list_item*
 */
static struct sd_event_source_list_item *
sd_event_source_list_item_alloc()
{
    struct sd_event_source_list_item *task;
    task = calloc(1, sizeof *task);
    if (!task)
        return NULL;

    INIT_LIST_HEAD(&task->list);

    return task;
}

/**
 * @brief Removes and deletes a task from the event loop.
 *
 * @param task The task to delete/remove.
 */
static void
sd_event_source_list_item_delete(struct sd_event_source_list_item *item)
{
    if (!item)
        return;

    sd_event_source_unref(item->source);
    list_del(&item->list);
    free(item->helper_context);
    free(item);
}

/**
 * @brief Initialize the event loop.
 *
 * @param loop The event loop control structure to initialize.
 * @return int 0 if initialization was successful, non-zero otherwise.
 */
int
event_loop_initialize(struct event_loop *loop)
{
    INIT_LIST_HEAD(&loop->sd_event_source_list);
    loop->clock = CLOCK_BOOTTIME;
    int ret = sd_event_default(&loop->ebase);
    if (ret < 0)
        return ret;
    
    return 0;
}

/**
 * @brief Uninitializes the event loop.
 *
 * This will cancel all existing timers. The event loop must not be active.
 *
 * @param loop The event loop control structure to uninitialize.
 */
void
event_loop_uninitialize(struct event_loop *loop)
{
    struct sd_event_source_list_item *item;
    struct sd_event_source_list_item *itemtmp;

    list_for_each_entry_safe (item, itemtmp, &loop->sd_event_source_list, list) {
        sd_event_source_list_item_delete(item);
    }
    sd_event_unref(loop->ebase);
}

// helper struct to implement the timer events
struct timer_event_helper_context {
    enum scheduled_task_type type;
    uint64_t usec_offset_from_now;
    scheduled_task_handler original_handler;
    void *original_context;
};

struct timer_event_helper_context *create_timer_event_helper_context(enum scheduled_task_type type,uint64_t usec_offset,scheduled_task_handler handler,void*context)
{
    struct timer_event_helper_context *tmp;
    tmp = calloc(1, sizeof *tmp);
    if (!tmp)
        return tmp;
    tmp->type = type;
    tmp->usec_offset_from_now = usec_offset;
    tmp->original_handler = handler;
    tmp->original_context = context;
    return tmp;
}

// helper function to implement the timer events
int helper_handler_for_timer_events(sd_event_source *s, uint64_t usec, void *context)
{
    __unused(usec);
    struct timer_event_helper_context *tinfo = (struct timer_event_helper_context *)context;

    tinfo->original_handler(tinfo->original_context);

    if (tinfo->type == TASK_PERIODIC) {
        // reschedule the event source
        sd_event_source_set_enabled(s, SD_EVENT_ON);
        uint64_t now;
        sd_event_source_get_time(s,&now);
        sd_event_source_set_time(s,now + tinfo->usec_offset_from_now);
    }
    return 0;
}

/**
 * @brief Schedules a task for execution at a later time.
 *
 * The expiry time is specified as the total number of seconds plus the
 * total number of microseconds from the current time.
 *
 * @param loop The event loop control structure.
 * @param seconds The number of seconds from now the task should execute.
 * @param useconds The number of microseconds, relative to the number of seconds, the task should execute.
 * @param type The type of scheduled task; oneshot or periodic.
 * @param handler The handler function to invoke when the task expiry time occurs.
 * @param task_context The contextual data that will be passed to the handler function.
 * @return int
 */
int
event_loop_task_schedule(struct event_loop *loop, uint32_t seconds, uint32_t useconds, enum scheduled_task_type type, scheduled_task_handler handler, void *task_context)
{
    int ret = 0;

    struct sd_event_source_list_item *task = sd_event_source_list_item_alloc();
    if (!task)
        return -ENOMEM;

    struct timespec now;
    ret = clock_gettime(loop->clock, &now);
    if (ret < 0) {
        ret = errno;
        zlog_error("failed to retrieve current time (%d)", ret);
        free(task);
        return ret;
    }

    // transform the seconds + useconds into a single useconds offset
    uint64_t usec_offset = 1000000 * ((uint64_t) seconds) + ((uint64_t) useconds);
    uint64_t usec_fire_time = usec_offset + (((uint64_t)now.tv_nsec) / 1000) + (((uint64_t)now.tv_sec) * 1000000);

    struct timer_event_helper_context *helper_context = create_timer_event_helper_context(type, usec_offset, handler, task_context);
    if (!helper_context) {
        ret = -ENOMEM;
        goto fail;
    }

    ret = sd_event_add_time(loop->ebase, &task->source, loop->clock, usec_fire_time, 0, helper_handler_for_timer_events, helper_context);
    if (ret < 0) {
        ret = errno;
        zlog_error("failed to schedule task (ret = %d)", ret);
        goto fail;
    }

    // Fill in structure with contextual data.
    task->context = task_context;
    task->helper_context = helper_context;
    task->event_type = TIMER;

    task->data.timer.handler = handler;
    task->data.timer.timer_type = type;
    task->data.timer.usec_offset = usec_offset;

    list_add(&task->list, &loop->sd_event_source_list);

out:
    return ret > 0 ? 0 : ret; // positive ret is not an error, so force it to 0
fail:
    free(helper_context);
    free(task);
    goto out;
}

/**
 * @brief Helper function to schedule a one-shot scheduled task to run immediately.
 * 
 * @param loop The event loop control structure.
 * @param handler The handler function to invoke when the task expiry time occurs.
 * @param task_context The contextual data that will be passed to the handler function.
 * @return int 
 */
int
event_loop_task_schedule_now(struct event_loop *loop, scheduled_task_handler handler, void *task_context)
{
    return event_loop_task_schedule(loop, 0, 0, TASK_ONESHOT, handler, task_context);
}

/**
 * @brief Cancels a scheduled task.
 *
 * @param loop The event loop control structure.
 * @param handler The task event handler.
 * @param context The context for the event handler.
 * @return uint32_t The number of tasks that were canceled.
 */
uint32_t
event_loop_task_cancel(struct event_loop *loop, scheduled_task_handler handler, void *context)
{
    uint32_t num_canceled = 0;
    struct sd_event_source_list_item *item;
    struct sd_event_source_list_item *itemtmp;

    list_for_each_entry_safe (item, itemtmp, &loop->sd_event_source_list, list) {
        if (item->event_type == TIMER && item->data.timer.handler == handler && item->context == context) {
            sd_event_source_list_item_delete(item);
            num_canceled++;
        }
    }

    return num_canceled;
}

/**
 * @brief Macro representing an infinite timeout for epoll_wait().
 */
#define EPOLL_TIMEOUT_INFINITE (-1)

// helper struct to implement the io based events
struct io_event_helper_context {
    int fd;
    uint32_t events;
    event_handler_fn original_handler;
    void *original_context;
};

struct io_event_helper_context *create_io_event_helper_context(int fd, uint32_t events, event_handler_fn handler, void *context)
{
    struct io_event_helper_context *tmp;
    tmp = calloc(1, sizeof *tmp);
    if (!tmp)
        return tmp;
    tmp->fd = fd;
    tmp->events = events;
    tmp->original_handler = handler;
    tmp->original_context = context;
    return tmp;
}

// helper function to implement the io based events
int helper_handler_for_io_events(sd_event_source *s, int fd, uint32_t revents, void *context)
{
    __unused(s);
    __unused(revents);
    struct io_event_helper_context *tinfo = (struct io_event_helper_context *)context;

    tinfo->original_handler(fd, tinfo->original_context);
    return 0;
}

/**
 * @brief Registers a handler for events that signal data is available from a file descriptor.
 *
 * @param loop The event loop instance.
 * @param events The event types to monitor. Must be one of the EPOLL* macros.
 * @param fd The file descriptor to monitor for changes.
 * @param handler The handler function to invoke when data is available on 'fd'.
 * @param handler_arg The argument that should be passed to the handler function.
 * @return int 0 if the handler was successfully registered, non-zero otherwise.
 */
int
event_loop_register_event(struct event_loop *loop, uint32_t events, int fd, event_handler_fn handler, void *handler_arg)
{
    int ret = 0;
    struct sd_event_source_list_item *item = sd_event_source_list_item_alloc();
    if (!item)
        return -ENOMEM;

    struct io_event_helper_context *helper_context = create_io_event_helper_context(fd, events, handler, handler_arg);
    if (!helper_context) {
        ret = -ENOMEM;
        goto fail;
    }

    ret = sd_event_add_io(loop->ebase, &item->source, fd, events, helper_handler_for_io_events, helper_context);
    if (ret < 0) {
        ret = errno;
        zlog_error("failed to register fd=%d for event monitoring (%d)", fd, ret);
        goto fail;
    }
    
    item->event_type = IO;
    item->context = handler_arg;
    item->helper_context = helper_context;
    item->data.io.fd = fd;
    item->data.io.handler = handler;

    list_add(&item->list, &loop->sd_event_source_list);
    return 0;

fail:
    free(helper_context);
    free(item);
    return ret;
}

/**
 * @brief Unregisters an read event handler.
 *
 * @param loop The event loop instance.
 * @param fd The file descriptor associated with the read event to unregister.
 */
void
event_loop_unregister_event(struct event_loop *loop, int fd)
{
    struct sd_event_source_list_item *item;
    struct sd_event_source_list_item *itemtmp;
    list_for_each_entry_safe (item, itemtmp, &loop->sd_event_source_list, list) {
        if (item->event_type == IO && item->data.io.fd == fd)
            sd_event_source_list_item_delete(item);
    }
}

/**
 * @brief Runs the event loop. This uses the calling thread to wait for changes
 * to the event loop's configured file descriptors. The event loop will run
 * until the event_loop_stop() function is called.
 *
 * @param loop The event loop instance.
 * @return 0 if it exited cleanly, else an error code
 */
int
event_loop_run(struct event_loop *loop)
{
    return sd_event_loop(loop->ebase);
}
