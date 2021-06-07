
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "event_loop.h"
#include "time_utils.h"
#include "ztp_log.h"

/**
 * @brief Converts a ztpd scheduled task type to a string.
 *
 * @param type The type of convert.
 * @return const char* A string representation of the task type.
 */
static const char *
scheduled_task_type_str(enum scheduled_task_type type)
{
    switch (type) {
        case TASK_ONESHOT:
            return "oneshot";
        case TASK_PERIODIC:
            return "periodic";
        default:
            return "??";
    }
}

/**
 * @brief Determines if the specified task timeout has expired, compared to a reference time.
 *
 * @param task The task to check.
 * @param reference The time to check against.
 * @return true If the task has expired: expiry time is earlier than reference time.
 * @return false If the task has not expired: expiry time is later than reference time.
 */
static bool
scheduled_task_is_expired(struct scheduled_task *task, struct timespec *reference)
{
    return timespec_time_is_earlier(&task->expiry, reference);
}

/**
 * @brief Allocates and initializes a new scheduled task.
 *
 * @return struct scheduled_task*
 */
static struct scheduled_task *
scheduled_task_alloc()
{
    struct scheduled_task *task;
    task = malloc(sizeof *task);
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
scheduled_task_delete(struct scheduled_task *task)
{
    if (!task)
        return;

    list_del(&task->list);
    free(task);
}

/**
 * @brief Calculates the timeout (remaining time) in milliseconds compared to a reference time.
 *
 * This calculates the number of milliseconds between the reference time and
 * the expiry time. In case the reference time is earlier than the expiry time
 * (eg. scheduled task is expired), 0 is returned as the timeout value,
 * indicating the scheduled task should be processed immediately.

 * @param task The task to calculate the timeout for.
 * @param reference The reference time to compare against.
 * @return int
 */
static int
scheduled_task_get_timeout(struct scheduled_task *task, struct timespec *reference)
{
    if (scheduled_task_is_expired(task, reference))
        return 0;

    // Task is not expired, so task->expiry > reference; calculate remaining timeout.
    struct timespec remaining = task->expiry;
    remaining.tv_sec -= reference->tv_sec;
    remaining.tv_nsec -= reference->tv_nsec;

    // Convert relative time to milliseconds.
    time_t timeout = 0;
    timeout += remaining.tv_sec * MSEC_PER_SEC;
    timeout += remaining.tv_nsec / NSEC_PER_MSEC;

    return (int)timeout;
}

/**
 * @brief Returns the next (in time) scheduled task.
 *
 * @param loop The event loop control structure.
 * @return struct scheduled_task The task structure of the next expiring
 * scheduled task.
 */
static struct scheduled_task *
scheduled_task_next(struct event_loop *loop)
{
    return list_first_entry_or_null(&loop->scheduled_tasks, struct scheduled_task, list);
}

/**
 * @brief Initializes an event dispatcher for use, allocating its initial descriptor table.
 *
 * @param num_events The number of events the dispatcher should support.
 * @return int 0 if the dispatcher was successfully initialized, non-zero otherwise.
 */
static int
event_dispatch_initialize(struct event_dispatch *dispatch, size_t num_events)
{
    struct event *events = calloc(num_events, sizeof *events);
    if (!events)
        return -ENOMEM;

    for (size_t i = 0; i < num_events; i++)
        events[i].fd = -1;

    dispatch->events = events;
    dispatch->num_events = num_events;

    return 0;
}

/**
 * @brief Uninitializes a event dispatcher for use.
 * 
 * @param dispatch The event dispatcher to uninitialize.
 */
static void
event_dispatch_uninitialize(struct event_dispatch *dispatch)
{
    if (dispatch->events) {
        free(dispatch->events);
        dispatch->events = NULL;
    }

    dispatch->num_events = 0;
}

/**
 * @brief Find an unused slot in the dispatch table.
 *
 * Note that this only returns the index of the free slot. It does not mark the
 * slot as being used; this is the responsibility of the caller (if desired).
 *
 * @param dispatch The dispatch table to find the slot from.
 * @return ssize_t The index of the slot, if one is available. Otherwise -1 is
 * returned indicating that no free slots are available.
 */
ssize_t
event_dispatch_find_slot(struct event_dispatch *dispatch)
{
    for (size_t i = 0; i < dispatch->num_events; i++) {
        if (dispatch->events[i].fd == -1)
            return (ssize_t)i;
    }

    return -1;
}

/**
 * @brief Maximum number of read events currently supported.
 */
#define EPOLL_MAX_READ_EVENTS 8

/**
 * @brief Initialize parts of the event loop that are related to epoll.
 *
 * @param loop The event loop instance.
 * @return int 0 if the epoll event loop was successfull configured, non-zero otherwise.
 */
static int
event_loop_epoll_initialize(struct event_loop *loop)
{
    int ret;
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        ret = errno;
        zlog_error("failed to create epoll instance (%d)", ret);
        return ret;
    }

    size_t events_max = EPOLL_MAX_READ_EVENTS;
    struct epoll_event *events = malloc(sizeof *events * events_max);
    if (!events) {
        zlog_error("failed to allocate epoll events array");
        ret = -ENOMEM;
        goto fail;
    }

    ret = event_dispatch_initialize(&loop->dispatch, events_max);
    if (ret < 0) {
        zlog_error("failed to initialize event dispatcher (%d)", ret);
        goto fail;
    }

    loop->events = events;
    loop->events_max = events_max;
    loop->epoll_fd = epoll_fd;
    loop->terminate_pending = false;

    ret = 0;
out:
    return ret;
fail:
    if (epoll_fd != -1)
        close(epoll_fd);
    if (events)
        free(events);
    goto out;
}

/**
 * @brief Uninitializes epoll related parts of the event loop. The event loop
 * must not be in the running state.
 *
 * @param loop The event loop instancece
 */
static void
event_loop_epoll_uninitialize(struct event_loop *loop)
{
    if (loop->epoll_fd != -1) {
        close(loop->epoll_fd);
        loop->epoll_fd = -1;
    }

    if (loop->events) {
        free(loop->events);
        loop->events = NULL;
    }

    event_dispatch_uninitialize(&loop->dispatch);
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
    INIT_LIST_HEAD(&loop->scheduled_tasks);
    loop->clock = CLOCK_BOOTTIME;
    loop->epoll_fd = -1;

    int ret = event_loop_epoll_initialize(loop);
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
    struct scheduled_task *task;
    struct scheduled_task *tasktmp;

    list_for_each_entry_safe (task, tasktmp, &loop->scheduled_tasks, list) {
        scheduled_task_delete(task);
    }

    event_loop_epoll_uninitialize(loop);
}

/**
 * @brief Schedules a task for deferred execution.
 *
 * @param loop The event loop control structure.
 * @param task The task to schedule.
 * @param reference The reference time to schedule against
 */
static void
event_loop_schedule_task(struct event_loop *loop, struct scheduled_task *task, struct timespec *reference)
{
    // If the task is already in the scheduled task list, remove it.
    if (!list_empty(&task->list))
        list_del_init(&task->list);

    // Calculate the (relative) expiry time from the reference time.
    task->expiry = *reference;
    task->expiry.tv_sec += task->timeout.seconds;
    task->expiry.tv_nsec += task->timeout.useconds * NSEC_PER_USEC;

    // Sanitize the expiry time to ensure time-context limits aren't exceeded.
    while (task->expiry.tv_nsec >= NSEC_PER_SEC) {
        task->expiry.tv_sec++;
        task->expiry.tv_nsec -= NSEC_PER_SEC;
    }

    // Insert the scheduled task into the list of all tasks according to its expiry time.
    struct scheduled_task *task_scheduled;
    list_for_each_entry (task_scheduled, &loop->scheduled_tasks, list) {
        if (timespec_time_is_earlier(&task->expiry, &task_scheduled->expiry)) {
            list_add_tail(&task->list, &task_scheduled->list);
            break;
        }
    }

    // If entry was not added, it is later than all existing timers, so add to
    // the end of the list.
    if (list_empty(&task->list))
        list_add(&task->list, &loop->scheduled_tasks);

    // Assign the loop context.
    task->loop = loop;
}

/**
 * @brief Schedules a task for execution at a later time.
 *
 * The expiry time is specified as the total number of seconds plus the
 * total number of microseconds from the current time.
 *
 * The event loop does not need to be rescheduled following the addition of new
 * or removal of existing timers. Each time the event loop blocks to wait for
 * events, it schedules its wait timeout to be the expiry time of the next
 * scheduled task. This ensures the event loop will be unblocked precisely when
 * the next (in time) scheduled task need to run.
 *
 * Since the event loop and all code interacting with it is single-threaded, a
 * new task cannot be scheduled until the event loop is unblocked. This
 * guarantees that newly added and removed tasks will be accounted for.
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
    int ret;
    struct timespec now;
    struct scheduled_task *task;

    task = scheduled_task_alloc();
    if (!task)
        return -ENOMEM;

    ret = clock_gettime(loop->clock, &now);
    if (ret < 0) {
        ret = errno;
        zlog_error("failed to retrieve current time (%d)", ret);
        goto fail;
    }

    // Fill in structure with contextual data.
    task->type = type;
    task->handler = handler;
    task->context = task_context;
    task->timeout.seconds = seconds;
    task->timeout.useconds = useconds;

    event_loop_schedule_task(loop, task, &now);

out:
    return 0;
fail:
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
    struct scheduled_task *task;
    struct scheduled_task *tasktmp;

    list_for_each_entry_safe (task, tasktmp, &loop->scheduled_tasks, list) {
        if (task->handler == handler && task->context == context) {
            scheduled_task_delete(task);
            num_canceled++;
        }
    }

    return num_canceled;
}

/**
 * @brief Macro representing an infinite timeout for epoll_wait().
 */
#define EPOLL_TIMEOUT_INFINITE (-1)

/**
 * @brief Calculates the timeout of the next scheduled task, specified in milliseconds.
 *
 * If there are no configured scheduled tasks, the returned value represents an
 * infinite timeout for epoll_wait().
 *
 * @param loop The event loop control structure.
 * @return int The timeout value to be passed to epoll_wait().
 */
static int
event_loop_scheduled_task_next_timeout(struct event_loop *loop, struct timespec *reference)
{
    int timeout;
    struct scheduled_task *task = scheduled_task_next(loop);

    if (!task) {
        timeout = EPOLL_TIMEOUT_INFINITE;
    } else {
        timeout = scheduled_task_get_timeout(task, reference);
    }

    return timeout;
}

/**
 * @brief Calculates the event loop timeout.
 *
 * The event loop timeout is the relative time when the event loops needs to
 * unblock to check for events. Currently the only events that need to be
 * checked after such a timeout is the expiry of a scheduled task.
 *
 * If there are no configured scheduled tasks, the returned value represents an
 * infinite timeout for epoll_wait().
 *
 * @param loop The event loop control structure.
 * @return int The timeout to be supplied to epoll_wait().
 */
int
event_loop_get_timeout(struct event_loop *loop)
{
    struct timespec now;
    int ret = clock_gettime(loop->clock, &now);
    if (ret < 0) {
        ret = errno;
        zlog_error("failed to retrieve current time (%d)", ret);
        return ret;
    }

    return event_loop_scheduled_task_next_timeout(loop, &now);
}

/**
 * @brief Process the scheduled task queue.
 *
 * @param loop The event loop control structure.
 */
void
event_loop_process_scheduled_tasks(struct event_loop *loop)
{
    struct scheduled_task *task = scheduled_task_next(loop);
    if (!task)
        return;

    struct timespec now;
    int ret = clock_gettime(loop->clock, &now);
    if (ret < 0) {
        ret = errno;
        zlog_error("failed to retrieve current time (%d)", ret);
        return;
    }

    if (!scheduled_task_is_expired(task, &now))
        return;

    // Copy the handler and context argument to allow removal if it's a oneshot timer.
    scheduled_task_handler handler = task->handler;
    enum scheduled_task_type type = task->type;
    void *context = task->context;

    // Set future task action (remove or reschedule).
    switch (type) {
        case TASK_ONESHOT:
            scheduled_task_delete(task);
            break;
        case TASK_PERIODIC:
            event_loop_schedule_task(loop, task, &now);
            break;
        default:
            break;
    }

    zlog_debug("executing scheduled task handler=0x%" PRIx64 "(arg=%p, type=%s)",
        (uint64_t)handler,
        context,
        scheduled_task_type_str(type));

    handler(context);
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
    struct event_dispatch *dispatch = &loop->dispatch;

    ssize_t event_slot = event_dispatch_find_slot(dispatch);
    if (event_slot == -1) {
        zlog_error("read event slots (%lu) exhausted", dispatch->num_events);
        return -ENOSPC;
    }

    struct epoll_event event;
    explicit_bzero(&event, sizeof event);
    event.events = events;
    event.data.fd = fd;

    int ret = epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, fd, &event);
    if (ret < 0) {
        ret = errno;
        zlog_error("failed to register fd=%d for event monitoring (%d)", fd, ret);
        return ret;
    }

    struct event *zevent = &dispatch->events[event_slot];
    zevent->fd = fd;
    zevent->handler = handler;
    zevent->handler_arg = handler_arg;

    return 0;
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
    struct event *event = NULL;
    struct event_dispatch *dispatch = &loop->dispatch;

    for (size_t i = 0; i < dispatch->num_events; i++) {
        if (dispatch->events[i].fd == fd) {
            event = &dispatch->events[i];
            break;
        }
    }

    if (!event)
        return;

    int ret = epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    if (ret < 0) {
        ret = errno;
        zlog_error("failed to unregister fd=%d from event monitoring (%d)", fd, ret);
        return;
    }

    event->fd = -1;
    event->handler = NULL;
    event->handler_arg = NULL;
}

/**
 * @brief Requests that the event loop stop running. The event loop will not
 * terminate immediately, however, it will terminate at the end of the current
 * loop iteration.
 *
 * @param loop The event loop instance.
 */
void
event_loop_stop(struct event_loop *loop)
{
    loop->terminate_pending = true;
}

/**
 * @brief Determines which event fired and dispatches the associated handler for the event.
 *
 * @param loop The event loop instance.
 * @param event The epoll event that was signaled.
 */
static void
event_loop_process_update(struct event_loop *loop, struct epoll_event *event)
{
    struct event_dispatch *dispatch = &loop->dispatch;

    for (size_t i = 0; i < dispatch->num_events; i++) {
        if (dispatch->events[i].fd == event->data.fd) {
            dispatch->events[i].handler(event->data.fd, dispatch->events[i].handler_arg);
            break;
        }
    }
}

/**
 * @brief Runs the event loop. This uses the calling thread to wait for changes
 * to the event loop's configured file descriptors. The event loop will run
 * until the event_loop_stop() function is called.
 *
 * @param loop The event loop instance.
 */
void
event_loop_run(struct event_loop *loop)
{
    for (;;) {
        int timeout = event_loop_get_timeout(loop);

        int num_events = epoll_wait(loop->epoll_fd, loop->events, (int)loop->events_max, timeout);
        for (int i = 0; i < num_events; i++) {
            event_loop_process_update(loop, &loop->events[i]);
        }

        event_loop_process_scheduled_tasks(loop);

        if (loop->terminate_pending) {
            loop->terminate_pending = false;
            break;
        }
    }
}
