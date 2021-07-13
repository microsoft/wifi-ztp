
#ifndef __EVENT_LOOP_H__
#define __EVENT_LOOP_H__

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <userspace/linux/list.h>

#include <systemd/sd-event.h>

struct scheduled_task;

/**
 * @brief Event loop read-event handler prototype.
 */
typedef void (*event_handler_fn)(int fd, void *context);

/**
 * @brief Generic file-descriptor based event.
 */
struct event {
    int fd;
    event_handler_fn handler;
    void *handler_arg;
};

/**
 * @brief Event dispatcher, holding a table of events.
 */
struct event_dispatch {
    size_t num_events;
    struct event *events;
};

/**
 * @brief Event loop control structure.
 */
struct event_loop {
    struct list_head sd_event_source_list;
    sd_event *ebase;
    clockid_t clock;
};

/**
 * @brief Registers a handler for events that signal data is available to be read from a file descriptor.
 *
 * @param loop The event loop instance.
 * @param events The event types to monitor. Must be one of the EPOLL* macros.
 * @param fd The file descriptor to monitor for changes to read from.
 * @param handler The handler function to invoke when data is available to be read from 'fd'.
 * @param handler_arg The argument that should be passed to the handler function.
 * @return int 0 if the handler was successfully registered, non-zero otherwise.
 */
int
event_loop_register_event(struct event_loop *loop, uint32_t events, int fd, sd_event_io_handler_t handler, void *handler_arg);

/**
 * @brief Unregisters an read event handler.
 *
 * @param loop The event loop instance.
 * @param fd The file descriptor associated with the read event to unregister.
 */
void
event_loop_unregister_event(struct event_loop *loop, int fd);

/**
 * @brief Type of scheduled task.
 */
enum scheduled_task_type {
    TASK_ONESHOT,
    TASK_PERIODIC
};

/**
 * @brief Handler function to be invoked for a scheduled task.
 */
typedef void (*scheduled_task_handler)(void *task_context);

struct scheduled_task_timeout {
    uint32_t seconds;
    uint32_t useconds;
};

enum source_event_type_enum {UNKNOWN=0, TIMER, IO};

/**
 * @brief 
 */
struct sd_event_source_list_item {
    struct list_head list;
    sd_event_source *source;
    void *helper_context; // contains the helper context for use with sd-event. will need to be freed when this event source is disabled and deleted
    void *context; // contains the original context, for use in looking up event sources

    enum source_event_type_enum event_type;

    union source_event_type_union {
        struct timer_event_info {
            enum scheduled_task_type timer_type;
            uint64_t usec_offset;
            scheduled_task_handler handler;
        } timer;
        struct io_event_info {
            int fd;
            event_handler_fn handler;
        } io;
    } data;
};

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
event_loop_task_schedule(struct event_loop *loop, uint32_t seconds, uint32_t useconds, enum scheduled_task_type type, scheduled_task_handler handler, void *task_context);

/**
 * @brief Helper function to schedule a one-shot scheduled task to run immediately.
 * 
 * @param loop The event loop control structure.
 * @param handler The handler function to invoke when the task expiry time occurs.
 * @param task_context The contextual data that will be passed to the handler function.
 * @return int 
 */
int
event_loop_task_schedule_now(struct event_loop *loop, scheduled_task_handler handler, void *task_context);

/**
 * @brief Cancels a scheduled task.
 *
 * @param loop The event loop control structure.
 * @param handler The task event handler.
 * @param context The context for the event handler.
 * @return uint32_t The number of tasks that were canceled.
 */
uint32_t
event_loop_task_cancel(struct event_loop *loop, scheduled_task_handler handler, void *task_context);

/**
 * @brief Initialize the event loop.
 *
 * @param loop The event loop control structure to initialize.
 * @return int 0 if initialization was successful, non-zero otherwise.
 */
int
event_loop_initialize(struct event_loop *loop);

/**
 * @brief Process the scheduled task queue.
 *
 * @param loop The event loop control structure.
 */
void
event_loop_process_scheduled_tasks(struct event_loop *loop);

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
event_loop_get_timeout(struct event_loop *loop);

/**
 * @brief Uninitializes the event loop.
 *
 * This will cancel all existing timers. The event loop must not be active.
 *
 * @param loop The event loop control structure to uninitialize.
 */
void
event_loop_uninitialize(struct event_loop *loop);

/**
 * @brief Requests that the event loop stop running. The event loop will not
 * terminate immediately, however, it will terminate at the end of the current
 * loop iteration.
 *
 * @param loop The event loop instance.
 * @param exit_code The return value, 0 if success, an error code otherwise
 * @return 0 if it exited cleanly, an error code otherwise
 */
int
event_loop_stop(struct event_loop *loop, int exit_code);

/**
 * @brief Runs the event loop. This uses the calling thread to wait for changes
 * to the event loop's configured file descriptors. The event loop will run
 * until the event_loop_stop() function is called.
 *
 * @param loop The event loop instance.
 * @return 0 if it exited cleanly, an error code otherwise
 */
int
event_loop_run(struct event_loop *loop);

#endif //__EVENT_LOOP_H__
