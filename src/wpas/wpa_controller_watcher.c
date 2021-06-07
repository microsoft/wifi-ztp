
#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <unistd.h>

#include "event_loop.h"
#include "wpa_controller_watcher.h"
#include "ztp_log.h"

/**
 * @brief Controller presence event handler.
 */
struct wpa_controller_presence_event_handler {
    struct list_head list;
    wpa_controller_presence_event_fn callback;
    void *context;
};

/**
 * @brief Destroys a wpa watch, releasing any resources it owns.
 *
 * @param pwatch
 */
static void
wpa_inotify_watch_destroy(struct wpa_inotify_watch **pwatch)
{
    struct wpa_inotify_watch *watch = *pwatch;
    if (!watch)
        return;

    free(watch);
    *pwatch = NULL;
}

/**
 * @brief Creates a new wpa watch.
 *
 * @param path The path of the control interface the watch is associated with.
 * @return struct wpa_watch* The newly created instance, if successful. NULL otherwise.
 */
static struct wpa_inotify_watch *
wpa_inotify_watch_create(const char *path)
{
    size_t pathlen = strlen(path) + 1;
    struct wpa_inotify_watch *watch = calloc(1, sizeof *watch + pathlen);
    if (!watch) {
        zlog_error("failed to allocate memory for new wpa controller watch");
        return NULL;
    }

    watch->id = -1;
    memcpy(watch->path, path, pathlen);

    return watch;
}

/**
 * @brief Registers a new wpa controller presence event handlers. The specified
 * handler will be invoked each time the presence of a wpa control socket
 * changes (either arrives or departs).
 *
 * @param watcher The watcher that is configured to watch for control socket presence events.
 * @param callback The callback function to invoke.
 * @param context The user-supplied context that will be passed to the handler.
 * @return int 0 if the handler was successfully registered, non-zero otherwise.
 */
int
wpa_controller_watcher_register_interface_presence_event_handler(struct wpa_controller_watcher *watcher, wpa_controller_presence_event_fn callback, void *context)
{
    struct wpa_controller_presence_event_handler *handler = calloc(1, sizeof *handler);
    if (!handler) {
        zlog_error("failed to allocate memory for wpa presence event handler");
        return -ENOMEM;
    }

    handler->callback = callback;
    handler->context = context;
    INIT_LIST_HEAD(&handler->list);
    list_add_tail(&handler->list, &watcher->handlers);

    return 0;
}

/**
 * @brief Unregisters a wpa controller presence event handler.
 *
 * @param watcher The watcher that the handler was previously associated with.
 * @param callback The callback function that was previously registered.
 * @param context The user-supplied context that was previously associated with
 * the handler. This is used to uniquely identify the handler registration.
 */
void
wpa_controller_watcher_unregister_interface_presence_event_handler(struct wpa_controller_watcher *watcher, wpa_controller_presence_event_fn callback, void *context)
{
    struct wpa_controller_presence_event_handler *handler;

    list_for_each_entry (handler, &watcher->handlers, list) {
        if (handler->callback == callback && handler->context == context) {
            list_del(&handler->list);
            free(handler);
            return;
        }
    }
}

/**
 * @brief Invokes a single presence event handler for the specified event.
 *
 * @param handler The handler to invoke.
 * @param event The event that occurred.
 * @param path The base path (parent directory) of the control socket.
 * @param interface The name of the intergace associated with the control socket.
 */
static void
invoke_presence_event_handler(const struct wpa_controller_presence_event_handler *handler, enum wpa_controller_presence_event event, const char *path, const char *interface)
{
    handler->callback(handler->context, event, path, interface);
}

/**
 * @brief Invokes all registered presence event handlers for the specified event.
 *
 * @param watcher The wpa controller watcher instance.
 * @param event The event that occurred.
 * @param path The control path the event was signaled on.
 * @param interface The name of the interface associated with the control socket.
 */
static void
invoke_presence_event_handlers(struct wpa_controller_watcher *watcher, enum wpa_controller_presence_event event, const char *path, const char *interface)
{
    struct wpa_controller_presence_event_handler *handler;
    list_for_each_entry (handler, &watcher->handlers, list) {
        invoke_presence_event_handler(handler, event, path, interface);
    }
}

/**
 * @brief Manually discover and fire presence events for all existing control
 * interfaces.
 *
 * @param watcher The watcher instance to discover control entries for.
 */
static void
prime_event_presence_arrivals(struct wpa_controller_watcher *watcher)
{
    DIR *dir = opendir(watcher->watch_ctrl->path);
    if (!dir) {
        int ret = errno;
        zlog_error("failed to open wpa control path (%d)", ret);
        return;
    }

    for (;;) {
        struct dirent *entry = readdir(dir);
        if (!entry)
            break;
        if (entry->d_type != DT_SOCK)
            continue;
        invoke_presence_event_handlers(watcher, WPA_CONTROLLER_ARRIVED, watcher->watch_ctrl->path, entry->d_name);
    }

    closedir(dir);
}

/**
 * @brief Handles when the control path arrives or is known to be present. This
 * primarily setups up a new watch on the control directory, and primes the
 * existing handlers with presence information by checking if there are any
 * existing control interface sockets.
 *
 * @param watcher The watcher instance the event occurred for.
 */
static void
on_ctrl_path_arrived(struct wpa_controller_watcher *watcher)
{
    int id = inotify_add_watch(watcher->inotify_fd, watcher->watch_ctrl->path, IN_CREATE | IN_DELETE);
    if (id < 0) {
        zlog_error("failed to add inotify watch for wpa control path %s (%d)", watcher->watch_ctrl->path, errno);
        return;
    }

    watcher->watch_ctrl->id = id;
    zlog_debug("wpa control path %s arrived", watcher->watch_ctrl->path);

    prime_event_presence_arrivals(watcher);
}

/**
 * @brief Handles when the control path departs or is known to be absent. This
 * primary removes the watch on the control directory.
 *
 * @param watcher The watcher instance the event occurred for.
 */
static void
on_ctrl_path_departed(struct wpa_controller_watcher *watcher)
{
    inotify_rm_watch(watcher->inotify_fd, watcher->watch_ctrl->id);
    watcher->watch_ctrl->id = -1;
    zlog_debug("wpa control path %s departed", watcher->watch_ctrl->path);
}

/**
 * @brief Handler for inotify events related to the parent control directory.
 *
 * @param watcher The watcher instance associated with the event.
 * @param event The event that occurred.
 */
static void
handle_inotify_event_parent(struct wpa_controller_watcher *watcher, const struct inotify_event *event)
{
    if ((event->mask & IN_ISDIR) == 0 || strncmp(event->name, watcher->ctrl_component, event->len) != 0)
        return;

    if (event->mask & IN_CREATE) {
        on_ctrl_path_arrived(watcher);
    } else if (event->mask & IN_DELETE) {
        on_ctrl_path_departed(watcher);
    } else {
        zlog_debug("unexpected mask=0x%08x for inotify event watch id=%d, for path %s", event->mask, event->wd, watcher->watch_ctrl->path);
    }
}

/**
 * @brief Handler for inotify events related to the control socket directory.
 *
 * @param watcher The watcher instance associated with the event.
 * @param event The event that occurred.
 */
static void
handle_inotify_event_ctrl(struct wpa_controller_watcher *watcher, const struct inotify_event *event)
{
    enum wpa_controller_presence_event presence;
    if (event->mask & IN_CREATE) {
        presence = WPA_CONTROLLER_ARRIVED;
    } else if (event->mask & IN_DELETE) {
        presence = WPA_CONTROLLER_DEPARTED;
    } else {
        zlog_warning("unexpected mask=0x%08x for inotify event watch id=%d for path %s", event->mask, event->wd, watcher->watch_ctrl->path);
        return;
    }

    invoke_presence_event_handlers(watcher, presence, watcher->watch_ctrl->path, event->name);
}

/**
 * @brief First-level handler for inotify events.
 *
 * This primarily determines if the event is related to the parent control
 * directory, or the control directory itself and dispatches the event
 * appropriately.
 *
 * @param watcher The watcher instance associated with the event.
 * @param event The event that occurred.
 */
static void
handle_inotify_event(struct wpa_controller_watcher *watcher, const struct inotify_event *event)
{
    const char *name = event->len ? event->name : "<none>";
    zlog_debug("inotify path=%s target=%s mask=0x%08x", watcher->watch_ctrl->path, name, event->mask);

    if (event->wd == watcher->watch_parent->id) {
        handle_inotify_event_parent(watcher, event);
    } else if (event->wd == watcher->watch_ctrl->id) {
        handle_inotify_event_ctrl(watcher, event);
    } else {
        zlog_warning("no watch found for inotify event id=%d name=%s", event->wd, name);
        return;
    }
}

/**
 * @brief Handler for all watches.
 *
 * @param fd The inotify file decriptor.
 * @param context The wpa controller watcher instance.
 */
static void
on_inotify_signaled(int fd, void *context)
{
    struct wpa_controller_watcher *watcher = (struct wpa_controller_watcher *)context;
    char eventbuf[sizeof(struct inotify_event) + NAME_MAX + 1];

    for (;;) {
        ssize_t n = read(fd, eventbuf, sizeof eventbuf);
        if (n < 0) {
            int ret = errno;
            if (ret != EAGAIN)
                zlog_error("error reading inotify event (%d)", ret);
            return;
        }

        char *p = eventbuf;
        do {
            const struct inotify_event *event = (struct inotify_event *)p;
            p += (ssize_t)((sizeof *event) + event->len);
            n -= (ssize_t)((sizeof *event) + event->len);
            handle_inotify_event(watcher, event);
        } while (n > 0);

        assert(n == 0);
    }
}

/**
 * @brief Initializes the inotify watches. The path should be the base
 * directory that hostapd or wpa_supplicant was configured to write its control
 * socket files to. Eg. /var/run/hostapd or /var/run/wpa_supplicant.
 *
 * @param watcher The watcher instance to initialize watches for.
 * @param path The base path where the target process writes its control socket information.
 * @return int 0 if the watches were successfully initialized, non-zero otherwise.
 */
static int
wpa_controller_watcher_configure_watches(struct wpa_controller_watcher *watcher, const char *path)
{
    int ret;
    struct wpa_inotify_watch *watch_ctrl = NULL;
    struct wpa_inotify_watch *watch_parent = NULL;

    char *separator = strrchr(path, '/');
    if (!separator) {
        zlog_error("wpa control path %s malformed", path);
        return -EINVAL;
    }

    watch_ctrl = wpa_inotify_watch_create(path);
    if (!watch_ctrl) {
        zlog_error("failed to create watch for wpa control path %s", path);
        return -ENOMEM;
    }

    size_t leaf_index = (size_t)(separator - path);
    watch_ctrl->path[leaf_index] = '\0';
    watch_parent = wpa_inotify_watch_create(watch_ctrl->path);
    watch_ctrl->path[leaf_index] = '/';

    if (!watch_parent) {
        zlog_error("failed to create watch for wpa control path parent %s", path);
        ret = -ENOMEM;
        goto fail;
    }

    int id = inotify_add_watch(watcher->inotify_fd, watch_parent->path, IN_CREATE | IN_DELETE);
    if (id == -1) {
        ret = errno;
        zlog_error("failed to add inotify watch for wpa control path parent %s (%d)", watch_parent->path, ret);
        goto fail;
    }

    watcher->watch_parent = watch_parent;
    watcher->watch_parent->id = id;
    watcher->watch_ctrl = watch_ctrl;
    watcher->ctrl_component = watcher->watch_ctrl->path + leaf_index + 1;

    zlog_debug("monitoring started for wpa control path %s", path);

    if (access(path, F_OK) == 0)
        on_ctrl_path_arrived(watcher);

    ret = 0;
out:
    return ret;
fail:
    if (watch_ctrl)
        free(watch_ctrl);
    if (watch_parent)
        free(watch_parent);
    goto out;
}

/**
 * @brief Destroys a wpa controller watcher that was previously created with
 * 'wpa_controller_watcher_create.
 *
 * @param pwatcher Pointer to the watcher to destroy.
 */
void
wpa_controller_watcher_destroy(struct wpa_controller_watcher **pwatcher)
{
    struct wpa_controller_watcher *watcher = *pwatcher;

    event_loop_unregister_event(watcher->loop, watcher->inotify_fd);
    wpa_inotify_watch_destroy(&watcher->watch_ctrl);
    wpa_inotify_watch_destroy(&watcher->watch_parent);

    struct wpa_controller_presence_event_handler *handler;
    struct wpa_controller_presence_event_handler *tmp;
    list_for_each_entry_safe (handler, tmp, &watcher->handlers, list) {
        list_del(&handler->list);
        free(handler);
    }

    free(watcher);
    *pwatcher = NULL;
}

/**
 * @brief Creates and initializes a new instance of a wpa controller watcher.
 *
 * @param loop The ztp event loop to be used to monitor for control socket presence.
 * @param path The base control socket path used by wpa_supplicant or hostapd.
 *
 * @return struct wpa_controller_watcher* A new instance of a wpa controller watcher.
 */
struct wpa_controller_watcher *
wpa_controller_watcher_create(struct event_loop *loop, const char *path)
{
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd == -1) {
        zlog_error("failed to initialize inotify for wpa controller watcher (%d)", errno);
        return NULL;
    }

    struct wpa_controller_watcher *watcher = calloc(1, sizeof *watcher);
    if (!watcher) {
        zlog_error("failed to allocate memory for new wpa controller watcher");
        return NULL;
    }

    INIT_LIST_HEAD(&watcher->handlers);

    watcher->loop = loop;
    watcher->inotify_fd = inotify_fd;

    int ret = event_loop_register_event(loop, EPOLLIN, inotify_fd, on_inotify_signaled, watcher);
    if (ret < 0) {
        zlog_error("failed to register inotify event handler for new wpa controller watcher (%d)", ret);
        wpa_controller_watcher_destroy(&watcher);
        return NULL;
    }

    ret = wpa_controller_watcher_configure_watches(watcher, path);
    if (ret < 0) {
        zlog_error("failed to configure inotify watches for wpa controller watcher (%d)", ret);
        wpa_controller_watcher_destroy(&watcher);
        return NULL;
    }

    return watcher;
}
