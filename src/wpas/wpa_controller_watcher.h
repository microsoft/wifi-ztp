
#ifndef __WPA_CONTROLLER_WATCHER_H__
#define __WPA_CONTROLLER_WATCHER_H__

#include <userspace/linux/list.h>

struct event_loop;

/**
 * @brief Directory wpa control socket watch. One watch exists for each control
 * socket information directory being monitored.
 */
struct wpa_inotify_watch {
    int id;
    char path[];
};

/**
 * @brief WPA controller watcher. This is the primary structure containing
 * state information needed to track the presence of wpa controllers on the
 * system.
 */
struct wpa_controller_watcher {
    struct wpa_inotify_watch *watch_parent;
    struct wpa_inotify_watch *watch_ctrl;
    struct list_head handlers;
    struct event_loop *loop;
    const char *ctrl_component;
    int inotify_fd;
};

/**
 * @brief Creates and initializes a new instance of a wpa controller watcher.
 *
 * @param loop The ztp event loop to be used to monitor for control socket presence.
 * @param path The base control socket path used by wpa_supplicant or hostapd.
 *
 * @return struct wpa_controller_watcher* A new instance of a wpa controller watcher.
 */
struct wpa_controller_watcher *
wpa_controller_watcher_create(struct event_loop *loop, const char *path);

/**
 * @brief Destroys a wpa controller watcher that was previously created with
 * 'wpa_controller_watcher_create.
 *
 * @param pwatcher Pointer to the watcher to destroy.
 */
void
wpa_controller_watcher_destroy(struct wpa_controller_watcher **pwatcher);

/**
 * @brief Describes a wpa controller presence event.
 */
enum wpa_controller_presence_event {
    WPA_CONTROLLER_ARRIVED,
    WPA_CONTROLLER_DEPARTED
};

/**
 * @brief Prototype for wpa controller presence event handlers.
 *
 * @param context The user-supplied context.
 * @param event The event that occurred.
 * @param path The full path of the control socket to the interface.
 * @param interface The interface for which the event occurred.
 */
typedef void (*wpa_controller_presence_event_fn)(void *context, enum wpa_controller_presence_event event, const char *path, const char *interface);

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
wpa_controller_watcher_register_interface_presence_event_handler(struct wpa_controller_watcher *watcher, wpa_controller_presence_event_fn callback, void *context);

/**
 * @brief Unregisters a wpa controller presence event handler.
 *
 * @param watcher The watcher that the handler was previously associated with.
 * @param callback The callback function that was previously registered.
 * @param context The user-supplied context that was previously associated with
 * the handler. This is used to uniquely identify the handler registration.
 */
void
wpa_controller_watcher_unregister_interface_presence_event_handler(struct wpa_controller_watcher *watcher, wpa_controller_presence_event_fn callback, void *context);

#endif //__WPA_CONTROLLER_WATCHER_H__
