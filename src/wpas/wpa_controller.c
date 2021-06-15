
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#include <userspace/linux/compiler.h>
#include <wpa_ctrl.h>

#include "dpp.h"
#include "event_loop.h"
#include "string_utils.h"
#include "wpa_controller.h"
#include "wpa_controller_watcher.h"
#include "ztp_log.h"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif //__clang__

/**
 * @brief Helper function to track registered event handlers.
 */
struct wpa_event_handler_instance {
    struct list_head list;
    struct wpa_event_handler *handler;
    void *userdata;
};

/**
 * @brief Macro to help invoking event handlers consistently.
 *
 * @param _ctrl A pointer to the control interface, of type struct wpa_controller *.
 * @param _name The name of the event handler symbol within struct wpa_event_handler.
 * @param ... The arguments to pass to the event handler.
 */
#define WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(_ctrl, _name, ...)                \
    do {                                                                       \
        struct wpa_event_handler_instance *_instance;                          \
        list_for_each_entry (_instance, &_ctrl->event_handlers, list) {        \
            if (_instance->handler->_name != NULL)                             \
                _instance->handler->_name(_instance->userdata, ##__VA_ARGS__); \
        }                                                                      \
    } while (0)

/**
 * @brief Helper to stringify macro arguments.
 */
#define xstr(s) str(s)
#define str(s) #s

/**
 * @brief Helpers for parsing a mac address string as encoded in wpa control
 * socket event messages.
 */
#define MAC_FORMAT "aa:bb:cc:dd:ee:ff"
#define MAC_SIZE (sizeof MAC_FORMAT)
#define MAC_SIZE_C 18
#define MAC_SIZE_STR xstr(MAC_SIZE_C)
static_assert(MAC_SIZE == MAC_SIZE_C, "invalid mac size");

/**
 * @brief Helpers for pasing a DPP bootstrap hash string as encoded in wpa
 * control socket event messages.
 */
#define DPP_HASH_FORMAT "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define DPP_HASH_SIZE (sizeof DPP_HASH_FORMAT)
#define DPP_HASH_SIZE_C 65
#define DPP_HASH_SIZE_STR xstr(DPP_HASH_SIZE_C)
static_assert(DPP_HASH_SIZE == DPP_HASH_SIZE_C, "invalid dpp hash size");

/**
 * @brief Processes the chirp received event.
 *
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_event_chirp_received(struct wpa_controller *ctrl, const char *payload)
{
    int32_t id;
    uint32_t frequency;
    char hash[DPP_HASH_SIZE];
    char src[MAC_SIZE];

    int ret = sscanf(payload, "id=%d src=%" MAC_SIZE_STR "s freq=%" PRIu32 " hash=%" DPP_HASH_SIZE_STR "s", &id, src, &frequency, hash);
    if (ret != 4) {
        zlog_error_if(ctrl->interface, "invalid chirp event received");
        return;
    }

    zlog_debug_if(ctrl->interface, "chirp received, id=%d src=%s, freq=%u, hash=%s", id, src, frequency, hash);

    struct dpp_bootstrap_publickey_hash publickey_hash;
    if (hex_decode(hash, publickey_hash.data, sizeof publickey_hash.data) < 0) {
        zlog_error_if(ctrl->interface, "ifailed to decode public key hash (invalid format)");
        return;
    }

    const char(*mac)[MAC_SIZE] = (const char(*)[MAC_SIZE])src;
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_chirp_received, id, mac, frequency, &publickey_hash);
}

/**
 * @brief Process the dpp frame received event.
 * 
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_dpp_frame_received(struct wpa_controller *ctrl, const char *payload)
{
    char src[MAC_SIZE];
    int type_value;
    uint32_t frequency;

    int ret = sscanf(payload, "src=%" MAC_SIZE_STR "s freq=%" PRIu32 " type=%d", src, &frequency, &type_value);
    if (ret != 3) {
        zlog_error("invalid dpp frame rx event received");
        return;
    }

    enum dpp_public_action_frame_type type = dpp_public_action_frame_parse_int(type_value);
    if (type == DPP_PAF_INVALID) {
        zlog_error("invalid dpp frame type in dpp frame rx event (type=%d)", type_value);
        return;
    }

    zlog_debug_if(ctrl->interface, "dpp frame event received src=%s freq=%" PRIu32 " type=%s", src, frequency, dpp_public_action_frame_str(type));

    const char(*mac)[MAC_SIZE] = (const char(*)[MAC_SIZE])src;
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_frame_received, mac, type, frequency);
}

/**
 * @brief Process the dpp frame transmitted event.
 * 
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_dpp_frame_transmitted(struct wpa_controller *ctrl, const char *payload)
{
    __unused(payload);

    char dst[MAC_SIZE];
    int type_value;
    uint32_t frequency;

    int ret = sscanf(payload, "dst=%" MAC_SIZE_STR "s freq=%" PRIu32 " type=%d", dst, &frequency, &type_value);
    if (ret != 3) {
        zlog_error("invalid dpp frame tx event received");
        return;
    }

    enum dpp_public_action_frame_type type = dpp_public_action_frame_parse_int(type_value);
    if (type == DPP_PAF_INVALID) {
        zlog_error("invalid dpp frame type in dpp frame tx event (type=%d)", type_value);
        return;
    }

    const char(*mac)[MAC_SIZE] = (const char(*)[MAC_SIZE])dst;
    zlog_debug_if(ctrl->interface, "dpp frame event transmitted dst=%s freq=%" PRIu32 " type=%s", dst, frequency, dpp_public_action_frame_str(type));
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_frame_transmitted, mac, type, frequency);
}

/**
 * @brief Process the dpp frame transmitted status event.
 * 
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_dpp_frame_transmitted_status(struct wpa_controller *ctrl, const char *payload)
{
    char dst[MAC_SIZE];
    char result[32];
    uint32_t frequency;

    int ret = sscanf(payload, "dst=%" MAC_SIZE_STR "s freq=%" PRIu32 " result=%31s", dst, &frequency, result);
    if (ret != 3) {
        zlog_error("invalid dpp frame tx status event received");
        return;
    }

    const char(*mac)[MAC_SIZE] = (const char(*)[MAC_SIZE])dst;
    zlog_debug_if(ctrl->interface, "dpp frame event transmitted status dst=%s freq=%" PRIu32 " result=%s", dst, frequency, result);
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_frame_transmitted_status, mac, frequency, result);
}

/**
 * @brief Processes the dpp chirp stopped event.
 * 
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_event_dpp_chirp_stopped(struct wpa_controller *ctrl, const char *payload)
{
    __unused(payload);

    zlog_debug_if(ctrl->interface, "dpp chirp stopped event received");
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_chirp_stopped);
}

/**
 * @brief Processes the dpp failure event.
 *
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_event_dpp_failure(struct wpa_controller *ctrl, const char *payload)
{
    zlog_debug_if(ctrl->interface, "dpp failure event received (details=%s)", payload);
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_failure, payload);
}

/**
 * @brief Processes the dpp authentication initialization failure event.
 *
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_event_dpp_authentication_failure(struct wpa_controller *ctrl, const char *payload)
{
    __unused(payload);

    zlog_debug_if(ctrl->interface, "dpp authentication failure event received");
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_authentication_failure);
}

/**
 * @brief Processes the dpp authentication success event.
 *
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_event_dpp_authentication_success(struct wpa_controller *ctrl, const char *payload)
{
    int initiator;
    int ret = sscanf(payload, "init=%d", &initiator);
    if (ret != 1) {
        zlog_error("invalid dpp authentication event received");
        return;
    }

    zlog_debug_if(ctrl->interface, "dpp authentication success event received, initiator=%01d", initiator);
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_authentication_success, !!initiator);
}

/**
 * @brief Processes the dpp configuration failure event.
 *
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_event_dpp_configuration_failure(struct wpa_controller *ctrl, const char *payload)
{
    __unused(payload);

    zlog_debug_if(ctrl->interface, "dpp configuration failure event received");
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_configuration_failure);
}

/**
 * @brief Processes the dpp configuration success event.
 *
 * @param ctrl The wpa controller instance.
 * @param payload The event payload.
 */
static void
wpa_controller_process_event_dpp_configuration_success(struct wpa_controller *ctrl, const char *payload)
{
    __unused(payload);

    zlog_debug_if(ctrl->interface, "dpp configuration success event received");
    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, dpp_configuration_success);
}

/**
 * @brief This describes an upper bound for a control message. The wpa_cli tool
 * uses this as an upper bound, so is used similarly here.
 */
#define WPA_MAX_MSG_SIZE 4096

/**
 * @brief wpa controller message handler. This handles a single event message
 * that has become available on the event control interface file descriptor.
 *
 * @param ctrl The controller associated with the event.
 */
static void
wpa_controller_process_event(struct wpa_controller *ctrl)
{
    char buf[WPA_MAX_MSG_SIZE + 1];
    size_t buf_length = (sizeof buf) - 1;

    int ret = wpa_ctrl_recv(ctrl->event, buf, &buf_length);
    if (ret < 0) {
        zlog_error("[%s] failed to retrieve pending wpa control event (%d)", ctrl->interface, ret);
        return;
    }

    buf[buf_length] = '\0';
    zlog_debug("[%s] event=%s", ctrl->interface, buf);

    // Each message begins with an integer priority between angle brackets,
    // <priority=#>. Find the ending angle bracket.
    const char *start = strchr(buf, '>');
    if (!start) {
        zlog_warning("[%s] malformed wpa control message detected", ctrl->interface);
        return;
    }

    // Advance 1 character to the beginning of the message contents.
    start++;

    const char *message = NULL;
    if (strstart(start, DPP_EVENT_CHIRP_RX, &message)) {
        wpa_controller_process_event_chirp_received(ctrl, message);
    } else if (strstart(start, DPP_EVENT_CHIRP_STOPPED, &message)) {
        wpa_controller_process_event_dpp_chirp_stopped(ctrl, message);
    } else if (strstart(start, DPP_EVENT_FAIL, &message)) {
        wpa_controller_process_event_dpp_failure(ctrl, message);
    } else if (strstart(start, DPP_EVENT_AUTH_INIT_FAILED, &message)) {
        wpa_controller_process_event_dpp_authentication_failure(ctrl, message);
    } else if (strstart(start, DPP_EVENT_CONF_FAILED, &message)) {
        wpa_controller_process_event_dpp_configuration_failure(ctrl, message);
    } else if (strstart(start, DPP_EVENT_AUTH_SUCCESS, &message)) {
        wpa_controller_process_event_dpp_authentication_success(ctrl, message);
    } else if (strstart(start, DPP_EVENT_CONF_RECEIVED, &message)) {
        wpa_controller_process_event_dpp_configuration_success(ctrl, message);
    } else if (strstart(start, DPP_EVENT_RX, &message)) {
        wpa_controller_process_dpp_frame_received(ctrl, message);
    } else if (strstart(start, DPP_EVENT_TX, &message)) {
        wpa_controller_process_dpp_frame_transmitted(ctrl, message);
    } else if (strstart(start, DPP_EVENT_TX_STATUS, &message)) {
        wpa_controller_process_dpp_frame_transmitted_status(ctrl, message);
    }
}

/**
 * @brief Primary control interface event handler. This gets
 * invoked for all "unsolicited" events on the control interface.
 *
 * @param fd The wpa controller control interface file descriptor for events.
 * @param context The wpa controller instance.
 */
static void
on_wpa_controller_event(int fd, void *context)
{
    __unused(fd);

    struct wpa_controller *ctrl = (struct wpa_controller *)context;
    assert(fd == ctrl->event_fd);

    for (;;) {
        int ret = wpa_ctrl_pending(ctrl->event);
        if (ret < 0) {
            zlog_error("[%s] failed to determine if wpa control event is pending; possible disconnection", ctrl->interface);
            break;
        } else if (ret == 0) {
            break;
        }

        wpa_controller_process_event(ctrl);
    }
}

/**
 * @brief Attempt to establish a connection with the control socket.
 *
 * @param ctrl The control interface instance.
 * @return int 0 if the connection was established, non-zero otherwise.
 */
static int
wpa_controller_connection_establish(struct wpa_controller *ctrl)
{
    int ret;
    struct wpa_ctrl *ctrl_command = wpa_ctrl_open(ctrl->path);
    if (!ctrl_command) {
        zlog_error("[%s] failed to establish wpa control command connection using control file %s", ctrl->interface, ctrl->path);
        return -ENODEV;
    }

    struct wpa_ctrl *ctrl_event = wpa_ctrl_open(ctrl->path);
    if (!ctrl_event) {
        zlog_error("[%s] failed to establish wpa control event connection using control file %s", ctrl->interface, ctrl->path);
        ret = -ENODEV;
        goto fail;
    }

    ret = wpa_ctrl_attach(ctrl_event);
    if (ret < 0) {
        zlog_error("[%s] failed to attach to wpa control event feed using control file %s (%d)", ctrl->interface, ctrl->path, ret);
        goto fail;
    }

    int ctrl_event_fd = wpa_ctrl_get_fd(ctrl_event);
    ret = event_loop_register_event(ctrl->loop, EPOLLIN, ctrl_event_fd, on_wpa_controller_event, ctrl);
    if (ret < 0) {
        zlog_error("[%s] failed to register wpa control event monitor (%d)", ctrl->interface, ret);
        goto fail;
    }

    ctrl->command = ctrl_command;
    ctrl->event = ctrl_event;
    ctrl->event_fd = ctrl_event_fd;
    ctrl->connected = true;

    zlog_info("[%s] control socket connection established", ctrl->interface);

out:
    return ret;
fail:
    if (ctrl_event) {
        wpa_ctrl_detach(ctrl_event);
        wpa_ctrl_close(ctrl_event);
    }

    if (ctrl_command) {
        wpa_ctrl_close(ctrl_command);
    }

    goto out;
}

/**
 * @brief Teardown a control socket connection.
 *
 * @param ctrl The control interface instance.
 */
static void
wpa_controller_connection_teardown(struct wpa_controller *ctrl)
{
    if (ctrl->event_fd != -1) {
        event_loop_unregister_event(ctrl->loop, ctrl->event_fd);
        ctrl->event_fd = -1;
    }

    if (ctrl->event) {
        wpa_ctrl_detach(ctrl->event);
        wpa_ctrl_close(ctrl->event);
        ctrl->event = NULL;
    }

    if (ctrl->command) {
        wpa_ctrl_close(ctrl->command);
        ctrl->command = NULL;
    }

    ctrl->connected = false;

    zlog_info("[%s] control socket connection severed", ctrl->interface);
}

/**
 * @brief Default parameters for pending connection retries.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS 10
#define CONNECTION_RETRY_PERIOD_US 1000000

/**
 * @brief Pending connection attempt context.
 */
struct wpa_controller_pending_connection_context {
    struct wpa_controller *ctrl;
    uint32_t num_attempts;
    uint32_t max_attempts;
    uint32_t period_us;
};

static void
on_pending_connection_attempt(void *context);

/**
 * @brief Cancels a pending connection attempt.
 * 
 * @param ctrl The control interface instance.
 */
static void
pending_connection_cancel(struct wpa_controller *ctrl)
{
    if (!ctrl->pending_connection_context)
        return;

    event_loop_task_cancel(ctrl->loop, on_pending_connection_attempt, ctrl->pending_connection_context);
    free(ctrl->pending_connection_context);
    ctrl->pending_connection_context = NULL;
}

/**
 * @brief Schedules a timer for periodic connection attempts.
 * 
 * This will schedule a timer that will be invoked at the specified period upon
 * connection attempt failures. The timer will be automatically canceled if the
 * maximum number of attempts have been reached or a connection has been
 * successfully established.
 *
 * @param ctrl The control interface instance.
 * @param period_us The period at which to attempt connections, in microseconds.
 * @param max_attempts The maximum number of attempts to make.
 * @return int 0 if the timer was scheduled, non-zero otherwise.
 */
static int
pending_connection_schedule(struct wpa_controller *ctrl, uint32_t period_us, uint32_t max_attempts)
{
    pending_connection_cancel(ctrl);

    struct wpa_controller_pending_connection_context *context = calloc(1, sizeof *context);
    if (!context) {
        zlog_error("failed to schedule pending connection attempt (no memory)");
        return -ENOMEM;
    }

    context->ctrl = ctrl;
    context->num_attempts = 0;
    context->max_attempts = max_attempts;

    int ret = event_loop_task_schedule(ctrl->loop, 0, period_us, TASK_PERIODIC, on_pending_connection_attempt, context);
    if (ret < 0) {
        zlog_error("failed to schedule pending connection attempt timer (%d)", ret);
        free(context);
        return ret;
    }

    ctrl->pending_connection_context = context;

    return 0;
}

/**
 * @brief Pending connection attempt handler.
 * 
 * This will attempt to establish a connection with the control socket. If
 * successful, the controller presence event handlers will be signaled and the
 * periodic pending connection attempt timer will be cancled.
 * 
 * @param context The pending connection attempt context.
 */
static void
on_pending_connection_attempt(void *context)
{
    struct wpa_controller_pending_connection_context *pending = (struct wpa_controller_pending_connection_context *)context;
    if (!pending)
        return;

    struct wpa_controller *ctrl = pending->ctrl;

    if (pending->num_attempts >= pending->max_attempts) {
        zlog_error_if(ctrl->interface, "failed to re-connect to control socket after %" PRIu32 " attempts; giving up", pending->max_attempts);
        pending_connection_cancel(ctrl);
        return;
    } else if (pending->num_attempts++ > 0) {
        zlog_info_if(ctrl->interface, "attempting to re-connect to control socket [%" PRIu32 "/%" PRIu32 "]", pending->num_attempts, pending->max_attempts);
    }

    if (wpa_controller_connection_establish(ctrl) < 0)
        return;

    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, interface_presence_changed, WPA_CONTROLLER_ARRIVED);
    pending_connection_cancel(ctrl);
}

/**
 * @brief Control socket presence event handler.
 *
 * @param context The wpa controller instance.
 * @param event The event that occurred.
 * @param path The parent path of the control interface.
 * @param interface The control socket file name.
 */
static void
on_ctrl_presence_changed(void *context, enum wpa_controller_presence_event event, const char *path, const char *interface)
{
    zlog_debug("wpa control socket %s/%s %s", path, interface, event == WPA_CONTROLLER_ARRIVED ? "arrived" : "departed");

    struct wpa_controller *ctrl = (struct wpa_controller *)context;
    if (strcmp(ctrl->interface, interface) != 0) {
        zlog_debug("ignoring wpa controller presence event for interface %s", interface);
        return;
    }

    pending_connection_cancel(ctrl);

    switch (event) {
        case WPA_CONTROLLER_DEPARTED: {
            wpa_controller_connection_teardown(ctrl);
            break;
        }
        case WPA_CONTROLLER_ARRIVED: {
            int ret = wpa_controller_connection_establish(ctrl);
            if (ret < 0) {
                zlog_warning_if(ctrl->interface, "failed to connect to control socket (%d); scheduling pending connection", ret);
                ret = pending_connection_schedule(ctrl, CONNECTION_RETRY_PERIOD_US, CONNECTION_RETRY_MAX_ATTEMPTS);
                if (ret < 0)
                    zlog_error_if(ctrl->interface, "failed to schedule pending control socket connection (%d)", ret);
                return;
            }
            break;
        }
        default:
            return;
    }

    WPA_CONTROLLER_INVOKE_EVENT_HANDLERS(ctrl, interface_presence_changed, WPA_CONTROLLER_DEPARTED);
}

/**
 * @brief Uninitializes a wpa controller.
 *
 * @param interface The interface to uninitialize the control interface for.
 */
void
wpa_controller_uninitialize(struct wpa_controller *ctrl)
{
    pending_connection_cancel(ctrl);
    wpa_controller_connection_teardown(ctrl);

    if (ctrl->watcher) {
        wpa_controller_watcher_destroy(&ctrl->watcher);
    }

    if (ctrl->path) {
        free(ctrl->path);
        ctrl->path = NULL;
    }
}

/**
 * @brief Initializes a wpa controller.
 *
 * @param ctrl The controller to initialize.
 * @param ctrl_path The full path to the wpa control socket.
 * @return int 0 if the control interface was successfully initialized non-zero otherwise.
 */
int
wpa_controller_initialize(struct wpa_controller *ctrl, const char *ctrl_path, struct event_loop *loop)
{
    char *path = strdup(ctrl_path);
    if (!path) {
        zlog_error("failed to allocate memory for wpa controller path %s", ctrl_path);
        return -ENOMEM;
    }

    char *separator = strrchr(path, '/');
    if (!separator) {
        free(path);
        zlog_error("control path %s is malformed (missing parent directory)", ctrl_path);
        return -EINVAL;
    }

    size_t leaf_index = (size_t)(separator - path);
    ctrl->loop = loop;
    ctrl->path = path;
    ctrl->interface = ctrl->path + leaf_index + 1;

    ctrl->path[leaf_index] = '\0';
    ctrl->watcher = wpa_controller_watcher_create(loop, path);
    ctrl->path[leaf_index] = '/';

    if (!ctrl->watcher) {
        zlog_error_if(ctrl->interface, "failed to create wpa controller watcher");
        wpa_controller_uninitialize(ctrl);
        return -EINVAL;
    }

    int ret = wpa_controller_watcher_register_interface_presence_event_handler(ctrl->watcher, on_ctrl_presence_changed, ctrl);
    if (ret < 0) {
        zlog_error_if(ctrl->interface, "failed to register for control interface presence change events (%d)", ret);
        goto fail;
    }

    // Attempt to establish a connection with the control interface. Do not
    // count failure here as catastrophic since the watcher will establish a
    // connection when the control socket becomes available.
    if (wpa_controller_connection_establish(ctrl) < 0)
        zlog_info_if(ctrl->interface, "control socket for %s unavailable; deferring connection", ctrl_path);

    ret = 0;
out:
    return ret;
fail:
    wpa_controller_uninitialize(ctrl);
    goto out;
}

/**
 * @brief Allocates a new wpa controller instance. The returned pointer must be
 * initialized with wpa_controller_initialize.
 *
 * @return struct wpa_controller*
 */
struct wpa_controller *
wpa_controller_alloc(void)
{
    struct wpa_controller *ctrl = (struct wpa_controller *)calloc(1, sizeof *ctrl);
    if (!ctrl) {
        zlog_error("failed to allocate memory for wpa controller");
        return NULL;
    }

    INIT_LIST_HEAD(&ctrl->event_handlers);

    return ctrl;
}

/**
 * @brief Destroys a wpa controller, as allocated by wpa_controller_alloc.
 *
 * @param ctrl The controller instance to destroy.
 */
void
wpa_controller_destroy(struct wpa_controller **ctrl)
{
    if (*ctrl) {
        free(*ctrl);
        *ctrl = NULL;
    }
}

/**
 * @brief Sends a generic command on the wpa control interface.
 *
 * This function should not be used directly. Instead, the
 * wpa_controller_send_commandf macro provides syntactic sugar for sending a
 * command in a similar way and constructs the 'fmt' argument as it is expected
 * here.
 *
 * This function allows printf style generation of the command payload, but
 * expects a very specific encoding of the 'fmt' argument, which must be of the
 * form:
 *
 *  "<command=name> <command payload>"
 *
 * The va_args must be provided according to the 'fmt' argument. The behavior is otherwise undefined.
 *
 * @param ctrl The control interface to send the command on.
 * @param name The name of the command to send.
 * @param reply The buffer to hold the reply. This must have enough space for the reply and a null terminator.
 * @param reply_length The size of the reply buffer. Will be updated with the actual reply length on success.
 * @param fmt The string format of the following arguments constituting the command payload.
 * @param ... The arguments constituting the command payload.
 * @return int 0 if the command was successfully sent. In this case, 'reply'
 * shall contain a NULL-terminated *reply_length response from the control interface. -ENOTCON
 * is returned if there is no established connection to the control socket.
 * Otherwise, a non-zero value is returned.
 */
static int
__wpa_controller_send_commandf(struct wpa_controller *ctrl, const char *name, char *reply, size_t *reply_length, const char *fmt, ...)
{
    int ret;
    char cmd[WPA_MAX_MSG_SIZE + 1];

    if (!ctrl->connected) {
        zlog_error_if(ctrl->interface, "no connection to control interface");
        return -ENOTCONN;
    }

    va_list args;
    va_start(args, fmt);
    ret = vsnprintf(cmd, sizeof cmd, fmt, args);
    va_end(args);

    if (ret < 0) {
        zlog_error_if(ctrl->interface, "failed to encode %s command (%d)", name, ret);
        return ret;
    }

    size_t cmd_length = (size_t)ret;
    zlog_debug_if(ctrl->interface, "wpa -> %.*s", (int)cmd_length, cmd);

    ret = wpa_ctrl_request(ctrl->command, cmd, cmd_length, reply, reply_length, NULL);
    if (ret < 0) {
        zlog_error_if(ctrl->interface, "failed to send %s command on ctrl interface (%d)", name, ret);
        return ret;
    }
    reply[*reply_length > WPA_MAX_MSG_SIZE? WPA_MAX_MSG_SIZE : *reply_length] = '\0';

    zlog_debug_if(ctrl->interface, "wpa <- %.*s", (int)(*reply_length), reply);

    return 0;
}

/**
 * @brief Helper macro to allow encoding the command buffer on the fly using va_args.
 *
 * The _cmd and _fmt arguments must be string literals. They are combined to
 * form the command buffer, with the command name fixed and the payload
 * populated by the va_args following the last argument (...).
 *
 * Eg.
 * const char *dpp_uri = "DPP:V:1;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACE0vdn8KsfXKHusJPcEscx+naQyQJLSob1VjuqPsP6r8=;";
 * wpa_controller_send_commandf(ctrl, "DPP_QRCODE", reply, reply_length, "%s", dpp_uri);
 */
#define wpa_controller_send_commandf(_ctrl, _cmd, _reply, _reply_length, _fmt, ...) \
    __wpa_controller_send_commandf(_ctrl, _cmd, _reply, _reply_length, _cmd " " _fmt, ##__VA_ARGS__)

/**
 * @brief Argument-less version of wpa_controller_send_commandf.
 */
#define wpa_controller_send_command(_ctrl, _cmd, _reply, _reply_length) \
    __wpa_controller_send_commandf(_ctrl, _cmd, _reply, _reply_length, _cmd)

/**
 * @brief Invokes the 'DPP_QR_CODE' command on the hostapd interface.
 *
 * @param ctrl The wpa controller instance.
 * @param dpp_uri The DPP URI to register with the configurator.
 * @return int 0 if successful, non-zero otherwise.
 */
int
wpa_controller_qrcode(struct wpa_controller *ctrl, const char *dpp_uri, uint32_t *bootstrap_id)
{
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    int ret = wpa_controller_send_commandf(ctrl, "DPP_QR_CODE", reply, &reply_length, "%s", dpp_uri);
    if (ret < 0)
        return ret;

    uint32_t id = (uint32_t)strtoul(reply, NULL, 10);
    if (id == 0) {
        zlog_error_if(ctrl->interface, "qrcode command failed (response='%.*s')", (int)reply_length, reply);
        return -1;
    }

    zlog_debug_if(ctrl->interface, "%s <-> id=%" PRIu32 "", dpp_uri, id);

    if (bootstrap_id)
        *bootstrap_id = id;

    return 0;
}

/**
 * @brief Invokes the 'SET" command on the control interface. This alllows
 * controlling runtime configuration parameters of wpa_supplicant and hostapd.
 *
 * The caller is responsible for sending appropriately supported key/value
 * pairs depending on the daemon respresented by the control interface, and the
 * key itself.
 *
 * @param ctrl The wpa controller instance.
 * @param key The name of the configuration key to set.
 * @param value The value of the configuration key to set.
 * @return int 0 if the command was successfully sent and the value was
 * applied. Otherwise a non-zero error value is returned.
 */
int
wpa_controller_set(struct wpa_controller *ctrl, const char *key, const char *value)
{
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    int ret = wpa_controller_send_commandf(ctrl, "SET", reply, &reply_length, "%s %s", key, value);
    if (ret < 0)
        return ret;

    return (strncmp(reply, "OK", 2) == 0) ? 0 : -1;
}

/**
 * @brief Invokes the 'DPP_AUTH_INIT' command on the control interface. This
 * initiated a DPP authentication with the bootstrapping information identified
 * by 'peer_id'.
 *
 * @param ctrl The wpa controller instance.
 * @param peer_id The bootstrapping info identifier for the peer to initiation
 * DPP authentication with.
 * @param frequency The radio frequency to use to initiation authentication. If
 * 0 is supplied, the configurator will attempt to initiate authentication on
 * all usable channels (not recommended).
 * @return int 0 if the command was
 * successfully send, non-zero otherwise.
 */
int
wpa_controller_dpp_auth_init(struct wpa_controller *ctrl, uint32_t peer_id, uint32_t frequency)
{
    int ret;
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    if (frequency > 0) {
        ret = wpa_controller_send_commandf(ctrl, "DPP_AUTH_INIT", reply, &reply_length, "peer=%" PRIu32 " neg_freq=%" PRIu32, peer_id, frequency);
    } else {
        ret = wpa_controller_send_commandf(ctrl, "DPP_AUTH_INIT", reply, &reply_length, "peer=%" PRIu32, peer_id);
    }

    if (ret < 0)
        return ret;

    return (strncmp(reply, "OK", 2) == 0) ? 0 : -1;
}

/**
 * @brief Invokes the 'DPP_AUTH_INIT' command on the control interface. This
 * initiated a DPP authentication with the bootstrapping information identified
 * by 'peer_id'.
 *
 * @param ctrl The wpa controller instance.
 * @param peer_id The bootstrapping info identifier for the peer to initiation
 * DPP authentication with.
 * @param frequency The radio frequency to use to initiation authentication. If
 * 0 is supplied, the configurator will attempt to initiate authentication on
 * all usable channels (not recommended).
 * @param conf The DPP configurator settings for authentication. This can
 * include the target network configuration, amongst other things.
 * @return int 0 if the command was
 * successfully send, non-zero otherwise.
 */
int
wpa_controller_dpp_auth_init_with_conf(struct wpa_controller *ctrl, uint32_t peer_id, uint32_t frequency, const char *conf)
{
    int ret;
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    if (frequency > 0) {
        ret = wpa_controller_send_commandf(ctrl, "DPP_AUTH_INIT", reply, &reply_length, "peer=%" PRIu32 " neg_freq=%" PRIu32 " %s", peer_id, frequency, conf);
    } else {
        ret = wpa_controller_send_commandf(ctrl, "DPP_AUTH_INIT", reply, &reply_length, "peer=%" PRIu32 " %s", peer_id, conf);
    }

    if (ret < 0)
        return ret;

    return (strncmp(reply, "OK", 2) == 0) ? 0 : -1;
}

/**
 * @brief Invokes the 'DPP_BOOTSTRAP_SET' command on the control interface.
 * This associates configurator parameters with the specified peer. Many
 * configurator params can be specified, however, the most useful for ztp are
 * those related to network provisioning.
 *
 * @param ctrl The wpa controller instance.
 * @param peer_id The bootstrapping info identifier of the peer to set
 * bootstrapping information for.
 * @param conf The bootstrapping configuration parameters, encoded as a string.
 * @return int 0 if the command was successfully sent, non-zero otherwise.
 */
int
wpa_controller_dpp_bootstrap_set(struct wpa_controller *ctrl, uint32_t peer_id, const char *conf)
{
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    int ret = wpa_controller_send_commandf(ctrl, "DPP_BOOTSTRAP_SET", reply, &reply_length, "%" PRIu32 " %s", peer_id, conf);
    if (ret < 0)
        return ret;

    return (strncmp(reply, "OK", 2) == 0) ? 0 : -1;
}

/**
 * @brief Invokes the 'DPP_BOOTSTRAP_GEN' command on the control interface.
 * This creates a DPP bootstrap key according to the specified parameters in
 * 'bi'.
 * 
 * @param ctrl The wpa controller instance.
 * @param bi The information describing the bootstrap key.
 * @param id The identifier of the bootstrap key, which is used to identify the
 * key in subsequent control interface DPP commands.  
 * @return int 0 if the command completed successfully, non-zero otherwise.
 */
int
wpa_controller_dpp_bootstrap_gen(struct wpa_controller *ctrl, const struct dpp_bootstrap_info *bi, uint32_t *id)
{
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    int ret = wpa_controller_send_commandf(ctrl, "DPP_BOOTSTRAP_GEN", reply, &reply_length, 
        "type=%s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        dpp_bootstrap_type_str(bi->type),
        bi->channel ? " chan="   : "", bi->channel ? bi->channel : "",
        bi->mac     ? " mac="    : "", bi->mac     ? bi->mac     : "",
        bi->info    ? " info="   : "", bi->info    ? bi->info    : "",
        bi->curve   ? " curve="  : "", bi->curve   ? bi->curve   : "",
        bi->key     ? " key="    : "", bi->key     ? bi->key     : "",
        bi->key_id  ? " key_id=" : "", bi->key_id  ? bi->key_id  : "",
        bi->engine_id    ? " engine=" : "", bi->engine_id  ? bi->engine_id  : "",
        bi->engine_path  ? " engine_path=" : "", bi->engine_path ? bi->engine_path : "");
    if (ret < 0)
        return ret;

    uint32_t id_reply = (uint32_t)strtoul(reply, NULL, 0);
    if (id_reply == 0)
        return -EINVAL;

    *id = id_reply;

    return 0;
}

/**
 * @brief Requests wpa_supplicant to begin chirping with a specific bootstrap key.
 * 
 * @param ctrl The wpa controller instance.
 * @param bootstrap_key_id The identifier of the bootstrapping key to chirp.
 * @param iterations The number of chirp iterations to perform.
 * @return int The result of the operation, 0 if successful, non-zero otherwise.
 */
int
wpa_controller_dpp_chirp(struct wpa_controller *ctrl, uint32_t bootstrap_key_id, uint32_t iterations)
{
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    int ret = wpa_controller_send_commandf(ctrl, "DPP_CHIRP", reply, &reply_length, "own=%" PRIu32 " iter=%" PRIu32, bootstrap_key_id, iterations);
    if (ret < 0)
        return ret;

    return (strncmp(reply, "OK", 2) == 0) ? 0 : -1;
}

/**
 * @brief Requests wpa_supplicant to stop chirping.
 * 
 * @param ctrl The wpa controller instance.
 * @return int The result of the operation, 0 if successful, non-zero otherwise.
 */
int
wpa_controller_dpp_chirp_stop(struct wpa_controller *ctrl)
{
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    int ret = wpa_controller_send_command(ctrl, "DPP_STOP_CHIRP", reply, &reply_length);
    if (ret < 0)
        return ret;

    return (strncmp(reply, "OK", 2) == 0) ? 0 : -1;
}

/**
 * @brief Requests wpa_supplicant to stop/cancel a DPP exchange.
 * @return int The result of the operation, 0 if successful, non-zero otherwise.
 */
int
wpa_controller_dpp_listen_stop(struct wpa_controller *ctrl)
{
    char reply[WPA_MAX_MSG_SIZE + 1];
    size_t reply_length = sizeof reply;

    int ret = wpa_controller_send_command(ctrl, "DPP_STOP_LISTEN", reply, &reply_length);
    if (ret < 0)
        return ret;

    return (strncmp(reply, "OK", 2) == 0) ? 0 : -1;
}

/**
 * @brief Registers a handler for when chirps are received on the specified interface.
 *
 * @param ctrl The wpa control instance.
 * @param handler The event handler to invoke when an event occurs.
 * @param userdata The context to be passed to the event handling functions.
 * @return int 0 if successful, non-zero otherwise.
 */
int
wpa_controller_register_event_handler(struct wpa_controller *ctrl, struct wpa_event_handler *handler, void *userdata)
{
    struct wpa_event_handler_instance *instance = (struct wpa_event_handler_instance *)malloc(sizeof *instance);
    if (!instance) {
        zlog_error_if(ctrl->interface, "failed to allocate memory for chirp received event handler");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&instance->list);
    instance->handler = handler;
    instance->userdata = userdata;
    list_add(&instance->list, &ctrl->event_handlers);

    zlog_debug_if(ctrl->interface, "wpa event handler registered, handler=0x%" PRIx64 " arg=0x%" PRIx64 "", (uint64_t)handler, (uint64_t)userdata);

    return 0;
}

/**
 * @brief Unregisters a handler for chirp received events.
 *
 * @param ctrl The wpa control instance.
 * @param handler The previously registered event handler.
 * @param userdata The event handler callback context.
 */
void
wpa_controller_unregister_event_handler(struct wpa_controller *ctrl, struct wpa_event_handler *handler, void *userdata)
{
    struct wpa_event_handler_instance *instance;
    list_for_each_entry (instance, &ctrl->event_handlers, list) {
        if (instance->handler == handler && instance->userdata == userdata) {
            zlog_debug_if(ctrl->interface, "wpa event handler unregistered, handler=0x%" PRIx64 " arg=0x%" PRIx64 "", (uint64_t)handler, (uint64_t)userdata);
            list_del(&instance->list);
            free(instance);
            break;
        }
    }
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif //__clang_
