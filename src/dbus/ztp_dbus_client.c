
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <userspace/linux/compiler.h>

#include "event_loop.h"
#include "ztp_dbus_client.h"
#include "ztp_log.h"

/**
 * @brief Private structure tracking context associated with a
 * PropertiesChanged handler.
 */
struct ztp_dbus_properties_changed_handle {
    struct list_head list;
    void *userdata;
    ztp_dbus_properties_changed_handler handler;
    sd_bus_slot *slot;
};

/**
 * @brief Generic properties changed handler that does some basic unwrapping of
 * the sd-bus message and passes on the changed property dictionary to
 * registered callbacks.
 *
 * @param msg The message containing the PropertiesChanged signal payload.
 * @param userdata The context containing the registered callback handler.
 * @param ret_error A proxy to return an error value. Unused (as we are the receiver).
 * @return int 0 if the properties were handled successfully, non-zero otherwise.
 */
static int
ztpd_dbus_on_properties_changed(sd_bus_message *msg, void *userdata, sd_bus_error *ret_error)
{
    __unused(ret_error);

    struct ztp_dbus_properties_changed_handle *context = (struct ztp_dbus_properties_changed_handle *)userdata;

    // All PropertiesChanged signals include the name of the interface as the first argument. Read it.
    char *interface;
    int ret = sd_bus_message_read_basic(msg, SD_BUS_TYPE_STRING, &interface);
    if (ret < 0) {
        zlog_error("failed to read 'interface' property of 'PropertiesChanged' signal (%d)", ret);
        goto fail;
    }

    // Unwrap the dictionary entries which are a d-bus "array".
    ret = sd_bus_message_enter_container(msg, SD_BUS_TYPE_ARRAY, "{sv}");
    if (ret < 0) {
        zlog_error("failed to enter properties array container (%d)", ret);
        goto fail;
    }

    // Invoke user-supplied handler, passing supplied data pointer and message.
    context->handler(msg, interface, context->userdata);

    ret = 0;
out:
    return ret;
fail:
    goto out;
}

/**
 * @brief Registers a property changed handler function for a d-bus interface.
 * This refers to the standard-defined org.freedesktop.DBus.Properties.PropertiesChanged
 * signal.
 *
 * @param dbus The dbus control object.
 * @param interface The dbus interface to monitor for property changes.
 * @param userdata User data that will be passed to the property change handler.
 * @param handler The function that will be invoked upon property changes.
 * @param handle A handle referencing the installed property handler.
 * @return int The result of the operation. 0 if successful, in which case
 * '*handle' will be populated with a value that refers to the monitor. A
 * negative error value is returned otherwise.
 */
int
ztp_dbus_register_properties_changed_handler(
    struct ztp_dbus_client *dbus,
    const char *interface,
    void *userdata,
    ztp_dbus_properties_changed_handler handler,
    struct ztp_dbus_properties_changed_handle **phandle)
{
    // Disallow unescaped single quote characters (') to prevent injection of
    // key-value pairs into the signal matching rule.
    if (strchr(interface, '\'') != NULL)
        return -EINVAL;

    struct ztp_dbus_properties_changed_handle *handle = calloc(1, sizeof *handle);
    if (!handle)
        return -ENOMEM;

    handle->userdata = userdata;
    handle->handler = handler;

    // Build a d-bus match expression that will link to a PropertiesChanged
    // event on a specific interface. This is done using an 'Arg' match, which
    // matches a positional argument that is passed to the signal. For the
    // PropertiesChanged event, the first argument is the interface for which
    // the signal is being raised, and so 'arg0' is used with the supplied
    // interface to limit the match to that interface. See 'Match Rules' at
    // https://dbus.freedesktop.org/doc/dbus-specification.html#type-system
    // for more information.
    char match[256];
    snprintf(match, sizeof match,
        "type='signal',"
        "interface='org.freedesktop.DBus.Properties',"
        "member='PropertiesChanged',"
        "arg0='%s'", interface);

    // Register the targeted match rule for this signal.
    int ret = sd_bus_add_match(dbus->bus, &handle->slot, match, ztpd_dbus_on_properties_changed, handle);
    if (ret < 0) {
        zlog_error("failed to add match for PropertiesChanged handler (%d)", ret);
        goto fail;
    }

    list_add(&handle->list, &dbus->property_changed_handles);
    *phandle = handle;
    ret = 0;

out:
    return ret;
fail:
    ztp_dbus_unregister_properties_changed_handler(handle);
    goto out;
}

/**
 * @brief Unregisters a property changed handler from ztpd.
 *
 * @param handle The handle to unregister. Must have been obtained from
 * ztpd_dbus_register_properties_changed_handler().
 */
void
ztp_dbus_unregister_properties_changed_handler(struct ztp_dbus_properties_changed_handle *handle)
{
    if (!handle)
        return;

    if (handle->slot) {
        sd_bus_slot_unref(handle->slot);
        handle->slot = NULL;
    }

    list_del(&handle->list);
    free(handle);
}

/**
 * @brief Processes an update for a file descriptor used for monitoring d-bus
 * socket changes.
 *
 * sd-bus may coalesce multiple ready messages into a single file descriptor
 * signal, so a loop is needed to ensure all such messages are processed.
 *
 * @param fd The file descriptor that has an update.
 * @param context The global ztpd instance.
 */
int
process_fd_update_dbus(sd_event_source *s,int fd, uint32_t revents, void *context)
{
    __unused(s);
    __unused(fd);
    __unused(revents);

    uint32_t nmsg = 0;
    sd_bus_message *msg;
    struct ztp_dbus_client *dbus = (struct ztp_dbus_client *)context;

    for (;;) {
        // Retrieve the next message that is available for processing.
        int ret = sd_bus_process(dbus->bus, &msg);
        if (ret < 0) {
            zlog_error("failed to retrieve pending sd-bus message (%d)", ret);
            break;
        // This indicates no more messages are available for processing.
        } else if (ret == 0) {
            break;
        }

        // Release message reference to indicate we're done with it.
        sd_bus_message_unref(msg);
        nmsg++;
    }

    // Re-configure the file descriptor with updated operations.
    uint32_t events = sd_bus_get_events(dbus->bus);
    struct epoll_event event;
    explicit_bzero(&event, sizeof event);
    event.events = events ? events : EPOLLIN;
    event.data.fd = dbus->fd;

    if (epoll_ctl(dbus->loop->epoll_fd, EPOLL_CTL_MOD, event.data.fd, &event) < 0)
        zlog_error("failed to update sd-bus fd settings for epoll (%d)", errno);
}

/**
 * @brief Uninitializes a dbus connector instance.
 *
 * @param dbus The instance to uninitialize.
 */
void
ztp_dbus_uninitialize(struct ztp_dbus_client *dbus)
{
    if (dbus->bus != NULL) {
        sd_bus_unref(dbus->bus);
        dbus->bus = NULL;
    }
}

/**
 * @brief Initializes an instance of a dbus connector.
 *
 * @param dbus The instance to initialize.
 * @param loop The ztp event loop to run the dbus connection on.
 * @return int 0 initialized successfuly, non-zero otherwise.
 */
int
ztp_dbus_initialize(struct ztp_dbus_client *dbus, sd_event *loop)
{
    INIT_LIST_HEAD(&dbus->property_changed_handles);
    dbus->loop = loop;
    dbus->fd = -1;

    // Get a handle to the system bus.
    int ret = sd_bus_default_system(&dbus->bus);
    if (ret < 0) {
        zlog_error("failed to open system bus (%d)", -ret);
        goto fail;
    }

    ret = sd_bus_attach_event(dbus->bus,loop,SD_EVENT_PRIORITY_NORMAL);
    if (ret < 0) {
        zlog_error("failed to register event for monitoring d-bus updates (%d)", ret);
        goto fail;
    }

    ret = 0;
out:
    return ret;
fail:
    ztp_dbus_uninitialize(dbus);
    goto out;
}
