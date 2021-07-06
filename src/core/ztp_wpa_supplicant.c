
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-bus.h>
#include <userspace/linux/compiler.h>

#include "dbus_common.h"
#include "string_utils.h"
#include "ztp.h"
#include "ztp_log.h"
#include "ztp_wpa_supplicant.h"

/**
 * @brief Helper function to track registered callbacks for the interface
 * presence changed event.
 */
struct interface_presence_changed_callback {
    struct list_head list;
    interface_presence_changed_fn handler;
    void *userdata;
};

/**
 * @brief Invoke the registered callback handler for the interface presence
 * changed event.
 *
 * @param callback The callback context for the event.
 * @param name the name of the interface whose presence changed
 * @param path the d-bus path of the interface whose presence changed.
 */
static void
invoke_interface_presence_changed_callback(struct interface_presence_changed_callback *callback, enum ztp_interface_presence presence, const char *name, const char *path)
{
    callback->handler(callback->userdata, presence, name, path);
}

/**
 * @brief Invoke all registered callback handlers for the interface added event.
 *
 * @param wpas the wpa supplicant instance.
 * @param name the name of the interface whose presence changed
 * @param path the d-bus path of the interface whose presence changed.
 */
static void
invoke_interface_presence_changed_callbacks(struct ztp_wpa_supplicant *wpas, enum ztp_interface_presence presence, const char *name, const char *path)
{
    struct interface_presence_changed_callback *callback;
    list_for_each_entry (callback, &wpas->interface_presence_changed, list) {
        invoke_interface_presence_changed_callback(callback, presence, name, path);
    }
}

/**
 * @brief Cleans up resources owned by a wpa_supplicant_interface_entry.
 *
 * @param entry The entry to uninitialize.
 */
static void
wpa_supplicant_interface_entry_uninitialize(struct wpa_supplicant_interface_entry *entry)
{
    if (!entry)
        return;

    list_del(&entry->list);

    if (entry->path)
        free(entry->path);
    if (entry->name)
        free(entry->name);
    free(entry);
}

/**
 * @brief Finds a wpa supplicant interface entry by d-bus path.
 *
 * @param wpas The wpa supplicant instance.
 * @param path  The d-bus path of the interface to find.
 * @return struct wpa_supplicant_interface_entry* The interface entry, if
 * present. Otherwise NULL.
 */
struct wpa_supplicant_interface_entry *
find_interface_entry_by_path(struct ztp_wpa_supplicant *wpas, const char *path)
{
    struct wpa_supplicant_interface_entry *entry;

    list_for_each_entry (entry, &wpas->interfaces, list) {
        if (strcmp(entry->path, path) == 0)
            break;
    }

    return entry;
}

/**
 * @brief Finds a wpa supplicant interface entry by an interface name.
 *
 * @param wpas The wpa supplicant instance.
 * @param name  The name of the interface to find.
 * @return struct wpa_supplicant_interface_entry* The interface entry, if
 * present. Otherwise NULL.
 */
struct wpa_supplicant_interface_entry *
find_interface_entry_by_name(struct ztp_wpa_supplicant *wpas, const char *name)
{
    struct wpa_supplicant_interface_entry *entry;

    list_for_each_entry (entry, &wpas->interfaces, list) {
        if (strcmp(entry->name, name) == 0)
            break;
    }

    return entry;
}

/**
 * @brief Adds a new interface to the list of interfaces being tracked.
 *
 * @param wpas The wpa_supplicant instance.
 * @param path The d-bus object path of the interface.
 * @param name The name of the interface.
 * @return int The result of the operation. 0 if successful, -1 otherwise.
 */
struct wpa_supplicant_interface_entry *
wpa_supplicant_interface_entry_initialize(const char *path, const char *name)
{
    struct wpa_supplicant_interface_entry *entry = calloc(1, sizeof *entry);
    if (!entry) {
        zlog_error_if(name, "failed to allocate memory for interface entry");
        return NULL;
    }

    INIT_LIST_HEAD(&entry->list);

    entry->path = strdup(path);
    if (!entry->path) {
        zlog_error_if(name, "failed to allocate memory for interface path string");
        free(entry);
        return NULL;
    }

    entry->name = strdup(name);
    if (!entry->name) {
        zlog_error_if(name, "failed to allocate memory for interface name string");
        goto fail;
    }

    return entry;

fail:
    wpa_supplicant_interface_entry_uninitialize(entry);
    return NULL;
}

/**
 * @brief Add a new interface for monitoring.
 *
 * @param wpas The wpa supplicant instance.
 * @param path The d-bus path of the interface to add.
 * @param name The name of the interface.
 * @return int 0 if the interface was added for monitoring, non-zero otherwise.
 */
static int
wpas_interface_add(struct ztp_wpa_supplicant *wpas, const char *path, const char *name)
{
    zlog_info_if(name, "arrived on %s", path);

    // Create new interface entry for this path.
    struct wpa_supplicant_interface_entry *entry = wpa_supplicant_interface_entry_initialize(path, name);
    if (!entry) {
        zlog_error_if(name, "failed to allocate memory for new interface entry");
        return -ENOMEM;
    }

    // Add the new interface to the tracking list.
    list_add(&entry->list, &wpas->interfaces);
    invoke_interface_presence_changed_callbacks(wpas, ZTP_INTERFACE_ARRIVED, name, path);

    return 0;
}

/**
 * @brief Generic wpa_supplicant interface added handler. This will be
 * invoked whenever wpa_supplicant begins monitoring a new interface. This
 * callback will dispatch the relevant information to the registered callback
 * in ztpd.
 *
 * @param msg The sd-bus message describing the InterfaceAdded signal.
 * @param userdata The user context that will be passed to the ztpd caback.
 * @param ret_error An sd-bus proxy for the return value. Unused.
 * @return int The result of the opertation. 0 if successful, otherwise
 * non-zero error value.
 */
static int
wpas_interface_added(sd_bus_message *msg, void *userdata, sd_bus_error *ret_error)
{
    __unused(ret_error);

    char *name = NULL;
    char *path = NULL;
    struct ztp_wpa_supplicant *wpas = (struct ztp_wpa_supplicant *)userdata;

    // Read the interface object path.
    int ret = sd_bus_message_read(msg, "o", &path);
    if (ret < 0) {
        zlog_error("failed reading InterfaceAdded 'interface' property (%d)", ret);
        return ret;
    }

    // Read the interface name.
    sd_bus_error error = SD_BUS_ERROR_NULL;
    ret = sd_bus_get_property_string(wpas->bus,
        WPAS_DBUS_SERVICE,
        path,
        WPAS_DBUS_INTERFACE,
        "Ifname",
        &error,
        &name);
    if (ret < 0) {
        zlog_error("failed to retrieve 'Ifname' property (%d)", ret);
        return ret;
    }

    ret = wpas_interface_add(wpas, path, name);
    if (ret < 0) {
        zlog_error_if(name, "failed to add new interface (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Remove an interface from the interface list. Following the call, the
 * interface will no longer be monitored.
 *
 * @param wpas The wpa supplicant instance.
 * @param path The d-bus path of the interface to remove.
 */
static void
wpas_interface_remove(struct ztp_wpa_supplicant *wpas, const char *path)
{
    struct wpa_supplicant_interface_entry *entry = find_interface_entry_by_path(wpas, path);
    const char *interface = entry ? entry->name : "<unknown>";
    zlog_info_if(interface, "departed from %s", path);

    invoke_interface_presence_changed_callbacks(wpas, ZTP_INTERFACE_DEPARTED, interface, path);
    wpa_supplicant_interface_entry_uninitialize(entry);
}

/**
 * @brief Generic wpa_supplicant interface removed handler. This will be
 * invoked whenever wpa_supplicant is no longer monitoring a particular
 * interface. This callback will dispatch the relevant information to the
 * registered callback in ztpd.
 *
 * @param msg The sd-bus message describing the InterfaceRemoved signal.
 * @param userdata The user context that will be passed to the ztpd caback.
 * @param ret_error An sd-bus proxy for the return value. Unused.
 * @return int The result of the opertation. 0 if successful, otherwise
 * non-zero error value.
 */
static int
wpas_interface_removed(sd_bus_message *msg, void *userdata, sd_bus_error *ret_error)
{
    __unused(ret_error);

    struct ztp_wpa_supplicant *wpas = (struct ztp_wpa_supplicant *)userdata;

    char *path = NULL;
    int ret = sd_bus_message_read(msg, "o", &path);
    if (ret < 0) {
        zlog_error("failed reading InterfaceRemoved interface property (%d)", ret);
        return ret;
    }

    wpas_interface_remove(wpas, path);
    return 0;
}

/**
 * @brief Enumerates and processes the current interfaces being controlled by
 * wpa_supplicant. Each interface will be added for monitoring for zero touch
 * provisioning.
 *
 * Note that in future, the decision to include an interface for ZTP will be
 * controlled by a configuration file option.
 *
 * @param wpas The wpa_supplicant instance to use.
 * @return int The result of the operation. 0 if successful, otherwise a
 * non-zero error value.
 */
static int
process_current_interfaces(struct ztp_wpa_supplicant *wpas)
{
    sd_bus_message *msg;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret = sd_bus_get_property(wpas->bus,
        WPAS_DBUS_SERVICE,
        WPAS_DBUS_SERVICE_PATH,
        WPAS_DBUS_SERVICE,
        "Interfaces",
        &error,
        &msg,
        "ao");
    if (ret < 0) {
        zlog_error("failed to retrieve 'Interfaces' property value (%d)", ret);
        return ret;
    }

    ret = sd_bus_message_enter_container(msg, SD_BUS_TYPE_ARRAY, "o");
    if (ret < 0) {
        zlog_error("unable to enter 'Interfaces' array' (%d)", ret);
        goto out;
    }

    {
        char *path = NULL;
        for (;;) {
            ret = sd_bus_message_read(msg, "o", &path);
            if (ret == 0) {
                break;
            } else if (ret < 0) {
                zlog_error("failed reading interface element (%d)", ret);
                goto out;
            }

            char *name = NULL;
            ret = sd_bus_get_property_string(wpas->bus,
                WPAS_DBUS_SERVICE,
                path,
                WPAS_DBUS_INTERFACE,
                "Ifname",
                &error,
                &name);
            if (ret < 0) {
                zlog_error("failed to retrieve 'Ifname' property (%d)", ret);
                goto out;
            }

            ret = wpas_interface_add(wpas, path, name);
            if (ret < 0) {
                zlog_error_if(name, "failed to add new interface entry (%d)", ret);
            }

            free(name);
        }
    }

    sd_bus_message_exit_container(msg);

out:
    sd_bus_message_unref(msg);
    return ret;
}

/**
 * @brief Resets the known interface list such that none are known.
 *
 * @param wpas The wpa_supplicant instance.
 */
static void
reset_interface_list(struct ztp_wpa_supplicant *wpas)
{
    // Invoke removed handler for all known interfaces, then delete them.
    struct wpa_supplicant_interface_entry *interface;
    struct wpa_supplicant_interface_entry *tmp;
    list_for_each_entry_safe (interface, tmp, &wpas->interfaces, list) {
        invoke_interface_presence_changed_callbacks(wpas, ZTP_INTERFACE_DEPARTED, interface->path, interface->name);
        wpa_supplicant_interface_entry_uninitialize(interface);
    }
}

/**
 * @brief Handler function for when the wpa_supplicant d-bus service arrives on
 * the bus.
 *
 * @param wpas The wpa_supplicant instance.
 */
static void
on_service_arrived(struct ztp_wpa_supplicant *wpas)
{
    zlog_info(WPAS_DBUS_SERVICE_PATH " service arrived on d-bus");
    process_current_interfaces(wpas);
}

/**
 * @brief Handler function for when the wpa_supplicant d-bus service departs
 * from the bus (eg. crash or manual stop).
 *
 * @param wpas The wpa_supplicant instance.
 */
static void
on_service_departed(struct ztp_wpa_supplicant *wpas)
{
    zlog_info(WPAS_DBUS_SERVICE_PATH " service departed d-bus");
    reset_interface_list(wpas);
}

/**
 * @brief Handler function to respond to the NameOwnerChanged signal for the
 * wpa_supplicant service. This callback will be invoked each time the owner of
 * the wpa_supplicant service name changes. This occurs when the daemon claims
 * the name (when it starts up) and when it releases the name (when it stops
 * running or crashes).
 *
 * See https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-name-owner-changed
 * for more details.
 *
 * @param msg The message containing the signal change data.
 * @param userdata User context associated with the callback. In this case,
 * this will always be the wpa_supplicant instance that was used to register
 * this signal handler.
 * @param error Pointer to pass back any errors to the signal generator. Unused.
 * @return int The result of the operation. 0 if successful, non-zero otherwise.
 */
static int
wpas_service_availability_changed(sd_bus_message *msg, void *userdata, sd_bus_error *error)
{
    __unused(error);

    struct ztp_wpa_supplicant *wpas = (struct ztp_wpa_supplicant *)userdata;

    // Read service name argument.
    const char *name;
    int ret = sd_bus_message_read_basic(msg, SD_BUS_TYPE_STRING, &name);
    if (ret < 0) {
        zlog_error("failed to read service name for NameOwnerChanged (%d)", ret);
        return ret;
    }

    // Read old owner name.
    const char *owner_old;
    ret = sd_bus_message_read_basic(msg, SD_BUS_TYPE_STRING, &owner_old);
    if (ret < 0) {
        zlog_error("failed to read 'old_owner' property of NameOwnerChanged (%d)", ret);
        return ret;
    }

    // Read new owner name.
    const char *owner_new;
    ret = sd_bus_message_read_basic(msg, SD_BUS_TYPE_STRING, &owner_new);
    if (ret < 0) {
        zlog_error("failed to read 'new_owner' property of NameOwnerChanged (%d)", ret);
        return ret;
    }

    zlog_debug("%s NameOwnerChanged '%s' -> '%s'", name, owner_old, owner_new);

    // When there was no previous owner, the service has arrived on the bus.
    if (strcmp(owner_old, "") == 0) {
        on_service_arrived(wpas);
        return 0;
    }

    // When the new owner is empty, the service has departed from the bus.
    if (strcmp(owner_new, "") == 0) {
        on_service_departed(wpas);
        return 0;
    }

    zlog_warning("%s NameOwnerChanged state unexpected", name);
    return 0;
}

/**
 * @brief Fixed match rule that triggers on NameOwnerChanged signals where the
 * first argument (service name) is equal to that of the wpa_supplicant
 * service. This allows us to detect when the wpa_supplicant service arrives
 * and departs the d-bus system bus.
 */
#define WPA_SUPPLICANT_MATCH_NAME_OWNER_CHANGED    \
    "type='signal',"                               \
    "interface='" DBUS_GLOBAL_SERVICE "',"         \
    "member='" DBUS_GLOBAL_NAME_OWNER_CHANGED "'," \
    "arg0='" WPAS_DBUS_SERVICE "'"

/**
 * @brief Initializes the wpa_supplicant related facilities.
 *
 * @param wpas A pointer to the structure to initialize.
 * @return int The result of the operation. 0 if successful, otherwise a non-zero error value.
 */
int
ztp_wpa_supplicant_initialize(struct ztp_wpa_supplicant *wpas)
{
    int ret;

    INIT_LIST_HEAD(&wpas->interfaces);
    INIT_LIST_HEAD(&wpas->interface_presence_changed);

    // Establish bus connection.
    ret = sd_bus_default_system(&wpas->bus);
    if (ret < 0) {
        zlog_error("failed to open system bus (%d)", -ret);
        goto fail;
    }

    // Register for signals we're interested in.
    ret = sd_bus_match_signal(wpas->bus, &wpas->slot_interface_added,
        WPAS_DBUS_SERVICE,      // sender
        WPAS_DBUS_SERVICE_PATH, // path
        WPAS_DBUS_SERVICE,      // interface
        "InterfaceAdded",       // member
        wpas_interface_added,   // callback
        wpas);                  // userdata
    if (ret < 0) {
        zlog_error("failed to register handler for InterfaceAdded signal (%d)", ret);
        goto fail;
    }

    ret = sd_bus_match_signal(wpas->bus, &wpas->slot_interface_removed,
        WPAS_DBUS_SERVICE,      // sender
        WPAS_DBUS_SERVICE_PATH, // path
        WPAS_DBUS_SERVICE,      // interface
        "InterfaceRemoved",     // member
        wpas_interface_removed, // callback
        wpas);                  // userdata
    if (ret < 0) {
        zlog_error("failed to register handler for InterfaceAdded signal (%d)", ret);
        goto fail;
    }

    ret = sd_bus_add_match(wpas->bus, &wpas->slot_service_availability, WPA_SUPPLICANT_MATCH_NAME_OWNER_CHANGED, wpas_service_availability_changed, wpas);
    if (ret < 0) {
        zlog_error("failed to register handler for wpa_supplicant service name ownership changes (%d)", ret);
        goto fail;
    }

    // Since we're init'ing, assume the service is up.
    on_service_arrived(wpas);

out:
    return ret;
fail:
    ztp_wpa_supplicant_uninitialize(wpas);
    goto out;
}

/**
 * @brief Uninitializes a ztpd_wpa_supplicant instance.
 *
 * @param wpas The instance to uninitialize.
 */
void
ztp_wpa_supplicant_uninitialize(struct ztp_wpa_supplicant *wpas)
{
    if (wpas->interfaces.next != NULL)
        reset_interface_list(wpas);

    if (wpas->slot_interface_added != NULL) {
        sd_bus_slot_unref(wpas->slot_interface_added);
        wpas->slot_interface_added = NULL;
    }

    if (wpas->slot_interface_removed != NULL) {
        sd_bus_slot_unref(wpas->slot_interface_removed);
        wpas->slot_interface_removed = NULL;
    }

    if (wpas->slot_service_availability != NULL) {
        sd_bus_slot_unref(wpas->slot_service_availability);
        wpas->slot_service_availability = NULL;
    }

    if (wpas->bus) {
        sd_bus_unref(wpas->bus);
        wpas->bus = NULL;
    }
}

/**
 * @brief Retrieves the 'State' property of the
 * 'fi.w1.wpa_supplicant1.Interface' d-bus interface of the object referred to
 * by 'path'.
 * 
 * @param wpas The wpa_supplicant instance.
 * @param path The path of the object which implements the interface.
 * @param state Output argument that will receive the interface state.
 * @return int 0 if the operation succeeded, non-zero otherwise.
 */
int
ztp_wpa_supplicant_get_interface_state(struct ztp_wpa_supplicant *wpas, const char *path, enum wpas_interface_state *state)
{
    char *statestr;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret = sd_bus_get_property_string(wpas->bus,
        WPAS_DBUS_SERVICE,
        path,
        WPAS_DBUS_INTERFACE,
        "State",
        &error,
        &statestr);
    if (ret < 0) {
        zlog_error("failed to retrieve interface 'State' property (%d)", ret);
        return ret;
    }

    *state = parse_wpas_interface_state(statestr);
    free(statestr);

    return 0;
}

/**
 * @brief Returns the number of networks configured for the specified interface.
 *
 * @param wpas The wpa_supplicant instance.
 * @param path The path of the object which implements the wpa_supplicant 'Interface' interface.
 * @param count Output argument to hold the number of networks.
 * @return int 0 if the operation was successful. *count will contain the
 * number of networks. Otherwise a non-zero error value is returned and *count
 * is undefined.
 */
int
ztp_get_interface_network_count(struct ztp_wpa_supplicant *wpas, const char *path, uint32_t *count)
{
    *count = 0;

    sd_bus_message *msg;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret = sd_bus_get_property(wpas->bus,
        WPAS_DBUS_SERVICE,
        path,
        WPAS_DBUS_INTERFACE,
        "Networks",
        &error,
        &msg,
        "ao");
    if (ret < 0) {
        zlog_error("failed to retrieve 'Networks' property value (%d)", ret);
        return ret;
    }

    ret = sd_bus_message_enter_container(msg, SD_BUS_TYPE_ARRAY, "o");
    if (ret < 0) {
        zlog_error("unable to enter 'Networks' array' (%d)", ret);
        goto out;
    }

    {
        // Just count the number of entries (no need to read them).
        while ((ret = sd_bus_message_skip(msg, "o")) > 0)
            (*count)++;
    }

    sd_bus_message_exit_container(msg);

out:
    sd_bus_message_unref(msg);
    return ret;
}

/**
 * @brief Registers a handler for the interface added event.
 *
 * @param wpas The wpa supplicant instance.
 * @param handler The handler function to invoke when interface presence changes.
 * @param userdata The context to be passed to the handler function.
 * @return int 0 if successful, non-zero otherwise.
 */
int
ztp_wpa_supplicant_register_interface_presence_changed_callback(struct ztp_wpa_supplicant *wpas, interface_presence_changed_fn handler, void *userdata)
{
    struct interface_presence_changed_callback *callback = malloc(sizeof *callback);
    if (!callback) {
        zlog_error("failed to allocate memory for interface presence changed callback");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&callback->list);
    callback->handler = handler;
    callback->userdata = userdata;
    list_add(&callback->list, &wpas->interface_presence_changed);

    // Manually invoke callback with all known present interfaces.
    struct wpa_supplicant_interface_entry *interface;
    list_for_each_entry (interface, &wpas->interfaces, list) {
        invoke_interface_presence_changed_callback(callback, ZTP_INTERFACE_ARRIVED, interface->name, interface->path);
    }

    return 0;
}

/**
 * @brief Unregisters an interface presence changed handler.
 * 
 * @param wpas The wpa supplicant instance.
 * @param handler The handler function that was previously registered.
 * @param userdata The context previously associated with the handler function.
 */
void
ztp_wpa_supplicant_unregister_interface_presence_changed_callback(struct ztp_wpa_supplicant *wpas, interface_presence_changed_fn handler, void *userdata)
{
    struct interface_presence_changed_callback *callback;

    list_for_each_entry (callback, &wpas->interface_presence_changed, list) {
        if (callback->handler == handler && callback->userdata == userdata) {
            list_del(&callback->list);
            free(callback);
            break;
        }
    }
}

/**
 * @brief Looks up a d-bus interface path, given its name.
 * 
 * @param wpas The wpa supplicant instance.
 * @param interface The name of the interface to lookup the d-bus path.
 * @param path An output pointer to hold the d-bus path, if it exists. In this
 * case, the caller owns the memory associated with the path which can be
 * released by passing it to free().
 * @return int 0 if the d-bus path was retrieved and written to *path. -ENOENT
 * is returned if wpa asupplicant is not aware of the specified interface.
 * Otherwise a non-zero value is returned.
 */
int
ztp_wpa_supplicant_get_interface_path(struct ztp_wpa_supplicant *wpas, const char *interface, char **path)
{
    sd_bus_message *reply;
    sd_bus_error error = SD_BUS_ERROR_NULL;

    int ret = sd_bus_call_method(wpas->bus,
        WPAS_DBUS_SERVICE,
        WPAS_DBUS_SERVICE_PATH,
        WPAS_DBUS_SERVICE,
        "GetInterface",
        &error,
        &reply,
        "s",
        interface);
    if (ret == -ENOENT) {
        zlog_debug_if(interface, "not monitored by wpa_supplicant, no d-bus path available");
        return ret;
    } else if (ret < 0) {
        zlog_error("failed to invoke 'GetInterface' wpa_supplicant method (%d)", ret);
        return ret;
    }

    const char *object_path = NULL;
    ret = sd_bus_message_read_basic(reply, SD_BUS_TYPE_OBJECT_PATH, &object_path);
    if (ret < 0) {
        zlog_error("failed to read 'GetInterface' reply string (%d)", ret);
        return ret;
    }

    *path = strdup(object_path);
    if (!*path) {
        zlog_error("failed to allocate memory for d-bus interface path");
        return -ENOMEM;
    }

    return 0;
}
