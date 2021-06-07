
#ifndef __ZTP_DBUS_CLIENT_H__
#define __ZTP_DBUS_CLIENT_H__

#include <systemd/sd-bus.h>
#include <userspace/linux/list.h>

#include "ztp_wpa_supplicant.h"

struct event_loop;

/**
 * @brief Callback prototype for PropertyChanged handlers.
 */
typedef void (*ztp_dbus_properties_changed_handler)(sd_bus_message *, const char *, void *);

/**
 * @brief Opaque handle for tracking PropertyChanged handlers.
 * Full definition is in ztp_dbus_client.c.
 */
struct ztp_dbus_properties_changed_handle;

/**
 * @brief Event control interface for d-bus connections. Primarily used to
 * interface with wpa_supplicant using sd-bus.
 */
struct ztp_dbus_client {
    sd_bus *bus;
    int fd;
    struct event_loop *loop;
    struct list_head property_changed_handles;
};

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
ztp_dbus_register_properties_changed_handler(struct ztp_dbus_client *dbus, const char *interface, void *userdata, ztp_dbus_properties_changed_handler handler, struct ztp_dbus_properties_changed_handle **handle);

/**
 * @brief Unregisters a property changed handler from ztpd.
 *
 * @param handle The handle to unregister. Must have been obtained from
 * ztp_dbus_register_properties_changed_handler().
 */
void
ztp_dbus_unregister_properties_changed_handler(struct ztp_dbus_properties_changed_handle *handle);

/**
 * @brief Initializes an instance of a dbus connector.
 *
 * @param dbus The instance to initialize.
 * @param loop The ztp event loop to run the dbus connection on.
 * @return int 0 initialized successfuly, non-zero otherwise.
 */
int
ztp_dbus_initialize(struct ztp_dbus_client *dbus, struct event_loop *loop);

/**
 * @brief Uninitializes a dbus connector instance.
 *
 * @param dbus The instance to uninitialize.
 */
void
ztp_dbus_uninitialize(struct ztp_dbus_client *dbus);

#endif //__ZTP_DBUS_CLIENT_H__
