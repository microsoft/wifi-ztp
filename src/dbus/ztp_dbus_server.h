
#ifndef __ZTP_DBUS_SERVER_H__
#define __ZTP_DBUS_SERVER_H__

#include <stdint.h>

#include <systemd/sd-bus.h>
#include <userspace/linux/list.h>

struct ztp_settings;
struct ztp_dbus_network_manager;

/**
 * @brief Maximum length of a complete d-bus path, as used by ztpd.
 */
#define ZTP_DBUS_MAX_PATH 512

/**
 * @brief Macros to help construct child paths and interfaces.
 */
#define ZTP_DBUS_CHILD_PATH(b, p) b "/" p
#define ZTP_DBUS_CHILD_INTERFACE(b, p) b "." p

/**
 * @brief Well-known ztpd d-bus server path and interfaces. The
 * server interface name is also used as the well known service name.
 */
#define ZTP_DBUS_SERVER_PATH "/com/microsoft/ztp1"
#define ZTP_DBUS_SERVER_INTERFACE "com.microsoft.ztp1"

/**
 * @brief Macros to help construct ztp service child paths and interfaces.
 */
#define ZTP_DBUS_SERVER_CHILD_PATH(p) ZTP_DBUS_CHILD_PATH(ZTP_DBUS_SERVER_PATH, p)
#define ZTP_DBUS_SERVER_CHILD_INTERFACE(i) ZTP_DBUS_CHILD_INTERFACE(ZTP_DBUS_SERVER_INTERFACE, i)

/**
 * @brief d-bus server control structure.
 */
struct ztp_dbus_server {
    sd_bus *bus;
    sd_bus_slot *slot_vtable;
    struct list_head configurators;
    struct ztp_settings *settings;
    struct ztp_device_role_settings *settings_configurator;
    struct ztp_dbus_network_configuration_manager *network_configuration_manager;
    struct ztp_dbus_network_configuration *network_configuration_default;
    uint32_t configurator_id_next;
};

/**
 * @brief Initializes a d-bus server on the specified bus.
 *
 * This will initialize all ztpd d-bus related server objects and services and
 * register them on the specified bus. The dbus-daemon proxy is used as the
 * messgage broker, so must be present on the system.

 * This does not handle processing of messages destined for these objects and
 * services. Message processing must be done externally in a message loop or
 * through the use of higher-level d-bus message processing. Messages for these
 * objctes and services can be processed by calling sd_bus_process(). It is
 * expected that the ztpd main event loop does this.
 *
 * Appropriate access control and authorization is not enforced. This is
 * expected to be performned by the dbus-daemon, which picks up settings
 * from distribution specific configuration files (eg. /etc/dbus-1/system.d).

 * @param server The server structure to initialize.
 * @param settings The settings associated with the service.
 * @param network_configuration_manager A network confiuration manager
 * instance. This instance must be valid for the lifetime of the d-bus server.
 * @param path The dbus path to register the service.
 * @return int 0 if the d-bus server was successfully initialized, non-zero
 * otherwise.
 */
int
ztp_dbus_server_initialize(struct ztp_dbus_server *server, struct ztp_settings *settings, struct ztp_dbus_network_configuration_manager *network_configuration_manager, const char *path);

/**
 * @brief Uninitializes a previously initialized d-bus server.
 *
 * @param server The server control structure that was previously filled in by
 * ztp_dbus_server_initialize.
 */
void
ztp_dbus_server_uninitialize(struct ztp_dbus_server *server);

/**
 * @brief Updates the current settings instance.
 * 
 * @param server The server control structure to update.
 * @param settings The new settings instance to use.
 */
void
ztp_dbus_server_update_settings(struct ztp_dbus_server *server, struct ztp_settings *settings);

#endif //__ZTP_DBUS_SERVER_H__
