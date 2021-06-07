
#ifndef __ZTP_DBUS_CONFIGURATOR_H__
#define __ZTP_DBUS_CONFIGURATOR_H__

#include "ztp_dbus_server.h"

struct ztp_configurator;

/**
 * @brief Configurator dbus name, path, and interface definitions.
 */
#define ZTP_DBUS_CONFIGURATOR_NAME "Configurator"
#define ZTP_DBUS_CONFIGURATOR_PATH ZTP_DBUS_SERVER_CHILD_PATH(ZTP_DBUS_CONFIGURATOR_NAME)
#define ZTP_DBUS_CONFIGURATOR_INTERFACE ZTP_DBUS_SERVER_CHILD_INTERFACE(ZTP_DBUS_CONFIGURATOR_NAME)

/**
 * @brief Macro to help construct configurator child interfaces.
 */
#define ZTP_DBUS_CONFIGURATOR_CHILD_INTERFACE(i) ZTP_DBUS_CHILD_INTERFACE(ZTP_DBUS_CONFIGURATOR_INTERFACE, i)

/**
 * @brief Bootstrap info provider dbus name and interface definitions.
 */
#define ZTP_DBUS_CONFIGURATOR_BIP_NAME "BootstrapInfoProvider"
#define ZTP_DBUS_CONFIGURATOR_BIP_FILE_NAME "File"
#define ZTP_DBUS_CONFIGURATOR_BIP_AZUREDPS_NAME "AzureDps"
#define ZTP_DBUS_CONFIGURATOR_BIP_INTERFACE ZTP_DBUS_CONFIGURATOR_CHILD_INTERFACE(ZTP_DBUS_CONFIGURATOR_BIP_NAME)

/**
 * @brief Macro to help constructor bootstrap info provider child interface definitions.
 */
#define ZTP_DBUS_CONFIGURATOR_BIP_CHILD_INTERFACE(i) ZTP_DBUS_CHILD_INTERFACE(ZTP_DBUS_CONFIGURATOR_BIP_INTERFACE, i)

/**
 * @brief Bootstrap info provider derivative dbus name and interface definitions.
 */
#define ZTP_DBUS_CONFIGURATOR_BIP_FILE_INTERFACE ZTP_DBUS_CONFIGURATOR_BIP_CHILD_INTERFACE(ZTP_DBUS_CONFIGURATOR_BIP_FILE_NAME)
#define ZTP_DBUS_CONFIGURATOR_BIP_AZUREDPS_INTERFACE ZTP_DBUS_CONFIGURATOR_BIP_CHILD_INTERFACE(ZTP_DBUS_CONFIGURATOR_BIP_AZUREDPS_NAME)

/**
 * @brief d-bus configurator object entry.
 */
struct ztp_dbus_configurator {
    struct list_head list;
    struct list_head bips;
    struct list_head networks;
    struct ztp_configurator *configurator;
    struct ztp_dbus_server *server;
    sd_bus *bus;
    sd_bus_slot *slot;
    uint32_t id;
    uint32_t bip_id_next;
    uint32_t network_id_next;
    char path[];
};

/**
 * @brief Registers a configurator with d-bus.
 *
 * @param server The d-bus server to register the configurator with.
 * @param configurator The configurator to register. The caller is responsible
 * for ensuring that the provided pointer is valid for the lifetime of the
 * d-bus object, or, until ztp_dbus_configurator unregister is called with the
 * same pointer.
 * @return int 0 if registration was successful, non-zero otherwise.
 */
int
ztp_dbus_configurator_register(struct ztp_dbus_server *server, struct ztp_configurator *configurator);

/**
 * @brief Unregisters a configurator from d-bus, removing its d-bus object and all its children from the bus.
 *
 * @param server The server the configurator was registered with.
 * @param configurator The configurator instance associated with the bus object.
 * @return int 0 if the configurator was unregisters, -ENOENT if the specified
 * configurator was not previously registered with the bus, and non-zero
 * otherwise.
 */
int
ztp_dbus_configurator_unregister(struct ztp_dbus_server *server, struct ztp_configurator *configurator);

#endif //__ZTP_DBUS_CONFIGURATOR_H__
