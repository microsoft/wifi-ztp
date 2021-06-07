
#ifndef __ZTP_DBUS_NETWORK_CONFIGURATION_H__
#define __ZTP_DBUS_NETWORK_CONFIGURATION_H__

#include "ztp_dbus_server.h"

/**
 * @brief Dpp network dbus name, path, and interface definitions.
 */
#define ZTP_DBUS_NETWORK_CONFIGURATION_NAME "DppNetworkConfiguration"
#define ZTP_DBUS_NETWORK_INTERFACE ZTP_DBUS_SERVER_CHILD_INTERFACE(ZTP_DBUS_NETWORK_CONFIGURATION_NAME)
#define ZTP_DBUS_NETWORK_CHILD_INTERFACE(i) ZTP_DBUS_CHILD_INTERFACE(ZTP_DBUS_NETWORK_INTERFACE, i)

/**
 * @brief d-bus network configuration object entry.
 */
struct ztp_dbus_network_configuration {
    struct list_head list;
    struct list_head credentials;
    struct dpp_network *network;
    sd_bus *bus;
    sd_bus_slot *slot;
    uint32_t id;
    uint32_t credential_id_next;
    char path[];
};

/**
 * @brief Dpp network credentials dbus name, path, and interface definitions.
 */
#define ZTP_DBUS_NETWORK_DPP_CREDENTIAL_NAME "DppCredential"
#define ZTP_DBUS_NETWORK_DPP_CREDENTIAL_INTERFACE ZTP_DBUS_NETWORK_CHILD_INTERFACE(ZTP_DBUS_NETWORK_DPP_CREDENTIAL_NAME)
#define ZTP_DBUS_NETWORK_DPP_CREDENTIAL_CHILD_INTERFACE(i) ZTP_DBUS_CHILD_INTERFACE(ZTP_DBUS_NETWORK_DPP_CREDENTIAL_INTERFACE, i)

/**
 * @brief d-bus dpp network credential object entry.
 */
struct ztp_dbus_dpp_credential {
    struct list_head list;
    struct dpp_network_credential *credential;
    sd_bus *bus;
    sd_bus_slot *slot;
    sd_bus_slot *slot_child;
    uint32_t id;
    char path[];
};

/**
 * @brief Dpp network credential interface types.
 */
#define ZTP_DBUS_NETWORK_DPP_CREDENTIAL_PSK_NAME "Psk"
#define ZTP_DBUS_NETWORK_DPP_CREDENTIAL_PSK_INTERFACE ZTP_DBUS_NETWORK_DPP_CREDENTIAL_CHILD_INTERFACE(ZTP_DBUS_NETWORK_DPP_CREDENTIAL_PSK_NAME)
#define ZTP_DBUS_NETWORK_DPP_CREDENTIAL_SAE_NAME "Sae"
#define ZTP_DBUS_NETWORK_DPP_CREDENTIAL_SAE_INTERFACE ZTP_DBUS_NETWORK_DPP_CREDENTIAL_CHILD_INTERFACE(ZTP_DBUS_NETWORK_DPP_CREDENTIAL_SAE_NAME)

/**
 * @brief d-bus interface name for the network profile manager.
 */
#define ZTP_DBUS_SERVER_NETWORK_CONFIGURATION_MANAGER_NAME "NetworkConfigurationManager"
#define ZTP_DBUS_SERVER_NETWORK_CONFIGURATION_MANAGER_INTERFACE ZTP_DBUS_SERVER_CHILD_INTERFACE(ZTP_DBUS_SERVER_NETWORK_CONFIGURATION_MANAGER_NAME)

/**
 * @brief d-bus network configuration manager. Manages all network
 * configuration d-bus objects.
 */
struct ztp_dbus_network_configuration_manager {
    struct list_head networks;
    uint32_t network_id_next;
    sd_bus *bus;
    sd_bus_slot *slot_vtable;
    char path[];
};

/**
 * @brief Registers a network with the specified configurator.
 *
 * @param manager The d-bus manager object associated with the network.
 * @param network The network to add. The caller is responsible for ensuring
 * this object remains valid for the lifetime of the parent object, or until
 * ztp_dbus_network_configuration_manager_unregister is called.
 * @param entryp Optional output argument to hold the allocated d-bus entry object.
 *
 * @return int 0 if the network was successfully added, non-zero otherwise.
 */
int
ztp_dbus_network_configuration_manager_register(struct ztp_dbus_network_configuration_manager *manager, struct dpp_network *network, struct ztp_dbus_network_configuration **entryp);

/**
 * @brief Unregisters a network from its parent d-bus configurator object.
 *
 * @param pnetwork Pointer to the network to remove. Referenced memory will be
 * set to NULL, so this pointer must not be used following this call.
 */
void
ztp_dbus_network_configuration_manager_unregister(struct ztp_dbus_network_configuration **pnetwork);

/**
 * @brief Creates and initializes a d-bus network configuration manager.
 * 
 * @param manager An output pointer to receive the newly created manager.
 * @param path The base d-bus path the manager will own.
 * @return int 0 if the manager was successfully initialized, non-zero otherwise.
 */
int
ztp_dbus_network_configuration_manager_create(struct ztp_dbus_network_configuration_manager **manager, const char *path);

/**
 * @brief Uninitializes and destroys a d-bus network configuration manager.
 * This will de-register all known d-bus network configuration objects from the
 * bus.
 * 
 * @param manager The manager to uninitialize and destroy.
 */
void
ztp_dbus_network_configuration_manager_destroy(struct ztp_dbus_network_configuration_manager **manager);

#endif //__ZTP_DBUS_NETWORK_CONFIGURATION_H__
