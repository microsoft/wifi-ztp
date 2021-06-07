
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <userspace/linux/compiler.h>

#include "dbus_message_helpers.h"
#include "dpp.h"
#include "ztp_dbus_configurator.h"
#include "ztp_dbus_network_configuration.h"
#include "ztp_log.h"

/**
 * @brief Property getter function for the 'Passphrase' property of DppCredential.Sae objects.
 * 
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.DppCredential.Sae".
 * @param property The name of the property. Must be "Properties".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type 'struct dpp_network_credential_sae'.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_dpp_credential_sae_get_passphrase(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct dpp_network_credential_sae *sae = (struct dpp_network_credential_sae *)userdata;

    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, sae->passphrase);
    if (ret < 0) {
        zlog_error("failed to append sae credential passphrase (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Virtual function table describing methods, properties and signals of
 * a ztp d-bus dpp network credential.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_dpp_credential_sae[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Passphrase", "s", ztp1_dpp_credential_sae_get_passphrase, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END,
};

/**
 * @brief Property getter function for the 'Properties' property of DppCredential.Psk objects.
 * 
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.DppCredential.Psk".
 * @param property The name of the property. Must be "Properties".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type 'struct dpp_network_credential_psk'.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_dpp_credential_psk_get_properties(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct dpp_network_credential_psk *psk = (struct dpp_network_credential_psk *)userdata;

    int ret = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "{sv}");
    if (ret < 0) {
        zlog_error("failed to open psk network credential dictionary array container (%d)", ret);
        return ret;
    }

    {
        switch (psk->type) {
            case PSK_CREDENTIAL_TYPE_PASSPHRASE: {
                ret = dbus_append_dict_entry_string(reply, "Passphrase", psk->passphrase.ascii);
                if (ret < 0) {
                    zlog_error("failed to append psk credential passphrase (%d)", ret);
                    return ret;
                }
                break;
            }
            case PSK_CREDENTIAL_TYPE_PSK: {
                ret = dbus_append_dict_entry_string(reply, "Psk", psk->key.hex);
                if (ret < 0) {
                    zlog_error("failed tp append psk credential key (%d)", ret);
                    return ret;
                }
                break;
            }
            default:
                break;
        }
    }

    ret = sd_bus_message_close_container(reply);
    if (ret < 0) {
        zlog_error("failed to close psk credential dictionary container (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Virtual function table describing methods, properties and signals of
 * a ztp d-bus dpp network credential.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_dpp_credential_psk[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Properties", "a{sv}", ztp1_dpp_credential_psk_get_properties, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END,
};

/**
 * @brief Property getter function for the 'Akm' property of DppCredential objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.DppCredential".
 * @param property The name of the property. Must be "Akm".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type 'struct dpp_network_credential'.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_dpp_credential_get_type(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct dpp_network_credential *credential = (struct dpp_network_credential *)userdata;

    const char *akm = dpp_akm_str(credential->akm);
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, akm);
    if (ret < 0)
        zlog_warning("failed to add akm %s to reply message (%d)", akm, ret);

    return ret;
}

/**
 * @brief Virtual function table describing methods, properties and signals of
 * a ztp d-bus dpp network credential.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_dpp_credential[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Akm", "s", ztp1_dpp_credential_get_type, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END,
};

/**
 * @brief Removes a dpp network credential from a network object.
 *
 * @param credential The credential object to remove.
 */
static void
ztp_dbus_network_configuration_credential_remove(struct ztp_dbus_dpp_credential *obj)
{
    if (obj->slot)
        sd_bus_slot_unref(obj->slot);
    if (obj->slot_child)
        sd_bus_slot_unref(obj->slot_child);
    if (obj->bus)
        sd_bus_unref(obj->bus);
    if (obj->list.next != NULL && !list_empty(&obj->list))
        list_del(&obj->list);

    free(obj);
}

/**
 * @brief Adds a network credential to a network configuration d-bus object.
 *
 * @param entry The entry to add the credential to.
 * @param credential The credential to add.
 * @return int 0 if the credential was successully added, non-zero otherwise.
 */
static int
ztp_dbus_network_configuration_credential_add(struct ztp_dbus_network_configuration *network, struct dpp_network_credential *credential)
{
    char path[ZTP_DBUS_MAX_PATH];
    uint32_t id = network->credential_id_next++;
    int ret = snprintf(path, sizeof path, "%s/" ZTP_DBUS_NETWORK_DPP_CREDENTIAL_NAME "/%u", network->path, id);
    if (ret < 0) {
        zlog_error("failed to format dbus dpp network credential path");
        return -EINVAL;
    }

    size_t pathlength = (size_t)ret;
    assert(pathlength <= sizeof path);

    struct ztp_dbus_dpp_credential *entry = calloc(1, (sizeof *entry) + pathlength);
    if (!entry) {
        zlog_error("failed to allocate memory for dbus dpp network credential");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&entry->list);
    entry->id = id;
    entry->bus = network->bus;
    entry->credential = credential;
    memcpy(entry->path, path, pathlength);
    sd_bus_ref(entry->bus);

    ret = sd_bus_add_object_vtable(entry->bus, &entry->slot, entry->path, ZTP_DBUS_NETWORK_DPP_CREDENTIAL_INTERFACE, vtable_com_microsoft_ztp1_dpp_credential, credential);
    if (ret < 0) {
        zlog_error("failed to attach dpp network credential to d-bus (%d)", ret);
        ztp_dbus_network_configuration_credential_remove(entry);
        return ret;
    }

    switch (credential->akm) {
        case DPP_AKM_PSK: {
            ret = sd_bus_add_object_vtable(entry->bus, &entry->slot_child, entry->path, ZTP_DBUS_NETWORK_DPP_CREDENTIAL_PSK_INTERFACE, vtable_com_microsoft_ztp1_dpp_credential_psk, &credential->psk);
            if (ret < 0) {
                zlog_error("failed to attach dpp psk credential to d-bus (%d)", ret);
                ztp_dbus_network_configuration_credential_remove(entry);
                return ret;
            }
            break;
        }
        case DPP_AKM_SAE: {
            ret = sd_bus_add_object_vtable(entry->bus, &entry->slot_child, entry->path, ZTP_DBUS_NETWORK_DPP_CREDENTIAL_SAE_INTERFACE, vtable_com_microsoft_ztp1_dpp_credential_sae, &credential->sae);
            if (ret < 0) {
                zlog_error("failed to attach dpp sae credential to d-bus (%d)", ret);
                ztp_dbus_network_configuration_credential_remove(entry);
                return ret;
            }
            break;
        }
        default:
            break;
    }

    list_add(&entry->list, &network->credentials);

    return 0;
}

/**
 * @brief Property getter function for the 'WifiTechnology' property of NetworkConfiguration objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.NetworkConfiguration".
 * @param property The name of the property. Must be "WifiTechnology".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type 'struct dpp_network'.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_network_configuration_get_wifitech(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(userdata);
    __unused(ret_error);

    static const char infrastructure[] = "Infrastructure";

    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, infrastructure);
    if (ret < 0)
        zlog_warning("failed to add infrastructure %s to reply message (%d)", infrastructure, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'Ssid' property of NetworkConfiguration objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.NetworkConfiguration".
 * @param property The name of the property. Must be "Ssid".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type 'struct dpp_network'.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_network_configuration_get_ssid(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_network_configuration *entry = (struct ztp_dbus_network_configuration *)userdata;

    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, entry->network->discovery.ssid);
    if (ret < 0)
        zlog_warning("failed to add ssid to reply message (%d)", ret);

    return ret;
}

/**
 * @brief Retrieves an array network credentials.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.NetworkConfiguration".
 * @param property The name of the property. Must be "Credentials".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct dpp_network.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_network_configuration_get_credentials(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_network_configuration *network = (struct ztp_dbus_network_configuration *)userdata;

    int ret = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "o");
    if (ret < 0) {
        zlog_error("failed to open array container in reply message for 'Credentials' property (%d)", ret);
        return ret;
    }

    {
        struct ztp_dbus_dpp_credential *credential;
        list_for_each_entry (credential, &network->credentials, list) {
            ret = sd_bus_message_append(reply, "o", credential->path);
            if (ret < 0) {
                zlog_error("failed to append network credential to reply message (%d)", ret);
                continue;
            }
        }
    }

    ret = sd_bus_message_close_container(reply);
    if (ret < 0) {
        zlog_warning("failed to close array container in reply message for 'Configurators' property (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Virtual function table describing methods, properties and signals of
 * a ztp d-bus bootstrap information provider. All such providers are
 * associated with a com.microsoft.ztp1.Configurator d-bus object.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_network_configuration[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("WifiTechnology", "s", ztp1_network_configuration_get_wifitech, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Ssid", "s", ztp1_network_configuration_get_ssid, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Credentials", "ao", ztp1_network_configuration_get_credentials, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END,
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
ztp_dbus_network_configuration_manager_register(struct ztp_dbus_network_configuration_manager *manager, struct dpp_network *network, struct ztp_dbus_network_configuration **entryp)
{
    char path[ZTP_DBUS_MAX_PATH];
    uint32_t id = manager->network_id_next++;
    int ret = snprintf(path, sizeof path, "%s/Networks/%u", manager->path, id);
    if (ret < 0) {
        zlog_error("failed to format dbus dpp network configuration path");
        return -EINVAL;
    }

    size_t pathlength = (size_t)ret;
    assert(pathlength <= sizeof path);

    struct ztp_dbus_network_configuration *entry = calloc(1, (sizeof *entry) + pathlength);
    if (!entry) {
        zlog_error("failed to allocate memory for dbus dpp network configuration");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&entry->list);
    INIT_LIST_HEAD(&entry->credentials);
    entry->id = id;
    entry->bus = manager->bus;
    entry->network = network;
    memcpy(entry->path, path, pathlength);

    ret = sd_bus_add_object_vtable(entry->bus, &entry->slot, entry->path, ZTP_DBUS_NETWORK_INTERFACE, vtable_com_microsoft_ztp1_network_configuration, entry);
    if (ret < 0) {
        zlog_error("failed to attach dpp network credential to d-bus (%d)", ret);
        free(entry);
        return ret;
    }

    struct dpp_network_credential *credential;
    list_for_each_entry (credential, &network->credentials, list) {
        ret = ztp_dbus_network_configuration_credential_add(entry, credential);
        if (ret < 0) {
            zlog_warning("failed to add network credential to d-bus network object with id=%u (%d)", id, ret);
            continue;
        }
    }

    sd_bus_ref(entry->bus);
    list_add(&entry->list, &manager->networks);

    if (entryp)
        *entryp = entry;

    return 0;
}

/**
 * @brief Unregisters a network from its parent d-bus configurator object.
 *
 * @param network The network to remove.
 */
void
ztp_dbus_network_configuration_manager_unregister(struct ztp_dbus_network_configuration **pnetwork)
{
    if (!pnetwork || !*pnetwork)
        return;

    struct ztp_dbus_network_configuration *network = *pnetwork;
    struct ztp_dbus_dpp_credential *credential;
    struct ztp_dbus_dpp_credential *credentialtmp;

    list_for_each_entry_safe (credential, credentialtmp, &network->credentials, list) {
        ztp_dbus_network_configuration_credential_remove(credential);
    }

    if (network->slot)
        sd_bus_slot_unref(network->slot);
    if (network->bus)
        sd_bus_unref(network->bus);

    list_del(&network->list);
    free(network);

    *pnetwork = NULL;
}

/*
 * @brief Retrieves an array of network configuration objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.NetworkConfigurationManager".
 * @param property The name of the property. Must be "Networks".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct ztp_dbus_network_configuration_manager.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise
 */
static int
ztp1_network_manager_get_networks(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_network_configuration_manager *manager = (struct ztp_dbus_network_configuration_manager *)userdata;

    int ret = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "o");
    if (ret < 0) {
        zlog_error("failed to open reply message for 'Networks' property (%d)", ret);
        return ret;
    }

    {
        struct ztp_dbus_network_configuration *entry;
        list_for_each_entry (entry, &manager->networks, list) {
            ret = sd_bus_message_append(reply, "o", entry->path);
            if (ret < 0) {
                zlog_error("failed to append network configuration path %s to reply message (%d)", entry->path, ret);
                continue;
            }
        }
    }

    ret = sd_bus_message_close_container(reply);
    if (ret < 0) {
        zlog_warning("failed to close reply message container for 'Networks' property (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Virtual table describing methods, properties, and signals of the ztp
 * d-bus network configuration manager interface.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_network_configuration_manager[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Networks", "ao", ztp1_network_manager_get_networks, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END,
};

/**
 * @brief Initializes a network manager instance.
 * 
 * @param manager The manager instance to initialize.
 * @return int 0 if the 
 */
static int
ztp_dbus_network_configuration_manager_initialize(struct ztp_dbus_network_configuration_manager *manager)
{
    sd_bus *bus;
    int ret = sd_bus_default_system(&bus);
    if (ret < 0) {
        zlog_error("failed to open system bus (%d)", ret);
        return ret;
    }

    sd_bus_slot *slot_vtable = NULL;
    ret = sd_bus_add_object_vtable(bus,
        &slot_vtable,
        manager->path,
        ZTP_DBUS_SERVER_NETWORK_CONFIGURATION_MANAGER_INTERFACE,
        vtable_com_microsoft_ztp1_network_configuration_manager,
        manager);
    if (ret < 0) {
        zlog_error("failed to install '%s' object vtable (%d)", ZTP_DBUS_SERVER_NETWORK_CONFIGURATION_MANAGER_INTERFACE, ret);
        return ret;
    }

    INIT_LIST_HEAD(&manager->networks);
    manager->network_id_next = 0;
    manager->bus = bus;
    manager->slot_vtable = slot_vtable;

    return 0;
}

/**
 * @brief Creates and initializes a d-bus network configuration manager.
 * 
 * @param manager An output pointer to receive the newly created manager.
 * @param path The base d-bus path the manager will own.
 * @return int 0 if the manager was successfully initialized, non-zero otherwise.
 */
int
ztp_dbus_network_configuration_manager_create(struct ztp_dbus_network_configuration_manager **pmanager, const char *path)
{
    size_t pathlength = strlen(path) + sizeof ZTP_DBUS_SERVER_NETWORK_CONFIGURATION_MANAGER_NAME + 1 /* / */;
    struct ztp_dbus_network_configuration_manager *manager = calloc(1, (sizeof *manager) + pathlength);
    if (!manager) {
        zlog_error("failed to allocate memory for dbus network manager");
        return -ENOMEM;
    }

    snprintf(manager->path, pathlength, "%s/" ZTP_DBUS_SERVER_NETWORK_CONFIGURATION_MANAGER_NAME, path);

    int ret = ztp_dbus_network_configuration_manager_initialize(manager);
    if (ret < 0) {
        zlog_error("failed to initialize dbus network manager (%d)", ret);
        free(manager);
        return ret;
    }

    *pmanager = manager;

    return 0;
}

/**
 * @brief Uninitializes a dbus network configuration manager.
 * 
 * @param manager 
 */
static void
ztp_dbus_network_configuration_manager_uninitialize(struct ztp_dbus_network_configuration_manager *manager)
{
    struct ztp_dbus_network_configuration *network;
    struct ztp_dbus_network_configuration *networktmp;
    list_for_each_entry_safe (network, networktmp, &manager->networks, list) {
        ztp_dbus_network_configuration_manager_unregister(&network);
    }

    if (manager->bus) {
        sd_bus_unref(manager->bus);
        manager->bus = NULL;
    }
}

/**
 * @brief Uninitializes and destroys a d-bus network configuration manager.
 * This will de-register all known d-bus network configuration objects from the
 * bus.
 * 
 * @param manager The manager to uninitialize and destroy.
 */
void
ztp_dbus_network_configuration_manager_destroy(struct ztp_dbus_network_configuration_manager **manager)
{
    if (!manager || !*manager)
        return;

    ztp_dbus_network_configuration_manager_uninitialize(*manager);
    free(*manager);

    *manager = NULL;
}
