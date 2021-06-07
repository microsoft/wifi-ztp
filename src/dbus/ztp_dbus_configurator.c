
#include <errno.h>
#include <stdio.h>

#include <userspace/linux/compiler.h>
#include <userspace/linux/list.h>

#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps.h"
#include "bootstrap_info_provider_file.h"
#include "bootstrap_info_provider_settings.h"
#include "ztp_configurator.h"
#include "ztp_configurator_config.h"
#include "ztp_dbus_configurator.h"
#include "ztp_dbus_network_configuration.h"
#include "ztp_log.h"

/**
 * @brief d-bus bootstrap info provider object entry.
 */
struct ztp_dbus_bootstrap_info_provider {
    struct list_head list;
    struct bootstrap_info_provider *bip;
    struct ztp_dbus_configurator *configurator;
    uint32_t id;
    sd_bus *bus;
    sd_bus_slot *slot;
    sd_bus_slot *slot_type;
    char path[];
};

/**
 * @brief Property getter function for the 'Path' property of BootstrapInfoProviderFile objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProviderFile".
 * @param property The name of the property. Must be "Path".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_profile_file_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_file_get_path(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_file_instance *bip = (struct bootstrap_info_provider_file_instance *)userdata;

    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, bip->settings->path);
    if (ret < 0)
        zlog_warning("failed to append bip file path %s to reply message (%d)", bip->settings->path, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'JsonPointerArray' property of BootstrapInfoProviderFile objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProviderFile".
 * @param property The name of the property. Must be "JsonPointerArray".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_profile_file_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_file_get_jsonptr_array(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_file_instance *bip = (struct bootstrap_info_provider_file_instance *)userdata;

    const char *value = bip->settings->json_pointer_array;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip json pointer array %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'JsonPointerObject' property of BootstrapInfoProviderFile objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProviderFile".
 * @param property The name of the property. Must be "JsonPointerObject".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_profile_file_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_file_get_jsonptr_object(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_file_instance *bip = (struct bootstrap_info_provider_file_instance *)userdata;

    const char *value = bip->settings->json_pointer_object_base;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip json pointer object %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'JsonKeyDppUri' property of BootstrapInfoProviderFile objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProviderFile".
 * @param property The name of the property. Must be "JsonKeyDppUri".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_profile_file_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_file_get_jsonkey_dppuri(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_file_instance *bip = (struct bootstrap_info_provider_file_instance *)userdata;

    const char *value = bip->settings->json_key_dpp_uri;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip json key dppuri %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'JsonKeyPublickeyHash' property of BootstrapInfoProviderFile objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProviderFile".
 * @param property The name of the property. Must be "JsonKeyPublickeyHash".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_profile_file_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_file_get_jsonkey_publickey_hash(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_file_instance *bip = (struct bootstrap_info_provider_file_instance *)userdata;

    const char *value = bip->settings->json_key_publickeyhash;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip json key publickey hash %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Virtual function table describing methods, properties and signals of
 * a ztp d-bus bootstrap information provider. All such providers are
 * associated with a com.microsoft.ztp1.Configurator d-bus object.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_configurator_bip_file[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Path", "s", ztp1_configurator_bip_file_get_path, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("JsonPointerArray", "s", ztp1_configurator_bip_file_get_jsonptr_array, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("JsonPointerObject", "s", ztp1_configurator_bip_file_get_jsonptr_object, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("JsonKeyDppUri", "s", ztp1_configurator_bip_file_get_jsonkey_dppuri, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("JsonKeyPublickeyHash", "s", ztp1_configurator_bip_file_get_jsonkey_publickey_hash, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END,
};

/**
 * @brief Property getter function for the 'JsonKeyPublickeyHash' property of BootstrapInfoProviderAzureDps objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProvider.AzureDps".
 * @param property The name of the property. Must be "JsonKeyPublickeyHash".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_provider_azure_dps_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_azuredps_get_service_endpoint_uri(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_azure_dps_instance *bip = (struct bootstrap_info_provider_azure_dps_instance *)userdata;

    const char *value = bip->settings->service_endpoint_uri;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip service endpoint uri %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'ServiceEndpointUri' property of BootstrapInfoProviderAzureDps objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProvider.AzureDps".
 * @param property The name of the property. Must be "ServiceEndpointUri".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_provider_azure_dps_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_azuredps_get_authority_url(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_azure_dps_instance *bip = (struct bootstrap_info_provider_azure_dps_instance *)userdata;

    const char *value = bip->settings->authority_url;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip authority url %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'ClientId' property of BootstrapInfoProviderAzureDps objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProvider.AzureDps".
 * @param property The name of the property. Must be "ClientId".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_provider_azure_dps_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_azuredps_get_clientid(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_azure_dps_instance *bip = (struct bootstrap_info_provider_azure_dps_instance *)userdata;

    const char *value = bip->settings->client_id;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip client id %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'ResourceUri' property of BootstrapInfoProviderAzureDps objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProvider.AzureDps".
 * @param property The name of the property. Must be "ResourceUri".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_provider_azure_dps_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_azuredps_get_resource_uri(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_azure_dps_instance *bip = (struct bootstrap_info_provider_azure_dps_instance *)userdata;

    const char *value = bip->settings->resource_uri;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip resource uri %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'ConnectionString' property of BootstrapInfoProviderAzureDps objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProvider.AzureDps".
 * @param property The name of the property. Must be "ConnectionString".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_provider_azure_dps_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_azuredps_get_connection_string(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct bootstrap_info_provider_azure_dps_instance *bip = (struct bootstrap_info_provider_azure_dps_instance *)userdata;

    const char *value = bip->settings->connection_string;
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, value);
    if (ret < 0)
        zlog_warning("failed to append bip resource uri %s to reply message (%d)", value, ret);

    return ret;
}

/**
 * @brief Method to authorize an azure dps bootstrap info provider. This will
 * perform oauth2 against the configured dps instance.
 * 
 * @param message The request message.
 * @param userdata The user context. Must be of type struct ztp_dbus_bootstrap_info_provider.
 * @param error The error proxy to use.
 * @return int 0 if the method was successfully executed, non-zero otherwise.
 */
static int
ztp1_configurator_bip_azuredps_authorize(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    __unused(error);

    struct bootstrap_info_provider_azure_dps_instance *bip = (struct bootstrap_info_provider_azure_dps_instance *)userdata;

    int ret = bootstrap_info_provider_azure_dps_authorize(bip);
    return sd_bus_reply_method_return(message, "i", ret);
}

/**
 * @brief Virtual function table describing methods, properties and signals of
 * a ztp d-bus bootstrap information provider. All such providers are
 * associated with a com.microsoft.ztp1.Configurator d-bus object.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_configurator_bip_azuredps[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("ServiceEndpointUri", "s", ztp1_configurator_bip_azuredps_get_service_endpoint_uri, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("AuthorityUrl", "s", ztp1_configurator_bip_azuredps_get_authority_url, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("ClientId", "s", ztp1_configurator_bip_azuredps_get_clientid, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("ResourceUri", "s", ztp1_configurator_bip_azuredps_get_resource_uri, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("ConnectionString", "s", ztp1_configurator_bip_azuredps_get_connection_string, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_METHOD("Authorize", NULL, "i", ztp1_configurator_bip_azuredps_authorize, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END,
};

/**
 * @brief Property getter function for the 'Name' property of BootstrapInfoProvider objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProvider".
 * @param property The name of the property. Must be "Name".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct ztp_dbus_bootstrap_info_provider.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_get_name(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_bootstrap_info_provider *obj = (struct ztp_dbus_bootstrap_info_provider *)userdata;

    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, obj->bip->name);
    if (ret < 0)
        zlog_warning("failed to append bip name %s to reply message (%d)", obj->bip->name, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'Type' property of BootstrapInfoProvider objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProvider".
 * @param property The name of the property. Must be "Type".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct ztp_dbus_bootstrap_info_provider.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_get_type(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_bootstrap_info_provider *obj = (struct ztp_dbus_bootstrap_info_provider *)userdata;

    const char *type = bootstrap_info_provider_type_str(obj->bip->type);
    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, type);
    if (ret < 0)
        zlog_warning("failed to append bip type %s to reply message (%d)", type, ret);

    return ret;
}

/**
 * @brief Property getter function for the 'ExpirationTime' property of BootstrapInfoProvider objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProvider".
 * @param property The name of the property. Must be "ExpirationTime".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct ztp_dbus_bootstrap_info_provider.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_bip_get_expiration_time(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_bootstrap_info_provider *obj = (struct ztp_dbus_bootstrap_info_provider *)userdata;

    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_UINT32, &obj->bip->settings->expiration_time);
    if (ret < 0)
        zlog_warning("failed to append bip expiration time %u to reply message (%d)", obj->bip->settings->expiration_time, ret);

    return ret;
}

/**
 * @brief Method to synchronize a bootstrap info provider.
 *
 * @param message The request message.
 * @param userdata The user content. Must be of type struct ztp_dbus_bootstrap_info_provider.
 * @param error The error proxy to use.
 * @return int 0 if the method was successfully executed, non-zero otherwise.
 * Note that zero is returned even if the synchronization itself fails; the
 * return value only indicates whether the method was executed.
 */
static int
ztp1_configurator_bip_synchronize(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    __unused(error);

    struct ztp_dbus_bootstrap_info_provider *obj = (struct ztp_dbus_bootstrap_info_provider *)userdata;

    struct bootstrap_info_sync_options options = { 0 };
    int ret = bootstrap_info_provider_synchronize(obj->bip, &options);

    return sd_bus_reply_method_return(message, "i", ret);
}

/**
 * @brief Virtual function table describing methods, properties and signals of
 * a ztp d-bus bootstrap information provider. All such providers are
 * associated with a com.microsoft.ztp1.Configurator d-bus object.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_configurator_bip[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Name", "s", ztp1_configurator_bip_get_name, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Type", "s", ztp1_configurator_bip_get_type, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("ExpirationTime", "u", ztp1_configurator_bip_get_expiration_time, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_METHOD("Synchronize", NULL, "i", ztp1_configurator_bip_synchronize, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END,
};

/**
 * @brief Adds a bootstrap information provider d-bus object to a configurator d-bus object.
 *
 * @param configurator The d-bus configurator object to add the provider to.
 * @param bip The bootstrap information provider to add. The caller must ensure
 * this pointer is valid for the lifetime of the bip d-bus object, or until
 * ztp_dbus_configurator_bip_remove is called.
 *
 * @return int 0 if the provider was successfully added, non-zero otherwise.
 */
static int
ztp_dbus_configurator_bip_add(struct ztp_dbus_configurator *configurator, struct bootstrap_info_provider *bip)
{
    char path[ZTP_DBUS_MAX_PATH];
    uint32_t id = configurator->bip_id_next++;
    int ret = snprintf(path, sizeof path, "%s/" ZTP_DBUS_CONFIGURATOR_BIP_NAME "/%u", configurator->path, id);
    if (ret < 0) {
        zlog_error("failed to format ztp dbus configurator bip path");
        return -EINVAL;
    }

    size_t pathlength = (size_t)ret;
    assert(pathlength <= sizeof path);

    struct ztp_dbus_bootstrap_info_provider *entry = calloc(1, (sizeof *entry) + pathlength);
    if (!entry) {
        zlog_error("failed to allocate memory for ztp dbus configurator bip object entry");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&entry->list);
    entry->id = id;
    entry->bip = bip;
    entry->bus = configurator->bus;
    entry->configurator = configurator;
    memcpy(entry->path, path, pathlength);

    ret = sd_bus_add_object_vtable(entry->bus, &entry->slot, entry->path, ZTP_DBUS_CONFIGURATOR_BIP_INTERFACE, vtable_com_microsoft_ztp1_configurator_bip, entry);
    if (ret < 0) {
        zlog_error("failed to attach bootstrap info provider with path %s to d-bus (%d)", entry->path, ret);
        free(entry);
        return ret;
    }

    switch (bip->type) {
        case BOOTSTRAP_INFO_PROVIDER_FILE: {
            struct bootstrap_info_provider_file_instance *bip_file = (struct bootstrap_info_provider_file_instance *)bip->context;
            ret = sd_bus_add_object_vtable(entry->bus, &entry->slot_type, entry->path, ZTP_DBUS_CONFIGURATOR_BIP_FILE_INTERFACE, vtable_com_microsoft_ztp1_configurator_bip_file, bip_file);
            if (ret < 0)
                zlog_warning("failed to attach bootstrap info provider file interface with path %s to d-bus (%d)", entry->path, ret);
            break;
        }
        case BOOTSTRAP_INFO_PROVIDER_AZUREDPS: {
            struct bootstrap_info_provider_azure_dps_instance *bip_dps = (struct bootstrap_info_provider_azure_dps_instance *)bip->context;
            ret = sd_bus_add_object_vtable(entry->bus, &entry->slot_type, entry->path, ZTP_DBUS_CONFIGURATOR_BIP_AZUREDPS_INTERFACE, vtable_com_microsoft_ztp1_configurator_bip_azuredps, bip_dps);
            if (ret < 0)
                zlog_warning("failed to attach bootstrap info provider azuredps interface with path %s to d-bus (%d)", entry->path, ret);
            break;
        }
        default: {
            entry->slot_type = NULL;
            break;
        }
    }

    sd_bus_ref(entry->bus);
    list_add(&entry->list, &configurator->bips);

    return 0;
}

/**
 * @brief Removes a bootstrap info provider object from d-bus, freeing any
 * owned resources.
 *
 * @param entry The entry to remove.
 */
static void
ztp_dbus_configurator_bip_remove(struct ztp_dbus_bootstrap_info_provider *entry)
{
    if (entry->slot_type)
        sd_bus_slot_unref(entry->slot_type);
    if (entry->slot)
        sd_bus_slot_unref(entry->slot);
    if (entry->bus)
        sd_bus_unref(entry->bus);
    if (entry->list.next != NULL && !list_empty(&entry->list))
        list_del(&entry->list);

    free(entry);
}

/**
 * @brief Property getter function for the 'DefaultNetwork' property of Configurator objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1.Configurator.BootstrapInfoProviderFile".
 * @param property The name of the property. Must be "DefaultNetworkConfiguration".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct bootstrap_info_profile_file_instance.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_configurator_get_default_network(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_configurator *obj = (struct ztp_dbus_configurator *)userdata;
    const char *objpath = obj->server->network_configuration_default
        ? obj->server->network_configuration_default->path
        : "";

    int ret = sd_bus_message_append_basic(reply, SD_BUS_TYPE_OBJECT_PATH, objpath);
    if (ret < 0)
        zlog_warning("failed to append default network path %s to reply message (%d)", objpath, ret);

    return ret;
}

/**
 * @brief Method to synchronize a bootstrap info provider.
 *
 * @param message The request message.
 * @param userdata The user content. Must be of type struct ztp_dbus_configurator.
 * @param error The error proxy to use.
 * @return int 0 if the method was successfully executed, non-zero otherwise.
 * Note that zero is returned even if the synchronization itself fails; the
 * return value only indicates whether the method was executed.
 */
static int
ztp1_configurator_synchronize_bootstrappinginfo(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    struct ztp_dbus_configurator *obj = (struct ztp_dbus_configurator *)userdata;

    struct bootstrap_info_sync_options options = { 0 };
    int ret = ztp_configurator_synchronize_bootstrapping_info(obj->configurator, &options);
    if (ret < 0) {
        sd_bus_error_set_errno(error, ret);
        return ret;
    }

    return sd_bus_reply_method_return(message, "u", (uint32_t)ret);
}

/**
 * @brief Virtual table describing methods, properties and signals of a ztp
 * d-bus configurator.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1_configurator[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("DefaultNetworkConfiguration", "o", ztp1_configurator_get_default_network, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_METHOD("SynchronizeBootstrappingInfo", NULL, "u", ztp1_configurator_synchronize_bootstrappinginfo, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END,
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
ztp_dbus_configurator_register(struct ztp_dbus_server *server, struct ztp_configurator *configurator)
{
    char path[ZTP_DBUS_MAX_PATH];
    uint32_t id = server->configurator_id_next++;
    int ret = snprintf(path, sizeof path, ZTP_DBUS_CONFIGURATOR_PATH "/%u", id);
    if (ret < 0) {
        zlog_error("failed to format ztp dbus configurator object path");
        return -EINVAL;
    }

    size_t pathlength = (size_t)ret;
    assert(pathlength <= sizeof path);

    struct ztp_dbus_configurator *entry = calloc(1, (sizeof *entry) + pathlength);
    if (!entry) {
        zlog_error("failed to allocate memory for ztp dbus configurator object entry");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&entry->list);
    INIT_LIST_HEAD(&entry->bips);
    entry->id = id;
    entry->bip_id_next = 0;
    entry->bus = server->bus;
    entry->server = server;
    entry->configurator = configurator;
    memcpy(entry->path, path, pathlength);

    ret = sd_bus_add_object_vtable(entry->bus, &entry->slot, entry->path, ZTP_DBUS_CONFIGURATOR_INTERFACE, vtable_com_microsoft_ztp1_configurator, entry);
    if (ret < 0) {
        zlog_error("failed to attach configurator with path %s to d-bus (%d)", entry->path, ret);
        free(entry);
        return ret;
    }

    sd_bus_ref(entry->bus);
    list_add(&entry->list, &server->configurators);

    struct bootstrap_info_provider *bip;
    list_for_each_entry (bip, &configurator->bootstrap_info_providers, list) {
        ret = ztp_dbus_configurator_bip_add(entry, bip);
        if (ret < 0)
            zlog_warning("failed to add bootstrap info provider %s to d-bus (%d)", bip->name, ret);
    }

    return 0;
}

/**
 * @brief Finds a configurator object entry, given its instance pointer.
 *
 * @param server The server owning the configurator object.
 * @param configurator The configurator instance pointers.
 * @return struct ztp_dbus_configurator* A pointer to the d-bus object entry if
 * one matching 'configurator' exists. NULL otherwise.
 */
static struct ztp_dbus_configurator *
find_configurator(struct ztp_dbus_server *server, const struct ztp_configurator *configurator)
{
    struct ztp_dbus_configurator *entry;
    list_for_each_entry (entry, &server->configurators, list) {
        if (entry->configurator == configurator) {
            return entry;
        }
    }

    return NULL;
}

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
ztp_dbus_configurator_unregister(struct ztp_dbus_server *server, struct ztp_configurator *configurator)
{
    struct ztp_dbus_configurator *entry = find_configurator(server, configurator);
    if (!entry)
        return -ENOENT;

    struct ztp_dbus_bootstrap_info_provider *bip;
    struct ztp_dbus_bootstrap_info_provider *biptmp;
    list_for_each_entry_safe (bip, biptmp, &entry->bips, list) {
        ztp_dbus_configurator_bip_remove(bip);
    }

    if (entry->slot)
        sd_bus_slot_unref(entry->slot);
    if (entry->bus)
        sd_bus_unref(entry->bus);
    if (entry->list.next != NULL && !list_empty(&entry->list))
        list_del(&entry->list);

    free(entry);

    return 0;
}
