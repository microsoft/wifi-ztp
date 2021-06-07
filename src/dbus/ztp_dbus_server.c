
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include <userspace/linux/compiler.h>
#include <userspace/linux/list.h>

#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps.h"
#include "bootstrap_info_provider_file.h"
#include "bootstrap_info_provider_settings.h"
#include "dbus_message_helpers.h"
#include "dpp.h"
#include "ztp_configurator_config.h"
#include "ztp_dbus_configurator.h"
#include "ztp_dbus_network_configuration.h"
#include "ztp_dbus_server.h"
#include "ztp_log.h"
#include "ztp_settings.h"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif //__clang__

/**
 * @brief Helper macros for logging dbus server specific messages. 
 */
#define zlog_dbus(_prio, _fmt, ...) zlog_##_prio("dbus: " _fmt, ##__VA_ARGS__)
#define zlog_panic_dbus(_fmt, ...) zlog_dbus(panic, _fmt, ##__VA_ARGS__)
#define zlog_alert_dbus(_fmt, ...) zlog_dbus(alert, _fmt, ##__VA_ARGS__)
#define zlog_critical_dbus(_fmt, ...) zlog_dbus(critical, _fmt, ##__VA_ARGS__)
#define zlog_error_dbus(_fmt, ...) zlog_dbus(error, _fmt, ##__VA_ARGS__)
#define zlog_warning_dbus(_fmt, ...) zlog_dbus(warning, _fmt, ##__VA_ARGS__)
#define zlog_notice_dbus(_fmt, ...) zlog_dbus(notice, _fmt, ##__VA_ARGS__)
#define zlog_info_dbus(_fmt, ...) zlog_dbus(info, _fmt, ##__VA_ARGS__)
#define zlog_debug_dbus(_fmt, ...) zlog_dbus(debug, _fmt, ##__VA_ARGS__)

/**
 * @brief Retrieves an array of active configurator objects.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1".
 * @param property The name of the property. Must be "Configurators".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct ztp_dbus_server.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_get_configurators(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_server *server = (struct ztp_dbus_server *)userdata;

    int ret = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "o");
    if (ret < 0) {
        zlog_error_dbus("failed to open reply message for 'Configurators' property (%d)", ret);
        return ret;
    }

    {
        struct ztp_dbus_configurator *entry;
        list_for_each_entry (entry, &server->configurators, list) {
            ret = sd_bus_message_append(reply, "o", entry->path);
            if (ret < 0) {
                zlog_error_dbus("failed to append configurator path %s to reply message (%d)", entry->path, ret);
                continue;
            }
        }
    }

    ret = sd_bus_message_close_container(reply);
    if (ret < 0) {
        zlog_warning_dbus("failed to close reply message container for 'Configurators' property (%d)", ret);
        return ret;
    }

    return 0;
}

/*
 * @brief Retrieves an array of active dpp roles.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1".
 * @param property The name of the property. Must be "Roles".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct ztp_dbus_server.
 * @param ret_error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_get_dpp_roles(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);
    __unused(ret_error);

    struct ztp_dbus_server *server = (struct ztp_dbus_server *)userdata;

    int ret = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "s");
    if (ret < 0) {
        zlog_error_dbus("failed to open reply message for 'Roles' property (%d)", ret);
        return ret;
    }

    {
        for (size_t i = 0; i < ARRAY_SIZE(server->settings->dpp_roles_activated); i++) {
            if (server->settings->dpp_roles_activated[i]) {
                const char *role = dpp_device_role_str((enum dpp_device_role)i);
                ret = sd_bus_message_append(reply, "s", role);
                if (ret < 0) {
                    zlog_error_dbus("failed to append role %s to 'Roles' reply message (%d)", role, ret);
                    continue;
                }
            }
        }
    }

    ret = sd_bus_message_close_container(reply);
    if (ret < 0) {
        zlog_warning_dbus("failed to close reply message container for 'Roles' property (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_BI_PROVIDER_FILE_CHILDREN "(ss)(ss)(ss)(ss)(ss)"
#define DBUS_DATA_BI_PROVIDER_FILE_SIGNATURE "(" DBUS_DATA_BI_PROVIDER_FILE_CHILDREN ")"

static int
ztp1_populate_bootstrap_info_provider_settings_file(sd_bus_message *message, const struct bootstrap_info_provider_file_settings *settings)
{
    const struct {
        const char *key;
        const char *value;
    } entries[] = {
        { "Path", settings->path },
        { "JsonKeyDppUri", settings->json_key_dpp_uri },
        { "JsonKeyPublickeyHash", settings->json_key_publickeyhash },
        { "JsonPointerObject", settings->json_pointer_object_base },
        { "JsonPointerArray", settings->json_pointer_array },
    };

    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_BI_PROVIDER_FILE_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to open file bootstrap info provider container (%d)", ret);
        return ret;
    }

    {
        for (size_t i = 0; i < ARRAY_SIZE(entries); i++) {
            ret = dbus_append_kv_pair_string(message, entries[i].key, entries[i].value);
            if (ret < 0) {
                zlog_error_dbus("failed to append '%s' setting for file bootstrap info provider (%d)", entries[i].key, ret);
                return ret;
            }
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to close file bootstrap info provider container (%d)", ret);
        return ret;
    }

    return 0;
}

static int
ztp1_decode_bootstrap_info_provider_settings_file(sd_bus_message *message, struct bootstrap_info_provider_file_settings *settings)
{
    const struct {
        const char *key;
        char **value;
    } entries[] = {
        { "Path", &settings->path },
        { "JsonKeyDppUri", &settings->json_key_dpp_uri },
        { "JsonKeyPublickeyHash", &settings->json_key_publickeyhash },
        { "JsonPointerObject", &settings->json_pointer_object_base },
        { "JsonPointerArray", &settings->json_pointer_array },
    };

    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_BI_PROVIDER_FILE_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to enter file bootstrap info provider container (%d)", ret);
        return ret;
    }

    {
        for (size_t i = 0; i < ARRAY_SIZE(entries); i++) {
            ret = dbus_read_kv_pair_string_cp(message, entries[i].key, entries[i].value);
            if (ret < 0) {
                zlog_error_dbus("failed to append '%s' setting for file bootstrap info provider (%d)", entries[i].key, ret);
                return ret;
            }
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit file bootstrap info provider container (%d)", ret);
        return ret;
    }

    return 0;
}

static int
ztp1_append_bootstrap_info_provider_setttings_file(sd_bus_message *message, const void *value, void *context)
{
    __unused(context);

    struct bootstrap_info_provider_file_settings *settings = (struct bootstrap_info_provider_file_settings *)value;
    return ztp1_populate_bootstrap_info_provider_settings_file(message, settings);
}

static int
ztp1_read_bootstrap_info_provider_setttings_file(sd_bus_message *message, void *value, void *context)
{
    __unused(context);

    struct bootstrap_info_provider_file_settings *settings = (struct bootstrap_info_provider_file_settings *)value;
    return ztp1_decode_bootstrap_info_provider_settings_file(message, settings);
}

#define DBUS_DATA_BI_PROVIDER_AZUREPDS_CHILDREN "(ss)(ss)(ss)(ss)(ss)(ss)"
#define DBUS_DATA_BI_PROVIDER_AZUREDPS_SIGNATURE "(" DBUS_DATA_BI_PROVIDER_AZUREPDS_CHILDREN ")"

static int
ztp1_populate_bootstrap_info_provider_settings_azuredps(sd_bus_message *message, const struct bootstrap_info_provider_azure_dps_settings *settings)
{
    const struct {
        const char *key;
        const char *value;
    } entries[] = {
        { "ServiceEndpointUri", settings->service_endpoint_uri },
        { "AuthorityUrl", settings->authority_url },
        { "ClientId", settings->client_id },
        { "ClientSecret", settings->client_secret },
        { "ResourceUri", settings->resource_uri },
        { "ConnectionString", settings->connection_string },
    };

    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_BI_PROVIDER_AZUREPDS_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to open azure dps bootstrap info provider container (%d)", ret);
        return ret;
    }

    {
        for (size_t i = 0; i < ARRAY_SIZE(entries); i++) {
            ret = dbus_append_kv_pair_string(message, entries[i].key, entries[i].value);
            if (ret < 0) {
                zlog_error_dbus("failed to append '%s' setting for azure dps bootstrap info provider (%d)", entries[i].key, ret);
                return ret;
            }
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to close azure dps bootstrap info provider container (%d)", ret);
        return ret;
    }

    return 0;
}

static int
ztp1_decode_bootstrap_info_provider_settings_azuredps(sd_bus_message *message, struct bootstrap_info_provider_azure_dps_settings *settings)
{
    const struct {
        const char *key;
        char **value;
    } entries[] = {
        { "ServiceEndpointUri", &settings->service_endpoint_uri },
        { "AuthorityUrl", &settings->authority_url },
        { "ClientId", &settings->client_id },
        { "ClientSecret", &settings->client_secret },
        { "ResourceUri", &settings->resource_uri },
        { "ConnectionString", &settings->connection_string },
    };

    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_BI_PROVIDER_AZUREPDS_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to enter azure dps bootstrap info provider container (%d)", ret);
        return ret;
    }

    {
        for (size_t i = 0; i < ARRAY_SIZE(entries); i++) {
            ret = dbus_read_kv_pair_string_cp(message, entries[i].key, entries[i].value);
            if (ret < 0) {
                zlog_error_dbus("failed to read '%s' setting for azure dps bootstrap info provider (%d)", entries[i].key, ret);
                return ret;
            }
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit azure dps bootstrap info provider container (%d)", ret);
        return ret;
    }

    return 0;
}

static int
ztp1_append_bootstrap_info_provider_setttings_azuredps(sd_bus_message *message, const void *value, void *context)
{
    __unused(context);

    struct bootstrap_info_provider_azure_dps_settings *settings = (struct bootstrap_info_provider_azure_dps_settings *)value;
    return ztp1_populate_bootstrap_info_provider_settings_azuredps(message, settings);
}

static int
ztp1_read_bootstrap_info_provider_setttings_azuredps(sd_bus_message *message, void *value, void *context)
{
    __unused(context);

    struct bootstrap_info_provider_azure_dps_settings *settings = (struct bootstrap_info_provider_azure_dps_settings *)value;
    return ztp1_decode_bootstrap_info_provider_settings_azuredps(message, settings);
}

#define DBUS_DATA_BI_PROVIDER_CHILDREN "(ss)(ss)(su)(sv)"
#define DBUS_DATA_BI_PROVIDER_SIGNATURE "(" DBUS_DATA_BI_PROVIDER_CHILDREN ")"

static int
ztp1_populate_bootstrap_info_provider_settings(sd_bus_message *message, const struct bootstrap_info_provider_settings *settings)
{
    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_BI_PROVIDER_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to open bootstrap info provider settings struct container (%d)", ret);
        return ret;
    }

    {
        ret = dbus_append_kv_pair_string(message, "Type", bootstrap_info_provider_type_str(settings->type));
        if (ret < 0) {
            zlog_error_dbus("failed to append bootstrap info provider type (%d)", ret);
            return ret;
        }

        ret = dbus_append_kv_pair_string(message, "Name", settings->name);
        if (ret < 0) {
            zlog_error_dbus("failed to append bootstrap info provider name (%d)", ret);
            return ret;
        }

        ret = dbus_append_kv_pair_basic(message, SD_BUS_TYPE_UINT32, "ExpirationTime", &settings->expiration_time);
        if (ret < 0) {
            zlog_error_dbus("failed to append expiration time value to bootstrap info provider (%d)", ret);
            return ret;
        }

        switch (settings->type) {
            case BOOTSTRAP_INFO_PROVIDER_FILE: {
                ret = dbus_append_kv_pair_variant(message, "File", settings->file, DBUS_DATA_BI_PROVIDER_FILE_SIGNATURE, ztp1_append_bootstrap_info_provider_setttings_file, NULL);
                if (ret < 0) {
                    zlog_error_dbus("failed to append file bootstrap info provider settings (%d)", ret);
                    return ret;
                }
                break;
            }
            case BOOTSTRAP_INFO_PROVIDER_AZUREDPS: {
                ret = dbus_append_kv_pair_variant(message, "AzureDps", settings->dps, DBUS_DATA_BI_PROVIDER_AZUREDPS_SIGNATURE, ztp1_append_bootstrap_info_provider_setttings_azuredps, NULL);
                if (ret < 0) {
                    zlog_error_dbus("failed to append azure dps bootstrap info provider settings (%d)", ret);
                    return ret;
                }
                break;
            }
            default:
                zlog_error_dbus("unsupported bootstrap info provider type (%d)", ret);
                return -EINVAL;
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to close bootstrap info provider settings struct container (%d)", ret);
        return ret;
    }

    return 0;
}

static int
ztp1_decode_bootstrap_info_provider_settings_instance(sd_bus_message *message, struct bootstrap_info_provider_settings *settings)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_BI_PROVIDER_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to enter bootstrap info provider settings struct container (%d)", ret);
        return ret;
    }

    {
        const char *type;
        ret = dbus_read_kv_pair_string(message, "Type", &type);
        if (ret < 0) {
            zlog_error_dbus("failed to read 'Type' property from bootstrap info provider (%d)", ret);
            return ret;
        }

        settings->type = parse_bootstrap_info_provider_type(type);
        if (settings->type == BOOTSTRAP_INFO_PROVIDER_INVALID) {
            zlog_error_dbus("invalid bootstrap info provider type specified");
            return -EINVAL;
        }

        ret = dbus_read_kv_pair_string_cp(message, "Name", &settings->name);
        if (ret < 0) {
            zlog_error_dbus("failed to read 'Name' property from bootstrap info provider (%d)", ret);
            return ret;
        }

        ret = dbus_read_kv_pair_basic(message, SD_BUS_TYPE_UINT32, "ExpirationTime", &settings->expiration_time);
        if (ret < 0) {
            zlog_error_dbus("failed to read expiration time value from bootstrap info provider (%d)", ret);
            return ret;
        }

        switch (settings->type) {
            case BOOTSTRAP_INFO_PROVIDER_FILE: {
                settings->file = calloc(1, sizeof *(settings->file));
                if (!settings->file) {
                    zlog_error_dbus("failed to allocate memory for file bootstrap provider settings");
                    return -ENOMEM;
                }

                ret = dbus_read_kv_pair_variant(message, "File", settings->file, DBUS_DATA_BI_PROVIDER_FILE_SIGNATURE, ztp1_read_bootstrap_info_provider_setttings_file, NULL);
                if (ret < 0) {
                    zlog_error_dbus("failed to append file bootstrap info provider settings (%d)", ret);
                    return ret;
                }
                break;
            }
            case BOOTSTRAP_INFO_PROVIDER_AZUREDPS: {
                settings->dps = calloc(1, sizeof *(settings->dps));
                if (!settings->dps) {
                    zlog_error_dbus("failed to allocate memory for azure dps bootstrap provider settings");
                    return -ENOMEM;
                }

                ret = dbus_read_kv_pair_variant(message, "AzureDps", settings->dps, DBUS_DATA_BI_PROVIDER_AZUREDPS_SIGNATURE, ztp1_read_bootstrap_info_provider_setttings_azuredps, NULL);
                if (ret < 0) {
                    zlog_error_dbus("failed to append azure dps bootstrap info provider settings (%d)", ret);
                    return ret;
                }
                break;
            }
            default:
                zlog_error_dbus("unsupported bootstrap info provider type (%d)", ret);
                return -EINVAL;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit bootstrap info provider settings struct container (%d)", ret);
        return ret;
    }

    return 0;
}

static int
ztp1_decode_bootstrap_info_provider_settings(sd_bus_message *message, struct ztp_configurator_settings *settings)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, DBUS_DATA_BI_PROVIDER_SIGNATURE);
    if (ret < 0) {
        zlog_error_dbus("failed to enter bootstrap info provider array container (%d)", ret);
        return ret;
    }

    {
        for (;;) {
            ret = sd_bus_message_at_end(message, 0);
            if (ret < 0) {
                zlog_error_dbus("failed to determine end of message reached (%d)", ret);
                return ret;
            } else if (ret) {
                break;
            }

            struct bootstrap_info_provider_settings *provider = bootstrap_info_provider_settings_alloc();
            if (!provider) {
                zlog_error_dbus("failed to allocate memory for bootstrap info provider settings");
                return -ENOMEM;
            }

            ret = ztp1_decode_bootstrap_info_provider_settings_instance(message, provider);
            if (ret < 0) {
                zlog_error_dbus("failed to decode bootstrap info provider settings (%d)", ret);
                bootstrap_info_provider_settings_uninitialize(provider);
                return ret;
            }

            ztp_configurator_settings_add_bi_provider_settings(settings, provider);
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit network credential array container (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_ROLES_CHILDREN "sas"
#define DBUS_DATA_ROLES_SIGNATURE "(" DBUS_DATA_ROLES_CHILDREN ")"

/**
 * @brief Populates a message with the roles setting of the ztp service.
 * 
 * The roles setting is encoded as a structure with the following d-bus signature: (sas)
 * 
 * The first entry, s, will always be the value "Roles".
 * The second entry, as, will contain the active roles of the service. The range of possible values is:
 * 
 *      "enrolleee"
 *      "configurator"
 * 
 * @param server The server control structure.
 * @param message The message to populate.
 * @return int 0 if the message was populated, non-zero otherwise.
 */
static int
ztp1_settings_property_populate_roles(struct ztp_dbus_server *server, sd_bus_message *message)
{
    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_ROLES_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to open roles containter (%d)", ret);
        return ret;
    }

    {
        ret = sd_bus_message_append_basic(message, SD_BUS_TYPE_STRING, "Roles");
        if (ret < 0) {
            zlog_error_dbus("failed to append 'Roles' key to roles container (%d)", ret);
            return ret;
        }

        ret = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY, "s");
        if (ret < 0) {
            zlog_error_dbus("failed to open roles array container (%d)", ret);
            return ret;
        }

        {
            for (size_t i = 0; i < ARRAY_SIZE(server->settings->dpp_roles_activated); i++) {
                if (server->settings->dpp_roles_activated[i]) {
                    const char *role = dpp_device_role_str((enum dpp_device_role)i);
                    ret = sd_bus_message_append(message, "s", role);
                    if (ret < 0) {
                        zlog_error_dbus("failed to append role %s to roles container (%d)", role, ret);
                        continue;
                    }
                }
            }
        }

        ret = sd_bus_message_close_container(message);
        if (ret < 0) {
            zlog_error_dbus("failed to close roles array container (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_warning_dbus("failed to close roles container (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_NETWORK_CREDENTIAL_PSK_CHILDREN "(ss)a{sv}"
#define DBUS_DATA_NETWORK_CREDENTIAL_PSK_SIGNATURE "(" DBUS_DATA_NETWORK_CREDENTIAL_PSK_CHILDREN ")"

static int
ztp1_decode_network_credential_psk(sd_bus_message *message, struct dpp_network_credential_psk *psk)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_NETWORK_CREDENTIAL_PSK_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to enter psk credential container (%d)", ret);
    }

    {
        const char *type;
        ret = dbus_read_kv_pair_string(message, "Type", &type);
        if (ret < 0) {
            zlog_error_dbus("failed to read psk credentiak type (%d)", ret);
            return ret;
        }

        psk->type = parse_dpp_psk_credential_type(type);
        if (psk->type == PSK_CREDENTIAL_TYPE_INVALID) {
            zlog_error_dbus("invalid psk credential type specified");
            return -EINVAL;
        }

        ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "{sv}");
        if (ret < 0) {
            zlog_error_dbus("failed to enter psk network credential dictionary array container (%d)", ret);
            return ret;
        }

        {
            switch (psk->type) {
                case PSK_CREDENTIAL_TYPE_PASSPHRASE: {
                    const char *passphrase;
                    ret = dbus_read_dict_entry_string(message, "Passphrase", &passphrase);
                    if (ret < 0) {
                        zlog_error_dbus("failed to read psk credential passphrase (%d)", ret);
                        return ret;
                    }

                    ret = dpp_credential_psk_set_passphrase(psk, passphrase);
                    if (ret < 0) {
                        zlog_error_dbus("failed to set psk credential passphrase (%d)", ret);
                        return ret;
                    }
                    break;
                }
                case PSK_CREDENTIAL_TYPE_PSK: {
                    const char *key_hex;
                    ret = dbus_read_dict_entry_string(message, "Psk", &key_hex);
                    if (ret < 0) {
                        zlog_error_dbus("failed to read psk credential key (%d)", ret);
                        return ret;
                    }

                    ret = dpp_credential_psk_set_key(psk, key_hex);
                    if (ret < 0) {
                        zlog_error_dbus("failed to set psk credential key (%d)", ret);
                        return ret;
                    }
                    break;
                }
                default:
                    break;
            }
        }

        ret = sd_bus_message_exit_container(message);
        if (ret < 0) {
            zlog_error_dbus("failed to exit psk credential dictionary container (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit psk credential psk container (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_NETWORK_CREDENTIAL_SAE_CHILDREN "(ss)"
#define DBUS_DATA_NETWORK_CREDENTIAL_SAE_SIGNATURE "(" DBUS_DATA_NETWORK_CREDENTIAL_SAE_CHILDREN ")"

static int
ztp1_decode_network_credential_sae(sd_bus_message *message, struct dpp_network_credential_sae *sae)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_NETWORK_CREDENTIAL_SAE_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to enter sae credential container (%d)", ret);
    }

    {
        const char *passphrase;
        ret = dbus_read_kv_pair_string(message, "Passphrase", &passphrase);
        if (ret < 0) {
            zlog_error_dbus("failed to read sae credential passphrase (%d)", ret);
            return ret;
        }

        ret = dpp_credential_sae_set_passphrase(sae, passphrase);
        if (ret < 0) {
            zlog_error_dbus("failed to set sae credential passphrase (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit sae credential container (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_NETWORK_CREDENTIAL_CHILDREN "(ss)(sv)"
#define DBUS_DATA_NETWORK_CREDENTIAL_SIGNATURE "(" DBUS_DATA_NETWORK_CREDENTIAL_CHILDREN ")"

static int
dbus_read_network_credential_psk(sd_bus_message *message, void *value, void *context)
{
    __unused(context);

    struct dpp_network_credential_psk *psk = (struct dpp_network_credential_psk *)value;
    return ztp1_decode_network_credential_psk(message, psk);
}

static int
dbus_read_network_credential_sae(sd_bus_message *message, void *value, void *context)
{
    __unused(context);

    struct dpp_network_credential_sae *sae = (struct dpp_network_credential_sae *)value;
    return ztp1_decode_network_credential_sae(message, sae);
}

static int
ztp1_decode_network_credential(sd_bus_message *message, struct dpp_network_credential *credential)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_NETWORK_CREDENTIAL_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to enter network credential container (%d)", ret);
        return ret;
    }

    {
        const char *akmstr;
        ret = dbus_read_kv_pair_string(message, "Akm", &akmstr);
        if (ret < 0) {
            zlog_error_dbus("failed to reak akm from network credential (%d)", ret);
            return ret;
        }

        credential->akm = parse_dpp_akm(akmstr);

        switch (credential->akm) {
            case DPP_AKM_PSK: {
                ret = dbus_read_kv_pair_variant(message, "Psk", &credential->psk, DBUS_DATA_NETWORK_CREDENTIAL_PSK_SIGNATURE, dbus_read_network_credential_psk, NULL);
                if (ret < 0) {
                    zlog_error_dbus("failed to decode psk network credential (%d)", ret);
                    return ret;
                }
                break;
            }
            case DPP_AKM_SAE: {
                ret = dbus_read_kv_pair_variant(message, "Sae", &credential->sae, DBUS_DATA_NETWORK_CREDENTIAL_SAE_SIGNATURE, dbus_read_network_credential_sae, NULL);
                if (ret < 0) {
                    zlog_error_dbus("failed to decode sae network credential (%d)", ret);
                    return ret;
                }
                break;
            }
            default: {
                zlog_error_dbus("invalid dpp credential akm specified");
                return -EINVAL;
            }
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to close network credential container (%d)", ret);
        return ret;
    }

    return 0;
}

static int
ztp1_decode_network_credentials(sd_bus_message *message, struct dpp_network *network)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, DBUS_DATA_NETWORK_CREDENTIAL_SIGNATURE);
    if (ret < 0) {
        zlog_error_dbus("failed to enter network credential array container (%d)", ret);
        return ret;
    }

    {
        for (;;) {
            ret = sd_bus_message_at_end(message, 0);
            if (ret < 0) {
                zlog_error_dbus("failed to determine end of message reached (%d)", ret);
                return ret;
            } else if (ret) {
                break;
            }

            struct dpp_network_credential *credential = dpp_network_credential_alloc();
            if (!credential) {
                zlog_error_dbus("failed to allocate memory for dpp network credential");
                return -ENOMEM;
            }

            ret = ztp1_decode_network_credential(message, credential);
            if (ret < 0) {
                zlog_error_dbus("failed to decode network credential (%d)", ret);
                dpp_network_credential_uninitialize(credential);
                return ret;
            }

            dpp_network_add_credential(network, credential);
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit network credential array container (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_NETWORK_CHILDREN "(ss)(ss)(sa" DBUS_DATA_NETWORK_CREDENTIAL_SIGNATURE ")"
#define DBUS_DATA_NETWORK_SIGNATURE "(" DBUS_DATA_NETWORK_CHILDREN ")"

static int
ztp1_decode_network(sd_bus_message *message, struct dpp_network *network)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_NETWORK_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to enter container for network (%d)", ret);
        return ret;
    }

    {
        const char *value;
        ret = dbus_read_kv_pair_string(message, "WifiTechnology", &value);
        if (ret < 0) {
            zlog_error_dbus("failed to read 'WifiTechnology' kv-pair from network (%d)", ret);
            return ret;
        }

        const char *ssid;
        ret = dbus_read_kv_pair_string(message, "SSID", &ssid);
        if (ret < 0) {
            zlog_error_dbus("failed to append 'SSID' kv-pair to network (%d)", ret);
            return ret;
        }

        size_t ssid_length = strlen(ssid) + 1;
        if (ssid_length > sizeof network->discovery.ssid) {
            zlog_error_dbus("ssid too long; must be <= %lu characters", (sizeof network->discovery.ssid) - 1);
            return -EINVAL;
        }

        memcpy(network->discovery.ssid, ssid, ssid_length);
        network->discovery.ssid_length = ssid_length;

        ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "sa" DBUS_DATA_NETWORK_CREDENTIAL_SIGNATURE);
        if (ret < 0) {
            zlog_error_dbus("failed to open struct container for network credentials (%d)", ret);
            return ret;
        }

        {
            ret = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &value);
            if (ret < 0) {
                zlog_error_dbus("failed to append network credentials array key 'Credentials' (%d)", ret);
                return ret;
            } else if (!value || strcmp(value, "Credentials") != 0) {
                zlog_error_dbus("failed to find 'Credentials' property, found '%s'", value ? value : "<null>");
                return -EINVAL;
            }

            ret = ztp1_decode_network_credentials(message, network);
            if (ret < 0) {
                zlog_error_dbus("failed to decode network credentials (%d)", ret);
                return ret;
            }
        }

        ret = sd_bus_message_exit_container(message);
        if (ret < 0) {
            zlog_error_dbus("failed to exit struct container for network credentials (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit struct container for network (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_BOOTSTRAP_INFO_CHILDREN "(su)(sa" DBUS_DATA_BI_PROVIDER_SIGNATURE ")"
#define DBUS_DATA_BOOTSTRAP_INFO_SIGNATURE "(" DBUS_DATA_BOOTSTRAP_INFO_CHILDREN ")"

static int
ztp1_populate_bootstrap_info(sd_bus_message *message, const struct ztp_configurator_settings *settings)
{
    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_BOOTSTRAP_INFO_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to open container for bootstrap info (%d)", ret);
        return ret;
    }

    {
        uint32_t expiration_time = settings->expiration_time;
        if (expiration_time == BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET) {
            expiration_time = 0;
        }

        ret = dbus_append_kv_pair_basic(message, SD_BUS_TYPE_UINT32, "ExpirationTime", &expiration_time);
        if (ret < 0) {
            zlog_error_dbus("failed to append 'ExpirationTime' to configurator settings container (%d)", ret);
            return ret;
        }

        ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "sa" DBUS_DATA_BI_PROVIDER_SIGNATURE);
        if (ret < 0) {
            zlog_error_dbus("failed to open bootstrap info provider array struct (%d)", ret);
            return ret;
        }

        {
            ret = sd_bus_message_append_basic(message, SD_BUS_TYPE_STRING, "Providers");
            if (ret < 0) {
                zlog_error_dbus("failed to append bootstrap info provider array (%d)", ret);
                return ret;
            }

            ret = sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY, DBUS_DATA_BI_PROVIDER_SIGNATURE);
            if (ret < 0) {
                zlog_error_dbus("failed to open bootstrap info provider array container for settings (%d)", ret);
                return ret;
            }

            {
                struct bootstrap_info_provider_settings *provider_settings;
                list_for_each_entry (provider_settings, &settings->provider_settings, list) {
                    ret = ztp1_populate_bootstrap_info_provider_settings(message, provider_settings);
                    if (ret < 0) {
                        zlog_error_dbus("failed to populate bootstrap info provider settings with name %s (%d)", provider_settings->name, ret);
                        return ret;
                    }
                }
            }

            ret = sd_bus_message_close_container(message);
            if (ret < 0) {
                zlog_error_dbus("failed to close bootstrap info array container for settings (%d)", ret);
                return ret;
            }
        }

        ret = sd_bus_message_close_container(message);
        if (ret < 0) {
            zlog_error_dbus("failed to close bootstrap info array struct (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to close struct container for bootstrap info (%d)", ret);
        return ret;
    }

    return 0;
}

static int
dbus_append_bootstrap_info(sd_bus_message *message, const void *value, void *value_context)
{
    __unused(value_context);

    const struct ztp_configurator_settings *settings = (const struct ztp_configurator_settings *)value;
    return ztp1_populate_bootstrap_info(message, settings);
}

static int
ztp1_decode_bootstrap_info(sd_bus_message *message, struct ztp_configurator_settings *settings)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_BOOTSTRAP_INFO_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to enter bootstrap info container (%d)", ret);
        return ret;
    }

    {
        ret = dbus_read_kv_pair_basic(message, SD_BUS_TYPE_UINT32, "ExpirationTime", &settings->expiration_time);
        if (ret < 0) {
            zlog_error_dbus("failed to read 'ExpirationTime' property (%d)", ret);
            return ret;
        }

        ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "sa" DBUS_DATA_BI_PROVIDER_SIGNATURE);
        if (ret < 0) {
            zlog_error_dbus("failed to enter bootstrap info array struct container (%d)", ret);
            return ret;
        }

        {
            const char *name;
            ret = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &name);
            if (ret < 0) {
                zlog_error_dbus("failed to read 'Providers' property (%d)", ret);
                return ret;
            } else if (!name || strcmp(name, "Providers") != 0) {
                zlog_error_dbus("failed to find 'Providers' property, found '%s'", name ? name : "<null>");
                return -EINVAL;
            }

            ret = ztp1_decode_bootstrap_info_provider_settings(message, settings);
            if (ret < 0) {
                zlog_error_dbus("failed to decode bootstrap info provider settings (%d)", ret);
                return ret;
            }
        }

        ret = sd_bus_message_exit_container(message);
        if (ret < 0) {
            zlog_error_dbus("failed to exit bootstrap info array struct container (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error_dbus("failed to exit bootstrap info container (%d)", ret);
        return ret;
    }

    return 0;
}

static int
dbus_read_bootstrap_info(sd_bus_message *message, void *value, void *context)
{
    __unused(context);

    struct ztp_configurator_settings *settings = (struct ztp_configurator_settings *)value;
    return ztp1_decode_bootstrap_info(message, settings);
}

#define DBUS_DATA_CONFIGURATOR_CHILDREN "(s" DBUS_DATA_NETWORK_SIGNATURE ")(s" DBUS_DATA_BOOTSTRAP_INFO_SIGNATURE ")"
#define DBUS_DATA_CONFIGURATOR_CHILDREN_R "(ss)(s" DBUS_DATA_BOOTSTRAP_INFO_SIGNATURE ")"
#define DBUS_DATA_CONFIGURATOR_SIGNATURE "(" DBUS_DATA_CONFIGURATOR_CHILDREN ")"
#define DBUS_DATA_CONFIGURATOR_SIGNATURE_R "(" DBUS_DATA_CONFIGURATOR_CHILDREN_R ")"

/**
 * @brief 
 * 
 * @param message 
 * @param server 
 * @return int 
 */
static int
ztp1_rolesettings_property_populate_configurator_settings(sd_bus_message *message, struct ztp_dbus_server *server)
{
    struct ztp_configurator_settings *settings = &server->settings_configurator->configurator;

    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_CONFIGURATOR_CHILDREN_R);
    if (ret < 0) {
        zlog_error_dbus("failed to open configurator settings container (%d)", ret);
        return ret;
    }

    {
        ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "ss");
        if (ret < 0) {
            zlog_error_dbus("failed to open default network container for settings (%d)", ret);
            return ret;
        }

        {
            const char *network_path = server->network_configuration_default
                ? server->network_configuration_default->path
                : "";

            ret = sd_bus_message_append_basic(message, SD_BUS_TYPE_STRING, "DefaultNetwork");
            if (ret < 0) {
                zlog_error_dbus("failed to append 'DefaultNetwork' key to default network container (%d)", ret);
                return ret;
            }

            ret = sd_bus_message_append_basic(message, SD_BUS_TYPE_STRING, network_path);
            if (ret < 0) {
                zlog_error_dbus("failed to append default network settings to container (%d)", ret);
                return ret;
            }
        }

        ret = sd_bus_message_close_container(message);
        if (ret < 0) {
            zlog_error_dbus("failed to close default network container for settings (%d)", ret);
            return ret;
        }

        ret = dbus_append_kv_pair(message, "BootstrapInfoProviderSettings", settings, DBUS_DATA_BOOTSTRAP_INFO_SIGNATURE, dbus_append_bootstrap_info, NULL);
        if (ret < 0) {
            zlog_error_dbus("failed to append bootstrap info provider settings (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_warning_dbus("failed to close configurator settings container (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param server 
 * @param message 
 * @return int 
 */
static int
ztp1_decode_configurator_settings(sd_bus_message *message, struct ztp_configurator_settings *settings)
{
    const char *name;

    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_CONFIGURATOR_CHILDREN);
    if (ret < 0) {
        zlog_error_dbus("failed to open configurator settings container (%d)", ret);
        return ret;
    }

    {
        ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "s" DBUS_DATA_NETWORK_SIGNATURE);
        if (ret < 0) {
            zlog_error_dbus("failed to open default network container for settings (%d)", ret);
            return ret;
        }

        {
            ret = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &name);
            if (ret < 0) {
                zlog_error_dbus("failed to read 'DefaultNetwork' property (%d)", ret);
                return ret;
            } else if (!name || strcmp(name, "DefaultNetwork") != 0) {
                zlog_error_dbus("failed to find 'DefaultNetwork' property, found '%s'", name ? name : "<null>");
                return -EINVAL;
            }

            settings->network_config_default = dpp_network_alloc();
            if (!settings->network_config_default) {
                zlog_error_dbus("failed to allocate dpp network for decode (%d)", ret);
                return -ENOMEM;
            }

            ret = ztp1_decode_network(message, settings->network_config_default);
            if (ret < 0) {
                zlog_error_dbus("failed to decode default network in configurator settings (%d)", ret);
                return ret;
            }
        }

        ret = sd_bus_message_exit_container(message);
        if (ret < 0) {
            zlog_error_dbus("failed to close default network container for settings (%d)", ret);
            return ret;
        }

        ret = dbus_read_kv_pair(message, "BootstrapInfoProviderSettings", settings, DBUS_DATA_BOOTSTRAP_INFO_SIGNATURE, dbus_read_bootstrap_info, NULL);
        if (ret < 0) {
            zlog_error_dbus("failed to decode bootstrap info provider settings (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_warning_dbus("failed to close configurator settings container (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_ROLESETTINGS_CHILDREN "s(s" DBUS_DATA_CONFIGURATOR_SIGNATURE ")"
#define DBUS_DATA_ROLESETTINGS_CHILDREN_R "s(s" DBUS_DATA_CONFIGURATOR_SIGNATURE_R ")"
#define DBUS_DATA_ROLESETTINGS_SIGNATURE "(" DBUS_DATA_ROLESETTINGS_CHILDREN ")"
#define DBUS_DATA_ROLESETTINGS_SIGNATURE_R "(" DBUS_DATA_ROLESETTINGS_CHILDREN_R ")"

/**
 * @brief Populates a message with the role settings of the ztp service.
 * 
 * The roles settings setting is encoded as a structure with the following d-bus signature: (sa{sv})
 * 
 * The first entry, s, will always be the value "RoleSettings".
 * The second entry, a{sv}, is an array of dictionary entries.
 * 
 * @param server The server control structure.
 * @param message The message to populate.
 * @return int 0 if the message was populated, non-zero otherwise
 */
static int
ztp1_settings_property_populate_rolesettings(struct ztp_dbus_server *server, sd_bus_message *message)
{
    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, DBUS_DATA_ROLESETTINGS_CHILDREN_R);
    if (ret < 0) {
        zlog_error_dbus("failed to open role-setting container (%d)", ret);
        return ret;
    }

    {
        ret = sd_bus_message_append_basic(message, SD_BUS_TYPE_STRING, "RoleSettings");
        if (ret < 0) {
            zlog_error_dbus("failed to append 'RoleSettings' key to role-setting container (%d)", ret);
            return ret;
        }

        ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "s" DBUS_DATA_CONFIGURATOR_SIGNATURE_R);
        if (ret < 0) {
            zlog_error_dbus("failed to open role-setting container (%d)", ret);
            return ret;
        }

        {
            ret = sd_bus_message_append_basic(message, SD_BUS_TYPE_STRING, "Configurator");
            if (ret < 0) {
                zlog_error_dbus("failed to append 'RoleSettings' key to role-setting container (%d)", ret);
                return ret;
            }

            ret = ztp1_rolesettings_property_populate_configurator_settings(message, server);
            if (ret < 0) {
                zlog_error_dbus("failed to populate configurator settings to role-settings (%d)", ret);
                return ret;
            }
        }

        ret = sd_bus_message_close_container(message);
        if (ret < 0) {
            zlog_warning_dbus("failed to close role-setting container (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_warning_dbus("failed to close role-setting container (%d)", ret);
        return ret;
    }

    return 0;
}

#define DBUS_DATA_SETTINGS_CHILDREN DBUS_DATA_ROLES_SIGNATURE DBUS_DATA_ROLESETTINGS_SIGNATURE
#define DBUS_DATA_SETTINGS_CHILDREN_R DBUS_DATA_ROLES_SIGNATURE DBUS_DATA_ROLESETTINGS_SIGNATURE_R
#define DBUS_DATA_SETTINGS_SIGNATURE "(" DBUS_DATA_SETTINGS_CHILDREN ")"
#define DBUS_DATA_SETTINGS_SIGNATURE_R "(" DBUS_DATA_SETTINGS_CHILDREN_R ")"

/*
 * @brief Retrieves the service settings.
 *
 * @param bus The bus owning this object.
 * @param path The d-bus path the property is being retrieved from.
 * @param interface The d-bus interface the property is being retrieved from. Must be "com.microsoft.ztp1".
 * @param property The name of the property. Must be "Settings".
 * @param reply The reply message.
 * @param userdata The user context. Must be of type struct ztp_dbus_server.
 * @param error The return value error.
 * @return int The return value. 0 if succeeded, non-zero otherwise.
 */
static int
ztp1_get_settings(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error)
{
    __unused(bus);
    __unused(path);
    __unused(interface);
    __unused(property);

    struct ztp_dbus_server *server = (struct ztp_dbus_server *)userdata;

    int ret = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, DBUS_DATA_SETTINGS_CHILDREN_R);
    if (ret < 0) {
        zlog_error_dbus("failed to open top-level containter in 'Settings' property (%d)", ret);
        return ret;
    }

    {
        ret = ztp1_settings_property_populate_roles(server, reply);
        if (ret < 0) {
            zlog_error_dbus("failed to populate 'Settings' property with device roles (%d)", ret);
            sd_bus_error_set_errno(error, ret);
            return ret;
        }

        ret = ztp1_settings_property_populate_rolesettings(server, reply);
        if (ret < 0) {
            zlog_error_dbus("failed to populate 'Settings' property with role settings (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_close_container(reply);
    if (ret < 0) {
        zlog_warning_dbus("failed to close top-level container for 'Settings' property (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Method to set a device role disposition.
 *
 * @param message The request message.
 * @param userdata The user content. Must be of type struct ztp_dbus_configurator.
 * @param error The error proxy to use.
 * @return int 0 if the method was successfully executed, non-zero otherwise.
 */
static int
ztp1_set_role_disposition(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    struct ztp_dbus_server *server = (struct ztp_dbus_server *)userdata;

    const char *rolestr;
    int ret = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &rolestr);
    if (ret < 0) {
        zlog_error_dbus("failed to read 'role' argument from SetRoleDisposition method (%d)", ret);
        ret = -EINVAL;
        sd_bus_error_set_errno(error, ret);
        return ret;
    }

    const char *action;
    ret = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &action);
    if (ret < 0) {
        zlog_error_dbus("failed to read 'action' argument from SetRoleDisposition method (%d)", ret);
        ret = -EINVAL;
        sd_bus_error_set_errno(error, ret);
        return ret;
    }

    bool activate = strcmp(action, "activate") == 0;
    enum dpp_device_role role = dpp_device_role_parse(rolestr);
    if (role == DPP_DEVICE_ROLE_UNKNOWN) {
        zlog_error_dbus("invalid device role %s specified", rolestr);
        ret = -EINVAL;
        sd_bus_error_set_errno(error, ret);
        return ret;
    }

    ret = ztp_settings_set_device_role_disposition(server->settings, role, activate);
    if (ret < 0) {
        zlog_error_dbus("failed to set role %s disposition to '%s' (%d)", rolestr, action, ret);
    } else if (ret > 0) {
        sd_bus_emit_properties_changed(server->bus, ZTP_DBUS_SERVER_PATH, ZTP_DBUS_SERVER_INTERFACE, "Roles", NULL);
    }

    return sd_bus_reply_method_return(message, "b", ret >= 0);
}

/**
 * @brief Method to set a configurator settings.
 *
 * @param message The request message.
 * @param userdata The user content. Must be of type struct ztp_dbus_server.
 * @param error The error proxy to use.
 * @return int 0 if the method was successfully executed, non-zero otherwise.
 */
static int
ztp1_set_configurator_settings(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    __unused(error);

    bool succeeded = false;
    struct ztp_dbus_server *server = (struct ztp_dbus_server *)userdata;

    struct ztp_configurator_settings settings;
    ztp_configurator_settings_initialize(&settings);

    int ret = ztp1_decode_configurator_settings(message, &settings);
    if (ret < 0) {
        zlog_error_dbus("failed to decode configurator settings (%d)", ret);
        goto out;
    }

    ret = ztp_configurator_settings_persist(server->settings_configurator->path, &settings);
    if (ret < 0) {
        zlog_error_dbus("failed to persist updated configurator settings (%d)", ret);
        goto out;
    }

    ztp_settings_signal_changed(server->settings, ZTP_SETTING_CHANGED_ITEM_CONFIGURATOR_SETTINGS);
    sd_bus_emit_properties_changed(server->bus, ZTP_DBUS_SERVER_PATH, ZTP_DBUS_SERVER_INTERFACE, "Settings", "Configurators", NULL);
    succeeded = true;
out:
    ztp_configurator_settings_uninitialize(&settings);
    return sd_bus_reply_method_return(message, "b", succeeded);
}

/**
 * @brief Virtual table describing methods, properties, and signals of the ZTP
 * d-bus service.
 */
static const sd_bus_vtable vtable_com_microsoft_ztp1[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Configurators", "ao", ztp1_get_configurators, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Roles", "as", ztp1_get_dpp_roles, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Settings", DBUS_DATA_SETTINGS_SIGNATURE_R, ztp1_get_settings, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_METHOD("SetRoleDisposition", "ss", "b", ztp1_set_role_disposition, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("SetConfiguratorSettings", DBUS_DATA_CONFIGURATOR_SIGNATURE, "b", ztp1_set_configurator_settings, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END,
};

/**
 * @brief Updates the current settings instance.
 * 
 * @param server The server control structure to update.
 * @param settings The new settings instance to use.
 */
void
ztp_dbus_server_update_settings(struct ztp_dbus_server *server, struct ztp_settings *settings)
{
    if (server->network_configuration_default) {
        ztp_dbus_network_configuration_manager_unregister(&server->network_configuration_default);
    }

    server->settings = settings;

    struct ztp_device_role_settings_entry *entry;
    list_for_each_entry (entry, &settings->role_settings, list) {
        if (entry->settings.role == DPP_DEVICE_ROLE_CONFIGURATOR) {
            server->settings_configurator = &entry->settings;
            break;
        }
    }

    if (server->settings_configurator) {
        struct dpp_network *network = server->settings_configurator->configurator.network_config_default;
        if (network) {
            int ret = ztp_dbus_network_configuration_manager_register(server->network_configuration_manager, network, &server->network_configuration_default);
            if (ret < 0) {
                zlog_warning("failed to register default network with dbus network configuration manager (%d)", ret);
            }
        }
    }
}

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
ztp_dbus_server_initialize(struct ztp_dbus_server *server, struct ztp_settings *settings, struct ztp_dbus_network_configuration_manager *network_configuration_manager, const char *path)
{
    sd_bus *bus;
    sd_bus_slot *slot_vtable = NULL;

    int ret = sd_bus_default_system(&bus);
    if (ret < 0) {
        zlog_error_dbus("failed to open system bus (%d)", ret);
        return ret;
    }

    ret = sd_bus_add_object_vtable(bus,
        &slot_vtable,
        path,
        ZTP_DBUS_SERVER_INTERFACE,
        vtable_com_microsoft_ztp1,
        server);
    if (ret < 0) {
        zlog_error_dbus("failed to install '%s' object vtable (%d)", ZTP_DBUS_SERVER_INTERFACE, ret);
        return ret;
    }

    ret = sd_bus_request_name(bus, ZTP_DBUS_SERVER_INTERFACE, 0);
    if (ret < 0) {
        zlog_error_dbus("failed to acquire well-known service name '%s' (%d)", ZTP_DBUS_SERVER_INTERFACE, ret);
        return ret;
    }

    explicit_bzero(server, sizeof *server);
    server->bus = bus;
    server->slot_vtable = slot_vtable;
    server->network_configuration_manager = network_configuration_manager;
    INIT_LIST_HEAD(&server->configurators);

    ztp_dbus_server_update_settings(server, settings);

    return ret;
}

/**
 * @brief Uninitializes a previously initialized d-bus server.
 *
 * @param server The server control structure that was previously filled in by
 * ztp_dbus_server_initialize.
 */
void
ztp_dbus_server_uninitialize(struct ztp_dbus_server *server)
{
    if (!server)
        return;

    if (server->configurators.next != NULL) {
        struct ztp_dbus_configurator *entry;
        struct ztp_dbus_configurator *tmp;
        list_for_each_entry_safe (entry, tmp, &server->configurators, list) {
            list_del(&entry->list);
            free(entry);
        }
    }

    ztp_dbus_network_configuration_manager_destroy(&server->network_configuration_manager);

    if (server->slot_vtable) {
        sd_bus_slot_unref(server->slot_vtable);
        server->slot_vtable = NULL;
    }

    if (server->bus) {
        sd_bus_unref(server->bus);
        server->bus = NULL;
    }
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif //__clang_
