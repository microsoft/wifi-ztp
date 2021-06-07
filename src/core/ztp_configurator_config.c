
#include <errno.h>
#include <json-c/json_util.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <userspace/linux/compiler.h>
#include <userspace/linux/kernel.h>

#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps_config.h"
#include "bootstrap_info_provider_file_config.h"
#include "bootstrap_info_provider_settings.h"
#include "file_utils.h"
#include "json_parse.h"
#include "string_utils.h"
#include "ztp_configurator.h"
#include "ztp_configurator_config.h"
#include "ztp_log.h"

/**
 * @brief Json object key names for bootstrap info.
 */
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO "bootstrap.info"
#define JSON_PROPERTY_NAME_BI_EXPIRATION_TIME "expirationTime"
#define JSON_PROPERTY_NAME_BI_PROVIDERS "providers"
#define JSON_PROPERTY_NAME_BI_COMMON_TYPE "type"
#define JSON_PROPERTY_NAME_BI_COMMON_NAME "name"
#define JSON_PROPERTY_NAME_BI_COMMON_EXPIRATION_TIME "expirationTime"

/**
 * @brief Json object key names for network configuration.
 */
#define JSON_PROPERTY_NAME_NET_CFG "network.configuration"
#define JSON_PROPERTY_NAME_NET_CFG_DEFAULT "default"
#define JSON_PROPERTY_NAME_NET_CFG_DISCOVERY "discovery"
#define JSON_PROPERTY_NAME_NET_CFG_DISCOVERY_SSID "ssid"
#define JSON_PROPERTY_NAME_NET_CFG_DISCOVERY_SSID_CHARSET "ssidCharset"
#define JSON_PROPERTY_NAME_NET_CFG_CREDENTIALS "credentials"
#define JSON_PROPERTY_NAME_CREDENTIAL_AKM "akm"
#define JSON_PROPERTY_NAME_CREDENTIAL_PSK "psk"
#define JSON_PROPERTY_NAME_CREDENTIAL_PASSPHRASE "passphrase"

/**
 * @brief Parser for the global "expirationTime" property for the "bootstrap.info" object.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "expirationTime".
 * @param jobj The json property value. Must be of type 'json_type_int'.
 * @param context The configurator settings object instance.
 */
static void
json_parse_expiration_time(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct ztp_configurator_settings *settings = (struct ztp_configurator_settings *)context;

    int32_t expiration_time = json_object_get_int(jobj);
    if (expiration_time <= 0) {
        zlog_warning("expirationTime must be > 0");
        return;
    }

    settings->expiration_time = (uint32_t)expiration_time;
}

/**
 * @brief Parser for the "type" property of a bootstrapping information
 * provider
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "type".
 * @param jobj The json property value. Must be of type json_type_string.
 * @param context The provider settings object instance.
 */
static void
json_parse_provider_type(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct bootstrap_info_provider_settings *settings = (struct bootstrap_info_provider_settings *)context;

    const char *value = json_object_get_string(jobj);
    enum bootstrap_info_provider_type type = parse_bootstrap_info_provider_type(value);
    if (type == BOOTSTRAP_INFO_PROVIDER_INVALID) {
        zlog_warning("unrecognized bootstrap info provider type '%s', ignoring", value);
        return;
    }

    settings->type = type;
}

/**
 * @brief Parser for the "name" property of a bootstrapping information
 * provider
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "name".
 * @param jobj The json property value. Must be of type json_type_string.
 * @param context The provider settings object instance.
 */
static void
json_parse_provider_name(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct bootstrap_info_provider_settings *settings = (struct bootstrap_info_provider_settings *)context;

    char *value = strdup(json_object_get_string(jobj));
    if (!value) {
        zlog_warning("allocation failure for bootstrap info provider name");
        return;
    }

    if (settings->name)
        free(settings->name);
    settings->name = value;
}

/**
 * @brief Parser for the "expirationTime" property of a bootstrapping
 * information provider.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must ne "expirationTime".
 * @param jobj The json value. Must be of type 'json_type_int'.
 * @param context The provider settings object instance.
 */
static void
json_parse_provider_expiration_time(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct bootstrap_info_provider_settings *settings = (struct bootstrap_info_provider_settings *)context;

    int32_t expiration_time = json_object_get_int(jobj);
    if (expiration_time <= 0) {
        zlog_warning("expirationTime must be > 0");
        return;
    }

    settings->expiration_time = (uint32_t)expiration_time;
}

/**
 * @brief Configurator 'providers' entry configuration options. This describes
 * the shared/common properties. All provider-specific properties are ignored.
 */
static struct json_property_parser configurator_config_provider_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_BI_COMMON_TYPE,
        .type = json_type_string,
        .value = {
            json_parse_provider_type,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_BI_COMMON_NAME,
        .type = json_type_string,
        .value = {
            json_parse_provider_name,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_BI_EXPIRATION_TIME,
        .type = json_type_int,
        .value = {
            json_parse_provider_expiration_time,
        },
    }
};

/**
 * @brief Parses a "providers" property value describing bootstrapping information provider settings.
 *
 * @param parent The parent object.
 * @param array The containing array object.
 * @param name The name of the parent json property. Must be "providers".
 * @param jobj The json value for the array entry.
 * @param index The index of the json value.
 * @param type The type of the json value. Must be json_type_object.
 * @param context The configurator settings object instance.
 */
static void
json_parse_providers(struct json_object *parent, struct json_object *array, const char *name, struct json_object *jobj, uint32_t index, json_type type, void *context)
{
    __unused(parent);
    __unused(array);
    __unused(name);
    __unused(index);
    __unused(type);

    struct ztp_configurator_settings *settings = (struct ztp_configurator_settings *)context;

    struct bootstrap_info_provider_settings *provider = bootstrap_info_provider_settings_alloc();
    if (!provider) {
        zlog_warning("allocation failure for bootstrap info provider");
        return;
    }

    json_parse_object_s(jobj, configurator_config_provider_properties, provider);

    if (provider->type == BOOTSTRAP_INFO_PROVIDER_INVALID ||
        provider->name == NULL ||
        provider->name[0] == '\0') {
        zlog_warning("invalid bootstrap info provider found, ignoring");
        goto fail;
    }

    switch (provider->type) {
        case BOOTSTRAP_INFO_PROVIDER_FILE: {
            struct bootstrap_info_provider_file_settings *file = calloc(1, sizeof *file);
            if (!file) {
                zlog_error("failed to allocate memory for file-based bootstrap info provider settings");
                goto fail;
            }

            int ret = bootstrap_info_provider_file_config_parse_jobj(jobj, file);
            if (ret < 0) {
                zlog_warning("failed to parse file-based bootstrap info provider settings (%d)", ret);
                free(file);
                goto fail;
            }

            provider->file = file;
            break;
        }
        case BOOTSTRAP_INFO_PROVIDER_AZUREDPS: {
            struct bootstrap_info_provider_azure_dps_settings *dps = calloc(1, sizeof *dps);
            if (!dps) {
                zlog_error("failed to allocate memory for azuredps-based bootstrap info provider settings");
                goto fail;
            }

            int ret = bootstrap_info_provider_azure_dps_config_parse_jobj(jobj, dps);
            if (ret < 0) {
                zlog_warning("failed to parse azuredps-based bootstrap info provider settings (%d)", ret);
                free(dps);
                goto fail;
            }

            provider->dps = dps;
            break;
        }
        default:
            break;
    }

    ztp_configurator_settings_add_bi_provider_settings(settings, provider);
    return;

fail:
    bootstrap_info_provider_settings_uninitialize(provider);
    free(provider);
}

/**
 * @brief Configurator top-level configuration file options.
 */
static struct json_property_parser configurator_bootstrap_info_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_BI_EXPIRATION_TIME,
        .type = json_type_int,
        .value = {
            json_parse_expiration_time,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_BI_PROVIDERS,
        .type = json_type_array,
        .array = {
            json_parse_providers,
            json_type_object,
        },
    },
};

/**
 * @brief Parser for the "bootstrap.info" configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "bootstrap.info".
 * @param jobj The json value of the bootstrap info property.
 * @param context The configurator settings object instance.
 */
static void
json_parse_bootstrap_info(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_parse_object_s(jobj, configurator_bootstrap_info_properties, context);
}

/**
 * @brief Encodes bootstrap info provider decoding info property map as json.
 * 
 * @param file The bootstrap file info provider settings.
 * @param jpropertymap Output argument that will hold the property map object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put. 
 * @return int 
 */
static int
json_encode_bootstrap_info_provider_file_decodinginfo_propertymap(const struct bootstrap_info_provider_file_settings *file, struct json_object **jpropertymap)
{
    int ret;
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate new json object for file bootstrap info provider decoding info property map");
        return -ENOMEM;
    }

    struct json_object *dpp_uri = json_object_new_string(file->json_key_dpp_uri);
    if (!dpp_uri) {
        zlog_error("failed to encode json dpp uri for file bootstrap info provider decoding info property map");
        json_object_put(jobj);
        ret = -EBADMSG;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_DPP_URI, dpp_uri);
    if (ret < 0) {
        zlog_error("failed to add dpp uri to file bootstrap info provider decodoing info property map (%d)", ret);
        json_object_put(dpp_uri);
        goto fail;
    }

    struct json_object *pkhash = json_object_new_string(file->json_key_publickeyhash);
    if (!pkhash) {
        zlog_error("failed to encode json public key hash for file bootstrap info provider decoding info property map");
        ret = -EBADMSG;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_PUBLIC_KEY_HASH, pkhash);
    if (ret < 0) {
        zlog_error("failed to add public key hash to file bootstrap info provider decodoing info property map (%d)", ret);
        json_object_put(pkhash);
        goto fail;
    }

    *jpropertymap = jobj;
out:
    return ret;
fail:
    if (jobj)
        json_object_put(jobj);
    goto out;
}

/**
 * @brief Encodes bootstrap file info provider decoding info as a json object.
 * 
 * @param file The bootstrap file info provider settings.
 * @param jdecoding_info Output argument that will hold the decoding info object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put.
 * @return int 0 if encoding was successful, non-zero otherwise.
 */
static int
json_encode_bootstrap_info_provider_file_decodinginfo(const struct bootstrap_info_provider_file_settings *file, struct json_object **jdecoding_info)
{
    int ret;
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate new json object for file bootstrap info provider decoding info");
        return -ENOMEM;
    }

    struct json_object *pointer_array = json_object_new_string(file->json_pointer_array);
    if (!pointer_array) {
        zlog_error("failed to encode json pointer array for file bootstrap info provider decoding info");
        ret = -EBADMSG;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_JSON_PTR, pointer_array);
    if (ret < 0) {
        zlog_error("failed to add pointer array to file bootstrap info provider decodoing info json (%d)", ret);
        goto fail;
    }

    struct json_object *pointer_base = json_object_new_string(file->json_pointer_object_base);
    if (!pointer_base) {
        zlog_error("failed to encode json pointer base for file bootstrap info provider decoding info");
        ret = -EBADMSG;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_JSON_PTR_BASE, pointer_base);
    if (ret < 0) {
        zlog_error("failed to add pointer base to file bootstrap info provider decoding info json (%d)", ret);
        goto fail;
    }

    struct json_object *property_map;
    ret = json_encode_bootstrap_info_provider_file_decodinginfo_propertymap(file, &property_map);
    if (ret < 0) {
        zlog_error("failed to encode file bootstrap info provider decoding info property map (%d)", ret);
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_PROPERTY_MAP, property_map);
    if (ret < 0) {
        zlog_error("failed to add property map to file bootstrap info provider decoding info (%d)", ret);
        json_object_put(property_map);
        goto fail;
    }

    *jdecoding_info = jobj;

out:
    return ret;
fail:
    if (jobj)
        json_object_put(jobj);
    goto out;
}

/**
 * @brief Encodes file-base bootstrap info provider settings to json.
 * 
 * @param file The file bootstrap info provider settings to encode. 
 * @param jobj The json object to append the settings to.
 * @return int 0 if all settings were appended successfully, non-zero otherwise.
 */
static int
json_encode_bootstrap_info_provider_file(const struct bootstrap_info_provider_file_settings *file, struct json_object *jobj)
{
    struct json_object *path = json_object_new_string(file->path);
    if (!path) {
        zlog_error("failed to encode file bootstrap info provider name to json");
        return -EBADMSG;
    }

    int ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_PATH, path);
    if (ret < 0) {
        zlog_error("failed to add path to file bootstrap info provider json (%d)", ret);
        json_object_put(path);
        return ret;
    }

    struct json_object *decoding_info;
    ret = json_encode_bootstrap_info_provider_file_decodinginfo(file, &decoding_info);
    if (ret < 0) {
        zlog_error("failed to encode file bootstrap info provider decoding info (%d)", ret);
        return ret;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_DECODING_INFO, decoding_info);
    if (ret < 0) {
        zlog_error("failed to add decoding info to file bootstrap info provider (%d)", ret);
        json_object_put(decoding_info);
        return ret;
    }

    return 0;
}

/**
 * @brief Encodes azure dps bootstrap info provider authentication info as json.
 * 
 * @param dps The azure dps bootstrap info provider settings.
 * @param jauth Output argument that will hold the authentication info object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put.
 * @return int 0 if encoding succeeded, non-zero otherwise.
 */
static int
json_encode_bootstrap_info_provider_azuredps_auth(const struct bootstrap_info_provider_azure_dps_settings *dps, struct json_object **jauth)
{
    int ret;
    const struct {
        const char *name;
        const char *value;
    } props[] = {
        { JSON_PROPERTY_NAME_AUTHORITY_URL, dps->authority_url },
        { JSON_PROPERTY_NAME_CLIENT_ID, dps->client_id },
        { JSON_PROPERTY_NAME_CLIENT_SECRET, dps->client_secret },
        { JSON_PROPERTY_NAME_RESOURCE_URI, dps->resource_uri },
        { JSON_PROPERTY_NAME_CONNECTION_STRING, dps->connection_string },
    };

    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate memory for azure dps bootstrap info provider auth json");
        ret = -ENOMEM;
        goto fail;
    }

    for (size_t i = 0; i < ARRAY_SIZE(props); i++) {
        struct json_object *value = json_object_new_string(props[i].value);
        if (!value) {
            zlog_error("failed to encode azure dps bootstrap info provider %s as json", props[i].name);
            ret = -EBADMSG;
            goto fail;
        }

        ret = json_object_object_add(jobj, props[i].name, value);
        if (ret < 0) {
            zlog_error("failed to add azure dps bootstrap info provider %s", props[i].name);
            json_object_put(value);
            goto fail;
        }
    }

    *jauth = jobj;
    ret = 0;
out:
    return ret;
fail:
    if (jobj)
        json_object_put(jobj);
    goto out;
}

/**
 * @brief Encodes azure dps bootstrap info provider settings as json.
 * 
 * @param dps The azure dps bootstrap info provider settings.
 * @param jobj The json object to append to.
 * @return int 0 if encoding succeeded, non-zero otherwise.
 */
static int
json_encode_bootstrap_info_provider_azuredps(const struct bootstrap_info_provider_azure_dps_settings *dps, struct json_object *jobj)
{
    json_object *service_endpoint_uri = json_object_new_string(dps->service_endpoint_uri);
    if (!service_endpoint_uri) {
        zlog_error("failed to encode azure dps bootstrap info provider service endpoint uri");
        return -EBADMSG;
    }

    int ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_SERVICE_ENDPOINT_URI, service_endpoint_uri);
    if (ret < 0) {
        zlog_error("failed to add azure dps bootstrap info provider service endpoint uri to json (%d)", ret);
        json_object_put(service_endpoint_uri);
        return ret;
    }

    struct json_object *auth;
    ret = json_encode_bootstrap_info_provider_azuredps_auth(dps, &auth);
    if (ret < 0) {
        zlog_error("failed to encode azure dps bootstrap info provider auth (%d)", ret);
        return ret;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_AUTHENTICATION, auth);
    if (ret < 0) {
        zlog_error("failed to add azure dps bootstrap info provider auth to json (%d)", ret);
        json_object_put(auth);
        return ret;
    }

    return 0;
}

/**
 * @brief Encodes bootstrap info provider settings to json.
 * 
 * @param provider The provider settings to encode.
 * @param jprovider Output argument that will hold the bootstrap info object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put.
 * @return int 
 */
static int
json_encode_bootstrap_info_provider(const struct bootstrap_info_provider_settings *provider, struct json_object **jprovider)
{
    int ret;
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate json object for bootstrap info provider)");
        return -ENOMEM;
    }

    struct json_object *type = json_object_new_string(bootstrap_info_provider_type_str(provider->type));
    if (!type) {
        zlog_error("failed to encode bootstrap info provider type for json object");
        ret = -EBADMSG;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_BI_COMMON_TYPE, type);
    if (ret < 0) {
        zlog_error("failed to add type to bootstrap info provider object (%d)", ret);
        json_object_put(type);
        goto fail;
    }

    struct json_object *name = json_object_new_string(provider->name ? provider->name : "default");
    if (!name) {
        zlog_error("failed to encode bootstrap info provider name for json object");
        ret = -EBADMSG;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_BI_COMMON_NAME, name);
    if (ret < 0) {
        zlog_error("failed to add name to bootstrap info provider object (%d)", ret);
        json_object_put(name);
        goto fail;
    }

    if (provider->expiration_time != BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET) {
        struct json_object *expiration_time = json_object_new_int((int32_t)provider->expiration_time);
        if (!expiration_time) {
            zlog_error("failed to encode bootstrap info provider expiration time");
            ret = -EBADMSG;
            goto fail;
        }

        ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_BI_COMMON_EXPIRATION_TIME, expiration_time);
        if (ret < 0) {
            zlog_error("failed to add expiratin time to bootstrap info provider object (%d)", ret);
            json_object_put(expiration_time);
            goto fail;
        }
    }

    switch (provider->type) {
        case BOOTSTRAP_INFO_PROVIDER_FILE: {
            ret = json_encode_bootstrap_info_provider_file(provider->file, jobj);
            if (ret < 0) {
                zlog_error("failed to encode file bootstrap info provider settings as json (%d)", ret);
                goto fail;
            }
            break;
        }
        case BOOTSTRAP_INFO_PROVIDER_AZUREDPS: {
            ret = json_encode_bootstrap_info_provider_azuredps(provider->dps, jobj);
            if (ret < 0) {
                zlog_error("failed to encode azure dps bootstrap info provider settings as json (%d)", ret);
                goto fail;
            }
            break;
        }
        default: {
            zlog_error("unsupported bootstrap info provider type for json encoding");
            ret = -EOPNOTSUPP;
            goto fail;
        }
    }

    *jprovider = jobj;
out:
    return ret;
fail:
    if (jobj)
        json_object_put(jobj);
    goto out;
}

/**
 * @brief Encodes bootstrap information providers to a json array.
 * 
 * @param settings The ztp configurator settings to source the bootstrap info provider settings from.
 * @param jbootstrap_info_providers  Output argument that will hold the bootstrap info providers array.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put.
 * @return int 0 if the encoding eas successful, non-zero otherwise.
 */
static int
json_encode_bootstrap_info_providers(const struct ztp_configurator_settings *settings, struct json_object **jproviders)
{
    int ret;
    json_object *obj = json_object_new_array();
    if (!obj) {
        zlog_error("failed to allocate new json array for bootstrap info providers");
        return -ENOMEM;
    }

    struct json_object *jprovider;
    struct bootstrap_info_provider_settings *provider;
    list_for_each_entry (provider, &settings->provider_settings, list) {
        ret = json_encode_bootstrap_info_provider(provider, &jprovider);
        if (ret < 0) {
            zlog_error("failed to encode bootstrap info provider for json (%d)", ret);
            goto fail;
        }

        ret = json_object_array_add(obj, jprovider);
        if (ret < 0) {
            zlog_error("failed to add bootstrap info provider to json array (%d)", ret);
            json_object_put(jprovider);
            goto fail;
        }
    }

    *jproviders = obj;
out:
    return ret;
fail:
    if (jproviders)
        json_object_put(obj);
    goto out;
}

/**
 * @brief Encodes the configurator bootstrap info provider details.
 * 
 * @param settings The configurator object to source bootstrap info details from.
 * @param jbootstrap_info  Output argument that will hold the bootstrap info object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put.
 * @return int 0 if the encoding was successful, non-zero otherwise.
 */
static int
json_encode_bootstrap_info(const struct ztp_configurator_settings *settings, struct json_object **jbootstrap_info)
{
    int ret;
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate new json bootstrap info object");
        return -ENOMEM;
    }

    if (settings->expiration_time != BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET) {
        struct json_object *expiration_time = json_object_new_int((int32_t)settings->expiration_time);
        if (!expiration_time) {
            zlog_error("failed to encode bootstrap info expiration time for json");
            ret = -EBADMSG;
            goto fail;
        }

        ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_BI_EXPIRATION_TIME, expiration_time);
        if (ret < 0) {
            zlog_error("failed to add expiration time to bootstrap info json object (%d)", ret);
            json_object_put(expiration_time);
            goto fail;
        }
    }

    struct json_object *jproviders;
    ret = json_encode_bootstrap_info_providers(settings, &jproviders);
    if (ret < 0) {
        zlog_error("failed to encode bootstrap info providers for json (%d)", ret);
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_BI_PROVIDERS, jproviders);
    if (ret < 0) {
        zlog_error("failed to add bootstrap info providers array to bootstrap info object (%d)", ret);
        json_object_put(jproviders);
        goto fail;
    }

    *jbootstrap_info = jobj;
out:
    return ret;
fail:
    json_object_put(jobj);
    goto out;
}

/**
 * @brief Encodes a psk-based network credential as json, appending it to the
 * passed in json object.
 * 
 * @param psk The psk to encode.
 * @param jobj The psk-based network credential to append to.
 * @return int 0 if the psk-based credential fields were encoded, non-zero otherwise.
 */
static int
json_encode_network_credential_psk(const struct dpp_network_credential_psk *psk, struct json_object *jobj)
{
    int ret;

    switch (psk->type) {
        case PSK_CREDENTIAL_TYPE_PSK: {
            struct json_object *keyhex = json_object_new_string(psk->key.hex);
            if (!keyhex) {
                zlog_error("failed to encode psk value for psk network credential json object");
                return -EBADMSG;
            }

            ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_CREDENTIAL_PSK, keyhex);
            if (ret < 0) {
                zlog_error("failed to add psk value for psk network credential json object (%d)", ret);
                json_object_put(keyhex);
                return ret;
            }
            break;
        }
        case PSK_CREDENTIAL_TYPE_PASSPHRASE: {
            struct json_object *passphrase = json_object_new_string(psk->passphrase.ascii);
            if (!passphrase) {
                zlog_error("failed to encode passphrase for psk network credential json object");
                return -EBADMSG;
            }

            ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_CREDENTIAL_PASSPHRASE, passphrase);
            if (ret < 0) {
                zlog_error("failed to add passphrase for psk network credential json object (%d)", ret);
                json_object_put(passphrase);
                return ret;
            }
            break;
        }
        default: {
            zlog_error("unsupported psk type for json psk credential encoding");
            return -EOPNOTSUPP;
        }
    }

    return 0;
}

/**
 * @brief Encodes an sae-based network credential as json, appending it to the
 * passed in json object.
 * 
 * @param The sae to encode.
 * @param jobj The sae-based network credential to append to.
 * @return int 0 if the sae-based credential fields were encoded, non-zero otherwise.
 */
static int
json_encode_network_credential_sae(const struct dpp_network_credential_sae *sae, struct json_object *jobj)
{
    int ret;

    struct json_object *passphrase = json_object_new_string(sae->passphrase);
    if (!passphrase) {
        zlog_error("failed to encode passphrase for sae network credential json object");
        return -EBADMSG;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_CREDENTIAL_PASSPHRASE, passphrase);
    if (ret < 0) {
        zlog_error("failed to add passphrase for sae network credential json object (%d)", ret);
        json_object_put(passphrase);
        return ret;
    }

    return 0;
}

/**
 * @brief Encodes a network credential as json.
 * 
 * @param credential The credential to encode.
 * @param jcredential Output argument that will hold the credential object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put.
 * @return int 
 */
static int
json_encode_network_credential(const struct dpp_network_credential *credential, struct json_object **jcredential)
{
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate json object for network credential");
        return -ENOMEM;
    }

    int ret;
    if (!dpp_network_credential_is_valid(credential)) {
        zlog_error("invalid credential found during network json encoding");
        ret = -EINVAL;
        goto fail;
    }

    struct json_object *akm = json_object_new_string(dpp_akm_str(credential->akm));
    if (!akm) {
        zlog_error("failed to encode network credential akm for json object");
        ret = -EBADMSG;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_CREDENTIAL_AKM, akm);
    if (ret < 0) {
        zlog_error("failed to add akm to network credential json object (%d)", ret);
        json_object_put(akm);
        goto fail;
    }

    switch (credential->akm) {
        case DPP_AKM_PSK: {
            ret = json_encode_network_credential_psk(&credential->psk, jobj);
            if (ret < 0) {
                zlog_error("failed to encode network psk for json object (%d)", ret);
                goto fail;
            }
            break;
        }
        case DPP_AKM_SAE: {
            ret = json_encode_network_credential_sae(&credential->sae, jobj);
            if (ret < 0) {
                zlog_error("failed to encode network sae for json object (%d)", ret);
                goto fail;
            }
            break;
        }
        default: {
            zlog_error("unsupported network credential akm for network credential json encoding");
            ret = -EOPNOTSUPP;
            goto fail;
        }
    }

    *jcredential = jobj;
out:
    return ret;
fail:
    json_object_put(jobj);
    goto out;
}

/**
 * @brief Parser for the "akm" configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "akm".
 * @param jobj The json value of the 'akm' property.
 * @param context The configurator settings object instance.
 */
static void
json_parse_credential_akm(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct dpp_network_credential *credential = (struct dpp_network_credential *)context;

    const char *value = json_object_get_string(jobj);
    enum dpp_akm akm = parse_dpp_akm(value);
    if (akm == DPP_AKM_INVALID) {
        zlog_warning("invalid dpp akm '%s', ignoring credential", value);
        return;
    }

    credential->akm = akm;
}

/**
 * @brief Parser for the "psk" configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "psk".
 * @param jobj The json value of the 'psk' property.
 * @param context The configurator settings object instance.
 */
static void
json_parse_credential_psk(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct dpp_network_credential *credential = (struct dpp_network_credential *)context;
    struct dpp_network_credential_psk *psk = &credential->psk;

    const char *key_hex = json_object_get_string(jobj);

    int ret = dpp_credential_psk_set_key(psk, key_hex);
    if (ret < 0) {
        zlog_error("failed to set credential pre-shared key (%d)", ret);
        return;
    }

    psk->type = PSK_CREDENTIAL_TYPE_PSK;
}

/**
 * @brief Parser for the "passphrase" configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "passphrase".
 * @param jobj The json value of the 'passphrase' property.
 * @param context The configurator settings object instance.
 */
static void
json_parse_credential_passphrase(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct dpp_network_credential *credential = (struct dpp_network_credential *)context;
    const char *passphrase = json_object_get_string(jobj);

    switch (credential->akm) {
        case DPP_AKM_PSK: {
            struct dpp_network_credential_psk *psk = &credential->psk;
            int ret = dpp_credential_psk_set_passphrase(psk, passphrase);
            if (ret < 0) {
                zlog_warning("failed to set passphrase for psk credential (%d)", ret);
                return;
            }
            psk->type = PSK_CREDENTIAL_TYPE_PASSPHRASE;
            break;
        }
        case DPP_AKM_SAE: {
            struct dpp_network_credential_sae *sae = &credential->sae;
            int ret = dpp_credential_sae_set_passphrase(sae, passphrase);
            if (ret < 0) {
                zlog_warning("failed to set passphrase for sae credential (%d)", ret);
                return;
            }
            break;
        }
        default: {
            zlog_warning("ignoring 'passphrase' property for non-psk/sae credential");
            return;
        }
    }
}

/**
 * @brief DPP "credential" network property configuration file options.
 */
static struct json_property_parser credential_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_CREDENTIAL_AKM,
        .type = json_type_string,
        .value = {
            json_parse_credential_akm,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_CREDENTIAL_PSK,
        .type = json_type_string,
        .value = {
            json_parse_credential_psk,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_CREDENTIAL_PASSPHRASE,
        .type = json_type_string,
        .value = {
            json_parse_credential_passphrase,
        },
    },
};

/**
 * @brief Function to parse "credentials" network option.
 *
 * @param parent The parent object.
 * @param array The containing array object.
 * @param name The name of the parent object ("credentials").
 * @param jobj The array element value.
 * @param index The array element index.
 * @param type The type of the array element (json_type_object).
 * @param context The configurator settings object instance.
 */
static void
json_parse_network_credentials(struct json_object *parent, struct json_object *array, const char *name, struct json_object *jobj, uint32_t index, json_type type, void *context)
{
    __unused(parent);
    __unused(array);
    __unused(name);
    __unused(index);
    __unused(type);

    struct dpp_network *network = (struct dpp_network *)context;
    struct dpp_network_credential *credential = dpp_network_credential_alloc();
    if (!credential) {
        zlog_warning("allocation failure for network credential");
        return;
    }

    json_parse_object_s(jobj, credential_properties, credential);

    if (!dpp_network_credential_is_valid(credential)) {
        zlog_warning("invalid network credential specified");
        dpp_network_credential_uninitialize(credential);
        free(credential);
        return;
    }

    dpp_network_add_credential(network, credential);
}

/**
 * @brief Encodes network credentials as a json array.
 * 
 * @param network The network with the credentials to encode.
 * @param jcredentials Output argument that will hold the credentials object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put. 
 * @return int 
 */
static int
json_encode_network_credentials(const struct dpp_network *network, struct json_object **jcredentials)
{
    int ret;
    json_object *credentials = json_object_new_array();
    if (!credentials) {
        zlog_error("failed to allocate json array for network credentials");
        return -ENOMEM;
    }

    struct json_object *jcredential;
    struct dpp_network_credential *credential;
    list_for_each_entry (credential, &network->credentials, list) {
        ret = json_encode_network_credential(credential, &jcredential);
        if (ret < 0) {
            zlog_error("failed to encode network credential for json network object (%d)", ret);
            goto fail;
        }

        ret = json_object_array_add(credentials, jcredential);
        if (ret < 0) {
            zlog_error("failed to add network credential to json credentials array (%d)", ret);
            json_object_put(jcredential);
            goto fail;
        }
    }

    *jcredentials = credentials;
out:
    return ret;
fail:
    json_object_put(credentials);
    goto out;
}

/**
 * @brief Parser for the "ssid" network discovery configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "ssid".
 * @param jobj The json value of the ssid property.
 * @param context The configurator settings object instance.
 */
static void
json_parse_network_discovery_ssid(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct dpp_network_discovery *discovery = (struct dpp_network_discovery *)context;

    const char *ssid = json_object_get_string(jobj);
    size_t ssid_length = strlen(ssid) /* + 1 */;
    if (ssid_length > (sizeof discovery->ssid)) {
        zlog_warning("ssid length (%lu) exceeds maximum length (%lu)", ssid_length, sizeof discovery->ssid);
        return;
    }

    memcpy(discovery->ssid, ssid, ssid_length);
    discovery->ssid_length = ssid_length;
}

/**
 * @brief Parser for the "ssidCharset" network discovery configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "ssidCharset".
 * @param jobj The json value. Must be of type 'json_type_int'.
 * @param context The provider settings object instance.
 */
static void
json_parse_network_discovery_ssid_charset(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct dpp_network_discovery *discovery = (struct dpp_network_discovery *)context;
    discovery->ssid_charset = json_object_get_int(jobj);
}

/**
 * @brief DPP "discovery" network property configuration file options.
 */
static struct json_property_parser network_discovery_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_NET_CFG_DISCOVERY_SSID,
        .type = json_type_string,
        .value = {
            json_parse_network_discovery_ssid,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_NET_CFG_DISCOVERY_SSID_CHARSET,
        .type = json_type_int,
        .value = {
            json_parse_network_discovery_ssid_charset,
        },
    },
};

/**
 * @brief Parser for the "discovery" network option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "discovery".
 * @param jobj The json value of the 'discovery' property.
 * @param context The configurator settings object instance.
 */
static void
json_parse_network_discovery(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_parse_object_s(jobj, network_discovery_properties, context);
}

/**
 * @brief Encodes network discovery information as json.
 * 
 * @param discovery The network discovery to encode.
 * @param jdiscovery Output argument that will hold the discovery object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put. 
 * @return int 
 */
static int
json_encode_network_discovery(const struct dpp_network_discovery *discovery, struct json_object **jdiscovery)
{
    int ret;
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate a new network discovery json object");
        return -ENOMEM;
    }

    struct json_object *ssid = json_object_new_string((const char *)discovery->ssid);
    if (!ssid) {
        zlog_error("failed to allocate json string for network discovery ssid");
        ret = -ENOMEM;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_NET_CFG_DISCOVERY_SSID, ssid);
    if (ret < 0) {
        json_object_put(ssid);
        zlog_error("failed to add ssid to network discovery json object (%d)", ret);
        goto fail;
    }

    struct json_object *ssid_charset = json_object_new_int(discovery->ssid_charset);
    if (!ssid_charset) {
        zlog_error("failed to encode ssid charset for network discovery json");
        ret = -EBADMSG;
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_NET_CFG_DISCOVERY_SSID_CHARSET, ssid_charset);
    if (ret < 0) {
        zlog_error("failed to add ssid charset to network discovery json object (%d)", ret);
        json_object_put(ssid_charset);
        goto fail;
    }

    *jdiscovery = jobj;
out:
    return ret;
fail:
    if (jobj)
        json_object_put(jobj);
    goto out;
}

/**
 * @brief DPP "network" property configuration file options.
 */
static struct json_property_parser network_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_NET_CFG_DISCOVERY,
        .type = json_type_object,
        .value = {
            json_parse_network_discovery,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_NET_CFG_CREDENTIALS,
        .type = json_type_array,
        .array = {
            json_parse_network_credentials,
            json_type_object,
        },
    },
};

/**
 * @brief Parser for the "default" network configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "default".
 * @param jobj The json value of the 'default' property.
 * @param context The configurator settings object instance.
 */
static void
json_parse_network_default(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct ztp_configurator_settings *settings = (struct ztp_configurator_settings *)context;

    struct dpp_network *network = dpp_network_alloc();
    if (!network) {
        zlog_warning("allocation failure for defaultNetwork");
        return;
    }

    json_parse_object_s(jobj, network_properties, network);

    if (!dpp_network_is_valid(network)) {
        zlog_warning("invalid defaultNetwork specified");
        dpp_network_uninitialize(network);
        free(network);
        return;
    }

    settings->network_config_default = network;
}

/**
 * @brief Encodes the default network as a json object.
 * 
 * @param settings The configurator settings to source the default network object from.
 * @param jnetwork Output argument that will hold the default network object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put. 
 * @return int 0 if the object was created, non-zero otherwise.
 */
static int
json_encode_network(const struct dpp_network *network, struct json_object **jnetwork)
{
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate new network json object");
        return -ENOMEM;
    }

    struct json_object *discovery;
    int ret = json_encode_network_discovery(&network->discovery, &discovery);
    if (ret < 0) {
        zlog_error("failed to encode network discovery for network json object (%d)", ret);
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_NET_CFG_DISCOVERY, discovery);
    if (ret < 0) {
        zlog_error("failed to add network discovery to network json object (%d)", ret);
        json_object_put(discovery);
        goto fail;
    }

    struct json_object *network_credentials;
    ret = json_encode_network_credentials(network, &network_credentials);
    if (ret < 0) {
        zlog_error("failed to encode network credentials for network json object (%d)", ret);
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_NET_CFG_CREDENTIALS, network_credentials);
    if (ret < 0) {
        zlog_error("failed to add network credential to network jonect object (%d)", ret);
        json_object_put(network_credentials);
        goto fail;
    }

    *jnetwork = jobj;
out:
    return ret;
fail:
    if (jobj)
        json_object_put(jobj);
    goto out;
}

/**
 * @brief Encodes ztp network configuration information as json. 
 * 
 * @param settings The ztp settings.
 * @param jnetwork_configuration Output argument that will hold the network object.
 * The caller owns the object and is responsible for freeing it by calling
 * json_object_put. 
 * @return int 
 */
static int
json_encode_network_configuration(const struct ztp_configurator_settings *settings, struct json_object **jnetwork_configuration)
{
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to allocate new json object for network configuration");
        return -ENOMEM;
    }

    struct json_object *default_network = NULL;
    int ret = json_encode_network(settings->network_config_default, &default_network);
    if (ret < 0) {
        zlog_error("failed to encode default network (%d)", ret);
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_NET_CFG_DEFAULT, default_network);
    if (ret < 0) {
        zlog_error("failed to add '" JSON_PROPERTY_NAME_NET_CFG_DEFAULT "' property to configurator json (%d)", ret);
        json_object_put(default_network);
        goto fail;
    }

    *jnetwork_configuration = jobj;
out:
    return ret;
fail:
    if (jobj)
        json_object_put(jobj);
    goto out;
}

/**
 * @brief Configurator "network" property configuration file options.
 */
static struct json_property_parser configurator_network_configuration_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_NET_CFG_DEFAULT,
        .type = json_type_object,
        .value = {
            json_parse_network_default,
        },
    },
};

/**
 * @brief Parser for the "network" configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json property. Must be "network".
 * @param jobj The json value of the 'network' info property.
 * @param context The configurator settings object instance.
 */
static void
json_parse_network_configuration(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_parse_object_s(jobj, configurator_network_configuration_properties, context);
}

/**
 * @brief Configurator top-level configuration file options.
 */
static struct json_property_parser configurator_config_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO,
        .type = json_type_object,
        .value = {
            json_parse_bootstrap_info,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_NET_CFG,
        .type = json_type_object,
        .value = {
            json_parse_network_configuration,
        },
    },
};

/**
 * @brief Parses a json-formatted configurator configuration file.
 *
 * @param file The path of the file to parse.
 * @param configurator The configurator settings to fill in.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
ztp_configurator_config_parse(const char *file, struct ztp_configurator_settings *settings)
{
    settings->expiration_time = BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET;

    int ret = json_parse_file_s(file, configurator_config_properties, settings, NULL);
    if (ret < 0)
        return ret;

    if (settings->expiration_time == BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET)
        settings->expiration_time = 0;

    struct bootstrap_info_provider_settings *bisettings;
    list_for_each_entry (bisettings, &settings->provider_settings, list) {
        if (bisettings->expiration_time == BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET)
            bisettings->expiration_time = settings->expiration_time;
    }

    return 0;
}

/**
 * @brief Serialize ztp configurator settings to a json object.
 * 
 * @param settings The settings to serialize.
 * @param jsettings Output argument for the serialized json object. If this is
 * populated, the caller must free it by passing it to json_object_put().
 * 
 * @return int
 */
static int
ztp_configurator_config_to_json(const struct ztp_configurator_settings *settings, struct json_object **jsettings)
{
    struct json_object *jobj = json_object_new_object();
    if (!jobj) {
        zlog_error("failed to json object for configurator settings");
        return -ENOMEM;
    }

    struct json_object *bootstrap_info = NULL;
    int ret = json_encode_bootstrap_info(settings, &bootstrap_info);
    if (ret < 0) {
        zlog_error("failed to encode bootstrap info (%d)", ret);
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_BOOTSTRAP_INFO, bootstrap_info);
    if (ret < 0) {
        zlog_error("failed to add '" JSON_PROPERTY_NAME_BOOTSTRAP_INFO "' property to configurator json (%d)", ret);
        goto fail;
    }

    struct json_object *network_configuration;
    ret = json_encode_network_configuration(settings, &network_configuration);
    if (ret < 0) {
        zlog_error("failed to encode network configuration (%d)", ret);
        goto fail;
    }

    ret = json_object_object_add(jobj, JSON_PROPERTY_NAME_NET_CFG, network_configuration);
    if (ret < 0) {
        zlog_error("failed to add network configuration to configurator json (%d)", ret);
        json_object_put(network_configuration);
        goto fail;
    }

    *jsettings = jobj;
out:
    return ret;
fail:
    if (jobj)
        json_object_put(jobj);
    goto out;
}

/**
 * @brief Persists configurator settings to file descriptor.
 * 
 * @param fd The file descriptor to write the settings to.
 * @param settings The settings to write to file.
 * @return int 0 if the settings were successfully written to file, non-zero otherwise.
 */
int
ztp_configurator_settings_persist_fd(int fd, const struct ztp_configurator_settings *settings)
{
    static const int JSON_C_SERIALIZE_FLAGS = (0 
        | JSON_C_TO_STRING_NOSLASHESCAPE    // don't escape paths
        | JSON_C_TO_STRING_PRETTY           // make it look good
        | JSON_C_TO_STRING_SPACED           // minimize whitespace
        | JSON_C_TO_STRING_PRETTY_TAB       // use a full tab character
    );

    struct json_object *jsettings;
    int ret = ztp_configurator_config_to_json(settings, &jsettings);
    if (ret < 0) {
        zlog_error("failed to encode configurator settings to json (%d)", ret);
        return ret;
    }

    ret = json_object_to_fd(fd, jsettings, JSON_C_SERIALIZE_FLAGS);
    if (ret < 0) {
        zlog_error("failed to write settings to file descriptor (%d)", ret);
    }

    json_object_put(jsettings);
    return ret;
}

/**
 * @brief Macros to help defined the temporary path string for writing the
 * configurator settings file.
 */
#define TMP_TEMPLATE_SUFFIX_STRING ".XXXXXX"

/**
 * @brief Persists configurator settings to file.
 * 
 * @param filename The filename to write the settings to.
 * @param settings The settings to write to file.
 * @return int 0 if the settings were successfully written to file, non-zero otherwise.
 */
int
ztp_configurator_settings_persist(const char *filename, const struct ztp_configurator_settings *settings)
{
    int ret;
    int fd = -1;

    char *filename_target = NULL;
    ret = get_link_target(filename, &filename_target);
    if (ret < 0) {
        zlog_error("failed to resolve configurator settings file '%s' link target (%d)", filename, ret);
        return ret;
    }

    if (filename_target)
        filename = filename_target;

    size_t filename_length = strlen(filename);
    char *pathtmp = malloc(filename_length + ARRAY_SIZE(TMP_TEMPLATE_SUFFIX_STRING));
    if (!pathtmp) {
        zlog_error("failed to allocate memory for temp configurator settings file path");
        ret = -ENOMEM;
        goto out;
    }

    memcpy(pathtmp, filename, filename_length);
    memcpy(pathtmp + filename_length, TMP_TEMPLATE_SUFFIX_STRING, ARRAY_SIZE(TMP_TEMPLATE_SUFFIX_STRING));

    fd = mkstemp(pathtmp);
    if (fd < 0) {
        ret = -errno;
        zlog_error("failed to create temporary file for configurator settings (%d)", ret);
        goto out;
    }

    ret = ztp_configurator_settings_persist_fd(fd, settings);
    if (ret < 0) {
        zlog_error("failed to write settings to temporary file (%d)", ret);
        goto out;
    }

    fdatasync(fd);

    ret = rename(pathtmp, filename);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to move temporary configurator settings file to target file (%d)", ret);
        goto out;
    }

out:
    if (fd != -1)
        close(fd);
    if (filename_target)
        free(filename_target);
    if (pathtmp)
        free(pathtmp);

    return ret;
}

/**
 * @brief Initializes the settings structure for use.
 * 
 * @param settings 
 */
void
ztp_configurator_settings_initialize(struct ztp_configurator_settings *settings)
{
    explicit_bzero(settings, sizeof *settings);
    INIT_LIST_HEAD(&settings->provider_settings);
    settings->expiration_time = BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET;
}

/**
 * @brief Uninitializes configurator settings, freeing any owned resources.
 *
 * @param settings The settings object to uninitialize.
 */
void
ztp_configurator_settings_uninitialize(struct ztp_configurator_settings *settings)
{
    if (!settings)
        return;

    if (!list_empty(&settings->provider_settings)) {
        struct bootstrap_info_provider_settings *bisettings;
        struct bootstrap_info_provider_settings *bisettingstmp;

        list_for_each_entry_safe (bisettings, bisettingstmp, &settings->provider_settings, list) {
            bootstrap_info_provider_settings_uninitialize(bisettings);
            free(bisettings);
        }
    }

    if (settings->network_config_default) {
        dpp_network_uninitialize(settings->network_config_default);
        free(settings->network_config_default);
        settings->network_config_default = NULL;
    }
}

/**
 * @brief Add new bootstrap information provider settings to the configurator settings.
 * 
 * @param settings The configurator settings to add the bootstrap info provider settings to.
 * @param provider The bootstrap info provider settings to add. 
 */
void
ztp_configurator_settings_add_bi_provider_settings(struct ztp_configurator_settings *settings, struct bootstrap_info_provider_settings *provider)
{
    list_add(&provider->list, &settings->provider_settings);
}
