
#include <errno.h>
#include <json-c/json_tokener.h>
#include <stdlib.h>
#include <userspace/linux/compiler.h>

#include "bootstrap_info_provider_azure_dps.h"
#include "bootstrap_info_provider_azure_dps_config.h"
#include "json_parse.h"
#include "ztp_log.h"

/**
 * @brief Get the context for the string properties of the settings object and its children.
 *
 * @param context The parent context. Must be of type struct bootstrap_info_provider_azure_dps_settings.
 * @param name The name of the child property to retrieve the context for.
 * @return void* The context for the child property with key 'name'.
 */
static void *
bip_azure_dps_get_settings_string_context(void *context, const char *name)
{
    struct bootstrap_info_provider_azure_dps_settings *settings = (struct bootstrap_info_provider_azure_dps_settings *)context;

    if (strcmp(name, JSON_PROPERTY_NAME_SERVICE_ENDPOINT_URI) == 0) {
        return &settings->service_endpoint_uri;
    } else if (strcmp(name, JSON_PROPERTY_NAME_AUTHORITY_URL) == 0) {
        return &settings->authority_url;
    } else if (strcmp(name, JSON_PROPERTY_NAME_CLIENT_ID) == 0) {
        return &settings->client_id;
    } else if (strcmp(name, JSON_PROPERTY_NAME_CLIENT_SECRET) == 0) {
        return &settings->client_secret;
    } else if (strcmp(name, JSON_PROPERTY_NAME_RESOURCE_URI) == 0) {
        return &settings->resource_uri;
    } else if (strcmp(name, JSON_PROPERTY_NAME_CONNECTION_STRING) == 0) {
        return &settings->connection_string;
    } else {
        return NULL;
    }
}

/**
 * @brief "authentication" configuration options.
 */
static struct json_property_parser bip_azure_dps_configuration_authentication_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_AUTHORITY_URL,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_azure_dps_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_CLIENT_ID,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_azure_dps_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_CLIENT_SECRET,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_azure_dps_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_RESOURCE_URI,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_azure_dps_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_CONNECTION_STRING,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_azure_dps_get_settings_string_context,
    },
};

/**
 * @brief Parser for "authentication" property.
 *
 * @param parent The parent object.
 * @param name Name of the json key. Must be "authentication".
 * @param jobj The json object value.
 * @param context The provider settings object. Must be of type struct
 * bootstrap_info_provider_azure_dps_settings.
 */
static void
json_parse_authentication(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_parse_object_s(jobj, bip_azure_dps_configuration_authentication_properties, context);
}

/**
 * @brief Top-level configuration options.
 */
static struct json_property_parser bip_azure_dps_configuration_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_SERVICE_ENDPOINT_URI,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_azure_dps_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_AUTHENTICATION,
        .type = json_type_object,
        .value = {
            json_parse_authentication,
        },
    },
};

/**
 * @brief Parses json configuration, writing it to the 'settings' object.
 *
 * @param jobj The json-c object with the configuration.
 * @param settings The object to populate with settings.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
bootstrap_info_provider_azure_dps_config_parse_jobj(struct json_object *jobj, struct bootstrap_info_provider_azure_dps_settings *settings)
{
    json_parse_object_s(jobj, bip_azure_dps_configuration_properties, settings);

    // check for all required properties
    if (!settings->service_endpoint_uri) {
        zlog_error("missing required property '" JSON_PROPERTY_NAME_SERVICE_ENDPOINT_URI "'");
        return -ENOENT;
    } else if (!settings->authority_url) {
        zlog_error("missing required property '" JSON_PROPERTY_NAME_AUTHORITY_URL "'");
        return -ENOENT;
    } else if (!settings->client_id) {
        zlog_error("missing required property '" JSON_PROPERTY_NAME_CLIENT_ID "'");
        return -ENOENT;
    } else if (!settings->client_secret) {
        zlog_error("missing required property '" JSON_PROPERTY_NAME_CLIENT_SECRET "'");
        return -ENOENT;
    } else if (!settings->resource_uri) {
        zlog_error("missing required property '" JSON_PROPERTY_NAME_RESOURCE_URI "'");
        return -ENOENT;
    } else if (!settings->connection_string) {
        zlog_error("missing required property '" JSON_PROPERTY_NAME_CONNECTION_STRING "'");
        return -ENOENT;
    }

    return 0;
}

/**
 * @brief Parses json configuration, writing it to the 'settings' object.
 *
 * @param json The json encoded configuration.
 * @param settings The object to populate with settings.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
bootstrap_info_provider_azure_dps_config_parse(const char *json, struct bootstrap_info_provider_azure_dps_settings *settings)
{
    struct json_object *jobj = json_tokener_parse(json);
    if (!jobj) {
        zlog_error("invalid json found while parsing azure dps-based bootstrap info provider");
        return -EINVAL;
    }

    int ret = bootstrap_info_provider_azure_dps_config_parse_jobj(jobj, settings);
    json_object_put(jobj);

    return ret;
}

/**
 * @brief Uninitializes an Azure DPS provider settings object, releasing any
 * resources.
 *
 * @param settings The settings object to uninitialize.
 */
void
bootstrap_info_provider_azure_dps_settings_uninitialize(struct bootstrap_info_provider_azure_dps_settings *settings)
{
    char **strs[] = {
        &settings->service_endpoint_uri,
        &settings->authority_url,
        &settings->client_id,
        &settings->client_secret,
        &settings->resource_uri,
    };

    for (size_t i = 0; i < ARRAY_SIZE(strs); i++) {
        if (*strs[i]) {
            free(*strs[i]);
            *strs[i] = NULL;
        }
    }
}
