
#include <errno.h>
#include <json-c/json_tokener.h>
#include <stdlib.h>
#include <userspace/linux/compiler.h>

#include "bootstrap_info_provider_file.h"
#include "bootstrap_info_provider_file_config.h"
#include "json_parse.h"
#include "ztp_log.h"

/**
 * @brief Get the context for the string properties of the "decodingInfo" object.
 *
 * @param context The parent context. Must be of type struct bootstrap_info_provider_file_settings.
 * @param name The name of the child property to retrieve the context for.
 * @return void* The context for the child property with key 'name'.
 */
static void *
bip_file_get_settings_string_context(void *context, const char *name)
{
    struct bootstrap_info_provider_file_settings *settings = (struct bootstrap_info_provider_file_settings *)context;

    if (strcmp(name, JSON_PROPERTY_NAME_PATH) == 0) {
        return &settings->path;
    } else if (strcmp(name, JSON_PROPERTY_NAME_DPP_URI) == 0) {
        return &settings->json_key_dpp_uri;
    } else if (strcmp(name, JSON_PROPERTY_NAME_PUBLIC_KEY_HASH) == 0) {
        return &settings->json_key_publickeyhash;
    } else if (strcmp(name, JSON_PROPERTY_NAME_JSON_PTR) == 0) {
        return &settings->json_pointer_array;
    } else if (strcmp(name, JSON_PROPERTY_NAME_JSON_PTR_BASE) == 0) {
        return &settings->json_pointer_object_base;
    } else {
        return NULL;
    }
}

/**
 * @brief Decoding info "propertyMap" configuration file options.
 */
static struct json_property_parser bip_file_configuration_property_map_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_DPP_URI,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_file_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_PUBLIC_KEY_HASH,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_file_get_settings_string_context,
    },
};

/**
 * @brief Parser for "propertyMap" property.
 *
 * @param parent The parent object.
 * @param name Name of the json key. Must be "propertyMap".
 * @param jobj The json object value.
 * @param context The provider settings object. Must be of type struct
 * bootstrap_info_provider_file_settings.
 */
static void
json_parse_decoding_info_property_map(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_parse_object_s(jobj, bip_file_configuration_property_map_properties, context);
}

/**
 * @brief "decodingInfo" configuration file options.
 */
static struct json_property_parser bip_file_configuration_decoding_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_JSON_PTR,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_file_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_JSON_PTR_BASE,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_file_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_PROPERTY_MAP,
        .type = json_type_object,
        .value = {
            json_parse_decoding_info_property_map,
        },
    },
};

/**
 * @brief Parser for "decodingInfo" property.
 *
 * @param parent The parent object.
 * @param name Name of the json key. Must be "decodingInfo".
 * @param jobj The json object value.
 * @param context The provider settings object. Must be of type struct
 * bootstrap_info_provider_file_settings.
 */
static void
json_parse_decoding_info(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_parse_object_s(jobj, bip_file_configuration_decoding_properties, context);
}

/**
 * @brief Top-level configuration file options.
 */
static struct json_property_parser bip_file_configuration_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_PATH,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = bip_file_get_settings_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_DECODING_INFO,
        .type = json_type_object,
        .value = {
            json_parse_decoding_info,
        },
    }
};

/**
 * @brief Parses json configuration, writing it to the 'settings' object.
 *
 * @param jobj The json-c object with the configuration.
 * @param settings The object to populate with settings.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
bootstrap_info_provider_file_config_parse_jobj(struct json_object *jobj, struct bootstrap_info_provider_file_settings *settings)
{
    json_parse_object_s(jobj, bip_file_configuration_properties, settings);

    // check for all required properties
    if (!settings->path) {
        zlog_error("missing required property 'path'");
        return -ENOENT;
    } else if (!settings->json_pointer_array) {
        zlog_error("missing required property 'pointer'");
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
bootstrap_info_provider_file_config_parse(const char *json, struct bootstrap_info_provider_file_settings *settings)
{
    struct json_object *jobj = json_tokener_parse(json);
    if (!jobj) {
        zlog_error("invalid json found while parsing file-based bootstrap info provider");
        return -EINVAL;
    }

    int ret = bootstrap_info_provider_file_config_parse_jobj(jobj, settings);
    json_object_put(jobj);

    return ret;
}

/**
 * @brief Uninitializes a file provider settings object. releasing any resources.
 *
 * @param settings The settings object to uninitialize.
 */
void
bootstrap_info_provider_file_settings_uninitialize(struct bootstrap_info_provider_file_settings *settings)
{
    char **strs[] = {
        &settings->path,
        &settings->json_key_dpp_uri,
        &settings->json_key_publickeyhash,
        &settings->json_pointer_array,
        &settings->json_pointer_object_base,
    };

    for (size_t i = 0; i < ARRAY_SIZE(strs); i++) {
        if (*strs[i]) {
            free(*strs[i]);
            *strs[i] = NULL;
        }
    }
}
