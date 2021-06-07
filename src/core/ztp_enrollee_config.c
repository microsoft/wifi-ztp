
#include <errno.h>
#include <json-c/json_object.h>
#include <stdlib.h>
#include <string.h>
#include <userspace/linux/compiler.h>

#include "json_parse.h"
#include "ztp_enrollee_config.h"
#include "ztp_log.h"

/**
 * @brief Json object key names for status.signals.
 */
#define JSON_PROPERTY_NAME_ENROLLEE_STATUS_SIGNALS "status.signals"
#define JSON_PROPERTY_NAME_ENROLLEE_STATUS_SIGNALS_LED "led"
#define JSON_PROPERTY_NAME_ENROLLEE_STATUS_SIGNALS_LED_NODE "sysfsNode"

/**
 * @brief Get the status signals led string context object
 * 
 * @param context The enrollee settings object instance.
 * @param name The name of the property.
 * @return void*
 */
static void *
get_status_signals_led_string_context(void *context, const char *name)
{
    struct ztp_enrollee_settings *settings = (struct ztp_enrollee_settings *)context;

    if (strcmp(name, JSON_PROPERTY_NAME_ENROLLEE_STATUS_SIGNALS_LED_NODE) == 0) {
        return &settings->status_signal_led_path;
    } else {
        return NULL;
    }
}

/**
 * @brief Property map for enrollee status signals configuration.
 */
static struct json_property_parser enrollee_status_signals_led_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_ENROLLEE_STATUS_SIGNALS_LED_NODE,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_status_signals_led_string_context,
    },
};

/**
 * @brief Parser for the "led" property of the "status.signals" object
 * 
 * @param parent The parent json object.
 * @param name The name of the property. Must be "led".
 * @param jobj The json object.
 * @param context The ztp_enrollee_settings object to populate.
 */
static void
json_parse_status_signals_led(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_parse_object_s(jobj, enrollee_status_signals_led_properties, context);
}

/**
 * @brief Property map for enrollee bootstrap info configuration.
 */
static struct json_property_parser enrollee_status_signals_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_ENROLLEE_STATUS_SIGNALS_LED,
        .type = json_type_object,
        .value = {
            json_parse_status_signals_led,
        },
    },
};

/**
 * @brief Parser for the "status.signals" property.
 * 
 * @param parent The parent json object.
 * @param name The name of the property. Must be "status.signals".
 * @param jobj The json object.
 * @param context The ztp_enrollee_settings object to populate.
 */
static void
json_parse_enrollee_status_signals(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_parse_object_s(jobj, enrollee_status_signals_properties, context);
}

/**
 * @brief Json object key names for bootstrap.info.
 */
#define JSON_PROPERTY_NAME_ENROLLEE_BOOTSTRAP_INFO "bootstrap.info"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_MAC "mac"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_KEY "key"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_KEY_ID "keyId"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_INFO "info"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_CURVE "curve"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_CHANNEL "channel"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_ENGINE_ID "engineId"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_ENGINE_PATH "enginePath"
#define JSON_PROPERTY_NAME_BOOTSTRAP_INFO_TYPE "type"

/**
 * @brief Get the context for the string properties of the bootstrap info object.
 *
 * @param context The parent context. Must be of type struct dpp_bootstrap_info.
 * @param name The name of the child property to retrieve the context for.
 * @return void* The context for the child property with key 'name'.
 */
static void *
get_bootstrap_info_string_context(void *context, const char *name)
{
    struct dpp_bootstrap_info *bi = (struct dpp_bootstrap_info *)context;

    if (strcmp(name, JSON_PROPERTY_NAME_BOOTSTRAP_INFO_MAC) == 0) {
        return &bi->mac;
    } else if (strcmp(name, JSON_PROPERTY_NAME_BOOTSTRAP_INFO_KEY) == 0) {
        return &bi->key;
    } else if (strcmp(name, JSON_PROPERTY_NAME_BOOTSTRAP_INFO_KEY_ID) == 0) {
        return &bi->key_id;
    } else if (strcmp(name, JSON_PROPERTY_NAME_BOOTSTRAP_INFO_INFO) == 0) {
        return &bi->info;
    } else if (strcmp(name, JSON_PROPERTY_NAME_BOOTSTRAP_INFO_CURVE) == 0) {
        return &bi->curve;
    } else if (strcmp(name, JSON_PROPERTY_NAME_BOOTSTRAP_INFO_CHANNEL) == 0) {
        return &bi->channel;
    } else if (strcmp(name, JSON_PROPERTY_NAME_BOOTSTRAP_INFO_ENGINE_ID) == 0) {
        return &bi->engine_id;
    } else if (strcmp(name, JSON_PROPERTY_NAME_BOOTSTRAP_INFO_ENGINE_PATH) == 0) {
        return &bi->engine_path;
    } else {
        return NULL;
    }
}

/**
 * @brief Parser for the "type" bootstrap info property.
 * 
 * @param parent The parent json object.
 * @param name The name of the property. Must be "type".
 * @param jobj The json object.
 * @param context The dpp_bootstrap_info object to populate.
 */
static void
json_parse_bootstrap_info_type(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct dpp_bootstrap_info *bi = (struct dpp_bootstrap_info *)context;
    const char *typestr = json_object_get_string(jobj);
    if (!typestr)
        return;

    bi->type = parse_dpp_bootstrap_type(typestr);
}

/**
 * @brief Property map for enrollee bootstrap info configuration.
 */
static struct json_property_parser enrollee_bootstrap_info_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_MAC,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_bootstrap_info_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_KEY,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_bootstrap_info_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_KEY_ID,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_bootstrap_info_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_INFO,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_bootstrap_info_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_CURVE,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_bootstrap_info_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_CHANNEL,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_bootstrap_info_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_ENGINE_ID,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_bootstrap_info_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_ENGINE_PATH,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_bootstrap_info_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_BOOTSTRAP_INFO_TYPE,
        .type = json_type_string,
        .value = {
            json_parse_bootstrap_info_type,
        },
    },
};

/**
 * @brief Parser for the "bootstrap.info" property.
 * 
 * @param parent The parent json object.
 * @param name The name of the property. Must be "bootstrap.info".
 * @param jobj 
 * @param context 
 */
static void
json_parse_enrollee_bootstrap_info(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct ztp_enrollee_settings *settings = (struct ztp_enrollee_settings *)context;
    json_parse_object_s(jobj, enrollee_bootstrap_info_properties, &settings->bootstrap);
}

/**
 * @brief Property map for enrollee configuration.
 */
static struct json_property_parser enrollee_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_ENROLLEE_BOOTSTRAP_INFO,
        .type = json_type_object,
        .value = {
            json_parse_enrollee_bootstrap_info,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_ENROLLEE_STATUS_SIGNALS,
        .type = json_type_object,
        .value = {
            json_parse_enrollee_status_signals,
        },
    },
};

/**
 * @brief Parses a json-formatted enrollee configuration file.
 *
 * @param file The path of the file to parse.
 * @param settings The enrollee settings to fill in.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
ztp_enrollee_config_parse(const char *file, struct ztp_enrollee_settings *settings)
{
    int ret = json_parse_file_s(file, enrollee_properties, settings, NULL);
    if (ret < 0) {
        zlog_error("failed to parse enrollee settings file '%s' (%d)", file, ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Initializes the settings structure for use.
 * 
 * @param settings The settings to initialize.
 */
void
ztp_enrollee_settings_initialize(struct ztp_enrollee_settings *settings)
{
    explicit_bzero(settings, sizeof *settings);
    settings->bootstrap.type = DPP_BOOTSTRAP_UNKNOWN;
}

/**
 * @brief Uninitializes enrollee settings, freeing any owned resources.
 *
 * @param settings The settings object to uninitialize.
 */
void
ztp_enrollee_settings_uninitialize(struct ztp_enrollee_settings *settings)
{
    if (settings->status_signal_led_path) {
        free(settings->status_signal_led_path);
        settings->status_signal_led_path = NULL;
    }

    dpp_bootstrap_info_uninitialize(&settings->bootstrap);
}
