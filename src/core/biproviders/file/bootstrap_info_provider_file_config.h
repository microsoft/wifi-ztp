
#ifndef __BOOTSTRAP_INFO_PROVIDER_FILE_CONFIG_H__
#define __BOOTSTRAP_INFO_PROVIDER_FILE_CONFIG_H__

#include <json-c/json_object.h>

/**
 * @brief Macros for JSON configuration property names.
 */
#define JSON_PROPERTY_NAME_PATH "path"
#define JSON_PROPERTY_NAME_DPP_URI "dppUri"
#define JSON_PROPERTY_NAME_PUBLIC_KEY_HASH "publicKeyHash"
#define JSON_PROPERTY_NAME_JSON_PTR "pointer"
#define JSON_PROPERTY_NAME_JSON_PTR_BASE "pointerBase"
#define JSON_PROPERTY_NAME_PROPERTY_MAP "propertyMap"
#define JSON_PROPERTY_NAME_DECODING_INFO "decodingInfo"

/**
 * @brief File bootstrap info provider settings.
 */
struct bootstrap_info_provider_file_settings {
    char *path;
    char *json_pointer_array;
    char *json_pointer_object_base;
    char *json_key_dpp_uri;
    char *json_key_publickeyhash;
};

/**
 * @brief Parses json configuration, writing it to the 'settings' object.
 *
 * @param jobj The json-c object with the configuration.
 * @param settings The object to populate with settings.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
bootstrap_info_provider_file_config_parse_jobj(struct json_object *jobj, struct bootstrap_info_provider_file_settings *settings);

/**
 * @brief Parses json configuration, writing it to the 'settings' object.
 *
 * @param json The json encoded configuration.
 * @param settings The object to populate with settings.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
bootstrap_info_provider_file_config_parse(const char *json, struct bootstrap_info_provider_file_settings *settings);

/**
 * @brief Uninitializes a file provider settings object. releasing any resources.
 *
 * @param settings The settings object to uninitialize.
 */
void
bootstrap_info_provider_file_settings_uninitialize(struct bootstrap_info_provider_file_settings *settings);

#endif //__BOOTSTRAP_INFO_PROVIDER_FILE_CONFIG_H__
