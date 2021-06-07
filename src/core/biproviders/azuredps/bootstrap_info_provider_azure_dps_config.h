
#ifndef __BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_CONFIG_H__
#define __BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_CONFIG_H__

#include <json-c/json_object.h>

/**
 * @brief Macros for JSON configuration property names.
 */
#define JSON_PROPERTY_NAME_SERVICE_ENDPOINT_URI "serviceEndpointUri"
#define JSON_PROPERTY_NAME_AUTHENTICATION "authentication"
#define JSON_PROPERTY_NAME_AUTHORITY_URL "authorityUrl"
#define JSON_PROPERTY_NAME_CLIENT_ID "clientId"
#define JSON_PROPERTY_NAME_CLIENT_SECRET "clientSecret"
#define JSON_PROPERTY_NAME_RESOURCE_URI "resourceUri"
#define JSON_PROPERTY_NAME_CONNECTION_STRING "connectionString"

/**
 * @brief Azure DPS bootstrap info provider settings.
 */
struct bootstrap_info_provider_azure_dps_settings {
    char *service_endpoint_uri;
    char *dps_api_version;
    char *authority_url;
    char *client_id;
    char *client_secret;
    char *resource_uri;
    char *connection_string;
};

/**
 * @brief Parses json configuration, writing it to the 'settings' object.
 *
 * @param jobj The json-c object with the configuration.
 * @param settings The object to populate with settings.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
bootstrap_info_provider_azure_dps_config_parse_jobj(struct json_object *jobj, struct bootstrap_info_provider_azure_dps_settings *settings);

/**
 * @brief Parses json configuration, writing it to the 'settings' object.
 *
 * @param json The json encoded configuration.
 * @param settings The object to populate with settings.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
bootstrap_info_provider_azure_dps_config_parse(const char *json, struct bootstrap_info_provider_azure_dps_settings *settings);

/**
 * @brief Uninitializes an Azure DPS provider settings object, releasing any
 * resources.
 *
 * @param settings The settings object to uninitialize.
 */
void
bootstrap_info_provider_azure_dps_settings_uninitialize(struct bootstrap_info_provider_azure_dps_settings *settings);

#endif //__BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_CONFIG_H__
