
#ifndef __BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_CLIENT_PROXY_H__
#define __BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_CLIENT_PROXY_H__

struct bootstrap_info_provider_azure_dps_settings;
struct bootstrap_info_query;
struct bootstrap_info_query_result;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**
 * @brief Initializes a new azure dps service client.
 *
 * @param settings The bootstrap info provider settings to use.
 * @param client_context A pointer where arbitrary context information may be
 * stored.
 * @return int 0 if the client was successfully initialized, non-zero otherwise.
 */
int
azure_dps_client_initialize(const struct bootstrap_info_provider_azure_dps_settings *settings, void **client_context);

/**
 * @brief Uninitializes an existing azure dps service client.
 *
 * @param client_context A pointer to the azure_dps_client_context instance
 * created in azure_dps_client_initialize.
 */
void
azure_dps_client_uninitialize(void *client_context);

/**
 * @brief Synchronizes the view of the bootstrap information between dps and ztp.
 *
 * @param client_context A pointer to the azure_dps_client_context instance
 * created in azure_dps_client_initialize.
 * @return int 0 if the in-memory contents are in sync with the DPS instance.
 * Non-zero otherwise.
 */
int
azure_dps_client_synchronize(void *context);

/**
 * @brief Queries the provider for bootstrap info record(s).
 *
 * @param client_context A pointer to the azure_dps_client_context instance
 * created in azure_dps_client_initialize.
 * @param query The query describing which records are requested.
 * @param result The structure to store record results.
 * @return int 0 if the query was successful and results provider in 'result',
 * non-zero otherwise.
 */
int
azure_dps_client_query(void *client_context, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result);

/**
 * @brief Performs authorization to the dps instance, refreshing its oauth2
 * token if necessary.
 * 
 * @param client_context A pointer to the azure_dps_client_context instance
 * created in azure_dps_client_initialize.
 * @return int 0 if the provider was authorized to use the DPS instance,
 * non-zero otherwise.
 */
int
azure_dps_client_authorize(void *client_context);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_CLIENT_PROXY_H__
