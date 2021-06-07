
#ifndef __BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_H__
#define __BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_H__

struct bootstrap_info_provider_ops;

#include "bootstrap_info_provider_azure_dps_config.h"

/**
 * @brief Represents an instance of a Azure DPS-based info provider.
 */
struct bootstrap_info_provider_azure_dps_instance {
    struct bootstrap_info_provider_azure_dps_settings *settings;
    void *client_context;
};

/**
 * @brief Operations vector for Azure DPS-based bootstrap info provider.
 */
extern struct bootstrap_info_provider_ops bootstrap_info_provider_azure_dps_ops;

/**
 * @brief Requests the provider to authorize itself to the DPS instance.
 * 
 * @param instance The azure dps instance to perform authorization for.
 * @return int 0 if authorization was successful, -EPERM if access was denied,
 * non-zero otherwise.
 */
int
bootstrap_info_provider_azure_dps_authorize(struct bootstrap_info_provider_azure_dps_instance *instance);

#endif //__BOOTSTRAP_INFO_PROVIDER_AZURE_DPS_H__
