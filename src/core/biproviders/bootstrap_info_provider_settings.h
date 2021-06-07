
#ifndef __BOOTSTRAP_INFO_PROVIDER_SETTINGS_H__
#define __BOOTSTRAP_INFO_PROVIDER_SETTINGS_H__

#include <stdint.h>
#include <userspace/linux/list.h>

#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps_config.h"
#include "bootstrap_info_provider_file_config.h"

/**
 * @brief Value indicating the provider expiration time is unset.
 */
#define BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET ((uint32_t)(INT32_MAX))

/**
 * @brief Bootstrap info provider settings. All structure members describe
 * settings that are shared by all providers.
 */
struct bootstrap_info_provider_settings {
    struct list_head list;
    char *name;
    uint32_t expiration_time;
    enum bootstrap_info_provider_type type;
    union {
        struct bootstrap_info_provider_file_settings *file;
        struct bootstrap_info_provider_azure_dps_settings *dps;
    };
};

/**
 * @brief Allocates and initializes a new bootstrap info provider settings object.
 *
 * @return struct bootstrap_info_provider_settings*
 */
struct bootstrap_info_provider_settings *
bootstrap_info_provider_settings_alloc(void);

/**
 * @brief Uninitializes provider settings, freeing any owned resources.
 *
 * @param settings The provider settings to uninitialize.
 */
void
bootstrap_info_provider_settings_uninitialize(struct bootstrap_info_provider_settings *settings);

#endif // __BOOTSTRAP_INFO_PROVIDER_SETTINGS_H__
