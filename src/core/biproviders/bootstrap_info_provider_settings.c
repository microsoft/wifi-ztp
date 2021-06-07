
#include <errno.h>
#include <string.h>

#include "bootstrap_info_provider_settings.h"
#include "string_utils.h"

/**
 * @brief Allocates and initializes a new bootstrap info provider settings object.
 *
 * @return struct bootstrap_info_provider_settings*
 */
struct bootstrap_info_provider_settings *
bootstrap_info_provider_settings_alloc(void)
{
    struct bootstrap_info_provider_settings *settings = calloc(1, sizeof *settings);
    if (!settings)
        return NULL;

    INIT_LIST_HEAD(&settings->list);
    settings->type = BOOTSTRAP_INFO_PROVIDER_INVALID;
    settings->expiration_time = BOOTSTRAP_INFO_PROVIDER_EXPIRATION_UNSET;

    return settings;
}

/**
 * @brief Uninitializes provider settings, freeing any owned resources.
 *
 * @param settings The provider settings to uninitialize.
 */
void
bootstrap_info_provider_settings_uninitialize(struct bootstrap_info_provider_settings *settings)
{
    if (!settings)
        return;

    switch (settings->type) {
        case BOOTSTRAP_INFO_PROVIDER_FILE:
            bootstrap_info_provider_file_settings_uninitialize(settings->file);
            break;
        case BOOTSTRAP_INFO_PROVIDER_AZUREDPS:
            bootstrap_info_provider_azure_dps_settings_uninitialize(settings->dps);
            break;
        default:
            break;
    }

    if (settings->name) {
        free(settings->name);
        settings->name = NULL;
    }

    if (!list_empty(&settings->list))
        list_del(&settings->list);
}
