
#include <errno.h>
#include <sys/types.h>
#include <userspace/linux/compiler.h>

#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps.h"
#include "bootstrap_info_provider_azure_dps_config.h"
#include "bootstrap_info_provider_settings.h"
#include "ztp_log.h"

#include "azure_dps_service_client_proxy.h"

/**
 * @brief Initialize a new provider instance. This will parse the settings,
 * associate them with the instance and prepare the provider for use.
 *
 * @param instance  The instance to initialize. It is assumed that object describes an uninitialized provider.
 * @param json_settings The json-encoded settings for the provider.
 * @return int 0 if the provider was successfully initialized, non-zero otherwise.
 */
static int
bootstrap_info_provider_azure_dps_initialize(struct bootstrap_info_provider_azure_dps_instance *instance, struct bootstrap_info_provider_azure_dps_settings *settings)
{
    instance->settings = settings;

    int ret = azure_dps_client_initialize(instance->settings, &instance->client_context);
    if (ret < 0) {
        zlog_error("azure dps client failed to initialize (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Creates and initializes a new instance of a azure dps-based bootstrap info provider.
 *
 * @param out The output pointer to write the new instance to.
 * @param settings The settings to use for this instance.
 * @return int 0 if the instance was created, *instance will hold the newly
 * created object. Otherwise a non-zero value will be returned, with *instance
 * having the value NULL.
 */
static int
bootstrap_info_provider_azure_dps_create(struct bootstrap_info_provider_azure_dps_instance **out, struct bootstrap_info_provider_azure_dps_settings *settings)
{
    *out = NULL;

    struct bootstrap_info_provider_azure_dps_instance *instance = calloc(1, sizeof *instance);
    if (!instance) {
        zlog_error("allocation failure creating azure dps-based bootstrap info provider");
        return -ENOMEM;
    }

    int ret = bootstrap_info_provider_azure_dps_initialize(instance, settings);
    if (ret < 0) {
        free(instance);
        return ret;
    }

    *out = instance;

    return 0;
}

/**
 * @brief Uninitializes a provider.
 *
 * @param instance The instance to uninitialize.
 */
static void
bootstrap_info_provider_azure_dps_uninitialize(struct bootstrap_info_provider_azure_dps_instance *instance)
{
    __unused(instance);
    // nothing to do
}

/**
 * @brief Uninitializes and destroys a provider. All owned resources will be
 * freed and the memory associated with the provider itself is released. The
 * 'instance' pointer must not be used beyond successfuly completion of this
 * call.
 *
 * @param instance The instance to destroy.
 */
static void
bootstrap_info_provider_azure_dps_destroy(struct bootstrap_info_provider_azure_dps_instance *instance)
{
    bootstrap_info_provider_azure_dps_uninitialize(instance);
    free(instance);
}

/**
 * @brief Wrapper to synchronize the DPS instance with the in-memory contents.
 *
 * Note that this is a 1-way synchronization only, from DPS to in-memory.
 *
 * @param instance The instance object.
 * @return int 0 if the in-memory contents are in sync with the DPS instance.
 * Non-zero otherwise.
 */
static int
bootstrap_info_provider_azure_dps_synchronize(struct bootstrap_info_provider_azure_dps_instance *instance)
{
    int ret = azure_dps_client_synchronize(instance->client_context);
    if (ret < 0) {
        zlog_error("azure dps client failed to synchronize (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Performs a query for bootstrapping information.
 *
 * @param instance The provider instance.
 * @param query The query object describing the criteria to search for.
 * @param result The result structure to add results to.
 * @return int 0 if the query was performed successfully, non-zero otherwise.
 * Note 0 is returned when no records matched; the return value indicates if
 * the query was performed, not whether a record matched.
 */
static int
bootstrap_info_provider_azure_dps_query(struct bootstrap_info_provider_azure_dps_instance *instance, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result)
{
    assert(query->criterion.type == BOOTSTRAP_INFO_QUERY_CRITERION_PUBKEY_HASH);

    int ret = azure_dps_client_query(instance->client_context, query, result);
    if (ret < 0) {
        zlog_error("azure dps client failed to execute query (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Performs authorization against the configured DPS endpoint.
 * 
 * @param instance The provider instance.
 * @return int 0 if the provider was authorized to use the DPS instance,
 * non-zero otherwise.
 */
int
bootstrap_info_provider_azure_dps_authorize(struct bootstrap_info_provider_azure_dps_instance *instance)
{
    int ret = azure_dps_client_authorize(instance->client_context);
    if (ret < 0) {
        zlog_debug("azure dps client failed authorization (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Initializes the provider for use.
 *
 * @param settings The bootstrap info provider settings to use.
 * @param context A pointer where the provider can store arbitrary context.
 * @return int 0 if the provider initialized successfully, non-zero otherwise.
 */
static int
bootstrap_info_provider_azure_dps_op_initialize(const struct bootstrap_info_provider_settings *settings, void **context)
{
    struct bootstrap_info_provider_azure_dps_instance *instance;
    int ret = bootstrap_info_provider_azure_dps_create(&instance, settings->dps);
    if (ret < 0) {
        zlog_error("failed to create azure dps-based bootstrap provider instance (%d)", ret);
        return ret;
    }

    *context = instance;
    return 0;
}

/**
 * @brief Uninitializes a provider. Frees all resources associated with the
 * instance.
 */
void
bootstrap_info_provider_azure_dps_op_uninitialize(void *context)
{
    struct bootstrap_info_provider_azure_dps_instance *instance = (struct bootstrap_info_provider_azure_dps_instance *)context;
    if (!instance)
        return;

    bootstrap_info_provider_azure_dps_destroy(instance);
}

/**
 * @brief Synchronizes the provider's view of bootstrap information with its
 * backing source, in this case, the configured DPS instance.
 * 
 * @return int 0 if synchronization was successful, non-zero otherwise.
 */
static int
bootstrap_info_provider_azure_dps_op_synchronize(void *context, const struct bootstrap_info_sync_options *options)
{
    __unused(options);

    struct bootstrap_info_provider_azure_dps_instance *instance = (struct bootstrap_info_provider_azure_dps_instance *)context;
    if (!instance)
        return -EBADF;

    int ret = bootstrap_info_provider_azure_dps_synchronize(instance);
    if (ret < 0) {
        zlog_debug("failed to synchronize azure dps-based bootstrap info provider (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Queries the provider for bootstrap info record(s).
 *
 * @param query The query describing which records are requested.
 * @param result The structure to store record results.
 * @return int 0 if the query was successful and results provider in 'result',
 * non-zero otherwise.
 */
static int
bootstrap_info_provider_azure_dps_op_query(void *context, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result)
{
    struct bootstrap_info_provider_azure_dps_instance *instance = (struct bootstrap_info_provider_azure_dps_instance *)context;
    if (!instance)
        return -EBADF;

    int ret = bootstrap_info_provider_azure_dps_query(instance, query, result);
    if (ret < 0) {
        zlog_debug("failed to query azure dps-based bootstrap info provider (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Azure DPS provider operation vector. This is provided to ztpd for
 * each installed instance of the Azure DPS provider.
 */
struct bootstrap_info_provider_ops bootstrap_info_provider_azure_dps_ops = {
    .initialize = bootstrap_info_provider_azure_dps_op_initialize,
    .uninitialize = bootstrap_info_provider_azure_dps_op_uninitialize,
    .synchronize = bootstrap_info_provider_azure_dps_op_synchronize,
    .query = bootstrap_info_provider_azure_dps_op_query,
};
