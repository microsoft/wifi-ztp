
#include <cerrno>
#include <memory>

extern "C" {
#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps.h"
}

#include "azure_dps_service_client.h"
#include "azure_dps_service_client_log.h"
#include "azure_dps_service_client_proxy.h"

/**
 * @brief Cookies value used to check the sanity of a bare (void*) pointer that
 * is being resolved to an instance pointer.
 */
#define AZURE_DPS_CLIENT_CONTEXT_COOKIE (0xAA55AA55)

/**
 * @brief Tracks context information associated with an azure dps service
 * client. This structure also contains information needed to marshal data
 * between the ztp bootstrap information provider (BIP) C interface and the
 * service client C++ implementation.
 */
struct azure_dps_client_context {
    const uint32_t cookie = AZURE_DPS_CLIENT_CONTEXT_COOKIE;
    std::unique_ptr<azure_dps_service_client> instance = nullptr;

    /**
     * @brief Resolves a bare (void*) pointer to an azure_dps_client_context
     * instance. If the specified bare pointer is invalid, nullptr is returned.
     * Otherwise a properly typed pointer to the instance is returned.
     *
     * @param client_context
     * @return struct azure_dps_client_context*
     */
    static struct azure_dps_client_context *
    resolve(void *client_context)
    {
        auto *context = reinterpret_cast<struct azure_dps_client_context *>(client_context);
        if (!context || context->cookie != AZURE_DPS_CLIENT_CONTEXT_COOKIE)
            return nullptr;

        return context;
    }
};

/**
 * @brief Initializes a new azure dps service client.
 *
 * @param settings The bootstrap info provider settings to use.
 * @param client_context A pointer where arbitrary context information may be
 * stored.
 * @return int 0 if the client was successfully initialized, non-zero otherwise.
 */
int
azure_dps_client_initialize(const struct bootstrap_info_provider_azure_dps_settings *settings, void **client_context)
{
    auto context = std::make_unique<azure_dps_client_context>();
    if (!context)
        return -ENOMEM;

    context->instance = std::make_unique<azure_dps_service_client>(settings);

    *client_context = context.release();

    return 0;
}

/**
 * @brief Uninitializes an existing azure dps service client.
 *
 * @param client_context A pointer to the azure_dps_client_context instance
 * created in azure_dps_client_initialize.
 */
void
azure_dps_client_uninitialize(void *client_context)
{
    auto *context = azure_dps_client_context::resolve(client_context);
    if (!context)
        return;

    std::unique_ptr<struct azure_dps_client_context>(context).reset(nullptr);
}

/**
 * @brief Synchronizes the view of the bootstrap information between dps and ztp.
 *
 * @param client_context A pointer to the azure_dps_client_context instance
 * created in azure_dps_client_initialize.
 * @return int 0 if the in-memory contents are in sync with the DPS instance.
 * Non-zero otherwise.
 */
int
azure_dps_client_synchronize(void *client_context)
{
    auto *context = azure_dps_client_context::resolve(client_context);
    if (!context)
        return -EBADF;

    int ret = context->instance->synchronize_dps_bi();
    if (ret < 0)
        return ret;

    return 0;
}

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
azure_dps_client_query(void *client_context, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result)
{
    auto *context = azure_dps_client_context::resolve(client_context);
    if (!context)
        return -EBADF;

    std::string chirp_hash = query->criterion.data.pubkey_hash.hexstr;
    std::string matched_dpp_uri;

    int ret = context->instance->lookup_dpp_uri(chirp_hash, matched_dpp_uri);
    if (ret < 0)
        return -ENOENT;

    ret = bootstrap_info_query_result_add(result, matched_dpp_uri.c_str());
    if (ret < 0)
        return ret;

    return 0;
}

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
azure_dps_client_authorize(void *client_context)
{
    auto *context = azure_dps_client_context::resolve(client_context);
    if (!context)
        return -EBADF;

    int ret = context->instance->authorize();
    if (ret < 0)
        return ret;

    return 0;
}
