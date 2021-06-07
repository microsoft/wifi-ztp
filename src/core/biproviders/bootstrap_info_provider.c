
#include <errno.h>
#include <string.h>
#include <userspace/linux/kernel.h>

#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps.h"
#include "bootstrap_info_provider_file.h"
#include "bootstrap_info_provider_private.h"
#include "bootstrap_info_provider_settings.h"
#include "string_utils.h"
#include "ztp_log.h"

/**
 * @brief Converts a string to a bootstrap info provider type.
 *
 * @param type The string representing the bootstrap info provider type.
 * @return enum bootstrap_info_provider_type The corresponding provider type,
 * if valid. Otherwise, BOOTSTRAP_INFO_PROVIDER_INVALID is returned.
 */
enum bootstrap_info_provider_type
parse_bootstrap_info_provider_type(const char *type)
{
    if (strcmp(type, "file") == 0) {
        return BOOTSTRAP_INFO_PROVIDER_FILE;
    } else if (strcmp(type, "azuredps") == 0) {
        return BOOTSTRAP_INFO_PROVIDER_AZUREDPS;
    } else {
        return BOOTSTRAP_INFO_PROVIDER_INVALID;
    }
}

/**
 * @brief Converts a bootstrap info provider type to a string.
 *
 * @param type The type to convert.
 * @return const char* A string representing the type.
 */
const char *
bootstrap_info_provider_type_str(enum bootstrap_info_provider_type type)
{
    switch (type) {
        case BOOTSTRAP_INFO_PROVIDER_FILE:
            return "file";
        case BOOTSTRAP_INFO_PROVIDER_AZUREDPS:
            return "azuredps";
        default:
            return "invalid";
    }
}

/**
 * @brief Initializes a bootstrap info provider.
 *
 * @param provider The provider instance to initialize.
 * @param settings The settings to use for the provider.
 * @return int 0 if the provider was successfully initialized, non-zero
 * otherwise.
 */
static int
bootstrap_info_provider_initialize(struct bootstrap_info_provider *provider, struct bootstrap_info_provider_settings *settings)
{
    switch (settings->type) {
        case BOOTSTRAP_INFO_PROVIDER_FILE:
            provider->ops = &bootstrap_info_provider_file_ops;
            break;
        case BOOTSTRAP_INFO_PROVIDER_AZUREDPS:
            provider->ops = &bootstrap_info_provider_azure_dps_ops;
            break;
        default:
            return -EINVAL;
    }

    char *name = strdup(settings->name);
    if (!name)
        return -ENOMEM;

    provider->name = name;
    provider->type = settings->type;
    provider->context = NULL;
    provider->settings = settings;
    provider->started = false;

    return 0;
}

/**
 * @brief Uninitialize a bootstrap info provider.
 *
 * @param provider The provider to uninitialize.
 */
static void
bootstrap_info_provider_uninitialize(struct bootstrap_info_provider *provider)
{
    bootstrap_info_provider_settings_uninitialize(provider->settings);

    provider->type = BOOTSTRAP_INFO_PROVIDER_INVALID;
    provider->settings = NULL;
    provider->ops = NULL;
    provider->started = false;

    if (provider->name) {
        free(provider->name);
        provider->name = NULL;
    }

    if (!list_empty(&provider->list))
        list_del(&provider->list);
}

/**
 * @brief Creates a new bootstrap info provider.
 *
 * @param settings The settings to use to initialize the provider with.
 * @return struct bootstrap_info_provider*
 */
struct bootstrap_info_provider *
bootstrap_info_provider_create(struct bootstrap_info_provider_settings *settings)
{
    struct bootstrap_info_provider *provider = calloc(1, sizeof *provider);
    if (!provider) {
        zlog_error("failed to allocate memory for bootstrap info provider");
        return NULL;
    }

    int ret = bootstrap_info_provider_initialize(provider, settings);
    if (ret < 0) {
        zlog_error("failed to initialize bootstrap info provider (%d)", ret);
        free(provider);
        return NULL;
    }

    return provider;
}

/**
 * @brief Destroy a bootstrap info provider. This will uninitialize the
 * provider and free its memory.
 *
 * @param provider The provider to destroy.
 */
void
bootstrap_info_provider_destroy(struct bootstrap_info_provider *provider)
{
    if (!provider)
        return;

    bootstrap_info_provider_uninitialize(provider);
    free(provider);
}

/**
 * @brief Get the containing bootstrap_info_record_result_entry structure
 * pointer from a record.
 *
 * No validity checks are done on the returned pointer. It is assumed that the
 * input pointer ('record') did in fact come from a proper container of type
 * struct bootstrap_info_record_result_entry.
 *
 * @param record The record to get the parent container for.
 * @return struct bootstrap_info_record_result_entry* A pointer to the
 * containing struct bootstrap_info_record_result_entry structure.
 */
static struct bootstrap_info_record_result_entry *
record_to_entry(struct bootstrap_info_record *record)
{
    return container_of(record, struct bootstrap_info_record_result_entry, record);
}

static void
bootstrap_info_query_result_entry_destroy(struct bootstrap_info_record_result_entry *entry);

/**
 * @brief Destroys a bootstrap_info_record that was obtained from
 * bootstrap_info_record_alloc().
 *
 * @param record The record to destroy.
 */
void
bootstrap_info_record_destroy(struct bootstrap_info_record *record)
{
    bootstrap_info_query_result_entry_destroy(record_to_entry(record));
}

/**
 * @brief Uninitialize a bootstrap info record.
 *
 * @param record The record to uninitialize.
 */
static void
bootstrap_info_record_uninitialize(struct bootstrap_info_record *record)
{
    if (record->dpp_uri) {
        free(record->dpp_uri);
        record->dpp_uri = NULL;
    }
}

/**
 * @brief Determines if the specified entry is valid. Specifically, this
 * ensures the record was allocated as part of
 * bootstrap_info_record_result_alloc().
 *
 * @param result The result to check for validity.
 * @return true If the result is valid.
 * @return false If the result is invalid.
 */
static bool
bootstrap_info_record_result_entry_is_valid(struct bootstrap_info_record_result_entry *result)
{
    return (result && (result->cookie == BOOTSTRAP_INFO_RECORD_RESULT_ENTRY_COOKIE));
}

/**
 * @brief Destroy a query result entry, releasing any owned resources.
 *
 * @param entry The entry to destroy.
 */
static void
bootstrap_info_query_result_entry_destroy(struct bootstrap_info_record_result_entry *entry)
{
    if (!entry)
        return;

    if (!bootstrap_info_record_result_entry_is_valid(entry)) {
        zlog_warning("invalid bootstrap_info_record specified (missing or invalid cookie)");
        return;
    }

    bootstrap_info_record_uninitialize(&entry->record);

    if (!list_empty(&entry->list))
        list_del(&entry->list);

    free(entry);
}

/**
 * @brief Initializes a query result.
 *
 * @param result The result to initialize.
 */
void
bootstrap_info_query_result_initialize(struct bootstrap_info_query_result *result)
{
    INIT_LIST_HEAD(&result->records);
}

/**
 * @brief Uninitializes a query result, releasing any owned resources.
 *
 * @param result The result to uninitialize.
 */
void
bootstrap_info_query_result_uninitialize(struct bootstrap_info_query_result *result)
{
    struct bootstrap_info_record_result_entry *entry;
    struct bootstrap_info_record_result_entry *entrytmp;

    list_for_each_entry_safe (entry, entrytmp, &result->records, list) {
        bootstrap_info_query_result_entry_destroy(entry);
    }
}

/**
 * @brief Initializes a bootstrap info query with required inputs.
 *
 * @param query The query to initialize.
 * @param hash The public key hash to serve as the primary, required criteria.
 */
void
bootstrap_info_query_initialize(struct bootstrap_info_query *query, const struct dpp_bootstrap_publickey_hash *hash)
{
    query->options = 0;
    query->criteria_extra_num = 0;

    struct bootstrap_info_query_criterion *criterion = &query->criterion;
    criterion->type = BOOTSTRAP_INFO_QUERY_CRITERION_PUBKEY_HASH;
    criterion->data.pubkey_hash.hash = hash;

    hex_encode(hash->data, sizeof hash->data, criterion->data.pubkey_hash.hexstr, sizeof query->criterion.data.pubkey_hash.hexstr);
}

/**
 * @brief Adds a record to the query result.
 *
 * @param record The record to add to the query result.
 */
int
bootstrap_info_query_result_add(struct bootstrap_info_query_result *result, const char *dpp_uri)
{
    struct bootstrap_info_record_result_entry *entry = calloc(1, sizeof *entry);
    if (!entry) {
        zlog_error("failed to allocate query result record");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&entry->list);
    entry->cookie = BOOTSTRAP_INFO_RECORD_RESULT_ENTRY_COOKIE;
    entry->record.dpp_uri = strdup(dpp_uri);
    if (!entry->record.dpp_uri) {
        zlog_error("failed to allocate query result dpp_uri");
        return -ENOMEM;
    }

    list_add(&entry->list, &result->records);

    return 0;
}

/**
 * @brief Synchronize the logical view of bootstrap information with its backing.
 *
 * Following successful execution of this function, the view of bootstrap
 * information must be current. This means that all bootstrap information
 * added since the last successful synchronization call must be available in response to a query.
 *
 * @param provider The provider to execute the operation on.
 * @param options Options controlling how synchronization should be performed.
 * @return int
 */
int
bootstrap_info_provider_synchronize(struct bootstrap_info_provider *provider, const struct bootstrap_info_sync_options *options)
{
    if (!provider->ops->synchronize)
        return -EOPNOTSUPP;
    if (!provider->context)
        return -EINVAL;

    return provider->ops->synchronize(provider->context, options);
}

/**
 * @brief Queries the provider for bootstrapping information matching a set
 * of criteria.
 *
 * Every query must match the fixed criteria in the 'criterion' field,
 * which will always be of type BOOTSTRAP_INFO_QUERY_CRITERION_PUBKEY_HASH.
 * Additional criteria may be specified by the framework in the
 * 'criteria_extra' field. Providers may use this criteria, if specified,
 * to improve query performance or to implement storage of records in a
 * more efficient way.
 *
 * Matching records must be added to the 'result' argument. This is an
 * opaque structure which cannot be interacted with directly. Instead,
 * convenience functions are provided for allocating records and adding
 * them to the result structure.
 *
 * To allocate a record for inclusion in a query result, providers should
 * use bootstrap_info_record_alloc().
 *
 * To include a record in a query result, use
 * bootstrap_info_query_add_result().
 *
 * @param provider The provider to execute the operation on.
 * @param query The query to perform, containing the criteria and options
 * controlling how to perform or filter the query.
 * @param result The result of the query operation.
 */
int
bootstrap_info_provider_query(struct bootstrap_info_provider *provider, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result)
{
    if (!provider->ops->query)
        return -EOPNOTSUPP;
    if (!provider->context)
        return -EINVAL;

    return provider->ops->query(provider->context, query, result);
}
