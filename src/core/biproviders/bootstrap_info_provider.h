
#ifndef __BOOTSTRAP_INFO_PROVIDER_H__
#define __BOOTSTRAP_INFO_PROVIDER_H__

#include <stdint.h>
#include <stdlib.h>

#include "dpp.h"
#include "userspace/linux/list.h"

struct bootstrap_info_provider_settings;

/**
 * @brief Bootstrapping information record.
 */
struct bootstrap_info_record {
    char *dpp_uri;
};

/**
 * @brief Destroys a bootstrap_info_record that was obtained from
 * bootstrap_info_record_alloc().
 *
 * @param record The record to destroy. Must have been obtained from
 * bootstrap_info_record_alloc().
 */
void
bootstrap_info_record_destroy(struct bootstrap_info_record *record);

/**
 * @brief Bootstrap info provider type.
 */
enum bootstrap_info_provider_type {
    BOOTSTRAP_INFO_PROVIDER_INVALID = 0,
    BOOTSTRAP_INFO_PROVIDER_FILE,
    BOOTSTRAP_INFO_PROVIDER_AZUREDPS,
};

/**
 * @brief Converts a string to a bootstrap info provider type.
 *
 * @param type The string representing the bootstrap info provider type.
 * @return enum bootstrap_info_provider_type The corresponding provider type,
 * if valid. Otherwise, BOOTSTRAP_INFO_PROVIDER_INVALID is returned.
 */
enum bootstrap_info_provider_type
parse_bootstrap_info_provider_type(const char *type);

/**
 * @brief Converts a bootstrap info provider type to a string.
 *
 * @param type The type to convert.
 * @return const char* A string representing the type.
 */
const char *
bootstrap_info_provider_type_str(enum bootstrap_info_provider_type type);

/**
 * @brief Bootstrap information query criterion type.
 *
 * Describes all the types of criteria that may be present in a bootstrapping
 * information query of a provider.
 */
enum bootstrap_info_query_criterion_type {
    BOOTSTRAP_INFO_QUERY_CRITERION_PUBKEY_HASH = 0,
    BOOTSTRAP_INFO_QUERY_CRITERION_MAC,
    BOOTSTRAP_INFO_QUERY_CRITERION_URI_INFO,
};

/**
 * @brief Bootstrap information query criterion. This represents a single
 * criterion, the type of which is specified by the 'type' field. The
 * corresponding field of the 'data' union must be used. The following maps the
 * type to the union fields:
 *
 *     BOOTSTRAP_INFO_QUERY_CRITERION_PUBKEY_HASH -> pubkey_hash
 *     BOOTSTRAP_INFO_QUERY_CRITERION_MAC         -> mac
 *     BOOTSTRAP_INFO_QUERY_CRITERION_URI_INFO    -> uri_info
 */
struct bootstrap_info_query_criterion {
    enum bootstrap_info_query_criterion_type type;
    union {
        struct {
            const uint8_t (*data)[DPP_MAC_LENGTH];
            char hexstr[(DPP_MAC_LENGTH * 2) + 1];
        } mac;
        struct {
            const struct dpp_bootstrap_publickey_hash *hash;
            char hexstr[(DPP_BOOTSTRAP_PUBKEY_HASH_LENGTH * 2) + 1];
        } pubkey_hash;
        const char *uri_info;
    } data;
};

/**
 * @brief All criteria provided must match. By default, any matching  criteria
 * should produce a positive result/match.
 */
#define BOOTSTRAP_INFO_QUERY_OPTION_ALL_OR_NOTHING (0x00000001u)

/**
 * @brief The query should complete once (if) a single record has matched. This
 * implies only one record should be returned, even if multiple records are
 * available; the first matching record should be returned. For providers that
 * match records in parallel, the following order of criteria precedence should
 * be used to determine which record to return first:
 *
 *      1) BOOTSTRAP_INFO_QUERY_CRITERION_PUBKEY_HASH
 *      2) BOOTSTRAP_INFO_QUERY_CRITERION_MAC
 *      3) BOOTSTRAP_INFO_QUERY_CRITERION_URI_INFO
 */
#define BOOTSTRAP_INFO_QUERY_OPTION_SINGLE (0x00000002u)

/**
 * @brief Bootstrapping information query. Contains information a provider needs
 * to lookup bootstrapping information from its backing source.
 *
 * The 'criterion' field will always be of type
 * BOOTSTRAP_INFO_QUERY_CRITERION_PUBKEY_HASH. This criteria must always match,
 * regardless of any option or extra criteria specified.
 */
struct bootstrap_info_query {
    uint32_t options;
    struct bootstrap_info_query_criterion criterion;
    struct bootstrap_info_query_criterion *criteria_extra;
    size_t criteria_extra_num;
};

/**
 * @brief Initializes a bootstrap info query with required inputs.
 *
 * @param query The query to initialize.
 * @param hash The public key hash to serve as the primary, required criteria.
 */
void
bootstrap_info_query_initialize(struct bootstrap_info_query *query, const struct dpp_bootstrap_publickey_hash *hash);

/**
 * @brief The result of querying a provider. This is a forward declaration as
 * bootstrap info providers should not interact with the result structure
 * directly. Instead, they should use the convenience functions
 * bootstrap_info_query_result_*.
 */
struct bootstrap_info_query_result;

/**
 * @brief Adds a record to the query result.
 *
 * @param dpp_uri The dpp uri to add to the query result.
 */
int
bootstrap_info_query_result_add(struct bootstrap_info_query_result *result, const char *dpp_uri);

/**
 * @brief Initializes a query result.
 *
 * @param result The result to initialize.
 */
void
bootstrap_info_query_result_initialize(struct bootstrap_info_query_result *result);

/**
 * @brief Uninitializes a query result, releasing any owned resources.
 *
 * @param result The result to uninitialize.
 */
void
bootstrap_info_query_result_uninitialize(struct bootstrap_info_query_result *result);

/**
 * @brief Options controlling how synchronization should be performed.
 * Currently none exist, however, to keep the interface stable, the structure
 * is defined and included in the synchronize API.
 */
struct bootstrap_info_sync_options {
    int sentinel;
};

/**
 * @brief Bootstrap information provider operation vector. Contains the
 * provider specific implementation of the bootstrap information provider
 * interface.
 */
struct bootstrap_info_provider_ops {
    /**
     * @brief Initializes a provider for use.
     *
     * It is not expected that the provider ensures an initially synchronized
     * view following initialization. The provider should only synchronize its
     * view of bootstrapping information when the synchronization operation is
     * invoked.
     *
     * The implementation must return 0 for the provider to be used by the
     * controlling daemon. Any non-zero value returned indicates failure to
     * initialize.
     *
     * @param settings The common settings for this provider.
     * @param context An output pointer to store context associated with the
     * instance. This context is passed to each provider operation and may be
     * used to save state.
     * @return Returns 0 if the provider successfully initialized, non-zero
     * otherwise.
     */
    int (*initialize)(const struct bootstrap_info_provider_settings *settings, void **context);

    /**
     * @brief Uninitializes a provider, freeing all owned resources.
     *
     * @param context The instance context associated during initialize.
     */
    void (*uninitialize)(void *context);

    /**
     * @brief Synchronize the logical view of bootstrap information with its backing.
     *
     * Following successful execution of this function, the view of bootstrap
     * information must be current. This means that all bootstrap information
     * added since the last successful synchronization call must be available in response to a query.
     *
     * @param context The instance context associated during initialize.
     * @param options Options controlling how synchronization should be performed.
     */
    int (*synchronize)(void *context, const struct bootstrap_info_sync_options *options);

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
     * @param context The instance context associated during initialize.
     * @param query The query to perform, containing the criteria and options
     * controlling how to perform or filter the query.
     * @param result The result of the query operation.
     */
    int (*query)(void *context, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result);
};

/**
 * @brief Bootstrap information provider.
 */
struct bootstrap_info_provider {
    struct list_head list;
    char *name;
    void *context;
    bool started;
    enum bootstrap_info_provider_type type;
    struct bootstrap_info_provider_ops *ops;
    struct bootstrap_info_provider_settings *settings;
};

/**
 * @brief Creates a new bootstrap info provider.
 *
 * @param settings The settings to use to initialize the provider with.
 * @return struct bootstrap_info_provider*
 */
struct bootstrap_info_provider *
bootstrap_info_provider_create(struct bootstrap_info_provider_settings *settings);

/**
 * @brief Destroy a bootstrap info provider. This will uninitialize the
 * provider and free its memory.
 *
 * @param provider The provider to destroy.
 */
void
bootstrap_info_provider_destroy(struct bootstrap_info_provider *provider);

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
bootstrap_info_provider_synchronize(struct bootstrap_info_provider *provider, const struct bootstrap_info_sync_options *options);

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
bootstrap_info_provider_query(struct bootstrap_info_provider *provider, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result);

#endif // __BOOTSTRAP_INFO_PROVIDER_H__
