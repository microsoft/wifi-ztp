
#include <errno.h>
#include <json-c/json_object.h>
#include <json-c/json_pointer.h>
#include <json-c/json_util.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <userspace/linux/compiler.h>

#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_file.h"
#include "bootstrap_info_provider_file_config.h"
#include "bootstrap_info_provider_settings.h"
#include "json_parse.h"
#include "time_utils.h"
#include "ztp_log.h"

/**
 * @brief Read all the bootstrap information from the file. This will place a
 * pointer to the base array which contains the bootstrapping information into
 * the 'jobj_bootstrap_info' field.
 *
 * @param instance The instance object.
 * @return int 0 if successful, non-zero otherwise.
 */
static int
bootstrap_info_provider_file_read_all(struct bootstrap_info_provider_file_instance *instance)
{
    int ret;
    const char *path = instance->settings->path;
    const char *pointer = instance->settings->json_pointer_array;

    struct json_object *jobj_bootstrap_info = NULL;
    struct json_object *jobj = json_object_from_file(path);
    if (!jobj) {
        const char *err = json_util_get_last_err();
        zlog_error("failed parsing bootstrap info provider record file %s (%s)", path, err);
        return -1;
    }

    json_type type_root = json_object_get_type(jobj);
    if (type_root == json_type_array) {
        jobj_bootstrap_info = jobj;
    } else {
        ret = json_pointer_get(jobj, pointer, &jobj_bootstrap_info);
        if (ret < 0) {
            zlog_error("failed to resolve boot info records from json pointer %s in file %s (%d)", pointer, path, ret);
            goto out;
        }

        json_type type_info = json_object_get_type(jobj_bootstrap_info);
        if (type_info != json_type_array) {
            zlog_error("json pointer does not refer to array type (actual=%s)", json_type_to_name(type_info));
            goto out;
        }
    }

    json_object_get(jobj_bootstrap_info);
    instance->jobj_bootstrap_info = jobj_bootstrap_info;

    // Refresh the saved file modification time. If this fails, set the modification time manually such that it is
    struct stat statbuf;
    ret = stat(path, &statbuf);
    if (ret < 0) {
        zlog_warning("failed to retrieve last modidication time for %s", path);
    } else {
        instance->time_modified = statbuf.st_mtim;
    }

out:
    json_object_put(jobj);
    return ret;
}

/**
 * @brief Initialize a new provider instance. This will parse the settings,
 * associate them with the instance and prepare the provider for use.
 *
 * @param instance  The instance to initialize. It is assumed that object describes an uninitialized provider.
 * @param settings The settings for the provider.
 * @return int 0 if the provider was successfully initialized, non-zero otherwise.
 */
static int
bootstrap_info_provider_file_initialize(struct bootstrap_info_provider_file_instance *instance, struct bootstrap_info_provider_file_settings *settings)
{
    instance->settings = settings;

    // Set last modified time to 0 to force the first synchronization.
    instance->time_modified.tv_sec = 0;
    instance->time_modified.tv_nsec = 0;

    instance->ptr_base = instance->settings->json_pointer_object_base
        ? instance->settings->json_pointer_object_base
        : "/";

    instance->ptr_dpp_uri = instance->settings->json_key_dpp_uri
        ? instance->settings->json_key_dpp_uri
        : "/" JSON_PROPERTY_NAME_DPP_URI;

    instance->ptr_publickeyhash = instance->settings->json_key_publickeyhash
        ? instance->settings->json_key_publickeyhash
        : "/" JSON_PROPERTY_NAME_PUBLIC_KEY_HASH;

    return 0;
}

/**
 * @brief Creates and initializes a new instance of a file-based bootstrap info provider.
 *
 * @param out The output pointer to write the new instance to.
 * @param settings The settings to be associated with the instance.
 * @return int 0 if the instance was created, *instance will hold the newly
 * created object. Otherwise a non-zero value will be returned, with *instance
 * having the value NULL.
 */
static int
bootstrap_info_provider_file_create(struct bootstrap_info_provider_file_instance **out, struct bootstrap_info_provider_file_settings *settings)
{
    *out = NULL;

    struct bootstrap_info_provider_file_instance *instance = calloc(1, sizeof *instance);
    if (!instance) {
        zlog_error("allocation failure creating file-based bootstrap info provider");
        return -ENOMEM;
    }

    int ret = bootstrap_info_provider_file_initialize(instance, settings);
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
bootstrap_info_provider_file_uninitialize(struct bootstrap_info_provider_file_instance *instance)
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
bootstrap_info_provider_file_destroy(struct bootstrap_info_provider_file_instance *instance)
{
    bootstrap_info_provider_file_uninitialize(instance);
    free(instance);
}

/**
 * @brief Determines if the file data backing this provider is dirty. The file
 * data is dirty if it has changed since the last time it was accessed.
 *
 * Note that this is not a strict check. The file's last modification time is
 * used to examine if the contents have changed. It is possible that the file
 * was opened and written back as-is. In this case, the file modification time
 * will change but the contents will be identical. Similarly, the records
 * stored in the file can stay the same but be re-written in a different order.
 * This will be detected as a change despite the record content remaining
 * unchanged. It is expected these scenarios will not often occur so this
 * approach is acceptable.
 *
 * @param instance The instance to check for dirtiness.
 * @return true If the file data has changed since the last time it was read.
 * @return false If the file data has not changed since the last time is was read.
 */
static bool
bootstrap_info_provider_file_is_dirty(struct bootstrap_info_provider_file_instance *instance)
{
    struct stat statbuf;

    int ret = stat(instance->settings->path, &statbuf);
    if (ret < 0) {
        ret = errno;
        zlog_warning("stat() dirty check of %s failed (%d), assuming dirty", instance->settings->path, ret);
        return true;
    }

    return timespeccmp(&statbuf.st_mtim, &instance->time_modified, !=);
}

/**
 * @brief Wrapper to synchronize the file contents with the in-memory contents.
 *
 * @param instance The instance object.
 * @return int 0 if the in-memory contents are in sync with the file contents.
 * Non-zero otherwise.
 */
static int
bootstrap_info_provider_file_synchronize(struct bootstrap_info_provider_file_instance *instance)
{
    if (!bootstrap_info_provider_file_is_dirty(instance))
        return 0;

    int ret = bootstrap_info_provider_file_read_all(instance);
    if (ret < 0) {
        zlog_warning("failed to synchronize bootstrap info (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief JSON parsing context that is passed to the query_bootstrap_info_entry
 * function, which is used to process json array entries that contain
 * bootstrapping information.
 */
struct query_bootstrap_info_entry_context {
    const struct bootstrap_info_query *query;
    struct bootstrap_info_query_result *result;
    struct bootstrap_info_provider_file_instance *instance;
    const char *ptr_publickey;
    const char *ptr_publickeyhash;
};

/**
 * @brief
 *
 * @param parent
 * @apram array
 * @param name
 * @param value
 * @param index
 * @param type
 * @param context
 */
static int
query_bootstrap_info_entry(struct json_object *parent, struct json_object *array, const char *name, struct json_object *value, uint32_t index, json_type type, void *context)
{
    __unused(parent);
    __unused(array);
    __unused(name);
    __unused(index);
    __unused(type);

    struct query_bootstrap_info_entry_context *opts = (struct query_bootstrap_info_entry_context *)context;

    struct json_object *jobj_pkhash = NULL;
    int ret = json_pointer_getf(value, &jobj_pkhash, "%s/%s", opts->instance->ptr_base, opts->instance->ptr_publickeyhash);
    if (ret < 0) {
        zlog_warning("unable to find public key hash entry");
        return JSON_ITERATE_CONTINUE;
    }

    json_type type_pkhash = json_object_get_type(jobj_pkhash);
    if (type_pkhash != json_type_string) {
        zlog_warning("unexpected type for public key hash (%s)", json_type_to_name(type_pkhash));
        return JSON_ITERATE_CONTINUE;
    }

    const char *pkhashstr = json_object_get_string(jobj_pkhash);
    if (strcmp(pkhashstr, opts->query->criterion.data.pubkey_hash.hexstr))
        return JSON_ITERATE_CONTINUE;

    struct json_object *jobj_dpp_uri = NULL;
    ret = json_pointer_getf(value, &jobj_dpp_uri, "%s/%s", opts->instance->ptr_base, opts->instance->ptr_dpp_uri);
    if (ret < 0) {
        zlog_error("unable to retrieve public key for matching hash '%s' (%d)", pkhashstr, ret);
        return JSON_ITERATE_CONTINUE;
    }

    const char *dpp_uri = json_object_get_string(jobj_dpp_uri);
    if (!dpp_uri) {
        zlog_error("failed to allocate buffer for bootstrap info public key");
        return JSON_ITERATE_CONTINUE;
    }

    ret = bootstrap_info_query_result_add(opts->result, dpp_uri);
    if (ret < 0) {
        zlog_error("failed to add matching bootstrap info record to result (%d)", ret);
        return JSON_ITERATE_CONTINUE;
    }

    return JSON_ITERATE_STOP;
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
bootstrap_info_provider_file_query(struct bootstrap_info_provider_file_instance *instance, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result)
{
    assert(query->criterion.type == BOOTSTRAP_INFO_QUERY_CRITERION_PUBKEY_HASH);

    struct query_bootstrap_info_entry_context context = {
        .query = query,
        .result = result,
        .instance = instance,
    };

    json_for_each_array_entry_ss(NULL, instance->jobj_bootstrap_info, "bip-file", query_bootstrap_info_entry, &context);

    return 0;
}

/**
 * @brief
 *
 * @param settings
 * @param context
 * @return int
 */
static int
bootstrap_info_provider_file_op_initialize(const struct bootstrap_info_provider_settings *settings, void **context)
{
    struct bootstrap_info_provider_file_instance *instance;
    int ret = bootstrap_info_provider_file_create(&instance, settings->file);
    if (ret < 0) {
        zlog_error("failed to create file-based bootstrap provider instance (%d)", ret);
        return ret;
    }

    *context = instance;
    return 0;
}

/**
 * @brief
 *
 */
void
bootstrap_info_provider_file_op_uninitialize(void *context)
{
    struct bootstrap_info_provider_file_instance *instance = (struct bootstrap_info_provider_file_instance *)context;
    if (!instance)
        return;

    bootstrap_info_provider_file_destroy(instance);
}

/**
 * @brief
 *
 * @return int
 */
static int
bootstrap_info_provider_file_op_synchronize(void *context, const struct bootstrap_info_sync_options *options)
{
    __unused(options);

    struct bootstrap_info_provider_file_instance *instance = (struct bootstrap_info_provider_file_instance *)context;
    if (!instance)
        return -EBADF;

    int ret = bootstrap_info_provider_file_synchronize(instance);
    if (ret < 0) {
        zlog_debug("failed to synchronize file-based bootstrap info provider (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief
 *
 * @param query
 * @param result
 * @return int
 */
static int
bootstrap_info_provider_file_op_query(void *context, const struct bootstrap_info_query *query, struct bootstrap_info_query_result *result)
{
    struct bootstrap_info_provider_file_instance *instance = (struct bootstrap_info_provider_file_instance *)context;
    if (!instance)
        return -EBADF;

    int ret = bootstrap_info_provider_file_query(instance, query, result);
    if (ret < 0) {
        zlog_debug("failed to query file-based bootstrap info provider (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief File provider operation vector. This is provided to ztpd for each
 * installed instance of the file provider.
 */
struct bootstrap_info_provider_ops bootstrap_info_provider_file_ops = {
    .initialize = bootstrap_info_provider_file_op_initialize,
    .uninitialize = bootstrap_info_provider_file_op_uninitialize,
    .synchronize = bootstrap_info_provider_file_op_synchronize,
    .query = bootstrap_info_provider_file_op_query,
};
