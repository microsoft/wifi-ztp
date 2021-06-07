
#ifndef __BOOTSTRAP_INFO_PROVIDER_FILE_H__
#define __BOOTSTRAP_INFO_PROVIDER_FILE_H__

#include <time.h>

#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_file_config.h"

struct json_object;

/**
 * @brief Represents an instance of a file-based provider.
 */
struct bootstrap_info_provider_file_instance {
    uint32_t flags;
    struct bootstrap_info_provider_file_settings *settings;
    struct timespec time_modified;
    struct json_object *jobj_bootstrap_info;
    const char *ptr_base;
    const char *ptr_dpp_uri;
    const char *ptr_publickeyhash;
};

/**
 * @brief Operations vector for file-based bootstrap info provider.
 */
extern struct bootstrap_info_provider_ops bootstrap_info_provider_file_ops;

#endif // __BOOTSTRAP_INFO_PROVIDER_FILE_H__
