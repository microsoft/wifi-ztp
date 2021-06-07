
#ifndef __BOOTSTRAP_INFO_PROVIDER_PRIVATE_H__
#define __BOOTSTRAP_INFO_PROVIDER_PRIVATE_H__

#include <stdint.h>
#include <userspace/linux/list.h>

#include "bootstrap_info_provider.h"

/**
 * @brief Cookie value that ensures bootstrap info records are authentic (ie.
 * obtained from bootstap_info_record_alloc()).
 */
#define BOOTSTRAP_INFO_RECORD_RESULT_ENTRY_COOKIE (0x0A0A0A0A)

/**
 * @brief Result structure to aid tracking results from bootstrap info
 * providers. This allows the providers to use dedicated functions to safely
 * allocate, destroy and add records to a query result.
 */
struct bootstrap_info_record_result_entry {
    struct list_head list;
    struct bootstrap_info_record record;
    uint32_t cookie;
};

/**
 * @brief The result of querying a provider.
 */
struct bootstrap_info_query_result {
    struct list_head records;
};

#endif //__BOOTSTRAP_INFO_PROVIDER_PRIVATE_H__
