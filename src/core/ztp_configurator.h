
#ifndef __ZTP_CONFIGURATOR_H__
#define __ZTP_CONFIGURATOR_H__

#include <stdint.h>
#include <stdlib.h>
#include <userspace/linux/list.h>

#include "bootstrap_info_provider.h"

struct wpa_controller;
struct event_loop;
struct ztp_configurator_settings;

/**
 * @brief DPP configurator.
 */
struct ztp_configurator {
    struct list_head bootstrap_info_providers;
    struct ztp_configurator_settings *settings;
    struct event_loop *loop;
    struct wpa_controller *ctrl;
    char *interface;
};

/**
 * @brief Creates and initializes a new configurator instance.
 *
 * @param interface The name of the interface to run on.
 * @param settings The settings to initialize the configurator with.
 * @param loop The ztpd event loop to run the configurator on.
 * @param pconfigurator Output pointer to accept the configurator instance.
 * @return int 
 */
int
ztp_configurator_create(const char *interface, struct ztp_configurator_settings *settings, struct event_loop *loop, struct ztp_configurator **pconfigurator);

/**
 * @brief Destroys a configurator, freeing all owned resources.
 *
 * @param configurator The configurator to desttroy.
 */
void
ztp_configurator_destroy(struct ztp_configurator **configurator);

/**
 * @brief Synchronizes the bootstrapping info for the configurator. This will
 * request each registered bootstrap information provider synchronize its view
 * immediately.
 * 
 * @param configurator The configurator instance to synchronize.
 * @param options Options controlling how synchronization should be performed.
 * @return int The number of providers that successfully synchronized, or
 * non-zero if synchronization could not be attempted for any of the providers.
 */
int
ztp_configurator_synchronize_bootstrapping_info(struct ztp_configurator *configurator, const struct bootstrap_info_sync_options *options);

#endif //__ZTP_CONFIGURATOR_H__
