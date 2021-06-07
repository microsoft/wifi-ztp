
#include <errno.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <userspace/linux/compiler.h>
#include <userspace/linux/kernel.h>

#include "bootstrap_info_provider_private.h"
#include "bootstrap_info_provider_settings.h"
#include "dpp.h"
#include "event_loop.h"
#include "string_utils.h"
#include "wpa_controller.h"
#include "wpa_controller_watcher.h"
#include "wpa_core.h"
#include "ztp_configurator.h"
#include "ztp_configurator_config.h"
#include "ztp_log.h"

/**
 * @brief Looks up bootstrap info given a public key "chirp" hash (distinct
 * from the standard cryptographic hash).
 *
 * @param configurator The configurator instance.
 * @param record The output pointer to write the record to. If bootstrap info
 * was found, this will be non-NULL and and must be freed using
 * bootstrap_info_record_destroy(). Otherwise, this will be NULL.
 * @return int 0 if the find operation was successful, non-zero otherwise.
 */
static int
ztp_configurator_bootstrap_info_find(struct ztp_configurator *configurator, const struct dpp_bootstrap_publickey_hash *hash, struct bootstrap_info_record **record)
{
    struct bootstrap_info_query query;
    struct bootstrap_info_query_result result;

    bootstrap_info_query_initialize(&query, hash);
    bootstrap_info_query_result_initialize(&result);

    *record = NULL;

    struct bootstrap_info_provider *provider;
    list_for_each_entry (provider, &configurator->bootstrap_info_providers, list) {
        int ret = bootstrap_info_provider_query(provider, &query, &result);
        if (ret != 0 || list_empty(&result.records))
            continue;

        struct bootstrap_info_record_result_entry *entry;
        entry = list_first_entry(&result.records, struct bootstrap_info_record_result_entry, list);
        list_del_init(&entry->list);
        *record = &entry->record;
        break;
    }

    bootstrap_info_query_result_uninitialize(&result);

    return 0;
}

/**
 * @brief Returns the network configuration for the enrollee with the specified (chirp) hash.
 *
 * @param configurator The configurator instance.
 * @param hash The chirp hash of the enrollee to find the network configuration for.
 * @return struct dpp_network* A pointer to the network the enrollee should be
 * provisioned for, if it exists. NULL if no network is configured.
 */
static struct dpp_network *
ztp_configurator_get_network_config(struct ztp_configurator *configurator, const struct dpp_bootstrap_publickey_hash *hash)
{
    __unused(hash);

    // Per-enrollee networks are not currently supported. Return the default network.
    return configurator->settings->network_config_default;
}

/**
 * @brief Sets the default network to provision enrollees, if none has been specified.
 *
 * @param configurator The configurator to set the default network to provision for.
 * @param network The default network to provision enrollees with.
 * @return int 0 if the specified network will be provisioned as a default, non-zero otherwise.
 */
static int
ztp_configurator_set_default_network(struct ztp_configurator *configurator, struct dpp_network *network)
{
    char params[WPA_CONFIGURATOR_PARAMS_MAX_LENGTH];
    size_t params_length = sizeof params;

    int ret = dpp_network_to_wpa_configurator_params(network, params, &params_length, DPP_NETWORK_ROLE_STATION);
    if (ret < 0) {
        zlog_error_if(configurator->interface, "failed to translate network configuration to wpa configurator params (%d)", ret);
        return ret;
    }

    ret = wpa_controller_set(configurator->ctrl, WPA_CFG_PROPERTY_DPP_CONFIGURATOR_PARAMS, params);
    if (ret < 0) {
        zlog_error_if(configurator->interface, "failed to set '" WPA_CFG_PROPERTY_DPP_CONFIGURATOR_PARAMS "' value with default network (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Registers an enrollee with the (hostapd) configurator. This includes
 * providing its DPP URI (qrcode) and associating the target network
 * provisioning information with the enrollee.
 *
 * @param configurator The configurator instance.
 * @param hash The chirp has of the enrollee to register.
 * @param record The bootstrap info record for the enrollee.
 * @param peer_id The bootstrap identifier of the enrollee (peer) in hostapd.
 * @return int 0 if the enrollee was successfully registered with hostapd. In
 * this case, it should be provisioned the next time it is seen by the
 * configurator.
 */
static int
ztp_configurator_register_enrollee(struct ztp_configurator *configurator, const struct dpp_bootstrap_publickey_hash *hash, struct bootstrap_info_record *record, uint32_t frequency, uint32_t *peer_id)
{
    __unused(frequency);

    int ret = wpa_controller_qrcode(configurator->ctrl, record->dpp_uri, peer_id);
    if (ret < 0) {
        zlog_error_if(configurator->interface, "unable to register qrcode for " DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_FMT " (%d)",
            DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_TOSTRING(hash->data), ret);
        return ret;
    }

    struct dpp_network *network = ztp_configurator_get_network_config(configurator, hash);
    if (!network) {
        zlog_error_if(configurator->interface, "failed to get network configuration for " DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_FMT,
            DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_TOSTRING(hash->data));
        return -ENOENT;
    }

    char conf[WPA_CONFIGURATOR_PARAMS_MAX_LENGTH];
    size_t conf_length = sizeof conf;

    ret = dpp_network_to_wpa_configurator_params(network, conf, &conf_length, DPP_NETWORK_ROLE_STATION);
    if (ret < 0) {
        zlog_error_if(configurator->interface, "failed to translate network configuration to wpa configurator params for " DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_FMT " (%d)",
            DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_TOSTRING(hash->data), ret);
        return ret;
    }

    ret = wpa_controller_dpp_bootstrap_set(configurator->ctrl, *peer_id, conf);
    if (ret < 0) {
        zlog_error_if(configurator->interface, "failed to associate wpa configurator params (network info) for " DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_FMT " (%d)",
            DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_TOSTRING(hash->data), ret);
        return ret;
    }

#if CONFIG_EXPLICIT_AUTH_ON_CHIRP
    ret = wpa_controller_dpp_auth_init_with_conf(configurator->ctrl, *peer_id, frequency, conf);
    if (ret < 0) {
        zlog_warning_if(configurator->interface, "failed to initiate dpp auth for " DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_FMT " (%d); auth will be processed on next chirp rx",
            DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_TOSTRING(hash->data), ret);
    }
#endif // CONFIG_EXPLICIT_AUTH_ON_CHIRP

    return 0;
}

/**
 * @brief Initialize hostapd with any state that it needs to begin operating.
 *
 * @param configurator The configurator instance.
 * @return int 0 if hostapd was successfully initialized with operating state, non-zero otherwise.
 */
static int
ztp_configurator_hostapd_initialize_state(struct ztp_configurator *configurator)
{
    if (configurator->settings->network_config_default) {
        int ret = ztp_configurator_set_default_network(configurator, configurator->settings->network_config_default);
        if (ret < 0) {
            zlog_error_if(configurator->interface, "failed to set default provisioning network (%d)", ret);
            return ret;
        }
    }

    zlog_debug_if(configurator->interface, "hostapd state initialized");
    return 0;
}

/**
 * @brief Resets any internal state related to the hostapd control interface.
 *
 * @param configurator The configurator instance.
 */
static void
ztp_configurator_hostapd_reset_state(struct ztp_configurator *configurator)
{
    zlog_debug_if(configurator->interface, "hostapd state reset");
}

/**
 * @brief Control socket presence event handler.
 *
 * @param context The configurator instance.
 * @param event The event that occurred.
 */
static void
on_control_interface_presence_changed(void *context, enum wpa_controller_presence_event event)
{
    struct ztp_configurator *configurator = (struct ztp_configurator *)context;

    switch (event) {
        case WPA_CONTROLLER_ARRIVED: {
            int ret = ztp_configurator_hostapd_initialize_state(configurator);
            if (ret < 0)
                zlog_error_if(configurator->interface, "failed to initialize hostapd state (%d)", ret);
            break;
        }
        case WPA_CONTROLLER_DEPARTED:
            ztp_configurator_hostapd_reset_state(configurator);
            break;
        default:
            break;
    }
}

/**
 * @brief Chirp received event handler function. This will attempt to lookup
 * any associated bootstrapping information, and subsequently attempt to
 * initiate a DPP provisioning exchange with the identified peer.
 *
 * @param userdata The configurator instance.
 * @param mac The mac address of the source of the chirp.
 * @param hash The "chirp" hash of the peer that wishes to be provisioned.
 */
static void
on_chirp_received(void *userdata, int32_t id, const char (*mac)[(DPP_MAC_LENGTH * 2) + (DPP_MAC_LENGTH - 1) + 1], uint32_t frequency, const struct dpp_bootstrap_publickey_hash *hash)
{
    __unused(mac);

    struct bootstrap_info_record *record;
    struct ztp_configurator *configurator = (struct ztp_configurator *)userdata;

    char hashstr[(DPP_BOOTSTRAP_PUBKEY_HASH_LENGTH * 2) + 1];
    hex_encode(hash->data, sizeof hash->data, hashstr, sizeof hashstr);
    hashstr[sizeof hashstr - 1] = '\0';

    int ret = ztp_configurator_bootstrap_info_find(configurator, hash, &record);
    if (ret < 0) {
        zlog_error_if(configurator->interface, "chirp hash query failed (%d)", ret);
        return;
    } else if (!record) {
        zlog_debug_if(configurator->interface, "bootstrap info not found for %.7s", hashstr);
        return;
    }

    zlog_info_if(configurator->interface, "bootstrap info found, %.7s -> %s", hashstr, record->dpp_uri);

    // If the peer is not known to hostapd (bootstrap id == -1), register its DPP URI.
    uint32_t peer_id = 0;
    if (id == -1) {
        ret = ztp_configurator_register_enrollee(configurator, hash, record, frequency, &peer_id);
        if (ret < 0) {
            zlog_error_if(configurator->interface, "unable to register enrollee (%d)", ret);
            return;
        }
    } else {
        assert(id > 0);
        peer_id = (uint32_t)id;
    }
}

/**
 * @brief Synchronize a single bootstrap info provider.
 *
 * @param provider The provider to synchronize.
 * @param options Options controlling how synchronization should be performed.
 * @return int 0 if the synchronization completed successfully, non-zero otherwise.
 */
static int
ztp_configurator_bootstrap_info_provider_synchronize(struct bootstrap_info_provider *provider, const struct bootstrap_info_sync_options *options)
{
    zlog_debug("[%s] +synchronize", provider->name);

    int ret = bootstrap_info_provider_synchronize(provider, options);
    if (ret < 0) {
        zlog_debug("[%s] bootstrap info provider synchronize() failed (%d)", provider->name, ret);
        goto out;
    }

out:
    zlog_debug("[%s] -synchronize (%d)", provider->name, ret);
    return ret;
}

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
ztp_configurator_synchronize_bootstrapping_info(struct ztp_configurator *configurator, const struct bootstrap_info_sync_options *options)
{
    int num_succeeded = 0;
    struct bootstrap_info_provider *provider;

    list_for_each_entry (provider, &configurator->bootstrap_info_providers, list) {
        if (ztp_configurator_bootstrap_info_provider_synchronize(provider, options) == 0)
            num_succeeded++;
    }

    return num_succeeded;
}

/**
 * @brief Handler for bootstrap info provider synchronization timer timeouts.
 * The timeout expires when the next synchronization must be performed, so this
 * function invokes the provider's synchronize function.
 * @param context The handler context. Must be of type struct
 * bootstrap_info_provider, which is an instance of the provider whose sync
 * timer expired.
 */
static void
ztp_configurator_on_provider_synchronize_timeout(void *context)
{
    struct bootstrap_info_provider *provider = (struct bootstrap_info_provider *)context;
    zlog_debug("[%s] sync time expired", provider->name);

    ztp_configurator_bootstrap_info_provider_synchronize(provider, NULL);
}

/**
 * @brief Cancels periodic synchronization for the specified provider.
 *
 * @param configurator The configurator instance.
 * @param provider The provider to cancel synchronization for.
 */
static void
ztp_configurator_bootstrap_info_provider_cancel_synchronization(struct ztp_configurator *configurator, struct bootstrap_info_provider *provider)
{
    event_loop_task_cancel(configurator->loop, ztp_configurator_on_provider_synchronize_timeout, provider);
}

/**
 * @brief Schedules a timer to perform synchronization according to the providers expiry time.
 *
 * @param configurator The configurator instance.
 * @param provider The provider to schedule for synchronization.
 * @return int 0 if synchronization was successfully scheduled, non-zero otherwise.
 */
static int
ztp_configurator_bootstrap_info_provider_schedule_synchronization(struct ztp_configurator *configurator, struct bootstrap_info_provider *provider)
{
    ztp_configurator_bootstrap_info_provider_cancel_synchronization(configurator, provider);

    if (provider->settings->expiration_time == 0) {
        zlog_debug_if(configurator->interface, "[%s] expiration time not set (0), omitting sync timer", provider->name);
        return 0;
    }

    zlog_debug_if(configurator->interface, "[%s] scheduling sync timer for %us", provider->name, provider->settings->expiration_time);

    int ret = event_loop_task_schedule(configurator->loop, provider->settings->expiration_time, 0, TASK_PERIODIC,
        ztp_configurator_on_provider_synchronize_timeout, provider);
    if (ret < 0) {
        zlog_error_if(configurator->interface, "[%s] failed to schedule synchronization timer (%d)", provider->name, ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Start a bootstrap info provider.
 *
 * @param provider The provider to start.
 * @return int 0 if the provider was started, non-zero otherwise.
 */
static int
ztp_configurator_bootstrap_info_provider_start(struct ztp_configurator *configurator, struct bootstrap_info_provider *provider)
{
    int ret = ztp_configurator_bootstrap_info_provider_schedule_synchronization(configurator, provider);
    if (ret < 0)
        return ret;

    ret = provider->ops->initialize(provider->settings, &provider->context);
    if (ret < 0) {
        zlog_warning_if(configurator->interface, "[%s] failed to start bootstrap info provider (%d)", provider->name, ret);
        ztp_configurator_bootstrap_info_provider_cancel_synchronization(configurator, provider);
        return ret;
    }

    provider->started = true;

    if (event_loop_task_schedule_now(configurator->loop, ztp_configurator_on_provider_synchronize_timeout, provider) < 0)
        zlog_warning_if(configurator->interface, "[%s] initial synchronization failed", provider->name);

    return 0;
}

/**
 * @brief Adds an existing, initialized bootstrap info provider to the configurator.
 *
 * @param configurator The configurator instance.
 * @param provider The provider to add.
 */
static void
ztp_configurator_bootstrap_info_provider_add(struct ztp_configurator *configurator, struct bootstrap_info_provider *provider)
{
    list_add(&provider->list, &configurator->bootstrap_info_providers);
    zlog_info_if(configurator->interface, "[%s] bootstrap info provider with type '%s' added", provider->name, bootstrap_info_provider_type_str(provider->type));
    ztp_configurator_bootstrap_info_provider_start(configurator, provider);
}

/**
 * @brief Uninitializes a configurator instance.
 *
 * @param configurator The configurator to uninitialize.
 */
static void
ztp_configurator_uninitialize(struct ztp_configurator *configurator)
{
    struct bootstrap_info_provider *provider;
    struct bootstrap_info_provider *providertmp;

    list_for_each_entry_safe (provider, providertmp, &configurator->bootstrap_info_providers, list) {
        ztp_configurator_bootstrap_info_provider_cancel_synchronization(configurator, provider);
        bootstrap_info_provider_destroy(provider);
    }

    if (configurator->ctrl) {
        wpa_controller_uninitialize(configurator->ctrl);
        wpa_controller_destroy(&configurator->ctrl);
    }

    if (configurator->interface) {
        free(configurator->interface);
        configurator->interface = NULL;
    }
}

/**
 * @brief Event handler for wpa control socket events.
 */
static struct wpa_event_handler wpa_event_handler_configurator = {
    .interface_presence_changed = on_control_interface_presence_changed,
    .dpp_chirp_received = on_chirp_received,
};

/**
 * @brief The default control socket path to use if none is specified.
 */
#define WPA_CTRL_PATH_BASE_DEFAULT "/var/run/hostapd"

/**
 * @brief Initializes a ztpd configurator instance.
 *
 * @param configurator The configurator instance to initialize.
 * @param interface The name of the interface the configurator is running on.
 * @param settings The settings to use to initialize the instance.
 * @param loop The main ztpd event loop.
 * @return int 0 if the configurator was successfully initialized, otherwise
 * non-zero.
 */
static int
ztp_configurator_initialize(struct ztp_configurator *configurator, const char *interface, struct ztp_configurator_settings *settings, struct event_loop *loop)
{
    int ret;

    INIT_LIST_HEAD(&configurator->bootstrap_info_providers);

    configurator->ctrl = wpa_controller_alloc();
    if (!configurator->ctrl) {
        ret = -ENOMEM;
        zlog_error_if(interface, "failed to allocate wpa controller (%d)", ret);
        goto fail;
    }

    char ctrl_path[128];
    snprintf(ctrl_path, sizeof ctrl_path, "%s/%s", WPA_CTRL_PATH_BASE_DEFAULT, interface);

    ret = wpa_controller_initialize(configurator->ctrl, ctrl_path, loop);
    if (ret < 0) {
        zlog_error_if(interface, "failed to initialize wpa controller (%d)", ret);
        goto fail;
    }

    configurator->loop = loop;
    configurator->settings = settings;
    configurator->interface = strdup(interface);

    if (!configurator->interface) {
        zlog_error(configurator->interface, "failed to allocate memory for interface name");
        ret = -ENOMEM;
        goto fail;
    }

    struct bootstrap_info_provider_settings *bisettings;
    list_for_each_entry (bisettings, &settings->provider_settings, list) {
        struct bootstrap_info_provider *provider = bootstrap_info_provider_create(bisettings);
        if (provider)
            ztp_configurator_bootstrap_info_provider_add(configurator, provider);
    }

    ret = wpa_controller_register_event_handler(configurator->ctrl, &wpa_event_handler_configurator, configurator);
    if (ret < 0) {
        zlog_error(interface, "failed to register wpa event handler (%d)", ret);
        goto fail;
    }

    ret = 0;

out:
    return ret;
fail:
    ztp_configurator_uninitialize(configurator);
    goto out;
}

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
ztp_configurator_create(const char *interface, struct ztp_configurator_settings *settings, struct event_loop *loop, struct ztp_configurator **pconfigurator)
{
    int ret;
    struct ztp_configurator *configurator = calloc(1, sizeof *configurator);
    if (!configurator) {
        zlog_error_if(interface, "failed to allocate memory to create configurator");
        ret = -ENOMEM;
        goto fail;
    }

    configurator->interface = strdup(interface);
    if (!configurator->interface) {
        zlog_error_if(interface, "failed to allocate memory for interface name");
        ret = -ENOMEM;
        goto fail;
    }

    ret = ztp_configurator_initialize(configurator, interface, settings, loop);
    if (ret < 0) {
        zlog_error_if(interface, "failed to initialize configurator (%d)", ret);
        goto fail;
    }

    *pconfigurator = configurator;
out:
    return ret;
fail:
    if (configurator)
        ztp_configurator_destroy(&configurator);
    goto out;
}

/**
 * @brief Destroys a configurator, freeing all owned resources.
 *
 * @param configurator The configurator to destroy.
 */
void
ztp_configurator_destroy(struct ztp_configurator **configurator)
{
    if (!configurator || !*configurator)
        return;

    ztp_configurator_uninitialize(*configurator);
    free(*configurator);

    *configurator = NULL;
}
