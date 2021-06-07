
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <userspace/linux/compiler.h>

#include "ztp_dbus_client.h"
#include "ztp_dbus_configurator.h"
#include "ztp_enrollee.h"

static void
ztp_enrollee_update_connectivity_state(struct ztp_enrollee *enrollee, enum ztp_connectivity_state state);

static void
ztp_enrollee_on_dpp_state_changed(struct ztp_enrollee *enrollee, enum dpp_state dpp_state);

/**
 * @brief Enumeration describing whether a network has been added or
 * removed.
 */
enum ztp_network_change {
    ZTP_NETWORK_ADDED = 0,
    ZTP_NETWORK_REMOVED,
};

/**
 * @brief Handler function invoked when the number of networks on an enrollee
 * has changed from a wpa_supplicant perspective.
 *
 * This function updates the number of networks for the interface in question.
 *
 * There are cases where wpa_supplicant does not emit the NetworkAdded and
 * NetworkRemoved signals, for example, when the configuration file is updated
 * by hand and then reloaded using the 'reconfigure' command. To handle such
 * cases, the number of networks is always explicitly read upon a change as
 * opposed to tracking the counts based on the signals. This should ensure that
 * an out-of-sync network count will synchronize to the correct value each time
 * the signal is emitted.
 *
 * @param enrollee The enrollee for which the network list has changed.
 * @param change The nature of the change (added, removed)
 */
static void
on_networks_changed(struct ztp_enrollee *enrollee, enum ztp_network_change change)
{
    static const char changechar[] = {
        '+',
        '-',
    };

    uint32_t num_networks = 0;
    uint32_t num_networks_last = enrollee->num_networks;
    int32_t num_networks_changed = 0;

    int ret = ztp_get_interface_network_count(enrollee->wpas, enrollee->path, &num_networks);
    if (ret < 0) {
        num_networks_changed = 1;
        zlog_error_if(enrollee->interface, "failed to retrieve network count (%d)", ret);

        // Update the count differentially based on the nature of the change.
        // This could result in an out-of-sync network count, however, it will
        // be more accurate than not adjusting the count at all.
        switch (change) {
            case ZTP_NETWORK_ADDED:
                enrollee->num_networks++;
                break;
            case ZTP_NETWORK_REMOVED:
                if (enrollee->num_networks > 0)
                    enrollee->num_networks--;
                break;
            default:
                break;
        }
    } else {
        num_networks_changed = (int32_t)enrollee->num_networks - (int32_t)num_networks;
        if (abs(num_networks_changed) != 1)
            zlog_warning_if(enrollee->interface, "out-of-sync network count detected (%+d changed)", num_networks_changed);

        enrollee->num_networks = num_networks;
    }

    zlog_info_if(enrollee->interface, "%cnetwork[%u]", changechar[change], enrollee->num_networks);

    if (num_networks_last == 0 && enrollee->num_networks > 0) {
        ztp_enrollee_update_connectivity_state(enrollee, ZTP_CONNECTIVITY_STATE_PROVISIONED);
    } else if (num_networks_last > 0 && enrollee->num_networks == 0) {
        ztp_enrollee_update_connectivity_state(enrollee, ZTP_CONNECTIVITY_STATE_INITIALIZING);
    }
}

/**
 * @brief Handler function invoked when a new network is added to an interface.
 *
 * The actual path of the added network is ignored since there is no current use for it.
 *
 * @param msg The sd-bus message containing the object path and propertirs of
 * the network that was added.
 * @param userdata Message context, of type 'struct ztp_enrollee', an
 * instance describing the interface for which a network was added.
 * @param ret_error
 * @return int
 */
static int
on_network_added(sd_bus_message *msg, void *userdata, sd_bus_error *ret_error)
{
    __unused(msg);
    __unused(ret_error);

    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    on_networks_changed(enrollee, ZTP_NETWORK_ADDED);
    return 0;
}

/**
 * @brief Handler function invoked when a network is removed from an interface.
 *
 * The actual path of the removed network is ignored since there is no current use for it.
 *
 * @param msg The sd-bus message containing the object path of the network that was removed.
 * @param userdata Message context, of type 'struct ztp_enrollee', an
 * instance describing the interface for which a network was removed.
 * @param ret_error
 * @return int 0
 */
static int
on_network_removed(sd_bus_message *msg, void *userdata, sd_bus_error *ret_error)
{
    __unused(msg);
    __unused(ret_error);

    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    on_networks_changed(enrollee, ZTP_NETWORK_REMOVED);
    return 0;
}

/**
 * @brief Determine if the interface is provisioned.
 * 
 * @param enrollee The enrollee to check for provisioning status.
 * @return true If the enrollee is provisioned.
 * @return false If the enrollee is not provisioned.
 */
static bool
ztp_enrollee_is_provisioned(struct ztp_enrollee *enrollee)
{
    switch (enrollee->state) {
        case ZTP_CONNECTIVITY_STATE_PROVISIONED:
        case ZTP_CONNECTIVITY_STATE_CONNECTED:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Determine if the interface has configured networks.
 *
 * @param enrollee The enrollee to check for configured networks.
 * @return true If the enrollee has at least one configured network.
 * @return false If the enrollee has no configured networks.
 */
static bool
ztp_enrollee_has_configured_networks(struct ztp_enrollee *enrollee)
{
    return (enrollee->num_networks > 0);
}

/**
 * @brief Determines if the enrollee is currently chirping. This is a passive
 * check that uses the last read value from wpa supplicant.
 * 
 * @param enrollee The enrollee to check.
 * @return true If the enrollee is chirping.
 * @return false If the enrollee is not chirping.
 */
static bool
is_dpp_in_progress(struct ztp_enrollee *enrollee)
{
    switch (enrollee->dpp_state) {
        case DPP_STATE_CHIRPING:
        case DPP_STATE_PROVISIONING:
        case DPP_STATE_BOOTSTRAP_KEY_ACQUIRING:
        case DPP_STATE_BOOTSTRAPPED:
        case DPP_STATE_AUTHENTICATING:
        case DPP_STATE_AUTHENTICATED:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Determines if provisioning is inactive.
 * 
 * @param enrollee The enrollee to check.
 * @return true If the enrollee is not undergoing active provisioning, or if
 * provisioning has succeeded.
 * @return false Otherwise.
 */
static bool
is_dpp_inactive(struct ztp_enrollee *enrollee)
{
    switch (enrollee->dpp_state) {
        case DPP_STATE_INACTIVE:
        case DPP_STATE_TERMINATED:
        case DPP_STATE_UNKNOWN:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Determines if the enrollee is connected to a network. This does not
 * imply any sort of network connectivity, only association.
 * 
 * @param enrollee The enrollee to check.
 * @return true If the enrollee is connected (associated) with an access point.
 * @return false If the enrollee is not connected (associated) with an access point.
 */
static bool
ztp_enrollee_is_connected(struct ztp_enrollee *enrollee)
{
    return (enrollee->if_state == WPAS_INTERFACE_STATE_COMPLETED);
}

/**
 * @brief Updates all configured signals with the current provisioning status.
 * Specifically, if an LED has been configured to display provisioning status,
 * it will be configured with an appropriate pattern to indicate the current
 * status.
 * 
 * @param enrollee The enrollee to update provision status signals for.
 */
static void
ztp_enrollee_status_signals_update(struct ztp_enrollee *enrollee)
{
    // If no status is configured, there is nothing to be done.
    struct led_ctrl *led = enrollee->led_status;
    if (!led)
        return;

    // Clear the led state.
    int ret = led_ctrl_set_off(led);
    if (ret < 0) {
        zlog_warning_if(enrollee->interface, "failed to configure led '%s' to off (%d)", led->path, ret);
        // non-critical, continue
    }

    // There are two primary paths to determine signal status, defined by
    // whether there is at least one (1) configured network.

    // At least 1 configured network.
    if (ztp_enrollee_has_configured_networks(enrollee)) {
        if (ztp_enrollee_is_connected(enrollee)) {
            ret = led_ctrl_set_on(led);
            if (ret < 0) {
                zlog_warning_if(enrollee->interface, "failed to configure led '%s' to on (%d)", led->path, ret);
                // non-critical, continue
            }
        } else {
            ret = led_ctrl_set_repeating_pattern(led, 250 /* ms, 4Hz */);
            if (ret < 0) {
                zlog_warning_if(enrollee->interface, "failed to configure led '%s' fast blink pattern (%d)", led->path, ret);
                // not critical, ignore and move on
            }
        }
    // No configured networks
    } else {
        if (is_dpp_in_progress(enrollee)) {
            ret = led_ctrl_set_repeating_pattern(led, 1000 /* ms, 1Hz */);
            if (ret < 0) {
                zlog_warning_if(enrollee->interface, "failed to configure led '%s' slow blink pattern (%d)", led->path, ret);
                // not critical, continue
            }
        }
    }
}

/**
 * @brief Initializes any/all provisioning status signals.
 * 
 * @param enrollee The enrollee to initialize the status signals for.
 * @return int 0 if the status 
 */
static int
ztp_enrollee_status_signals_initialize(struct ztp_enrollee *enrollee)
{
    const char *led_path = enrollee->settings->status_signal_led_path;
    if (!led_path)
        return 0;

    int ret = led_ctrl_create(led_path, &enrollee->led_status);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to create led '%s' control object for provisioning status signaling (%d); ignoring", led_path, ret);
        return ret;
    }

    zlog_info_if(enrollee->interface, "configured '%s' for provisioning status signaling", led_path);

    return 0;
}

/**
 * @brief Uninitializes provisioning status signals. Note that active signals
 * are not reset or cleared. For example, if an LED was configured and
 * currently flashing a blink pattern, the blink pattern will be left as-is
 * instead of turned off.
 * 
 * @param enrollee The enrollee to uninitialize the signals for.
 */
static void
ztp_enrollee_status_signals_uninitialize(struct ztp_enrollee *enrollee)
{
    if (enrollee->led_status) {
        led_ctrl_destroy(enrollee->led_status);
        enrollee->led_status = NULL;
    }
}

/**
 * @brief Creates a new bootstrap info/key in wpa_supplicant.
 *
 * @param enrollee The interface to create the bootstrap info for.
 * @param id An output argument to hold a pointer to the newly created
 * bootstrap info object identifier if this function succeeds.
 * @return int Returns zero if successful, and non-zero error code otherwise.
 */
static int
ztp_enrollee_create_bootstrap_dpp_key(struct ztp_enrollee *enrollee, uint32_t *id)
{
    if (!enrollee->settings) {
        zlog_error_if(enrollee->interface, "no bootstrap info available, missing interface settings");
        return -ENOENT;
    }

    // Issue command to create new bootstrap info entry.
    int ret = wpa_controller_dpp_bootstrap_gen(enrollee->ctrl, &enrollee->settings->bootstrap, id);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to bootstrap dpp key (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Retrieves the wpa_supplicant bootstrap info for use in chirping.
 *
 * If bootstrapping info hasn't been cached or created with wpa_supplicant,
 * this function will first create it and cache it.
 *
 * @param interface The interface to retrieve the bootstrap key for.
 * @param id An output argument to hold a pointer to the newly created
 * bootstrap info object identifier if this function succeeds.
 * @return int Returns 0 if bootstrap information is available. Non-zero otherwise.
 */
static int
ztp_enrollee_get_bootstrap_info(struct ztp_enrollee *enrollee, uint32_t *id)
{
    // First check if bootstrap info has already been setup and cached.
    if (enrollee->bootstrap_id)
        goto out;

    // Bootstrap info is stored in settings, so verify presence.
    if (!enrollee->settings) {
        zlog_error_if(enrollee->interface, "no bootstrap info available, missing interface settings");
        return -1;
    }

    // No bootstrap entry is cached nor has ztpd created one with
    // wpa_supplicant. Create it now and cache it in the interface structure.
    int ret = ztp_enrollee_create_bootstrap_dpp_key(enrollee, &enrollee->bootstrap_id);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to create dpp bootstrap info (%d)", ret);
        return ret;
    }

out:
    *id = enrollee->bootstrap_id;
    return 0;
}

/**
 * @brief Number of chirp iterations before giving up.  According to the
 * specification (v2.0), chirping should never stop so in theory the number of
 * iterations should not need to be specified (indefinite), however,
 * wpa_supplicant requires a value so one is specified here.
 * 
 * The choice of this value was largely arbitrary.
 */
#define NUM_CHIRP_ITERATIONS (1u << 27)

/**
 * @brief Start DPP presence announcement (chirping).  This will ensure the
 * bootstrapping information is instrumented in wpa_supplicant and initiates
 * the DPP protocol.  No prior state is assumed or modified, so this may fail
 * if there is an ongoing exchange.  The caller is responsible for ensureing
 * this is not the case, for example, by aborted any such in-flight exchanges.
 * 
 * @param enrollee The enrollee instance.
 * @return int 0 if presence announcement started successfully, non-zero
 * otherwise.
 */
static int
dpp_chirp(struct ztp_enrollee *enrollee)
{
    // Get dpp bootstrap info that will be used for chirping.
    uint32_t id;
    int ret = ztp_enrollee_get_bootstrap_info(enrollee, &id);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to retrieve dpp bootstrap info (%d)", ret);
        return ret;
    }

    // Request to start chirping with the bootstrap info key id.
    ret = wpa_controller_dpp_chirp(enrollee->ctrl, id, NUM_CHIRP_ITERATIONS);
    if (ret < 0)
        zlog_error_if(enrollee->interface, "failed to start chirping (%d)", ret);
    else
        ztp_enrollee_on_dpp_state_changed(enrollee, DPP_STATE_BOOTSTRAP_KEY_ACQUIRING);

    return ret;
}

/**
 * @brief Start DPP provisioning.
 * 
 * @param enrollee The enrollee instance.
 * @return int 
 */
static int
dpp_start(struct ztp_enrollee *enrollee)
{
    // Explicitly stop listening.  This effectively clears out any existing DPP
    // exchange/state from wpa_supplicant.
    wpa_controller_dpp_listen_stop(enrollee->ctrl);
    return dpp_chirp(enrollee);
}

/**
 * @brief 'unprovisioned' state handler.
 *
 * @param interface The interface for which the 'unprovisioned' state was entered.
 */
static void
on_connectivity_state_unprovisioned(struct ztp_enrollee *enrollee)
{
    dpp_start(enrollee);
}

/**
 * @brief 'connecting' state handler.
 *
 * @param interface The interface for which the 'connecting' state was entered.
 */
static void
on_connectivity_state_provisioned(struct ztp_enrollee *enrollee)
{
    // We have entered the terminal state, so chirping is no longer needed.
    if (wpa_controller_dpp_chirp_stop(enrollee->ctrl) < 0)
        zlog_warning_if(enrollee->interface, "request to stop chirping failed");
}

/**
 * @brief 'inactive' state handler.
 * 
 * @param interface The interface for which the 'inactive' state was entered.
 */
static void
on_connectivity_state_inactive(struct ztp_enrollee *enrollee)
{
    __unused(enrollee);
    // nothing to do
}

/**
 * @brief 'connected' state handler.
 * 
 * @param interface The interface for which the 'connected' state was entered.
 */
static void
on_connectivity_state_connected(struct ztp_enrollee *enrollee)
{
    __unused(enrollee);
    // nothing to do
}

/**
 * @brief 'initializing' state handler.
 *
 * @param interface The interface for which the 'initializing' state was entered.
 */
static void
on_connectivity_state_initializing(struct ztp_enrollee *enrollee)
{
    enum ztp_connectivity_state state = ztp_enrollee_has_configured_networks(enrollee)
        ? ZTP_CONNECTIVITY_STATE_PROVISIONED
        : ZTP_CONNECTIVITY_STATE_UNPROVISIONED;

    ztp_enrollee_update_connectivity_state(enrollee, state);
}

/**
 * @brief Array of connectivity state changed handlers.
 */
static void (*const on_connectivity_state_changed[])(struct ztp_enrollee *) = {
    on_connectivity_state_initializing,
    on_connectivity_state_inactive,
    on_connectivity_state_unprovisioned,
    on_connectivity_state_provisioned,
    on_connectivity_state_connected,
};

/**
 * @brief Updates the connectivity state of the interface, trigger any consequent actions.
 *
 * @param interface The interface to change the state for.
 * @param state The new connectivity state of the interface.
 */
static void
ztp_enrollee_update_connectivity_state(struct ztp_enrollee *enrollee, enum ztp_connectivity_state state)
{
    if (enrollee->state == state)
        return;

    enum ztp_connectivity_state state_old = enrollee->state;
    enrollee->state = state;
    zlog_info_if(enrollee->interface, "Δstate[connectivity] %s -> %s", ztp_connectivity_state_str(state_old), ztp_connectivity_state_str(state));

    ztp_enrollee_status_signals_update(enrollee);
    on_connectivity_state_changed[state](enrollee);
}

/**
 * @brief Interface-bound DPP state changed handler. This function will be
 * invoked each time a DPP state changes occurs on the associated wireless
 * interface in wpa_supplicant.
 *
 * @param interface The ztpd interface the DPP state change occurred on.
 * @param dpp_state The new dpp state.
 */
static void
ztp_enrollee_on_dpp_state_changed(struct ztp_enrollee *enrollee, enum dpp_state dpp_state)
{
    enum dpp_state dpp_state_old = enrollee->dpp_state;
    enrollee->dpp_state = dpp_state;
    zlog_info_if(enrollee->interface, "Δstate[dpp] %s -> %s", dpp_state_str(dpp_state_old), dpp_state_str(dpp_state));

    // dpp state only affects unprovisioned devices, so ignore other conditions
    if (ztp_enrollee_is_provisioned(enrollee))
        return;

    if (is_dpp_inactive(enrollee))
        dpp_start(enrollee);

    ztp_enrollee_status_signals_update(enrollee);
}

/**
 * @brief Interface-bound state changed handler. This function will be
 * invoked each time an interface state changes occurs on the associated
 * wireless interface in wpa_supplicant.
 *
 * @param interface The ztpd interface the interface state change occurred on.
 * @param if_state The new interface state.
 */
static void
on_interface_state_changed(struct ztp_enrollee *enrollee, enum wpas_interface_state if_state)
{
    if (enrollee->if_state == if_state)
        return;

    enum wpas_interface_state if_state_old = enrollee->if_state;
    enrollee->if_state = if_state;
    zlog_info_if(enrollee->interface, "Δstate[interface] %s -> %s", wpas_interface_state_str(if_state_old), wpas_interface_state_str(if_state));

    // interface state only affects provisioned devices, so ignore other conditions
    if (!ztp_enrollee_is_provisioned(enrollee))
        return;

    // only concerned about association changes: connected <-> not connected
    enum ztp_connectivity_state state;
    if (if_state_old == WPAS_INTERFACE_STATE_COMPLETED) {
        state = ZTP_CONNECTIVITY_STATE_INITIALIZING;
    } else if (if_state == WPAS_INTERFACE_STATE_COMPLETED) {
        state = ZTP_CONNECTIVITY_STATE_CONNECTED;
    } else {
        return;
    }

    ztp_enrollee_update_connectivity_state(enrollee, state);
}

/**
 * @brief Handler for changes to interface dbus property changes.
 * 
 * @param msg The dbus message containing a dictionary with the changed values.
 * @param dbus_interface The dbus inteface the change occurred on.
 * @param userdata The ztp_interface structure.
 */
static void
on_dbus_properties_changed(sd_bus_message *msg, const char *dbus_interface, void *userdata)
{
    __unused(dbus_interface);

    const char *property;
    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;

    for (;;) {
        // Enter dictionary entry.
        int ret = sd_bus_message_enter_container(msg, SD_BUS_TYPE_DICT_ENTRY, "sv");
        if (ret < 0) {
            zlog_error_if(enrollee->interface, "failed to enter dictionary entry container (%d)", ret);
            return;
        } else if (ret == 0)
            break;

        // Read property identifier string.
        ret = sd_bus_message_read_basic(msg, SD_BUS_TYPE_STRING, &property);
        if (ret < 0) {
            zlog_error_if(enrollee->interface, "failed to read property name from PropertiesChanged dictionary (%d)", ret);
            return;
        } else if (ret == 0) {
            break;
        }

        // Determine contents of variant container.
        char type;
        const char *contents;
        ret = sd_bus_message_peek_type(msg, &type, &contents);
        if (ret < 0) {
            zlog_error_if(enrollee->interface, "failed to peek message type for PropertiesChanged (%d)", ret);
            return;
        }

        // Enter property value (variant) container.
        ret = sd_bus_message_enter_container(msg, SD_BUS_TYPE_VARIANT, contents);
        if (ret < 0) {
            zlog_error_if(enrollee->interface, "failed to enter variant container for property '%s' (%d)", property, ret);
            return;
        }

        // Check for properties of interest.
        if (strcmp(property, "State") == 0) {
            const char *state;
            ret = sd_bus_message_read_basic(msg, SD_BUS_TYPE_STRING, &state);
            if (ret < 0) {
                zlog_error_if(enrollee->interface, "failed to read 'State' property value (%d)", ret);
                return;
            }

            on_interface_state_changed(enrollee, parse_wpas_interface_state(state));
        } else {
            ret = sd_bus_message_skip(msg, contents);
            if (ret < 0) {
                zlog_error_if(enrollee->interface, "failed to skip unrecognized property '%s' (%d)", property, ret);
                return;
            }
        }

        // Exit value (variant) container.
        sd_bus_message_exit_container(msg); // variant

        // Exit dictionary entry container.
        ret = sd_bus_message_exit_container(msg);
        if (ret < 0) {
            zlog_error_if(enrollee->interface, "failed to exit dictionary entry container (%d)", ret);
            return;
        }
    } // for each dictionary entry
}

/**
 * @brief De-activates monitoring of the specified enrollee instance.
 * 
 * @param enrollee The enrollee instance to de-activate.
 */
static void
ztp_enrollee_deactivate(struct ztp_enrollee *enrollee)
{
    enrollee->bootstrap_id = 0;

    if (enrollee->slot_network_added) {
        sd_bus_slot_unref(enrollee->slot_network_added);
        enrollee->slot_network_added = NULL;
    }

    if (enrollee->slot_network_removed) {
        sd_bus_slot_unref(enrollee->slot_network_removed);
        enrollee->slot_network_removed = NULL;
    }

    ztp_enrollee_status_signals_uninitialize(enrollee);
    enrollee->active = false;
}

/**
 * @brief Activates monitoring of the specified enrollee instance. This will
 * set up handlers to listen for relevant changes to interface and dpp state,
 * including provisioned networks.
 * 
 * @param enrollee The enrollee instance to activate.
 * @return int 0 if activation was successful, non-zero otherwise.
 */
static int
ztp_enrollee_activate(struct ztp_enrollee *enrollee)
{
    if (enrollee->active)
        return 0;

    int ret = ztp_wpa_supplicant_get_interface_state(enrollee->wpas, enrollee->path, &enrollee->if_state);
    if (ret < 0) {
        zlog_warning_if(enrollee->interface, "failed to retreive initial interface state (%d); defaulting to unknown", ret);
        enrollee->if_state = WPAS_INTERFACE_STATE_UNKNOWN;
    }

    // Register for changes to the network list.
    ret = sd_bus_match_signal(enrollee->dbus->bus, 
        &enrollee->slot_network_added,
        WPAS_DBUS_SERVICE,
        enrollee->path,
        WPAS_DBUS_INTERFACE,
        "NetworkAdded",
        on_network_added,
        enrollee);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to register handler for NetworkAdded signal (%d)", ret);
        goto fail;
    }

    ret = sd_bus_match_signal(enrollee->dbus->bus, 
        &enrollee->slot_network_removed,
        WPAS_DBUS_SERVICE,
        enrollee->path,
        WPAS_DBUS_INTERFACE,
        "NetworkRemoved",
        on_network_removed,
        enrollee);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to register handler for NetworkRemoved signal (%d)", ret);
        goto fail;
    }

    // Determine initial network count.
    ret = ztp_get_interface_network_count(enrollee->wpas, enrollee->path, &enrollee->num_networks);
    if (ret < 0) {
        zlog_warning_if(enrollee->interface, "failed to retrieve initial network count (%d); assuming 0", ret);
        enrollee->num_networks = 0;
    }

    ret = ztp_enrollee_status_signals_initialize(enrollee);
    if (ret < 0)
        zlog_warning_if(enrollee->interface, "failed to initialize provisioning status signals (%d); ignoring", ret);

    enrollee->active = true;
    enrollee->dpp_state = DPP_STATE_INACTIVE;
    enrollee->state = ZTP_CONNECTIVITY_STATE_INACTIVE;

    zlog_info_if(enrollee->interface, "dpp enrollee activated");

    // Finally, update the connectivity state, which will kickstart the state machine.
    ztp_enrollee_update_connectivity_state(enrollee, ZTP_CONNECTIVITY_STATE_INITIALIZING);
out:
    return ret;
fail:
    ztp_enrollee_deactivate(enrollee);
    goto out;
}

/**
 * @brief wpa_supplicant interface added callback. This will be invoked each
 * time wpa_supplicant begins monitoring a new interface.
 *
 * @param enrollee The enrollee instance.
 * @param interface The interface name that has been added to wpa_supplicant.
 * @param path The d-bus path of the interface that has been added to
 * wpa_supplicant.
 */
static void
on_interface_added(struct ztp_enrollee *enrollee, const char *interface, const char *path)
{
    if (enrollee->active)
        ztp_enrollee_deactivate(enrollee);

    if (enrollee->path && strcmp(enrollee->path, path) != 0) {
        zlog_info_if(interface, "d-bus path updated: %s -> %s", enrollee->path, path);
        free(enrollee->path);
        enrollee->path = NULL;
    }

    if (!enrollee->path) {
        enrollee->path = strdup(path);
        if (!enrollee->path) {
            zlog_panic_if(interface, "failed to allocate memory for interface path");
            return;
        }
    }

    int ret = ztp_enrollee_activate(enrollee);
    if (ret < 0) {
        zlog_panic_if(interface, "failed to activate upon arrival (%d)", ret);
        return;
    }
}

/**
 * @brief wpa_supplicant interface removed callback. This will be invoked each
 * time wpa_supplicant stops monitoring an interface.
 *
 * @param enrollee The enrollee instance.
 * @param interface The name of the interface that has been removed from wpa_supplicant
 * @param path The path of the interface that has been removed from wpa_supplicant
 */
static void
on_interface_removed(struct ztp_enrollee *enrollee, const char *interface, const char *path)
{
    __unused(interface);
    __unused(path);

    ztp_enrollee_deactivate(enrollee);
}

/**
 * @brief Handler function for interface presence changes.
 *
 * @param context The enrollee instance.
 * @param presence The type of presence change that occurred.
 * @param name The name of the interface the presence change occurred for.
 * @param path The d-bus path of the interface the presence change occurred for.
 */
static void
on_interface_presence_changed(void *context, enum ztp_interface_presence presence, const char *interface, const char *path)
{
    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)context;

    if (strcmp(enrollee->interface, interface) != 0)
        return;

    switch (presence) {
        case ZTP_INTERFACE_ARRIVED:
            on_interface_added(enrollee, interface, path);
            break;
        case ZTP_INTERFACE_DEPARTED:
            on_interface_removed(enrollee, interface, path);
            break;
        default:
            break;
    }
}

/**
 * @brief Handler function for dpp frame rx.
 * 
 * @param userdata The enrollee instance.
 * @param type The type of public action frame received.
 * @param frequency The radio frequency on which the frame was received.
 */
static void
on_dpp_frame_received(void *userdata, const char (*mac)[(DPP_MAC_LENGTH * 2) + (DPP_MAC_LENGTH - 1) + 1], enum dpp_public_action_frame_type type, uint32_t frequency)
{
    __unused(mac);
    __unused(frequency);

    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    enum dpp_state dpp_state = DPP_STATE_UNKNOWN;

    switch (type) {
        case DPP_PAF_AUTHENTICATION_REQUEST:
        case DPP_PAF_AUTHENTICATION_RESPONSE:
            dpp_state = DPP_STATE_AUTHENTICATED;
            break;
        default:
            break;
    }

    if (dpp_state != DPP_STATE_UNKNOWN)
        ztp_enrollee_on_dpp_state_changed(enrollee, dpp_state);
}

/**
 * @brief Handler function for dpp frame tx.
 * 
 * @param userdata The enrollee instance.
 * @param type The type of public action frame sent.
 * @param frequency The radio frequency on which the frame was sent.
 */
static void
on_dpp_frame_transmitted(void *userdata, const char (*mac)[(DPP_MAC_LENGTH * 2) + (DPP_MAC_LENGTH - 1) + 1], enum dpp_public_action_frame_type type, uint32_t frequency)
{
    __unused(mac);
    __unused(frequency);

    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    enum dpp_state dpp_state = DPP_STATE_UNKNOWN;

    switch (type) {
        case DPP_PAF_PRESENCE_ANNOUNCEMENT:
            dpp_state = DPP_STATE_CHIRPING;
            break;
        default:
            break;
    }

    if (dpp_state != DPP_STATE_UNKNOWN)
        ztp_enrollee_on_dpp_state_changed(enrollee, dpp_state);
}

/**
 * @brief Handler function for dpp chirp stopped event.
 * 
 * @param userdata The enrollee instance.
 */
static void
on_dpp_chirp_stopped(void *userdata)
{
    __unused(userdata);

    // struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    // TODO: set a timer to re-check provisioning state after a short period
}

/**
 * @brief Handler function for dpp failures (generic).
 * 
 * @param userdata The enrollee instance.
 * @param details Details of the failure.
 */
static void
on_dpp_failure(void *userdata, const char *details)
{
    __unused(details);

    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    ztp_enrollee_on_dpp_state_changed(enrollee, DPP_STATE_TERMINATED);
}

/**
 * @brief Handler function for dpp authentication success.
 * 
 * @param userdata The enrollee instance.
 * @param is_initiator Indicates whether this device is the dpp initiator.
 */
static void
on_dpp_authentication_succeeded(void *userdata, bool is_initiator)
{
    __unused(is_initiator);

    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    ztp_enrollee_on_dpp_state_changed(enrollee, DPP_STATE_AUTHENTICATED);
}

/**
 * @brief Handler function for dpp authentication failures.
 * 
 * @param userdata The enrollee instance.
 */
static void
on_dpp_authentication_failure(void *userdata)
{
    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    ztp_enrollee_on_dpp_state_changed(enrollee, DPP_STATE_TERMINATED);
}

/**
 * @brief Handler function for dpp configuration success.
 * 
 * @param userdata The enrollee instance.
 */
static void
on_dpp_configuration_success(void *userdata)
{
    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    ztp_enrollee_on_dpp_state_changed(enrollee, DPP_STATE_PROVISIONED);
}

/**
 * @brief Handler function for dpp authentication failures.
 * 
 * @param userdata The enrollee instance.
 */
static void
on_dpp_configuration_failure(void *userdata)
{
    struct ztp_enrollee *enrollee = (struct ztp_enrollee *)userdata;
    ztp_enrollee_on_dpp_state_changed(enrollee, DPP_STATE_TERMINATED);
}

/**
 * @brief Event handler for wpa control socket events.
 */
static struct wpa_event_handler wpa_event_handler_enrollee = {
    .dpp_chirp_stopped = on_dpp_chirp_stopped,
    .dpp_failure = on_dpp_failure,
    .dpp_authentication_failure = on_dpp_authentication_failure,
    .dpp_authentication_success = on_dpp_authentication_succeeded,
    .dpp_configuration_success = on_dpp_configuration_success,
    .dpp_configuration_failure = on_dpp_configuration_failure,
    .dpp_frame_received = on_dpp_frame_received,
    .dpp_frame_transmitted = on_dpp_frame_transmitted,
};

/**
 * @brief Uninitialize the enrollee device role.
 * 
 * @param enrollee The enrollee to uninitialize.
 */
void
ztp_enrollee_uninitialize(struct ztp_enrollee *enrollee)
{
    ztp_enrollee_deactivate(enrollee);
    ztp_wpa_supplicant_unregister_interface_presence_changed_callback(enrollee->wpas, on_interface_presence_changed, enrollee);

    if (enrollee->ctrl) {
        wpa_controller_unregister_event_handler(enrollee->ctrl, &wpa_event_handler_enrollee, enrollee);
        wpa_controller_uninitialize(enrollee->ctrl);
        wpa_controller_destroy(&enrollee->ctrl);
    }

    if (enrollee->dpp_properties_changed_handle) {
        ztp_dbus_unregister_properties_changed_handler(enrollee->dpp_properties_changed_handle);
        enrollee->dpp_properties_changed_handle = NULL;
    }

    if (enrollee->properties_changed_handle) {
        ztp_dbus_unregister_properties_changed_handler(enrollee->properties_changed_handle);
        enrollee->properties_changed_handle = NULL;
    }

    if (enrollee->interface) {
        free(enrollee->interface);
        enrollee->interface = NULL;
    }

    if (enrollee->path) {
        free(enrollee->path);
        enrollee->path = NULL;
    }

    if (enrollee->settings) {
        enrollee->settings = NULL;
        // 'settings' object is not owned, hence is not free()'ed.
    }
}

/**
 * @brief Uninitialize and destroy an existing enrollee.
 *
 * @param enrollee The enrollee to uninitialize.
 */
void
ztp_enrollee_destroy(struct ztp_enrollee **enrollee)
{
    if (!enrollee || !*enrollee)
        return;

    ztp_enrollee_uninitialize(*enrollee);
    free(*enrollee);

    *enrollee = NULL;
}

/**
 * @brief The default control socket path to use if none is specified.
 */
#define WPA_CTRL_PATH_BASE_DEFAULT "/var/run/wpa_supplicant"

/**
 * @brief Create and initialize a new interface.
 * 
 * @param interface The name of the interface.
 * @param settings The settings to use.
 * @param wpas A wpa_supplicant instance.
 * @param dbus The d-bus client instance.
 * @param loop The ztp event loop.
 * @param penrollee Output argument to hold the enrollee instance.
 * @return int 
 */
int
ztp_enrollee_create(const char *interface, struct ztp_enrollee_settings *settings, struct ztp_wpa_supplicant *wpas, struct ztp_dbus_client *dbus, struct event_loop *loop, struct ztp_enrollee **penrollee)
{
    int ret;
    struct ztp_enrollee *enrollee;

    enrollee = calloc(1, sizeof *enrollee);
    if (!enrollee)
        return -ENOMEM;

    enrollee->wpas = wpas;
    enrollee->dbus = dbus;
    enrollee->loop = loop;
    enrollee->interface = strdup(interface);
    enrollee->state = ZTP_CONNECTIVITY_STATE_INACTIVE;
    enrollee->settings = settings;
    enrollee->bootstrap_id = 0;

    if (!enrollee->interface) {
        ret = -ENOMEM;
        goto fail;
    }

    enrollee->ctrl = wpa_controller_alloc();
    if (!enrollee->ctrl) {
        zlog_error_if(enrollee->interface, "failed to allocare wpa controller (no memory)");
        ret = -ENOMEM;
        goto fail;
    }

    char ctrl_path[128];
    snprintf(ctrl_path, sizeof ctrl_path, "%s/%s", WPA_CTRL_PATH_BASE_DEFAULT, interface);

    ret = wpa_controller_initialize(enrollee->ctrl, ctrl_path, loop);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to initialize wpa controller (%d)", ret);
        goto fail;
    }

    ret = wpa_controller_register_event_handler(enrollee->ctrl, &wpa_event_handler_enrollee, enrollee);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to register wpa event handler (%d)", ret);
        goto fail;
    }

    // Register for interface property changes.
    ret = ztp_dbus_register_properties_changed_handler(enrollee->dbus,
        WPAS_DBUS_INTERFACE,
        enrollee,
        on_dbus_properties_changed,
        &enrollee->properties_changed_handle);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to register 'PropertiesChanged' handler (%d)", ret);
        goto fail;
    }

    // Register for interface presence changes.
    ret = ztp_wpa_supplicant_register_interface_presence_changed_callback(wpas, on_interface_presence_changed, enrollee);
    if (ret < 0) {
        zlog_error_if(enrollee->interface, "failed to register for interface presence changes (%d)", ret);
        goto fail;
    }

    ret = ztp_wpa_supplicant_get_interface_path(wpas, interface, &enrollee->path);
    switch (ret) {
        case -ENOENT:
            zlog_warning_if(interface, "interface not present; deferring activation");
            break;
        case 0:
            ret = ztp_enrollee_activate(enrollee);
            if (ret < 0) {
                zlog_error_if(interface, "failed to activate enrollee (%d)", ret);
                goto fail;
            }
            break;
        default:
            zlog_error_if(interface, "failed to retrieve d-bus path (%d)", ret);
            goto fail;
    }

    *penrollee = enrollee;
    ret = 0;
out:
    return ret;
fail:
    ztp_enrollee_destroy(&enrollee);
    goto out;
}
