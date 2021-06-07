
#ifndef __ZTP_ENROLLEE_H__
#define __ZTP_ENROLLEE_H__

#include <stdbool.h>
#include <stdint.h>

#include "dpp.h"
#include "led_ctrl.h"
#include "wpa_controller.h"
#include "wpa_supplicant.h"
#include "ztp.h"
#include "ztp_log.h"
#include "ztp_settings.h"
#include "ztp_wpa_supplicant.h"

struct ztp_dbus_client;
struct ztp_dbus_properties_changed_handle;
struct ztp_enrollee_settings;

/**
 * @brief Describes a network interface that managed for zero touch
 * provisioning.
 */
struct ztp_enrollee {
    char *interface;
    char *path;
    bool active;
    enum dpp_state dpp_state;
    enum wpas_interface_state if_state;
    enum ztp_connectivity_state state;
    struct event_loop *loop;
    struct ztp_enrollee_settings *settings;
    struct ztp_dbus_client *dbus;
    struct ztp_dbus_properties_changed_handle *dpp_properties_changed_handle;
    struct ztp_dbus_properties_changed_handle *properties_changed_handle;
    struct ztp_wpa_supplicant *wpas;
    struct led_ctrl *led_status;
    struct wpa_controller *ctrl;
    sd_bus_slot *slot_network_added;
    sd_bus_slot *slot_network_removed;
    uint32_t num_networks;
    uint32_t bootstrap_id;
};

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
ztp_enrollee_create(const char *interface, struct ztp_enrollee_settings *settings, struct ztp_wpa_supplicant *wpas, struct ztp_dbus_client *dbus, struct event_loop *loop, struct ztp_enrollee **penrollee);

/**
 * @brief Uninitialize and destroy an existing enrollee.
 *
 * @param enrollee The enrollee to uninitialize.
 */
void
ztp_enrollee_destroy(struct ztp_enrollee **enrollee);

#endif //__ZTP_ENROLLEE_H__
