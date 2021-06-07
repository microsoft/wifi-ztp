
#ifndef __ZTP_WPA_SUPPLICANT_H__
#define __ZTP_WPA_SUPPLICANT_H__

#include <stdbool.h>

#include <systemd/sd-bus.h>
#include <userspace/linux/list.h>

#include "dpp.h"
#include "wpa_supplicant.h"
#include "ztp.h"

struct wpa_ctrl;

/**
 * @brief Helper structure to track known intefaces.
 */
struct wpa_supplicant_interface_entry {
    struct list_head list;
    char *path;
    char *name;
};

/**
 * @brief Structure collecting wpa_supplicant related details. This
 * primarily refers to the global/system wpa_supplicant interface and
 * not specific wireless interfaces.
 */
struct ztp_wpa_supplicant {
    sd_bus *bus;
    sd_bus_slot *slot_service_availability;
    sd_bus_slot *slot_interface_added;
    sd_bus_slot *slot_interface_removed;
    struct list_head interfaces;
    struct list_head interface_presence_changed;
};

/**
 * @brief Initializes the wpa_supplicant related facilities.
 *
 * @param wpas A pointer to the structure to initialize.
 * @return int The result of the operation. 0 if successful, otherwise a non-zero error value.
 */
int
ztp_wpa_supplicant_initialize(struct ztp_wpa_supplicant *wpas);

/**
 * @brief Uninitializes a ztp_wpa_supplicant instance.
 *
 * @param wpas The instance to uninitialize.
 */
void
ztp_wpa_supplicant_uninitialize(struct ztp_wpa_supplicant *wpas);

/**
 * @brief Retrieves the 'State' property of the
 * 'fi.w1.wpa_supplicant1.Interface' d-bus interface of the object referred to
 * by 'path'.
 * 
 * @param wpas The wpa_supplicant instance.
 * @param path The path of the object which implements the interface.
 * @param state Output argument that will hold receive the interface state.
 * @return int 0 if the operation succeeded, non-zero otherwise.
 */
int
ztp_wpa_supplicant_get_interface_state(struct ztp_wpa_supplicant *wpas, const char *path, enum wpas_interface_state *state);

/**
 * @brief Returns the number of networks configured for this interface.
 *
 * @param wpas The wpa_supplicant instance.
 * @param path The d-bus object path to retrieve state from.
 * @param count Output variable to receive the number of networks.
 * @return int The status of the operation. 0 if successful, non-zero otherise.
 */
int
ztp_get_interface_network_count(struct ztp_wpa_supplicant *wpas, const char *path, uint32_t *count);

/**
 * @brief Describes the presence action of an interface.
 */
enum ztp_interface_presence {
    ZTP_INTERFACE_ARRIVED,
    ZTP_INTERFACE_DEPARTED,
};

/**
 * @brief Prototype for the interface added event callback.
 *
 * @param userdata Contextual data that was registered with the handler.
 * @param name The interface name.
 * @param path The d-bus object path of the interface that was added.
 */
typedef void (*interface_presence_changed_fn)(void *userdata, enum ztp_interface_presence presence, const char *name, const char *path);

/**
 * @brief Registers a handler for the interface added event.
 *
 * @param wpas The wpa supplicant instance.
 * @param handler The handler function to invoke when an interface is added.
 * @param userdata The context to be passed to the handler function.
 * @return int 0 if successful, non-zero otherwise.
 */
int
ztp_wpa_supplicant_register_interface_presence_changed_callback(struct ztp_wpa_supplicant *wpas, interface_presence_changed_fn handler, void *userdata);

/**
 * @brief Unregisters an interface presence changed handler.
 * 
 * @param wpas The wpa supplicant instance.
 * @param handler The handler function that was previously registered.
 * @param userdata The context previously associated with the handler function.
 */
void
ztp_wpa_supplicant_unregister_interface_presence_changed_callback(struct ztp_wpa_supplicant *wpas, interface_presence_changed_fn handler, void *userdata);

/**
 * @brief Looks up a d-bus interface path, given its name.
 * 
 * @param wpas The wpa supplicant instance.
 * @param interface The name of the interface to lookup the d-bus path.
 * @param path An output pointer to hold the d-bus path, if it exists. In this
 * case, the caller owns the memory associated with the path which can be
 * released by passing it to free().
 * @return int 0 if the d-bus path was retrieved and written to *path. -ENOENT
 * is returned if wpa asupplicant is not aware of the specified interface.
 * Otherwise a non-zero value is returned.
 */
int
ztp_wpa_supplicant_get_interface_path(struct ztp_wpa_supplicant *wpas, const char *interface, char **path);

#endif //__ZTP_WPA_SUPPLICANT_H__
