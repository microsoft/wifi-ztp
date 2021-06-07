
#ifndef __WPA_CONTROLLER_H__
#define __WPA_CONTROLLER_H__

#include <stdbool.h>
#include <stdint.h>

#include <userspace/linux/list.h>

#include "dpp.h"
#include "wpa_controller_watcher.h"
#include "wpa_core.h"

struct wpa_ctrl;
struct event_loop;

struct wpa_event_handler {
    /**
     * @brief Prototype for the interface presence changed event.
     * 
     * This event fires when the interface presence changes. Specifically, this
     * occurs when the interface departs (no longer accessible/usable) or
     * arrives (becomes usable).
     * 
     * @param userdata Contextual data that was registered with the handler.
     * @param presence The new presence of the interface.
     */
    void (*interface_presence_changed)(void *userdata, enum wpa_controller_presence_event presence);

    /**
     * @brief Prototype for the dpp frame received event.
     * 
     * This event fires each time a DPP frame is received.
     */
    void (*dpp_frame_received)(void *userdata, const char (*mac)[(DPP_MAC_LENGTH * 2) + (DPP_MAC_LENGTH - 1) + 1], enum dpp_public_action_frame_type type, uint32_t frequency);

    /**
     * @brief Prototype for the dpp frame transmitted event.
     * 
     * This event fires each time a DPP frame is transmitted.
     */
    void (*dpp_frame_transmitted)(void *userdata, const char (*mac)[(DPP_MAC_LENGTH * 2) + (DPP_MAC_LENGTH - 1) + 1], enum dpp_public_action_frame_type type, uint32_t frequency);

    /**
     * @brief Prototype for the dpp frame transmitted status event.
     * 
     * This event fires each time a dpp frame transmission completes.  This can
     * either be due to completion, timeout (no acknowledgement) or some other
     * failure.
     * 
     * @param userdata Contextual data that was registered with the handler.
     * @param dst The mac address of the frame destination.
     * @param frequency The radio frequency the frame was transmitted on.
     * @param result The result of the operation, either "SUCCESS", "FAILURE", or "no-ACK".
     */
    void (*dpp_frame_transmitted_status)(void *userdata, const char (*dst)[(DPP_MAC_LENGTH * 2) + (DPP_MAC_LENGTH - 1) + 1], uint32_t frequency, const char *result);

    /**
     * @brief Prototype for the chirp received event callback.
     *
     * @param userdata Contextual data that was registered with the handler.
     * @param id The bootstrap identifier of the peer. If the peer is not known, -1 will be populated.
     * @param mac The mac address of the peer the chirp originated from.
     * @param frequency The radio frequency the chirp was received on.
     * @param hash The "chirp" hash of the peer's public bootstrapping key.
     */
    void (*dpp_chirp_received)(void *userdata, int32_t id, const char (*mac)[(DPP_MAC_LENGTH * 2) + (DPP_MAC_LENGTH - 1) + 1], uint32_t frequency, const struct dpp_bootstrap_publickey_hash *hash);

    /**
     * @brief Prototype for the DPP chirp stopped event callback.
     * 
     * This event fires when DPP chirping stops.
     * 
     * @param userdata Contextual data that was registered with the handler.
     */
    void (*dpp_chirp_stopped)(void *userdata);

    /**
     * @brief Prototype for the DPP failure event callback. 
     * 
     * This event fires when a generic DPP failure occurs. Some failures
     * including failure details.
     * 
     * @param userdata Contextual data that was registered with the handler.
     * @param details A string describing the details of the failure.
     * This pointer is always valid. When no failure details were provided,
     * this will point to the empty string.
     */
    void (*dpp_failure)(void *userdata, const char *details);

    /**
     * @brief Prototype for the DPP authentication failure event callback.
     * 
     * This event fires when a DPP exchange fails the authentication stage.
     * 
     * @param userdata Contextual data that was registered with the handler.
     */
    void (*dpp_authentication_failure)(void *userdata);

    /**
     * @brief Prototype for the DPP authentication success event.
     * 
     * This event fires when DPP authentication completes successfully.
     * 
     * @param initiator Indicates whether this device is the initiator.
     */
    void (*dpp_authentication_success)(void *userdata, bool initiator);

    /**
     * @brief Prototype for the DPP configuration failed event.
     * 
     * This event fires when a DPP exchange fails the configuration stage.
     * 
     * @param userdata Contextual data that was registered with the handler.
     */
    void (*dpp_configuration_failure)(void *userdata);

    /**
     * @brief Prototype for the DPP configuration success event.
     * 
     * This event fires when a DPP configuration completes successfully.
     * 
     * @param userdata Contextual data that was registered with the handler.
     */
    void (*dpp_configuration_success)(void *userdata);
};

struct wpa_controller {
    int event_fd;
    char *path;
    const char *interface;
    bool connected;
    struct wpa_ctrl *event;
    struct wpa_ctrl *command;
    struct wpa_controller_watcher *watcher;
    struct event_loop *loop;
    struct list_head event_handlers;
    void *pending_connection_context;
};

/**
 * @brief Allocates a new wpa controller instance. The returned pointer must be
 * initialized with wpa_controller_initialize.
 *
 * @return struct wpa_controller*
 */
struct wpa_controller *
wpa_controller_alloc(void);

/**
 * @brief Destroys a wpa controller, as allocated by wpa_controller_alloc.
 *
 * @param ctrl The controller instance to destroy.
 */
void
wpa_controller_destroy(struct wpa_controller **ctrl);

/**
 * @brief Initializes the hostapd control interface.
 *
 * @param ctrl The controller to initialize.
 * @param ctrl_path The full path to the wpa control socket.
 * @return int 0 if the control interface was successfully initialized non-zero otherwise.
 */
int
wpa_controller_initialize(struct wpa_controller *ctrl, const char *ctrl_path, struct event_loop *loop);

/**
 * @brief Uninitializes a wpa controller.
 *
 * @param interface The interface to uninitialize.
 */
void
wpa_controller_uninitialize(struct wpa_controller *ctrl);

/**
 * @brief Invokes the 'DPP_QRCODE' command on the hostapd interface.
 *
 * @param ctrl The wpa controller instance.
 * @param dpp_uri The DPP URI to register with the configurator.
 * @param bootstrap_id The unique identifier for the bootstrapping information .
 * @return int 0 if successful, non-zero otherwise.
 */
int
wpa_controller_qrcode(struct wpa_controller *ctrl, const char *dpp_uri, uint32_t *bootstrap_id);

/**
 * @brief Invokes the 'SET" command on the control interface. This alllows
 * controlling runtime configuration parameters of wpa_supplicant and hostapd.
 *
 * The caller is responsible for sending appropriately supported key/value
 * pairs depending on the daemon respresented by the control interface, and the
 * key itself.
 *
 * @param ctrl The wpa controller instance.
 * @param key The name of the configuration key to set.
 * @param value The value of the configuration key to set.
 * @return int 0 if the command was successfully sent and the value was
 * applied. Otherwise a non-zero error value is returned.
 */
int
wpa_controller_set(struct wpa_controller *ctrl, const char *key, const char *value);

/**
 * @brief Invokes the 'DPP_AUTH_INIT' command on the control interface. This
 * initiated a DPP authentication with the bootstrapping information identified
 * by 'peer_id'.
 *
 * @param ctrl The wpa controller instance.
 * @param peer_id The bootstrapping info identifier for the peer to initiation
 * DPP authentication with.
 * @param frequency The radio frequency to use to initiation authentication. If
 * 0 is supplied, the configurator will attempt to initiate authentication on
 * all usable channels (not recommended)
 * @return int 0 if the command was successfully send, non-zero otherwise.
 */
int
wpa_controller_dpp_auth_init(struct wpa_controller *ctrl, uint32_t peer_id, uint32_t frequency);

/**
 * @brief Invokes the 'DPP_AUTH_INIT' command on the control interface. This
 * initiated a DPP authentication with the bootstrapping information identified
 * by 'peer_id'.
 *
 * @param ctrl The wpa controller instance.
 * @param peer_id The bootstrapping info identifier for the peer to initiation
 * DPP authentication with.
 * @param frequency The radio frequency to use to initiation authentication. If
 * 0 is supplied, the configurator will attempt to initiate authentication on
 * all usable channels (not recommended).
 * @param conf The DPP configurator settings for authentication. This can
 * include the target network configuration, amongst other things.
 * @return int 0 if the command was
 * successfully send, non-zero otherwise.
 */
int
wpa_controller_dpp_auth_init_with_conf(struct wpa_controller *ctrl, uint32_t peer_id, uint32_t frequency, const char *conf);

/**
 * @brief Invokes the 'DPP_BOOTSTRAP_SET' command on the control interface.
 * This associates configurator parameters with the specified peer. Many
 * configurator params can be specified, however, the most useful for ztp are
 * those related to network provisioning.
 *
 * @param ctrl The wpa controller instance.
 * @param peer_id The bootstrapping info identifier of the peer to set
 * bootstrapping information for.
 * @param conf The bootstrapping configuration parameters, encoded as a string.
 * @return int 0 if the command was successfully sent, non-zero otherwise.
 */
int
wpa_controller_dpp_bootstrap_set(struct wpa_controller *ctrl, uint32_t peer_id, const char *conf);

/**
 * @brief Invokes the 'DPP_BOOTSTRAP_GEN' command on the control interface.
 * This creates a DPP bootstrap key according to the specified parameters in
 * 'bi'.
 * 
 * @param ctrl The wpa controller instance.
 * @param bi The information describing the bootstrap key.
 * @param id The identifier of the bootstrap key, which is used to identify the
 * key in subsequent control interface DPP commands.  
 * @return int 0 if the command completed successfully, non-zero otherwise.
 */
int
wpa_controller_dpp_bootstrap_gen(struct wpa_controller *ctrl, const struct dpp_bootstrap_info *bi, uint32_t *id);

/**
 * @brief Requests wpa_supplicant to begin chirping with a specific bootstrap key.
 * 
 * @param ctrl The wpa controller instance.
 * @param bootstrap_key_id The identifier of the bootstrapping key to chirp.
 * @param iterations The number of chirp iterations to perform.
 * @return int The result of the operation, 0 if successful, non-zero otherwise.
 */
int
wpa_controller_dpp_chirp(struct wpa_controller *ctrl, uint32_t bootstrap_key_id, uint32_t iterations);

/**
 * @brief Requests wpa_supplicant to stop chirping.
 * 
 * @param ctrl The wpa controller instance.
 * @return int The result of the operation, 0 if successful, non-zero otherwise.
 */
int
wpa_controller_dpp_chirp_stop(struct wpa_controller *ctrl);

/**
 * @brief Requests wpa_supplicant to stop/cancel a DPP exchange.
 * @return int The result of the operation, 0 if successful, non-zero otherwise.
 */
int
wpa_controller_dpp_listen_stop(struct wpa_controller *ctrl);

/**
 * @brief Registers a handler for when chirps are received on the specified interface.
 *
 * @param ctrl The wpa control instance.
 * @param handler The event handler to invoke when an event occurs.
 * @param userdata The context to be passed to the event handling functions.
 * @return int 0 if successful, non-zero otherwise.
 */
int
wpa_controller_register_event_handler(struct wpa_controller *ctrl, struct wpa_event_handler *handler, void *userdata);

/**
 * @brief Unregisters a handler for chirp received events.
 *
 * @param ctrl The wpa control instance.
 * @param handler The previously registered event handler.
 * @param userdata The event handler callback context.
 */
void
wpa_controller_unregister_event_handler(struct wpa_controller *ctrl, struct wpa_event_handler *handler, void *userdata);

#endif // __WPA_CONTROLLER_H__
