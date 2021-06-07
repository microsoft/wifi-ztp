#ifndef __ZTP_H__
#define __ZTP_H__

/**
 * @brief Describes the states of connectivity for an interface.
 */
enum ztp_connectivity_state {

    /**
     * @brief Initializing state. This is the initial state which determines
     * the next state based on persistent Wi-Fi configuration on the device. If
     * any networks have been configured, then the device will enter into
     * “Connecting” state. If no networks have been configured, then the device
     * will enter into “Chirping” state to indicate provisioning is needed.
     */
    ZTP_CONNECTIVITY_STATE_INITIALIZING = 0,

    /**
     * @brief Inactive state. This occurs when ztp is disabled.
     */
    ZTP_CONNECTIVITY_STATE_INACTIVE = 1,

    /**
     * @brief Unprovisioned state. This occurs when the interface has no
     * provisioned Wi-Fi networks. The device will attempt to acquire Wi-Fi
     * network configuration using the Device Provisioning Protocol (DPP).
     */
    ZTP_CONNECTIVITY_STATE_UNPROVISIONED = 2,

    /**
     * @brief Provisioned state. In the connecting state, at least one Wi-Fi
     * network has been provisioned and the device is attempting to find and
     * connect to a network.
     */
    ZTP_CONNECTIVITY_STATE_PROVISIONED = 3,

    /**
     * @brief Connected state. In connected state, the device has connected to
     * a network it has been provisioned.
     */
    ZTP_CONNECTIVITY_STATE_CONNECTED = 4,
};

/**
 * @brief Converts a ZTP connectivity state into a string. The returned string
 * is a literal and must be duplicated in some way; the caller does not own it.
 *
 * @param state The state to convert.
 * @return const char* A string representation of the state, or "??" if state
 * is invalid or unknown.
 */
const char*
ztp_connectivity_state_str(enum ztp_connectivity_state state);

#endif //__ZTP_H__
