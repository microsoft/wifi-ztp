
#ifndef __WPA_SUPPLICANT_H__
#define __WPA_SUPPLICANT_H__

#define WPAS_DBUS_SERVICE_PATH "/fi/w1/wpa_supplicant1"
#define WPAS_DBUS_SERVICE "fi.w1.wpa_supplicant1"
#define WPAS_DBUS_INTERFACE "fi.w1.wpa_supplicant1.Interface"
#define WPAS_DBUS_NETWORK "fi.w1.wpa_supplicant1.Network"
#define WPAS_DBUS_BSS "fi.w1.wpa_supplicant1.BSS"

/**
 * @brief wpa supplicant interface state. 
 */
enum wpas_interface_state {
    WPAS_INTERFACE_STATE_DISCONNECTED = 0,
    WPAS_INTERFACE_STATE_INACTIVE,
    WPAS_INTERFACE_STATE_DISABLED,
    WPAS_INTERFACE_STATE_SCANNING,
    WPAS_INTERFACE_STATE_AUTHENTICATING,
    WPAS_INTERFACE_STATE_ASSOCIATING,
    WPAS_INTERFACE_STATE_ASSOCIATED,
    WPAS_INTERFACE_STATE_4WAY_HANDSHAKE,
    WPAS_INTERFACE_STATE_GROUP_HANDSHAKE,
    WPAS_INTERFACE_STATE_COMPLETED,
    WPAS_INTERFACE_STATE_UNKNOWN,
    WPAS_INTERFACE_STATE_INVALID
};

/**
 * @brief Parses a string and converts it to a wpa supplicant interface state
 * enumeration value.
 * 
 * If the string does not correspond to a valid enumeration value, WPAS_INTERFACE_STATE_INVALID is returned.
 * @param state The string to parse and convert.
 * @return enum wpas_interface_state The enumeration value corresponding to the
 * string, oo WPAS_INTERFACE_STATE_INVALID if no such correspondence exists.
 */
enum wpas_interface_state
parse_wpas_interface_state(const char *state);

/**
 * @brief Converts a wpa supplicant interface state to a string.
 * 
 * @param state The state to convert.
 * @return const char* The string representation of the state.
 */
const char *
wpas_interface_state_str(enum wpas_interface_state state);

#endif //__WPA_SUPPLICANT_H__
