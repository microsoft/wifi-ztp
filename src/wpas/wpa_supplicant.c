
#include <stddef.h>
#include <string.h>

#include <userspace/linux/kernel.h>

#include "wpa_supplicant.h"

/**
 * @brief Table mapping enum wpas_interface_state values to strings.
 */
static const char *wpas_interface_state_strs[WPAS_INTERFACE_STATE_INVALID + 1] = {
    "disconnected",
    "inactive",
    "disabled",
    "scanning",
    "authenticating",
    "associating",
    "associated",
    "4way_handshake",
    "group_handshake",
    "completed",
    "unknown",
    "invalid",
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
parse_wpas_interface_state(const char *state)
{
    for (size_t i = 0; i < ARRAY_SIZE(wpas_interface_state_strs); i++) {
        if (strcmp(state, wpas_interface_state_strs[i]) == 0)
            return (enum wpas_interface_state)i;
    }

    return WPAS_INTERFACE_STATE_INVALID;
}

/**
 * @brief Converts a wpa supplicant interface state to a string.
 * 
 * @param state The state to convert.
 * @return const char* The string representation of the state.
 */
const char *
wpas_interface_state_str(enum wpas_interface_state state)
{
    return wpas_interface_state_strs[state];
}
