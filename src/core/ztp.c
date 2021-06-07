
#include <string.h>

#include "ztp.h"

/**
 * @brief Converts a ZTP connectivity state into a string. The returned string
 * is a literal and must be duplicated in some way; the caller does not own it.
 *
 * @param state The state to convert.
 * @return const char* A string representation of the state, or "??" if state
 * is invalid or unknown.
 */
const char*
ztp_connectivity_state_str(enum ztp_connectivity_state state)
{
    switch (state) {
        case ZTP_CONNECTIVITY_STATE_INITIALIZING:
            return "initializing";
        case ZTP_CONNECTIVITY_STATE_INACTIVE:
            return "inactive";
        case ZTP_CONNECTIVITY_STATE_UNPROVISIONED:
            return "unprovisioned";
        case ZTP_CONNECTIVITY_STATE_PROVISIONED:
            return "provisioned";
        case ZTP_CONNECTIVITY_STATE_CONNECTED:
            return "connected";
        default:
            return "invalid";
    }
}
