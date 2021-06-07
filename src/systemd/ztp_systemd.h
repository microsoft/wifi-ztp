
#ifndef __ZTP_SYSTEMD_H__
#define __ZTP_SYSTEMD_H__

#include <stdbool.h>

#include <systemd/sd-bus.h>

#define SYSTEMD_SERVICE_PATH "/org/freedesktop/systemd1"
#define SYSTEMD_SERVICE "org.freedesktop.systemd1"

#define SYSTEMD_INTERFACE_MANAGER SYSTEMD_SERVICE ".Manager"
#define SYSTEMD_INTERFACE_UNIT SYSTEMD_SERVICE ".Unit"

/**
 * @brief Wrapper function for the 'StartUnit' command on the Manager interface
 * for systemd.
 *
 * This function uses the "replace" mode which will replace any existing calls
 * to start the unit with a new one. Note this only invokes the call and
 * doesn't enforce that the service stays up. For example, if the service
 * immediately crashes or otherwise exits and is not configured to restart,
 * this function will not make any attempts to start it again. The service
 * should be configured appropriately to stay up and have fault-tolerant logic
 * or systemd options built in.

 * @param bus Pointer to a d-bus bus connection to send the call on.
 * @param unit The name of the unit to start.
 * @return int 0 if the unit was started, 0 otherwise.
 */
int
ztp_systemd_unit_start(sd_bus *bus, const char *unitname);

/**
 * @brief Wrapper function for the 'StopUnit' command on the Manager interface
 * for systemd. this function uses the "replace" mode which will replace any
 * existing calls to stop the unit with a new one.

 * @param bus Pointer to a d-bus bus connection to send the call on.
 * @param unit The name of the unit to stop.
 * @return int 0 if the unit was stopped, 0 otherwise.
 */
int
ztp_systemd_unit_stop(sd_bus *bus, const char *unitname);

/**
 * @brief Retrieves the active state of the specified activation unit.
 * 
 * @param bus Pointer to a d-bus bus connection to send the call on.
 * @param unit The name of the unit to query.
 * @param active_state Output pointer to hold the active state string. Must be free()'ed.
 * @return int 0 if the active state was determined, non-zero otherwise.
 */
int
ztpd_systemd_unit_get_activestate(sd_bus *bus, const char *unit, char **active_state);

#endif //__ZTP_SYSTEMD_H__
