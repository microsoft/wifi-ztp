
#include <string.h>

#include <systemd/sd-bus.h>

#include "ztp_log.h"
#include "ztp_systemd.h"

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
ztp_systemd_unit_start(sd_bus *bus, const char *unit)
{
    sd_bus_message *msg;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret = sd_bus_call_method(bus,
        SYSTEMD_SERVICE,
        SYSTEMD_SERVICE_PATH,
        SYSTEMD_INTERFACE_MANAGER,
        "StartUnit",
        &error,
        &msg,
        "ss",
        unit,
        "replace");
    if (ret < 0) {
        zlog_error("failed to call StartUnit for unit %s(%d)", unit, ret);
        return ret;
    }

    sd_bus_message_unref(msg);
    return 0;
}

/**
 * @brief Wrapper function for the 'StopUnit' command on the Manager interface
 * for systemd. this function uses the "replace" mode which will replace any
 * existing calls to stop the unit with a new one.

 * @param bus Pointer to a d-bus bus connection to send the call on.
 * @param unit The name of the unit to stop.
 * @return int 0 if the unit was stopped, 0 otherwise.
 */
int
ztp_systemd_unit_stop(sd_bus *bus, const char *unit)
{
    sd_bus_message *msg;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret = sd_bus_call_method(bus,
        SYSTEMD_SERVICE,
        SYSTEMD_SERVICE_PATH,
        SYSTEMD_INTERFACE_MANAGER,
        "StopUnit",
        &error,
        &msg,
        "ss",
        unit,
        "replace");
    if (ret < 0) {
        zlog_error("failed to call StopUnit for unit %s (%d)", unit, ret);
        return ret;
    }

    sd_bus_message_unref(msg);
    return 0;
}

/**
 * @brief Retrieves the active state of the specified activation unit.
 * 
 * @param bus Pointer to a d-bus bus connection to send the call on.
 * @param unit The name of the unit to query.
 * @param active_state Output pointer to hold the active state string. Must be free()'ed.
 * @return int 0 if the active state was determined, non-zero otherwise.
 */
int
ztpd_systemd_unit_get_activestate(sd_bus *bus, const char *unit, char **active_state)
{
    sd_bus_message *msg;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret = sd_bus_call_method(bus,
        SYSTEMD_SERVICE,
        SYSTEMD_SERVICE_PATH,
        SYSTEMD_INTERFACE_MANAGER,
        "LoadUnit",
        &error,
        &msg,
        "s",
        unit);
    if (ret < 0) {
        zlog_error("failed to determine d-bus path for unit %s (%d)", unit, ret);
        return ret;
    }

    const char *unit_path = NULL;
    ret = sd_bus_message_read_basic(msg, SD_BUS_TYPE_OBJECT_PATH, &unit_path);
    sd_bus_message_unref(msg);
    if (ret < 0) {
        zlog_error("failed to read unit path from message response (%d)", ret);
        return ret;
    }

    ret = sd_bus_get_property_string(bus,
        SYSTEMD_SERVICE,
        unit_path,
        SYSTEMD_INTERFACE_UNIT,
        "ActiveState",
        &error,
        active_state);
    if (ret < 0) {
        zlog_error("failed to retrieve ActiveState property from unit %s (%d)", unit, ret);
        return ret;
    }

    return 0;
}
