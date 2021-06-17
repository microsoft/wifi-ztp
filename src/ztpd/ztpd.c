
#include <errno.h>
#include <gpiod.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <userspace/linux/compiler.h>

#include "dpp.h"
#include "event_loop.h"
#include "time_utils.h"
#include "ztp_configurator.h"
#include "ztp_dbus_client.h"
#include "ztp_dbus_configurator.h"
#include "ztp_dbus_server.h"
#include "ztp_enrollee.h"
#include "ztp_log.h"
#include "ztp_settings.h"
#include "ztp_systemd.h"
#include "ztp_wpa_supplicant.h"
#include "ztpd.h"
#include "ztpd_ui.h"

/**
 * @brief Deactivate the enrollee device role.
 * 
 * @param ztpd The ztpd global instance.
 * @param enrollee The enrollee to deactivate.
 */
static void
ztpd_device_role_deactivate_enrollee(struct ztpd *ztpd, struct ztp_enrollee **enrollee)
{
    __unused(ztpd);

    ztp_enrollee_destroy(enrollee);
}

/**
 * @brief Activate the enrollee device role.
 *
 * @param interface The interface to activate the enrollee role on.
 * @return int 0 if the enrollee role was successfully activated, non-zero otherwise.
 */
static int
ztpd_device_role_activate_enrollee(struct ztpd *ztpd, const char *interface, struct ztp_enrollee_settings *settings, struct ztp_enrollee **penrollee)
{
    struct ztp_enrollee *enrollee;
    int ret = ztp_enrollee_create(interface, settings, ztpd->wpas, ztpd->dbus, ztpd->loop, &enrollee);
    if (ret < 0) {
        zlog_error_if(interface, "failed to create enrollee (%d)", ret);
        return ret;
    }

    *penrollee = enrollee;

    return 0;
}

/**
 * @brief Activate the configurator device role.
 *
 * @param interface The interface to activate the configurator role on.
 * @return int 0 if the configurator role was successfully activated, non-zero otherwise.
 */
int
ztpd_device_role_activate_configurator(struct ztpd *ztpd, const char *interface, struct ztp_configurator_settings *settings, struct ztp_configurator **pconfigurator)
{
    struct ztp_configurator *configurator;
    int ret = ztp_configurator_create(interface, settings, ztpd->loop, &configurator);
    if (ret < 0) {
        zlog_error_if(interface, "failed to create configurator (%d)", ret);
        return ret;
    }

    ret = ztp_dbus_configurator_register(ztpd->dbus_srv, configurator);
    if (ret < 0) {
        zlog_error_if(interface, "failed to register configurator with d-bus (%d)", ret);
        ztp_configurator_destroy(&configurator);
        return ret;
    }

    *pconfigurator = configurator;

    return 0;
}

/**
 * @brief Deactivate the configurator device role.
 * 
 * @param ztpd The global ztpd instance.
 * @param pconfigurator The configurator to deactivate.
 */
static void
ztpd_device_role_deactivate_configurator(struct ztpd *ztpd, struct ztp_configurator **pconfigurator)
{
    if (!pconfigurator || !*pconfigurator)
        return;

    int ret = ztp_dbus_configurator_unregister(ztpd->dbus_srv, *pconfigurator);
    if (ret < 0)
        zlog_warning_if((*pconfigurator)->interface, "failed to unregister configurator d-bus object (%d)", ret);

    ztp_configurator_destroy(pconfigurator);
}

/**
 * @brief Unenforce any dependencies of the dpp role function. This includes any
 * configured, dependent systemd activation unit.
 * 
 * @param ztpd The global ztpd instance.
 * @param settings The device role settings to use for deactivation.
 */
static void
ztpd_device_role_deactivate_unenforce_dependencies(struct ztpd *ztpd, struct ztp_device_role_settings *settings)
{
    if (settings->activation_unit) {
        int ret = ztp_systemd_unit_stop(ztpd->dbus->bus, settings->activation_unit);
        if (ret < 0) {
            zlog_error_if(settings->interface, "failed to stop deactivation unit %s dependency (%d)", settings->activation_unit, ret);
            return;
        }
    }
}

/**
 * @brief Deactivate a device role.
 * 
 * @param ztpd The global ztpd instance.
 * @param instance The device role instance to deaactivate.
 */
static void
ztpd_device_role_deactivate(struct ztpd *ztpd, struct ztpd_device_role_instance *instance)
{
    ztpd_device_role_deactivate_unenforce_dependencies(ztpd, instance->settings);

    switch (instance->settings->role) {
        case DPP_DEVICE_ROLE_ENROLLEE:
            ztpd_device_role_deactivate_enrollee(ztpd, &instance->enrollee);
            break;
        case DPP_DEVICE_ROLE_CONFIGURATOR:
            ztpd_device_role_deactivate_configurator(ztpd, &instance->configurator);
            break;
        default:
            break;
    }

    list_del(&instance->list);
    free(instance);
}

/**
 * @brief Deactivates all enabled device roles.
 *
 * @param ztpd The global ztpd instance.
*/
static void
ztpd_device_role_deactivate_all(struct ztpd *ztpd)
{
    struct ztpd_device_role_instance *instance;
    struct ztpd_device_role_instance *instancetmp;
    list_for_each_entry_safe (instance, instancetmp, &ztpd->instances, list) {
        ztpd_device_role_deactivate(ztpd, instance);
    }
}

/**
 * @brief Enforce any dependencies of the dpp role function. This includes any
 * configured, dependent systemd activation unit.
 * 
 * @param ztpd The global ztpd instance.
 * @param settings The device role settings to use for activation.
 * @return int 0 if all dependencies were enforced, non-zero otherwise.
 */
static int
ztpd_device_role_activate_enforce_dependencies(struct ztpd *ztpd, struct ztp_device_role_settings *settings)
{
    if (settings->activation_unit) {
        int ret = ztp_systemd_unit_start(ztpd->dbus->bus, settings->activation_unit);
        if (ret < 0) {
            zlog_error_if(settings->interface, "failed to start activation unit %s dependency (%d)", settings->activation_unit, ret);
            return ret;
        }
    }

    return 0;
}

/**
 * @brief Activate a device role.
 * 
 * This creates a new instance of the device role using the specified settings.
 * 
 * @param ztpd The global ztpd instance.
 * @param settings The device role settings to use for activation.
 * @return int 0 if the role was activated and added to ztpds tracking list, non-zero otherwise.
 */
static int
ztpd_device_role_activate(struct ztpd *ztpd, struct ztp_device_role_settings *settings)
{
    int ret;
    const char *role = dpp_device_role_str(settings->role);
    if (!ztpd->settings->dpp_roles_activated[settings->role]) {
        zlog_info_if(settings->interface, "dpp device role '%s' not activated; ignoring", role);
        return -ENODEV;
    }

    struct ztpd_device_role_instance *instance = calloc(1, sizeof *instance);
    if (!instance) {
        zlog_error_if(settings->interface, "failed to allocate memory for device role instance");
        return -ENOMEM;
    }

    ret = ztpd_device_role_activate_enforce_dependencies(ztpd, settings);
    if (ret < 0) {
        zlog_error_if(settings->interface, "failed to enforce dependencies (%d)", ret);
        free(instance);
        return ret;
    }

    switch (settings->role) {
        case DPP_DEVICE_ROLE_ENROLLEE:
            ret = ztpd_device_role_activate_enrollee(ztpd, settings->interface, &settings->enrollee, &instance->enrollee);
            break;
        case DPP_DEVICE_ROLE_CONFIGURATOR:
            ret = ztpd_device_role_activate_configurator(ztpd, settings->interface, &settings->configurator, &instance->configurator);
            break;
        default:
            ret = -EINVAL;
            break;
    }

    if (ret < 0) {
        zlog_error_if(settings->interface, "failed to activate dpp device role '%s' (%d)", role, ret);
        return ret;
    }

    instance->settings = settings;

    zlog_info_if(settings->interface, "dpp device role '%s' activated", role);
    list_add(&instance->list, &ztpd->instances);

    return 0;
}

/**
 * @brief Activates all enabled device roles.
 *
 * @param ztpd The global ztpd instance.
*/
static void
ztpd_device_role_activate_all(struct ztpd *ztpd)
{
    struct ztp_device_role_settings_entry *entry;
    list_for_each_entry (entry, &ztpd->settings->role_settings, list) {
        int ret = ztpd_device_role_activate(ztpd, &entry->settings);
        if (ret < 0 && ret != -ENODEV) {
            zlog_warning_if(entry->settings.interface, "failed to process device role (%d)", ret);
            continue;
        }
    }
}

/**
 * @brief Handler function invoked when ui activation state changes.
 *
 * @param ztpd The global ztpd instance.
 * @param activated Describes the current (desired) activation state.
 */
static void
on_ui_activation_changed(struct ztpd *ztpd, bool activated)
{
    static const char *state[] = {
        "deactivated",
        "activated",
    };
    zlog_info("Δstate[ui] %s -> %s", state[!activated], state[activated]);

    int ret = activated ? ztpd_ui_activate(ztpd) : ztpd_ui_deactivate(ztpd);
    if (ret < 0)
        zlog_warning("failed to enforce ui mode change to %s (%d)", state[activated], ret);
}

/**
 * @brief Processes an update of the ui activation file descriptor used for
 * monitoring when the ui should be activated and de-activated.
 *
 * @param fd The file descriptor that has an update.
 * @param context The global ztpd instance.
 */
static void
process_fd_update_ui_activation(int fd, void *context)
{
    struct ztpd *ztpd = (struct ztpd *)context;

    struct gpiod_line_event event;
    if (gpiod_line_event_read_fd(fd, &event) < 0) {
        zlog_warning("gpio line singaled, but failed to read event(s)");
        return;
    }

    struct timespec now;
    int ret = clock_gettime(CLOCK_BOOTTIME, &now);
    if (ret < 0) {
        ret = errno;
        zlog_warning("failed to retrieve current time (%d); unable to debounce button press", ret);
        return;
    }

    switch (event.event_type) {
        case GPIOD_LINE_EVENT_RISING_EDGE: {
            if (ztpd->ui_activation_gpio_line_last_rising_edge.tv_sec == 0 &&
                ztpd->ui_activation_gpio_line_last_rising_edge.tv_nsec == 0) {
                ztpd->ui_activation_gpio_line_last_rising_edge = now;
            }
            return;
        }
        case GPIOD_LINE_EVENT_FALLING_EDGE: {
            struct timespec elapsed = timespec_diff(&now, &ztpd->ui_activation_gpio_line_last_rising_edge);
            if (timespeccmp(&elapsed, &ztpd->ui_activation_gpio_debounce, <)) {
                zlog_debug("debounce time not met; ignoring spurious falling edge");
                return;
            }
            break;
        }
        default:
            zlog_warning("unexpected gpio line signal (%d) received; ignoring", event.event_type);
            return;
    }

    ztpd->ui_activation_gpio_line_last_rising_edge.tv_sec = 0;
    ztpd->ui_activation_gpio_line_last_rising_edge.tv_nsec = 0;

    // refresh unit active state so it can be accurately toggled
    char *active_state;
    ret = ztpd_systemd_unit_get_activestate(ztpd->dbus->bus, ztpd->settings->ui_activation_unit, &active_state);
    if (ret < 0) {
        zlog_warning("failed to determine ui activation unit state (%d); using cached value", ret);
    } else {
        ztpd->ui_activated = strcmp(active_state, "active") == 0;
        free(active_state);
    }

    ztpd->ui_activated = !ztpd->ui_activated;
    on_ui_activation_changed(ztpd, ztpd->ui_activated);
}

/**
 * @brief Runs the main ztpd event loop.
 *
 * This is the main event loop and primary thread of execution for the daemon.
 * epoll is used to wait for changes on a set of monitored file descriptors.
 *
 * @param ztpd The global ztpd instance.
 * @return 0 if success, an error code otherwise
 */
int
ztpd_run(struct ztpd *ztpd)
{
    return event_loop_run(ztpd->loop);
}

/**
 * @brief Uninitialize the ui activation context.
 *
 * @param ztpd The global ztpd instance.
 */
static void
ztpd_uninitialize_ui_activation(struct ztpd *ztpd)
{
    if (ztpd->fd_uiactivation != -1) {
        event_loop_unregister_event(ztpd->loop, ztpd->fd_uiactivation);
        ztpd->fd_uiactivation = -1;
    }

    if (ztpd->ui_activation_gpio_chip) {
        gpiod_chip_close(ztpd->ui_activation_gpio_chip);
        ztpd->ui_activation_gpio_chip = NULL;
    }
}

/**
 * @brief Default delay value, in milliseconds, to use to debounce a button
 * press. This will only be used if no debounce value is specified in settings.
 */
#define DEFAULT_GPIO_BUTTON_DEBOUNCE_DELAY_MS 50

/**
 * @brief Initializes the ui activation trigger(s).

 * @param ztpd The global ztpd instance.
 * @return int The status of initialization; 0 if successful, -1 otherwise.
 */
static int
ztpd_initialize_ui_activation(struct ztpd *ztpd)
{
    int ret;

    if (!ztpd->settings->ui_activation_gpio)
        return 0;

    struct gpiod_chip *chip = gpiod_chip_open_lookup(ztpd->settings->ui_activation_gpio_chip);
    if (!chip) {
        zlog_error("failed to open gpio chip '%s'", ztpd->settings->ui_activation_gpio_chip);
        return -1;
    }

    struct gpiod_line *line = NULL;
    if (ztpd->settings->ui_activation_gpio_line_name)
        line = gpiod_chip_find_line(chip, ztpd->settings->ui_activation_gpio_line_name);
    if (!line && ztpd->settings->ui_activation_gpio_line >= 0)
        line = gpiod_chip_get_line(chip, (unsigned)ztpd->settings->ui_activation_gpio_line);
    if (!line) {
        zlog_error("failed to open gpio line");
        goto fail;
    }

    if (gpiod_line_request_both_edges_events(line, "ztpd") < 0) {
        zlog_error("failed to configure gpio line for both edge events");
        goto fail;
    }

    int fd = gpiod_line_event_get_fd(line);
    if (fd < 0) {
        zlog_error("failed to obtain gpio event fd");
        goto fail;
    }

    ret = event_loop_register_event(ztpd->loop, EPOLLIN, fd, process_fd_update_ui_activation, ztpd);
    if (ret < 0) {
        zlog_error("failed to register event for monitoring gpio events (%d)", ret);
        goto fail;
    }

    if (ztpd->settings->ui_activation_unit) {
        char *active_state;
        ret = ztpd_systemd_unit_get_activestate(ztpd->dbus->bus, ztpd->settings->ui_activation_unit, &active_state);
        if (ret < 0) {
            zlog_warning("failed to determine ui activation unit state (%d); assuming inactive", ret);
            ztpd->ui_activated = false;
        } else {
            ztpd->ui_activated = strcmp(active_state, "active") == 0;
            free(active_state);
        }

        zlog_debug("ui activation unit (%s) state %s", ztpd->settings->ui_activation_unit, ztpd->ui_activated ? "active" : "inactive");
    }

    ztpd->fd_uiactivation = fd;
    ztpd->ui_activation_gpio_chip = chip;
    ztpd->ui_activation_gpio_line = line;
    ztpd->ui_activation_gpio_line_last_rising_edge.tv_nsec = 0;
    ztpd->ui_activation_gpio_line_last_rising_edge.tv_sec = 0;
    ztpd->ui_activation_gpio_debounce.tv_sec = 0;
    ztpd->ui_activation_gpio_debounce.tv_nsec = ztpd->settings->ui_activation_gpio_delay;

    if (ztpd->ui_activation_gpio_debounce.tv_nsec <= 0)
        ztpd->ui_activation_gpio_debounce.tv_nsec = DEFAULT_GPIO_BUTTON_DEBOUNCE_DELAY_MS;
    ztpd->ui_activation_gpio_debounce.tv_nsec *= NSEC_PER_MSEC;

    ret = 0;
out:
    return ret;
fail:
    ztpd_uninitialize_ui_activation(ztpd);
    ret = -1;
    goto out;
}

/**
 * @brief Uninitialize the ztpd daemon.
 *
 * @param ztpd The global daemon instance to uninitialize.
 */
void
ztpd_uninitialize(struct ztpd *ztpd)
{
    ztpd_device_role_deactivate_all(ztpd);
    ztpd_uninitialize_ui_activation(ztpd);
}

/**
 * @brief Initialize the ztpd daemon.
 *
 * @param ztpd The instance to initialize.
 * @param settings The options with which to initialize the daemon.
 * @param loop The event loop to run the daemon with.
 * @param dbus A dbus connector instance.
 * @param dbus_srv A dbus server instance.
 * @param wpas A wpa supplicant connector instance.
 * @return int 0 if the instance was successfully initialized, non-zero otherwise.
 */
int
ztpd_initialize(struct ztpd *ztpd, struct ztp_settings *settings, struct event_loop *loop, struct ztp_dbus_client *dbus, struct ztp_dbus_server *dbus_srv, struct ztp_wpa_supplicant *wpas)
{
    explicit_bzero(ztpd, sizeof *ztpd);

    INIT_LIST_HEAD(&ztpd->instances);
    ztpd->wpas = wpas;
    ztpd->dbus = dbus;
    ztpd->loop = loop;
    ztpd->settings = settings;
    ztpd->dbus_srv = dbus_srv;
    ztpd->fd_uiactivation = -1;

    int ret = ztpd_initialize_ui_activation(ztpd);
    if (ret < 0) {
        zlog_error("failed to initialize ztpd ui activation (%d)", ret);
        ztpd_uninitialize(ztpd);
        return ret;
    }

    ztpd_device_role_activate_all(ztpd);
    return 0;
}
