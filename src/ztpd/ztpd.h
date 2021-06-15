
#ifndef __ZTPD_H__
#define __ZTPD_H__

#include <stdbool.h>

#include <systemd/sd-bus.h>
#include <userspace/linux/list.h>

struct ztp_dbus_client;
struct ztp_dbus_server;
struct ztp_wpa_supplicant;
struct ztp_settings;

struct ztpd_device_role_instance {
    struct list_head list;
    struct ztp_device_role_settings *settings;
    union {
        struct ztp_enrollee *enrollee;
        struct ztp_configurator *configurator;
    };
};

/**
 * @brief The global daemon instance structure.
 */
struct ztpd {
    // generic bits
    struct list_head interfaces;
    struct ztp_settings *settings;
    int terminate_pending;

    // epoll
    int fd_uiactivation;
    struct event_loop *loop;

    // child event control interfaces
    struct ztp_dbus_client *dbus;
    struct ztp_dbus_server *dbus_srv;
    struct ztp_wpa_supplicant *wpas;

    // role instance pointers
    struct list_head instances;

    // ui activation
    bool ui_activated;
    struct gpiod_chip *ui_activation_gpio_chip;
    struct gpiod_line *ui_activation_gpio_line;
    struct timespec ui_activation_gpio_debounce;
    struct timespec ui_activation_gpio_line_last_rising_edge;
};

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
ztpd_initialize(struct ztpd *ztpd, struct ztp_settings *settings, struct event_loop *loop, struct ztp_dbus_client *dbus, struct ztp_dbus_server *dbus_srv, struct ztp_wpa_supplicant *wpas);

/**
 * @brief Uninitialize the ztpd daemon.
 *
 * @param ztpd The global daemon instance to uninitialize.
 */
void
ztpd_uninitialize(struct ztpd *ztpd);

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
ztpd_run(struct ztpd *ztpd);

#endif
