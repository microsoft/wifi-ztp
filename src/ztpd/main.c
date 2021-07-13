
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include <userspace/linux/compiler.h>

#include "event_loop.h"
#include "ztp_dbus_client.h"
#include "ztp_dbus_network_configuration.h"
#include "ztp_dbus_server.h"
#include "ztp_log.h"
#include "ztp_settings.h"
#include "ztp_wpa_supplicant.h"
#include "ztp_version.h"
#include "ztpd.h"

/**
 * @brief Returns a pointer to the first non-whitespace character in a string.

 * @param s The string to trim.
 * @return char* The first non-whitespace character in the string, or '\0' if
 * the string is entirely whitespce.
 */
static char *
triml(char *s)
{
    while (isspace(*s))
        s++;
    return s;
}

/**
 * @brief Arguments that are used to initialize a ztpd instance.
 */
struct ztpd_args {
    struct ztp_settings *settings;
    struct ztp_dbus_client *dbus_client;
    struct ztp_dbus_server *dbus_server;
    struct event_loop *loop;
    struct ztp_wpa_supplicant *wpas;
};

/**
 * @brief Settings-changed event handler context. This is used to pass the ztpd
 * service pointer to the event handler such that it can be used to provide it
 * new settings.
 */
struct ztp_settings_changed_event_context {
    struct ztpd *ztpd;
    struct ztpd_args *ztpd_args;
};

/**
 * @brief Cycle initialization of ztpd.
 * 
 * @param ztpd The instance to cycle.
 * @param args The arguments to initialize ztpd with.
 * @return int 0 if re-initialization succeeded, non-zero otherwise.
 */
static int
ztpd_reinitialize(struct ztpd *ztpd, struct ztpd_args *args)
{
    ztpd_uninitialize(ztpd);

    int ret = ztpd_initialize(ztpd, args->settings, args->loop, args->dbus_client, args->dbus_server, args->wpas);
    if (ret < 0) {
        zlog_error("failed to reinitialize ztpd (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief ztp settings changed handler. This function will be invoked each time
 * the ztp settings are changed on-disk. It will determine how to handle the
 * change and supply new settings to ztpd.
 * 
 * @param settings_old The old settings that have changed.
 * @param changed_event The settings-changed event payload.
 * @param context The context previously associated with the settings-changed handler.
 */
static void
on_settings_changed(struct ztp_settings *settings_old, struct ztp_settings_changed_event *changed_event, void *context)
{
    __unused(changed_event);

    struct ztp_settings_changed_event_context *changed_event_context = (struct ztp_settings_changed_event_context *)context;
    const char *config_file = settings_old->config_file;

    struct ztp_settings *settings = NULL;
    int ret = ztp_settings_parse(config_file, &settings);
    if (ret < 0) {
        zlog_error("failed to parse updated ztp settings file %s (%d)", config_file, ret);
        return;
    }

    ret = ztp_settings_register_change_handler(settings, on_settings_changed, context);
    if (ret < 0) {
        zlog_warning("failed to register settings changed handler (%d); future settings changes reflected on process restart", ret);
    }

    changed_event_context->ztpd_args->settings = settings;
    ztp_dbus_server_update_settings(changed_event_context->ztpd_args->dbus_server, settings);
    ztpd_reinitialize(changed_event_context->ztpd, changed_event_context->ztpd_args);

    ztp_settings_destroy(&settings_old);
}

/**
 * @brief Processes an update for a file descriptor used for monitoring
 * traditional process signals.
 *
 * @param fd The file descriptor which signaled an update.
 * @param context The ztpd event loop instance.
 */
static void
on_signal_received(int fd, void *context)
{
    struct event_loop *loop = (struct event_loop *)context;

    struct signalfd_siginfo siginfo;
    ssize_t bytes = read(fd, &siginfo, sizeof siginfo);
    if (bytes < (ssize_t)(sizeof siginfo)) {
        zlog_warning("siginfo read returned too little data");
        return;
    }

    switch (siginfo.ssi_signo) {
        case SIGINT:
        case SIGTERM:
            sd_event_exit(loop->ebase,-((int) siginfo.ssi_signo));
            break;
        default:
            break;
    }
}

/**
 * @brief Register for file descriptor signal updates.
 *
 * This function registers a file descriptor to receive updates for a set of
 * signals. Normally, signals must be handled by dedicated signal handlers
 * which have severe restrictions on the code they can execute (since a signal
 * halts all execution of a process). This normally results in adding a new
 * thread and using a self-pipe trick to communicate the intent of the signal,
 * which is messy.
 *
 * We are only interested in the signals used to stop the service: SIGTERM (eg.
 * kill) and SIGINT (eg. Ctrl+C). These signals are masked so that the
 * regular/default signal handlers will be disabled, then hook these up to a
 * file descriptor.
 *
 * @param loop The event loop to register the signal handler with.
 * @param pfd_signals The output pointer for the signal handling descriptor.
 * @return int The status of the operation; 0 if successful, -1 otherwise.
 */
static int
register_terminate_signals(struct event_loop *loop, int *pfd_signals)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        zlog_error("failed to block terminate signals");
        return -1;
    }

    int fd_signals = signalfd(-1, &mask, 0);
    if (fd_signals < 0) {
        zlog_error("failed to allocate signal fd");
        return -1;
    }

    int ret = event_loop_register_event(loop, EPOLLIN, fd_signals, on_signal_received, loop);
    if (ret < 0) {
        zlog_error("failed to register event for monitoring termination signals (%d)", ret);
        return ret;
    }

    *pfd_signals = fd_signals;
    return 0;
}

/**
 * @brief Output the current daemon version to standard output.
 */
static void
show_version(void)
{
    zlog_info("ztpd v%u.%u.%u.%u", 
        ZTP_VERSION_MAJOR, ZTP_VERSION_MINOR, ZTP_VERSION_PATCH, ZTP_VERSION_TWEAK);
}

/**
 * @brief Main program entrypoint.
 *
 * @param argc
 * @param argv
 * @return int
 */
int
main(int argc, char *argv[])
{
    int ret, signalfd = -1;
    bool daemonize = false;
    char *config_file = ZTP_DEFAULT_CONFIG_PATH;
    struct ztp_settings *settings;
    struct ztpd ztpd;
    struct ztp_dbus_client dbus_client;
    struct ztp_dbus_server dbus_server;
    struct event_loop loop;
    struct ztp_wpa_supplicant wpas;
    struct ztp_dbus_network_configuration_manager *network_configuration_manager;

    show_version();

    // Process command line options.
    for (;;) {
        int opt = getopt(argc, argv, "bc:v");
        if (opt < 0) {
            break;
        }

        switch (opt) {
            case 'b':
                daemonize = true;
                break;
            case 'c':
                config_file = triml(optarg);
                break;
            case 'v':
                // when explicitly specified, exit immediately
                return 0;
            default:
                break;
        }
    }

    ret = ztp_settings_parse(config_file, &settings);
    if (ret < 0) {
        zlog_panic("failed to parse settings from %s (%d)", config_file, ret);
        return -1;
    }

    ret = event_loop_initialize(&loop);
    if (ret < 0) {
        zlog_panic("failed to initialize event loop (%d)", ret);
        return -1;
    }

    ret = ztp_dbus_initialize(&dbus_client, &loop);
    if (ret < 0) {
        zlog_panic("failed to initialize dbus connector (%d)", ret);
        return -1;
    }

    ret = ztp_dbus_network_configuration_manager_create(&network_configuration_manager, ZTP_DBUS_SERVER_PATH);
    if (ret < 0) {
        zlog_error("failed to instantiate d-bus network configuration manager (%d)", ret);
        return ret;
    }

    ret = ztp_dbus_server_initialize(&dbus_server, settings, network_configuration_manager, ZTP_DBUS_SERVER_PATH);
    if (ret < 0) {
        zlog_panic("failed to initialize dbus server (%d)", ret);
        return -1;
    }

    ret = ztp_wpa_supplicant_initialize(&wpas);
    if (ret < 0) {
        zlog_panic("failed to initialize wpa supplicant connector (%d)", ret);
        return -1;
    }

    ret = register_terminate_signals(&loop, &signalfd);
    if (ret < 0) {
        zlog_panic("failed to register termination signals (%d)", ret);
        return -1;
    }

    ret = ztpd_initialize(&ztpd, settings, &loop, &dbus_client, &dbus_server, &wpas);
    if (ret < 0) {
        zlog_panic("failed to initialize ztpd (%d)", ret);
        return -1;
    }

    struct ztpd_args ztpd_args = {
        .settings = settings,
        .dbus_client = &dbus_client,
        .dbus_server = &dbus_server,
        .loop = &loop,
        .wpas = &wpas,
    };

    struct ztp_settings_changed_event_context changed_event_context = {
        .ztpd = &ztpd,
        .ztpd_args = &ztpd_args,
    };

    ret = ztp_settings_register_change_handler(settings, on_settings_changed, &changed_event_context);
    if (ret < 0) {
        zlog_panic("failed to register settings changed event handler (%d)", ret);
        return -1;
    }

    // Run the process in the background if requested.
    if (daemonize) {
        if (daemon(0, 0)) {
            zlog_panic("failed to daemonize");
            return -1;
        }
    }

    ret = ztpd_run(&ztpd);
    if (ret < 0) {
        zlog_panic("ztpd did not exit cleanly (%d)", ret);
        return ret;
    }

    zlog_debug("event loop completed");

    ztpd_uninitialize(&ztpd);
    ztp_dbus_uninitialize(&dbus_client);
    ztp_dbus_server_uninitialize(&dbus_server);
    ztp_settings_destroy(&ztpd_args.settings);
    event_loop_uninitialize(&loop);

    close(signalfd);

    zlog_debug("exiting");

    return 0;
}
