
#include "ztpd_ui.h"
#include "ztp_dbus_client.h"
#include "ztp_log.h"
#include "ztp_settings.h"
#include "ztp_systemd.h"
#include "ztpd.h"

/**
 * @brief Activates the ui service.
 *
 * @param ztpd The global ztpd instance.
 * @return int
 */
int
ztpd_ui_activate(struct ztpd *ztpd)
{
    int ret;
    if (ztpd->settings->ui_activation_unit) {
        ret = ztp_systemd_unit_start(ztpd->dbus->bus, ztpd->settings->ui_activation_unit);
        if (ret < 0) {
            zlog_warning("failed to start unit %s", ztpd->settings->ui_activation_unit);
        } else {
            zlog_info("started ui service unit %s", ztpd->settings->ui_activation_unit);
        }
    } else {
        ret = 0;
    }

    return ret;
}

/**
 * @brief Deactivates the ui service.
 *
 * @param ztpd The global ztpd instance.
 * @return int
 */
int
ztpd_ui_deactivate(struct ztpd *ztpd)
{
    int ret;
    if (ztpd->settings->ui_activation_unit) {
        ret = ztp_systemd_unit_stop(ztpd->dbus->bus, ztpd->settings->ui_activation_unit);
        if (ret < 0) {
            zlog_warning("failed to stop unit %s", ztpd->settings->ui_activation_unit);
        } else {
            zlog_info("stopped ui service unit %s", ztpd->settings->ui_activation_unit);
        }
    } else {
        ret = 0;
    }

    return ret;
}
