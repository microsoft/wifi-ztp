
#ifndef __ZTP_SETTINGS_H__
#define __ZTP_SETTINGS_H__

#include <stdbool.h>
#include <stdint.h>

#include <json-c/json_object.h>

#include "dpp.h"
#include "ztp_configurator_config.h"
#include "ztp_enrollee_config.h"

/**
 * @brief Type mapping a role and interface to its settings.
 */
struct ztp_device_role_settings {
    enum dpp_device_role role;
    char *path;
    char *interface;
    char *activation_unit;
    union {
        struct ztp_enrollee_settings enrollee;
        struct ztp_configurator_settings configurator;
    };
};

/**
 * @brief List/map entry for ztp role settings.
 */
struct ztp_device_role_settings_entry {
    struct list_head list;
    struct ztp_device_role_settings settings;
};

/**
 * @brief Default location of the ztpd configuration file. The daemon will
 * attempt to use this file if no configuration is specified as a command line
 * argument (-c <config>).
 */
#define ZTP_DEFAULT_CONFIG_PATH "/etc/ztpd/config.json"

/**
 * @brief The daemon configuration options.
 */
struct ztp_settings {
    // Global service options
    bool dpp_roles_exclusive;
    bool dpp_roles_supported[DPP_DEVICE_ROLE_COUNT];
    bool dpp_roles_activated[DPP_DEVICE_ROLE_COUNT];
    struct json_object *dpp_roles_activated_json;
    struct json_object *json;

    // UI activation options
    bool ui_activation_command;
    bool ui_activation_gpio;
    char *ui_activation_gpio_chip;
    char *ui_activation_gpio_line_name;
    int32_t ui_activation_gpio_line;
    int32_t ui_activation_gpio_delay;
    char *ui_activation_unit;

    // Per-interface settings
    struct list_head role_settings;
    struct list_head change_handlers;

    char config_file[];
};

enum ztp_settings_changed_item {
    ZTP_SETTING_CHANGED_ITEM_DEVICE_ROLES,
    ZTP_SETTING_CHANGED_ITEM_CONFIGURATOR_SETTINGS,
};

/**
 * @brief Event payload for when ztp settings change. 
 * 
 * There is no current need to denote which setting or group of settings
 * changed, so this structure does not currently need a body. It is defined
 * here to keep the API stable for clients in case such details become
 * pertinent in the future.
*/
struct ztp_settings_changed_event {
    enum ztp_settings_changed_item changed_item;
};

/**
 * @brief Callback prototype for a settings-changed event.
 */
typedef void (*ztp_settings_changed_fn)(struct ztp_settings *, struct ztp_settings_changed_event *, void *);

/**
 * @brief Registers a settings changed handler. The specified callback function
 * will be invoked with the context argument and a changed event structure each
 * time the settings change.
 * 
 * @param settings The ztp settings to monitor change events for.
 * @param callback The callback function to invoke oin change.
 * @param context An additional context-specific argument to be passed to the callback function.
 * @return int 0 if the handler was successfully registered, non-zero otherwise.
 */
int
ztp_settings_register_change_handler(struct ztp_settings *settings, ztp_settings_changed_fn callback, void *context);

/**
 * @brief Unregisters a settings changed handler.
 * 
 * @param settings The ztp settings to remove the handler from.
 * @param callback The previously registered callback.
 * @param context The context previously registered with the callback.
 */
void
ztp_settings_unregister_change_handler(struct ztp_settings *settings, ztp_settings_changed_fn callback, void *context);

/**
 * @brief Signals that the ztp settings have changed.
 * 
 * @param settings The settings object that has changed.
 * @param changed_item The setting item that changed.
 */
void
ztp_settings_signal_changed(struct ztp_settings *settings, enum ztp_settings_changed_item changed_item);

/**
 * @brief Parses a ztp settings file.
 *
 * @param config_file The full path of the configuration file to parse.
 * @param psettings An output pointer to receive a parsed settings object. The
 * caller is responsible for calling ztp_settings_destroy on this object.
 * @return int
 */
int
ztp_settings_parse(const char *path, struct ztp_settings **psettings);

/**
 * @brief Uninitialize ztpd daemon options.
 *
 * @param psettings Pointer to the settings to destroy.
 */
void
ztp_settings_destroy(struct ztp_settings **psettings);

/**
 * @brief Finds role settings, given an interface name.
 *
 * @param settings The ztp settings structure to search.
 * @param interface The name of the interface to lookup settings for.
 * @return struct ztp_device_role_settings*
 */
struct ztp_device_role_settings *
ztp_settings_find_device_role_settings(const struct ztp_settings *settings, const char *interface);

/**
 * @brief Sets the device role setting to activated or deactivated. Note that
 * this does not necessarily affect the functionality of any running daemon;
 * this only updates the setting.
 * 
 * If exclusive mode is set, and the new role diposition is to activate, then
 * the existing activated role (if one exists) will be changed to disabled.
 * 
 * @param settings The settings instance to update.
 * @param role The role to set the disposition for.
 * @param activate The role disposition.
 * @return int 0 if the role disposition was successfully updated, -EOPNOTSUP
 * if the role isn't supported.
 */
int
ztp_settings_set_device_role_disposition(struct ztp_settings *settings, enum dpp_device_role role, bool activate);

#endif //__ZTP_SETTINGS_H__
