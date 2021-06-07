
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <json-c/json_object.h>
#include <json-c/json_util.h>
#include <userspace/linux/compiler.h>
#include <userspace/linux/kernel.h>

#include "file_utils.h"
#include "json_parse.h"
#include "ztp_log.h"
#include "ztp_settings.h"

/**
 * @brief Settings changed event handler.
 */
struct ztp_settings_changed_event_handler {
    struct list_head list;
    ztp_settings_changed_fn callback;
    void *context;
};

/**
 * @brief Signals that the ztp settings have changed.
 * 
 * @param settings The settings object that has changed.
 * @param changed_item The setting item that changed.
 */
void
ztp_settings_signal_changed(struct ztp_settings *settings, enum ztp_settings_changed_item changed_item)
{
    struct ztp_settings_changed_event changed_event = {
        .changed_item = changed_item,
    };
    const struct ztp_settings_changed_event_handler *changed_handler;
    const struct ztp_settings_changed_event_handler *changed_handler_tmp;

    list_for_each_entry_safe (changed_handler, changed_handler_tmp, &settings->change_handlers, list) {
        changed_handler->callback(settings, &changed_event, changed_handler->context);
    }
}

/**
 * @brief Finds a changed handler, given a callback and context argument.
 * 
 * @param settings The ztp settings to search for the specified handler.
 * @param callback The callback function associated with the handler.
 * @param context The context argument assoicated with the callback.
 * @return struct ztp_settings_changed_event_handler* If such a handler has
 * been registered, otherwise NULL.
 */
struct ztp_settings_changed_event_handler *
find_settings_changed_handler(struct ztp_settings *settings, ztp_settings_changed_fn callback, void *context)
{
    struct ztp_settings_changed_event_handler *change_handler;

    list_for_each_entry (change_handler, &settings->change_handlers, list) {
        if (change_handler->callback == callback && change_handler->context == context) {
            return change_handler;
        }
    }

    return NULL;
}

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
ztp_settings_register_change_handler(struct ztp_settings *settings, ztp_settings_changed_fn callback, void *context)
{
    if (find_settings_changed_handler(settings, callback, context))
        return 0;

    struct ztp_settings_changed_event_handler *changed_handler = malloc(sizeof *changed_handler);
    if (!changed_handler) {
        zlog_error("failed to allocate memory for ztp settings changed handler");
        return -ENOMEM;
    }

    changed_handler->callback = callback;
    changed_handler->context = context;
    list_add(&changed_handler->list, &settings->change_handlers);

    return 0;
}

/**
 * @brief Unregisters a settings changed handler.
 * 
 * @param settings The ztp settings to remove the handler from.
 * @param callback The previously registered callback.
 * @param context The context previously registered with the callback.
 */
void
ztp_settings_unregister_change_handler(struct ztp_settings *settings, ztp_settings_changed_fn callback, void *context)
{
    struct ztp_settings_changed_event_handler *change_handler = find_settings_changed_handler(settings, callback, context);
    if (!change_handler)
        return;

    list_del(&change_handler->list);
    free(change_handler);
}

/**
 * @brief Uninitializes a role settings entry.
 *
 * @param settings The settings object to uninitialize.
 */
static void
ztp_device_role_settings_uninitialize(struct ztp_device_role_settings *settings)
{
    if (settings->activation_unit) {
        free(settings->activation_unit);
        settings->activation_unit = NULL;
    }

    if (settings->interface) {
        free(settings->interface);
        settings->interface = NULL;
    }

    if (settings->path) {
        free(settings->path);
        settings->path = NULL;
    }

    switch (settings->role) {
        case DPP_DEVICE_ROLE_ENROLLEE: {
            ztp_enrollee_settings_uninitialize(&settings->enrollee);
            break;
        }
        case DPP_DEVICE_ROLE_CONFIGURATOR:
            ztp_configurator_settings_uninitialize(&settings->configurator);
            break;
        default:
            break;
    }
}

/**
 * @brief Create an initialize a new interface settings entry.
 *
 * @return struct ztp_interface_settings_entry*
 */
struct ztp_device_role_settings_entry *
ztp_device_role_settings_entry_initialize(void)
{
    struct ztp_device_role_settings_entry *entry = calloc(1, sizeof *entry);
    if (!entry) {
        zlog_warning("failed to allocate memory for role settings entry");
        return NULL;
    }

    INIT_LIST_HEAD(&entry->list);
    return entry;
}

/**
 * @brief Finds a device role settings entry, given an interface name.
 *
 * @param settings The ztp settings structure to search.
 * @param interface The interface name to lookup settings for.
 * @return struct ztp_device_role_settings_entry*
 */
static struct ztp_device_role_settings_entry *
ztp_settings_find_device_role_settings_entry(const struct ztp_settings *settings, const char *interface)
{
    struct ztp_device_role_settings_entry *entry;

    list_for_each_entry (entry, &settings->role_settings, list) {
        if (strcmp(entry->settings.interface, interface) == 0)
            return entry;
    }

    return NULL;
}

/**
 * @brief Finds role settings, given an interface name.
 *
 * @param settings The ztp settings structure to search.
 * @param interface The name of the interface to lookup settings for.
 * @return struct ztp_device_role_settings*
 */
struct ztp_device_role_settings *
ztp_settings_find_device_role_settings(const struct ztp_settings *settings, const char *interface)
{
    struct ztp_device_role_settings_entry *entry = ztp_settings_find_device_role_settings_entry(settings, interface);
    if (entry)
        return &entry->settings;

    return NULL;
}

/**
 * @brief Uninitialize an interface settings entry.
 *
 * @param entry The interface settings entry to uninitialize.
 */
static void
ztp_device_role_settings_entry_uninitialize(struct ztp_device_role_settings_entry *entry)
{
    ztp_device_role_settings_uninitialize(&entry->settings);
    list_del(&entry->list);
}

/**
 * @brief Adds a new interface settings entry to ztpd.
 *
 * @param ztpd The global ztpd instance.
 * @param entry The entry to add.
 */
static void
ztp_settings_add_device_role_settings(struct ztp_settings *settings, struct ztp_device_role_settings_entry *entry)
{
    struct ztp_device_role_settings_entry *existing = ztp_settings_find_device_role_settings_entry(settings, entry->settings.interface);
    if (existing) {
        ztp_device_role_settings_entry_uninitialize(existing);
        free(existing);
    }

    list_add(&entry->list, &settings->role_settings);
}

/**
 * @brief Function to parse each "ui.activation.gpio" configuration option
 * object entry.
 *
 * @param parent The parent object.
 * @param name The name of the json entry.
 * @param jobj The json object for the entry.
 * @param context A pointer to a ztpd instance. Will be of type (struct ztpd *).
 */
static void
json_parse_ui_activation_gpio_entry(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct ztp_settings *settings = (struct ztp_settings *)context;

    if (strcmp(name, "chip") == 0) {
        if (!json_validate_object_type(name, jobj, json_type_string))
            return;
        const char *chip = json_object_get_string(jobj);
        settings->ui_activation_gpio_chip = strdup(chip);
    } else if (strcmp(name, "line") == 0) {
        json_type type = json_object_get_type(jobj);
        switch (type) {
            case json_type_string: {
                const char *line_name = json_object_get_string(jobj);
                settings->ui_activation_gpio_line_name = strdup(line_name);
                break;
            }
            case json_type_int: {
                int32_t line = json_object_get_int(jobj);
                settings->ui_activation_gpio_line = line;
                break;
            }
            default:
                return;
        }
    } else if (strcmp(name, "debounceDelay") == 0) {
        int32_t debounce_delay = json_object_get_int(jobj);
        settings->ui_activation_gpio_delay = debounce_delay;
    }
}

/**
 * @brief Functon to parse "ui.activation.gpio" configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json entry. Must be "ui.activation.gpio".
 * @param jobj The json object value for "ui.activation.gpio".
 * @param ztpd The global ztpd instance.
 */
static void
json_parse_ui_activation_gpio(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    json_for_each_object(jobj, json_parse_ui_activation_gpio_entry, context);
}

/**
 * @brief Functon to parse "ui.activation.unit" configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json entry. Must be "ui.activation.unit".
 * @param jobj The json object value for "ui.activation.unit".
 * @param ztpd The global ztpd instance.
 */
static void
json_parse_ui_activation_unit(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct ztp_settings *settings = (struct ztp_settings *)context;

    const char *ui_activation_unit = json_object_get_string(jobj);
    settings->ui_activation_unit = strdup(ui_activation_unit);
}

/**
 * @brief Function to parse "ui.activation" configuration option array entry.
 *
 * @param parent The parent object.
 * @param array The containing array object.
 * @param name The name of the parent object ("ui.activation").
 * @param jobj The array element value.
 * @param index The array element index.
 * @param type The type of the array element (json_type_string).
 * @param context The ztpd global instance.
 */
static void
json_parse_ui_activation_array_entry(struct json_object *parent, struct json_object *array, const char *name, struct json_object *jobj, uint32_t index, json_type type, void *context)
{
    __unused(parent);
    __unused(array);
    __unused(name);
    __unused(index);
    __unused(type);

    struct ztp_settings *settings = (struct ztp_settings *)context;

    const char *value = json_object_get_string(jobj);
    if (strcmp(value, "command") == 0) {
        settings->ui_activation_command = true;
    } else if (strcmp(value, "gpio") == 0) {
        settings->ui_activation_gpio = true;
    }
}

/**
 * @brief Json object key names for "device.roles" array and child objects.
 */
#define JSON_PROPERTY_NAME_DEVICE_ROLES "device.roles"
#define JSON_PROPERTY_NAME_DEVICE_ROLE_ROLE "role"
#define JSON_PROPERTY_NAME_DEVICE_ROLE_INTERFACE "interface"
#define JSON_PROPERTY_NAME_DEVICE_ROLE_SETTINGS_PATH "settingsPath"
#define JSON_PROPERTY_NAME_DEVICE_ROLE_ACTIVATION_UNIT "activationUnit"

/**
 * @brief Get the context for the string properties of the bootstrap info object.
 *
 * @param context The parent context. Must be of type struct dpp_bootstrap_info.
 * @param name The name of the child property to retrieve the context for.
 * @return void* The context for the child property with key 'name'.
 */
static void *
get_device_role_string_context(void *context, const char *name)
{
    struct ztp_device_role_settings *settings = (struct ztp_device_role_settings *)context;

    if (strcmp(name, JSON_PROPERTY_NAME_DEVICE_ROLE_INTERFACE) == 0) {
        return &settings->interface;
    } else if (strcmp(name, JSON_PROPERTY_NAME_DEVICE_ROLE_SETTINGS_PATH) == 0) {
        return &settings->path;
    } else if (strcmp(name, JSON_PROPERTY_NAME_DEVICE_ROLE_ACTIVATION_UNIT) == 0) {
        return &settings->activation_unit;
    } else {
        return NULL;
    }
}

/**
 * @brief Parses individual "role" property of a device role entry.
 *
 * @param parent The parent object.
 * @param name The name of the json entry. Must be "role".
 * @param jobj The json object value.
 * @param ztpd The ztp_device_role_settings instance to populate.
 */
static void
json_parse_device_role_rolestr(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct ztp_device_role_settings *settings = (struct ztp_device_role_settings *)context;

    const char *device_role = json_object_get_string(jobj);
    settings->role = dpp_device_role_parse(device_role);

    switch (settings->role) {
        case DPP_DEVICE_ROLE_ENROLLEE:
            ztp_enrollee_settings_initialize(&settings->enrollee);
            break;
        case DPP_DEVICE_ROLE_CONFIGURATOR:
            ztp_configurator_settings_initialize(&settings->configurator);
            break;
        default:
            break;
    }
}

/**
 * @brief Property map for enrollee bootstrap info configuration.
 */
static struct json_property_parser device_role_entry_properties[] = {
    {
        .name = JSON_PROPERTY_NAME_DEVICE_ROLE_ROLE,
        .type = json_type_string,
        .value = {
            json_parse_device_role_rolestr,
        },
    },
    {
        .name = JSON_PROPERTY_NAME_DEVICE_ROLE_INTERFACE,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_device_role_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_DEVICE_ROLE_SETTINGS_PATH,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_device_role_string_context,
    },
    {
        .name = JSON_PROPERTY_NAME_DEVICE_ROLE_ACTIVATION_UNIT,
        .type = json_type_string,
        .value = {
            json_parse_string_generic,
        },
        .get_context = get_device_role_string_context,
    },
};

/**
 * @brief Function to parse an "device.roles" json object.
 *
 * If a valid device role object was found, it is added to the passed in
 * ztp_settings structure. If settings already existed for the interface name
 * in question, they will be replaced by the newly parsed settings.
 *
 * @param parent The parent object.
 * @param array The containing array object.
 * @param name The name of the json entry.
 * @param jobj The json object value associated with the device role settings.
 * @param index The array index of the object.
 * @param type The type of the object.
 * @param context The struct ztp_settings object to populate.
 */
static void
json_parse_device_roles(struct json_object *parent, struct json_object *array, const char *name, struct json_object *jobj, uint32_t index, json_type type, void *context)
{
    __unused(parent);
    __unused(array);
    __unused(name);
    __unused(index);
    __unused(type);

    struct ztp_settings *settings = (struct ztp_settings *)context;
    struct ztp_device_role_settings_entry *entry = ztp_device_role_settings_entry_initialize();
    if (!entry)
        return;

    json_parse_object_s(jobj, device_role_entry_properties, &entry->settings);

    if (!entry->settings.interface) {
        zlog_warning("role settings entry missing interface name; ignoring");
        ztp_device_role_settings_entry_uninitialize(entry);
        free(entry);
        return;
    }

    ztp_settings_add_device_role_settings(settings, entry);
}

/**
 * @brief Function to parse "device.roles.exclusive" configuration option.
 *
 * @param parent The parent object.
 * @param name The name of the json entry. Must be "device.roles.exclusive".
 * @param jobj The json object value for "device.roles.exclusive".
 * @param ztpd The global ztpd instance.
 */
static void
json_parse_device_roles_exclusive(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct ztp_settings *settings = (struct ztp_settings *)context;

    bool exclusive = json_object_get_boolean(jobj);
    settings->dpp_roles_exclusive = exclusive;
}

/**
 * @brief Parses the "device.roles.activated" object (not the entries).
 * 
 * @param parent The parent object.
 * @param name The name, which will always be NULL.
 * @param jobj The array object.
 * @param context The array context.
 */
static void
json_parse_device_roles_activated(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);
    __unused(name);

    struct ztp_settings *settings = (struct ztp_settings *)context;

    if (settings->dpp_roles_activated_json == NULL) {
        settings->dpp_roles_activated_json = jobj;
        json_object_get(jobj);
    }
}

/**
 * @brief Parses individual "device.roles.activated" entries.
 *
 * @param parent The parent object.
 * @param array The containing array object.
 * @param name The name of the json object.
 * @param jobj The json object value.
 * @param index The index of the json value within the array.
 * @param context A pointer to the ztpd global instance. This must be of type 'struct ztpd'.
 */
static void
json_parse_device_roles_activated_entry(struct json_object *parent, struct json_object *array, const char *name, struct json_object *jobj, uint32_t index, json_type type, void *context)
{
    __unused(parent);
    __unused(array);
    __unused(name);
    __unused(index);
    __unused(type);

    struct ztp_settings *settings = (struct ztp_settings *)context;

    const char *rolestr = json_object_get_string(jobj);
    enum dpp_device_role role = dpp_device_role_parse(rolestr);

    if (role != DPP_DEVICE_ROLE_UNKNOWN)
        settings->dpp_roles_activated[role] = true;
}

/**
 * @brief Array of supported configuration file options.
 */
static struct json_property_parser ztp_config_properties[] = {
    {
        .name = "ui.activation",
        .type = json_type_array,
        .array = {
            json_parse_ui_activation_array_entry,
            json_type_string,
        },
    },
    {
        .name = "ui.activation.gpio",
        .type = json_type_object,
        .value = {
            json_parse_ui_activation_gpio,
        },
    },
    {
        .name = "ui.activation.unit",
        .type = json_type_string,
        .value = {
            json_parse_ui_activation_unit,
        },
    },
    {
        .name = "device.roles",
        .type = json_type_array,
        .array = {
            json_parse_device_roles,
            json_type_object,
        },
    },
    {
        .name = "device.roles.exclusive",
        .type = json_type_boolean,
        .value = {
            json_parse_device_roles_exclusive,
        },
    },
    {
        .name = "device.roles.activated",
        .type = json_type_array,
        .value = {
            json_parse_device_roles_activated,
        },
        .array = {
            json_parse_device_roles_activated_entry,
            json_type_string,
        },
    },
};

/**
 * @brief Creates and initializes a new ztp settings intance.
 * 
 * @param config_file The full path of the configuration file.
 * @return struct ztp_settings* A pointer to the settings object.
 */
static struct ztp_settings *
ztp_settings_create(const char *config_file)
{
    size_t config_file_length = strlen(config_file) + 1;
    struct ztp_settings *settings = malloc((sizeof *settings) * config_file_length);
    if (!settings) {
        zlog_error("failed to allocate memory for ztp settings");
        return NULL;
    }

    explicit_bzero(settings, sizeof *settings);
    INIT_LIST_HEAD(&settings->role_settings);
    INIT_LIST_HEAD(&settings->change_handlers);
    memcpy(settings->config_file, config_file, config_file_length);

    return settings;
}

/**
 * @brief Parses a ztp settings file.
 *
 * @param config_file The full path of the configuration file to parse.
 * @param psettings An output pointer to receive a parsed settings object. The
 * caller is responsible for calling ztp_settings_destroy on this object.
 * @return int
 */
int
ztp_settings_parse(const char *config_file, struct ztp_settings **psettings)
{
    struct ztp_settings *settings = ztp_settings_create(config_file);
    if (!settings) {
        zlog_error("failed to allocate memory for ztp settings");
        return -ENOMEM;
    }

    int ret = json_parse_file_s(config_file, ztp_config_properties, settings, &settings->json);
    if (ret < 0) {
        zlog_error("failed to parse ztp settings from %s (%d)", config_file, ret);
        goto fail;
    }

    struct ztp_device_role_settings_entry *entry;
    list_for_each_entry (entry, &settings->role_settings, list) {
        switch (entry->settings.role) {
            case DPP_DEVICE_ROLE_ENROLLEE:
                ret = ztp_enrollee_config_parse(entry->settings.path, &entry->settings.enrollee);
                break;
            case DPP_DEVICE_ROLE_CONFIGURATOR:
                ret = ztp_configurator_config_parse(entry->settings.path, &entry->settings.configurator);
                break;
            default:
                ret = -EINVAL;
                break;
        }

        if (ret < 0) {
            zlog_error("failed to parse '%s' settings from '%s' (%d)", dpp_device_role_str(entry->settings.role), entry->settings.path, ret);
            goto fail;
        }
    }

    *psettings = settings;
    ret = 0;
out:
    return ret;
fail:
    if (settings)
        ztp_settings_destroy(&settings);
    goto out;
}

/**
 * @brief Persists settings to file descriptor.
 * 
 * @param fd The file descriptor to write the settings to.
 * @param settings The settings to write to file.
 * @return int 0 if the settings were successfully written to file, non-zero otherwise.
 */
static int
ztp_settings_persist_fd(int fd, const struct ztp_settings *settings)
{
    static const int JSON_C_SERIALIZE_FLAGS = (0
        | JSON_C_TO_STRING_NOSLASHESCAPE // don't escape paths
        | JSON_C_TO_STRING_PRETTY        // make it look good
        | JSON_C_TO_STRING_SPACED        // minimize whitespace
        | JSON_C_TO_STRING_PRETTY_TAB    // use a full tab character
    );

    struct json_object *jsettings = settings->json;
    if (!jsettings) {
        zlog_error("serialized json settings not found");
        return -EINVAL;
    }

    int ret = json_object_to_fd(fd, jsettings, JSON_C_SERIALIZE_FLAGS);
    if (ret < 0) {
        zlog_error("failed to write settings to file descriptor (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief Macros to help defined the temporary path string for writing the
 * settings file.
 */
#define TMP_TEMPLATE_SUFFIX_STRING ".XXXXXX"

/**
 * @brief Persists ztp settings to file.
 * 
 * @param filename The filename to write the settings to.
 * @param settings The settings to write to file.
 * @return int 0 if the settings were successfully written to file, non-zero otherwise.
 */
int
ztp_settings_persist(const char *filename, const struct ztp_settings *settings)
{
    int ret;
    int fd = -1;

    char *filename_target = NULL;
    ret = get_link_target(filename, &filename_target);
    if (ret < 0) {
        zlog_error("failed to resolve ztp settings file '%s' link target (%d)", filename, ret);
        return ret;
    }

    if (filename_target)
        filename = filename_target;

    size_t filename_length = strlen(filename);
    char *pathtmp = malloc(filename_length + ARRAY_SIZE(TMP_TEMPLATE_SUFFIX_STRING));
    if (!pathtmp) {
        zlog_error("failed to allocate memory for temp configurator settings file path");
        ret = -ENOMEM;
        goto out;
    }

    memcpy(pathtmp, filename, filename_length);
    memcpy(pathtmp + filename_length, TMP_TEMPLATE_SUFFIX_STRING, ARRAY_SIZE(TMP_TEMPLATE_SUFFIX_STRING));

    fd = mkstemp(pathtmp);
    if (fd < 0) {
        ret = -errno;
        zlog_error("failed to create temporary file for ztp settings (%d)", ret);
        goto out;
    }

    ret = ztp_settings_persist_fd(fd, settings);
    if (ret < 0) {
        zlog_error("failed to write ztp settings to temporary file (%d)", ret);
        goto out;
    }

    fdatasync(fd);

    ret = rename(pathtmp, filename);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to move temporary settings file to target file (%d)", ret);
        goto out;
    }

    zlog_debug("ztp settings persisted to '%s'", filename);
out:
    if (fd != -1)
        close(fd);
    if (filename_target)
        free(filename_target);
    if (pathtmp)
        free(pathtmp);

    return ret;
}

/**
 * @brief Uninitialize ztpd daemon options.
 *
 * @param settings The options to uninitialize.
 */
void
ztp_settings_uninitialize(struct ztp_settings *settings)
{
    if (settings->ui_activation_gpio_chip) {
        free(settings->ui_activation_gpio_chip);
        settings->ui_activation_gpio_chip = NULL;
    }

    if (settings->ui_activation_gpio_line_name) {
        free(settings->ui_activation_gpio_line_name);
        settings->ui_activation_gpio_line_name = NULL;
    }

    if (settings->ui_activation_unit) {
        free(settings->ui_activation_unit);
        settings->ui_activation_unit = NULL;
    }

    if (settings->dpp_roles_activated_json) {
        json_object_put(settings->dpp_roles_activated_json);
        settings->dpp_roles_activated_json = NULL;
    }

    if (settings->json) {
        json_object_put(settings->json);
        settings->json = NULL;
    }

    struct ztp_device_role_settings_entry *entry;
    struct ztp_device_role_settings_entry *entrytmp;

    list_for_each_entry_safe (entry, entrytmp, &settings->role_settings, list) {
        ztp_device_role_settings_entry_uninitialize(entry);
        free(entry);
    }

    struct ztp_settings_changed_event_handler *change_handler;
    struct ztp_settings_changed_event_handler *change_handler_tmp;
    list_for_each_entry_safe (change_handler, change_handler_tmp, &settings->change_handlers, list) {
        ztp_settings_unregister_change_handler(settings, change_handler->callback, change_handler->context);
    }
}

/**
 * @brief Uninitializes and destroys a ztp settings instance.
 * 
 * @param settings A pointer to the settings instance to destroy. This function
 * will set the memory this references to NULL, so the pointer must not be
 * accessed following this call.
 */
void
ztp_settings_destroy(struct ztp_settings **settings)
{
    if (!settings || !*settings)
        return;

    ztp_settings_uninitialize(*settings);
    free(*settings);

    *settings = NULL;
}

/**
 * @brief Synchronizes the in-memory activated roles with those stored in the
 * json object. This is a one-way function which will replace anything that
 * currently exists in the json object.
 * 
 * @param settings The ztp settings.
 * @return int 0 if the json object associated with activated roles was
 * succcessfully updated to reflect the in-memory activated roles.
 */
static int
ztp_settings_role_disposition_synchronize_json(struct ztp_settings *settings)
{
    int ret;
    struct json_object *roles_activated = settings->dpp_roles_activated_json;

    size_t roles_activated_num = json_object_array_length(roles_activated);
    if (roles_activated_num > 0) {
        ret = json_object_array_del_idx(roles_activated, 0, roles_activated_num);
        if (ret < 0) {
            zlog_error("failed to clear activated roles json array (%d)", ret);
            return ret;
        }
    }

    for (size_t i = 0, index = 0; i < ARRAY_SIZE(settings->dpp_roles_activated); i++) {
        if (!settings->dpp_roles_activated[i])
            continue;

        const char *role = dpp_device_role_str((enum dpp_device_role)i);
        struct json_object *value = json_object_new_string(role);
        if (!value) {
            zlog_error("failed to allocate memory for device role string");
            return -ENOMEM;
        }

        ret = json_object_array_put_idx(roles_activated, index, value);
        if (ret < 0) {
            zlog_error("failed to add activated role to activated role json array (%d)", ret);
            json_object_put(value);
            return ret;
        }

        zlog_debug("device role '%s' added to activated json array", role);
        index++;
    }

    return 0;
}

/**
 * @brief Set the disposition of a role.
 * 
 * @param settings The settings instance to update.
 * @param role The role to set the disposition for.
 * @param activate The role disposition.
 * @return true If the role disposition was changed
 * @return false If the role disposition was not changed.
 */
static bool
set_role_disposition(struct ztp_settings *settings, enum dpp_device_role role, bool activate)
{
    if (settings->dpp_roles_activated[role] == activate)
        return false;

    const char *rolestr = dpp_device_role_str(role);
    settings->dpp_roles_activated[role] = activate;
    zlog_debug("role '%s' disposition set to '%s'", rolestr, activate ? "activated" : "deactivated");

    return true;
}

/**
 * @brief Sets the device role setting to activated or deactivated. Note that
 * this does not necessarily affect the functionality of any running daemon;
 * this only updates the setting.
 * 
 * If exclusive mode is set, and the new role disposition is to activate, then
 * the existing activated role (if one exists) will be changed to disabled.
 * 
 * @param settings The settings instance to update.
 * @param role The role to set the disposition for.
 * @param activate The role disposition.
 * @return int The number of roles that changed disposition successfully
 * updated, otherwise a negative value indicating the cause for the failure.
 */
int
ztp_settings_set_device_role_disposition(struct ztp_settings *settings, enum dpp_device_role role, bool activate)
{
    int num_role_changes = 0;

    if (set_role_disposition(settings, role, activate))
        num_role_changes++;

    if (settings->dpp_roles_exclusive) {
        enum dpp_device_role role_peer = dpp_device_role_peer(role);
        if (dpp_device_role_is_valid(role_peer)) {
            if (set_role_disposition(settings, role_peer, !activate))
                num_role_changes++;
        }
    }

    if (num_role_changes == 0)
        return 0;

    int ret = ztp_settings_role_disposition_synchronize_json(settings);
    if (ret < 0) {
        zlog_error("failed to synchronize role dispoition change with json settings (%d)", ret);
        return ret;
    }

    ret = ztp_settings_persist(settings->config_file, settings);
    if (ret < 0) {
        zlog_error("failed to persist updated ztp settings to file (%d)", ret);
        return ret;
    }

    ztp_settings_signal_changed(settings, ZTP_SETTING_CHANGED_ITEM_DEVICE_ROLES);
    return num_role_changes;
}
