
#include <errno.h>
#include <stdio.h>

#include "dbus_message_helpers.h"
#include "ztp_log.h"

/**
 * @brief 
 * 
 * @param message 
 * @param contents 
 * @param value 
 * @param read_value 
 * @param value_context 
 * @return int 
 */
int
dbus_read_variant(sd_bus_message *message, const char *contents, void *value, dbus_read_obj_fn read_value, void *value_context)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_VARIANT, contents);
    if (ret < 0) {
        zlog_error("failed to enter variant container (%d)", ret);
        return ret;
    }

    {
        ret = read_value(message, value, value_context);
        if (ret < 0) {
            zlog_error("failed to read variant value (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error("failed to exit variant container (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param message 
 * @param contents 
 * @param value 
 * @param append_value 
 * @param value_context 
 * @return int 
 */
int
dbus_append_variant(sd_bus_message *message, const char *contents, const void *value, dbus_append_obj_fn append_value, void *value_context)
{
    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_VARIANT, contents);
    if (ret < 0) {
        zlog_error("failed to open variant container (%d)", ret);
        return ret;
    }

    {
        ret = append_value(message, value, value_context);
        if (ret < 0) {
            zlog_error("failed to append variant value (%d)", ret);
            return ret;
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_error("failed to close variant container (%d)", ret);
        return ret;
    }

    return 0;
}

struct dbus_append_value_basic_context {
    char value_type;
};

/**
 * @brief 
 * 
 * @param message 
 * @param value 
 * @param contextp 
 * @return int 
 */
static int
dbus_append_value_basic(sd_bus_message *message, const void *value, void *contextp)
{
    struct dbus_append_value_basic_context *context = (struct dbus_append_value_basic_context *)contextp;

    int ret = sd_bus_message_append_basic(message, context->value_type, value);
    if (ret < 0) {
        zlog_error("failed to append value of type '%c' to message (%d)", context->value_type, ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param message 
 * @param value_type 
 * @param value 
 * @return int 
 */
int
dbus_append_variant_basic(sd_bus_message *message, char value_type, const void *value)
{
    struct dbus_append_value_basic_context context = {
        .value_type = value_type,
    };

    char contents[16];
    int ret = snprintf(contents, sizeof contents, "%c", value_type);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to format variant value type '%c' (%d)", value_type, ret);
        return ret;
    } else if ((size_t)ret > sizeof contents) {
        zlog_error("invalid variant value type '%c' specified", value_type);
        return -EINVAL;
    }

    return dbus_append_variant(message, contents, value, dbus_append_value_basic, &context);
}

struct dbus_append_value_variant_context {
    const char *contents;
    dbus_append_obj_fn append_value;
    void *append_value_context;
};

static int
dbus_append_value_variant(sd_bus_message *message, const void *value, void *contextp)
{
    struct dbus_append_value_variant_context *context = (struct dbus_append_value_variant_context *)contextp;

    int ret = dbus_append_variant(message, context->contents, value, context->append_value, context->append_value_context);
    if (ret < 0) {
        zlog_error("failed to append variant value (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param append_value 
 * @param value_context 
 * @return int 
 */
int
dbus_append_dict_entry(sd_bus_message *message, const char *key, const void *value, const char *contents, dbus_append_obj_fn append_value, void *value_context)
{
    int ret = sd_bus_message_open_container(message, SD_BUS_TYPE_DICT_ENTRY, "sv");
    if (ret < 0) {
        zlog_error("failed to open dictionary entry container with key %s (%d)", key, ret);
        return ret;
    }

    {
        ret = sd_bus_message_append_basic(message, SD_BUS_TYPE_STRING, key);
        if (ret < 0) {
            zlog_error("failed to append dictionary entry with key %s (%d)", key, ret);
            return ret;
        }

        ret = dbus_append_variant(message, contents, value, append_value, value_context);
        if (ret < 0) {
            zlog_error("failed to append variant value to dictionary entry with key %s (%d)", key, ret);
            return ret;
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_error("failed to close dictionary entry container with key %s (%d)", key, ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_append_dict_entry_basic(sd_bus_message *message, char value_type, const char *key, const void *value)
{
    struct dbus_append_value_basic_context context = {
        .value_type = value_type,
    };

    char contents[16];
    int ret = snprintf(contents, sizeof contents, "%c", value_type);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to format dictionary entry value type '%c' (%d)", value_type, ret);
        return ret;
    } else if ((size_t)ret > sizeof contents) {
        zlog_error("invalid dictionary entry value type '%c' specified", value_type);
        return -EINVAL;
    }

    return dbus_append_dict_entry(message, key, value, contents, dbus_append_value_basic, &context);
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_append_dict_entry_string(sd_bus_message *message, const char *key, const char *value)
{
    return dbus_append_dict_entry_basic(message, SD_BUS_TYPE_STRING, key, value);
}

struct dbus_read_value_basic_context {
    char value_type;
};

/**
 * @brief 
 * 
 * @param message 
 * @param value 
 * @param contextp 
 * @return int 
 */
static int
dbus_read_value_basic(sd_bus_message *message, void *value, void *contextp)
{
    struct dbus_read_value_basic_context *context = (struct dbus_read_value_basic_context *)contextp;

    int ret = sd_bus_message_read_basic(message, context->value_type, value);
    if (ret < 0) {
        zlog_error("failed to read value of type '%c' from message (%d)", context->value_type, ret);
        return ret;
    }

    return 0;
}

struct dbus_read_value_variant_context {
    const char *contents;
    dbus_read_obj_fn read_value;
    void *read_value_context;
};

/**
 * @brief 
 * 
 * @param message 
 * @param value 
 * @param contextp 
 * @return int 
 */
static int
dbus_read_value_variant(sd_bus_message *message, void *value, void *contextp)
{
    struct dbus_read_value_variant_context *context = (struct dbus_read_value_variant_context *)contextp;

    int ret = dbus_read_variant(message, context->contents, value, context->read_value, context->read_value_context);
    if (ret < 0) {
        zlog_error("failed to read variant value (%d)", ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @param contents 
 * @param read_value 
 * @param value_context 
 * @return int 
 */
int
dbus_read_dict_entry(sd_bus_message *message, const char *key, void *value, const char *contents, dbus_read_obj_fn read_value, void *value_context)
{
    int ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_DICT_ENTRY, "sv");
    if (ret < 0) {
        zlog_error("failed to enter dictionary entry container with key %s (%d)", key, ret);
        return ret;
    }

    {
        const char *key_read;
        ret = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &key_read);
        if (ret < 0) {
            zlog_error("failed to read dictionary entry key %s (%d)", key, ret);
            return ret;
        } else if (!key_read || strcmp(key_read, key) != 0) {
            zlog_error("dictionary entry key mismatch, got %s, expected %s", key_read, key);
            return -EINVAL;
        }

        ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_VARIANT, contents);
        if (ret < 0) {
            zlog_error("failed to enter variant container for dictionary entry with key %s (%d)", key, ret);
            return ret;
        }

        {
            ret = read_value(message, value, value_context);
            if (ret < 0) {
                zlog_error("failed to read value from dictionary entry with key %s (%d)", key, ret);
                return ret;
            }
        }

        ret = sd_bus_message_exit_container(message);
        if (ret < 0) {
            zlog_error("failed to exit variant container for dictionary entry with key %s (%d)", key, ret);
            return ret;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error("failed to exit dictionary entry container with key %s (%d)", key, ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param message 
 * @param value_type 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_read_dict_entry_basic(sd_bus_message *message, char value_type, const char *key, void *value)
{
    struct dbus_read_value_basic_context context = {
        .value_type = value_type,
    };

    char contents[16];
    int ret = snprintf(contents, sizeof contents, "%c", value_type);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to format dictionary entry value type '%c' (%d)", value_type, ret);
        return ret;
    } else if ((size_t)ret > sizeof contents) {
        zlog_error("invalid dictionary entry value type '%c' specified", value_type);
        return -EINVAL;
    }

    return dbus_read_dict_entry(message, key, value, contents, dbus_read_value_basic, &context);
}

/**
 * @brief 
 * 
 * @param message 
 * @param value_type 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_read_dict_entry_string(sd_bus_message *message, const char *key, const char **value)
{
    return dbus_read_dict_entry_basic(message, SD_BUS_TYPE_STRING, key, value);
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param contents 
 * @param append_value 
 * @param value_context 
 * @return int 
 */
int
dbus_append_kv_pair(sd_bus_message *message, const char *key, const void *value, const char *contents, dbus_append_obj_fn append_value, void *value_context)
{
    char value_contents[64];
    int ret = snprintf(value_contents, sizeof value_contents, "s%s", contents);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to format key-value contents (%d)", ret);
        return ret;
    } else if ((size_t)ret > sizeof value_contents) {
        zlog_error("key-value contents too big");
        return -ERANGE;
    }

    ret = sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, value_contents);
    if (ret < 0) {
        zlog_error("failed to open struct container with key %s (%d)", key, ret);
        return ret;
    }

    {
        ret = sd_bus_message_append_basic(message, SD_BUS_TYPE_STRING, key);
        if (ret < 0) {
            zlog_error("failed to append dictionary entry with key %s (%d)", key, ret);
            return ret;
        }

        ret = append_value(message, value, value_context);
        if (ret < 0) {
            zlog_error("failed to append value to struct container with key %s (%d)", key, ret);
            return ret;
        }
    }

    ret = sd_bus_message_close_container(message);
    if (ret < 0) {
        zlog_error("failed to close struct container with key %s (%d)", key, ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_append_kv_pair_basic(sd_bus_message *message, char value_type, const char *key, const void *value)
{
    struct dbus_append_value_basic_context context = {
        .value_type = value_type,
    };

    char contents[16];
    int ret = snprintf(contents, sizeof contents, "%c", value_type);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to format struct entry value type '%c' (%d)", value_type, ret);
        return ret;
    } else if ((size_t)ret > sizeof contents) {
        zlog_error("invalid struct entry value type '%c' specified", value_type);
        return -EINVAL;
    }

    return dbus_append_kv_pair(message, key, value, contents, dbus_append_value_basic, &context);
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_append_kv_pair_string(sd_bus_message *message, const char *key, const char *value)
{
    return dbus_append_kv_pair_basic(message, SD_BUS_TYPE_STRING, key, value);
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @param contents 
 * @param append_value 
 * @param value_context 
 * @return int 
 */
int
dbus_append_kv_pair_variant(sd_bus_message *message, const char *key, const void *value, const char *contents, dbus_append_obj_fn append_value, void *value_context)
{
    struct dbus_append_value_variant_context context = {
        .contents = contents,
        .append_value = append_value,
        .append_value_context = value_context,
    };

    return dbus_append_kv_pair(message, key, value, "v", dbus_append_value_variant, &context);
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @param contents 
 * @param read_value 
 * @param value_context 
 * @return int 
 */
int
dbus_read_kv_pair(sd_bus_message *message, const char *key, void *value, const char *contents, dbus_read_obj_fn read_value, void *value_context)
{
    char value_contents[64];
    int ret = snprintf(value_contents, sizeof value_contents, "s%s", contents);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to format key-value contents (%d)", ret);
        return ret;
    } else if ((size_t)ret > sizeof value_contents) {
        zlog_error("key-value contents too big");
        return -ERANGE;
    }

    ret = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, value_contents);
    if (ret < 0) {
        zlog_error("failed to enter struct container with key %s (%d)", key, ret);
        return ret;
    }

    {
        const char *key_read;
        ret = sd_bus_message_read_basic(message, SD_BUS_TYPE_STRING, &key_read);
        if (ret < 0) {
            zlog_error("failed to read dictionary entry with key %s (%d)", key, ret);
            return ret;
        } else if (!key_read || strcmp(key_read, key) != 0) {
            zlog_error("struct key mismatch, got %s, expected %s", key_read, key);
            return -EINVAL;
        }

        ret = read_value(message, value, value_context);
        if (ret < 0) {
            zlog_error("failed to read value from struct with key %s (%d)", key, ret);
            return ret;
        }
    }

    ret = sd_bus_message_exit_container(message);
    if (ret < 0) {
        zlog_error("failed to exit struct with key %s (%d)", key, ret);
        return ret;
    }

    return 0;
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_read_kv_pair_basic(sd_bus_message *message, char value_type, const char *key, void *value)
{
    struct dbus_read_value_basic_context context = {
        .value_type = value_type,
    };

    char contents[16];
    int ret = snprintf(contents, sizeof contents, "%c", value_type);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to format struct entry value type '%c' (%d)", value_type, ret);
        return ret;
    } else if ((size_t)ret > sizeof contents) {
        zlog_error("invalid struct entry value type '%c' specified", value_type);
        return -EINVAL;
    }

    return dbus_read_kv_pair(message, key, value, contents, dbus_read_value_basic, &context);
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_read_kv_pair_string(sd_bus_message *message, const char *key, const char **value)
{
    return dbus_read_kv_pair_basic(message, SD_BUS_TYPE_STRING, key, value);
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_read_kv_pair_string_cp(sd_bus_message *message, const char *key, char **value)
{
    const char *valuetmp = NULL;

    int ret = dbus_read_kv_pair_string(message, key, &valuetmp);
    if (ret == 0) {
        *value = strdup(valuetmp);
        if (!*value) {
            zlog_error("failed to allocate memory for kv pair with key %s string copy", key);
            return -ENOMEM;
        }
    }

    return ret;
}

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @param contents 
 * @param append_value 
 * @param value_context 
 * @return int 
 */
int
dbus_read_kv_pair_variant(sd_bus_message *message, const char *key, void *value, const char *contents, dbus_read_obj_fn read_value, void *value_context)
{
    struct dbus_read_value_variant_context context = {
        .contents = contents,
        .read_value = read_value,
        .read_value_context = value_context,
    };

    return dbus_read_kv_pair(message, key, value, "v", dbus_read_value_variant, &context);
}
