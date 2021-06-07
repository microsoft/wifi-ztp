
#ifndef __DBUS_COMMON_H__
#define __DBUS_COMMON_H__

#define DBUS_GLOBAL_SERVICE "org.freedesktop.DBus"
#define DBUS_GLOBAL_NAME_OWNER_CHANGED "NameOwnerChanged"

#define DBUS_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define DBUS_PROPERTIES_METHOD_GETALL "GetAll"

/**
 * @brief Helper structure to manage metadata for reading string properties
 * from a d-bus dictionary.
 */
struct dbus_str_prop_desc {
    const char *name;
    char **dst;
};

/**
 * @brief Helper structure to manage metadata for reading array properties from
 * a d-bus dictionary
 */
struct dbus_array_prop_desc {
    const char *name;
    char type;
    size_t *count;
    size_t elem_size;
    void **dst;
};

#endif //__DBUS_COMMON_H__
