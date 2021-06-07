
#ifndef __DBUS_MESSAGE_HELPERS_H__
#define __DBUS_MESSAGE_HELPERS_H__

#include <stdint.h>

#include <systemd/sd-bus.h>

/**
 * @brief 
 */
typedef int (*dbus_append_obj_fn)(sd_bus_message *message, const void *value, void *value_context);

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
dbus_append_dict_entry(sd_bus_message *message, const char *key, const void *value, const char *contents, dbus_append_obj_fn append_value, void *value_context);

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_append_dict_entry_basic(sd_bus_message *message, char value_type, const char *key, const void *value);

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_append_dict_entry_string(sd_bus_message *message, const char *key, const char *value);

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
dbus_append_variant(sd_bus_message *message, const char *contents, const void *value, dbus_append_obj_fn append_value, void *value_context);

/**
 * @brief 
 * 
 * @param message 
 * @param value_type 
 * @param value 
 * @return int 
 */
int
dbus_append_variant_basic(sd_bus_message *message, char value_type, const void *value);

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
dbus_append_kv_pair(sd_bus_message *message, const char *key, const void *value, const char *contents, dbus_append_obj_fn append_value, void *value_context);

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_append_kv_pair_basic(sd_bus_message *message, char value_type, const char *key, const void *value);

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_append_kv_pair_string(sd_bus_message *message, const char *key, const char *value);

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
dbus_append_kv_pair_variant(sd_bus_message *message, const char *key, const void *value, const char *contents, dbus_append_obj_fn append_value, void *value_context);

/**
 * @brief 
 */
typedef int (*dbus_read_obj_fn)(sd_bus_message *message, void *value, void *value_context);

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
dbus_read_variant(sd_bus_message *message, const char *contents, void *value, dbus_read_obj_fn read_value, void *value_context);

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
dbus_read_dict_entry(sd_bus_message *message, const char *key, void *value, const char *contents, dbus_read_obj_fn read_value, void *value_context);

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
dbus_read_dict_entry_basic(sd_bus_message *message, char value_type, const char *key, void *value);

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
dbus_read_dict_entry_string(sd_bus_message *message, const char *key, const char **value);

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
dbus_read_kv_pair(sd_bus_message *message, const char *key, void *value, const char *contents, dbus_read_obj_fn read_value, void *value_context);

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_read_kv_pair_basic(sd_bus_message *message, char value_type, const char *key, void *value);

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_read_kv_pair_string(sd_bus_message *message, const char *key, const char **value);

/**
 * @brief 
 * 
 * @param message 
 * @param key 
 * @param value 
 * @return int 
 */
int
dbus_read_kv_pair_string_cp(sd_bus_message *message, const char *key, char **value);

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
dbus_read_kv_pair_variant(sd_bus_message *message, const char *key, void *value, const char *contents, dbus_read_obj_fn read_value, void *value_context);

#endif //__DBUS_MESSAGE_HELPERS_H__
