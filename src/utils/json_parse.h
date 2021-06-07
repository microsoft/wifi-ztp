
#ifndef __JSON_PARSE_H__
#define __JSON_PARSE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <json-c/json_object.h>
#include <userspace/linux/kernel.h>

/**
 * @brief Helper function to confirm two json types match, logging an error if not.
 *
 * @param name The name of the json object for which the type describes.
 * @param actual The actual type of the object.
 * @param expected The expected type of the object.
 * @return true If the types match.
 * @return false If the types differ.
 */
bool
json_validate_type(const char *name, json_type actual, json_type expected);

/**
 * @brief Helper function to confirm json type of object.
 *
 * @param name The name of the json object for which the json object describes.
 * @param jobj The json object to validate the type for.
 * @param expected The expected json type for the object.
 * @return true If the json object 'jobj' has actual type 'expected'.
 * @return false if the json object 'jobj' has actual type different than 'expected'.
 */
bool
json_validate_object_type(const char *name, struct json_object *jobj, json_type expected);

/**
 * @brief Helper function to confirm two json types of an array element match, logging an error if not.
 *
 * @param name The name of the json object for which the type describes.
 * @param index The index of the array element within its parent.
 * @param actual The actual type of the object.
 * @param expected The expected type of the object.
 * @return true If the types match.
 * @return false If the types differ.
 */
bool
json_validate_type_array_entry(const char *name, uint32_t index, json_type actual, json_type expected);

/**
 * @brief Macros to be returned by the visit functions to indicate whether iteration should stop or continue.
 */
#define JSON_ITERATE_CONTINUE 0
#define JSON_ITERATE_STOP 1

/**
 * @brief Prototypes for json entry handler function used in
 * json_for_each_object helper. The 'ss' version allows short-circuiting
 * iteration based on the return value of the visit function.
 */
typedef void (*json_object_visit_fn)(struct json_object *parent, const char *name, struct json_object *value, void *context);
typedef int (*json_object_visit_ss_fn)(struct json_object *parent, const char *name, struct json_object *value, void *context);

/**
 * @brief Helper function for processing all entries in a json object. Mostly
 * syntactic sugar around the clunky iterator interface.

 * @param jobj The json object to process.
 * @param visit The function to process each json object entry.
 * @param context The user supplied context data.
 */
void
json_for_each_object(struct json_object *jobj, json_object_visit_fn visit, void *context);

/**
 * @brief Helper function for processing all entries in a json object. Mostly
 * syntactic sugar around the clunky iterator interface.

 * @param jobj The json object to process.
 * @param visit The function to process each json object entry.
 * @param context The user supplied context data.
 */
void
json_for_each_object_ss(struct json_object *jobj, json_object_visit_ss_fn visit, void *context);

/**
 * @brief Prototype for json entry handler function used in
 * json_for_each_array_entry helper.
 */
typedef void (*json_array_visit_fn)(struct json_object *parent, struct json_object *array, const char *name, struct json_object *value, uint32_t index, json_type type, void *context);
typedef int (*json_array_visit_ss_fn)(struct json_object *parent, struct json_object *array, const char *name, struct json_object *value, uint32_t index, json_type type, void *context);

/**
 * @brief Helper function for processing all entries in a json array.
 *
 * @param parent The parent object.
 * @param array The json array object to process.
 * @param name The name of the key/object representing the array.
 * @param visit The function to process each json array entry.
 * @param context The user supplied context data.
 */
void
json_for_each_array_entry(struct json_object *parent, struct json_object *array, const char *name, json_array_visit_fn visit, void *context);

/**
 * @brief Helper function for processing all entries in a json array.
 *
 * @param parent The parent object.
 * @param array The json array object to process.
 * @param name The name of the key/object representing the array.
 * @param visit The function to process each json array entry.
 * @param context The user supplied context data.
 */
void
json_for_each_array_entry_ss(struct json_object *parent, struct json_object *array, const char *name, json_array_visit_ss_fn visit, void *context);

/**
 * @brief Visitor function used with json_for_each_array_type.
 *
 * @param parent The parent object.
 * @param array The json array object to process.
 * @param name The name of  the parent object.
 * @param value The value of the array entry with index 'index' of the parent (ie. parent[index]).
 * @param index The index of the value within the parent.
 * @param type The type of the array element value.
 * @param context The user-supplied context information.
 */
void
json_for_each_array_type_visitor(struct json_object *parent, struct json_object *array, const char *name, struct json_object *value, uint32_t index, json_type type, void *context);

/**
 * @brief Helper function for processing all entries in a json array. This also
 * provides strict type checking on each array element.

 * @param parent The parent object.
 * @param array The json object to process.
 * @param name The name of the parent json object.
 * @param visit The function to process each json array entry.
 * @param type_expected  The expected type of each array element.
 * @param context The user supplied context data.
 */
void
json_for_each_array_entry_type(struct json_object *parent, struct json_object *array, const char *name, json_type type_expected, json_array_visit_fn visit, void *context);

/**
 * @brief Function prototype for returning the property's context, given its parent context.
 */
typedef void *(*json_property_get_context_fn)(void *parent_context, const char *name);

/**
 * @brief JSON property parser.
 */
struct json_property_parser {
    const char *name;
    json_type type;
    struct {
        json_object_visit_fn parse;
    } value;
    struct {
        json_array_visit_fn parse;
        json_type type;
    } array;
    json_property_get_context_fn get_context;
};

/**
 * @brief Generic string parsing function.
 *
 * This function parses a json string and writes it to a destination pointer.
 * The destination must be provided as the context (type char**). If The
 * context holds an existing string, it will be deleted using free().
 *
 * @param name The name of the json property.
 * @param jobj The json object value.
 * @param context The destination where a copy of the string should be written.
 */
void
json_parse_string_generic(struct json_object *parent, const char *name, struct json_object *jobj, void *context);

/**
 * @brief Parses a json object and all of its properties.
 *
 * @param jobj The json object to parse.
 * @param parsers An array of parsers describing the supported properties.
 * @param parsers_num The number of parsers in the 'parsers' array.
 * @param context The user-supplied context to be passed to each parsing
 * function.
 */
void
json_parse_object(struct json_object *jobj, struct json_property_parser *parsers, size_t parsers_num, void *context);

/**
 * @brief Helper macro accepting a statically-sized parsers array.
 */
#define json_parse_object_s(_jobj, _parsers, _context) \
    json_parse_object((_jobj), (_parsers), ARRAY_SIZE((_parsers)), _context)

/**
 * @brief Parses a json-formatted file.
 *
 * @param file The path of the file to parse.
 * @param parsers An array of parses describing the supported properties.
 * @param parsers_num The number of parses in the 'parsers' array.
 * @param context The user-supplied context to be passed to each parsing
 * function.
 * @param json Output argument to hold the parsed json object. May be NULL.
 * @return int Returns 0 if parsing was successful, non-zero otherwise.
 */
int
json_parse_file(const char *file, struct json_property_parser *parsers, size_t parsers_num, void *context, struct json_object **json);

/**
 * @brief Helper macro accepting a statically-sized parsers array.
 */
#define json_parse_file_s(_file, _parsers, _context, _json) \
    json_parse_file((_file), (_parsers), ARRAY_SIZE((_parsers)), _context, _json)

#endif //__JSON_PARSE_H__
