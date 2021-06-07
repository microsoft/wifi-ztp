
#include <stdio.h>
#include <stdlib.h>

#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_util.h>
#include <userspace/linux/compiler.h>
#include <userspace/linux/kernel.h>

#include "json_parse.h"
#include "ztp_log.h"

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
json_validate_type(const char *name, json_type actual, json_type expected)
{
    if (actual == expected)
        return true;

    zlog_debug("%s expected %s, got %s", name, json_type_to_name(expected), json_type_to_name(actual));
    return false;
}

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
json_validate_object_type(const char *name, struct json_object *jobj, json_type expected)
{
    return json_validate_type(name, json_object_get_type(jobj), expected);
}

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
json_validate_type_array_entry(const char *name, uint32_t index, json_type actual, json_type expected)
{
    if (actual == expected)
        return true;

    zlog_debug("%s[%u] expected %s, got %s", name, index, json_type_to_name(expected), json_type_to_name(actual));
    return false;
}

/**
 * @brief Context used for automatically continuing object iteration.
 */
struct json_object_visit_continue_context {
    void *context;
    json_object_visit_fn visit;
};

/**
 * @brief Convenience visitor function for json_for_each_object that continues
 * following each iteration. This is suitable when all properties need to be
 * enumerated with no stopping condition.
 *
 * @param parent The parent object.
 * @param name The name of the property associated with the object.
 * @param jobj The json object to iterate over.
 * @param context Context pointer. This must be of type struct
 * json_object_visit_continue_context, which contains the outer/child context
 * that will be supplied to the visit function.
 * @return int
 */
static int
json_object_visit_continue(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    struct json_object_visit_continue_context *child = (struct json_object_visit_continue_context *)context;
    child->visit(parent, name, jobj, child->context);
    return JSON_ITERATE_CONTINUE;
}

/**
 * @brief Helper function for processing all entries in a json object. Mostly
 * syntactic sugar around the clunky iterator interface.

 * @param jobj The json object to process.
 * @param visit The function to process each json object entry.
 * @param context The user supplied context data.
 */
void
json_for_each_object_ss(struct json_object *jobj, json_object_visit_ss_fn visit, void *context)
{
    struct json_object_iterator it = json_object_iter_begin(jobj);
    struct json_object_iterator end = json_object_iter_end(jobj);

    while (!json_object_iter_equal(&it, &end)) {
        int ret = visit(jobj, json_object_iter_peek_name(&it), json_object_iter_peek_value(&it), context);
        if (ret != JSON_ITERATE_CONTINUE)
            break;
        json_object_iter_next(&it);
    }
}

/**
 * @brief Helper function for processing all entries in a json object. Mostly
 * syntactic sugar around the clunky iterator interface.

 * @param jobj The json object to process.
 * @param visit The function to process each json object entry.
 * @param context The user supplied context data.
 */
void
json_for_each_object(struct json_object *jobj, json_object_visit_fn visit, void *context)
{
    struct json_object_visit_continue_context parent_context = {
        .visit = visit,
        .context = context,
    };

    json_for_each_object_ss(jobj, json_object_visit_continue, &parent_context);
}

/**
 * @brief Context used for automatically continuing array iteration.
 */
struct json_array_visit_continue_context {
    void *context;
    json_array_visit_fn visit;
};

/**
 * @brief Convenience visitor function for json_for_each_array that continues
 * following each iteration. This is suitable when all array entires need to be
 * iterated over with no stopping function.
 *
 * @param parent The parent object.
 * @param array The containing json array.
 * @param name The name of the parent object.
 * @param value The current array object value.
 * @param index The current array index.
 * @param type The type of the object value.
 * @param context Context pointer. This must be of type struct
 * json_array_visit_continue_context, which contains the outer/child context
 * that will be supplied to the visit function
 */
int
json_array_visit_continue(struct json_object *parent, struct json_object *array, const char *name, struct json_object *value, uint32_t index, json_type type, void *context)
{
    struct json_array_visit_continue_context *child = (struct json_array_visit_continue_context *)context;
    child->visit(parent, array, name, value, index, type, child->context);
    return JSON_ITERATE_CONTINUE;
}

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
json_for_each_array_entry_ss(struct json_object *parent, struct json_object *array, const char *name, json_array_visit_ss_fn visit, void *context)
{
    size_t num_entries = json_object_array_length(array);
    if (num_entries == 0)
        return;

    for (uint32_t i = 0; i < num_entries; i++) {
        struct json_object *element = json_object_array_get_idx(array, i);
        json_type type = json_object_get_type(element);
        int ret = visit(parent, array, name, element, i, type, context);
        if (ret != JSON_ITERATE_CONTINUE)
            break;
    }
}

/**
 * @brief Helper function for processing all entries in a json array.
 *
 * @param parent The parent object.
 * @param array The json object to process.
 * @param name The name of the key/object representing the array.
 * @param visit The function to process each json array entry.
 * @param context The user supplied context data.
 */
void
json_for_each_array_entry(struct json_object *parent, struct json_object *array, const char *name, json_array_visit_fn visit, void *context)
{
    struct json_array_visit_continue_context parent_context = {
        .visit = visit,
        .context = context,
    };

    json_for_each_array_entry_ss(parent, array, name, json_array_visit_continue, &parent_context);
}

/**
 * @brief Context used for processing each array entry with
 * json_for_each_array_type_visitor.
 */
struct json_for_each_array_type_context {
    json_type type_expected;
    json_array_visit_fn visit;
    void *visit_context;
};

/**
 * @brief Visitor function used with json_for_each_array_type.
 *
 * @param parent The parent object.
 * @param array The containing array object.
 * @param name The name of  the parent object.
 * @param value The value of the array entry with index 'index' of the parent (ie. parent[index]).
 * @param index The index of the value within the parent.
 * @param type The type of the array element value.
 * @param context The user-supplied context information.
 */
void
json_for_each_array_type_visitor(struct json_object *parent, struct json_object *array, const char *name, struct json_object *value, uint32_t index, json_type type, void *context)
{
    struct json_for_each_array_type_context *array_context = (struct json_for_each_array_type_context *)context;

    if (!json_validate_type_array_entry(name, index, type, array_context->type_expected))
        return;

    array_context->visit(parent, array, name, value, index, type, array_context->visit_context);
}

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
json_for_each_array_entry_type(struct json_object *parent, struct json_object *array, const char *name, json_type type_expected, json_array_visit_fn visit, void *context)
{
    struct json_for_each_array_type_context array_context = {
        .type_expected = type_expected,
        .visit = visit,
        .visit_context = context,
    };

    json_for_each_array_entry(parent, array, name, json_for_each_array_type_visitor, &array_context);
}

/**
 * @brief Generic string parsing function.
 *
 * This function parses a json string and writes it to a destination pointer.
 * The destination must be provided as the context (type char**). If The
 * context holds an existing string, it will be deleted using free().
 *
 * @param parent The parent object.
 * @param name The name of the json property.
 * @param jobj The json object value.
 * @param context The destination where a copy of the string should be written.
 */
void
json_parse_string_generic(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    __unused(parent);

    char *value = strdup(json_object_get_string(jobj));
    if (!value) {
        zlog_warning("allocation failure parsing string property '%s'", name);
        return;
    }

    char **destination = (char **)context;
    if (*destination)
        free(*destination);

    *destination = value;
}

/**
 * @brief Helper structure used for parsing arbitrary json values. This allows
 * passing parsing-specific context, along with user-supplied context to
 * parsers.
 */
struct json_parse_property_opts {
    struct json_property_parser *parsers;
    size_t count;
    void *context;
};

/**
 * @brief Returns the child property context, given the parent property context.
 *
 * @param parser The parsing configuration for the property.
 * @param parent_context The parent object context.
 * @return void* The child's context object.
 */
static void *
json_get_child_context(struct json_property_parser *parser, void *parent_context)
{
    return parser->get_context
        ? parser->get_context(parent_context, parser->name)
        : parent_context;
}

/**
 * @brief Handler function to parse a json property of an object.
 *
 * @param parent The parent object.
 * @param name The name of the json property being parsed.
 * @param jobj The value of the json property being parsed.
 * @param context The context for the property being parsed. This must be an
 * instance of type 'struct json_parse_property_opts *' which describes all of
 * the supported properties and their parsers.
 */
static void
json_parse_property(struct json_object *parent, const char *name, struct json_object *jobj, void *context)
{
    struct json_parse_property_opts *properties = (struct json_parse_property_opts *)context;

    for (size_t i = 0; i < properties->count; i++) {
        struct json_property_parser *property = &properties->parsers[i];
        if (strcmp(name, property->name) != 0)
            continue;

        if (!json_validate_object_type(name, jobj, property->type))
            continue;

        void *context_child = json_get_child_context(property, properties->context);

        json_type type = json_object_get_type(jobj);
        switch (type) {
            case json_type_array:
                if (property->array.parse)
                    json_for_each_array_entry_type(parent, jobj, name, property->array.type, property->array.parse, context_child);
                // fall-through to value parser since array entries can have both.
                // fallthrough
            default:
                if (property->value.parse)
                    property->value.parse(parent, name, jobj, context_child);
                break;
        }
    }
}

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
json_parse_object(struct json_object *jobj, struct json_property_parser *parsers, size_t parsers_num, void *context)
{
    struct json_parse_property_opts opts = {
        .parsers = parsers,
        .count = parsers_num,
        .context = context,
    };

    json_for_each_object(jobj, json_parse_property, &opts);
}

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
json_parse_file(const char *file, struct json_property_parser *parsers, size_t parsers_num, void *context, struct json_object **json)
{
    zlog_debug("parsing %s", file);

    struct json_object *jobj = json_object_from_file(file);
    if (!jobj) {
        const char *err = json_util_get_last_err();
        zlog_error("parsing %s failed (%s)", file, err);
        return -1;
    }

    json_parse_object(jobj, parsers, parsers_num, context);

    if (json) {
        *json = jobj;
    } else {
        json_object_put(jobj);
    }

    return 0;
}
