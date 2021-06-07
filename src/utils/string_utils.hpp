
#ifndef __STRING_UTILS_HPP__
#define __STRING_UTILS_HPP__

#include <algorithm>
#include <cctype>
#include <string>

/**
 * @brief Helper unary predicate function which uses 'unsigned char' as the
 * input, as is required by std::isspace.
 * 
 * @param c The value to determine whether it is a character.
 * @return true If the value is a character.
 * @return false Otherwise.
 */
static inline bool
is_not_space(unsigned char c)
{
    return !std::isspace(c);
}

/**
 * @brief Trims leading whitespace from a string in-place.
 * 
 * @param input The string to trim leading whitespace from.
 */
static inline void
triml(std::string& input)
{
    input.erase(input.begin(), std::find_if(input.begin(), input.end(), is_not_space));
}

/**
 * @brief Trims trailing whitespace from a string in-place.
 * 
 * @param input The string to trim trailing whitespace from.
 */
static inline void
trimt(std::string& input)
{
    input.erase(std::find_if(input.rbegin(), input.rend(), is_not_space).base(), input.end());
}

/**
 * @brief Trims leading and trailing whitespace from a string in-place.
 * 
 * @param input The string to trim leading and trailing whitespace from.
 */
static inline void
trim(std::string& input)
{
    triml(input);
    trimt(input);
}

/**
 * @brief Trims leading space from a string, and returns a copy. Note that since
 * the argument ('input') is passed by value, the original string is copied and
 * hence, not modified.
 * 
 * @param input The string to trim leading whitespace from.
 * @return std::string A new string with leading whitespace removed.
 */
static inline std::string
triml_copy(std::string input)
{
    triml(input);
    return input;
}

/**
 * @brief Trims trailing space from a string, and returns a copy. Note that since
 * the argument ('input') is passed by value, the original string is copied and
 * hence, not modified.
 * 
 * @param input The string to trim trailing whitespace from.
 * @return std::string A new string with trailing whitespace removed.
 */
static inline std::string
trimt_copy(std::string input)
{
    trimt(input);
    return input;
}

/**
 * @brief Trims leading and trailing space from a string, and returns a copy.
 * Note that since the argument ('input') is passed by value, the original
 * string is copied and hence, not modified.
 * 
 * @param input The string to trim leading and trailing whitespace from.
 * @return std::string A new string with leading and trailing whitespace removed.
 */
static inline std::string
trim_copy(std::string input)
{
    trim(input);
    return input;
}

#endif //  __STRING_UTILS_HPP__
