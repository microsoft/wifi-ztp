
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "string_utils.h"

/**
 * @brief Decodes a single hex binary value.
 *
 * @param hex A pointer to the string to decode the next hex digit for.
 * @param skip The function used to determine if characters should be skipped.
 * @return int The value of the hex digit, if valid. Otherwise -1.
 */
static int
hex_decode_next(const char **hex, skip_fn skip)
{
    while (skip(**hex))
        (*hex)++;

    if (!**hex || !isxdigit(**hex))
        return -1;

    char c = *((*hex)++);
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/**
 * @brief Decodes a hex string into a raw buffer, skipping characters according
 * to a specified skip function.
 *
 * @param hex The hex string to decode.
 * @param buffer The buffer to write the binary output to.
 * @param length The length of 'buffer', in bytes.
 * @param skip The function used to determine if a character in the string should be skipped.
 * @return ssize_t The number of bytes written to 'buffer' if the string was
 * decoded successfully, -1 otherwise.
 */
ssize_t
hex_decode_withskip(const char *hex, uint8_t *buffer, size_t length, skip_fn skip)
{
    size_t length_original = length;

    for (;;) {
        if (!*hex)
            return (ssize_t)(length_original - length);

        int high = hex_decode_next(&hex, skip);
        int low  = hex_decode_next(&hex, skip);
        if (high == -1 || low == -1 || length == 0)
            return -1;

        *buffer++ = (uint8_t)(high << 4) | (uint8_t)low;
        length--;
    }
}

/**
 * @brief Decodes a hex string into a raw buffer, skipping whitespace.
 *
 * @param hex The hex string to decode.
 * @param buffer The buffer to write the binary output to.
 * @param length The length of 'buffer', in bytes.
 * @return ssize_t The number of bytes written to 'buffer' if the string was
 * decoded successfully, -1 otherwise.
 */
ssize_t
hex_decode(const char *hex, uint8_t *buffer, size_t length)
{
    return hex_decode_withskip(hex, buffer, length, isspace);
}

/**
 * @brief Encodes a byte array as a hex string.
 *
 * @param buffer The buffer to encode.
 * @param length The length, in bytes, of 'buffer'. Must be > 0.
 * @param dst The buffer to write the string.
 * @param dstlength The length, in bytes. of 'dst'.
 */
void
hex_encode(const uint8_t *buffer, size_t length, char *dst, size_t dstlength)
{
    assert(length > 0);
    assert(dstlength >= ((length * 2) + 1));

    const uint8_t *end = buffer + length;
    while (buffer < end) {
        snprintf(dst, dstlength, "%02x", *buffer++);
        dstlength -= 2;
        dst += 2;
    }

    *dst = '\0';
}

/**
 * @brief Function to skip common MAC address separators.
 *
 * @param c The character to check.
 * @return true If the character should be skipped.
 * @return false Otherwise.
 */
int
mac_skip(int c)
{
    switch (c) {
        case ':':
        case '-':
            return 1;
        default:
            return isspace(c);
    }
}

/**
 * @brief Determine if a string starts with a substring, providing a pointer to
 * the first character following the substring match.
 *
 * Eg.  s1 = "<10> DPP-RX_CHIRP src=0A:1B:2C:3D:4E:5F hash=..."
 *      s2 = "DPP-RX-CHIRP "
 *      strstart(s1, s2) -> true, *out = "src=0A:1B:2C:3D:4E:5F hash=..."
 *
 * @param s1 The string to check.
 * @param s2 The substring to find.
 * @param out The output string to hold the first character following the
 * occurrence of the substring in s1.
 * @return true
 * @return false
 */
bool
strstart(const char *s1, const char *s2, const char **out)
{
    size_t s2len = strlen(s2);
    if (strncmp(s1, s2, s2len) != 0)
        return false;

    *out = s1 + s2len;
    return true;
}
