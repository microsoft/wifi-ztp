
#ifndef __STRING_UTILS_H__
#define __STRING_UTILS_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * @brief Function signature for checking if a character should be skipped.
 */
typedef int (*skip_fn)(int);

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
hex_decode_withskip(const char *hex, uint8_t *buffer, size_t length, skip_fn skip);

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
hex_decode(const char *hex, uint8_t *buffer, size_t length);

/**
 * @brief Encodes a byte array as a hex string.
 *
 * @param buffer The buffer to encode.
 * @param length The length, in bytes, of 'buffer'.
 * @param dst The buffer to write the string.
 * @param dstlength The length, in bytes. of 'dst'.
 */
void
hex_encode(const uint8_t *buffer, size_t length, char *dst, size_t dstlength);

/**
 * @brief Function to skip common MAC address separators.
 *
 * @param c The character to check.
 * @return true If the character should be skipped.
 * @return false Otherwise.
 */
int
mac_skip(int c);

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
strstart(const char *s1, const char *s2, const char **out);

#endif //__STRING_UTILS_H__
