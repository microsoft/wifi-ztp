
#ifndef __FILE_UTILS_H__
#define __FILE_UTILS_H__

/**
 * @brief Get the link target of a file.
 * 
 * @param filename The filename to get the link target for.
 * @param target An output argument holding the link target, if it exists.
 * Otherwise this will be set to NULL. 
 * @return int 0 if it was determined whether a link target exists and was
 * written to *target. If the file does not have a link target (eg. non
 * symbolic link), then *target will be set to NULL.
 */
int
get_link_target(const char *filename, char **target);

#endif //__FILE_UTILS_H__
