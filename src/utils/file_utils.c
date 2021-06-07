
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "file_utils.h"
#include "ztp_log.h"

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
get_link_target(const char *filename, char **target)
{
    ssize_t len;
    char *path = NULL;
    struct stat statbuf;

    int ret = lstat(filename, &statbuf);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to lstat file '%s' (%d)", filename, ret);
        goto fail;
    } else if (!S_ISLNK(statbuf.st_mode)) {
        goto out;
    } else if (statbuf.st_size < 0) {
        zlog_error("link size (st_size) for file '%s' is invalid (< 0)", filename);
        ret = -EINVAL;
        goto out;
    }

    size_t path_length = (size_t)statbuf.st_size;

    path = (char *)malloc(path_length + 1);
    if (!path) {
        zlog_error("failed to allocate memory for file '%s' link target", filename);
        ret = -ENOMEM;
        goto fail;
    }

    len = readlink(filename, path, path_length + 1);
    if (len < 0) {
        ret = -errno;
        zlog_error("failed to obtain file '%s' link target (%d)", filename, ret);
        goto fail;
    } else if ((size_t)len > path_length) {
        zlog_error("file '%s' link target changed", filename);
        ret = -EBUSY;
        goto fail;
    }

    path[len] = '\0';
    ret = 0;
out:
    *target = path;
    return ret;
fail:
    if (path) {
        free(path);
        path = NULL;
    }
    goto out;
}
