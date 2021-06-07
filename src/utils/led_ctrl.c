
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "led_ctrl.h"
#include "ztp_log.h"

/**
 * @brief Destroys an led_ctrl object, freeing all owned resources.
 * 
 * @param led The led control object to destroy.
 */
void
led_ctrl_destroy(struct led_ctrl *led)
{
    led_ctrl_set_off(led);

    if (led->fd_pattern != -1) {
        close(led->fd_pattern);
        led->fd_pattern = -1;
    }

    if (led->fd_repeat != -1) {
        close(led->fd_repeat);
        led->fd_repeat = -1;
    }

    free(led);
}

/**
 * @brief Path prefix for all sysfs-based led nodes.
 */
#define LED_SYSFS_PATH_PREFIX "/sys/class/leds/"

/**
 * @brief Value for the pattern trigger.
 */
#define LED_TRIGGER_PATTERN "pattern"

/**
 * @brief Creates a new led control object. This can be used to perform various
 * common tasks controlling an LED.
 * 
 * @param node The sysfs node name of the led. Eg. /sys/class/leds/<nodename>
 * @param led_ctrl Output argument to hold to allocated control object.
 * @return int 0 if the control object was successfully created, non-zero otherwise.
 */
int
led_ctrl_create(const char *node, struct led_ctrl **led_ctrl)
{
    size_t path_length = strlen(node) + (sizeof LED_SYSFS_PATH_PREFIX) + 1;

    struct led_ctrl *led = calloc(1, (sizeof *led) + path_length);
    if (!led) {
        zlog_error("failed to allocate memory for led control structure");
        return -ENOMEM;
    }

    int ret = snprintf(led->path, path_length, LED_SYSFS_PATH_PREFIX "%s", node);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to construct led node path (%d)", ret);
        goto fail;
    } else if ((size_t)ret > path_length) {
        zlog_error("failed to construct led node path (too long)");
        ret = -ENAMETOOLONG;
        goto fail;
    }

    char path[PATH_MAX];
    ret = snprintf(path, sizeof path, "%s/trigger", led->path);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to construct led trigger path (%d)", ret);
        goto fail;
    } else if ((size_t)ret > sizeof path) {
        zlog_error("failed to construct led trigger path (too long)");
        ret = -ENAMETOOLONG;
        goto fail;
    }

    int fd_trigger = open(path, O_WRONLY);
    if (fd_trigger < 0) {
        ret = -errno;
        zlog_error("failed to open led trigger path (%d)", ret);
        goto fail;
    }

    ssize_t written = write(fd_trigger, LED_TRIGGER_PATTERN, sizeof LED_TRIGGER_PATTERN);
    if (written < 0 || (size_t)written != sizeof LED_TRIGGER_PATTERN) {
        ret = (written < 0) ? -errno : -EAGAIN;
        zlog_error("failed to set led trigger to '" LED_TRIGGER_PATTERN "' (%d)", ret);
        close(fd_trigger);
        goto fail;
    }

    close(fd_trigger);

    ret = snprintf(path, sizeof path, "%s/pattern", led->path);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to construct led pattern path (%d)", ret);
        goto fail;
    } else if ((size_t)ret > sizeof path) {
        ret = -ENAMETOOLONG;
        zlog_error("failed to construct led pattern path (too long)");
        goto fail;
    }

    led->fd_pattern = open(path, O_RDWR);
    if (led->fd_pattern < 0) {
        ret = -errno;
        zlog_error("failed to open led pattern path '%s' (%d)", path, ret);
        goto fail;
    }

    ret = snprintf(path, sizeof path, "%s/repeat", led->path);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to construct led repeat path (%d)", ret);
        goto fail;
    } else if ((size_t)ret > sizeof path) {
        ret = -ENAMETOOLONG;
        zlog_error("failed to construct led repeat path (too long)");
        goto fail;
    }

    led->fd_repeat = open(path, O_RDWR);
    if (led->fd_repeat < 0) {
        ret = -errno;
        zlog_error("failed to open led repeat path '%s' (%d)", path, ret);
        goto fail;
    }

    *led_ctrl = led;
    ret = 0;
out:
    return ret;
fail:
    led_ctrl_destroy(led);
    goto out;
}

/**
 * @brief Macro stringification helpers.
 */
#define XSTR(s) STR(s)
#define STR(s) #s

/**
 * @brief Helper macros for working with the led pattern driver.
 */
#define LED_BRIGHTNESS_MIN 0
#define LED_BRIGHTNESS_MAX 255
#define LED_BRIGHTNESS_MIN_STR XSTR(LED_BRIGHTNESS_MIN)
#define LED_BRIGHTNESS_MAX_STR XSTR(LED_BRIGHTNESS_MAX)

/**
 * @brief LED repeat value to repeat the current pattern indefinitely.
 */
#define LED_REPEAT_INDEFINITELY "-1"

/**
 * @brief Pattern which defines a repeating series of on/offs. Specifically,
 * this describes an led pattern where the LED will fully illuminate then fully
 * clear for the same period of time.
 */
#define LED_FMT_PATTERN_REPEATING \
    LED_BRIGHTNESS_MIN_STR " %" PRIu32 " " LED_BRIGHTNESS_MIN_STR " 0 " \
    LED_BRIGHTNESS_MAX_STR " %" PRIu32 " " LED_BRIGHTNESS_MAX_STR " 0"

/**
 * @brief Pattern which defines either turning the LED on or off indefinitely.
 */
#define LED_FMT_PATTERN_ONOFF \
    "%" PRIu32 " 0 %" PRIu32 " 0"

/**
 * @brief Sets a pattern on the led node. The pattern must be a series of
 * tuples of brightness and duration.
 * 
 * The pattern will repeat indefinitely.
 * 
 * @param led The led control object for the led to set the pattern for.
 * @param pattern The pattern to set. Must be a serious of tuples. See above
 * for more details.
 * @return int 0 if the pattern was set, non-zero otherwise.
 */
int
led_ctrl_set_pattern(struct led_ctrl *led, const char *pattern)
{
    if (led->fd_repeat == -1 || led->fd_pattern == -1) {
        zlog_error("failed to set pattern for led '%s' (uninitialized)", led->path);
        return -EBADF;
    }

    int ret;
    size_t length = sizeof LED_REPEAT_INDEFINITELY;
    ssize_t written = write(led->fd_repeat, LED_REPEAT_INDEFINITELY, length);
    if (written < 0 || (size_t)written < length) {
        ret = (written < 0) ? -errno : -EAGAIN;
        zlog_error("failed to enable indefinite repearing for led '%s' (%d)", led->path, ret);
        return ret;
    }

    length = strlen(pattern);
    written = write(led->fd_pattern, pattern, length);
    if (written < 0 || (size_t)written < length) {
        ret = (written < 0) ? -errno : -EAGAIN;
        zlog_error("failed to set pattern for led '%s' (%d)", led->path, ret);
        return ret;
    }

    zlog_debug("set pattern='%s' for led '%s'", pattern, led->path);

    return 0;
}

/**
 * @brief Sets a pattern interval, or blink pattern, for an led. The blink
 * pattern toggles between maximum brightness and no brightness, making it an
 * on/off pattern.
 * 
 * The amount of time the led stays on and off is specified by the 'ms_on' and
 * 'ms_off' arguments respectively. Both intervals are specified in milliseconds.
 * 
 * The pattern will repeat indefinitely.
 * 
 * @param led The led control object to set the pattern for.
 * @param ms_off The number of milliseconds the led should stay off.
 * @param ms_on The number of milliseconds the led should stay illuminated.
 * @return int 0 if the pattern was set, non-zero otherwise.
 */
int
led_ctrl_set_repeating_pattern_interval(struct led_ctrl *led, uint32_t ms_off, uint32_t ms_on)
{
    char pattern[64];

    int ret = snprintf(pattern, sizeof pattern, LED_FMT_PATTERN_REPEATING, ms_off, ms_on);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to construct pattern string for led '%s' (%d)", led->path, ret);
        return ret;
    } else if ((size_t)ret > sizeof pattern) {
        zlog_error("failed to construct pattern string for led '%s' (pattern too long)", led->path);
        return -ENAMETOOLONG;
    }

    return led_ctrl_set_pattern(led, pattern);
}

/**
 * @brief Sets a pattern interval, or blink pattern. The blink pattern toggles
 * between maximum brightness and no brightness, for equal amounts of time.
 * 
 * Eg. period_ms = 500 means the led will stay on for 500 ms (0.5s) and then
 * stay off for 500 ms.
 * 
 * The pattern will repeat indefinitely.
 * 
 * @param led The led control object to set the pattern for.
 * @param period_ms The number of milliseconds the led should stay on and off.
 * @return int 0 if the pattern was set, non-zero otherwise.
 */
int
led_ctrl_set_repeating_pattern(struct led_ctrl *led, uint32_t period_ms)
{
    return led_ctrl_set_repeating_pattern_interval(led, period_ms, period_ms);
}

/**
 * @brief Sets the coarse on/off state of the led, either on (max brightness)
 * or off (min brightness).
 * 
 * @param led The led control object to set the pattern for.
 * @param state The desired state of the led, either LED_ON or LED_OFF.
 * @return int 0 if the pattern was set, non-zero otherwise.
 */
int
led_ctrl_set_state(struct led_ctrl *led, enum led_state state)
{
    uint32_t brightness;
    switch (state) {
        case LED_ON:
            brightness = LED_BRIGHTNESS_MAX;
            break;
        case LED_OFF:
            brightness = LED_BRIGHTNESS_MIN;
            break;
        default:
            zlog_error("invalid led state specified");
            return -EINVAL;
    }

    char pattern[32];
    int ret = snprintf(pattern, sizeof pattern, LED_FMT_PATTERN_ONOFF, brightness, brightness);
    if (ret < 0) {
        ret = -errno;
        zlog_error("failed to construct on/off pattern string for led '%s' (%d)", led->path, ret);
        return ret;
    } else if ((size_t)ret > sizeof pattern) {
        zlog_error("failed to construct on/off pattern string for led '%s' (pattern too long)", led->path);
        return -ENAMETOOLONG;
    }

    return led_ctrl_set_pattern(led, pattern);
}

/**
 * @brief Turns the LED on.
 * 
 * @param led The led to turn on.
 * @return int 0 if the led was turned on, non-zero otherwise.
 */
int
led_ctrl_set_on(struct led_ctrl *led)
{
    return led_ctrl_set_state(led, LED_ON);
}

/**
 * @brief Turns the LED off.
 * 
 * @param led The led to turn off.
 * @return int 0 if the led was turned off, non-zero otherwise.
 */
int
led_ctrl_set_off(struct led_ctrl *led)
{
    return led_ctrl_set_state(led, LED_OFF);
}
