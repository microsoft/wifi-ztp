
#ifndef __LED_CTRL_H__
#define __LED_CTRL_H__

#include <stdint.h>

/**
 * @brief LED control object, exposing common functionality interacting with an
 * LED.
 */
struct led_ctrl {
    int fd_pattern;
    int fd_repeat;
    char path[];
};

/**
 * @brief Coarse LED state, either on (max brightness) or off (min brightness).
 */
enum led_state {
    LED_ON,
    LED_OFF
};

/**
 * @brief Destroys an led_ctrl object, freeing all owned resources.
 * 
 * @param led The led control object to destroy.
 */
void
led_ctrl_destroy(struct led_ctrl *led);

/**
 * @brief Creates a new led control object. This can be used to perform various
 * common tasks controlling an LED.
 * 
 * @param node The sysfs node name of the led. Eg. /sys/class/leds/<nodename>
 * @param led_ctrl Output argument to hold to allocated control object.
 * @return int 0 if the control object was successfully created, non-zero otherwise.
 */
int
led_ctrl_create(const char *node, struct led_ctrl **led_ctrl);

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
led_ctrl_set_pattern(struct led_ctrl *led, const char *pattern);

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
led_ctrl_set_repeating_pattern_interval(struct led_ctrl *led, uint32_t ms_off, uint32_t ms_on);

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
led_ctrl_set_repeating_pattern(struct led_ctrl *led, uint32_t period_ms);

/**
 * @brief Sets the coarse on/off state of the led, either on (max brightness)
 * or off (min brightness).
 * 
 * @param led The led control object to set the pattern for.
 * @param state The desired state of the led, either LED_ON or LED_OFF.
 * @return int 0 if the pattern was set, non-zero otherwise.
 */
int
led_ctrl_set_state(struct led_ctrl *led, enum led_state state);

/**
 * @brief Turns the LED on.
 * 
 * @param led The led to turn on.
 * @return int 0 if the led was turned on, non-zero otherwise.
 */
int
led_ctrl_set_on(struct led_ctrl *led);

/**
 * @brief Turns the LED off.
 * 
 * @param led The led to turn off.
 * @return int 0 if the led was turned off, non-zero otherwise.
 */
int
led_ctrl_set_off(struct led_ctrl *led);

#endif //__LED_CTRL_H__
