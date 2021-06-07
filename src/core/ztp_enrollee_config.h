
#ifndef __ZTP_ENROLLEE_CONFIG_H__
#define __ZTP_ENROLLEE_CONFIG_H__

#include "dpp.h"

/**
 * @brief Enrollee DPP device role settings.
 */
struct ztp_enrollee_settings {
    char *status_signal_led_path;
    struct dpp_bootstrap_info bootstrap;
};

/**
 * @brief Parses a json-formatted enrollee configuration file.
 *
 * @param file The path of the file to parse.
 * @param settings The enrollee settings to fill in.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
ztp_enrollee_config_parse(const char *file, struct ztp_enrollee_settings *settings);

/**
 * @brief Initializes the settings structure for use.
 * 
 * @param settings 
 */
void
ztp_enrollee_settings_initialize(struct ztp_enrollee_settings *settings);

/**
 * @brief Uninitializes enrollee settings, freeing any owned resources.
 *
 * @param settings The settigns object to uninitialize.
 */
void
ztp_enrollee_settings_uninitialize(struct ztp_enrollee_settings *settings);

#endif //__ZTP_ENROLLEE_CONFIG_H__
