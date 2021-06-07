
#ifndef __ZTP_CONFIGURATOR_CONFIG_H__
#define __ZTP_CONFIGURATOR_CONFIG_H__

#include <userspace/linux/list.h>

/**
 * @brief Forward declarations.
 */
struct dpp_network;
struct bootstrap_info_provider_settings;

/**
 * @brief DPP configurator settings.
 */
struct ztp_configurator_settings {
    uint32_t expiration_time;
    struct dpp_network *network_config_default;
    struct list_head provider_settings;
};

/**
 * @brief Parses a json-formatted configurator configuration file.
 *
 * @param file The path of the file to parse.
 * @param configurator The configurator settings to fill in.
 * @return int 0 if parsing was successful, non-zero otherwise.
 */
int
ztp_configurator_config_parse(const char *file, struct ztp_configurator_settings *settings);

/**
 * @brief Persists configurator settings to file.
 * 
 * @param filename The filename to write the settings to.
 * @param settings The settings to write to file.
 * @return int 0 if the settings were successfully written to file, non-zero otherwise.
 */
int
ztp_configurator_settings_persist(const char *filename, const struct ztp_configurator_settings *settings);

/**
 * @brief Persists configurator settings to file descriptor.
 * 
 * @param fd The file descriptor to write the settings to.
 * @param settings The settings to write to file.
 * @return int 0 if the settings were successfully written to file, non-zero otherwise.
 */
int
ztp_configurator_settings_persist_fd(int fd, const struct ztp_configurator_settings *settings);

/**
 * @brief Initializes the settings structure for use.
 * 
 * @param settings 
 */
void
ztp_configurator_settings_initialize(struct ztp_configurator_settings *settings);

/**
 * @brief Uninitializes configurator settings, freeing any owned resources.
 *
 * @param settings The settings object to uninitialize.
 */
void
ztp_configurator_settings_uninitialize(struct ztp_configurator_settings *settings);

/**
 * @brief Add new bootstrap information provider settings to the configurator settings.
 * 
 * @param settings The configurator settings to add the bootstrap info provider settings to.
 * @param provider The bootstrap info provider settings to add. 
 */
void
ztp_configurator_settings_add_bi_provider_settings(struct ztp_configurator_settings *settings, struct bootstrap_info_provider_settings *provider);

#endif //__ZTP_CONFIGURATOR_CONFIG_H__
