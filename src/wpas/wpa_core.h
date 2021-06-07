
#ifndef __WPA_CORE_H__
#define __WPA_CORE_H__

#include "dpp.h"

/**
 * @brief Prototype for the chirp received event callback.
 *
 * @param userdata Contextual data that was registered with the handler.
 * @param id The bootstrap identifier of the peer. If the peer is not known, -1 will be populated.
 * @param mac The mac address of the peer the chirp originated from.
 * @param frequency The radio frequency the chirp was received on.
 * @param hash The "chirp" hash of the peer's public bootstrapping key.
 */
typedef void (*dpp_chirp_received_fn)(void *userdata, int32_t id, const char (*mac)[(DPP_MAC_LENGTH * 2) + 1], uint32_t frequency, const struct dpp_bootstrap_publickey_hash *hash);

/**
 * @brief The maximum length of a configurator params string. Currently, this
 * is defined to allow enough space for an SSID and PSK encoded as hex.
 */
#define WPA_CONFIGURATOR_PARAMS_MAX_LENGTH 512

/**
 * @brief wpa config option name for setting global DPP configurator parameters.
 */
#define WPA_CFG_PROPERTY_DPP_CONFIGURATOR_PARAMS "dpp_configurator_params"

/**
 * @brief DPP network role strings as used in dpp_configurator_params.
 */
#define WPA_DPP_CONF_NETROLE_STA "sta"
#define WPA_DPP_CONF_NETROLE_AP "ap"
#define WPA_DPP_CONF_NETWORK_CONFIGURATOR "configurator"

/**
 * @brief DPP network credential type names as used in dpp_configurator_params.
 */
#define WPA_DPP_CONF_CRED_PSK_TYPE_PSK "psk"
#define WPA_DPP_CONF_CRED_PSK_TYPE_PASSPHRASE "pass"
#define WPA_DPP_CONF_CRED_SAE_TYPE_PASSPHRASE "pass"

/**
 * @brief Translates a dpp_network to a wpa_supplicant and/or hostapd DPP
 * configurator params string. The configurator params string is used to
 * associated provisioning information with peers/enrollees.
 *
 * Currently, this function only supports PSK-based network credentials.
 *
 * @param network The network to convert.
 * @param params A string buffer to write the configurator params to.
 * @param params_length The size of the 'params' buffer, in bytes.
 * @return int 0 If the network was successfully converted. In this case,
 * params will contain the properly encoded configurator params and
 * params_length will indicate the length. Otherwise a non-zero value is
 * returned.
 */
int
dpp_network_to_wpa_configurator_params(struct dpp_network *network, char *params, size_t *params_length, enum dpp_network_role netrole);

#endif //__WPA_CORE_H__
