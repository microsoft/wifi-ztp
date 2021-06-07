
#include <errno.h>
#include <stdio.h>

#include "string_utils.h"
#include "wpa_core.h"
#include "ztp_log.h"

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
dpp_network_to_wpa_configurator_params(struct dpp_network *network, char *params, size_t *params_length, enum dpp_network_role netrole)
{
    char ssid_hex[(DPP_SSID_LENGTH_MAX * 2) + 1];
    hex_encode(network->discovery.ssid, network->discovery.ssid_length, ssid_hex, sizeof ssid_hex);

    if (!dpp_network_is_valid(network)) {
        zlog_error("dpp network is invalid or unsupported");
        return -EINVAL;
    }

    // This is guaranteed to be non-NULL by dpp_network_is_valid() above.
    struct dpp_network_credential *credential = list_first_entry(&network->credentials, struct dpp_network_credential, list);
    const char *akm = dpp_akm_str(credential->akm);
    const char *netrolestr = dpp_network_role_str(netrole);

    const char *cred_type;
    const char *cred_value;

    if (credential->akm == DPP_AKM_PSK) {
        switch (credential->psk.type) {
            case PSK_CREDENTIAL_TYPE_PASSPHRASE:
                cred_type = WPA_DPP_CONF_CRED_PSK_TYPE_PASSPHRASE;
                cred_value = credential->psk.passphrase.hex;
                break;
            case PSK_CREDENTIAL_TYPE_PSK:
                cred_type = WPA_DPP_CONF_CRED_PSK_TYPE_PSK;
                cred_value = credential->psk.key.hex;
                break;
            default:
                zlog_error("dpp network has unsupported psk credential type=%u", (uint32_t)credential->psk.type);
                return -ENOTSUP;
        }
    } else if (credential->akm == DPP_AKM_SAE) {
        cred_type = WPA_DPP_CONF_CRED_SAE_TYPE_PASSPHRASE;
        cred_value = credential->sae.passphrase_hex;
    } else {
        zlog_error("dpp network has unsupported akm '%s'", akm);
        return -ENOTSUP;
    }

    int ret = snprintf(params, *params_length, "conf=%s-%s ssid=%s %s=%s", netrolestr, akm, ssid_hex, cred_type, cred_value);
    if (ret < 0) {
        zlog_error("failed to translate dpp network to configurator params (%d)", ret);
        return ret;
    }

    *params_length = (size_t)ret;

    return 0;
}
