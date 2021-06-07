
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dpp.h"
#include "string_utils.h"
#include "ztp_log.h"

/**
 * @brief Parses an integer, converting it to a dpp public action frame type.
 * 
 * @param value The value to parse.
 * @return enum dpp_public_action_frame_type The public action frame type
 * associated with the value.
 */
enum dpp_public_action_frame_type
dpp_public_action_frame_parse_int(int value)
{
    switch (value) {
        case 0:
            return DPP_PAF_AUTHENTICATION_REQUEST;
        case 1:
            return DPP_PAF_AUTHENTICATION_RESPONSE;
        case 2:
            return DPP_PAF_AUTHENTICATION_CONFIRM;
        case 5:
            return DPP_PAF_PEER_DISCOVERY_REQUEST;
        case 6:
            return DPP_PAF_PEER_DISCOVERY_RESPONE;
        case 7:
            return DPP_PAF_PKEX_V1_EXCHANGE_REQUEST;
        case 8:
            return DPP_PAF_PKEX_EXCHANGE_RESPONSE;
        case 9:
            return DPP_PAF_PKEX_REVEAL_REQUEST;
        case 10:
            return DPP_PAF_PKEX_REVEAL_RESPONSE;
        case 11:
            return DPP_PAF_CONFIGURATION_RESULT;
        case 12:
            return DPP_PAF_CONNECTION_STATUS;
        case 13:
            return DPP_PAF_PRESENCE_ANNOUNCEMENT;
        case 14:
            return DPP_PAF_RECONFIGURATION_ANNOUNCEMENT;
        case 15:
            return DPP_PAF_RECONFIGURATION_AUTHENTICATION_REQUEST;
        case 16:
            return DPP_PAF_RECONFIGURATION_AUTHENTICATION_RESPONSE;
        case 17:
            return DPP_PAF_RECONFIGURATION_AUTHENTICATION_CONFIRM;
        case 18:
            return DPP_PAF_PKEX_EXCHANGE_REQUEST;
        default:
            return DPP_PAF_INVALID;
    }
}

/**
 * @brief Converts a dpp public action frame type to a string.
 * 
 * @param type The public actio nframe type to parse.
 * @return const char* The string representation of the type.
 */
const char *
dpp_public_action_frame_str(enum dpp_public_action_frame_type type)
{
    switch (type) {
        case DPP_PAF_AUTHENTICATION_REQUEST:
            return "auth-request";
        case DPP_PAF_AUTHENTICATION_RESPONSE:
            return "auth-response";
        case DPP_PAF_AUTHENTICATION_CONFIRM:
            return "auth-confirm";
        case DPP_PAF_PEER_DISCOVERY_REQUEST:
            return "peer-discovery-request";
        case DPP_PAF_PEER_DISCOVERY_RESPONE:
            return "peer-discovery-response";
        case DPP_PAF_PKEX_V1_EXCHANGE_REQUEST:
            return "pkex-exchange-request-v1";
        case DPP_PAF_PKEX_EXCHANGE_RESPONSE:
            return "pkex-exchange-response";
        case DPP_PAF_PKEX_REVEAL_REQUEST:
            return "pkex-reveal-request";
        case DPP_PAF_PKEX_REVEAL_RESPONSE:
            return "pkex-reveal-response";
        case DPP_PAF_CONFIGURATION_RESULT:
            return "config-result";
        case DPP_PAF_CONNECTION_STATUS:
            return "connection-status";
        case DPP_PAF_PRESENCE_ANNOUNCEMENT:
            return "presence-announce";
        case DPP_PAF_RECONFIGURATION_ANNOUNCEMENT:
            return "reconfig-auth-announce";
        case DPP_PAF_RECONFIGURATION_AUTHENTICATION_REQUEST:
            return "reconfig-auth-request";
        case DPP_PAF_RECONFIGURATION_AUTHENTICATION_RESPONSE:
            return "reconfig-auth-response";
        case DPP_PAF_RECONFIGURATION_AUTHENTICATION_CONFIRM:
            return "reconfig-auth-confirm";
        case DPP_PAF_PKEX_EXCHANGE_REQUEST:
            return "pkex-exchange-request";
        case DPP_PAF_INVALID:
        default:
            return "invalid";
    }
}

/**
 * @brief Parses a string and converts it to a dpp device role.
 *
 * @param str The string to parse.
 * @return enum dpp_device_role
 */
enum dpp_device_role
dpp_device_role_parse(const char *str)
{
    if (strcmp(str, "enrollee") == 0) {
        return DPP_DEVICE_ROLE_ENROLLEE;
    } else if (strcmp(str, "configurator") == 0) {
        return DPP_DEVICE_ROLE_CONFIGURATOR;
    } else {
        return DPP_DEVICE_ROLE_UNKNOWN;
    }
}

/**
 * @brief Determines if the specified device role is valid.
 * 
 * @param role The role to check.
 * @return true If the device role is valid.
 * @return false If the device role is invalid.
 */
bool
dpp_device_role_is_valid(enum dpp_device_role role)
{
    switch (role) {
        case DPP_DEVICE_ROLE_ENROLLEE:
        case DPP_DEVICE_ROLE_CONFIGURATOR:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Returns the peer role.
 * 
 * @param role The role to get the peer for.
 * @return enum dpp_device_role The peer role.
 */
enum dpp_device_role
dpp_device_role_peer(enum dpp_device_role role)
{
    switch (role) {
        case DPP_DEVICE_ROLE_ENROLLEE:
            return DPP_DEVICE_ROLE_CONFIGURATOR;
        case DPP_DEVICE_ROLE_CONFIGURATOR:
            return DPP_DEVICE_ROLE_ENROLLEE;
        default:
            return DPP_DEVICE_ROLE_UNKNOWN;
    }
}

/**
 * @brief Converts a dpp device role to a string.
 *
 * @return const char*  A string representation of the role.
 */
const char *
dpp_device_role_str(enum dpp_device_role role)
{
    switch (role) {
        case DPP_DEVICE_ROLE_ENROLLEE:
            return "enrollee";
        case DPP_DEVICE_ROLE_CONFIGURATOR:
            return "configurator";
        default:
            return "??";
    }
}

/**
 * @brief Parses a string and converts it to a dpp network role.
 *
 * @param str The string to parse.
 * @return enum dpp_network_role The network role corresponding to the string,
 * if it is valid. Otherwise DPP_NETWORK_ROLE_UNKNOWN is returned.
 */
enum dpp_network_role
dpp_network_role_parse(const char *str)
{
    if (strcmp(str, "sta") == 0 || strcmp(str, "station") == 0) {
        return DPP_NETWORK_ROLE_STATION;
    } else if (strcmp(str, "ap") == 0 || strcmp(str, "accesspoint") == 0) {
        return DPP_NETWORK_ROLE_AP;
    } else if (strcmp(str, "configurator") == 0) {
        return DPP_NETWORK_ROLE_CONFIGURATOR;
    } else {
        return DPP_NETWORK_ROLE_UNKNOWN;
    }
}

/**
 * @brief Convert a dpp network role to a string.
 *
 * The values here must be defined as specified in the Device Provisioning
 * Protocol Specification, section 4.4, Table 6, 'DPP Configuration Request
 * object.
 *
 * @param role The role to convert.
 * @return const char* A string representation of the network role.
 */
const char *
dpp_network_role_str(enum dpp_network_role role)
{
    switch (role) {
        case DPP_NETWORK_ROLE_STATION:
            return "sta";
        case DPP_NETWORK_ROLE_AP:
            return "ap";
        case DPP_NETWORK_ROLE_CONFIGURATOR:
            return "configurator";
        default:
            return "??";
    }
}

/**
 * @brief Parses a string and converts it to a dpp_state.
 *
 * @param state The string to parse.
 * @return enum dpp_state The corresponding dpp_state. Returns
 * DPP_STATS_UNKNOWN for invalid and unknown input strings.
 */
enum dpp_state
parse_dpp_state(const char *state)
{
    if (strcmp(state, "inactive") == 0) {
        return DPP_STATE_INACTIVE;
    } else if (strcmp(state, "terminated") == 0) {
        return DPP_STATE_TERMINATED;
    } else if (strcmp(state, "presence_announce") == 0) {
        return DPP_STATE_CHIRPING;
    } else if (strcmp(state, "provisioning") == 0) {
        return DPP_STATE_PROVISIONING;
    } else if (strcmp(state, "bootstrap_key_acquiring") == 0) {
        return DPP_STATE_BOOTSTRAP_KEY_ACQUIRING;
    } else if (strcmp(state, "bootstrapped") == 0) {
        return DPP_STATE_BOOTSTRAPPED;
    } else if (strcmp(state, "authenticating") == 0) {
        return DPP_STATE_AUTHENTICATING;
    } else if (strcmp(state, "authenticated") == 0) {
        return DPP_STATE_AUTHENTICATED;
    } else if (strcmp(state, "provisioned") == 0) {
        return DPP_STATE_PROVISIONED;
    } else {
        return DPP_STATE_UNKNOWN;
    }
}

/**
 * @brief Converts a dpp state into a string.
 *
 * @param dpp_state The dpp state to convert.
 * @return const char* A string representation of the state.
 */
const char *
dpp_state_str(enum dpp_state dpp_state)
{
    switch (dpp_state) {
        case DPP_STATE_INACTIVE:
            return "inactive";
        case DPP_STATE_TERMINATED:
            return "terminated";
        case DPP_STATE_CHIRPING:
            return "presence_announce";
        case DPP_STATE_PROVISIONING:
            return "provisioning";
        case DPP_STATE_BOOTSTRAP_KEY_ACQUIRING:
            return "bootstrap_key_acquiring";
        case DPP_STATE_BOOTSTRAPPED:
            return "bootstrapped";
        case DPP_STATE_AUTHENTICATING:
            return "authenticating";
        case DPP_STATE_AUTHENTICATED:
            return "authenticated";
        case DPP_STATE_PROVISIONED:
            return "provisioned";
        case DPP_STATE_UNKNOWN:
        default:
            return "??";
    }
}

/**
 * @brief Parses a string and converts it to a dpp_bootstrap_type.
 *
 * @param str The string to parse.
 * @return enum dpp_bootstrap_type The corresponding type. Returns
 * DPP_BOOTSTRAP_TYPE_UNKNOWN for invalid and unknown input strings.
 */
enum dpp_bootstrap_type
parse_dpp_bootstrap_type(const char *str)
{
    if (strcmp(str, "qrcode") == 0) {
        return DPP_BOOTSTRAP_QRCODE;
    } else if (strcmp(str, "pkex") == 0) {
        return DPP_BOOTSTRAP_PKEX;
    } else if (strcmp(str, "nfc") == 0) {
        return DPP_BOOTSTRAP_NFC;
    } else if (strcmp(str, "ble") == 0 || strcmp(str, "bluetooth") == 0) {
        return DPP_BOOTSTRAP_BLE;
    } else if (strcmp(str, "cloud") == 0) {
        return DPP_BOOTSTRAP_CLOUD;
    } else {
        return DPP_BOOTSTRAP_UNKNOWN;
    }
}

/**
 * @brief Converts a dpp bootstrap type into a string.
 *
 * @param dpp_bootstrap_type The dpp bootstrap type to convert.
 * @return const char* A string represtation of the type.
 */
const char *
dpp_bootstrap_type_str(enum dpp_bootstrap_type dpp_bootstrap_type)
{
    switch (dpp_bootstrap_type) {
        case DPP_BOOTSTRAP_QRCODE:
            return "qrcode";
        case DPP_BOOTSTRAP_PKEX:
            return "pkex";
        case DPP_BOOTSTRAP_NFC:
            return "nfc";
        case DPP_BOOTSTRAP_BLE:
            return "bluetooth";
        case DPP_BOOTSTRAP_CLOUD:
            return "cloud";
        case DPP_BOOTSTRAP_UNKNOWN:
        default:
            return "??";
    }
}

/**
 * @brief Determines if DPP provisioning is in progress based on the DPP state.
 *
 * @param dpp_state The state to check.
 * @return true If the state reflects that DPP provisioning is in progress.
 * @return false If the state reflects that DPP provisioning is not in progress.
 */
bool
is_dpp_provisioning_in_progress(enum dpp_state dpp_state)
{
    switch (dpp_state) {
        case DPP_STATE_CHIRPING:
        case DPP_STATE_PROVISIONING:
        case DPP_STATE_BOOTSTRAP_KEY_ACQUIRING:
        case DPP_STATE_BOOTSTRAPPED:
        case DPP_STATE_AUTHENTICATING:
        case DPP_STATE_AUTHENTICATED:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Parses a string and converts it to a dpp akm.
 *
 * @param str The string to parse.
 * @return enum dpp_akm The role corresponding with the specified string.
 */
enum dpp_akm
parse_dpp_akm(const char *str)
{
    if (strcmp(str, "psk") == 0) {
        return DPP_AKM_PSK;
    } else if (strcmp(str, "sae") == 0) {
        return DPP_AKM_SAE;
    } else if (strcmp(str, "dpp") == 0) {
        return DPP_AKM_DPP;
    } else if (strcmp(str, "dot1x") == 0) {
        return DPP_AKM_DOT1X;
    } else {
        return DPP_AKM_INVALID;
    }
}

/**
 * @brief Converts a dpp akm to a string.
 *
 * @param akm The akm to convert.
 * @return const char* A string representing the dpp akm.
 */
const char *
dpp_akm_str(enum dpp_akm akm)
{
    switch (akm) {
        case DPP_AKM_PSK:
            return "psk";
        case DPP_AKM_SAE:
            return "sae";
        case DPP_AKM_DPP:
            return "dpp";
        case DPP_AKM_DOT1X:
            return "dot1x";
        default:
            return "??";
    }
}

/**
 * @brief Parses a string and converts it to a dpp psk credential type.
 * 
 * @param str The strong to parse.
 * @return enum dpp_psk_credential_type The psk credential type corresponding
 * to the string.
 */
enum dpp_psk_credential_type
parse_dpp_psk_credential_type(const char *str)
{
    if (strcmp(str, "passphrase") == 0) {
        return PSK_CREDENTIAL_TYPE_PASSPHRASE;
    } else if (strcmp(str, "psk") == 0) {
        return PSK_CREDENTIAL_TYPE_PSK;
    } else {
        return PSK_CREDENTIAL_TYPE_INVALID;
    }
}

/**
 * @brief Converts a dpp psk credential type to a string.
 * 
 * @param type The psk credential type to convert.
 * @return const char* A string representing the psk credential type.
 */
const char *
dpp_psk_credential_type_str(const enum dpp_psk_credential_type type)
{
    switch (type) {
        case PSK_CREDENTIAL_TYPE_PASSPHRASE:
            return "passphrase";
        case PSK_CREDENTIAL_TYPE_PSK:
            return "psk";
        default:
            return "??";
    }
}

/**
 * @brief Allocates and initializes a new network credential object. The
 * initial state describes an invalid network credential. It must be filled in
 * to be made valid.
 *
 * @return struct dpp_network_credential*
 */
struct dpp_network_credential *
dpp_network_credential_alloc(void)
{
    struct dpp_network_credential *credential = calloc(1, sizeof *credential);
    if (!credential)
        return NULL;

    INIT_LIST_HEAD(&credential->list);
    credential->akm = DPP_AKM_INVALID;

    return credential;
}

/**
 * @brief Sets a passphrase for the credential.
 * 
 * @param credential The psk credential to set the passphrase for.
 * @param passphrase The passphrase to set.
 * @return int 0 if the passphrase was successfully set. -ERANGE if the
 * passphrase was outside of the allowed bounds.
 */
int
dpp_credential_psk_set_passphrase(struct dpp_network_credential_psk *credential, const char *passphrase)
{
    size_t length = strlen(passphrase);
    if (length < DPP_PASSPHRASE_LENGTH_MIN || length > DPP_PASSPHRASE_LENGTH_MAX) {
        zlog_warning("psk credential passphrase length (%lu) out of bounds [%u, %u]", length, DPP_PASSPHRASE_LENGTH_MIN, DPP_PASSPHRASE_LENGTH_MAX);
        return -ERANGE;
    }

    hex_encode((const uint8_t *)passphrase, length, credential->passphrase.hex, sizeof credential->passphrase.hex);
    memcpy(credential->passphrase.ascii, passphrase, length + 1);
    credential->passphrase.length = length;

    return 0;
}

/**
 * @brief Sets a pre-shared key for the credential.
 * 
 * @param credential The psk credential to set the psk for.
 * @param key_hex The hex encoded pre-shared key.
 * @return int 0 if the key was successfully set. -EINVAL if the key was
 * invalid, -ERANGE if the key was outside the allowed bounds.
 */
int
dpp_credential_psk_set_key(struct dpp_network_credential_psk *credential, const char *key_hex)
{
    if (hex_decode(key_hex, credential->key.buffer, sizeof credential->key.buffer) < 0) {
        zlog_error("invalid pre-shared key value specified");
        return -EINVAL;
    }

    size_t key_length = strlen(key_hex);
    if (key_length > (sizeof credential->key.buffer * 2)) {
        zlog_error("invalid pre-shared key length");
        return -ERANGE;
    }

    memcpy(credential->key.hex, key_hex, (sizeof credential->key.buffer * 2) + 1);

    return 0;
}

/**
 * @brief Sets a passphrase for the credential.
 * 
 * @param credential The sae credential to set the passphrase for.
 * @param passphrase The passphrase to set. 
 * @return int 0 if the passphrase was successfully set, non-zero otherwise.
 */
int
dpp_credential_sae_set_passphrase(struct dpp_network_credential_sae *credential, const char *passphrase)
{
    size_t length = strlen(passphrase);
    size_t length_hex = length * 2;

    char *ptr = malloc((length + 1) + (length_hex + 1));
    if (!ptr) {
        zlog_error("failed to allocate memory for sae credential passphrase");
        return -ENOMEM;
    }

    char *passphrase_hex = ptr + length + 1;

    credential->passphrase = ptr;
    credential->passphrase_hex = (ptr + length + 1);
    memcpy(credential->passphrase, passphrase, length + 1);
    hex_encode((const uint8_t *)passphrase, length, passphrase_hex, length_hex + 1);

    return 0;
}

/**
 * @brief Determines if a sae-based network credential is valid.
 * 
 * @param sae The credential to check.
 * @return true If the credential describes a valid sae.
 * @return false If the credential is invalid.
 */
static bool
dpp_credential_sae_is_valid(const struct dpp_network_credential_sae *sae)
{
    return (sae->passphrase && strlen(sae->passphrase) > 0);
}

/**
 * @brief Uninitializes an sae credential.
 * 
 * @param sae The sae-based credential to uninitialize.
 */
static void
dpp_credential_sae_uninitialize(struct dpp_network_credential_sae *sae)
{
    if (sae->passphrase) {
        free(sae->passphrase);
        sae->passphrase = NULL;
        sae->passphrase_hex = NULL;
    }
}

/**
 * @brief Determines if a psk-based network credential is valid.
 *
 * @param credential The credential to check. 
 * @return true If the credential describes a valid psk.
 * @return false If the credential is invalid.
 */
static bool
dpp_credential_psk_is_valid(const struct dpp_network_credential_psk *credential)
{
    switch (credential->type) {
        case PSK_CREDENTIAL_TYPE_PASSPHRASE: {
            if (credential->passphrase.length == 0) {
                zlog_error("psk credential missing passphrase");
                return false;
            } else if (credential->passphrase.length < DPP_PASSPHRASE_LENGTH_MIN || credential->passphrase.length > DPP_PASSPHRASE_LENGTH_MAX) {
                zlog_error("psk credential passphrase length invalid (%u <= passphrase <= %u)", DPP_PASSPHRASE_LENGTH_MIN, DPP_PASSPHRASE_LENGTH_MAX);
                return false;
            } else if (strlen(credential->passphrase.hex) != credential->passphrase.length * 2) {
                zlog_error("psk credential has missing or invalid passphrase hex encoding");
                return false;
            }
            break;
        }
        case PSK_CREDENTIAL_TYPE_PSK: {
            if (strlen(credential->key.hex) != sizeof credential->key.buffer * 2) {
                zlog_error("psk credential has missing or invalid psk hex encoding");
                return false;
            }
            break;
        }
        default:
            zlog_error("psk credential has invalid type");
            return false;
    }

    return true;
}

/**
 * @brief Determines if a network credential is valid.
 *
 * @param credential The credential to check.
 * @return true If the credential is valid.
 * @return false If the credential is invalid.
 */
bool
dpp_network_credential_is_valid(const struct dpp_network_credential *credential)
{
    switch (credential->akm) {
        case DPP_AKM_PSK:
            return dpp_credential_psk_is_valid(&credential->psk);
        case DPP_AKM_SAE:
            return dpp_credential_sae_is_valid(&credential->sae);
        case DPP_AKM_INVALID:
        default:
            zlog_error("credential has invalid akm");
            return false;
    }
}

/**
 * @brief Uninitializes a dpp network credential, releasing any owned resources.
 *
 * @param credential The credential to uninitialize.
 */
void
dpp_network_credential_uninitialize(struct dpp_network_credential *credential)
{
    switch (credential->akm) {
        case DPP_AKM_SAE:
            dpp_credential_sae_uninitialize(&credential->sae);
            break;
        default:
            break;
    }

    if (!list_empty(&credential->list))
        list_del(&credential->list);
}

/**
 * @brief Allocates and initializes a new dpp network object.
 *
 * @return struct dpp_network
 */
struct dpp_network *
dpp_network_alloc(void)
{
    struct dpp_network *network = calloc(1, sizeof *network);
    if (!network)
        return NULL;

    INIT_LIST_HEAD(&network->credentials);
    return network;
}

/**
 * @brief Uninitializes a dpp network, releasing any owned resources. If the
 * network is part of a list, it is removed from that list.
 *
 * @param network The network to uninitialize.
 */
void
dpp_network_uninitialize(struct dpp_network *network)
{
    if (!list_empty(&network->credentials)) {
        struct dpp_network_credential *credential;
        struct dpp_network_credential *credentialtmp;
        list_for_each_entry_safe (credential, credentialtmp, &network->credentials, list) {
            dpp_network_credential_uninitialize(credential);
        }
    }
}

/**
 * @brief Adds a new credential to the network.
 * 
 * @param network The network to add the credential to.
 * @param credential The credential to add.
 */
void
dpp_network_add_credential(struct dpp_network *network, struct dpp_network_credential *credential)
{
    list_add(&credential->list, &network->credentials);
}

/**
 * @brief Determines if a DPP network structure is valid.
 *
 * @param network The network to validate.
 * @return true If the network described is valid.
 * @return false Otherwise.
 */
bool
dpp_network_is_valid(const struct dpp_network *network)
{
    if (list_empty(&network->credentials)) {
        zlog_error("network missing credentials");
        return false;
    } else if (network->discovery.ssid_length == 0) {
        zlog_error("network missing ssid");
        return false;
    }

    struct dpp_network_credential *credential;
    list_for_each_entry (credential, &network->credentials, list) {
        if (!dpp_network_credential_is_valid(credential)) {
            zlog_error("network has invalid credential");
            return false;
        }
    }

    return true;
}

/**
 * @brief Uninitializes a dpp bootstrap info structure, releasing any owned
 * resources.
 * 
 * @param bi The bootstrap info structure to uninitialize.
 */
void
dpp_bootstrap_info_uninitialize(struct dpp_bootstrap_info *bi)
{
    char **strs[] = {
        &bi->channel,
        &bi->curve,
        &bi->engine_id,
        &bi->engine_path,
        &bi->info,
        &bi->key,
        &bi->key_id,
        &bi->mac,
    };

    for (size_t i = 0; i < ARRAY_SIZE(strs); i++) {
        if (*strs[i]) {
            free(*strs[i]);
            *strs[i] = NULL;
        }
    }
}
