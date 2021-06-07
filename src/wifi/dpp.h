
#ifndef __DPP_H__
#define __DPP_H__

#include <stdbool.h>
#include <stdint.h>

#include <userspace/linux/list.h>

/**
 * @brief The digest length of a SHA256 hash.
 */
#define SHA256_HASH_LENGTH 32

/**
 * @brief Macro defining the length of the DPP bootstrapping public key hash.
 * See Device Provisioning Protocol Specification, version 1.2.5, section
 * 6.3.3, 'DPP authentication response'.
 */
#define DPP_BOOTSTRAP_PUBKEY_HASH_LENGTH SHA256_HASH_LENGTH

/**
 * @brief Macro defining the length of a WiFi hardware address, or MAC.
 */
#define DPP_MAC_LENGTH 6

/**
 * @brief The maximum length of an SSID (as used by DPP).
 */
#define DPP_SSID_LENGTH_MAX 32

/**
 * @brief DPP Public Action Frame Type.
 * @see Wi-Fi EasyConnect Specification v2.0, Table 31.
 */
enum dpp_public_action_frame_type {
    DPP_PAF_AUTHENTICATION_REQUEST = 0,
    DPP_PAF_AUTHENTICATION_RESPONSE = 1,
    DPP_PAF_AUTHENTICATION_CONFIRM = 2,
    DPP_PAF_PEER_DISCOVERY_REQUEST = 5,
    DPP_PAF_PEER_DISCOVERY_RESPONE = 6,
    DPP_PAF_PKEX_V1_EXCHANGE_REQUEST = 7,
    DPP_PAF_PKEX_EXCHANGE_RESPONSE = 8,
    DPP_PAF_PKEX_REVEAL_REQUEST = 9,
    DPP_PAF_PKEX_REVEAL_RESPONSE = 10,
    DPP_PAF_CONFIGURATION_RESULT = 11,
    DPP_PAF_CONNECTION_STATUS = 12,
    DPP_PAF_PRESENCE_ANNOUNCEMENT = 13,
    DPP_PAF_RECONFIGURATION_ANNOUNCEMENT = 14,
    DPP_PAF_RECONFIGURATION_AUTHENTICATION_REQUEST = 15,
    DPP_PAF_RECONFIGURATION_AUTHENTICATION_RESPONSE = 16,
    DPP_PAF_RECONFIGURATION_AUTHENTICATION_CONFIRM = 17,
    DPP_PAF_PKEX_EXCHANGE_REQUEST = 18,
    DPP_PAF_INVALID = 256,
};

/**
 * @brief Parses an integer, converting it to a dpp public action frame type.
 * 
 * @param value The value to parse.
 * @return enum dpp_public_action_frame_type The public action frame type
 * associated with the value.
 */
enum dpp_public_action_frame_type
dpp_public_action_frame_parse_int(int value);

/**
 * @brief Converts a dpp public action frame type to a string.
 * 
 * @param type The public actio nframe type to parse.
 * @return const char* The string representation of the type.
 */
const char *
dpp_public_action_frame_str(enum dpp_public_action_frame_type type);

/**
 * @brief Describes the DPP device role. Note that this is distinct from the
 * DPP network role.
 */
enum dpp_device_role {
    DPP_DEVICE_ROLE_UNKNOWN = 0,
    DPP_DEVICE_ROLE_ENROLLEE,
    DPP_DEVICE_ROLE_CONFIGURATOR,
    DPP_DEVICE_ROLE_COUNT,
};

/**
 * @brief Parses a string and converts it to a dpp device role.
 *
 * @param str The string to parse.
 * @return enum dpp_device_role
 */
enum dpp_device_role
dpp_device_role_parse(const char *str);

/**
 * @brief Determines if the specified device role is valid.
 * 
 * @param role The role to check.
 * @return true If the device role is valid.
 * @return false If the device role is invalid.
 */
bool
dpp_device_role_is_valid(enum dpp_device_role role);

/**
 * @brief Returns the peer role.
 * 
 * @param role The role to get the peer for.
 * @return enum dpp_device_role The peer role.
 */
enum dpp_device_role
dpp_device_role_peer(enum dpp_device_role role);

/**
 * @brief Converts a dpp device role to a string.
 *
 * @return const char*  A string representation of the role.
 */
const char *
dpp_device_role_str(enum dpp_device_role role);

/**
 * @brief DPP Network role, describing the role/function of an enrollee device.
 */
enum dpp_network_role {
    DPP_NETWORK_ROLE_UNKNOWN = 0,
    DPP_NETWORK_ROLE_STATION,
    DPP_NETWORK_ROLE_AP,
    DPP_NETWORK_ROLE_CONFIGURATOR,
};

/**
 * @brief Parses a string and converts it to a dpp network role.
 *
 * @param str The string to parse.
 * @return enum dpp_network_role The network role corresponding to the string,
 * if it is valid. Otherwise DPP_NETWORK_ROLE_UNKNOWN is returned.
 */
enum dpp_network_role
dpp_network_role_parse(const char *str);

/**
 * @brief Convert a dpp network role to a string.
 *
 * @param role The role to convert.
 * @return const char* A string representation of the network role.
 */
const char *
dpp_network_role_str(enum dpp_network_role role);

/**
 * @brief Device provisioning protocol (DPP) device state. This applies to the
 * overall process and so can be applied to an enrollee or a configurator. Some
 * states will never be reported for certain roles. For example,
 * DPP_STATE_CHIRPING will never be attributed to a device with
 * role=configurator.
 */
enum dpp_state {
    DPP_STATE_INACTIVE,
    DPP_STATE_TERMINATED,
    DPP_STATE_UNKNOWN,
    DPP_STATE_CHIRPING,
    DPP_STATE_PROVISIONING,
    DPP_STATE_BOOTSTRAP_KEY_ACQUIRING,
    DPP_STATE_BOOTSTRAPPED,
    DPP_STATE_AUTHENTICATING,
    DPP_STATE_AUTHENTICATED,
    DPP_STATE_PROVISIONED,
};

/**
 * @brief Parses a string and converts it to a dpp_state.
 *
 * @param str The string to parse.
 * @return enum dpp_state The corresponding dpp_state. Returns
 * DPP_STATE_UNKNOWN for invalid and unknown input strings.
 */
enum dpp_state
parse_dpp_state(const char *str);

/**
 * @brief Converts a dpp state into a string.
 *
 * @param dpp_state The dpp state to convert.
 * @return const char* A string representation of the state.
 */
const char *
dpp_state_str(enum dpp_state dpp_state);

/**
 * @brief Describes DPP bootstrapping methods.
 */
enum dpp_bootstrap_type {
    DPP_BOOTSTRAP_UNKNOWN = 0,
    DPP_BOOTSTRAP_QRCODE,
    DPP_BOOTSTRAP_PKEX,
    DPP_BOOTSTRAP_NFC,
    DPP_BOOTSTRAP_BLE,
    DPP_BOOTSTRAP_CLOUD,
    DPP_BOOTSTRAP_COUNT,
};

/**
 * @brief Parses a string and converts it to a dpp_bootstrap_type.
 *
 * @param str The string to parse.
 * @return enum dpp_bootstrap_type The corresponding type. Returns
 * DPP_BOOTSTRAP_TYPE_UNKNOWN for invalid and unknown input strings.
 */
enum dpp_bootstrap_type
parse_dpp_bootstrap_type(const char *str);

/**
 * @brief Converts a dpp bootstrap type into a string.
 *
 * @param dpp_bootstrap_type The dpp bootstrap type to convert.
 * @return const char* A string represtation of the type.
 */
const char *
dpp_bootstrap_type_str(enum dpp_bootstrap_type dpp_bootstrap_type);

/**
 * @brief Determines if DPP provisioning is in progress based on the DPP state.
 *
 * @param dpp_state The state to check.
 * @return true If the state reflects that DPP provisioning is in progress.
 * @return false If the state reflects that DPP provisioning is not in progress.
 */
bool
is_dpp_provisioning_in_progress(enum dpp_state dpp_state);

/**
 * @brief Describes dpp bootstrapping information.
 */
struct dpp_bootstrap_info {
    enum dpp_bootstrap_type type;
    char *channel;
    char *curve;
    char *mac;
    char *info;
    char *key;
    char *key_id;
    char *engine_id;
    char *engine_path;
};

/**
 * @brief Uninitializes a dpp bootstrap info structure, releasing any owned
 * resources.
 * 
 * @param bi The bootstrap info structure to uninitialize.
 */
void
dpp_bootstrap_info_uninitialize(struct dpp_bootstrap_info *bi);

/**
 * @brief Represents a binary dpp bootstrapping key.
 *
 * This is a DER-encoded ASN.1 SubjectPublicKeyInfo data structure as defined
 * in RFC 5280,Internet X.509 Public Key Infrastructure Certificate and
 * Certificate Revocation List (CRL) Profile
 */
struct dpp_bootstrap_publickey {
    uint8_t *data;
    size_t length;
};

/**
 * @brief Represents a cryptographic hash of a dpp bootstrapping key.
 */
struct dpp_bootstrap_publickey_hash {
    uint8_t data[DPP_BOOTSTRAP_PUBKEY_HASH_LENGTH];
};

/**
 * @brief Helper macro for printing a public key hash as hex.
 */
#define DPP_BOOTSTRAP_PUBLICKEY_HASH_FMT \
    "%02x%02x%02x%02x%02x%02x%02x%02x"   \
    "%02x%02x%02x%02x%02x%02x%02x%02x"   \
    "%02x%02x%02x%02x%02x%02x%02x%02x"   \
    "%02x%02x%02x%02x%02x%02x%02x%02x"

/**
 * @brief Helper macro to convert public key buffer to hex string.
 */
#define DPP_BOOTSTRAP_PUBLICKEY_HASH_TOSTRING(a)             \
    a[ 0], a[ 1], a[ 2], a[ 3], a[ 4], a[ 5], a[ 6], a[ 7],  \
    a[ 8], a[ 9], a[10], a[11], a[12], a[13], a[14], a[15],  \
    a[16], a[17], a[18], a[19], a[20], a[21], a[22], a[23],  \
    a[24], a[25], a[26], a[27], a[28], a[29], a[30], a[31]

/**
 * @brief Helper macro for printing a shortened (7-byte) public key hash as
 * hex.
 */
#define DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_FMT \
    "%02x%02x%02x%02x%02x%02x%02x"

/**
 * @brief Helper macro to convert a shortened (7-byte) public key buffer to hex
 * string.
 */
#define DPP_BOOTSTRAP_PUBLICKEY_HASH_SHORT_TOSTRING(a) \
    a[0], a[1], a[2], a[3], a[4], a[5], a[6]

/**
 * @brief WiFi Authentication and Key Management (AKM).
 */
enum dpp_akm {
    DPP_AKM_INVALID = 0,
    DPP_AKM_PSK,
    DPP_AKM_SAE,
    DPP_AKM_DPP,
    DPP_AKM_DOT1X,
    DPP_AKM_COUNT,
};

/**
 * @brief Converts a string to a wifi akm enumeration value.
 *
 * @param str
 * @return enum wifi_akm The wifi akm corresponding to the specified string, if
 * it exists. Otherwise, AKM_COUNT is returned.
 */
enum dpp_akm
parse_dpp_akm(const char *str);

/**
 * @brief Converts a dpp akm to a string.
 *
 * @param akm The akm to convert.
 * @return const char* A string representing the dpp akm.
 */
const char *
dpp_akm_str(enum dpp_akm akm);

/**
 * @brief DPP network discovery information.
 */
struct dpp_network_discovery {
    uint8_t ssid[DPP_SSID_LENGTH_MAX];
    size_t ssid_length;
    int32_t ssid_charset;
};

/**
 * @brief Type of data for pre-shared key (DPP_AKM_PSK) authentication.
 */
enum dpp_psk_credential_type {
    PSK_CREDENTIAL_TYPE_PSK,
    PSK_CREDENTIAL_TYPE_PASSPHRASE,
    PSK_CREDENTIAL_TYPE_INVALID
};

/**
 * @brief Parses a string and converts it to a dpp psk credential type.
 * 
 * @param str The strong to parse.
 * @return enum dpp_psk_credential_type The psk credential type corresponding
 * to the string.
 */
enum dpp_psk_credential_type
parse_dpp_psk_credential_type(const char *str);

/**
 * @brief Converts a dpp psk credential type to a string.
 * 
 * @param type The psk credential type to convert.
 * @return const char* A string representing the psk credential type.
 */
const char *
dpp_psk_credential_type_str(const enum dpp_psk_credential_type type);

/**
 * @brief Maximum length (bytes) of a pre-shared key (psk).
 */
#define DPP_PSK_LENGTH_MAX 32

/**
 * @brief Minimum length (ASCII characters) of a passphrase.
 */
#define DPP_PASSPHRASE_LENGTH_MIN 8

/**
 * @brief Maximum length (ASCII characters) of a passphrase.
 */
#define DPP_PASSPHRASE_LENGTH_MAX 63

/**
 * @brief Represents a PSK (raw) key.
 */
struct dpp_network_credential_psk_key {
    uint8_t buffer[DPP_PSK_LENGTH_MAX];
    char hex[(DPP_PSK_LENGTH_MAX * 2) + 1];
};

/**
 * @brief Represents a PSK (ascii) passphrase.
 */
struct dpp_network_credential_psk_passphrase {
    size_t length;
    char ascii[DPP_PASSPHRASE_LENGTH_MAX + 1];
    char hex[(DPP_PASSPHRASE_LENGTH_MAX * 2) + 1];
};

/**
 * @brief Credential type for pre-shared key (DPP_AKM_PSK) authentication.
 */
struct dpp_network_credential_psk {
    enum dpp_psk_credential_type type;
    union {
        struct dpp_network_credential_psk_passphrase passphrase;
        struct dpp_network_credential_psk_key key;
    };
};

/**
 * @brief Credential type for SAE (DPP_AKM_SAE) authentication. The
 * passphrase/password is similar to the one used for PSK, except does not have
 * length limits.
 */
struct dpp_network_credential_sae {
    char *passphrase;
    const char *passphrase_hex;
};

/**
 * @brief DPP network credential.
 */
struct dpp_network_credential {
    struct list_head list;
    enum dpp_akm akm;
    union {
        struct dpp_network_credential_psk psk;
        struct dpp_network_credential_sae sae;
    };
};

/**
 * @brief Allocates and initializes a new network credential object. The initial state describes an invalid network credential. It must be filled in to be made valid.
 *
 * @return struct dpp_network_credential*
 */
struct dpp_network_credential *
dpp_network_credential_alloc(void);

/**
 * @brief Sets a passphrase for the credential.
 * 
 * @param credential The psk credential to set the passphrase for.
 * @param passphrase The passphrase to set.
 * @return int 0 if the passphrase was successfully set. -ERANGE is the
 * passphrase was outside of the allowed bounds for the passphrase.
 */
int
dpp_credential_psk_set_passphrase(struct dpp_network_credential_psk *credential, const char *passphrase);

/**
 * @brief Sets a pre-shared key for the credential.
 * 
 * @param credential The psk credential to set the psk for.
 * @param key_hex The hex encoded pre-shared key.
 * @return int 0 if the key was successfully set. -ERANGE if the key was
 * outside of the allowed bounds.
 */
int
dpp_credential_psk_set_key(struct dpp_network_credential_psk *credential, const char *key_hex);

/**
 * @brief Sets a passphrase for the credential.
 * 
 * @param credential The sae credential to set the passphrase for.
 * @param passphrase The passphrase to set. 
 * @return int 0 if the passphrase was successfully set, non-zero otherwise.
 */
int
dpp_credential_sae_set_passphrase(struct dpp_network_credential_sae *credential, const char *passphrase);

/**
 * @brief Determines if a network credential is valid.
 *
 * @param credential The credential to check.
 * @return true If the credential is valid.
 * @return false If the credential is invalid.
 */
bool
dpp_network_credential_is_valid(const struct dpp_network_credential *credential);

/**
 * @brief Uninitializes a dpp network credential, releasing any owned resources.
 *
 * @param credential The credential to uninitialize.
 */
void
dpp_network_credential_uninitialize(struct dpp_network_credential *credential);

/**
 * @brief DPP network configuration.
 */
struct dpp_network {
    struct dpp_network_discovery discovery;
    struct list_head credentials;
};

/**
 * @brief Allocates and initializes a new dpp network object.
 *
 * @return struct dpp_network
 */
struct dpp_network *
dpp_network_alloc(void);

/**
 * @brief Uninitializes a dpp network, releasing any owned resources. If the
 * network is part of a list, it is removed from that list.
 *
 * @param network The network to uninitialize.
 */
void
dpp_network_uninitialize(struct dpp_network *network);

/**
 * @brief Adds a new credential to the network.
 * 
 * @param network The network to add the credential to.
 * @param credential The credential to add.
 */
void
dpp_network_add_credential(struct dpp_network *network, struct dpp_network_credential *credential);

/**
 * @brief Determines if a DPP network structure is valid.
 *
 * @param network The network to validate.
 * @return true If the network described is valid.
 * @return false Otherwise.
 */
bool
dpp_network_is_valid(const struct dpp_network *network);

#endif //__DPP_H__
