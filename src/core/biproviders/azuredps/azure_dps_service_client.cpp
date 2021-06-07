
#include <algorithm>
#include <cerrno>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <thread>
#include <vector>

#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <cpprest/oauth2.h>
#include <cpprest/uri.h>
#include <openssl/evp.h>

extern "C" {
#include "bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps.h"
}

#include "azure_dps_service_client.h"
#include "azure_dps_service_client_log.h"
#include "string_utils.hpp"

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::details;
using namespace web::http::oauth2::experimental;

const std::string dps_api_version = "2021-06-01";

/**
 * @brief Free function implementing case-insensitive string comparison.
 * 
 * @param s1 The first string to compare.
 * @param s2 The second string to compare.
 * @return true If the first and second string contain the same letters in the same order in any case.
 * @return false If the first and second strings differ in size or ordering of letters.
 */
static bool
string_iequals(const std::string& s1, const std::string& s2)
{
    return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char c1, char c2) {
        return std::tolower(static_cast<unsigned char>(c1)) == std::tolower(static_cast<unsigned char>(c2));
    });
}

/**
 * @brief Logs an http request.
 * 
 * @param request The request to log.
 */
static void
log_http_request(const http_request& request)
{
    tlog(request.method() << " " << request.relative_uri().to_string() << " " << request.http_version().to_utf8string());
}

/**
 * @brief Constructs an http request object for querying an azure dps instance
 * for individual device records.
 * 
 * @return http_request 
 */
static http_request
build_device_records_query_request(const std::string& SAS_token)
{
    http::uri_builder encoded_uri("/enrollments/query");
    encoded_uri.append_query("api-version", dps_api_version);

    http_request request(methods::POST);
    request.set_request_uri(encoded_uri.to_uri());
    request.headers().add(header_names::content_type, mime_types::application_json);
    request.headers().add(header_names::authorization, SAS_token);
    request.set_body("{\"query\":\"*\"}");

    return request;
}

/**
 * @brief Indicates whether SAS-token based authentication is used.
 * 
 * @return true If SAS-token based authentication is being used.
 * @return false If SAS-token based authentication is not being used.
 */
bool
azure_dps_service_client::using_sas_token() const
{
    return bool(m_connection_string);
}

/**
 * @brief Construct a new azure dps service client::azure dps service client object.
 * 
 * @param settings The settings to use to instantiate the object.
 */
azure_dps_service_client::azure_dps_service_client(const struct bootstrap_info_provider_azure_dps_settings* settings) :
    m_dps_url(settings->service_endpoint_uri)
{
    if (strlen(settings->connection_string))
        m_connection_string = settings->connection_string;
    else {
        m_config.set_oauth2(oauth2_config(
            settings->client_id,      // client key
            settings->client_secret,  // client secret
            U(""),                    // auth_endpoint
            settings->authority_url,  // token_endpoint
            U(""),                    // redirect_url
            settings->resource_uri)); // scope
    }
}

/**
 * @brief Parses the connection string and writes the parsed values to hostname,
 * shared_access_key_name, shared_access_key.
 * 
 * @param connection_string The connection string to parse.
 * @param hostname The hostname of the target system.
 * @param shared_access_key_name The name of the shared access key to use.
 * @param shared_access_key The shared access key value.
 */
static int
parse_connection_string(const std::string& connection_string, std::string& hostname, std::string& shared_access_key_name, std::string& shared_access_key)
{
    std::string key;
    std::stringstream tokens(connection_string);
    std::unordered_map<std::string, std::string> results;

    static const std::array<std::string, 3> keynames = {
        "HostName",
        "SharedAccessKeyName",
        "SharedAccessKey",
    };

    std::string token;

    for (const auto& keyname : keynames) {
        if (std::getline(tokens, token, '=')) {
            key = trim_copy(token);
            if (key == keyname) {
                std::getline(tokens, token, ';');
                results[key] = trim_copy(token);
            } else
                return -1;
        } else
            return -1;
    }

    try {
        hostname = results[keynames[0]];
        shared_access_key_name = results[keynames[1]];
        shared_access_key = results[keynames[2]];
    } catch (...) {
        return -1;
    }

    return 0;
}

/**
 * @brief Constructs a SAS token given a connection string, and saves it to 'sas_token'.
 * 
 * @param connection_string The connection string.
 * @param sas_token The destination to write the sas token to.
 * @param expiry_seconds The amount of time in seconds the SAS token will be valid [default=90].
 * 
 * @return int 0 If the connection string can be properly parsed and the 
 * SAS token formed. Otherwise, -1 is returned.
 */
static int
gen_sas_token(const std::string& connection_string, std::string& sas_token, int expiry_seconds = 90)
{
    std::string hostname;
    std::string sharedaccesskeyname;
    std::string sharedaccesskey;

    int ret = parse_connection_string(connection_string, hostname, sharedaccesskeyname, sharedaccesskey);
    if (ret < 0) {
        tlog("connection string is invalid, could not form sas token");
        return -1;
    }

    time_t expiry_time = time(0) + ((time_t)expiry_seconds);

    std::string hostname_url = web::uri::encode_data_string(hostname);
    std::string string_to_sign = hostname_url + "\n" + std::to_string(expiry_time);

    //EVP_DecodeBlock outputs 3 bytes for every 4 in the input, rounded up
    std::size_t decodedkey_len = ((sharedaccesskey.length() + 3) / 4) * 3;
    std::vector<unsigned char> decodedkey_buffer(decodedkey_len + 1);

    ret = EVP_DecodeBlock(decodedkey_buffer.data(),
        (const unsigned char*)sharedaccesskey.c_str(),
        (int)sharedaccesskey.length());
    if (ret == -1)
        return ret;

    unsigned int digest_len = 0;
    unsigned char* digest = HMAC(EVP_sha256(),
        decodedkey_buffer.data(),
        (int)decodedkey_len,
        (const unsigned char*)string_to_sign.c_str(),
        string_to_sign.length(),
        0,
        &digest_len);

    //EVP_EncodeBlock outputs 4 bytes for every 3 in the input, rounded up
    std::vector<unsigned char>::size_type signature_len = ((digest_len + 2) / 3) * 4;
    std::vector<unsigned char> signature(signature_len + 1);

    ret = EVP_EncodeBlock(signature.data(),
        (const unsigned char*)digest,
        static_cast<int>(digest_len));
    if (ret == -1)
        return ret;

    std::string signature_url_encoded =
        web::uri::encode_data_string(std::string(signature.begin(), signature.end() - 1));

    std::string sas_string = std::string("sr=") + hostname_url
                           + std::string("&sig=") + signature_url_encoded
                           + std::string("&se=")  + std::to_string(expiry_time)
                           + std::string("&skn=") + sharedaccesskeyname;

    sas_token = std::string("SharedAccessSignature ") + sas_string;

    return ret;
}

/**
 * @brief Retrieve an oauth2 token for use with the DPS service.
 * 
 * @return int 0 if a valid oauth2 token was obtained and stored in the http
 * client configuration member object. Otherwise, a negtative error code is
 * returned.
 */
int
azure_dps_service_client::authorize(void)
{
    static constexpr std::size_t auth_check_timeout_ms = 3'000;

    int ret;
    try {
        m_config.set_timeout(std::chrono::milliseconds(auth_check_timeout_ms));
        m_config.oauth2()->token_from_client_credentials().get();
        tlog("acquired dps oauth2 token, expires in " << m_config.oauth2()->token().expires_in() << " seconds");
        ret = 0;
    } catch (const pplx::task_canceled&) {
        tlog("timed out waiting for dps authentication to complete (" << auth_check_timeout_ms << " ms)");
        ret = -ETIMEDOUT;
    } catch (const std::exception& e) {
        tlog("exception occurred while acquiring oauth2 token :(");
        tlog(e.what());
        ret = -EINTR;
    }

    if (!m_config.oauth2()->token().is_valid_access_token()) {
        tlog("oauth2 token invalid! oauth2_config->state() = " << m_config.oauth2()->state());
        if (ret == 0)
            ret = -EPERM;
    } else
        tlog("The token is valid " << m_config.oauth2()->token().access_token());

    return ret;
}

/**
 * @brief Synchronizes the local view of device records with the remote view.
 * This will first get a new sas token. Then this will download all new records from the dps instance and save them
 * locally.
 * 
 * @return int 0 if the local view was successfully synchronized, non-zero
 * otherwise.
 */
int
azure_dps_service_client::synchronize_dps_bi(void)
{
    static constexpr std::size_t http_request_timeout_ms = 5'000;

    if (using_sas_token()) {
        int ret = gen_sas_token(*m_connection_string, m_sas_token);
        if (ret < 0) {
            tlog("something went wrong in creating sas token");
            return ret;
        }
    } else if (!m_config.oauth2()->token().is_valid_access_token()) {
        int ret = authorize();
        if (ret < 0) {
            tlog("failed to renew expired dps oauth2 token (%d)" << ret);
            return ret;
        }
    }

    m_config.set_timeout(std::chrono::milliseconds(http_request_timeout_ms));
    http_client api(m_dps_url, m_config);

    auto device_bootstrapping_info_old = std::move(m_device_bootstrapping_info);
    m_device_bootstrapping_info.clear();

    json::value device_records_json;

    {
        http_request request = build_device_records_query_request(m_sas_token);
        pplx::task<http_response> task_request = api.request(request);
        log_http_request(request);

        try {
            http_response response = task_request.get();
            device_records_json = response.extract_json().get();
        } catch (const pplx::task_canceled&) {
            tlog("timed out waiting for dps device group query to complete (" << http_request_timeout_ms << " ms)");
            return -ETIMEDOUT;
        } catch (const std::exception& e) {
            tlog("exception caught in device group query request task");
            tlog(e.what());
            return -EINTR;
        }
    }

    std::vector<device_bi> device_bi_list = extract_device_bootstrapping_info(device_records_json);

    m_device_bootstrapping_info.insert(m_device_bootstrapping_info.end(),
        std::make_move_iterator(std::begin(device_bi_list)),
        std::make_move_iterator(std::end(device_bi_list)));

    int32_t changed = int32_t(m_device_bootstrapping_info.size()) - int32_t(device_bootstrapping_info_old.size());
    if (changed != 0)
        tlog(std::showpos << changed << " records");
    return 0;
}

/**
 * @brief Finds the DPP URI matching the specified chirp hash.
 * 
 * @param chirp_hash The chirp hash of the public bootstrapping key.
 * @param matching_dpp_uri Output argument to hold the DPP URI matching the chirp hash.
 * @return int 0 if a matching device bootstrap information device record has
 * a public bootstrapping key whose chirp hash matches. Otherwise -1 is
 * returned.
 */
int
azure_dps_service_client::lookup_dpp_uri(const std::string& chirp_hash, std::string& matching_dpp_uri) const
{
    const auto match = std::find_if(m_device_bootstrapping_info.cbegin(), m_device_bootstrapping_info.cend(), [&](const device_bi& bi_instance) {
        return string_iequals(bi_instance.chirp_hash, chirp_hash);
    });

    if (match != m_device_bootstrapping_info.cend()) {
        matching_dpp_uri = match->dpp_uri;
        return 0;
    }

    return -1;
}

/**
 * @brief Calculates the "chirp" hash of a DPP bootstrapping key.
 * 
 * @param dpp_bootstrapping_key_base64 The encoded public key derived from the DPP
 * URI. Specifically, the string must describe the DER of an ASN.1
 * SubjectPublicKeyInfo, encoded as base64. See section 4.1 'Public Keys' of
 * the Wi-Fi Alliance Device Provisioning Protocol (DPP) Specification for more
 * details.
 * 
 * @return std::vector<uint8_t>
 */
static std::vector<uint8_t>
calculate_chirp_hash(const std::string& dpp_bootstrapping_key_base64)
{
    static const char chirp_prefix[] = "chirp";
    static constexpr std::size_t dpp_bootstrapping_key_base64_max = 4096;

    std::vector<uint8_t> chirp_hash(SHA256_DIGEST_LENGTH);
    uint8_t dpp_bootstrap_key_pub[dpp_bootstrapping_key_base64_max];
    const uint8_t* dpp_bootstrap_key_buffer = reinterpret_cast<const uint8_t*>(dpp_bootstrapping_key_base64.c_str());
    int dpp_bootstrap_key_pub_length = EVP_DecodeBlock(dpp_bootstrap_key_pub, dpp_bootstrap_key_buffer, (int)dpp_bootstrapping_key_base64.length());
    if (dpp_bootstrap_key_pub_length < 0) {
        tlog("failed to base64-decode dpp public key");
        return chirp_hash;
    }

    EVP_MD_CTX* chirp_hash_context;
    chirp_hash_context = EVP_MD_CTX_new();
    if (chirp_hash_context == nullptr) {
        tlog("failed to allocate openssl sha256 evp hash context");
        return chirp_hash;
    }

    unsigned chirp_hash_length;
    EVP_DigestInit(chirp_hash_context, EVP_sha256());
    EVP_DigestUpdate(chirp_hash_context, chirp_prefix, sizeof chirp_prefix - 1);
    EVP_DigestUpdate(chirp_hash_context, dpp_bootstrap_key_pub, static_cast<size_t>(dpp_bootstrap_key_pub_length) - 1);
    EVP_DigestFinal(chirp_hash_context, chirp_hash.data(), &chirp_hash_length);

    if (chirp_hash.size() != chirp_hash_length)
        chirp_hash.resize(chirp_hash_length);

    return chirp_hash;
}

/**
 * @brief Extracts the public bootstrapping key encoding from the DPP URI. Note
 * that the extracted key is a DER ASN.1 SubjectPublicKeyInfo object encoded as
 * base64.
 * 
 * @param dpp_uri The DPP URI to parse.
 * @return std::string A string containing the public key, if one was found and
 * valid. Otherwise and empty string is returned.
 */
static std::string
extract_bootstrapping_key_from_dpp_uri(const std::string& dpp_uri)
{
    std::size_t start = dpp_uri.find("K:");
    if (start != std::string::npos) {
        start += 2;
        std::size_t end = dpp_uri.find(';', start);
        if (end != std::string::npos)
            return dpp_uri.substr(start, end - start);
    }

    return "";
}

/**
 * @brief Convert a buffer to its hex string representation.
 * 
 * @param buffer The buffer to convert.
 * @return std::string A string containing the hex representation of the buffer.
 */
static std::string
buffer_to_hex_string(const std::vector<uint8_t>& buffer)
{
    std::stringstream output;
    output << std::hex << std::setfill('0');

    for (const auto& byte_value : buffer) {
        output << std::setw(2) << static_cast<uint32_t>(byte_value);
    }

    return output.str();
}

/**
 * @brief Extracts device bootstrapping information from the device record json
 * content returned from a dps device record query.
 * 
 * @param device_records_json The json returned from a dps device record query.
 * @return std::vector<azure_dps_service_client::device_bi> 
 */
std::vector<azure_dps_service_client::device_bi>
azure_dps_service_client::extract_device_bootstrapping_info(json::value device_records_json)
{
    auto& device_records = device_records_json.as_array();
    std::vector<device_bi> extracted_device_bootstrapping_info;

    for (json::value& device_record : device_records) {
        try {
            json::array& interfaces_array = device_record.as_object()["optionalDeviceInformation"]["ZeroTouchProvisioning"]["WiFi"]["Interfaces"].as_array();
            const json::value& dpp_uri = interfaces_array[0].as_object()["DppUri"];

            const auto& dpp_uri_string = dpp_uri.as_string();
            const auto dpp_bootstrap_key = extract_bootstrapping_key_from_dpp_uri(dpp_uri_string);
            const auto dpp_chirp = calculate_chirp_hash(dpp_bootstrap_key);
            const auto dpp_chirp_string = buffer_to_hex_string(dpp_chirp);

            tlog(" " << dpp_chirp_string.substr(0, 7) << " -> " << dpp_uri_string);

            extracted_device_bootstrapping_info.push_back({ dpp_chirp_string, dpp_uri_string });
        } catch (const std::exception& e) {
            tlog("Invalid device_record object!");
            tlog(e.what());
        }
    }

    return extracted_device_bootstrapping_info;
}
