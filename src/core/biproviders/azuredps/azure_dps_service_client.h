
#ifndef __AZURE_DPS_SERVICE_CLIENT_H__
#define __AZURE_DPS_SERVICE_CLIENT_H__

#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <cpprest/http_client.h>
#include <cpprest/oauth2.h>

/**
 * @brief Azure DPS service client object. Provides functionality for
 * interacting with the Azure DPS service, wrapping use of its REST API into a
 * C++ class.
 */
class azure_dps_service_client
{
public:
    /**
     * @brief Construct a new azure dps service client::azure dps service client object.
     * 
     * @param settings The settings to use to instantiate the object.
     */
    azure_dps_service_client(const struct bootstrap_info_provider_azure_dps_settings* settings);
    ~azure_dps_service_client() = default;

    /**
     * @brief Retrieve an oauth2 token for use with the DPS service.
     * 
     * @return int 0 if a valid oauth2 token was obtained and stored in the http
     * client configuration member object. Otherwise, a negtative error code is
     * returned.
     */
    int
    authorize(void);

    /**
     * @brief Synchronizes the local view of device records with the remote view.
     * This will download all new records from the dps instance and save them
     * locally.
     * 
     * @return int 0 if the local view was successfully synchronized, non-zero otherwise.
     */
    int
    synchronize_dps_bi(void);

    /**
     * @brief Finds the DPP URI matching the specified chirp hash.
     * 
     * @param chirp_hash The chirp hash of the public bootstrapping key.
     * @param matching_dpp_uri Output argument to hold the DPP URI matching the chirp hash.
     * @return int 0 if a matching device bootstrap information device records has
     * a public bootstrapping key whose chirp hash matches. Otherwise -1 is
     * returned.
     */
    int
    lookup_dpp_uri(const std::string& chirp_hash, std::string& matching_dpp_uri) const;

    /**
     * @brief Indicates whether SAS-token based authentication is used.
     * 
     * @return true If SAS-token based authentication is being used.
     * @return false If SAS-token based authentication is not being used.
     */
    bool
    using_sas_token() const;

private:
    std::string m_dps_url;
    web::http::client::http_client_config m_config;
    std::string m_sas_token;
    std::optional<std::string> m_connection_string;

    struct device_bi {
        std::string chirp_hash;
        std::string dpp_uri;
    };

    std::vector<device_bi> m_device_bootstrapping_info;

protected:
    /**
     * @brief Extracts dps device group names from the json result obtained from a device group query.
     * 
     * @param json_body The json contents returned from a dps device group query.
     * @return std::vector<std::string> 
     */
    static std::vector<std::string>
    extract_device_records(web::json::value json_body);

    /**
     * @brief Extracts device bootstrapping information from the device record json
     * content returned from a dps device record query.
     * 
     * @param device_records_json The json returned from a dps device record query.
     * @return std::vector<azure_dps_service_client::device_bi> 
     */
    static std::vector<device_bi>
    extract_device_bootstrapping_info(web::json::value device_records_json);
};

#endif //__AZURE_DPS_SERVICE_CLIENT_H__
