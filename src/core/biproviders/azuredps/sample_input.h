
#ifndef __SAMPLE_INPUT_H__
#define __SAMPLE_INPUT_H__

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include "../bootstrap_info_provider.h"
#include "bootstrap_info_provider_azure_dps.h"

const struct {
    const char *service_endpoint_uri = "https://wifiztp.azure-devices-provisioning.net";
    const char *dps_api_version = "2019-03-31";
} sample_dps_settings;

extern const struct dpp_bootstrap_publickey_hash sample_hash;
extern const struct bootstrap_info_query sample_query;

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__SAMPLE_INPUT_H__
