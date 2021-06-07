
#include <iostream>

#include "azure_dps_service_client.h"
#include "azure_dps_service_client_log.h"
#include "sample_input.h"

int
main(int argc, char *argv[])
{
    if (argc != 3 && argc != 4) {
        tlog("USAGE: ./sample_cpp <connection_string> <service_endpoint_uri> [api_version]");
        tlog("service_endpoint_uri must start with https:// or http://");
        return 0;
    }

    struct bootstrap_info_provider_azure_dps_settings dps_settings = {
        /* .service_endpoint_uri = */ strdup(argv[2]),
        /*      .dps_api_version = */ strdup(argc == 4 ? argv[3] : sample_dps_settings.dps_api_version),
        /*        .authority_url = */ NULL,
        /*            .client_id = */ NULL,
        /*        .client_secret = */ NULL,
        /*         .resource_uri = */ NULL,
        /*    .connection_string = */ strdup(argv[1]),
    };

    tlog(dps_settings.service_endpoint_uri);

    auto session = std::make_unique<azure_dps_service_client>(&dps_settings);

    int ret = session->synchronize_dps_bi();
    tlog("synchronize_dps_bi() returned " << ret);

    free(dps_settings.service_endpoint_uri);
    free(dps_settings.dps_api_version);
    free(dps_settings.connection_string);

    return 0;
}