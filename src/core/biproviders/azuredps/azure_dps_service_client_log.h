
#ifndef __AZURE_DPS_SERVICE_CLIENT_LOG_H__
#define __AZURE_DPS_SERVICE_CLIENT_LOG_H__

#include <iostream>

#include "ztp_log.h"

#define tlog(x) std::cout << SYSTEMD_LOG_PRIORITY_DEBUG << x << std::endl

#endif //__AZURE_DPS_SERVICE_CLIENT_LOG_H__