# Wi-Fi Zero Touch Provisioning (ZTP)

![ZTP Penguin](docs/ztppenguin.png)

This project provides a Wi-Fi zero touch provisioning library and daemon for Linux. It supports provisioning of Wi-Fi credentials using [Wi-Fi Easy Connect](https://www.wi-fi.org/discover-wi-fi/wi-fi-easy-connect), also known as the Device Provisioning Protocol (DPP).

## Building

### Ubuntu (focal)

Install package dependencies:

```bash
sudo apt install build-essential cmake git libboost-filesystem-dev libboost-random-dev libboost-regex-dev libboost-system-dev libboost-thread-dev libbrotli-dev libgpiod-dev libjson-c-dev libssl-dev libsystemd-dev pkg-config zlib1g-dev
```

Checkout and build:

```bash
git clone git@github.com:microsoft/wifi-ztp.git
cd wifi-ztp
mkdir build && cd $_
cmake ..
make -j $(nproc)
```

## Usage

The daemon usage is driven primarily by configuration files whose path is passed
to the daemon as a command line flag. The daemon accepts the following command
line flags:

| Flag | Presence     | Description                        | Supported Values                                | Examples                   |
|------|--------------|------------------------------------|-------------------------------------------------|----------------------------|
| `-c` | **Required** | Configuration file path            | Absolute path to the primary configuration file | `-c /etc/ztpd/config.json` |
| `-d` | Optional     | Daemonize flag (run in background) | None (unary flag)                               | `-d`                       |

### Configuration files

#### Primary configuration file

This file controls global daemon options, including the Wi-Fi EasyConnect device
roles (enrollee, configurator) that are supported and activated. For each of
these roles, a separate configuration file is specified by providing its absolute path. Each configuration file option is specified in [config.json.schema](/samples/ztpd/config/config.schema.json), and an example configuration file can be found [here](/samples/ztpd/config/config.json).

#### Enrollee configuration file

When the primary configuration file specifies that the Wi-Fi EasyConnect `enrollee` device role is supported, it also specifies its configuration file. This file describes enrollee options, including information about the bootstrapping key. Each configuration file option is specified in [config-enrollee.schema.json](samples/ztpd/config/config-enrollee.schema.json), and an example configuration file can be found [here](/samples/ztpd/config/config-enrollee.json).

#### Configurator configuration file

When the primary configuration file specifies that the Wi-Fi EasyConnect `configurator` device role is supported, it also specifies its configuration file. This file describes configurator options, including information regarding enrollee bootstrapping information. Each configuration file option is specified in [config-enrollee.schema.json](samples/ztpd/config/config-configurator.schema.json), and an example configuration file can be found [here](/samples/ztpd/config/config-configurator.json). Enrollee bootstrapping information is provided by _bootstrapping information providers (BIPs)_, which are specified in the configuration file. Currently, there are two built-in providers:

##### Azure Device Provisioning Service (DPS)

This bootstrapping information provider sources enrollee bootstrapping records from an [Azure Device Provisioning Service (DPS)](https://docs.microsoft.com/en-us/azure/iot-dps/about-iot-dps) instance. The bootstrapping information is contained in device records under a top-level object property called `optionalDeviceInformation`. The object structure expected is as follows:

```json
"optionalDeviceInformation": {
    "ZeroTouchProvisioning": {
        "WiFi": {
            "Interfaces": [
                {
                    "DppUri": "DPP:V:2;M:d8c0a65935ed;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACE0vdn8KsfXKHusJPcEscx+naQyQJLSob1VjuqPsP6r8=;;"
                },
                {
                    "DppUri": "DPP:V:2;M:70665509b591;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACiLN+2Rk4tRlwl4CKYkSEdheJIEbZO5UBr9SPoPFI394=;;"
                }
            ]
        }
    }
}
```

Each supported wireless interface can be specified and must contain a child property with key `DppUri`. The value is a string describing a valid Device Provisioning Protocol (DPP, EasyConnect) URI for an enrollee device.

The provider will periodically retrieve the device records from the instance and cache them in a local view. Each provider can optionally define the DPS instance record expiration time. The daemon will consider the local device record view as consistent with the remote instance view until the expiry time elapses, at which point the local view will be re-synchronized.

##### File

This bootstrapping information provider sources enrollee bootstrapping records from a json-formatted file. It may be configured to point to the enrollee bootstrapping records using [json pointers](https://datatracker.ietf.org/doc/html/rfc6901). The example configuration file shows an example of this provider where the file [config-bootstrapinfo.json](samples/ztpd/config/config-bootstrapinfo.json) contains the enrollee records, amongst other unrelated information.

This bootstrap provider is not meant to scale to a large number of records. It is meant more for small scale deployments or for testing and debugging purposes.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [https://cla.opensource.microsoft.com](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
