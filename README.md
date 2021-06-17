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
