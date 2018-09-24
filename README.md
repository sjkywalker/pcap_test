# Pcap test

This program parses network packets of given interface and displays the contents: A simplified CLI Wireshark

## Getting started

### Overview

* Receive packets and analyze, display contents.

### Program Flow

```txt
1. Receive network packets
2. Parse
3. Display
```

The following data is retrieved.

```txt
* eth.smac, eth.dmac
* ip.sip, ip.dip
* tcp.sport, tcp.dport
* data (max. of 32 bytes)
```

*Any 'non-TCP/IP' packet is omitted.*

### Development Environment

```bash
$ uname -a
Linux ubuntu 4.15.0-30-generic #32~16.04.1-Ubuntu SMP Thu Jul 26 20:25:39 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

$ g++ --version
g++ (Ubuntu 5.4.0-6ubuntu1~16.04.10) 5.4.0 20160609
```

### Prerequisites

This program includes the following headers. Make sure you have the right packages.

```c
#include <pcap.h>
#include <libnet.h>
```

Install with the following commands.

```bash
sudo apt install libpcap-dev
sudo apt install libnet-dev
```

## Running the program

### Build

Simply hit 'make' to create object files and executable.

```bash
make
```

### Run

Format

```bash
./pcap_test <interface>
```

Example

```bash
./pcap_test eth0
```

You might need root priviledges to capture network packets.

## Acknowledgements

* [Simple pcap programming](https://gitlab.com/gilgil/network/wikis/ethernet-packet-dissection/pcap-programming)
* [libnet api](https://github.com/korczis/libnet)
* [Winpcap user's manual](https://www.winpcap.org/docs/docs_40_2/html/group__wpcap.html)
* [Winpcap user's manual - def](https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__def.html)

## Authors

* **James Sung** - *Initial work* - [sjkywalker](https://github.com/sjkywalker)
* Copyright © 2018 James Sung. All rights reserved.

