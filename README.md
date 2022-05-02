# ICSNPP-Modbus

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Modbus.

## Overview

ICSNPP-Modbus is a Zeek package that extends the logging capabilities of Zeek's default Modbus protocol parser.

Zeek's default Modbus parser logs Modbus traffic to modbus.log. This log file remains unchanged. This package extends Modbus logging capability by adding three new Modbus log files:
* modbus_detailed.log
* modbus_mask_write_register.log
* modbus_read_write_multiple_registers.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-modbus
```

If you have ZKG configured to load packages (see @load packages in quickstart guide), this script will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If you are not using site/local.zeek or another site installation of Zeek and just want to run this script on a packet capture you can add `icsnpp-modbus` to your command to run this script on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-modbus.git
zeek -Cr icsnpp-modbus/tests/traces/modbus_example.pcap icsnpp-modbus
```

### Manual Install

To install this script manually, clone this repository and copy the contents of the scripts directory into `${ZEEK_INSTALLATION_DIR}/share/zeek/site/icsnpp-modbus`.

```bash
git clone https://github.com/cisagov/icsnpp-modbus.git
zeek_install_dir=$(dirname $(dirname `which zeek`))
cp -r icsnpp-modbus/scripts/ $zeek_install_dir/share/zeek/site/icsnpp-modbus
```

If you are using a site deployment, simply add echo `@load icsnpp-modbus` to your local.site file.

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp-modbus` to your command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-modbus/tests/traces/modbus_example.pcap icsnpp-modbus
```

## Logging Capabilities

### Detailed Modbus Field Log (modbus_detailed.log)

#### Overview

This log captures Modbus header and data fields and logs them to **modbus_detailed.log**.

This log file contains the functions (read/write), count, addresses, and values of Modbus coils, discrete inputs, input registers, and holding registers.

A "network_direction" meta-data field is also included in the log.  The "network_direction" column specifies whether the message was a *request* or a *response* message. 
If an exception arises in the Modbus data the exception code will be logged in the "values" field.

#### Fields Captured

| Field             | Type      | Description                                                       |
| ----------------- |-----------|-------------------------------------------------------------------|
| ts                | time      | Timestamp                                                         |
| uid               | string    | Unique ID for this connection                                     |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)                |
| uint_id           | count     | Modbus unit-id                                                    |
| func              | string    | Modbus function code                                              |
| network_direction | string    | Message network direction (request or response)                   |
| address           | count     | Starting address of value(s) field                                |
| quantity          | count     | Number of addresses/values read or written to                     |
| values            | string    | Value(s) of coils, discrete_inputs, or registers read/written to  |  


### Mask Write Register Log (modbus_mask_write_register.log)

#### Overview

This log captures the fields of the Modbus *mask_write_register* function (function code 0x16) and logs them to **modbus_mask_write_register.log**.

#### Fields Captured

| Field             | Type      | Description                                           |
| ----------------- |-----------|-------------------------------------------------------|
| ts                | time      | Timestamp                                             |
| uid               | string    | Unique ID for this connection                         |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)    |
| uint_id           | count     | Modbus unit-id                                        |
| func              | string    | Modbus function code                                  |
| network_direction | string    | Message network direction (request or response)       |
| address           | count     | Address of the target register                        |
| and_mask          | count     | Boolean 'and' mask to apply to the target register    |
| or_mask           | count     | Boolean 'or' mask to apply to the target register     |

### Read Write Multiple Registers Log (modbus_read_write_multiple_registers.log)

#### Overview

This log captures the fields of the Modbus *read/write multiple registers* function (function code 0x17) and logs them to **modbus_read_write_multiple_registers.log**.

#### Fields Captured

| Field                 | Type      | Description                                           |
| ----------------------|-----------|-------------------------------------------------------|
| ts                    | time      | Timestamp                                             |
| uid                   | string    | Unique ID for this connection                         |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)    |
| uint_id               | count     | Modbus unit-id                                        |
| func                  | string    | Modbus function code                                  |
| network_direction     | string    | Message network direction (request or response)       |
| write_start_address   | count     | Starting address of registers to be written           |
| write_registers       | string    | Register values written                               |
| read_start_address    | count     | Starting address of the registers to read             |
| read_quantity         | count     | Number of registers to read in                        |
| read_registers        | string    | Register values read                                  |

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/icsnpp-bsap)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a cutting edge research facility which is a constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2022 Battelle Energy Alliance, LLC

Licensed under the 3-Part BSD (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  https://opensource.org/licenses/BSD-3-Clause

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




Licensing
-----
This software is licensed under the terms you may find in the file named "LICENSE" in this directory.

You agree your contributions are submitted under the BSD-3-Clause license. You represent you are authorized to make the contributions and grant the license. If your employer has rights to intellectual property that includes your contributions, you represent that you have received permission to make contributions and grant the required license on behalf of that employer.
