# ICSNPP-Modbus

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Modbus.

## Overview

ICSNPP-Modbus is a Zeek package that extends the logging capabilities of Zeek's default Modbus protocol parser.

Zeek's default Modbus parser logs Modbus traffic to modbus.log. This log file remains unchanged. This package extends Modbus logging capability by adding four new Modbus log files:
* modbus_detailed.log
* modbus_mask_write_register.log
* modbus_read_write_multiple_registers.log
* modbus_read_device_identification.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-modbus
```

If ZKG is configured to load packages (see @load packages in quickstart guide), this script will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If users are not using site/local.zeek or another site installation of Zeek and want to run this script on a packet capture, they can add `icsnpp-modbus` to the command to run this script on the packet capture:

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

If using a site deployment, simply add echo `@load icsnpp-modbus` to the local.site file.

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add `icsnpp-modbus` to the command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-modbus/tests/traces/modbus_example.pcap icsnpp-modbus
```

## Logging Capabilities

### Detailed Modbus Field Log (modbus_detailed.log)

#### Overview

This log captures Modbus header and data fields and logs them to **modbus_detailed.log**.

This log file contains the functions (read/write), count, addresses, and values of Modbus coils, discrete inputs, input registers, and holding registers.

A "network_direction" meta-data field is also included in the log.  The "network_direction" column specifies whether the message was a *request* or a *response* message. 
If an exception arises in the Modbus data, the exception code will be logged in the "values" field.

#### Fields Captured

| Field                     | Type              | Description                                                       |
| ------------------------- |-------------------|-------------------------------------------------------------------|
| ts                        | time              | Timestamp                                                         |
| uid                       | string            | Unique ID for this connection                                     |
| id                        | conn_id           | Zeek connection struct (addresses and ports)                      |            
| tid                       | count             | Modbus transaction identifier                                     |
| unit                      | count             | Modbus terminal unit identifier                                   | 
| func                      | string            | Modbus function code                                              |                                       
| address                   | count             | Starting address of response_counts or request_counts field       |
| quantity                  | count             | Number of coils, discrete_inputs, or registers read or written to |
| request_values            | vector of count   | Value(s) of coils, discrete_inputs, or registers in the request   |
| response_values           | vector of count   | Value(s) of coils, discrete_inputs, or registers in the response  |
| modbus_detailed_link_id   | string            | This is a unique identifier that links to other detailed logs     | 
| matched                   | bool              | States if information is from matching request/response packets   |
| request_subfunction_code  | string            | Diagnostic subfunction code in the request                        |
| response_subfunction_code | string            | Diagnostic subfunction code in the request                        |
| request_data              | string            | Any additional data or padding in the request                     |
| response_data             | string            | Any additional data or padding in the response                    |
| exception_code            | string            | Exception code in the response                                    |
| mei_type                  | string            | MEI Type in the encap interface transport                         |

### Mask Write Register Log (modbus_mask_write_register.log)        

#### Overview

This log captures the fields of the Modbus *mask_write_register* function (function code 0x16) and logs them to **modbus_mask_write_register.log**.

#### Fields Captured

| Field                     | Type      | Description                                                       |
| ------------------------- |-----------|-------------------------------------------------------------------|
| ts                        | time      | Timestamp                                                         |
| uid                       | string    | Unique ID for this connection                                     |
| id                        | conn_id   | Default Zeek connection info (IP addresses, ports)                |
| is_orig                   | bool      | True if the packet is sent from the originator                    |
| source_h                  | address   | Source IP address (see *Source and Destination Fields*)           |
| source_p                  | port      | Source port (see *Source and Destination Fields*)                 |
| destination_h             | address   | Destination IP address (see *Source and Destination Fields*)      |
| destination_p             | port      | Destination port (see *Source and Destination Fields*)            |
| modbus_detailed_link_id   | string    | This is a unique identifier that links to other detailed logs     |
| tid                       | count     | Modbus transaction identifier                                     |
| uint                      | count     | Modbus terminal unit identifier                                   |
| func                      | string    | Modbus function code                                              |
| request_response          | string    | REQUEST or RESPONSE                                               |
| address                   | count     | Address of the target register                                    |
| and_mask                  | count     | Boolean 'and' mask to apply to the target register                |
| or_mask                   | count     | Boolean 'or' mask to apply to the target register                 |

### Read Write Multiple Registers Log (modbus_read_write_multiple_registers.log)

#### Overview

This log captures the fields of the Modbus *read/write multiple registers* function (function code 0x17) and logs them to **modbus_read_write_multiple_registers.log**.

#### Fields Captured

| Field                     | Type      | Description                                                   |
| --------------------------|-----------|---------------------------------------------------------------|
| ts                        | time      | Timestamp                                                     |
| uid                       | string    | Unique ID for this connection                                 |
| id                        | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig                   | bool      | True if the packet is sent from the originator                |
| source_h                  | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p                  | port      | Source port (see *Source and Destination Fields*)             |
| destination_h             | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p             | port      | Destination port (see *Source and Destination Fields*)        |
| modbus_detailed_link_id   | string    | This is a unique identifier that links to other detailed logs |
| tid                       | count     | Modbus transaction identifier                                 |
| uint                      | count     | Modbus terminal unit identifier                               |
| func                      | string    | Modbus function code                                          |
| request_response          | string    | REQUEST or RESPONSE                                           |
| write_start_address       | count     | Starting address of registers to be written                   |
| write_registers           | string    | Register values written                                       |
| read_start_address        | count     | Starting address of the registers to read                     |
| read_quantity             | count     | Number of registers to read in                                |
| read_registers            | string    | Register values read                                          |


### Read Device Identification Log (modbus_read_device_identification.log)

#### Overview

This log captures the fields of the Modbus *encapsulated interface transport* function (function code 0x2B) when the MEI type is set to 14 (0x0E) and logs them to **modbus_read_device_identification.log**.

Note: this log is only produced in Zeek versions 6.1 and above
 
#### Fields Captured

| Field                     | Type      | Description                                                   |
| --------------------------|-----------|---------------------------------------------------------------|
| ts                        | time      | Timestamp                                                     |
| uid                       | string    | Unique ID for this connection                                 |
| id                        | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig                   | bool      | True if the packet is sent from the originator                |
| source_h                  | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p                  | port      | Source port (see *Source and Destination Fields*)             |
| destination_h             | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p             | port      | Destination port (see *Source and Destination Fields*)        |
| modbus_detailed_link_id   | string    | This is a unique identifier that links to other detailed logs |
| tid                       | count     | Modbus transaction identifier                                 |
| uint                      | count     | Modbus terminal unit identifier                               |
| func                      | string    | Modbus function code                                          |
| request_response          | string    | REQUEST or RESPONSE                                           |
| mei_type                  | string    | MEI Type - Always READ-DEVICE-IDENTIFICATION                  |
| conformity_level_code     | string    | Conformity Level Code                                         |
| conformity_level          | string    | Conformity Level                                              |
| device_id_code            | count     | Device ID Code                                                |
| object_id_code            | string    | Object ID Code                                                |
| object_id                 | string    | Object ID                                                     |
| object_value              | string    | Object Value                                                  |

### Source and Destination Fields

#### Overview

Zeek's typical behavior is to focus on and log packets from the originator and not log packets from the responder. However, most ICS protocols contain useful information in the responses, so the ICSNPP parsers log both originator and responses packets. Zeek's default behavior, defined in its `id` struct, is to never switch these originator/responder roles which leads to inconsistencies and inaccuracies when looking at ICS traffic that logs responses.

The default Zeek `id` struct contains the following logged fields:
* id.orig_h (Original Originator/Source Host)
* id.orig_p (Original Originator/Source Port)
* id.resp_h (Original Responder/Destination Host)
* id.resp_p (Original Responder/Destination Port)

Additionally, the `is_orig` field is a boolean field that is set to T (True) when the id_orig fields are the true originators/source and F (False) when the id_resp fields are the true originators/source.

To not break existing platforms that utilize the default `id` struct and `is_orig` field functionality, the ICSNPP team has added four new fields to each log file instead of changing Zeek's default behavior. These four new fields provide the accurate information regarding source and destination IP addresses and ports:
* source_h (True Originator/Source Host)
* source_p (True Originator/Source Port)
* destination_h (True Responder/Destination Host)
* destination_p (True Responder/Destination Port)

The pseudocode below shows the relationship between the `id` struct, `is_orig` field, and the new `source` and `destination` fields.

```
if is_orig == True
    source_h == id.orig_h
    source_p == id.orig_p
    destination_h == id.resp_h
    destination_p == id.resp_p
if is_orig == False
    source_h == id.resp_h
    source_p == id.resp_p
    destination_h == id.orig_h
    destination_p == id.orig_p
```

#### Example

The table below shows an example of these fields in the log files. The first log in the table represents a Modbus request from 192.168.1.10 -> 192.168.1.200 and the second log represents a Modbus reply from 192.168.1.200 -> 192.168.1.10. As shown in the table below, the `id` structure lists both packets as having the same originator and responder, but the `source` and `destination` fields reflect the true source and destination of these packets.

| id.orig_h    | id.orig_p | id.resp_h     | id.resp_p | is_orig | source_h      | source_p | destination_h | destination_p |
| ------------ | --------- |---------------|-----------|---------|---------------|----------|---------------|-------------- |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | T       | 192.168.1.10  | 47785    | 192.168.1.200 | 502           |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | F       | 192.168.1.200 | 502      | 192.168.1.10  | 47785         |

## Coverage

See [Logging Capabilities](#logging-capabilities) for detailed information of the parser coverage.

The Modbus protocol contains a few vendor and product specific functions. These vendor/product specific functions are not included in this parser. All coverage details in this section include information and statistics based on the basic/default Modbus protocol.

### General/Header Logging

The general log file for Modbus (modbus.log) is produced by Zeek's default Modbus parser and is not modified by this parser extension.

### Detailed Logging

Detailed logging for 11 Modbus functions are logged in the detailed log file (modbus_detailed.log), 1 Modbus function is logged in the mask write register log file (modbus_mask_write_register.log), 1 Modbus function is logged in the read write multiple registers log file (modbus_read_write_multiple_registers.log), and 1 Modbus function is logged in the read device identification log file (modbus_read_device_identification.log). The other, much less common, 5 Modbus functions do not contain detailed logging, therefore, ~74% (14/19) of the default Modbus functions contain detailed logging.

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
* [GE SRTP](https://github.com/cisagov/icsnpp-ge-srtp)
    * Full Zeek protocol parser for GE SRTP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)
* [Profinet IO CM](https://github.com/cisagov/icsnpp-profinet-io-cm)
    * Full Zeek protocol parser for Profinet I/O Context Manager

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### License

Copyright 2023 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE.txt`](./LICENSE.txt)).
