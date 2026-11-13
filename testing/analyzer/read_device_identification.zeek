# @TEST-REQUIRES: zeek -e 'exit(Version::at_least("6.1.0") ? 0 : 1)'
# @TEST-EXEC: base64 -d ${TRACES}/modbus_read_device_identification.pcap.b64 > modbus_read_device_identification.pcap
# @TEST-EXEC: zeek -C -r modbus_read_device_identification.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: zeek-cut tid request_response device_id_code conformity_level_code conformity_level object_id_code object_id object_value < modbus_read_device_identification.log > read_device_identification.out
# @TEST-EXEC: btest-diff read_device_identification.out
#
# @TEST-DOC: Read Device Identification (0x2B/0x0E): conformity level 0x03 is named, and request object ids use the object names from the Modbus Application Protocol V1.1b3, section 6.21.
