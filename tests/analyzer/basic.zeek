# @TEST-EXEC: zeek -C -r ${TRACES}/modbus_example.pcap $PACKAGE %INPUT
# @TEST-EXEC: grep -v "$(printf '\t')REQ$(printf '\t')" modbus.log > modbus.tmp && mv modbus.tmp modbus.log
# @TEST-EXEC: zeek-cut -n tid unit pdu_type < modbus.log > modbus.tmp && mv modbus.tmp modbus.log
# @TEST-EXEC: btest-diff modbus_detailed.log
# @TEST-EXEC: btest-diff modbus.log
# @TEST-EXEC: btest-diff modbus_mask_write_register.log
# @TEST-EXEC: btest-diff modbus_read_write_multiple_registers.log
#
# @TEST-DOC: Test MODBUS analyzer extennsions with small trace.
