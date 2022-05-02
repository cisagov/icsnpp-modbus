# @TEST-EXEC: zeek -C -r ${TRACES}/modbus_example.pcap $PACKAGE %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff modbus_detailed.log
# @TEST-EXEC: btest-diff modbus.log
# @TEST-EXEC: btest-diff modbus_mask_write_register.log
# @TEST-EXEC: btest-diff modbus_read_write_multiple_registers.log
#
# @TEST-DOC: Test MODBUS analyzer extennsions with small trace.
