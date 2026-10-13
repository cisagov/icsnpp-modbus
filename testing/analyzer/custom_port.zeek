# @TEST-EXEC: base64 -d ${TRACES}/modbus_custom_port.pcap.b64 > modbus_custom_port.pcap
# @TEST-EXEC: mkdir unconfigured likely-only configured
# @TEST-EXEC: cd unconfigured && zeek -C -r ../modbus_custom_port.pcap ${PACKAGE}
# @TEST-EXEC: test ! -e unconfigured/modbus.log
# @TEST-EXEC: cd likely-only && zeek -C -r ../modbus_custom_port.pcap ${PACKAGE} -e 'redef likely_server_ports += { 12345/tcp };'
# @TEST-EXEC: test ! -e likely-only/modbus.log
# @TEST-EXEC: cd configured && zeek -C -r ../modbus_custom_port.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test "$(zeek-cut id.resp_p < configured/modbus.log | sort -u)" = "12345"
# @TEST-EXEC: test "$(zeek-cut id.resp_p < configured/modbus_detailed.log | sort -u)" = "12345"
#
# @TEST-DOC: Verify that a non-standard TCP port is parsed only after it is added to the package's additional port set.

redef Modbus_Extended::additional_tcp_ports += { 12345/tcp };

event zeek_init() &priority=-10
    {
    assert(12345/tcp in Modbus_Extended::additional_tcp_ports);
    assert(12345/tcp in likely_server_ports);
    assert(12345/tcp in Analyzer::registered_ports(Analyzer::ANALYZER_MODBUS));
    }
