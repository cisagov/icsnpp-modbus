
@load base/protocols/modbus
@load base/bif/zeek.bif

#@load ics

module ics::Modbus;

export {
    type Coils: record {
        address: count &optional;
        quantity: count &optional;
        values: ModbusCoils &optional;
    };

    type Registers: record {
        address: count &optional;
        quantity: count &optional;
        values: ModbusRegisters &optional;
    };

    type Message: record {
        conn: connection;
        headers: ModbusHeaders;
    };

    type Exception: record {
        msg: string;
        code: count &optional;
    };

    type Data: record {
        request: Message &optional;
        response: Message &optional;
        registers: Registers
            &default = Registers();
        coils: Coils
            &default = Coils();
        exceptions: vector of Exception
            &default = vector();
    };

    event ics_modbus_data(data: Data)
    {}

    event ics_modbus_exceptions(data: Data)
    {}
}


type ConnUid: string;
type UnitId: count;
type TransId: count;
type Connection:
    table[UnitId, TransId]
    of Data;
type Requests:
    table[ConnUid]
    of Connection;


function log_expire_request(h: Connection, u: UnitId, t: TransId): interval
{
    ics::debug("expiring request", [
        $protocol = "modbus",
        $connection = h[u,t]$request$conn$uid,
        $unit = u,
        $transaction = t,
    ]);
    return 0sec;
}

function log_expire_host(t: Requests, u: ConnUid): interval
{
    ics::debug("expiring connection", [
        $protocol = "modbus",
        $connection = u,
    ]);
    return 0sec;
}


global requests:
    Requests
    &default_insert = (
        table()
        &create_expire = ics::request_ttl
        &expire_func = log_expire_request
    )
    &write_expire = ics::connection_ttl
    &expire_func = log_expire_host;


type EventCallback: function (action: string, data_type: string, address: count, value: ics::Value);

function write_modbus_registers(data: Data, reg_type: string, do_event: EventCallback)
{
    local start = data$registers$address;
    for (i, v in data$registers$values) {
        do_event("READ", reg_type, start + i, ics::value_for_int(v));
    }
}

function write_modbus_coils(data: Data, reg_type: string, do_event: EventCallback)
{
    local start = data$coils$address;
    for (i, v in data$coils$values) {
        do_event("READ", reg_type, start + i, ics::value_for_bool(v));
    }
}


function write_modbus_data(data: Data)
{
    local start: count;

    if (|data$exceptions| > 0) {
        event ics_modbus_exceptions(data);
        return;
    }

    const do_event = function [data] (
        action: string,
        data_type: string,
        address: count,
        value: ics::Value)
    {
        const r = data$request;
        const c = r$conn;
        local point = ics::DataPoint(
            $ts = c$start_time,
            $uid = c$uid,
            $protocol = "MODBUS",
            $ip = c$id$resp_h,
            $unit = fmt("%d", r$headers$uid),
            $transaction = fmt("%d", r$headers$tid),
            $action = action,
            $data_type = data_type,
            $address = fmt("%d", address),
            $value = value,
        );
        event ics_data_point(point);
    };

    switch (Modbus::function_codes[data$request$headers$function_code]) {
        case "READ_COILS":
            write_modbus_coils(data, "COIL", do_event);
            break;
        case "READ_INPUT_REGISTERS":
            write_modbus_registers(data, "INPUT_REGISTER", do_event);
            break;
        case "READ_HOLDING_REGISTERS":
            write_modbus_registers(data, "HOLDING_REGISTER", do_event);
            break;
        case "READ_DISCRETE_INPUTS":
            write_modbus_coils(data, "DISCRETE_INPUT", do_event);
            break;
    }
}



function put_data_for_request(
        c: connection,
        headers: ModbusHeaders
    ): Data
{
    local data = Data(
        $request = Message(
            $conn = c,
            $headers = headers,
        ),
    );
    requests[c$uid][headers$uid, headers$tid] = data;
    return data;
}

function get_data_for_response(
        c: connection,
        headers: ModbusHeaders
    ): Data
{
    local data: Data;
    local host = requests[c$uid];
    local response = Message($conn=c, $headers=headers);

    if ([headers$uid, headers$tid] in host) {
        data = host[headers$uid, headers$tid];
        if (data$request$headers$function_code != headers$function_code) {
            data$exceptions += Exception(
                $msg = "modbus request/response function mismatch",
            );
        }
        delete host[headers$uid, headers$tid];
    } else {
        data = Data();
        data$exceptions += Exception(
            $msg = "modbus response without request",
        );
    }

    data$response = response;
    return data;
}



event ics_modbus_data(data: Data)
{
    write_modbus_data(data);
}

event ics_modbus_exceptions(data: Data)
{
    if (data ?$ request) {
        ics::debug("exceptions", [
            $protocol = "modbus",
            $connection = data$request$conn$uid,
            $unit = data$request$headers$uid,
            $transaction = data$request$headers$tid,
            $exceptions = data$exceptions,
        ]);
    } else if (data ?$ response) {
        ics::debug("exceptions", [
            $protocol = "modbus",
            $connection = data$response$conn$uid,
            $unit = data$response$headers$uid,
            $transaction = data$response$headers$tid,
            $exceptions = data$exceptions,
        ]);
    } else {
        ics::debug("exceptions", [
            $protocol = "modbus",
            $exceptions = data$exceptions,
        ]);
    }
}


event modbus_message(
    c: connection,
    headers: ModbusHeaders,
    is_orig: bool)
{
    #print "message", c$uid, headers$tid, Modbus::function_codes[headers$function_code], is_orig;
}

event modbus_exception(
    c: connection,
    headers: ModbusHeaders,
    code: count)
{
    local data = get_data_for_response(c, headers);
    data$exceptions += Exception(
        $msg = Modbus::exception_codes[code],
        $code = code,
    );
    print data$exceptions;
    event ics_modbus_data(data);
}

event modbus_read_input_registers_request(
    c: connection,
    headers: ModbusHeaders,
    start_address: count,
    quantity: count)
{
    local data = put_data_for_request(c, headers);
    data$registers$address = start_address;
    data$registers$quantity = quantity;
}

event modbus_read_input_registers_response(
    c: connection,
    headers: ModbusHeaders,
    registers: ModbusRegisters)
{
    local data = get_data_for_response(c, headers);
    data$registers$values = registers;
    event ics_modbus_data(data);
}

event modbus_read_holding_registers_request(
    c: connection,
    headers: ModbusHeaders,
    start_address: count,
    quantity: count)
{
    local data = put_data_for_request(c, headers);
    data$registers$address = start_address;
    data$registers$quantity = quantity;
}

event modbus_read_holding_registers_response(
    c: connection,
    headers: ModbusHeaders,
    registers: ModbusRegisters)
{
    local data = get_data_for_response(c, headers);
    data$registers$values = registers;
    event ics_modbus_data(data);
}

event modbus_read_coils_request(
    c: connection,
    headers: ModbusHeaders,
    start_address: count,
    quantity: count)
{
    local data = put_data_for_request(c, headers);
    data$coils$address = start_address;
    data$coils$quantity = quantity;
}

event modbus_read_coils_response(
    c: connection,
    headers: ModbusHeaders,
    coils: ModbusCoils)
{
    local data = get_data_for_response(c, headers);
    data$coils$values = coils;
    event ics_modbus_data(data);
}

event modbus_read_discrete_inputs_request(
    c: connection,
    headers: ModbusHeaders,
    start_address: count,
    quantity: count)
{
    local data = put_data_for_request(c, headers);
    data$coils$address = start_address;
    data$coils$quantity = quantity;
}

event modbus_read_discrete_inputs_response(
    c: connection,
    headers: ModbusHeaders,
    coils: ModbusCoils)
{
    local data = get_data_for_response(c, headers);
    data$coils$values = coils;
    event ics_modbus_data(data);
}




