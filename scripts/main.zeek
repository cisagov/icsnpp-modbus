##! modbus_extended.zeek
##!
##! Binpac Modbus Protocol Analyzer - Contains the base script-layer functionality for processing events 
##!                                   emitted from the analyzer. (Utilizes Zeek's built-in Modbus parser)
##!
##! Authors:  Brett Rasmussen & Stephen Kleinheider
##! Contact:  brett.rasmussen@inl.gov & stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

@load base/protocols/modbus

module Modbus_Extended;

export {
    redef enum Log::ID += { LOG_DETAILED,
                            LOG_MASK_WRITE_REGISTER,
                            LOG_READ_WRITE_MULTIPLE_REGISTERS,
                            LOG_READ_DEVICE_IDENTIFICATION };

    #########################################################################################################################
    #####################################  Modbus Detailed Log -> modbus_detailed.log  ######################################
    #########################################################################################################################
    type Modbus_Detailed: record {
        ts                      : time              &log;             ##< Timestamp of event
        uid                     : string            &log;             ##< Zeek unique ID for connection
        id                      : conn_id           &log;             ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool              &log;             ##< the message came from the originator/client or the responder/server
        source_h                : addr              &log;             ##< Source IP Address
        source_p                : port              &log;             ##< Source Port
        destination_h           : addr              &log;             ##< Destination IP Address
        destination_p           : port              &log;             ##< Destination Port
        tid                     : count             &log &optional;   ##< Modbus transaction id
        unit                    : count             &log &optional;   ##< Modbus terminal unit identifier
        func                    : string            &log &optional;   ##< Modbus Function
        request_response        : string            &log &optional;   ##< REQUEST or RESPONSE
        address                 : count             &log &optional;   ##< Starting address for value(s) field
        quantity                : count             &log &optional;   ##< Number of addresses/values read or written to
        values                  : string            &log &optional;   ##< Coils, discrete_inputs, or registers read/written to
    };
    global log_modbus_detailed: event(rec: Modbus_Detailed);

    #########################################################################################################################
    #############################  Mask Write Register Log -> modbus_mask_write_register.log  ###############################
    #########################################################################################################################
    type Mask_Write_Register: record {
        ts                      : time              &log;             ##< Timestamp of event
        uid                     : string            &log;             ##< Zeek unique ID for connection
        id                      : conn_id           &log;             ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool              &log;             ##< the message came from the originator/client or the responder/server
        source_h                : addr              &log;             ##< Source IP Address
        source_p                : port              &log;             ##< Source Port
        destination_h           : addr              &log;             ##< Destination IP Address
        destination_p           : port              &log;             ##< Destination Port
        tid                     : count             &log &optional;   ##< Modbus transaction id
        unit                    : count             &log &optional;   ##< Modbus terminal unit identifier
        func                    : string            &log &optional;   ##< Modbus Function
        request_response        : string            &log &optional;   ##< REQUEST or RESPONSE
        address                 : count             &log &optional;   ##< Address of the target register
        and_mask                : count             &log &optional;   ##< Boolean 'and' mask to apply to the target register
        or_mask                 : count             &log &optional;   ##< Boolean 'or' mask to apply to the target register
    };
    global log_mask_write_register: event(rec: Mask_Write_Register);

    #########################################################################################################################
    ###################  Read Write Multiple Registers Log -> modbus_read_write_multiple_registers.log  #####################
    #########################################################################################################################
    type Read_Write_Multiple_Registers: record {
        ts                      : time              &log;             ##< Timestamp of event
        uid                     : string            &log;             ##< Zeek unique ID for connection
        id                      : conn_id           &log;             ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool              &log;             ##< the message came from the originator/client or the responder/server
        source_h                : addr              &log;             ##< Source IP Address
        source_p                : port              &log;             ##< Source Port
        destination_h           : addr              &log;             ##< Destination IP Address
        destination_p           : port              &log;             ##< Destination Port
        tid                     : count             &log &optional;   ##< Modbus transaction id
        unit                    : count             &log &optional;   ##< Modbus terminal unit identifier
        func                    : string            &log &optional;   ##< Modbus Function
        request_response        : string            &log &optional;   ##< REQUEST or RESPONSE
        write_start_address     : count             &log &optional;   ##< Starting address of the registers to write to
        write_registers         : ModbusRegisters   &log &optional;   ##< Register values written
        read_start_address      : count             &log &optional;   ##< Starting address of the registers to read
        read_quantity           : count             &log &optional;   ##< Number of registers to read
        read_registers          : ModbusRegisters   &log &optional;   ##< Register values read
    };
    global log_read_write_multiple_registers: event(rec: Read_Write_Multiple_Registers);

    #########################################################################################################################
    #######################  Read Device Identification Log -> modbus_read_device_identification.log  #######################
    #########################################################################################################################
    type Read_Device_Identification: record {
        ts                      : time              &log;             ##< Timestamp of event
        uid                     : string            &log;             ##< Zeek unique ID for connection
        id                      : conn_id           &log;             ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool              &log;             ##< the message came from the originator/client or the responder/server
        source_h                : addr              &log;             ##< Source IP Address
        source_p                : port              &log;             ##< Source Port
        destination_h           : addr              &log;             ##< Destination IP Address
        destination_p           : port              &log;             ##< Destination Port
        tid                     : count             &log &optional;   ##< Modbus transaction id
        unit                    : count             &log &optional;   ##< Modbus terminal unit identifier
        func                    : string            &log &optional;   ##< Modbus Function - 
        request_response        : string            &log &optional;   ##< REQUEST or RESPONSE
        mei_type                : string            &log &optional;   ##< MEI Type - Always READ-DEVICE-IDENTIFICATION
        conformity_level_code   : string            &log &optional;   ##< Conformity Level Code
        conformity_level        : string            &log &optional;   ##< Conformity Level 
        device_id_code          : count             &log &optional;   ##< Device ID Code
        object_id_code          : string            &log &optional;   ##< Object ID Code
        object_id               : string            &log &optional;   ##< Object ID
        object_value            : string            &log &optional;   ##< Object Value
    };
    global log_read_device_identification: event(rec: Read_Device_Identification);
}

redef DPD::ignore_violations += { Analyzer::ANALYZER_MODBUS };

@if (Version::at_least("6.1.0"))
const device_identification_conformity_level = {
    [0x01] = "Basic Identification (Stream)",
    [0x02] = "Regular Identification (Stream)",
    [0x04] = "Extended Identification (Stream)",
    [0x81] = "Basic Identification (Stream, Individual)",
    [0x82] = "Regular Identification (Stream, Individual)",
    [0x83] = "Extended Identification (Stream, Individual)"
} &default=function(i: count):string { return "Unknown"; } &redef;

const device_identification_object_id = {
    [0x00] = "VendorName",
    [0x01] = "ProductCode",
    [0x02] = "MajorMinorVersion",
    [0x03] = "VendorURL",
    [0x04] = "ProductName",
    [0x05] = "ModelName",
    [0x06] = "UserApplicationName"
} &default=function(i: count):string { return "Unknown"; } &redef;

const device_identification_read_object_id = {
    [0x00] = "Basic Device Identification",
    [0x01] = "Regular Device Identification",
    [0x02] = "Extended Device Identification",
    [0x03] = "Specific Device Identification"
} &default=function(i: count):string { return "Unknown"; } &redef;
@endif

#############################################################################################################################
#######################################  Converts Coil Vector to List of Boolean Values #####################################
#############################################################################################################################
function coils_to_bools_string (coils: ModbusCoils): string {

    local first_iter = T;
    local ret_str = "";

    for ([i] in coils) {
        if (first_iter){
            ret_str = fmt("%s", coils[i]);
            first_iter = F;
        }
        else
            ret_str = fmt("%s,%s", ret_str, coils[i]);
    }

    return ret_str;
}

#############################################################################################################################
######################################  Converts Register Vector to List of Count Values ####################################
#############################################################################################################################
function registers_to_counts_string (registers: ModbusRegisters): string {

    local first_iter = T;
    local ret_str = "";

    for ([i] in registers) {
        if (first_iter) {
            ret_str = fmt("%d", registers[i]);
            first_iter = F;
        }
        else
            ret_str = fmt("%s,%d", ret_str, registers[i]);
    }

    return ret_str;
}
#############################################################################################################################
##############################################  Test for Handled Modbus Functions ###########################################
#############################################################################################################################
function handled_modbus_funct_list (cur_func_str : string): bool {
    if ((cur_func_str == "READ_COILS") ||
        (cur_func_str == "READ_COILS_EXCEPTION") ||
        (cur_func_str == "READ_DISCRETE_INPUTS") ||
        (cur_func_str == "READ_DISCRETE_INPUTS_EXCEPTION") ||
        (cur_func_str == "READ_HOLDING_REGISTERS") ||
        (cur_func_str == "READ_HOLDING_REGISTERS_EXCEPTION") ||
        (cur_func_str == "READ_INPUT_REGISTERS") ||
        (cur_func_str == "READ_INPUT_REGISTERS_EXCEPTION") ||
        (cur_func_str == "READ_FILE_RECORD") ||
        (cur_func_str == "READ_FILE_RECORD_EXCEPTION") ||
        (cur_func_str == "WRITE_SINGLE_COIL") ||
        (cur_func_str == "WRITE_SINGLE_COIL_EXCEPTION") ||
        (cur_func_str == "WRITE_SINGLE_REGISTER") ||
        (cur_func_str == "WRITE_SINGLE_REGISTER_EXCEPTION") ||
        (cur_func_str == "WRITE_MULTIPLE_COILS") ||
        (cur_func_str == "WRITE_MULTIPLE_COILS_EXCEPTION") ||
        (cur_func_str == "WRITE_MULTIPLE_REGISTERS") ||
        (cur_func_str == "WRITE_MULTIPLE_REGISTERS_EXCEPTION") ||
        (cur_func_str == "READ_WRITE_MULTIPLE_REGISTERS") ||
        (cur_func_str == "READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION") ||
        (cur_func_str == "MASK_WRITE_REGISTER") ||
        (cur_func_str == "MASK_WRITE_REGISTER_EXCEPTION") ||
        (cur_func_str == "WRITE_FILE_RECORD") ||
        (cur_func_str == "WRITE_FILE_RECORD_EXCEPTION") ||
        (cur_func_str == "READ_FIFO_QUEUE") ||
        (cur_func_str == "READ_FIFO_QUEUE_EXCEPTION")) {
            return T;
    }
    @if (Version::at_least("6.1.0"))
    if ((cur_func_str == "DIAGNOSTICS") ||
        (cur_func_str == "DIAGNOSTICS_EXCEPTION") ||
        (cur_func_str == "ENCAP_INTERFACE_TRANSPORT") ||
        (cur_func_str == "ENCAP_INTERFACE_TRANSPORT_EXCEPTION")) {
            return T;
    }
    @endif

    # This function does not yet have a separate message handler
    return F;
}

#############################################################################################################################
# Defines Log Streams for modbus_detailed.log, modbus_mask_write_register.log, and modbus_read_write_multiple_registers.log #
#############################################################################################################################
event zeek_init() &priority=5 {
    Log::create_stream(Modbus_Extended::LOG_DETAILED, [$columns=Modbus_Detailed, 
                                                       $ev=log_modbus_detailed,
                                                       $path="modbus_detailed"]);

    Log::create_stream(Modbus_Extended::LOG_MASK_WRITE_REGISTER, [$columns=Mask_Write_Register,
                                                                  $ev=log_mask_write_register,
                                                                  $path="modbus_mask_write_register"]);

    Log::create_stream(Modbus_Extended::LOG_READ_WRITE_MULTIPLE_REGISTERS, [$columns=Read_Write_Multiple_Registers, 
                                                                            $ev=log_read_write_multiple_registers,
                                                                            $path="modbus_read_write_multiple_registers"]);

    Log::create_stream(Modbus_Extended::LOG_READ_DEVICE_IDENTIFICATION, [$columns=Read_Device_Identification, 
                                                                            $ev=log_read_device_identification,
                                                                            $path="modbus_read_device_identification"]);
}

#############################################################################################################################
###################  Defines logging of modbus_read_discrete_inputs_request event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_discrete_inputs_request(c: connection, 
                                          headers: ModbusHeaders, 
                                          start_address: count, 
                                          quantity: count){

    local read_discrete_inputs_request: Modbus_Detailed;

    read_discrete_inputs_request$ts                 = network_time();
    read_discrete_inputs_request$uid                = c$uid;
    read_discrete_inputs_request$id                 = c$id;

    read_discrete_inputs_request$is_orig            = T;
    read_discrete_inputs_request$source_h           = c$id$orig_h;
    read_discrete_inputs_request$source_p           = c$id$orig_p;
    read_discrete_inputs_request$destination_h      = c$id$resp_h;
    read_discrete_inputs_request$destination_p      = c$id$resp_p;

    read_discrete_inputs_request$tid                = headers$tid;
    read_discrete_inputs_request$unit               = headers$uid;
    read_discrete_inputs_request$func               = Modbus::function_codes[headers$function_code];
    read_discrete_inputs_request$request_response   = "REQUEST";
    read_discrete_inputs_request$address            = start_address;
    read_discrete_inputs_request$quantity           = quantity;

    Log::write(LOG_DETAILED, read_discrete_inputs_request);
}

#############################################################################################################################
##################  Defines logging of modbus_read_discrete_inputs_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_discrete_inputs_response(c: connection, 
                                           headers: ModbusHeaders, 
                                           coils: ModbusCoils){

    local read_discrete_inputs_response: Modbus_Detailed;

    read_discrete_inputs_response$ts                = network_time();
    read_discrete_inputs_response$uid               = c$uid;
    read_discrete_inputs_response$id                = c$id;

    read_discrete_inputs_response$is_orig           = F;
    read_discrete_inputs_response$source_h          = c$id$resp_h;
    read_discrete_inputs_response$source_p          = c$id$resp_p;
    read_discrete_inputs_response$destination_h     = c$id$orig_h;
    read_discrete_inputs_response$destination_p     = c$id$orig_p;

    read_discrete_inputs_response$tid               = headers$tid;
    read_discrete_inputs_response$unit              = headers$uid;
    read_discrete_inputs_response$func              = Modbus::function_codes[headers$function_code];
    read_discrete_inputs_response$request_response  = "RESPONSE";
    read_discrete_inputs_response$quantity          = |coils|;
    read_discrete_inputs_response$values            = coils_to_bools_string (coils);

    Log::write(LOG_DETAILED, read_discrete_inputs_response);
}

#############################################################################################################################
########################  Defines logging of modbus_read_coils_request event -> modbus_detailed.log  ########################
#############################################################################################################################
event modbus_read_coils_request(c: connection, 
                                headers: ModbusHeaders, 
                                start_address: count, 
                                quantity: count){
    
    local read_coils_request: Modbus_Detailed;

    read_coils_request$ts                   = network_time();
    read_coils_request$uid                  = c$uid;
    read_coils_request$id                   = c$id;

    read_coils_request$is_orig              = T;
    read_coils_request$source_h             = c$id$orig_h;
    read_coils_request$source_p             = c$id$orig_p;
    read_coils_request$destination_h        = c$id$resp_h;
    read_coils_request$destination_p        = c$id$resp_p;

    read_coils_request$tid                  = headers$tid;
    read_coils_request$unit                 = headers$uid;
    read_coils_request$func                 = Modbus::function_codes[headers$function_code];
    read_coils_request$request_response     = "REQUEST";
    read_coils_request$address              = start_address;
    read_coils_request$quantity             = quantity;

    Log::write(LOG_DETAILED, read_coils_request);
}

#############################################################################################################################
#######################  Defines logging of modbus_read_coils_response event -> modbus_detailed.log  ########################
#############################################################################################################################
event modbus_read_coils_response(c: connection,
                                 headers: ModbusHeaders,
                                 coils: ModbusCoils){
    
    local read_coils_response: Modbus_Detailed;

    read_coils_response$ts                  = network_time();
    read_coils_response$uid                 = c$uid;
    read_coils_response$id                  = c$id;

    read_coils_response$is_orig             = F;
    read_coils_response$source_h            = c$id$resp_h;
    read_coils_response$source_p            = c$id$resp_p;
    read_coils_response$destination_h       = c$id$orig_h;
    read_coils_response$destination_p       = c$id$orig_p;

    read_coils_response$tid                 = headers$tid;
    read_coils_response$unit                = headers$uid;
    read_coils_response$func                = Modbus::function_codes[headers$function_code];
    read_coils_response$request_response    = "RESPONSE";
    read_coils_response$quantity            = |coils|;
    read_coils_response$values              = coils_to_bools_string (coils);

    Log::write(LOG_DETAILED, read_coils_response);
}

#############################################################################################################################
##################  Defines logging of modbus_read_input_registers_request event -> modbus_detailed.log  ####################
#############################################################################################################################
event modbus_read_input_registers_request(c: connection, 
                                          headers: ModbusHeaders, 
                                          start_address: count, 
                                          quantity: count) {

    local read_input_request: Modbus_Detailed;

    read_input_request$ts                   = network_time();
    read_input_request$uid                  = c$uid;
    read_input_request$id                   = c$id;

    read_input_request$is_orig              = T;
    read_input_request$source_h             = c$id$orig_h;
    read_input_request$source_p             = c$id$orig_p;
    read_input_request$destination_h        = c$id$resp_h;
    read_input_request$destination_p        = c$id$resp_p;

    read_input_request$tid                  = headers$tid;
    read_input_request$unit                 = headers$uid;
    read_input_request$func                 = Modbus::function_codes[headers$function_code];
    read_input_request$request_response     = "REQUEST";
    read_input_request$address              = start_address;
    read_input_request$quantity             = quantity;

    Log::write(LOG_DETAILED, read_input_request);
}

#############################################################################################################################
##################  Defines logging of modbus_read_input_registers_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_input_registers_response(c: connection, 
                                           headers: ModbusHeaders, 
                                           registers: ModbusRegisters) {

    local read_input_response: Modbus_Detailed;

    read_input_response$ts                  = network_time();
    read_input_response$uid                 = c$uid;
    read_input_response$id                  = c$id;

    read_input_response$is_orig             = F;
    read_input_response$source_h            = c$id$resp_h;
    read_input_response$source_p            = c$id$resp_p;
    read_input_response$destination_h       = c$id$orig_h;
    read_input_response$destination_p       = c$id$orig_p;

    read_input_response$tid                 = headers$tid;
    read_input_response$unit                = headers$uid;
    read_input_response$func                = Modbus::function_codes[headers$function_code];
    read_input_response$request_response    = "RESPONSE";
    read_input_response$quantity            = |registers|;
    read_input_response$values              = registers_to_counts_string (registers);

    Log::write(LOG_DETAILED, read_input_response);
}

#############################################################################################################################
##################  Defines logging of modbus_read_holding_registers_request event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_read_holding_registers_request(c: connection, 
                                            headers: ModbusHeaders, 
                                            start_address: count, 
                                            quantity: count) {

    local read_holding_request: Modbus_Detailed;
    read_holding_request$ts                 = network_time();
    read_holding_request$uid                = c$uid;
    read_holding_request$id                 = c$id;

    read_holding_request$is_orig            = T;
    read_holding_request$source_h           = c$id$orig_h;
    read_holding_request$source_p           = c$id$orig_p;
    read_holding_request$destination_h      = c$id$resp_h;
    read_holding_request$destination_p      = c$id$resp_p;

    read_holding_request$tid                = headers$tid;
    read_holding_request$unit               = headers$uid;
    read_holding_request$func               = Modbus::function_codes[headers$function_code];
    read_holding_request$request_response   = "REQUEST";
    read_holding_request$address            = start_address;
    read_holding_request$quantity           = quantity;

    Log::write(LOG_DETAILED, read_holding_request);
}

#############################################################################################################################
#################  Defines logging of modbus_read_holding_registers_response event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_read_holding_registers_response(c: connection, 
                                             headers: ModbusHeaders, 
                                             registers: ModbusRegisters) {

    local read_holding_reg_response: Modbus_Detailed;

    read_holding_reg_response$ts                = network_time();
    read_holding_reg_response$uid               = c$uid;
    read_holding_reg_response$id                = c$id;

    read_holding_reg_response$is_orig           = F;
    read_holding_reg_response$source_h          = c$id$resp_h;
    read_holding_reg_response$source_p          = c$id$resp_p;
    read_holding_reg_response$destination_h     = c$id$orig_h;
    read_holding_reg_response$destination_p     = c$id$orig_p;

    read_holding_reg_response$tid               = headers$tid;
    read_holding_reg_response$unit              = headers$uid;
    read_holding_reg_response$func              = Modbus::function_codes[headers$function_code];
    read_holding_reg_response$request_response  = "RESPONSE";
    read_holding_reg_response$quantity          = |registers|;
    read_holding_reg_response$values            = registers_to_counts_string (registers);;

    Log::write(LOG_DETAILED, read_holding_reg_response);
}

#############################################################################################################################
#####################  Defines logging of modbus_read_fifo_queue_request event -> modbus_detailed.log  ######################
#############################################################################################################################
event modbus_read_fifo_queue_request(c: connection, 
                                     headers: ModbusHeaders, 
                                     start_address: count) {
    
    local read_fifo_queue_request: Modbus_Detailed;
    
    read_fifo_queue_request$ts                  = network_time();
    read_fifo_queue_request$uid                 = c$uid;
    read_fifo_queue_request$id                  = c$id;

    read_fifo_queue_request$is_orig             = T;
    read_fifo_queue_request$source_h            = c$id$orig_h;
    read_fifo_queue_request$source_p            = c$id$orig_p;
    read_fifo_queue_request$destination_h       = c$id$resp_h;
    read_fifo_queue_request$destination_p       = c$id$resp_p;

    read_fifo_queue_request$tid                 = headers$tid;
    read_fifo_queue_request$unit                = headers$uid;
    read_fifo_queue_request$func                = Modbus::function_codes[headers$function_code];
    read_fifo_queue_request$request_response    = "REQUEST";
    read_fifo_queue_request$address             = start_address;

    Log::write(LOG_DETAILED, read_fifo_queue_request);
}

#############################################################################################################################
#####################  Defines logging of modbus_read_fifo_queue_response event -> modbus_detailed.log  #####################
#############################################################################################################################
event modbus_read_fifo_queue_response(c: connection, 
                                      headers: ModbusHeaders, 
                                      fifos: ModbusRegisters) {

    local read_fifo_queue_response: Modbus_Detailed;

    read_fifo_queue_response$ts                 = network_time();
    read_fifo_queue_response$uid                = c$uid;
    read_fifo_queue_response$id                 = c$id;

    read_fifo_queue_response$is_orig            = F;
    read_fifo_queue_response$source_h           = c$id$resp_h;
    read_fifo_queue_response$source_p           = c$id$resp_p;
    read_fifo_queue_response$destination_h      = c$id$orig_h;
    read_fifo_queue_response$destination_p      = c$id$orig_p;

    read_fifo_queue_response$tid                = headers$tid;
    read_fifo_queue_response$unit               = headers$uid;
    read_fifo_queue_response$func               = Modbus::function_codes[headers$function_code];
    read_fifo_queue_response$request_response   = "RESPONSE";
    read_fifo_queue_response$quantity           = |fifos|;
    read_fifo_queue_response$values             = registers_to_counts_string (fifos);

    Log::write(LOG_DETAILED, read_fifo_queue_response);
}

#############################################################################################################################
#####################  Defines logging of modbus_write_single_coil_request event -> modbus_detailed.log  ####################
#############################################################################################################################
event modbus_write_single_coil_request(c: connection, 
                                       headers: ModbusHeaders, 
                                       address: count, 
                                       value: bool) {
    
    local write_single_coil_request: Modbus_Detailed;
    
    write_single_coil_request$ts                = network_time();
    write_single_coil_request$uid               = c$uid;
    write_single_coil_request$id                = c$id;

    write_single_coil_request$is_orig           = T;
    write_single_coil_request$source_h          = c$id$orig_h;
    write_single_coil_request$source_p          = c$id$orig_p;
    write_single_coil_request$destination_h     = c$id$resp_h;
    write_single_coil_request$destination_p     = c$id$resp_p;

    write_single_coil_request$tid               = headers$tid;
    write_single_coil_request$unit              = headers$uid;
    write_single_coil_request$func              = Modbus::function_codes[headers$function_code];
    write_single_coil_request$request_response  = "REQUEST";
    write_single_coil_request$address           = address;
    write_single_coil_request$quantity          = 1;
    write_single_coil_request$values            = fmt("%s", value);

    Log::write(LOG_DETAILED, write_single_coil_request);
}

#############################################################################################################################
####################  Defines logging of modbus_write_single_coil_response event -> modbus_detailed.log  ####################
#############################################################################################################################
event modbus_write_single_coil_response(c: connection, 
                                        headers: ModbusHeaders, 
                                        address: count, 
                                        value: bool) {
    
    local write_single_coil_response: Modbus_Detailed;
    
    write_single_coil_response$ts                   = network_time();
    write_single_coil_response$uid                  = c$uid;
    write_single_coil_response$id                   = c$id;

    write_single_coil_response$is_orig              = F;
    write_single_coil_response$source_h             = c$id$resp_h;
    write_single_coil_response$source_p             = c$id$resp_p;
    write_single_coil_response$destination_h        = c$id$orig_h;
    write_single_coil_response$destination_p        = c$id$orig_p;

    write_single_coil_response$tid                  = headers$tid;
    write_single_coil_response$unit                 = headers$uid;
    write_single_coil_response$func                 = Modbus::function_codes[headers$function_code];
    write_single_coil_response$request_response     = "RESPONSE";
    write_single_coil_response$address              = address;
    write_single_coil_response$quantity             = 1;
    write_single_coil_response$values               = fmt("%s", value);

    Log::write(LOG_DETAILED, write_single_coil_response);
}

#############################################################################################################################
###################  Defines logging of modbus_write_single_register_request event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_write_single_register_request(c: connection, 
                                           headers: ModbusHeaders, 
                                           address: count, 
                                           value: count) {

    local write_single_register_request: Modbus_Detailed;

    write_single_register_request$ts                = network_time();
    write_single_register_request$uid               = c$uid;
    write_single_register_request$id                = c$id;

    write_single_register_request$is_orig           = T;
    write_single_register_request$source_h          = c$id$orig_h;
    write_single_register_request$source_p          = c$id$orig_p;
    write_single_register_request$destination_h     = c$id$resp_h;
    write_single_register_request$destination_p     = c$id$resp_p;

    write_single_register_request$tid               = headers$tid;
    write_single_register_request$unit              = headers$uid;
    write_single_register_request$func              = Modbus::function_codes[headers$function_code];
    write_single_register_request$request_response  = "REQUEST";
    write_single_register_request$address           = address;
    write_single_register_request$quantity          = 1;
    write_single_register_request$values            = fmt("%d", value);

    Log::write(LOG_DETAILED, write_single_register_request);
}

#############################################################################################################################
##################  Defines logging of modbus_write_single_register_response event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_write_single_register_response(c: connection, 
                                            headers: ModbusHeaders, 
                                            address: count, 
                                            value: count) {
    
    local write_single_register_response: Modbus_Detailed;

    write_single_register_response$ts                   = network_time();
    write_single_register_response$uid                  = c$uid;
    write_single_register_response$id                   = c$id;

    write_single_register_response$is_orig              = F;
    write_single_register_response$source_h             = c$id$resp_h;
    write_single_register_response$source_p             = c$id$resp_p;
    write_single_register_response$destination_h        = c$id$orig_h;
    write_single_register_response$destination_p        = c$id$orig_p;

    write_single_register_response$tid                  = headers$tid;
    write_single_register_response$unit                 = headers$uid;
    write_single_register_response$func                 = Modbus::function_codes[headers$function_code];
    write_single_register_response$request_response     = "RESPONSE";
    write_single_register_response$address              = address;
    write_single_register_response$quantity             = 1;
    write_single_register_response$values               = fmt("%d", value);

    Log::write(LOG_DETAILED, write_single_register_response);
}

#############################################################################################################################
###################  Defines logging of modbus_write_multiple_coils_request event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_write_multiple_coils_request(c: connection, 
                                          headers: ModbusHeaders, 
                                          start_address: count, 
                                          coils: ModbusCoils) {

    local write_multiple_coils_request: Modbus_Detailed;

    write_multiple_coils_request$ts                 = network_time();
    write_multiple_coils_request$uid                = c$uid;
    write_multiple_coils_request$id                 = c$id;

    write_multiple_coils_request$is_orig            = T;
    write_multiple_coils_request$source_h           = c$id$orig_h;
    write_multiple_coils_request$source_p           = c$id$orig_p;
    write_multiple_coils_request$destination_h      = c$id$resp_h;
    write_multiple_coils_request$destination_p      = c$id$resp_p;

    write_multiple_coils_request$tid                = headers$tid;
    write_multiple_coils_request$unit               = headers$uid;
    write_multiple_coils_request$func               = Modbus::function_codes[headers$function_code];
    write_multiple_coils_request$request_response   = "REQUEST";
    write_multiple_coils_request$address            = start_address;
    write_multiple_coils_request$quantity           = |coils|;
    write_multiple_coils_request$values             = coils_to_bools_string (coils);;
    
    Log::write(LOG_DETAILED, write_multiple_coils_request);
}

#############################################################################################################################
##################  Defines logging of modbus_write_multiple_coils_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_write_multiple_coils_response(c: connection, 
                                           headers: ModbusHeaders, 
                                           start_address: count, 
                                           quantity: count) {

    local write_multiple_coils_response: Modbus_Detailed;

    write_multiple_coils_response$ts                = network_time();
    write_multiple_coils_response$uid               = c$uid;
    write_multiple_coils_response$id                = c$id;

    write_multiple_coils_response$is_orig           = F;
    write_multiple_coils_response$source_h          = c$id$resp_h;
    write_multiple_coils_response$source_p          = c$id$resp_p;
    write_multiple_coils_response$destination_h     = c$id$orig_h;
    write_multiple_coils_response$destination_p     = c$id$orig_p;

    write_multiple_coils_response$tid               = headers$tid;
    write_multiple_coils_response$unit              = headers$uid;
    write_multiple_coils_response$func              = Modbus::function_codes[headers$function_code];
    write_multiple_coils_response$request_response  = "RESPONSE";
    write_multiple_coils_response$address           = start_address;
    write_multiple_coils_response$quantity          = quantity;

    Log::write(LOG_DETAILED, write_multiple_coils_response);
}

#############################################################################################################################
#################  Defines logging of modbus_write_multiple_registers_request event -> modbus_detailed.log  #################
#############################################################################################################################
event modbus_write_multiple_registers_request(c: connection, 
                                              headers: ModbusHeaders, 
                                              start_address: count, 
                                              registers: ModbusRegisters) {

    local write_multiple_registers_request: Modbus_Detailed;

    write_multiple_registers_request$ts                 = network_time();
    write_multiple_registers_request$uid                = c$uid;
    write_multiple_registers_request$id                 = c$id;

    write_multiple_registers_request$is_orig            = T;
    write_multiple_registers_request$source_h           = c$id$orig_h;
    write_multiple_registers_request$source_p           = c$id$orig_p;
    write_multiple_registers_request$destination_h      = c$id$resp_h;
    write_multiple_registers_request$destination_p      = c$id$resp_p;

    write_multiple_registers_request$tid                = headers$tid;
    write_multiple_registers_request$unit               = headers$uid;
    write_multiple_registers_request$func               = Modbus::function_codes[headers$function_code];
    write_multiple_registers_request$request_response   = "REQUEST";
    write_multiple_registers_request$address            = start_address;
    write_multiple_registers_request$quantity           = |registers|;
    write_multiple_registers_request$values             = registers_to_counts_string (registers);;

    Log::write(LOG_DETAILED, write_multiple_registers_request);
}

#############################################################################################################################
#################  Defines logging of modbus_write_multiple_registers_response event -> modbus_detailed.log  ################
#############################################################################################################################
event modbus_write_multiple_registers_response(c: connection, 
                                               headers: ModbusHeaders, 
                                               start_address: count, 
                                               quantity: count) {

    local write_multiple_registers_response: Modbus_Detailed;
        
    write_multiple_registers_response$ts                = network_time();
    write_multiple_registers_response$uid               = c$uid;
    write_multiple_registers_response$id                = c$id;

    write_multiple_registers_response$is_orig           = F;
    write_multiple_registers_response$source_h          = c$id$resp_h;
    write_multiple_registers_response$source_p          = c$id$resp_p;
    write_multiple_registers_response$destination_h     = c$id$orig_h;
    write_multiple_registers_response$destination_p     = c$id$orig_p;

    write_multiple_registers_response$tid               = headers$tid;
    write_multiple_registers_response$unit              = headers$uid;
    write_multiple_registers_response$func              = Modbus::function_codes[headers$function_code];
    write_multiple_registers_response$request_response  = "RESPONSE";
    write_multiple_registers_response$address           = start_address;
    write_multiple_registers_response$quantity          = quantity;

    Log::write(LOG_DETAILED, write_multiple_registers_response);
}

#############################################################################################################################
####  Defines logging of modbus_read_write_multiple_registers_request event -> modbus_read_write_multiple_registers.log  ####
####  Defines logging of modbus_read_write_multiple_registers_request event -> modbus_detailed.log                       ####
#############################################################################################################################
event modbus_read_write_multiple_registers_request(c: connection, 
                                                   headers: ModbusHeaders, 
                                                   read_start_address: count, 
                                                   read_quantity: count, 
                                                   write_start_address: count, 
                                                   write_registers: ModbusRegisters) {

    local read_write_multiple_registers_request: Read_Write_Multiple_Registers;
    local read_write_multiple_registers_request_detailed: Modbus_Detailed;

    read_write_multiple_registers_request$ts                   = network_time();
    read_write_multiple_registers_request$uid                  = c$uid;
    read_write_multiple_registers_request$id                   = c$id;

    read_write_multiple_registers_request$is_orig              = T;
    read_write_multiple_registers_request$source_h             = c$id$orig_h;
    read_write_multiple_registers_request$source_p             = c$id$orig_p;
    read_write_multiple_registers_request$destination_h        = c$id$resp_h;
    read_write_multiple_registers_request$destination_p        = c$id$resp_p;

    read_write_multiple_registers_request$tid                  = headers$tid;
    read_write_multiple_registers_request$unit                 = headers$uid;
    read_write_multiple_registers_request$func                 = Modbus::function_codes[headers$function_code];
    read_write_multiple_registers_request$request_response     = "REQUEST";
    read_write_multiple_registers_request$read_start_address   = read_start_address;
    read_write_multiple_registers_request$read_quantity        = read_quantity;
    read_write_multiple_registers_request$write_start_address  = write_start_address;
    read_write_multiple_registers_request$write_registers      = write_registers;

    read_write_multiple_registers_request_detailed$ts                   = network_time();
    read_write_multiple_registers_request_detailed$uid                  = c$uid;
    read_write_multiple_registers_request_detailed$id                   = c$id;

    read_write_multiple_registers_request_detailed$is_orig              = T;
    read_write_multiple_registers_request_detailed$source_h             = c$id$orig_h;
    read_write_multiple_registers_request_detailed$source_p             = c$id$orig_p;
    read_write_multiple_registers_request_detailed$destination_h        = c$id$resp_h;
    read_write_multiple_registers_request_detailed$destination_p        = c$id$resp_p;

    read_write_multiple_registers_request_detailed$tid                  = headers$tid;
    read_write_multiple_registers_request_detailed$unit                 = headers$uid;
    read_write_multiple_registers_request_detailed$func                 = Modbus::function_codes[headers$function_code];
    read_write_multiple_registers_request_detailed$request_response     = "REQUEST";
    read_write_multiple_registers_request_detailed$values               = "see modbus_read_write_multiple_registers.log";

    Log::write(LOG_READ_WRITE_MULTIPLE_REGISTERS, read_write_multiple_registers_request);
    Log::write(LOG_DETAILED, read_write_multiple_registers_request_detailed);
}

#############################################################################################################################
####  Defines logging of modbus_read_write_multiple_registers_response event -> modbus_read_write_multiple_registers.log  ###
####  Defines logging of modbus_read_write_multiple_registers_response event -> modbus_detailed.log                       ###
#############################################################################################################################
event modbus_read_write_multiple_registers_response(c: connection, 
                                                    headers: ModbusHeaders, 
                                                    written_registers: ModbusRegisters) {
    
    local read_write_multiple_registers_response: Read_Write_Multiple_Registers;
    local read_write_multiple_registers_response_detailed: Modbus_Detailed;

    read_write_multiple_registers_response$ts                   = network_time();
    read_write_multiple_registers_response$uid                  = c$uid;
    read_write_multiple_registers_response$id                   = c$id;

    read_write_multiple_registers_response$is_orig              = F;
    read_write_multiple_registers_response$source_h             = c$id$resp_h;
    read_write_multiple_registers_response$source_p             = c$id$resp_p;
    read_write_multiple_registers_response$destination_h        = c$id$orig_h;
    read_write_multiple_registers_response$destination_p        = c$id$orig_p;

    read_write_multiple_registers_response$tid                  = headers$tid;
    read_write_multiple_registers_response$unit                 = headers$uid;
    read_write_multiple_registers_response$func                 = Modbus::function_codes[headers$function_code];
    read_write_multiple_registers_response$request_response     = "RESPONSE";
    read_write_multiple_registers_response$read_registers       = written_registers;

    read_write_multiple_registers_response_detailed$ts                   = network_time();
    read_write_multiple_registers_response_detailed$uid                  = c$uid;
    read_write_multiple_registers_response_detailed$id                   = c$id;

    read_write_multiple_registers_response_detailed$is_orig              = F;
    read_write_multiple_registers_response_detailed$source_h             = c$id$resp_h;
    read_write_multiple_registers_response_detailed$source_p             = c$id$resp_p;
    read_write_multiple_registers_response_detailed$destination_h        = c$id$orig_h;
    read_write_multiple_registers_response_detailed$destination_p        = c$id$orig_p;

    read_write_multiple_registers_response_detailed$tid                  = headers$tid;
    read_write_multiple_registers_response_detailed$unit                 = headers$uid;
    read_write_multiple_registers_response_detailed$func                 = Modbus::function_codes[headers$function_code];
    read_write_multiple_registers_response_detailed$request_response     = "RESPONSE";
    read_write_multiple_registers_response_detailed$values               = "see modbus_read_write_multiple_registers.log";

    Log::write(LOG_READ_WRITE_MULTIPLE_REGISTERS, read_write_multiple_registers_response);
    Log::write(LOG_DETAILED, read_write_multiple_registers_response_detailed);
}

#############################################################################################################################
#####################  Defines logging of modbus_read_file_record_request event -> modbus_detailed.log  #####################
#############################################################################################################################
@if (Version::at_least("6.1.0"))
event modbus_read_file_record_request(c: connection,
                                      headers: ModbusHeaders,
                                      byte_count: count,
                                      refs: ModbusFileRecordRequests)
@else
event modbus_read_file_record_request(c: connection,
                                      headers: ModbusHeaders)
@endif
{

    local read_file_record_request: Modbus_Detailed;

    read_file_record_request$ts                 = network_time();
    read_file_record_request$uid                = c$uid;
    read_file_record_request$id                 = c$id;

    read_file_record_request$is_orig            = T;
    read_file_record_request$source_h           = c$id$orig_h;
    read_file_record_request$source_p           = c$id$orig_p;
    read_file_record_request$destination_h      = c$id$resp_h;
    read_file_record_request$destination_p      = c$id$resp_p;

    read_file_record_request$tid                = headers$tid;
    read_file_record_request$unit               = headers$uid;
    read_file_record_request$func               = Modbus::function_codes[headers$function_code];
    read_file_record_request$request_response   = "REQUEST";

    Log::write(LOG_DETAILED, read_file_record_request);
}

#############################################################################################################################
####################  Defines logging of modbus_read_file_record_response event -> modbus_detailed.log  #####################
#############################################################################################################################
@if (Version::at_least("6.1.0"))
event modbus_read_file_record_response(c: connection,
                                       headers: ModbusHeaders,
                                       byte_count: count,
                                       refs: ModbusFileRecordResponses)
@else
event modbus_read_file_record_response(c: connection,
                                       headers: ModbusHeaders)
@endif
{

    local read_file_record_response: Modbus_Detailed; 

    read_file_record_response$ts                = network_time();
    read_file_record_response$uid               = c$uid;
    read_file_record_response$id                = c$id;

    read_file_record_response$is_orig           = F;
    read_file_record_response$source_h          = c$id$resp_h;
    read_file_record_response$source_p          = c$id$resp_p;
    read_file_record_response$destination_h     = c$id$orig_h;
    read_file_record_response$destination_p     = c$id$orig_p;

    read_file_record_response$tid               = headers$tid;
    read_file_record_response$unit              = headers$uid;
    read_file_record_response$func              = Modbus::function_codes[headers$function_code];
    read_file_record_response$request_response  = "RESPONSE";

    Log::write(LOG_DETAILED, read_file_record_response);
}

#############################################################################################################################
####################  Defines logging of modbus_write_file_record_request event -> modbus_detailed.log  #####################
#############################################################################################################################
@if (Version::at_least("6.1.0"))
event modbus_write_file_record_request(c: connection,
                                       headers: ModbusHeaders,
                                       byte_count: count,
                                       refs: ModbusFileReferences)
@else
event modbus_write_file_record_request(c: connection,
                                       headers: ModbusHeaders)
@endif
{

    local write_file_record_request: Modbus_Detailed;

    write_file_record_request$ts                = network_time();
    write_file_record_request$uid               = c$uid;
    write_file_record_request$id                = c$id;

    write_file_record_request$is_orig           = T;
    write_file_record_request$source_h          = c$id$orig_h;
    write_file_record_request$source_p          = c$id$orig_p;
    write_file_record_request$destination_h     = c$id$resp_h;
    write_file_record_request$destination_p     = c$id$resp_p;

    write_file_record_request$tid               = headers$tid;
    write_file_record_request$unit              = headers$uid;
    write_file_record_request$func              = Modbus::function_codes[headers$function_code];
    write_file_record_request$request_response  = "REQUEST";

    Log::write(LOG_DETAILED, write_file_record_request);
}

#############################################################################################################################
###################  Defines logging of modbus_write_file_record_response event -> modbus_detailed.log  #####################
#############################################################################################################################
@if (Version::at_least("6.1.0"))
event modbus_write_file_record_response(c: connection,
                                        headers: ModbusHeaders,
                                        byte_count: count,
                                        refs: ModbusFileReferences)
@else
event modbus_write_file_record_response(c: connection,
                                        headers: ModbusHeaders)
@endif
{

    local write_file_record_response: Modbus_Detailed;

    write_file_record_response$ts                   = network_time();
    write_file_record_response$uid                  = c$uid;
    write_file_record_response$id                   = c$id;

    write_file_record_response$is_orig              = F;
    write_file_record_response$source_h             = c$id$resp_h;
    write_file_record_response$source_p             = c$id$resp_p;
    write_file_record_response$destination_h        = c$id$orig_h;
    write_file_record_response$destination_p        = c$id$orig_p;

    write_file_record_response$tid                  = headers$tid;
    write_file_record_response$unit                 = headers$uid;
    write_file_record_response$func                 = Modbus::function_codes[headers$function_code];
    write_file_record_response$request_response     = "RESPONSE";

    Log::write(LOG_DETAILED, write_file_record_response);
}

#############################################################################################################################
#################  Defines logging of modbus_mask_write_register_request event -> mask_write_register.log  ##################
#################  Defines logging of modbus_mask_write_register_request event -> modbus_detailed.log      ##################
#############################################################################################################################
event modbus_mask_write_register_request(c: connection, 
                                         headers: ModbusHeaders, 
                                         address: count, 
                                         and_mask: count, 
                                         or_mask: count) {

    local mask_write_register_request: Mask_Write_Register;
    local mask_write_register_request_detailed: Modbus_Detailed;
 
    mask_write_register_request$ts                  = network_time();
    mask_write_register_request$uid                 = c$uid;
    mask_write_register_request$id                  = c$id;

    mask_write_register_request$is_orig             = T;
    mask_write_register_request$source_h            = c$id$orig_h;
    mask_write_register_request$source_p            = c$id$orig_p;
    mask_write_register_request$destination_h       = c$id$resp_h;
    mask_write_register_request$destination_p       = c$id$resp_p;

    mask_write_register_request$tid                 = headers$tid;
    mask_write_register_request$unit                = headers$uid;
    mask_write_register_request$func                = Modbus::function_codes[headers$function_code];
    mask_write_register_request$request_response    = "REQUEST";
    mask_write_register_request$address             = address;
    mask_write_register_request$and_mask            = and_mask;
    mask_write_register_request$or_mask             = or_mask;
 
    mask_write_register_request_detailed$ts                  = network_time();
    mask_write_register_request_detailed$uid                 = c$uid;
    mask_write_register_request_detailed$id                  = c$id;

    mask_write_register_request_detailed$is_orig             = T;
    mask_write_register_request_detailed$source_h            = c$id$orig_h;
    mask_write_register_request_detailed$source_p            = c$id$orig_p;
    mask_write_register_request_detailed$destination_h       = c$id$resp_h;
    mask_write_register_request_detailed$destination_p       = c$id$resp_p;

    mask_write_register_request_detailed$tid                 = headers$tid;
    mask_write_register_request_detailed$unit                = headers$uid;
    mask_write_register_request_detailed$func                = Modbus::function_codes[headers$function_code];
    mask_write_register_request_detailed$request_response    = "REQUEST";
    mask_write_register_request_detailed$values              = "see modbus_mask_write_register.log";

    Log::write(LOG_MASK_WRITE_REGISTER, mask_write_register_request);
    Log::write(LOG_DETAILED, mask_write_register_request_detailed);
}

#############################################################################################################################
#################  Defines logging of modbus_mask_write_register_response event -> mask_write_register.log  #################
#################  Defines logging of modbus_mask_write_register_response event -> modbus_detailed.log      #################
#############################################################################################################################
event modbus_mask_write_register_response(c: connection, 
                                          headers: ModbusHeaders, 
                                          address: count,
                                          and_mask: count, 
                                          or_mask: count) {
  
    local mask_write_register_response: Mask_Write_Register;
    local mask_write_register_response_detailed: Modbus_Detailed;

    mask_write_register_response$ts                 = network_time();
    mask_write_register_response$uid                = c$uid;
    mask_write_register_response$id                 = c$id;

    mask_write_register_response$is_orig            = F;
    mask_write_register_response$source_h           = c$id$resp_h;
    mask_write_register_response$source_p           = c$id$resp_p;
    mask_write_register_response$destination_h      = c$id$orig_h;
    mask_write_register_response$destination_p      = c$id$orig_p;

    mask_write_register_response$tid                = headers$tid;
    mask_write_register_response$unit               = headers$uid;
    mask_write_register_response$func               = Modbus::function_codes[headers$function_code];
    mask_write_register_response$request_response   = "RESPONSE";
    mask_write_register_response$address            = address;
    mask_write_register_response$and_mask           = and_mask;
    mask_write_register_response$or_mask            = or_mask;

    mask_write_register_response_detailed$ts                 = network_time();
    mask_write_register_response_detailed$uid                = c$uid;
    mask_write_register_response_detailed$id                 = c$id;

    mask_write_register_response_detailed$is_orig            = F;
    mask_write_register_response_detailed$source_h           = c$id$resp_h;
    mask_write_register_response_detailed$source_p           = c$id$resp_p;
    mask_write_register_response_detailed$destination_h      = c$id$orig_h;
    mask_write_register_response_detailed$destination_p      = c$id$orig_p;

    mask_write_register_response_detailed$tid                = headers$tid;
    mask_write_register_response_detailed$unit               = headers$uid;
    mask_write_register_response_detailed$func               = Modbus::function_codes[headers$function_code];
    mask_write_register_response_detailed$request_response   = "RESPONSE";
    mask_write_register_response_detailed$values              = "see modbus_mask_write_register.log";

    Log::write(LOG_MASK_WRITE_REGISTER, mask_write_register_response);
    Log::write(LOG_DETAILED, mask_write_register_response_detailed);
}


@if (Version::at_least("6.1.0"))
#############################################################################################################################
########################  Defines logging of modbus_diagnostics_request event -> modbus_detailed.log  #######################
#############################################################################################################################
event modbus_diagnostics_request(c: connection, 
                                 headers: ModbusHeaders, 
                                 subfunction: count, 
                                 data: string) {

    local diagnostics_request: Modbus_Detailed;

    diagnostics_request$ts                  = network_time();
    diagnostics_request$uid                 = c$uid;
    diagnostics_request$id                  = c$id;

    diagnostics_request$is_orig             = T;
    diagnostics_request$source_h            = c$id$orig_h;
    diagnostics_request$source_p            = c$id$orig_p;
    diagnostics_request$destination_h       = c$id$resp_h;
    diagnostics_request$destination_p       = c$id$resp_p;

    diagnostics_request$tid                 = headers$tid;
    diagnostics_request$unit                = headers$uid;
    diagnostics_request$func                = Modbus::function_codes[headers$function_code];
    diagnostics_request$request_response    = "REQUEST";
    diagnostics_request$address             = subfunction;
    diagnostics_request$values              = data;

    Log::write(LOG_DETAILED, diagnostics_request);
}

#############################################################################################################################
#######################  Defines logging of modbus_diagnostics_response event -> modbus_detailed.log  #######################
#############################################################################################################################
event modbus_diagnostics_response(c: connection, 
                                  headers: ModbusHeaders, 
                                  subfunction: count, 
                                  data: string) {

    local diagnostics_response: Modbus_Detailed;

    diagnostics_response$ts                  = network_time();
    diagnostics_response$uid                 = c$uid;
    diagnostics_response$id                  = c$id;

    diagnostics_response$is_orig             = F;
    diagnostics_response$source_h            = c$id$resp_h;
    diagnostics_response$source_p            = c$id$resp_p;
    diagnostics_response$destination_h       = c$id$orig_h;
    diagnostics_response$destination_p       = c$id$orig_p;

    diagnostics_response$tid                 = headers$tid;
    diagnostics_response$unit                = headers$uid;
    diagnostics_response$func                = Modbus::function_codes[headers$function_code];
    diagnostics_response$request_response    = "RESPONSE";
    diagnostics_response$address             = subfunction;
    diagnostics_response$values              = data;

    Log::write(LOG_DETAILED, diagnostics_response);
}

#############################################################################################################################
#######  Defines logging of modbus_read_device_identification_request event -> modbus_read_device_identification.log  #######
#############################################################################################################################
function modbus_read_device_identification_request(c: connection, 
                                                   headers: ModbusHeaders,
                                                   data: string) {


    local read_device_identification_request: Read_Device_Identification;

    read_device_identification_request$ts                  = network_time();
    read_device_identification_request$uid                 = c$uid;
    read_device_identification_request$id                  = c$id;

    read_device_identification_request$is_orig             = T;
    read_device_identification_request$source_h            = c$id$orig_h;
    read_device_identification_request$source_p            = c$id$orig_p;
    read_device_identification_request$destination_h       = c$id$resp_h;
    read_device_identification_request$destination_p       = c$id$resp_p;
    
    read_device_identification_request$request_response    = "REQUEST";
    read_device_identification_request$tid                 = headers$tid;
    read_device_identification_request$unit                = headers$uid;
    read_device_identification_request$func                = Modbus::function_codes[headers$function_code];
    read_device_identification_request$mei_type            = "READ-DEVICE-IDENTIFICATION";
    read_device_identification_request$device_id_code      = bytestring_to_count(data[0]);
    read_device_identification_request$object_id_code      = fmt("0x%02x",bytestring_to_count(data[1]));
    read_device_identification_request$object_id           = device_identification_read_object_id[bytestring_to_count(data[1])];

    Log::write(LOG_READ_DEVICE_IDENTIFICATION, read_device_identification_request);
}


#############################################################################################################################
#######  Defines logging of modbus_read_device_identification_response event -> modbus_read_device_identification.log  ######
#############################################################################################################################
function modbus_read_device_identification_response(c: connection, 
                                                    headers: ModbusHeaders,
                                                    data: string) {

    local read_device_identification_response: Read_Device_Identification;

    read_device_identification_response$ts                      = network_time();
    read_device_identification_response$uid                     = c$uid;
    read_device_identification_response$id                      = c$id;

    read_device_identification_response$is_orig                 = F;
    read_device_identification_response$source_h                = c$id$resp_h;
    read_device_identification_response$source_p                = c$id$resp_p;
    read_device_identification_response$destination_h           = c$id$orig_h;
    read_device_identification_response$destination_p           = c$id$orig_p;
    
    read_device_identification_response$request_response        = "RESPONSE";
    read_device_identification_response$tid                     = headers$tid;
    read_device_identification_response$unit                    = headers$uid;
    read_device_identification_response$func                    = Modbus::function_codes[headers$function_code];
    read_device_identification_response$mei_type                = "READ-DEVICE-IDENTIFICATION";
    read_device_identification_response$device_id_code          = bytestring_to_count(data[0]);
    read_device_identification_response$conformity_level_code   = fmt("0x%02x",bytestring_to_count(data[1]));
    read_device_identification_response$conformity_level        = device_identification_conformity_level[bytestring_to_count(data[1])];

    local num_objects: count = bytestring_to_count(data[4]);
    local object_index: count = 0;
    local byte_index: count = 5;
    local object_length: count;

    while(object_index < num_objects)
    {
        read_device_identification_response$object_id_code      = fmt("0x%02x",bytestring_to_count(data[byte_index]));
        read_device_identification_response$object_id           = device_identification_object_id[bytestring_to_count(data[byte_index])];
        byte_index                                              += 1;
        object_length                                           = bytestring_to_count(data[byte_index]);
        byte_index                                              += 1;
        read_device_identification_response$object_value        = fmt("%s", data[byte_index:byte_index+object_length]);
        byte_index                                              += object_length;

        object_index                                            += 1;
        Log::write(LOG_READ_DEVICE_IDENTIFICATION, read_device_identification_response);
    }
}


#############################################################################################################################
################  Defines logging of modbus_encap_interface_transport_request event -> modbus_detailed.log  #################
#############################################################################################################################
event modbus_encap_interface_transport_request(c: connection, 
                                               headers: ModbusHeaders, 
                                               mei_type: count, 
                                               data: string) {

    local encap_interface_transport_request: Modbus_Detailed;

    encap_interface_transport_request$ts                  = network_time();
    encap_interface_transport_request$uid                 = c$uid;
    encap_interface_transport_request$id                  = c$id;

    encap_interface_transport_request$is_orig             = T;
    encap_interface_transport_request$source_h            = c$id$orig_h;
    encap_interface_transport_request$source_p            = c$id$orig_p;
    encap_interface_transport_request$destination_h       = c$id$resp_h;
    encap_interface_transport_request$destination_p       = c$id$resp_p;

    encap_interface_transport_request$tid                 = headers$tid;
    encap_interface_transport_request$unit                = headers$uid;
    encap_interface_transport_request$func                = Modbus::function_codes[headers$function_code];
    encap_interface_transport_request$request_response    = "REQUEST";

    if (mei_type == 0x0D)
    {
        encap_interface_transport_request$values          = "CANopen";
    }
    else if (mei_type == 0x0E)
    {
        modbus_read_device_identification_request(c, headers, data);
        encap_interface_transport_request$values          = "see modbus_read_device_identification.log";
    }
    else
    {
        encap_interface_transport_request$values          = fmt("invalid encapsulated interface transport mei-(0x%02x)",mei_type);
    }

    Log::write(LOG_DETAILED, encap_interface_transport_request);
}

#############################################################################################################################
###############  Defines logging of modbus_encap_interface_transport_response event -> modbus_detailed.log  #################
#############################################################################################################################
event modbus_encap_interface_transport_response(c: connection, 
                                                headers: ModbusHeaders, 
                                                mei_type: count, 
                                                data: string) {

    local encap_interface_transport_response: Modbus_Detailed;

    encap_interface_transport_response$ts                  = network_time();
    encap_interface_transport_response$uid                 = c$uid;
    encap_interface_transport_response$id                  = c$id;

    encap_interface_transport_response$is_orig             = F;
    encap_interface_transport_response$source_h            = c$id$resp_h;
    encap_interface_transport_response$source_p            = c$id$resp_p;
    encap_interface_transport_response$destination_h       = c$id$orig_h;
    encap_interface_transport_response$destination_p       = c$id$orig_p;

    encap_interface_transport_response$tid                 = headers$tid;
    encap_interface_transport_response$unit                = headers$uid;
    encap_interface_transport_response$func                = Modbus::function_codes[headers$function_code];
    encap_interface_transport_response$request_response    = "RESPONSE";
    
    if (mei_type == 0x0D)
    {
        encap_interface_transport_response$values          = "CANopen";
    }
    else if (mei_type == 0x0E)
    {
        modbus_read_device_identification_response(c, headers, data);
        encap_interface_transport_response$values          = "see modbus_read_device_identification.log";
    }
    else
    {
        encap_interface_transport_response$values          = fmt("unknown encapsulated interface transport mei-(0x%02x)",mei_type);
    }

    Log::write(LOG_DETAILED, encap_interface_transport_response);
}
@endif

#############################################################################################################################
##################################  Logs Modbus connection object to modbus_detailed.log  ###################################
#############################################################################################################################
event modbus_message(c: connection, 
                     headers: ModbusHeaders, 
                     is_orig: bool) &priority=-3 {

    local modbus_detailed_rec: Modbus_Detailed;

    if (( headers$function_code < 0x80)) {

        if (is_orig){
            modbus_detailed_rec$is_orig           = T;
            modbus_detailed_rec$source_h          = c$id$orig_h;
            modbus_detailed_rec$source_p          = c$id$orig_p;
            modbus_detailed_rec$destination_h     = c$id$resp_h;
            modbus_detailed_rec$destination_p     = c$id$resp_p;
            modbus_detailed_rec$request_response  = "REQUEST";
        }else{
            modbus_detailed_rec$is_orig           = F;
            modbus_detailed_rec$source_h          = c$id$resp_h;
            modbus_detailed_rec$source_p          = c$id$resp_p;
            modbus_detailed_rec$destination_h     = c$id$orig_h;
            modbus_detailed_rec$destination_p     = c$id$orig_p;
            modbus_detailed_rec$request_response  = "RESPONSE";
        }

        if ( !handled_modbus_funct_list (c$modbus$func)) {
            modbus_detailed_rec$ts        = network_time();
            modbus_detailed_rec$uid       = c$uid;
            modbus_detailed_rec$id        = c$id;
            modbus_detailed_rec$tid       = headers$tid;
            modbus_detailed_rec$unit      = headers$uid;
            modbus_detailed_rec$func      = Modbus::function_codes[headers$function_code];

            Log::write(LOG_DETAILED, modbus_detailed_rec);
        }
    }
}

#############################################################################################################################
######################  Defines logging of modbus_exception event -> modbus.log & modbus_detailed.log  ######################
#############################################################################################################################
event modbus_exception(c: connection, 
                       headers: ModbusHeaders, 
                       code: count) &priority=-4 {
    
    local exception_detailed: Modbus_Detailed;

    exception_detailed$ts                   = network_time();
    exception_detailed$uid                  = c$uid;
    exception_detailed$id                   = c$id;

    exception_detailed$is_orig              = F;
    exception_detailed$source_h             = c$id$resp_h;
    exception_detailed$source_p             = c$id$resp_p;
    exception_detailed$destination_h        = c$id$orig_h;
    exception_detailed$destination_p        = c$id$orig_p;

    exception_detailed$tid                  = headers$tid;
    exception_detailed$unit                 = headers$uid;
    exception_detailed$func                 = c$modbus$func;
    exception_detailed$request_response     = "RESPONSE";
    exception_detailed$values               = c$modbus$exception;

    Log::write(LOG_DETAILED, exception_detailed);
}
