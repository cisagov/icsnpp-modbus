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
        ts                        : time              &log;             # Timestamp of event
        uid                       : string            &log;             # Zeek unique ID for connection
        id                        : conn_id           &log;             # Zeek connection struct (addresses and ports)
        tid                       : count             &log &optional;   # Modbus transaction id
        unit                      : count             &log &optional;   # Modbus terminal unit identifier
        func                      : string            &log &optional;   # Modbus Function
        address                   : count             &log &optional;   # Starting address for value(s) field
        quantity		          : count             &log &optional;
        request_values            : vector of count   &optional &log;   #  Value(s) of coils, discrete_inputs, or registers in the request
	    response_values           : vector of count   &optional &log;   #  Value(s) of coils, discrete_inputs, or registers in the response 
	    modbus_detailed_link_id   : string            &log &optional;
	    matched			          : bool 		      &log &optional;
        request_subfunction_code  : string            &log &optional;   # Diagnostic subfunction code in the request
        response_subfunction_code : string            &log &optional;   # Diagnostic subfunction code in the response
        request_data              : string            &log &optional;   # Any additional data or padding in the request
        response_data             : string            &log &optional;   # Any additional data or padding in the response
        exception_code            : string            &log &optional;   # Exception code in the response
        mei_type                  : string            &log &optional;   # MEI Type in the encap interface transport
    };
    global modbus_pending: table[string] of table[count] of Modbus_Detailed; 
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
        modbus_detailed_link_id : string            &log &optional;   # Link to the Modbus_Detailed log record
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
        ts                      : time              &log;             # Timestamp of event
        uid                     : string            &log;             # Zeek unique ID for connection
        id                      : conn_id           &log;             # Zeek connection struct (addresses and ports)
        is_orig                 : bool              &log;             # the message came from the originator/client or the responder/server
        source_h                : addr              &log;             # Source IP Address
        source_p                : port              &log;             # Source Port
        destination_h           : addr              &log;             # Destination IP Address
        destination_p           : port              &log;	          # Destination IP
        modbus_detailed_link_id : string            &log &optional;   # Link to the Modbus_Detailed log record
        tid                     : count             &log &optional;   # Modbus transaction id
        unit                    : count             &log &optional;   # Modbus terminal unit identifier
        func                    : string            &log &optional;   # Modbus Function
        request_response        : string            &log &optional;   # REQUEST or RESPONSE
        write_start_address     : count             &log &optional;   # Starting address of the registers to write to
        write_registers         : ModbusRegisters   &log &optional;   # Register values written
        read_start_address      : count             &log &optional;   # Starting address of the registers to read
        read_quantity           : count             &log &optional;   # Number of registers to read
        read_registers          : ModbusRegisters   &log &optional;   # Register values read
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
        modbus_detailed_link_id : string            &log &optional;   # Link to the Modbus_Detailed log record
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

const request_string: string = "REQUEST";
const response_string: string = "RESPONSE";
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
#######################################  Converts Count Vector to List of Count Values ######################################
#############################################################################################################################
function counts_to_misc_string (count_vector: vector of count): string {

    local first_iter = T;
    local ret_str = "";

    for ([i] in count_vector) {
        if (first_iter) {
            ret_str = fmt("%d", count_vector[i]);
            first_iter = F;
        }
        else
            ret_str = fmt("%s,%d", ret_str, count_vector[i]);
    }

    return ret_str;
}
#############################################################################################################################
#######################################  Slice Vector of Bool ###############################################################
#############################################################################################################################
function vector_slice_bool(v: vector of bool, len: count, start_address: count): vector of bool {
    local result: vector of bool = vector();

    local i = 0;
    while (i < len) {
        result += v[start_address + i];
        i += 1;
    }

    return result;
}

#############################################################################################################################
################################### Vector of Bool to Vector of Count  ######################################################
#############################################################################################################################
function bool_vec_to_count_vec(bools: vector of bool): vector of count {
    local counts: vector of count;

    for (i in bools) {
        if ( bools[i] )
            counts[i] = 1;
        else
            counts[i] = 0;
    }

    return counts;
}

#############################################################################################################################
######################################### Generate a Unique ID  #############################################################
#############################################################################################################################
function generate_uid(): string{
    local charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    local uid = "";
    local len = 16;
    local i = 0;

    while (i < len)
        {
        local index = rand(|charset| -1);
        uid += sub_bytes(charset, index, 1);
        i +=1;
        }

    return uid;
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
    modbus_pending[request_string] = table();
    modbus_pending[response_string] = table();
}

#############################################################################################################################
###################  Defines logging of modbus_read_discrete_inputs_request event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_discrete_inputs_request(c: connection, 
					                      headers: ModbusHeaders,
				   	                      start_address: count,
                                          quantity: count){

    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = start_address;
        resp$quantity = quantity;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=start_address,
                                                       $quantity=quantity];
    }
}

#############################################################################################################################
##################  Defines logging of modbus_read_discrete_inputs_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_discrete_inputs_response(c: connection, 
                                           headers: ModbusHeaders, 
                                           coils: ModbusCoils){

 
    if(request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
    	local req = modbus_pending[request_string][headers$tid];
        local coil_count = req$quantity;
        local sliced = vector_slice_bool(coils, coil_count, 0);
	    req$response_values = bool_vec_to_count_vec(sliced);
        local padding_size: count = |coils| - coil_count;
        if (padding_size > 0) {
            local padding_data: string = "";
            local padding: vector of bool = vector_slice_bool(coils, padding_size, coil_count);
            local padding_counts: vector of count = bool_vec_to_count_vec(padding);
            padding_data = counts_to_misc_string(padding_counts);
            req$response_data = padding_data;  
        }

	    req$matched = T;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
        return;

    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $quantity=|coils|,
                                                        $response_values = bool_vec_to_count_vec(coils)];
    }   
}

#############################################################################################################################
########################  Defines logging of modbus_read_coils_request event -> modbus_detailed.log  ########################
#############################################################################################################################
event modbus_read_coils_request(c: connection,
                                headers: ModbusHeaders,
                                start_address: count,
                                quantity: count){
                            
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = start_address;
        resp$quantity = quantity;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=start_address,
				                                       $quantity=quantity];
    }
}

#############################################################################################################################
#######################  Defines logging of modbus_read_coils_response event -> modbus_detailed.log  ########################
#############################################################################################################################
event modbus_read_coils_response(c: connection,
                                 headers: ModbusHeaders,
                                 coils: ModbusCoils){

    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {        
        local req = modbus_pending[request_string][headers$tid];
        local coil_count = req$quantity;
        local sliced = vector_slice_bool(coils, coil_count, 0);
	    req$response_values = bool_vec_to_count_vec(sliced);
        local padding_size: count = |coils| - coil_count;
        if (padding_size > 0) {
            local padding_data: string = "";
            local padding: vector of bool = vector_slice_bool(coils, padding_size, coil_count);
            local padding_counts: vector of count = bool_vec_to_count_vec(padding);
            padding_data = counts_to_misc_string(padding_counts);
            req$response_data = padding_data;  
        }
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $quantity=|coils|,
                                                        $response_values = bool_vec_to_count_vec(coils)];
    }
}

#############################################################################################################################
##################  Defines logging of modbus_read_input_registers_request event -> modbus_detailed.log  ####################
#############################################################################################################################
event modbus_read_input_registers_request(c: connection,
                                          headers: ModbusHeaders,
                                          start_address: count,
                                          quantity: count) {

    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = start_address;
        resp$quantity = quantity;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }

    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=start_address,
				                                       $quantity=quantity];
    }
}

#############################################################################################################################
##################  Defines logging of modbus_read_input_registers_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_input_registers_response(c: connection,
                                           headers: ModbusHeaders,
                                           registers: ModbusRegisters) {

    # local sliced = vector_slice_count(registers, req$address, register_count);
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        local req = modbus_pending[request_string][headers$tid];
        local register_count = req$quantity;
        req$response_values = registers;
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $quantity=|registers|,
                                                        $response_values = registers];
    }
}

#############################################################################################################################
##################  Defines logging of modbus_read_holding_registers_request event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_read_holding_registers_request(c: connection,
                                            headers: ModbusHeaders,
                                            start_address: count,
                                            quantity: count) {


    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = start_address;
        resp$quantity = quantity;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=start_address,
                                                       $quantity=quantity];
    }
}

#############################################################################################################################
#################  Defines logging of modbus_read_holding_registers_response event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_read_holding_registers_response(c: connection,
                                             headers: ModbusHeaders,
                                             registers: ModbusRegisters) {
    
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {

        local req = modbus_pending[request_string][headers$tid];
        local register_count = req$quantity; 
        req$response_values = registers;
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        delete modbus_pending[request_string][headers$tid];
    }

    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $quantity=|registers|,
                                                        $response_values = registers];
    }
}

#############################################################################################################################
#####################  Defines logging of modbus_read_fifo_queue_request event -> modbus_detailed.log  ######################
#############################################################################################################################
event modbus_read_fifo_queue_request(c: connection,
                                     headers: ModbusHeaders,
                                     start_address: count) {


    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = start_address;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
                                        
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                    $uid=c$uid,
                                    $id=c$id,
                                    $tid=headers$tid,
                                    $func=Modbus::function_codes[headers$function_code],
                                    $unit=headers$uid,
                                    $address=start_address];
    }

}

#############################################################################################################################
#####################  Defines logging of modbus_read_fifo_queue_response event -> modbus_detailed.log  #####################
#############################################################################################################################
event modbus_read_fifo_queue_response(c: connection,
                                      headers: ModbusHeaders,
                                      fifos: ModbusRegisters) {

    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        local req = modbus_pending[request_string][headers$tid];
        if (|fifos| > 0){
            req$response_values=fifos;
        }
        req$quantity = |fifos|;
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }

    else {
        if (|fifos| > 0){
            modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                            $uid=c$uid,
                                                            $id=c$id,
                                                            $tid=headers$tid,
                                                            $func=Modbus::function_codes[headers$function_code],
                                                            $unit=headers$uid,
                                                            $quantity=|fifos|,
                                                            $response_values = fifos];
        }
        else {
            modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                            $uid=c$uid,
                                                            $id=c$id,
                                                            $tid=headers$tid,
                                                            $func=Modbus::function_codes[headers$function_code],
                                                            $unit=headers$uid,
                                                            $quantity=|fifos|];
        }
    }
}

#############################################################################################################################
#####################  Defines logging of modbus_write_single_coil_request event -> modbus_detailed.log  ####################
#############################################################################################################################

event modbus_write_single_coil_request(c: connection,
                                       headers: ModbusHeaders,
                                       address: count,
                                       value: bool) {

    local val: vector of bool = vector(value);
	local request_values = bool_vec_to_count_vec(val);

    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = address;
        resp$quantity = 1;
        resp$request_values = request_values;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=address,
                                                       $request_values=request_values,
				                                       $quantity=1];
    }
}


#############################################################################################################################
####################  Defines logging of modbus_write_single_coil_response event -> modbus_detailed.log  ####################
#############################################################################################################################
event modbus_write_single_coil_response(c: connection,
                                        headers: ModbusHeaders,
                                        address: count,
                                        value: bool) {
	
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
     	local req = modbus_pending[request_string][headers$tid];
        local val = vector(value);
	    req$response_values = bool_vec_to_count_vec(val);
        req$address = address;
        req$quantity = 1;
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $quantity=1,
                                                        $address=address,
                                                        $response_values = bool_vec_to_count_vec(vector(value))];
    }	
}

#############################################################################################################################
###################  Defines logging of modbus_write_single_register_request event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_write_single_register_request(c: connection,
                                           headers: ModbusHeaders,
                                           address: count,
                                           value: count) {

    local val = vector(value);
	local request_values: vector of count = val;
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {   
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = address;
        resp$quantity = 1;
        resp$request_values = request_values;
        resp$unit = headers$uid;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }

    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=address,
                                                       $request_values=request_values,
                                                       $quantity=1];  
    }  
}

#############################################################################################################################
##################  Defines logging of modbus_write_single_register_response event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_write_single_register_response(c: connection,
                                            headers: ModbusHeaders,
                                            address: count,
                                            value: count) {

    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        local req = modbus_pending[request_string][headers$tid];
        local val = vector(value);
	    req$response_values = val;
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];

    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $quantity=1,
                                                        $address=address,
                                                        $response_values = vector(value)];
    }
}

#############################################################################################################################
###################  Defines logging of modbus_write_multiple_coils_request event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_write_multiple_coils_request(c: connection,
                                          headers: ModbusHeaders,
                                          start_address: count,
                                          coils: ModbusCoils) {

    local request_values: vector of count = bool_vec_to_count_vec(coils);
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {   
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = start_address;
        resp$quantity = |coils|;
        resp$request_values = request_values;
        resp$unit = headers$uid;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }

    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=start_address,
                                                       $request_values=request_values,
                                                       $quantity=|coils|];
    }

}

#############################################################################################################################
##################  Defines logging of modbus_write_multiple_coils_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_write_multiple_coils_response(c: connection,
                                           headers: ModbusHeaders,
                                           start_address: count,
                                           quantity: count) {
    
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        local req = modbus_pending[request_string][headers$tid];
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }

    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $quantity=quantity,
                                                        $address=start_address];
    }
}

#############################################################################################################################
#################  Defines logging of modbus_write_multiple_registers_request event -> modbus_detailed.log  #################
#############################################################################################################################
event modbus_write_multiple_registers_request(c: connection,
                                               headers: ModbusHeaders,
                                               start_address: count,
                                               registers: ModbusRegisters) {
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$address = start_address;
        resp$quantity = |registers|;
        resp$request_values = registers;
        resp$unit = headers$uid;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=start_address,
                                                       $request_values=registers,
                                                       $quantity=|registers|];
    }
}

#############################################################################################################################
#################  Defines logging of modbus_write_multiple_registers_response event -> modbus_detailed.log  ################
#############################################################################################################################
event modbus_write_multiple_registers_response(c: connection,
                                               headers: ModbusHeaders,
                                               start_address: count,
                                               quantity: count) {
    
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        local req = modbus_pending[request_string][headers$tid];
        req$quantity = quantity;
        req$matched = T;
        req$address = start_address;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $quantity=quantity,
                                                        $address=start_address];
    }

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

    local modbus_connection_id: string = generate_uid();

    local read_write_multiple_registers_request: Read_Write_Multiple_Registers;

    read_write_multiple_registers_request$ts                        = network_time();
    read_write_multiple_registers_request$uid                       = c$uid;
    read_write_multiple_registers_request$id                        = c$id;

    read_write_multiple_registers_request$is_orig                   = T;
    read_write_multiple_registers_request$source_h                  = c$id$orig_h;
    read_write_multiple_registers_request$source_p                  = c$id$orig_p;
    read_write_multiple_registers_request$destination_h             = c$id$resp_h;
    read_write_multiple_registers_request$destination_p             = c$id$resp_p;

    read_write_multiple_registers_request$tid                       = headers$tid;
    read_write_multiple_registers_request$unit                      = headers$uid;
    read_write_multiple_registers_request$func                      = Modbus::function_codes[headers$function_code];
    read_write_multiple_registers_request$request_response          = "REQUEST";
    read_write_multiple_registers_request$read_start_address        = read_start_address;
    read_write_multiple_registers_request$read_quantity             = read_quantity;
    read_write_multiple_registers_request$write_start_address       = write_start_address;
    read_write_multiple_registers_request$write_registers           = write_registers;
    read_write_multiple_registers_request$modbus_detailed_link_id   = modbus_connection_id;

    Log::write(LOG_READ_WRITE_MULTIPLE_REGISTERS, read_write_multiple_registers_request);

    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;

        Log::write(LOG_DETAILED, resp);
        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $modbus_detailed_link_id=modbus_connection_id]; 
    }   
}

#############################################################################################################################
####  Defines logging of modbus_read_write_multiple_registers_response event -> modbus_read_write_multiple_registers.log  ###
####  Defines logging of modbus_read_write_multiple_registers_response event -> modbus_detailed.log                       ###
#############################################################################################################################
event modbus_read_write_multiple_registers_response(c: connection,
                                                    headers: ModbusHeaders,
                                                    written_registers: ModbusRegisters) {

    local read_write_multiple_registers_response: Read_Write_Multiple_Registers;
    local modbus_connection_id: string = "";

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
  

    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) { {
        local req = modbus_pending[request_string][headers$tid];
        req$matched = T;
        modbus_connection_id = req$modbus_detailed_link_id;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
        } 
    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $modbus_detailed_link_id=modbus_connection_id];
    }
    read_write_multiple_registers_response$modbus_detailed_link_id = modbus_connection_id;
    Log::write(LOG_READ_WRITE_MULTIPLE_REGISTERS, read_write_multiple_registers_response);
}

#############################################################################################################################
#####################  Defines logging of modbus_read_file_record_request event -> modbus_detailed.log  #####################
#############################################################################################################################
##check this one to deal with ModbusFileRecordRequests!!##
@if ( Version::at_least("6.1.0") )
event modbus_read_file_record_request(c: connection,
                                      headers: ModbusHeaders,
                                      byte_count: count,
                                      refs: ModbusFileRecordRequests)
{
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {   
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$quantity=|refs|;

        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $quantity=|refs|];
    }
}
@else
event modbus_read_file_record_request(c: connection,
                                      headers: ModbusHeaders)
{
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {   
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;

        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }

    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid];
    }
}
@endif


#############################################################################################################################
####################  Defines logging of modbus_read_file_record_response event -> modbus_detailed.log  #####################
#############################################################################################################################
##double check this one!!##
@if ( Version::at_least("6.1.0") )
event modbus_read_file_record_response(c: connection,
                                       headers: ModbusHeaders,
                                       byte_count: count,
                                       refs: ModbusFileRecordResponses)
{
    local response_data = "";
    for ( i in refs )
    {
        local ref_str = fmt("%s", refs[i]);
        response_data = response_data == "" ? ref_str : fmt("%s | %s", response_data, ref_str);
    }
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string])
    {
        local req = modbus_pending[request_string][headers$tid];

        # Build response_data from refs
        if (response_data != "") {
            req$response_data = response_data;
        } 
    
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        delete modbus_pending[request_string][headers$tid];
    }
    else {
        if (response_data != "") {
            modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                            $uid=c$uid,
                                                            $id=c$id,
                                                            $tid=headers$tid,
                                                            $func=Modbus::function_codes[headers$function_code],
                                                            $unit=headers$uid,
                                                            $response_data=response_data];
        }
        else {
            modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                            $uid=c$uid,
                                                            $id=c$id,
                                                            $tid=headers$tid,
                                                            $func=Modbus::function_codes[headers$function_code],
                                                            $unit=headers$uid];
        }
    }
}
@else
event modbus_read_file_record_response(c: connection,
                                       headers: ModbusHeaders)
{
    if ( request_string in modbus_pending && headers$tid in modbus_pending[request_string] )
    {
        local req = modbus_pending[request_string][headers$tid];

        req$matched = T;

        Log::write(LOG_DETAILED, req);

        delete modbus_pending[request_string][headers$tid];
    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid];
    }
}
@endif

#############################################################################################################################
####################  Defines logging of modbus_write_file_record_request event -> modbus_detailed.log  #####################
#############################################################################################################################
@if (Version::at_least("6.1.0"))
event modbus_write_file_record_request(c: connection,
                                       headers: ModbusHeaders,
                                       byte_count: count,
                                       refs: ModbusFileReferences) 
{
    
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {   
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        resp$quantity=|refs|;

        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $quantity=|refs|];
    }
}
@else
event modbus_write_file_record_request(c: connection,
                                       headers: ModbusHeaders)
{
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {   
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;
        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }

    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid];
    }
}
@endif

#############################################################################################################################
###################  Defines logging of modbus_write_file_record_response event -> modbus_detailed.log  #####################
#############################################################################################################################
@if (Version::at_least("6.1.0"))
event modbus_write_file_record_response(c: connection,
                                        headers: ModbusHeaders,
                                        byte_count: count,
                                        refs: ModbusFileReferences)
{

    # Build response_data from refs
    local response_data = "";
    for ( i in refs )
    {
        local ref_str = fmt("%s", refs[i]);
        response_data = response_data == "" ? ref_str : fmt("%s | %s", response_data, ref_str);
    }

    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string])
    {
        local req = modbus_pending[request_string][headers$tid];

        if (response_data != "") {
            req$response_data = response_data;
        }
        req$matched = T;

        Log::write(LOG_DETAILED, req);

        delete modbus_pending[request_string][headers$tid];
    }

    else {
        if (response_data == "") {
            modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                            $uid=c$uid,
                                                            $id=c$id,
                                                            $tid=headers$tid,
                                                            $func=Modbus::function_codes[headers$function_code],
                                                            $unit=headers$uid,
                                                            $response_data=response_data];
        }
        else {
            modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                            $uid=c$uid,
                                                            $id=c$id,
                                                            $tid=headers$tid,
                                                            $func=Modbus::function_codes[headers$function_code],
                                                            $unit=headers$uid];
        }
    }

}
@else
event modbus_write_file_record_response(c: connection,
                                        headers: ModbusHeaders)
{
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string])
    {
        local req = modbus_pending[request_string][headers$tid];

        req$matched = T;

        Log::write(LOG_DETAILED, req);

        delete modbus_pending[request_string][headers$tid];
    }

    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid];
    }

}
@endif



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
    local modbus_connection_id: string = generate_uid();

    mask_write_register_request$ts                      = network_time();
    mask_write_register_request$uid                     = c$uid;
    mask_write_register_request$id                      = c$id;

    mask_write_register_request$is_orig                 = T;
    mask_write_register_request$source_h                = c$id$orig_h;
    mask_write_register_request$source_p                = c$id$orig_p;
    mask_write_register_request$destination_h           = c$id$resp_h;
    mask_write_register_request$destination_p           = c$id$resp_p;

    mask_write_register_request$tid                     = headers$tid;
    mask_write_register_request$unit                    = headers$uid;
    mask_write_register_request$func                    = Modbus::function_codes[headers$function_code];
    mask_write_register_request$request_response        = "REQUEST";
    mask_write_register_request$address                 = address;
    mask_write_register_request$and_mask                = and_mask;
    mask_write_register_request$or_mask                 = or_mask;
    mask_write_register_request$modbus_detailed_link_id = modbus_connection_id;

    Log::write(LOG_MASK_WRITE_REGISTER, mask_write_register_request);    

    
    if (response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;

        Log::write(LOG_DETAILED, resp);
        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $address=address,
                                                       $modbus_detailed_link_id=modbus_connection_id];
    }
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
    local modbus_connection_id: string = "";

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

    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        local req = modbus_pending[request_string][headers$tid];
        
        req$matched = T;
        modbus_connection_id = req$modbus_detailed_link_id;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }

    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $address=address,
                                                        $modbus_detailed_link_id=modbus_connection_id];
    }

    mask_write_register_response$modbus_detailed_link_id = modbus_connection_id;

    Log::write(LOG_MASK_WRITE_REGISTER, mask_write_register_response);    

}

@if (Version::at_least("6.1.0"))
#############################################################################################################################
########################  Defines logging of modbus_diagnostics_request event -> modbus_detailed.log  #######################
#############################################################################################################################
event modbus_diagnostics_request(c: connection,
                                 headers: ModbusHeaders,
                                 subfunction: count,
                                 data: string) {
   
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {   
        local resp = modbus_pending[response_string][headers$tid];
        resp$matched = T;

        resp$request_subfunction_code += diagnostic_subfunction_code[subfunction];
        resp$request_data += data;

        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }
    else {                 
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $request_subfunction_code=diagnostic_subfunction_code[subfunction],
                                                       $request_data=data];
    }
}

#############################################################################################################################
#######################  Defines logging of modbus_diagnostics_response event -> modbus_detailed.log  #######################
#############################################################################################################################
event modbus_diagnostics_response(c: connection,
                                  headers: ModbusHeaders,
                                  subfunction: count,
                                  data: string) {
    
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        local req = modbus_pending[request_string][headers$tid];
        req$response_data = data;
        req$matched = T;
        req$response_subfunction_code = diagnostic_subfunction_code[subfunction];

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }
    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $response_subfunction_code=diagnostic_subfunction_code[subfunction],
                                                        $response_data=data];
    }
}

#############################################################################################################################
#######  Defines logging of modbus_read_device_identification_request event -> modbus_read_device_identification.log  #######
#############################################################################################################################
function modbus_read_device_identification_request(c: connection,
                                                   headers: ModbusHeaders,
                                                   data: string,
                                                   connection_id: string) {


    local read_device_identification_request: Read_Device_Identification;

    read_device_identification_request$ts                       = network_time();
    read_device_identification_request$uid                      = c$uid;
    read_device_identification_request$id                       = c$id;

    read_device_identification_request$is_orig                  = T;
    read_device_identification_request$source_h                 = c$id$orig_h;
    read_device_identification_request$source_p                 = c$id$orig_p;
    read_device_identification_request$destination_h            = c$id$resp_h;
    read_device_identification_request$destination_p            = c$id$resp_p;

    read_device_identification_request$modbus_detailed_link_id  = connection_id;  
    read_device_identification_request$request_response         = "REQUEST";
    read_device_identification_request$tid                      = headers$tid;
    read_device_identification_request$unit                     = headers$uid;
    read_device_identification_request$func                     = Modbus::function_codes[headers$function_code];
    read_device_identification_request$mei_type                 = "READ-DEVICE-IDENTIFICATION";
    read_device_identification_request$device_id_code           = bytestring_to_count(data[0]);
    read_device_identification_request$object_id_code           = fmt("0x%02x",bytestring_to_count(data[1]));
    read_device_identification_request$object_id                = device_identification_read_object_id[bytestring_to_count(data[1])];

    Log::write(LOG_READ_DEVICE_IDENTIFICATION, read_device_identification_request);
}

#############################################################################################################################
#######  Defines logging of modbus_read_device_identification_response event -> modbus_read_device_identification.log  ######
#############################################################################################################################
function modbus_read_device_identification_response(c: connection,
                                                    headers: ModbusHeaders,
                                                    data: string,
                                                    connection_id: string) {

    local read_device_identification_response: Read_Device_Identification;

    read_device_identification_response$ts                      = network_time();
    read_device_identification_response$uid                     = c$uid;
    read_device_identification_response$id                      = c$id;

    read_device_identification_response$is_orig                 = F;
    read_device_identification_response$source_h                = c$id$resp_h;
    read_device_identification_response$source_p                = c$id$resp_p;
    read_device_identification_response$destination_h           = c$id$orig_h;
    read_device_identification_response$destination_p           = c$id$orig_p;

    read_device_identification_response$modbus_detailed_link_id = connection_id;  
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

        object_index						+= 1;

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

    local modbus_connection_id: string = generate_uid();
    local misc: string;
    local resp: Modbus_Detailed;
    if (response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {
        resp = modbus_pending[response_string][headers$tid];
        modbus_connection_id = resp$modbus_detailed_link_id;
    }
    if (mei_type == 0x0D)
    {
        misc = "CANopen";
	#encap_interface_transport_request$values          = "CANopen";
    }
    else if (mei_type == 0x0E)
    {
        modbus_read_device_identification_request(c, headers, data, modbus_connection_id);
        misc = "Read Device Identification";
	#encap_interface_transport_request$values          = "see modbus_read_device_identification.log";
    }
    else
    {
	    misc = fmt("invalid encapsulated interface transport mei-(0x%02x)", mei_type);
        #encap_interface_transport_request$values          = fmt("invalid encapsulated interface transport mei-(0x%02x)",mei_type);
    }
    if(response_string in modbus_pending && headers$tid in modbus_pending[response_string]) {  
        resp$matched = T;

        if (resp$mei_type != "") {
            if (resp$mei_type != misc) {
                resp$mei_type += " and " + misc;
            }
        }
        else {
            resp$mei_type = misc;
        }

        Log::write(LOG_DETAILED, resp);

        delete modbus_pending[response_string][headers$tid];
        return;
    }

    else{
        modbus_pending[request_string][headers$tid] = [$ts=network_time(),
                                                       $uid=c$uid,
                                                       $id=c$id,
                                                       $tid=headers$tid,
                                                       $func=Modbus::function_codes[headers$function_code],
                                                       $unit=headers$uid,
                                                       $mei_type=misc,
                                                       $modbus_detailed_link_id=modbus_connection_id];
    }
}

#############################################################################################################################
###############  Defines logging of modbus_encap_interface_transport_response event -> modbus_detailed.log  #################
#############################################################################################################################
event modbus_encap_interface_transport_response(c: connection,
                                                headers: ModbusHeaders,
                                                mei_type: count,
                                                data: string) {
    local misc: string;
    local modbus_connection_id: string = generate_uid();
    local req: Modbus_Detailed;
    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        req = modbus_pending[request_string][headers$tid];
        modbus_connection_id = req$modbus_detailed_link_id;
    }
    if (mei_type == 0x0D)
    {
        misc = "CANopen";
    }
    else if (mei_type == 0x0E)
    {
        modbus_read_device_identification_response(c, headers, data, modbus_connection_id);
        misc = "Read Device Identification";
    }
    else
    {
        misc = fmt("unknown encapsulated interface transport mei-(ox%02x)", mei_type);
    }

    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        req$matched = T;
        if (req$mei_type != "") {
            if (req$mei_type != misc) {
                req$mei_type += " and " + misc;
            }
        }
        else {
            req$mei_type = misc;
        }


        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }

    else {
        modbus_pending[response_string][headers$tid] = [$ts=network_time(),
                                                        $uid=c$uid,
                                                        $id=c$id,
                                                        $tid=headers$tid,
                                                        $func=Modbus::function_codes[headers$function_code],
                                                        $unit=headers$uid,
                                                        $mei_type=misc,
                                                        $modbus_detailed_link_id=modbus_connection_id];
    }
}
@endif

#############################################################################################################################
##################################  Logs Modbus connection object to modbus_detailed.log  ###################################
#############################################################################################################################
#This event causes my entire log to get messed up!! Why?!?!#
event modbus_message(c: connection,
                     headers: ModbusHeaders,
                     is_orig: bool) &priority=-3 {

    local modbus_detailed_rec: Modbus_Detailed;

    if (( headers$function_code < 0x80)) {

	# look over how to handle this because maybe i can make this neater??
    if ( !handled_modbus_funct_list (c$modbus$func)) {
        modbus_detailed_rec = [$ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $tid=headers$tid,
                               $func=Modbus::function_codes[headers$function_code],
                               $unit=headers$uid];
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

    if (request_string in modbus_pending && headers$tid in modbus_pending[request_string]) {
        local req = modbus_pending[request_string][headers$tid];
        req$matched = T;
        req$exception_code = c$modbus$exception;

        Log::write(LOG_DETAILED, req);

        #cleanup
        delete modbus_pending[request_string][headers$tid];
    }

    else {
        exception_detailed$ts                   = network_time();
        exception_detailed$uid                  = c$uid;
        exception_detailed$id                   = c$id;

        exception_detailed$tid                  = headers$tid;
        exception_detailed$unit                 = headers$uid;
        exception_detailed$func                 = c$modbus$func;
        exception_detailed$exception_code           = c$modbus$exception;

        Log::write(LOG_DETAILED, exception_detailed);
    }
}

event connection_state_remove(c: connection) {
    for ( id in modbus_pending[request_string] ) {
        local req: Modbus_Detailed = modbus_pending[request_string][id];
        req$matched = F;
        Log::write(LOG_DETAILED, req);
    }
    for ( id in modbus_pending[response_string] ) {
        local resp: Modbus_Detailed = modbus_pending[response_string][id];
        resp$matched = F;
        Log::write(LOG_DETAILED, resp);
    }
}

