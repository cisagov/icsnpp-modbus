@load base/frameworks/logging

module ics;

export {
    redef enum Log::ID += { LOG };

    const debug_logging = T;
    const request_ttl = 30sec;
    const connection_ttl = 1min;

    function debug(msg: string, info: any)
    {
        if (debug_logging) {
            print fmt("DEBUG: %s : %s", msg, info);
        }
    }

    type Value: record {
        t: string &log;
        s: string &log &optional;
        b: bool &log &optional;
        i: int &log &optional;
        f: double &log &optional;
    };

    function value_for_bool(value: bool): Value
    {
        return Value($t="bool", $b=value, $i=|value|);
    }

    function value_for_int(value: int): Value
    {
        return Value($t="int", $i=value);
    }

    type DataPoint: record {
        ts: time &log;
        uid: string &log;
        protocol: string &log;
        ip: addr &log;
        unit: string &log &optional;
        transaction: string &log &optional;
        action: string &log;
        data_type: string &log;
        address: string &log;
        value: Value &log &optional;
    };

    event ics_data_point(data: DataPoint)
    {
        Log::write(ics::LOG, data);
    }
}

event zeek_init()
{
    print "here";
    Log::create_stream(ics::LOG, [$columns=DataPoint, $path="ics_data"]);
}

