module Modbus_Extended;

export {
    # Define a set of handled Modbus function codes
    const diagnostic_subfunction_code  = {
        [0x00] =  "Return Query Data",
        [0x01] =  "Restart Communications Option",
        [0x02] =  "Return Diagnostic Register",
        [0x03] =  "Change ASCII Input Delimiter",
        [0x04] =  "Force Listen Only Mode",
        [0x0A] =  "Clear Counters and Diagnostic Register",
        [0x0B] =  "Return Bus Message Count",
        [0x0C] =  "Return Bus Communication Error Count",
        [0x0D] =  "Return Bus Exception Error Count",
        [0x0E] =  "Return Server Message Count",
        [0x0F] =  "Return Server No Response Count",
        [0x10] =  "Return Server NAK Count",
        [0x11] =  "Return Server Busy Count",
        [0x12] =  "Return Bus Character Overrun Count",
        [0x14] =  "Clear Overrun Counter and Flag"
    } &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;
}