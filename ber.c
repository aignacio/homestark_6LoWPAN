#include <string.h>
#include <stdlib.h>
#include "snmp.h"
#include "ber.h"

/*-----------------------------------------------------------------------------------*/
/*
 * Decode BER encoded sequence header.
 */
resp_con_t ber_decode_sequence(const u8t* const input, const u16t len, u16t* pos)
{
    u8t type;
    u16t length;
    TRY(ber_decode_type_length(input, len, pos, &type, &length));
    if (type != BER_TYPE_SEQUENCE || length != (len - *pos)) {
        snmp_log("bad type or length value for an expected sequence: type %02X length %d\n", type, length);
        return -1;
    }
    return 0;
}
