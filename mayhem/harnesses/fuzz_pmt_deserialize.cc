// PMT binary deserializer: the wire format GNU Radio uses for messages, metadata file headers,
// ZMQ/socket PDUs and tags. Deserialize, then print and re-serialize the result.
#include "gr_fuzz_common.h"
#include <pmt/pmt.h>
#include <pmt/pmt_serial_tags.h>
#include <sstream>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string s(reinterpret_cast<const char*>(data), size);
    try {
        pmt::pmt_t p = pmt::deserialize_str(s);
        std::string text = pmt::write_string(p);
        std::string again = pmt::serialize_str(p);
        pmt::pmt_t q = pmt::deserialize_str(again);
        (void)pmt::write_string(q);
    } catch (const std::exception&) {
    }
    return 0;
}
