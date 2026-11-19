// gr::digital header_format_* parsers (default, counter, crc, ofdm) as protocol_parser_b drives
// them: access-code search, header_buffer bit extraction, CRC checks and length/counter/OFDM
// field parsing of a received bit stream. The bits are fed through the public
// header_format_base::parse() API the way protocol_parser_b_impl::work() calls it (repeatedly,
// advancing by the number of bits the parser reports as processed), from a heap buffer so
// out-of-bounds reads are visible.
#include "gr_fuzz_common.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <gnuradio/digital/header_format_counter.h>
#include <gnuradio/digital/header_format_crc.h>
#include <gnuradio/digital/header_format_default.h>
#include <gnuradio/digital/header_format_ofdm.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

// Default GNU Radio packet access code (digital.packet_utils.default_access_code).
static const std::string kAccessCode =
    "1010110011011101101001001110001011110010100011000010000011111100";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try {
        gr::digital::header_format_base::sptr fmt;
        int threshold = fdp.ConsumeIntegralInRange<int>(0, 3);
        int bps = fdp.ConsumeIntegralInRange<int>(1, 3);
        switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
        case 0:
            fmt = gr::digital::header_format_default::make(kAccessCode, threshold, bps);
            break;
        case 1:
            fmt = gr::digital::header_format_counter::make(kAccessCode, threshold, bps);
            break;
        case 2:
            fmt = gr::digital::header_format_crc::make("packet_len", "packet_num");
            break;
        default: {
            // 802.11-style carrier allocation; the header spans the first n_syms symbols, so
            // n_syms <= occ.size() (header_format_ofdm.h).
            std::vector<int> c;
            for (int k = -26; k <= 26; k++)
                if (k != 0 && k != -21 && k != -7 && k != 7 && k != 21)
                    c.push_back(k);
            std::vector<std::vector<int>> occ(4, c);
            int n_syms = fdp.ConsumeIntegralInRange<int>(1, occ.size());
            fmt = gr::digital::header_format_ofdm::make(occ, n_syms, "packet_len",
                                                         "frame_len", "packet_num", 1,
                                                         bps, fdp.ConsumeBool());
            break;
        }
        }
        std::vector<uint8_t> bytes = fdp.ConsumeRemainingBytes<uint8_t>();
        std::vector<uint8_t> bits;
        bits.reserve(bytes.size() * 8);
        for (uint8_t b : bytes)
            for (int i = 7; i >= 0; i--)
                bits.push_back((b >> i) & 1);
        if (bits.empty())
            return 0;
        // protocol_parser_b's input is unpacked bits; give the parser an exact-size heap copy.
        size_t offset = 0;
        while (offset < bits.size()) {
            std::vector<uint8_t> window(bits.begin() + offset, bits.end());
            std::vector<pmt::pmt_t> info;
            int count = 0;
            fmt->parse(int(window.size()), window.data(), info, count);
            for (auto& p : info)
                (void)pmt::write_string(p);
            if (count <= 0)
                break;
            offset += size_t(count);
        }
    } catch (const std::exception&) {
    }
    return 0;
}
