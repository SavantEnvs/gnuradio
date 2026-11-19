// gr::digital::packet_headerparser_b with packet_header_default / packet_header_ofdm: header
// bit-field decoding (length, number, CRC8), OFDM header descrambling, on received header bits.
#include "gr_fuzz_common.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/digital/packet_header_default.h>
#include <gnuradio/digital/packet_header_ofdm.h>
#include <gnuradio/digital/packet_headerparser_b.h>
#include <gnuradio/top_block.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try {
        gr::digital::packet_header_default::sptr hdr;
        int bps = fdp.ConsumeIntegralInRange<int>(1, 4);
        if (fdp.ConsumeBool()) {
            long len = fdp.ConsumeIntegralInRange<long>(8, 64);
            hdr = gr::digital::packet_header_default::make(len, "packet_len", "packet_num",
                                                           bps);
        } else {
            std::vector<std::vector<int>> occ = { { -6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6 },
                                                  { -7, -5, -3, -1, 1, 3, 5, 7 } };
            // The header spans the first n_syms OFDM symbols, so n_syms <= occ.size()
            // (packet_header_ofdm.h: "occupied_carriers ... n_syms").
            int n_syms = fdp.ConsumeIntegralInRange<int>(1, occ.size());
            hdr = gr::digital::packet_header_ofdm::make(occ, n_syms, "packet_len", "frame_len",
                                                        "packet_num", 1, bps,
                                                        fdp.ConsumeBool());
        }
        std::vector<uint8_t> in = fdp.ConsumeRemainingBytes<uint8_t>();
        // Input is unpacked bits (packet_headerparser_b.h); keep the LSB of each byte.
        for (auto& b : in)
            b &= 1;
        if (in.empty())
            return 0;
        auto tb = gr::make_top_block("fuzz");
        auto src = gr::blocks::vector_source_b::make(in, false);
        auto parser = gr::digital::packet_headerparser_b::make(hdr);
        tb->connect(src, 0, parser, 0);
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
