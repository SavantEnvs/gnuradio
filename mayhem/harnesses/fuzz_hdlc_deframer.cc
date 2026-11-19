// gr::digital::hdlc_deframer_bp: HDLC flag search, bit de-stuffing, length bounds, CRC-CCITT
// check and PDU emission on a received bit stream (each input byte gives 8 bits).
#include "gr_fuzz_common.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/digital/hdlc_deframer_bp.h>
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
        // Frame length bounds are configuration, not received data: keep them in the range the
        // block documents (defaults 32..500 bytes; length_max sets the output multiple).
        int len_min = fdp.ConsumeIntegralInRange<int>(4, 64);
        int len_max = fdp.ConsumeIntegralInRange<int>(64, 600);
        std::vector<uint8_t> bytes = fdp.ConsumeRemainingBytes<uint8_t>();
        std::vector<uint8_t> bits;
        for (uint8_t b : bytes)
            for (int i = 0; i < 8; i++)
                bits.push_back((b >> i) & 1);
        if (bits.empty())
            return 0;
        auto tb = gr::make_top_block("fuzz");
        auto src = gr::blocks::vector_source_b::make(bits, false);
        auto deframer = gr::digital::hdlc_deframer_bp::make(len_min, len_max);
        tb->connect(src, 0, deframer, 0);
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
