// Access-code correlators and legacy framers on a received bit/soft-bit stream:
// correlate_access_code_bb_ts / _ff_ts (length-header decode, tagged-stream emission),
// correlate_access_code_tag_bb, and correlate_access_code_bb -> framer_sink_1 (msg_queue).
// Byte 0 picks the variant and threshold; each following byte gives 8 received bits.
#include "gr_fuzz_common.h"
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/digital/correlate_access_code_bb.h>
#include <gnuradio/digital/correlate_access_code_bb_ts.h>
#include <gnuradio/digital/correlate_access_code_ff_ts.h>
#include <gnuradio/digital/correlate_access_code_tag_bb.h>
#include <gnuradio/digital/framer_sink_1.h>
#include <gnuradio/msg_queue.h>
#include <gnuradio/top_block.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

// Default GNU Radio packet access code (digital.packet_utils.default_access_code).
static const std::string kCode = "1010110011011101101001001110001011110010100011000010000011111100";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2)
        return 0;
    int variant = data[0] & 3;
    int threshold = (data[0] >> 2) & 7;
    std::vector<uint8_t> bits;
    for (size_t i = 1; i < size; i++)
        for (int b = 7; b >= 0; b--)
            bits.push_back((data[i] >> b) & 1);
    try {
        auto tb = gr::make_top_block("fuzz");
        if (variant == 1) {
            std::vector<float> soft;
            for (uint8_t b : bits)
                soft.push_back(b ? 1.0f : -1.0f);
            auto src = gr::blocks::vector_source_f::make(soft, false);
            auto corr = gr::digital::correlate_access_code_ff_ts::make(kCode, threshold, "len");
            auto sink = gr::blocks::null_sink::make(sizeof(float));
            tb->connect(src, 0, corr, 0);
            tb->connect(corr, 0, sink, 0);
        } else {
            auto src = gr::blocks::vector_source_b::make(bits, false);
            if (variant == 0) {
                auto corr =
                    gr::digital::correlate_access_code_bb_ts::make(kCode, threshold, "len");
                auto sink = gr::blocks::null_sink::make(1);
                tb->connect(src, 0, corr, 0);
                tb->connect(corr, 0, sink, 0);
            } else if (variant == 2) {
                auto corr =
                    gr::digital::correlate_access_code_tag_bb::make(kCode, threshold, "sync");
                auto sink = gr::blocks::null_sink::make(1);
                tb->connect(src, 0, corr, 0);
                tb->connect(corr, 0, sink, 0);
            } else {
                auto corr = gr::digital::correlate_access_code_bb::make(kCode, threshold);
                auto q = gr::msg_queue::make(0);
                auto framer = gr::digital::framer_sink_1::make(q);
                tb->connect(src, 0, corr, 0);
                tb->connect(corr, 0, framer, 0);
            }
        }
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
