// gr::trellis::fsm from an attacker-supplied FSM text file (I S O + next-state/output tables,
// PS/PI and TM table generation), then Viterbi decoding over that trellis in a flowgraph.
// Layout: the FSM text runs up to the first NUL byte; the bytes after it are branch metrics.
#include "gr_fuzz_common.h"
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/top_block.h>
#include <gnuradio/trellis/fsm.h>
#include <gnuradio/trellis/viterbi.h>
#include <cstring>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const uint8_t* nul = static_cast<const uint8_t*>(memchr(data, 0, size));
    size_t text_len = nul ? size_t(nul - data) : size;
    const uint8_t* rest = nul ? nul + 1 : data + size;
    size_t rest_len = (data + size) - rest;
    std::string path = gr_fuzz_scratch_file(data, text_len, "input.fsm");
    try {
        gr::trellis::fsm f(path.c_str());
        if (rest_len < 1)
            return 0;
        int K = 1 + (rest[0] & 0x1f);
        rest++;
        rest_len--;
        std::vector<float> metrics;
        for (size_t i = 0; i < rest_len; i++)
            metrics.push_back(static_cast<int8_t>(rest[i]) / 8.0f);
        if (metrics.empty())
            return 0;
        auto tb = gr::make_top_block("fuzz");
        auto src = gr::blocks::vector_source_f::make(metrics, false);
        auto vit = gr::trellis::viterbi_b::make(f, K, -1, -1);
        auto sink = gr::blocks::null_sink::make(sizeof(uint8_t));
        tb->connect(src, 0, vit, 0);
        tb->connect(vit, 0, sink, 0);
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
