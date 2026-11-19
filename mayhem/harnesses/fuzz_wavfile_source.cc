// gr::blocks::wavfile_source on an attacker-supplied audio file: header/format handling and
// sample conversion for every channel.
#include "gr_fuzz_common.h"
#include <gnuradio/blocks/head.h>
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/blocks/wavfile_source.h>
#include <gnuradio/top_block.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string path = gr_fuzz_scratch_file(data, size, "input.wav");
    try {
        auto src = gr::blocks::wavfile_source::make(path.c_str(), false);
        int nch = src->channels();
        auto tb = gr::make_top_block("fuzz");
        for (int c = 0; c < nch; c++) {
            auto head = gr::blocks::head::make(sizeof(float), 1 << 15);
            auto sink = gr::blocks::null_sink::make(sizeof(float));
            tb->connect(src, c, head, 0);
            tb->connect(head, 0, sink, 0);
        }
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
