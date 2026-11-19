// gr::blocks::file_meta_source on an attacker-supplied metadata file (inline header): PMT header
// parsing, extras, segment handling, tag generation and item reads.
#include "gr_fuzz_common.h"
#include <gnuradio/blocks/file_meta_source.h>
#include <gnuradio/blocks/head.h>
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/top_block.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string path = gr_fuzz_scratch_file(data, size, "input.dat");
    try {
        auto src = gr::blocks::file_meta_source::make(path, false, false, "");
        size_t itemsize = src->output_signature()->sizeof_stream_item(0);
        auto tb = gr::make_top_block("fuzz");
        auto head = gr::blocks::head::make(itemsize, 1 << 16);
        auto sink = gr::blocks::null_sink::make(itemsize);
        tb->connect(src, 0, head, 0);
        tb->connect(head, 0, sink, 0);
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
