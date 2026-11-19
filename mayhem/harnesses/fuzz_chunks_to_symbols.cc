// gr::digital::chunks_to_symbols_{bc,bf} in a flowgraph, with in-stream "set_symbol_table"
// tags (the code path fixed by upstream e791ebb447: overrun after the last tag when D > 1).
//
// Contract (chunks_to_symbols.h): each input chunk is an index into the symbol table, which holds
// D values per symbol, so every input value must be < table.size() / D. The harness reduces each
// input byte modulo the number of symbols; every table (the initial one and those carried by
// tags) has the same size, so that precondition holds for the whole stream.
#include "gr_fuzz_common.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <gnuradio/blocks/vector_sink.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/digital/chunks_to_symbols.h>
#include <gnuradio/top_block.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

template <class T>
static T next_val(FuzzedDataProvider& fdp);
template <>
float next_val<float>(FuzzedDataProvider& fdp)
{
    return fdp.ConsumeIntegral<int8_t>() / 16.0f;
}
template <>
gr_complex next_val<gr_complex>(FuzzedDataProvider& fdp)
{
    float re = fdp.ConsumeIntegral<int8_t>() / 16.0f;
    return gr_complex(re, fdp.ConsumeIntegral<int8_t>() / 16.0f);
}
static pmt::pmt_t to_pmt(const std::vector<float>& v) { return pmt::init_f32vector(v.size(), v); }
static pmt::pmt_t to_pmt(const std::vector<gr_complex>& v)
{
    return pmt::init_c32vector(v.size(), v);
}

template <class T, class SINK>
static void run(FuzzedDataProvider& fdp)
{
    unsigned D = fdp.ConsumeIntegralInRange<unsigned>(1, 4);
    unsigned nsym = fdp.ConsumeIntegralInRange<unsigned>(1, 16);
    auto make_table = [&]() {
        std::vector<T> t(nsym * D);
        for (auto& x : t)
            x = next_val<T>(fdp);
        return t;
    };
    std::vector<T> table = make_table();
    unsigned ntags = fdp.ConsumeIntegralInRange<unsigned>(0, 4);
    std::vector<gr::tag_t> tags;
    for (unsigned i = 0; i < ntags; i++) {
        gr::tag_t tag;
        tag.offset = fdp.ConsumeIntegralInRange<uint64_t>(0, 4096);
        tag.key = pmt::mp("set_symbol_table");
        tag.value = to_pmt(make_table());
        tags.push_back(tag);
    }
    std::vector<uint8_t> in = fdp.ConsumeRemainingBytes<uint8_t>();
    if (in.empty())
        return;
    for (auto& b : in)
        b %= nsym;

    auto tb = gr::make_top_block("fuzz");
    auto src = gr::blocks::vector_source_b::make(in, false, 1, tags);
    auto blk = gr::digital::chunks_to_symbols<uint8_t, T>::make(table, D);
    auto sink = SINK::make();
    tb->connect(src, 0, blk, 0);
    tb->connect(blk, 0, sink, 0);
    tb->run();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try {
        if (fdp.ConsumeBool())
            run<gr_complex, gr::blocks::vector_sink_c>(fdp);
        else
            run<float, gr::blocks::vector_sink_f>(fdp);
    } catch (const std::exception&) {
    }
    return 0;
}
