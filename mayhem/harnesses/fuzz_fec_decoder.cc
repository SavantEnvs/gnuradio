// gr-fec decoder kernels (cc_decoder Viterbi in all modes, repetition, polar SC and SC-list),
// driven through the public generic_decoder API on received soft symbols, and through the
// gr::fec::decoder deployment block in a flowgraph.
#include "gr_fuzz_common.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/fec/cc_decoder.h>
#include <gnuradio/fec/decoder.h>
#include <gnuradio/fec/polar_decoder_sc.h>
#include <gnuradio/fec/polar_decoder_sc_list.h>
#include <gnuradio/fec/repetition_decoder.h>
#include <gnuradio/top_block.h>
#include <algorithm>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

static gr::fec::generic_decoder::sptr make_decoder(FuzzedDataProvider& fdp)
{
    switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
    case 0: {
        // Frame sizes from 64 bits up: in CC_TAILBITING mode generic_work() re-reads
        // (veclen - frame_size) * rate input symbols, more than a shorter frame provides.
        int frame = fdp.ConsumeIntegralInRange<int>(64, 512);
        auto mode = static_cast<cc_mode_t>(fdp.ConsumeIntegralInRange<int>(0, 3));
        bool padded = fdp.ConsumeBool();
        return gr::fec::code::cc_decoder::make(
            frame, 7, 2, { 109, 79 }, 0, -1, mode, padded);
    }
    case 1: {
        int frame = fdp.ConsumeIntegralInRange<int>(1, 512);
        int rep = fdp.ConsumeIntegralInRange<int>(1, 8);
        return gr::fec::code::repetition_decoder::make(frame, rep, 0.5f);
    }
    default: {
        // Polar codes: block size is a power of two; frozen positions are a sorted subset.
        int n = 1 << fdp.ConsumeIntegralInRange<int>(3, 9);
        int k = fdp.ConsumeIntegralInRange<int>(1, n - 1);
        std::vector<int> frozen;
        for (int i = 0; i < n && (int)frozen.size() < n - k; i++)
            frozen.push_back(i);
        std::vector<uint8_t> frozen_vals(frozen.size(), 0);
        if (fdp.ConsumeBool())
            return gr::fec::code::polar_decoder_sc::make(n, k, frozen, frozen_vals);
        int list = 1 << fdp.ConsumeIntegralInRange<int>(0, 3);
        return gr::fec::code::polar_decoder_sc_list::make(list, n, k, frozen, frozen_vals);
    }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try {
        auto dec = make_decoder(fdp);
        bool flowgraph = fdp.ConsumeBool();
        int in_items = dec->get_input_size();
        int out_items = dec->get_output_size();
        int in_isz = dec->get_input_item_size();
        int out_isz = dec->get_output_item_size();
        if (in_items <= 0 || out_items <= 0)
            return 0;
        if (!flowgraph) {
            // Soft symbols: finite values, as a demodulator produces.
            std::vector<uint8_t> in(size_t(in_items) * in_isz, 0);
            if (in_isz == (int)sizeof(float)) {
                for (int i = 0; i < in_items; i++) {
                    float v = fdp.ConsumeIntegral<int8_t>() / 32.0f;
                    memcpy(&in[size_t(i) * 4], &v, 4);
                }
            } else {
                std::vector<uint8_t> b = fdp.ConsumeBytes<uint8_t>(in.size());
                std::copy(b.begin(), b.end(), in.begin());
            }
            std::vector<uint8_t> out(size_t(out_items) * out_isz + 64, 0);
            dec->generic_work(in.data(), out.data());
        } else {
            if (in_isz != (int)sizeof(float))
                return 0; // gr::fec::decoder's float input path; byte-input decoders use generic_work above
            std::vector<float> in;
            while (fdp.remaining_bytes())
                in.push_back(fdp.ConsumeIntegral<int8_t>() / 32.0f);
            if (in.empty())
                return 0;
            auto tb = gr::make_top_block("fuzz");
            auto src = gr::blocks::vector_source_f::make(in, false);
            auto blk = gr::fec::decoder::make(dec, sizeof(float), out_isz);
            auto sink = gr::blocks::null_sink::make(out_isz);
            tb->connect(src, 0, blk, 0);
            tb->connect(blk, 0, sink, 0);
            tb->run();
        }
    } catch (const std::exception&) {
    }
    return 0;
}
