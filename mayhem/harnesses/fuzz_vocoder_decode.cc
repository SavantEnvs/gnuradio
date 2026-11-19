// gr-vocoder bundled decoders on a received code stream: G.721 / G.723 (24 and 40 kbit/s) ADPCM,
// A-law, mu-law and CVSD. Byte 0 picks the decoder; the rest is the encoded stream.
#include "gr_fuzz_common.h"
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/top_block.h>
#include <gnuradio/vocoder/alaw_decode_bs.h>
#include <gnuradio/vocoder/cvsd_decode_bs.h>
#include <gnuradio/vocoder/g721_decode_bs.h>
#include <gnuradio/vocoder/g723_24_decode_bs.h>
#include <gnuradio/vocoder/g723_40_decode_bs.h>
#include <gnuradio/vocoder/ulaw_decode_bs.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2)
        return 0;
    try {
        gr::basic_block_sptr dec;
        switch (data[0] % 6) {
        case 0:
            dec = gr::vocoder::g721_decode_bs::make();
            break;
        case 1:
            dec = gr::vocoder::g723_24_decode_bs::make();
            break;
        case 2:
            dec = gr::vocoder::g723_40_decode_bs::make();
            break;
        case 3:
            dec = gr::vocoder::alaw_decode_bs::make();
            break;
        case 4:
            dec = gr::vocoder::ulaw_decode_bs::make();
            break;
        default:
            dec = gr::vocoder::cvsd_decode_bs::make();
            break;
        }
        std::vector<uint8_t> in(data + 1, data + size);
        auto tb = gr::make_top_block("fuzz");
        auto src = gr::blocks::vector_source_b::make(in, false);
        auto sink = gr::blocks::null_sink::make(sizeof(short));
        tb->connect(src, 0, dec, 0);
        tb->connect(dec, 0, sink, 0);
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
