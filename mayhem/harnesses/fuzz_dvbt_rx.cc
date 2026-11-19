// gr-dtv DVB-T receive chain on received OFDM data cells, as in upstream's dvbt_rx_8k example:
// demap -> symbol inner deinterleaver -> bit inner deinterleaver -> Viterbi -> outer
// convolutional deinterleaver -> RS(204,188) decoder -> energy descrambler (TS sync search).
// The first bytes pick mode/constellation/code rate and the number of OFDM symbols; every other
// byte becomes one received cell (4-bit I, 4-bit Q), repeated cyclically to fill the symbols.
#include "gr_fuzz_common.h"
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/blocks/vector_source.h>
#include <gnuradio/blocks/vector_to_stream.h>
#include <gnuradio/dtv/dvbt_bit_inner_deinterleaver.h>
#include <gnuradio/dtv/dvbt_convolutional_deinterleaver.h>
#include <gnuradio/dtv/dvbt_demap.h>
#include <gnuradio/dtv/dvbt_energy_descramble.h>
#include <gnuradio/dtv/dvbt_reed_solomon_dec.h>
#include <gnuradio/dtv/dvbt_symbol_inner_interleaver.h>
#include <gnuradio/dtv/dvbt_viterbi_decoder.h>
#include <gnuradio/top_block.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 3)
        return 0;
    using namespace gr::dtv;
    const dvb_constellation_t consts[] = { MOD_QPSK, MOD_16QAM, MOD_64QAM };
    const dvb_code_rate_t rates[] = { C1_2, C2_3, C3_4, C5_6, C7_8 };
    dvbt_transmission_mode_t mode = (data[0] & 1) ? T8k : T2k;
    dvb_constellation_t constellation = consts[(data[0] >> 1) % 3];
    dvb_code_rate_t rate = rates[(data[0] >> 3) % 5];
    int nsym = 1 + (data[1] & 0x0f);
    const uint8_t* cells = data + 2;
    size_t ncells_in = size - 2;
    int payload = (mode == T8k) ? 6048 : 1512; // data cells per OFDM symbol (EN 300 744)

    std::vector<gr_complex> in(size_t(payload) * nsym);
    for (size_t i = 0; i < in.size(); i++) {
        uint8_t c = cells[i % ncells_in];
        in[i] = gr_complex(((c & 0xf) - 7.5f) / 5.0f, ((c >> 4) - 7.5f) / 5.0f);
    }
    // dvbt_demod_reference_signals, which feeds dvbt_demap in a real receiver, tags every OFDM
    // symbol with its index in the frame ("symbol_index", 68 symbols per frame) and the first
    // symbol of each superframe ("superframe_start"); the deinterleavers rely on those tags.
    std::vector<gr::tag_t> tags;
    for (int s = 0; s < nsym; s++) {
        gr::tag_t t;
        t.offset = s;
        t.key = pmt::string_to_symbol("symbol_index");
        t.value = pmt::from_long(s % 68);
        tags.push_back(t);
        if (s % (68 * 4) == 0) {
            t.key = pmt::string_to_symbol("superframe_start");
            t.value = pmt::from_long(0xaa);
            tags.push_back(t);
        }
    }
    try {
        auto tb = gr::make_top_block("fuzz");
        auto src = gr::blocks::vector_source_c::make(in, false, payload, tags);
        auto demap = dvbt_demap::make(payload, constellation, NH, mode, 1.0f);
        auto sdeint = dvbt_symbol_inner_interleaver::make(payload, mode, 0);
        auto bdeint = dvbt_bit_inner_deinterleaver::make(payload, constellation, NH, mode);
        auto v2s = gr::blocks::vector_to_stream::make(1, payload);
        auto vit = dvbt_viterbi_decoder::make(constellation, NH, rate, 768);
        auto cdeint = dvbt_convolutional_deinterleaver::make(136, 12, 17);
        auto rs = dvbt_reed_solomon_dec::make(2, 8, 0x11d, 255, 239, 8, 51, 8);
        auto descr = dvbt_energy_descramble::make(8);
        auto sink = gr::blocks::null_sink::make(1);
        tb->connect(src, 0, demap, 0);
        tb->connect(demap, 0, sdeint, 0);
        tb->connect(sdeint, 0, bdeint, 0);
        tb->connect(bdeint, 0, v2s, 0);
        tb->connect(v2s, 0, vit, 0);
        tb->connect(vit, 0, cdeint, 0);
        tb->connect(cdeint, 0, rs, 0);
        tb->connect(rs, 0, descr, 0);
        tb->connect(descr, 0, sink, 0);
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
