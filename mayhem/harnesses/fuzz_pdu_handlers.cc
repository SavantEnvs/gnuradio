// PDU message handlers fed an attacker-supplied PMT (deserialized from the input, as it arrives
// from a socket, ZMQ or a file): gr-pdu pdu_split/pdu_filter/pdu_remove/pdu_set/pdu_to_tagged_stream/
// time_delta/add_system_time and the gr-digital async CRC blocks + crc_append/crc_check.
// Byte 0 picks the block; the rest is a serialized PMT that is posted to each of the block's
// message input ports, followed by the scheduler's "done" message, and the flowgraph is run.
#include "gr_fuzz_common.h"
#include <gnuradio/digital/crc16_async_bb.h>
#include <gnuradio/digital/crc32_async_bb.h>
#include <gnuradio/digital/crc_append.h>
#include <gnuradio/digital/crc_check.h>
#include <gnuradio/pdu/add_system_time.h>
#include <gnuradio/pdu/pdu_filter.h>
#include <gnuradio/pdu/pdu_remove.h>
#include <gnuradio/pdu/pdu_set.h>
#include <gnuradio/pdu/pdu_split.h>
#include <gnuradio/pdu/pdu_to_tagged_stream.h>
#include <gnuradio/pdu/time_delta.h>
#include <gnuradio/blocks/message_debug.h>
#include <gnuradio/blocks/null_sink.h>
#include <gnuradio/top_block.h>
#include <pmt/pmt.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

static gr::basic_block_sptr make_block(uint8_t sel)
{
    switch (sel % 12) {
    case 0:
        return gr::pdu::pdu_split::make(sel & 0x80);
    case 1:
        return gr::pdu::pdu_filter::make(pmt::mp("k"), pmt::from_long(1), sel & 0x80);
    case 2:
        return gr::pdu::pdu_remove::make(pmt::mp("k"));
    case 3:
        return gr::pdu::pdu_set::make(pmt::mp("k"), pmt::from_long(1));
    case 4:
        return gr::pdu::pdu_to_tagged_stream::make(gr::types::byte_t, "packet_len");
    case 5:
        return gr::pdu::time_delta::make(pmt::mp("delta"), pmt::mp("time"));
    case 6:
        return gr::pdu::add_system_time::make(pmt::mp("time"));
    case 7:
        return gr::digital::crc32_async_bb::make(sel & 0x80);
    case 8:
        return gr::digital::crc16_async_bb::make(sel & 0x80);
    case 9:
        return gr::digital::crc_append::make(32, 0x4C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true, true,
                                             false, sel & 0x80 ? 4 : 0);
    case 10:
        return gr::digital::crc_check::make(32, 0x4C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true, true,
                                            false, sel & 0x80, sel & 0x40 ? 4 : 0);
    default:
        return gr::digital::crc_check::make(16, 0x1021, 0xFFFF, 0xFFFF, false, false, false,
                                            true, 0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    try {
        pmt::pmt_t msg =
            pmt::deserialize_str(std::string(reinterpret_cast<const char*>(data + 1), size - 1));
        gr::basic_block_sptr blk = make_block(data[0]);
        auto tb = gr::make_top_block("fuzz");
        auto dbg = gr::blocks::message_debug::make();
        if (blk->output_signature()->max_streams() != 0)
            tb->connect(blk, 0, gr::blocks::null_sink::make(blk->output_signature()->sizeof_stream_item(0)), 0);
        pmt::pmt_t outs = blk->message_ports_out();
        for (size_t i = 0; i < pmt::length(outs); i++)
            tb->msg_connect(blk, pmt::symbol_to_string(pmt::nth(i, outs)), dbg, "store");
        pmt::pmt_t ins = blk->message_ports_in();
        for (size_t i = 0; i < pmt::length(ins); i++) {
            pmt::pmt_t port = pmt::nth(i, ins);
            if (pmt::eqv(port, pmt::mp("system")))
                continue;
            blk->_post(port, msg);
        }
        blk->_post(pmt::mp("system"), pmt::cons(pmt::mp("done"), pmt::from_long(1)));
        tb->run();
    } catch (const std::exception&) {
    }
    return 0;
}
