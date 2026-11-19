// gr-fec LDPC from an attacker-supplied alist parity-check file: the alist parser + cldpc/gf2mat
// generator computation (gr::fec::ldpc_decoder), then belief-propagation decoding of soft input.
// Layout: byte 0 sets the iteration count, the alist text runs up to the first NUL byte, the
// bytes after it are the received soft symbols.
// (The GSL-backed ldpc_H_matrix path is not driven: GSL's default error handler abort()s on the
// first malformed matrix, so fuzzing it only rediscovers that abort.)
#include "gr_fuzz_common.h"
#include <gnuradio/fec/ldpc_decoder.h>
#include <cstring>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    uint8_t sel = data[0];
    data++;
    size--;
    const uint8_t* nul = static_cast<const uint8_t*>(memchr(data, 0, size));
    size_t text_len = nul ? size_t(nul - data) : size;
    const uint8_t* soft = nul ? nul + 1 : data + size;
    size_t soft_len = (data + size) - soft;
    std::string path = gr_fuzz_scratch_file(data, text_len, "input.alist");
    try {
        gr::fec::generic_decoder::sptr dec = gr::fec::ldpc_decoder::make(path, 1 + (sel & 0x3f));
        int n = dec->get_input_size();
        int k = dec->get_output_size();
        if (n <= 0 || k <= 0)
            return 0;
        std::vector<float> in(n, 1.0f);
        for (size_t i = 0; i < soft_len && i < size_t(n); i++)
            in[i] = static_cast<int8_t>(soft[i]) / 32.0f;
        std::vector<uint8_t> out(size_t(n) * dec->get_output_item_size() + 64, 0);
        dec->generic_work(in.data(), out.data());
    } catch (const std::exception&) {
    }
    return 0;
}
