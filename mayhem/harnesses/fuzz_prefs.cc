// gr::prefs configuration-file parsing (add_config_file: INI sections/options), its string dump
// and the typed getters on what was parsed.
#include "gr_fuzz_common.h"
#include <gnuradio/prefs.h>
#include <stdexcept>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    gr_fuzz_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string path = gr_fuzz_scratch_file(data, size, "input.conf");
    try {
        gr::prefs p;
        p.add_config_file(path);
        std::string dump = p.to_string();
        (void)p.get_string("LOG", "log_level", "x");
        (void)p.get_bool("PerfCounters", "on", false);
        (void)p.get_long("LOG", "debug_level", 0);
        (void)p.get_double("DEFAULT", "verbose", 0.0);
        (void)p.has_option("ControlPort", "on");
    } catch (const std::exception&) {
    }
    return 0;
}
