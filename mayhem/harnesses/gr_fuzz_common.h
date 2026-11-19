// Shared setup for the GNU Radio fuzz harnesses (mayhem/ layer, not upstream code).
//
// State kept across inputs, on purpose:
//  * GR_PREFS_PATH / GR_CACHE_PATH point at one private scratch dir created once under $TMPDIR.
//    GNU Radio writes its vmcircbuf factory choice there on first buffer allocation; it only
//    selects how stream buffers are mapped, never what a block computes, so it cannot make one
//    input's result depend on another.
//  * Logging is turned off once (read-only afterwards); it only affects console output.
//  * gr_fuzz_scratch_file() rewrites the same file in that dir for every input.
#pragma once

#include <gnuradio/logger.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

static std::string g_gr_fuzz_dir;

static inline void gr_fuzz_init()
{
    if (!g_gr_fuzz_dir.empty())
        return;
    const char* t = getenv("TMPDIR");
    std::string tmpl = std::string((t && *t) ? t : "/tmp") + "/grfuzz-XXXXXX";
    if (char* d = mkdtemp(&tmpl[0])) {
        g_gr_fuzz_dir = d;
    } else {
        g_gr_fuzz_dir = ".";
    }
    setenv("GR_PREFS_PATH", g_gr_fuzz_dir.c_str(), 1);
    setenv("GR_CACHE_PATH", g_gr_fuzz_dir.c_str(), 1);
    setenv("TMP", g_gr_fuzz_dir.c_str(), 1);
    gr::logging::singleton().set_default_level(spdlog::level::off);
    gr::logging::singleton().set_debug_level(spdlog::level::off);
}

// Write the input to a fixed scratch file (overwritten per input) and return its path.
static inline std::string
gr_fuzz_scratch_file(const uint8_t* data, size_t size, const char* name = "input")
{
    std::string path = g_gr_fuzz_dir + "/" + name;
    FILE* f = fopen(path.c_str(), "wb");
    if (!f)
        abort(); // the scratch dir is ours; failing to write it is a harness bug
    if (size && fwrite(data, 1, size, f) != size)
        abort();
    fclose(f);
    return path;
}
