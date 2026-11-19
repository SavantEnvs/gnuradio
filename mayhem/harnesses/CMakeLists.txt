# Fuzz harnesses for GNU Radio (mayhem/ layer). Configured by mayhem/build.sh against the
# sanitized GNU Radio install in build-fuzz/prefix. Each harness is linked twice: with libFuzzer
# (<name>) and with the run-once standalone driver (<name>-standalone).
cmake_minimum_required(VERSION 3.16)
project(gnuradio_fuzz LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Gnuradio REQUIRED COMPONENTS runtime pmt blocks fft filter analog digital fec trellis pdu vocoder dtv)

set(LIB_FUZZING_ENGINE "-fsanitize=fuzzer" CACHE STRING "libFuzzer link flag")
set(STANDALONE_FUZZ_MAIN "" CACHE FILEPATH "run-once driver source")

set(LSAN_OFF_SRC "" CACHE FILEPATH "__lsan_is_turned_off() hook source")
add_library(lsan_off OBJECT ${LSAN_OFF_SRC})
add_library(standalone_main OBJECT ${STANDALONE_FUZZ_MAIN})
set_source_files_properties(${STANDALONE_FUZZ_MAIN} PROPERTIES LANGUAGE C)

set(GR_LIBS gnuradio::gnuradio-runtime gnuradio::gnuradio-pmt gnuradio::gnuradio-blocks
            gnuradio::gnuradio-digital gnuradio::gnuradio-fec gnuradio::gnuradio-trellis
            gnuradio::gnuradio-pdu gnuradio::gnuradio-vocoder gnuradio::gnuradio-dtv)

set(HARNESSES
    fuzz_pmt_deserialize fuzz_chunks_to_symbols fuzz_file_meta_source fuzz_wavfile_source
    fuzz_protocol_parser fuzz_packet_headerparser fuzz_hdlc_deframer fuzz_correlate_access_code
    fuzz_trellis_fsm fuzz_ldpc_alist fuzz_fec_decoder fuzz_pdu_handlers fuzz_vocoder_decode
    fuzz_prefs fuzz_dvbt_rx)

foreach(h ${HARNESSES})
    add_executable(${h} ${h}.cc $<TARGET_OBJECTS:lsan_off>)
    target_compile_options(${h} PRIVATE -fsanitize=fuzzer-no-link)
    target_link_libraries(${h} PRIVATE ${GR_LIBS})
    target_link_options(${h} PRIVATE ${LIB_FUZZING_ENGINE})

    add_executable(${h}-standalone ${h}.cc $<TARGET_OBJECTS:lsan_off>
                                   $<TARGET_OBJECTS:standalone_main>)
    target_link_libraries(${h}-standalone PRIVATE ${GR_LIBS})
endforeach()
