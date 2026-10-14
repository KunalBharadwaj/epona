# GoogleTest via FetchContent -- no system package required.
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
# Don't let gtest override our compiler/linker flags on Windows (harmless here).
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(tcpstack_tests
    test_byteorder.cpp
    test_buffer.cpp
    test_checksum.cpp
    test_address.cpp
    test_ethernet.cpp
    test_arp.cpp
    test_ipv4.cpp
    test_icmp.cpp
    test_udp.cpp
    test_seq.cpp
    test_tcp.cpp
    test_sack.cpp
    test_http.cpp
)
target_link_libraries(tcpstack_tests
    PRIVATE tcpstack_lib tcpstack_warnings GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(tcpstack_tests)
