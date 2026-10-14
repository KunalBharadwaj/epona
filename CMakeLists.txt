cmake_minimum_required(VERSION 3.20)
project(tcpstack LANGUAGES CXX)

# ---- Language standard -------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# ---- Warnings ----------------------------------------------------------------
add_library(tcpstack_warnings INTERFACE)
target_compile_options(tcpstack_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

# ---- Sanitizers (on by default; the guide says day one) ----------------------
option(TCPSTACK_SANITIZE "Build with Address+UB sanitizers" ON)
add_library(tcpstack_sanitizers INTERFACE)
if(TCPSTACK_SANITIZE)
    target_compile_options(tcpstack_sanitizers INTERFACE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(tcpstack_sanitizers INTERFACE
        -fsanitize=address,undefined)
endif()

# ---- The stack library -------------------------------------------------------
# Every protocol layer compiles into this one library; the app and the tests
# both link it. src/ is the include root so headers are "net/buffer.hpp" etc.
add_library(tcpstack_lib
    src/net/tap_device.cpp
    src/net/event_loop.cpp
    src/eth/ethernet.cpp
    src/eth/arp.cpp
    src/ip/ipv4.cpp
    src/ip/icmp.cpp
    src/udp/udp.cpp
    src/tcp/tcp.cpp
    src/tcp/tcp_connection.cpp
    src/stack.cpp
)
target_include_directories(tcpstack_lib PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(tcpstack_lib
    PUBLIC  tcpstack_sanitizers
    PRIVATE tcpstack_warnings)

# ---- The application ---------------------------------------------------------
add_executable(tcpstack src/main.cpp)
target_link_libraries(tcpstack PRIVATE tcpstack_lib tcpstack_warnings)

# ---- Tests -------------------------------------------------------------------
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
