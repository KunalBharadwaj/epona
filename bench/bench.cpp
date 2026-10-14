//
// Benchmark harness for the user-space TCP stack.
//
// Runs as an ordinary Linux-sockets client against a TCP echo server, so it
// measures the full path through whatever stack is listening. Point it at our
// stack (10.0.0.2:7777) or, for a fair baseline, at a kernel echo server on
// loopback (this same tool's `server` mode).
//
//   bench server <port>                         # kernel echo server (baseline)
//   bench <ip> <port> latency    [count] [size] # ping-pong RTT percentiles
//   bench <ip> <port> throughput [bytes]         # bulk echo MB/s
//   bench <ip> <port> connrate   [count]         # connections (handshakes)/sec
//
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;

namespace {

[[noreturn]] void die(const char* msg) {
    std::perror(msg);
    std::exit(1);
}

int dial(const char* ip, std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); // latency: no Nagle
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    ::inet_pton(AF_INET, ip, &sa.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) die("connect");
    return fd;
}

bool write_all(int fd, const char* buf, std::size_t n) {
    std::size_t off = 0;
    while (off < n) {
        ssize_t w = ::write(fd, buf + off, n - off);
        if (w <= 0) return false;
        off += static_cast<std::size_t>(w);
    }
    return true;
}

bool read_all(int fd, char* buf, std::size_t n) {
    std::size_t off = 0;
    while (off < n) {
        ssize_t r = ::read(fd, buf + off, n - off);
        if (r <= 0) return false;
        off += static_cast<std::size_t>(r);
    }
    return true;
}

double pct(std::vector<double>& v, double p) {
    if (v.empty()) return 0;
    std::size_t idx = static_cast<std::size_t>(p / 100.0 * (static_cast<double>(v.size()) - 1) + 0.5);
    return v[std::min(idx, v.size() - 1)];
}

// ---- modes ----------------------------------------------------------------

int run_server(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) die("bind");
    if (::listen(fd, 128) < 0) die("listen");
    std::printf("kernel echo server on 127.0.0.1:%u (Ctrl-C to quit)\n", port);
    for (;;) {
        int c = ::accept(fd, nullptr, nullptr);
        if (c < 0) continue;
        int n = 1;
        ::setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &n, sizeof(n));
        std::thread([c] {
            char buf[65536];
            for (;;) {
                ssize_t r = ::read(c, buf, sizeof(buf));
                if (r <= 0) break;
                if (!write_all(c, buf, static_cast<std::size_t>(r))) break;
            }
            ::close(c);
        }).detach();
    }
}

int run_latency(const char* ip, std::uint16_t port, int count, std::size_t size) {
    int fd = dial(ip, port);
    std::vector<char> out(size, 'x'), in(size);
    std::vector<double> us;
    us.reserve(static_cast<std::size_t>(count));

    // Warm up (handshake + first-segment effects out of the sample).
    for (int i = 0; i < 100; ++i) { write_all(fd, out.data(), size); read_all(fd, in.data(), size); }

    for (int i = 0; i < count; ++i) {
        auto t0 = Clock::now();
        if (!write_all(fd, out.data(), size) || !read_all(fd, in.data(), size)) die("io");
        auto t1 = Clock::now();
        us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
    }
    ::close(fd);
    std::sort(us.begin(), us.end());

    std::printf("latency over %d round-trips of %zuB (%s:%u)\n", count, size, ip, port);
    std::printf("  min   %8.1f us\n", us.front());
    std::printf("  p50   %8.1f us\n", pct(us, 50));
    std::printf("  p90   %8.1f us\n", pct(us, 90));
    std::printf("  p99   %8.1f us\n", pct(us, 99));
    std::printf("  p99.9 %8.1f us\n", pct(us, 99.9));
    std::printf("  max   %8.1f us\n", us.back());
    return 0;
}

int run_throughput(const char* ip, std::uint16_t port, std::size_t total) {
    int fd = dial(ip, port);
    std::atomic<bool> send_ok{true};
    auto t0 = Clock::now();

    std::thread sender([&] {
        std::vector<char> buf(65536, 'a');
        std::size_t left = total;
        while (left > 0) {
            std::size_t chunk = std::min(buf.size(), left);
            if (!write_all(fd, buf.data(), chunk)) { send_ok = false; break; }
            left -= chunk;
        }
        ::shutdown(fd, SHUT_WR); // tell peer we're done sending
    });

    std::vector<char> in(65536);
    std::size_t got = 0;
    while (got < total) {
        ssize_t r = ::read(fd, in.data(), in.size());
        if (r <= 0) break;
        got += static_cast<std::size_t>(r);
    }
    auto t1 = Clock::now();
    sender.join();
    ::close(fd);

    double s = std::chrono::duration<double>(t1 - t0).count();
    std::printf("throughput (%s:%u): echoed %zu/%zu bytes in %.3fs\n", ip, port, got, total, s);
    std::printf("  one-way %6.1f MB/s | round-trip %6.1f MB/s\n",
                static_cast<double>(total) / 1e6 / s, static_cast<double>(2 * total) / 1e6 / s);
    return send_ok ? 0 : 1;
}

int run_connrate(const char* ip, std::uint16_t port, int count) {
    auto t0 = Clock::now();
    int ok = 0;
    for (int i = 0; i < count; ++i) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        ::inet_pton(AF_INET, ip, &sa.sin_addr);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0) ++ok;
        ::close(fd); // our close -> full handshake + teardown exercised
    }
    auto t1 = Clock::now();
    double s = std::chrono::duration<double>(t1 - t0).count();
    std::printf("conn setup (%s:%u): %d/%d connections in %.3fs = %.0f conn/s\n",
                ip, port, ok, count, s, ok / s);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 3 && std::strcmp(argv[1], "server") == 0)
        return run_server(static_cast<std::uint16_t>(std::atoi(argv[2])));

    if (argc < 4) {
        std::fprintf(stderr,
            "usage:\n"
            "  %s server <port>\n"
            "  %s <ip> <port> latency    [count=2000] [size=64]\n"
            "  %s <ip> <port> throughput [bytes=10000000]\n"
            "  %s <ip> <port> connrate   [count=2000]\n",
            argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }
    const char* ip = argv[1];
    auto port = static_cast<std::uint16_t>(std::atoi(argv[2]));
    std::string mode = argv[3];

    if (mode == "latency")
        return run_latency(ip, port, argc > 4 ? std::atoi(argv[4]) : 2000,
                           argc > 5 ? static_cast<std::size_t>(std::atoi(argv[5])) : 64);
    if (mode == "throughput")
        return run_throughput(ip, port,
                              argc > 4 ? static_cast<std::size_t>(std::atoll(argv[4])) : 10'000'000);
    if (mode == "connrate")
        return run_connrate(ip, port, argc > 4 ? std::atoi(argv[4]) : 2000);

    std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
    return 2;
}
