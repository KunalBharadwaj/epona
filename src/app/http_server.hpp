#pragma once
//
// A small HTTP/1.1 server running over the user-space TCP stack. Point curl or
// a browser at http://10.0.0.2:8080/ and the page is served by this stack, from
// the Ethernet frame up.
//
// The HTTP parsing and response building are pure functions (unit-tested with
// no sockets); the HttpServer class wires them to TCP with per-connection
// request buffering and HTTP/1.1 keep-alive.
//
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "tcp/tcp.hpp"

namespace app {

struct HttpRequest {
    bool             complete   = false; // did we see the full header block?
    std::string      method;
    std::string      path;
    std::string      version;
    bool             keep_alive = true;  // HTTP/1.1 default
    std::size_t      header_len = 0;     // bytes up to and including CRLFCRLF
};

// Parse the request line + headers out of `buf`. Returns complete=false if the
// terminating CRLFCRLF hasn't arrived yet (caller should wait for more data).
inline HttpRequest parse_request(std::string_view buf) {
    HttpRequest req;
    auto end = buf.find("\r\n\r\n");
    if (end == std::string_view::npos) return req; // incomplete
    req.complete   = true;
    req.header_len = end + 4;

    std::string_view head = buf.substr(0, end);

    // Request line: METHOD SP PATH SP VERSION
    auto line_end = head.find("\r\n");
    std::string_view line = head.substr(0, line_end == std::string_view::npos ? head.size() : line_end);
    auto sp1 = line.find(' ');
    auto sp2 = (sp1 == std::string_view::npos) ? std::string_view::npos : line.find(' ', sp1 + 1);
    if (sp1 != std::string_view::npos) {
        req.method = std::string(line.substr(0, sp1));
        if (sp2 != std::string_view::npos) {
            req.path    = std::string(line.substr(sp1 + 1, sp2 - sp1 - 1));
            req.version = std::string(line.substr(sp2 + 1));
        } else {
            req.path = std::string(line.substr(sp1 + 1));
        }
    }

    // Keep-alive: HTTP/1.1 defaults open; HTTP/1.0 defaults closed; an explicit
    // Connection header wins. (Case-insensitive scan.)
    req.keep_alive = (req.version == "HTTP/1.1");
    std::string lower;
    lower.reserve(head.size());
    for (char c : head) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (auto p = lower.find("connection:"); p != std::string::npos) {
        auto val = lower.find_first_not_of(' ', p + 11);
        if (val != std::string::npos) {
            if (lower.compare(val, 5, "close") == 0)      req.keep_alive = false;
            else if (lower.compare(val, 10, "keep-alive") == 0) req.keep_alive = true;
        }
    }
    return req;
}

// Build a full HTTP response (status line + headers + body) for `req`.
inline std::string build_response(const HttpRequest& req) {
    std::string status, body, content_type = "text/html; charset=utf-8";

    const bool head_only = (req.method == "HEAD");
    if (req.method != "GET" && req.method != "HEAD") {
        status = "405 Method Not Allowed";
        body   = "<h1>405 Method Not Allowed</h1>";
    } else if (req.path == "/") {
        status = "200 OK";
        body =
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>user-space TCP/IP stack</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;"
            "line-height:1.6;color:#222}code{background:#f2f2f2;padding:.1em .3em;border-radius:3px}"
            "</style></head><body>"
            "<h1>Hello from a user-space TCP/IP stack</h1>"
            "<p>This page was served by hand-written C++20 that implements "
            "Ethernet, ARP, IPv4, ICMP, UDP and TCP over a TAP device. "
            "The Linux kernel moved raw frames; everything above that is my code.</p>"
            "<p>Try <code>GET /hello</code> for a plain-text response.</p>"
            "</body></html>";
    } else if (req.path == "/hello") {
        status       = "200 OK";
        content_type = "text/plain; charset=utf-8";
        body         = "hello from a user-space TCP stack\n";
    } else {
        status = "404 Not Found";
        body   = "<h1>404 Not Found</h1>";
    }

    std::string resp;
    resp += "HTTP/1.1 " + status + "\r\n";
    resp += "Server: tcpstack/0.1\r\n";
    resp += "Content-Type: " + content_type + "\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += std::string("Connection: ") + (req.keep_alive ? "keep-alive" : "close") + "\r\n";
    resp += "\r\n";
    if (!head_only) resp += body; // HEAD: headers only, but correct Content-Length
    return resp;
}

class HttpServer {
public:
    HttpServer(tcp::Tcp& tcp, std::uint16_t port) : port_(port) {
        tcp.listen(port_, [this](tcp::TcpConnection& c) {
            ++connections_;
            auto buf = std::make_shared<std::string>();
            c.on_data = [this, buf](tcp::TcpConnection& conn,
                                    std::span<const std::byte> data) {
                buf->append(reinterpret_cast<const char*>(data.data()), data.size());
                // Handle as many complete requests as are buffered (pipelining).
                for (;;) {
                    HttpRequest req = parse_request(*buf);
                    if (!req.complete) break;
                    std::string resp = build_response(req);
                    auto rbytes = std::as_bytes(std::span<const char>(resp.data(), resp.size()));
                    conn.send(rbytes);
                    ++requests_;
                    buf->erase(0, req.header_len);
                    if (!req.keep_alive) { conn.close(); break; }
                }
            };
            // When the client closes its side (e.g. curl exits a keep-alive
            // connection), close ours too, otherwise we'd leak the TCB in
            // CLOSE-WAIT forever.
            c.on_close = [](tcp::TcpConnection& conn) { conn.close(); };
        });
    }

    std::uint16_t port()        const noexcept { return port_; }
    std::uint64_t connections() const noexcept { return connections_; }
    std::uint64_t requests()    const noexcept { return requests_; }

private:
    std::uint16_t port_;
    std::uint64_t connections_ = 0;
    std::uint64_t requests_    = 0;
};

} // namespace app
