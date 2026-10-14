#include "app/http_server.hpp"

#include <gtest/gtest.h>

using namespace app;

TEST(Http, ParsesRequestLine) {
    auto r = parse_request("GET /hello HTTP/1.1\r\nHost: x\r\n\r\n");
    ASSERT_TRUE(r.complete);
    EXPECT_EQ(r.method, "GET");
    EXPECT_EQ(r.path, "/hello");
    EXPECT_EQ(r.version, "HTTP/1.1");
    EXPECT_TRUE(r.keep_alive);           // HTTP/1.1 default
    EXPECT_EQ(r.header_len, std::string("GET /hello HTTP/1.1\r\nHost: x\r\n\r\n").size());
}

TEST(Http, IncompleteUntilBlankLine) {
    EXPECT_FALSE(parse_request("GET / HTTP/1.1\r\nHost: x\r\n").complete);
    EXPECT_TRUE(parse_request("GET / HTTP/1.1\r\n\r\n").complete);
}

TEST(Http, ConnectionHeaderOverridesDefault) {
    EXPECT_FALSE(parse_request("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").keep_alive);
    EXPECT_TRUE(parse_request("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").keep_alive);
    EXPECT_FALSE(parse_request("GET / HTTP/1.0\r\n\r\n").keep_alive); // 1.0 default close
}

TEST(Http, RootServesHtmlWithCorrectContentLength) {
    auto r = parse_request("GET / HTTP/1.1\r\n\r\n");
    std::string resp = build_response(r);
    EXPECT_NE(resp.find("HTTP/1.1 200 OK\r\n"), std::string::npos);
    EXPECT_NE(resp.find("Content-Type: text/html"), std::string::npos);

    // Content-Length must equal the actual body length (the classic HTTP bug).
    auto hdr_end = resp.find("\r\n\r\n");
    ASSERT_NE(hdr_end, std::string::npos);
    std::string body = resp.substr(hdr_end + 4);
    auto cl = resp.find("Content-Length: ");
    ASSERT_NE(cl, std::string::npos);
    std::size_t declared = std::stoul(resp.substr(cl + 16));
    EXPECT_EQ(declared, body.size());
}

TEST(Http, UnknownPathIs404) {
    auto resp = build_response(parse_request("GET /nope HTTP/1.1\r\n\r\n"));
    EXPECT_NE(resp.find("HTTP/1.1 404 Not Found"), std::string::npos);
}

TEST(Http, NonGetIs405) {
    auto resp = build_response(parse_request("DELETE / HTTP/1.1\r\n\r\n"));
    EXPECT_NE(resp.find("HTTP/1.1 405"), std::string::npos);
}

TEST(Http, HeadHasHeadersButNoBody) {
    auto r = parse_request("HEAD / HTTP/1.1\r\n\r\n");
    auto resp = build_response(r);
    auto hdr_end = resp.find("\r\n\r\n");
    ASSERT_NE(hdr_end, std::string::npos);
    EXPECT_EQ(resp.substr(hdr_end + 4), "");            // no body
    EXPECT_NE(resp.find("Content-Length: "), std::string::npos); // but length present
}
