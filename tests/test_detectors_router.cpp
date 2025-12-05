#include "detector.hpp"
#include "router.hpp"
#include "test_common.hpp"

using namespace port_sharer;

int main() {
    auto test_detectors = [] {
        DetectionContext ctx_http{std::string_view("GET /index HTTP/1.1\r\n"), {}, {}};
        DetectionContext ctx_tls{std::string_view("\x16\x03\x01", 3), {}, {}};
        DetectionContext ctx_ssh{std::string_view("SSH-2.0-OpenSSH"), {}, {}};
        DetectionContext ctx_prefix{std::string_view("HELLO THERE"), {}, {}};
        DetectionContext ctx_ssh_user{std::string_view("SSH-2.0-OpenSSH\r\nUSER admin\r\n"), {}, {}};

        RouteRule http_rule{"http", DetectorKind::Http, {}, {}, Backend{"a", 1, false}, {}};
        RouteRule tls_rule{"tls", DetectorKind::TlsClientHello, {}, {}, Backend{"b", 2, false}, {}};
        RouteRule prefix_rule{"pref", DetectorKind::Prefix, "HELLO", {}, Backend{"c", 3, false}, {}};
        RouteRule ssh_user_rule{"ssh-user", DetectorKind::SshUsername, {}, {}, Backend{"d", 4, false}, {}};
        ssh_user_rule.ssh_usernames = {"admin"};

        EXPECT_TRUE(make_detector(http_rule)->match(ctx_http));
        EXPECT_FALSE(make_detector(http_rule)->match(ctx_tls));
        EXPECT_TRUE(make_detector(tls_rule)->match(ctx_tls));
        EXPECT_TRUE(make_detector(RouteRule{"mix", DetectorKind::HttpOrTls, {}, {}, {}, {}})->match(ctx_http));
        EXPECT_TRUE(make_detector(RouteRule{"ssh", DetectorKind::SshBanner, {}, {}, {}, {}})->match(ctx_ssh));
        EXPECT_FALSE(make_detector(prefix_rule)->match(ctx_http));
        EXPECT_TRUE(make_detector(prefix_rule)->match(ctx_prefix));
        EXPECT_TRUE(make_detector(ssh_user_rule)->match(ctx_ssh_user));
        ssh_user_rule.ssh_usernames = {"root"};
        EXPECT_FALSE(make_detector(ssh_user_rule)->match(ctx_ssh_user));
    };

    auto test_router = [] {
        DetectionContext ctx_http{std::string_view("GET /index HTTP/1.1\r\n"), {}, {}};
        DetectionContext ctx_tls{std::string_view("\x16\x03\x01", 3), {}, {}};

        RouteRule http_rule{"http", DetectorKind::Http, {}, {}, Backend{"a", 1, false}, {}};
        RouteRule tls_rule{"tls", DetectorKind::TlsClientHello, {}, {}, Backend{"b", 2, false}, {}};
        Router router({http_rule, tls_rule}, Backend{"fallback", 99, false});
        auto dec1 = router.select(ctx_http);
        EXPECT_EQ(dec1.backend->host, "a");
        auto dec2 = router.select(ctx_tls);
        EXPECT_EQ(dec2.backend->host, "b");
        auto dec3 = router.select(DetectionContext{std::string_view("UNKNOWN"), {}, {}});
        EXPECT_EQ(dec3.backend->host, "fallback");
    };

    return run_tests({
        {"detectors", test_detectors},
        {"router", test_router},
    });
}
