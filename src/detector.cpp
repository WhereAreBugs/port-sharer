#include "detector.hpp"

#include <array>
#include <memory>
#include <string>
#include <vector>

namespace port_sharer {

namespace {

class HttpDetector : public ProtocolDetector {
public:
    std::string name() const override { return "http"; }

    bool match(const DetectionContext& ctx) const override {
        static const std::array<std::string_view, 9> methods = {
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
            "OPTIONS ", "CONNECT ", "TRACE ", "PATCH "
        };
        for (const auto& m : methods) {
            if (ctx.data.size() >= m.size() && ctx.data.compare(0, m.size(), m) == 0) {
                return true;
            }
        }
        return false;
    }
};

class TlsClientHelloDetector : public ProtocolDetector {
public:
    std::string name() const override { return "tls-client-hello"; }

    bool match(const DetectionContext& ctx) const override {
        // TLS record: type(1) version_major(1) version_minor(1) ...
        return ctx.data.size() >= 3 &&
               static_cast<unsigned char>(ctx.data[0]) == 0x16 &&
               static_cast<unsigned char>(ctx.data[1]) == 0x03;
    }
};

class HttpOrTlsDetector : public ProtocolDetector {
public:
    std::string name() const override { return "http-or-tls"; }

    bool match(const DetectionContext& ctx) const override {
        return http_.match(ctx) || tls_.match(ctx);
    }

private:
    HttpDetector http_;
    TlsClientHelloDetector tls_;
};

class PrefixDetector : public ProtocolDetector {
public:
    explicit PrefixDetector(std::string prefix) : prefix_(std::move(prefix)) {}

    std::string name() const override { return "prefix"; }

    bool match(const DetectionContext& ctx) const override {
        if (prefix_.empty()) return false;
        return ctx.data.size() >= prefix_.size() &&
               ctx.data.compare(0, prefix_.size(), prefix_) == 0;
    }

private:
    std::string prefix_;
};

std::string extract_ssh_username(const std::string_view& data) {
    static const std::array<std::string_view, 2> markers = {"USER ", "user "};
    for (const auto& marker : markers) {
        auto pos = data.find(marker);
        if (pos == std::string_view::npos) continue;
        auto start = pos + marker.size();
        while (start < data.size() && (data[start] == ' ' || data[start] == '\t')) ++start;
        auto end = start;
        while (end < data.size()) {
            char c = data[end];
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == '\0') break;
            ++end;
        }
        if (end > start) {
            return std::string(data.substr(start, end - start));
        }
    }
    return {};
}

class SshBannerDetector : public ProtocolDetector {
public:
    std::string name() const override { return "ssh-banner"; }

    bool match(const DetectionContext& ctx) const override {
        static constexpr std::string_view kPrefix = "SSH-";
        return ctx.data.size() >= kPrefix.size() &&
               ctx.data.compare(0, kPrefix.size(), kPrefix) == 0;
    }
};

class SshUsernameDetector : public ProtocolDetector {
public:
    explicit SshUsernameDetector(std::vector<std::string> users)
        : usernames_(std::move(users)) {}

    std::string name() const override { return "ssh-username"; }

    bool match(const DetectionContext& ctx) const override {
        if (usernames_.empty()) return false;
        auto user = extract_ssh_username(ctx.data);
        if (user.empty()) return false;
        for (const auto& u : usernames_) {
            if (u == user) return true;
        }
        return false;
    }

private:
    std::vector<std::string> usernames_;
};

class AlwaysDetector : public ProtocolDetector {
public:
    std::string name() const override { return "always"; }
    bool match(const DetectionContext&) const override { return true; }
};

} // namespace

std::shared_ptr<ProtocolDetector> make_detector(const RouteRule& rule) {
    switch (rule.detector) {
        case DetectorKind::Http:
            return std::make_shared<HttpDetector>();
        case DetectorKind::TlsClientHello:
            return std::make_shared<TlsClientHelloDetector>();
        case DetectorKind::HttpOrTls:
            return std::make_shared<HttpOrTlsDetector>();
        case DetectorKind::Prefix:
            return std::make_shared<PrefixDetector>(rule.prefix);
        case DetectorKind::SshBanner:
            return std::make_shared<SshBannerDetector>();
        case DetectorKind::SshUsername:
            return std::make_shared<SshUsernameDetector>(rule.ssh_usernames);
        case DetectorKind::Always:
        default:
            return std::make_shared<AlwaysDetector>();
    }
}

} // namespace port_sharer
