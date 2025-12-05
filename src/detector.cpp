#include "detector.hpp"

#include <array>
#include <memory>

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

class SshBannerDetector : public ProtocolDetector {
public:
    std::string name() const override { return "ssh-banner"; }

    bool match(const DetectionContext& ctx) const override {
        static constexpr std::string_view kPrefix = "SSH-";
        return ctx.data.size() >= kPrefix.size() &&
               ctx.data.compare(0, kPrefix.size(), kPrefix) == 0;
    }
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
        case DetectorKind::Always:
        default:
            return std::make_shared<AlwaysDetector>();
    }
}

} // namespace port_sharer
