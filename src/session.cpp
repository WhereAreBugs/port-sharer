#include "session.hpp"

#include "detector.hpp"
#include "proxy_protocol.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detail/socket_option.hpp>

#include <array>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <poll.h>
#include <sstream>
#include <thread>
#include <unistd.h>

#ifdef __linux__
#include <fcntl.h>
#endif

#if defined(PORT_SHARER_HAS_IO_URING)
#include <liburing.h>
#endif

namespace port_sharer {

namespace {

using boost::asio::ip::tcp;

bool is_http_request(const std::string_view& data) {
    static const std::array<std::string_view, 9> methods = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
        "OPTIONS ", "CONNECT ", "TRACE ", "PATCH "
    };
    for (const auto& m : methods) {
        if (data.size() >= m.size() && data.compare(0, m.size(), m) == 0) {
            return true;
        }
    }
    return false;
}

std::string build_forward_headers(const HttpForward& cfg,
                                  const boost::asio::ip::tcp::endpoint& remote,
                                  const boost::asio::ip::tcp::endpoint& local) {
    if (!cfg.enable) return {};
    std::ostringstream oss;
    const auto remote_ip = remote.address().to_string();
    const auto local_port = local.port();
    if (cfg.add_x_real_ip) {
        oss << "X-Real-IP: " << remote_ip << "\r\n";
    }
    if (cfg.add_x_forwarded_for) {
        oss << "X-Forwarded-For: " << remote_ip << "\r\n";
    }
    if (cfg.add_x_forwarded_proto) {
        oss << "X-Forwarded-Proto: http\r\n";
    }
    if (cfg.add_x_forwarded_port) {
        oss << "X-Forwarded-Port: " << local_port << "\r\n";
    }
    if (cfg.add_forwarded) {
        oss << "Forwarded: for=\"" << remote_ip << "\";proto=http\r\n";
    }
    for (const auto& kv : cfg.extra_headers) {
        if (!kv.name.empty()) {
            oss << kv.name << ": " << kv.value << "\r\n";
        }
    }
    return oss.str();
}

struct ReusePort : public boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> {
    using boolean::boolean;
};

void enable_reuse(tcp::socket& sock) {
    boost::system::error_code ec;
    sock.set_option(tcp::socket::reuse_address(true), ec);
#ifdef SO_REUSEPORT
    sock.set_option(ReusePort(true), ec);
#endif
}

} // namespace

Session::Session(boost::asio::ip::tcp::socket client_socket,
                 std::shared_ptr<Router> router,
                 std::size_t peek_size,
                 MetricsPtr metrics,
                 bool prefer_zero_copy,
                 bool prefer_kernel_dnat)
    : router_(std::move(router)),
      strand_(std::make_shared<Strand>(client_socket.get_executor())),
      client_socket_(std::move(client_socket)),
      backend_socket_(client_socket_.get_executor()),
      peek_size_(peek_size),
      metrics_(std::move(metrics)),
      prefer_zero_copy_(prefer_zero_copy),
      prefer_kernel_dnat_(prefer_kernel_dnat) {
    boost::system::error_code ec;
    local_endpoint_ = client_socket_.local_endpoint(ec);
    if (ec) {
        local_endpoint_ = boost::asio::ip::tcp::endpoint();
    }
    auto remote = client_socket_.remote_endpoint(ec);
    if (!ec) {
        remote_label_ = remote.address().to_string() + ":" + std::to_string(remote.port());
    }

    if (metrics_) {
        metrics_->total_connections.fetch_add(1, std::memory_order_relaxed);
        metrics_->active_sessions.fetch_add(1, std::memory_order_relaxed);
    }
}

void Session::start() {
    do_peek();
}

void Session::do_peek() {
    peek_buffer_.assign(peek_size_, 0);
    client_socket_.async_read_some(
        boost::asio::buffer(peek_buffer_),
        boost::asio::bind_executor(*strand_, [self = shared_from_this()](auto ec, auto len) {
            self->on_peek(ec, len);
        }));
}

void Session::on_peek(const boost::system::error_code& ec, std::size_t length) {
    if (ec) {
        if (ec != boost::asio::error::eof) {
            std::cerr << "[session] Peek error from " << remote_label_ << ": " << ec.message() << "\n";
        }
        close_sockets(ec);
        return;
    }
    peek_length_ = length;

    DetectionContext ctx{
        std::string_view(peek_buffer_.data(), peek_length_),
        client_socket_.remote_endpoint(),
        local_endpoint_
    };
    auto decision = router_->select(ctx);
    selected_backend_ = *decision.backend;
    if (decision.rule) {
        selected_rule_ = *decision.rule;
    }
    is_http_traffic_ = is_http_request(ctx.data);

    std::cout << "[session] New connection " << remote_label_
              << " -> " << selected_backend_.host << ":" << selected_backend_.port;
    if (!selected_rule_.name.empty()) {
        std::cout << " via rule " << selected_rule_.name;
    }
    if (selected_backend_.proxy_protocol) {
        std::cout << " (proxy-protocol)";
    }
    std::cout << "\n";

    resolve_and_connect(selected_backend_);
}

void Session::resolve_and_connect(const Backend& backend) {
    auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(*strand_);
    resolver->async_resolve(
        backend.host,
        std::to_string(backend.port),
        boost::asio::bind_executor(*strand_,
            [self = shared_from_this(), resolver, backend](auto ec, auto endpoints) {
                self->on_resolve(ec, endpoints, backend);
            }));
}

void Session::on_resolve(const boost::system::error_code& ec,
                         const boost::asio::ip::tcp::resolver::results_type& endpoints,
                         Backend backend) {
    if (ec) {
        std::cerr << "[session] Resolve error for " << backend.host << ":" << backend.port
                  << " - " << ec.message() << "\n";
        close_sockets(ec);
        return;
    }

    auto it = endpoints.begin();
    if (it == endpoints.end()) {
        std::cerr << "[session] Resolve returned no endpoints for " << backend.host << ":" << backend.port << "\n";
        close_sockets(boost::asio::error::host_not_found);
        return;
    }

    boost::system::error_code open_ec;
    if (backend_socket_.is_open()) backend_socket_.close(open_ec);
    backend_socket_.open(it->endpoint().protocol(), open_ec);
    if (open_ec) {
        std::cerr << "[session] Open error to backend: " << open_ec.message() << "\n";
        close_sockets(open_ec);
        return;
    }
    enable_reuse(backend_socket_);

    boost::asio::async_connect(
        backend_socket_,
        endpoints,
        boost::asio::bind_executor(*strand_,
            [self = shared_from_this()](auto connect_ec, auto) {
                self->on_connect(connect_ec);
            }));
}

void Session::on_connect(const boost::system::error_code& ec) {
    if (ec) {
        std::cerr << "[session] Connect error to backend: " << ec.message() << "\n";
        close_sockets(ec);
        return;
    }

    std::vector<boost::asio::const_buffer> buffers;
    if (selected_backend_.proxy_protocol) {
        proxy_header_ = build_proxy_protocol_v2(client_socket_.remote_endpoint(), local_endpoint_);
        buffers.push_back(boost::asio::buffer(proxy_header_));
    }

    if (is_http_traffic_ && selected_rule_.http_forward.enable) {
        const auto header_text = build_forward_headers(selected_rule_.http_forward,
                                                       client_socket_.remote_endpoint(),
                                                       local_endpoint_);
        if (!header_text.empty()) {
            const std::string_view peek_view(peek_buffer_.data(), peek_length_);
            const std::string delimiter = "\r\n\r\n";
            auto pos = peek_view.find(delimiter);
            if (pos != std::string::npos) {
                std::string mutated;
                mutated.reserve(peek_view.size() + header_text.size());
                mutated.append(peek_view.substr(0, pos + 2)); // include first CRLF
                mutated.append(header_text);
                mutated.append(peek_view.substr(pos + 2)); // keep rest
                peek_buffer_.assign(mutated.begin(), mutated.end());
                peek_length_ = peek_buffer_.size();
            }
        }
    }
    buffers.push_back(boost::asio::buffer(peek_buffer_.data(), peek_length_));

    boost::asio::async_write(
        backend_socket_,
        buffers,
        boost::asio::bind_executor(*strand_, [self = shared_from_this()](auto write_ec, auto) {
            if (write_ec) {
                std::cerr << "[session] Initial write failed: " << write_ec.message() << "\n";
                self->close_sockets(write_ec);
                return;
            }
            if (self->metrics_) {
                self->metrics_->bytes_upstream.fetch_add(self->peek_length_, std::memory_order_relaxed);
            }
            if (self->prefer_kernel_dnat_ && self->is_local_backend(self->selected_backend_)) {
                auto res = self->kernel_bypass_.attempt_dnat(self->client_socket_, self->backend_socket_, self->selected_backend_, self->remote_label_);
                if (res.engaged) {
                    self->bypass_cookies_ = std::make_pair(res.client_cookie, res.backend_cookie);
                    self->start_kernel_bypass_watch(res.client_cookie, res.backend_cookie);
                    return;
                }
            }
            if (self->prefer_zero_copy_ && self->is_local_backend(self->selected_backend_) && self->start_zero_copy()) {
                return;
            }
            self->do_read_from_client();
            self->do_read_from_backend();
        }));
}

void Session::do_read_from_client() {
    client_socket_.async_read_some(
        boost::asio::buffer(client_buffer_),
        boost::asio::bind_executor(*strand_, [self = shared_from_this()](auto ec, auto len) {
            if (!ec) {
                self->do_write_to_backend(len);
            } else {
                self->close_sockets(ec);
            }
        }));
}

void Session::do_write_to_backend(std::size_t length) {
    boost::asio::async_write(
        backend_socket_,
        boost::asio::buffer(client_buffer_.data(), length),
        boost::asio::bind_executor(*strand_, [self = shared_from_this(), length](auto ec, auto) {
            if (!ec) {
                self->do_read_from_client();
                if (self->metrics_) {
                    self->metrics_->bytes_upstream.fetch_add(length, std::memory_order_relaxed);
                }
            } else {
                self->close_sockets(ec);
            }
        }));
}

void Session::do_read_from_backend() {
    backend_socket_.async_read_some(
        boost::asio::buffer(backend_buffer_),
        boost::asio::bind_executor(*strand_, [self = shared_from_this()](auto ec, auto len) {
            if (!ec) {
                self->do_write_to_client(len);
            } else {
                self->close_sockets(ec);
            }
        }));
}

void Session::do_write_to_client(std::size_t length) {
    boost::asio::async_write(
        client_socket_,
        boost::asio::buffer(backend_buffer_.data(), length),
        boost::asio::bind_executor(*strand_, [self = shared_from_this(), length](auto ec, auto) {
            if (!ec) {
                self->do_read_from_backend();
                if (self->metrics_) {
                    self->metrics_->bytes_downstream.fetch_add(length, std::memory_order_relaxed);
                }
            } else {
                self->close_sockets(ec);
            }
        }));
}

void Session::close_sockets(const boost::system::error_code& ec) {
    auto self = shared_from_this();
    boost::asio::post(*strand_, [self, ec]() {
        if (self->closed_.exchange(true)) return;
        if (ec && ec != boost::asio::error::eof) {
            std::cerr << "[session] Closing session " << self->remote_label_ << ": " << ec.message() << "\n";
        }

        auto cookies = self->bypass_cookies_;
        self->bypass_cookies_.reset();
        if (cookies) {
            self->kernel_bypass_.teardown(cookies->first, cookies->second);
        }

        boost::system::error_code ignored;
        if (self->client_socket_.is_open()) {
            self->client_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
            self->client_socket_.close(ignored);
        }
        if (self->backend_socket_.is_open()) {
            self->backend_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
            self->backend_socket_.close(ignored);
        }

        if (self->metrics_) {
            self->metrics_->active_sessions.fetch_sub(1, std::memory_order_relaxed);
        }
    });
}

bool Session::is_local_backend(const Backend& backend) const {
    const auto& host = backend.host;
    return host == "127.0.0.1" || host == "::1" || host == "localhost";
}

bool Session::start_zero_copy() {
#ifdef __linux__
#if defined(PORT_SHARER_HAS_IO_URING)
    if (start_zero_copy_io_uring()) {
        return true;
    }
#endif
    if (start_zero_copy_splice()) {
        return true;
    }
    return false;
#elif defined(__APPLE__)
    static std::atomic<bool> warned{false};
    if (!warned.exchange(true)) {
        std::cerr << "[session] zero-copy forwarding is not available on macOS "
                  << "(no splice/io_uring/MSG_ZEROCOPY equivalents); using buffered path\n";
    }
    return false;
#else
    return false;
#endif
}

void Session::start_kernel_bypass_watch(std::uint64_t client_cookie, std::uint64_t backend_cookie) {
#ifdef __linux__
    auto self = shared_from_this();
    std::thread([self, client_cookie, backend_cookie]() {
        struct pollfd fds[2];
        fds[0].fd = self->client_socket_.native_handle();
        fds[0].events = POLLRDHUP | POLLERR | POLLHUP;
        fds[1].fd = self->backend_socket_.native_handle();
        fds[1].events = POLLRDHUP | POLLERR | POLLHUP;
        while (!self->closed_.load()) {
            int rc = ::poll(fds, 2, 500);
            if (rc < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (rc == 0) continue;
            if ((fds[0].revents | fds[1].revents) & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL)) {
                break;
            }
        }
        self->kernel_bypass_.teardown(client_cookie, backend_cookie);
        self->close_sockets(boost::system::error_code{});
    }).detach();
#else
    (void)client_cookie;
    (void)backend_cookie;
#endif
}

bool Session::start_zero_copy_splice() {
#ifdef __linux__
    int cfd = client_socket_.native_handle();
    int bfd = backend_socket_.native_handle();
    if (cfd < 0 || bfd < 0) return false;

    auto pipe_c2b = std::make_shared<std::array<int, 2>>();
    auto pipe_b2c = std::make_shared<std::array<int, 2>>();
    if (pipe2(pipe_c2b->data(), O_NONBLOCK | O_CLOEXEC) != 0) return false;
    if (pipe2(pipe_b2c->data(), O_NONBLOCK | O_CLOEXEC) != 0) {
        close((*pipe_c2b)[0]); close((*pipe_c2b)[1]);
        return false;
    }

    auto self = shared_from_this();
    using boost::asio::awaitable;
    using boost::asio::co_spawn;
    using boost::asio::detached;
    using boost::asio::posix::stream_descriptor;
    using boost::asio::use_awaitable;

    // Duplicate fds so coroutine descriptors can close without touching sockets.
    auto cwait = std::make_shared<stream_descriptor>(client_socket_.get_executor());
    auto bwait = std::make_shared<stream_descriptor>(client_socket_.get_executor());
    auto cdup = ::dup(cfd);
    auto bdup = ::dup(bfd);
    if (cdup < 0 || bdup < 0) {
        if (cdup >= 0) ::close(cdup);
        if (bdup >= 0) ::close(bdup);
        return false;
    }
    cwait->assign(cdup);
    bwait->assign(bdup);

    auto pump = [self](int from_fd, int to_fd,
                       std::shared_ptr<std::array<int, 2>> pipes,
                       std::shared_ptr<stream_descriptor> wait_in,
                       std::shared_ptr<stream_descriptor> wait_out,
                       const char* tag) -> awaitable<void> {
        constexpr std::size_t kChunk = 64 * 1024;
        for (;;) {
            ssize_t n = ::splice(from_fd, nullptr, (*pipes)[1], nullptr, kChunk,
                                 SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);
            if (n == 0) break; // EOF
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN) {
                    co_await wait_in->async_wait(stream_descriptor::wait_read, use_awaitable);
                    if (self->closed_.load()) break;
                    continue;
                }
                std::cerr << "[session] splice read error (" << tag << "): " << strerror(errno) << "\n";
                break;
            }

            std::size_t transferred = 0;
            while (transferred < static_cast<std::size_t>(n)) {
                ssize_t w = ::splice((*pipes)[0], nullptr, to_fd, nullptr,
                                     static_cast<size_t>(n) - transferred,
                                     SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);
                if (w == 0) break;
                if (w < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN) {
                        co_await wait_out->async_wait(stream_descriptor::wait_write, use_awaitable);
                        if (self->closed_.load()) break;
                        continue;
                    }
                    std::cerr << "[session] splice write error (" << tag << "): " << strerror(errno) << "\n";
                    self->close_sockets(boost::system::error_code{});
                    goto done;
                }
                transferred += static_cast<std::size_t>(w);
                if (self->closed_.load()) goto done;
            }
        }
    done:
        close((*pipes)[0]);
        close((*pipes)[1]);
        self->close_sockets(boost::system::error_code{});
        co_return;
    };

    co_spawn(client_socket_.get_executor(),
             pump(cfd, bfd, pipe_c2b, cwait, bwait, "c->b"),
             detached);
    co_spawn(client_socket_.get_executor(),
             pump(bfd, cfd, pipe_b2c, bwait, cwait, "b->c"),
             detached);
    std::cout << "[session] zero-copy splice engaged for " << remote_label_ << "\n";
    return true;
#else
    return false;
#endif
}

#if defined(PORT_SHARER_HAS_IO_URING)
bool Session::start_zero_copy_io_uring() {
#ifdef __linux__
    int cfd = client_socket_.native_handle();
    int bfd = backend_socket_.native_handle();
    if (cfd < 0 || bfd < 0) return false;

    auto ring = std::make_shared<io_uring>();
    if (io_uring_queue_init(64, ring.get(), 0) != 0) {
        return false;
    }
    std::unique_ptr<io_uring_probe, decltype(&io_uring_free_probe)> probe(io_uring_get_probe_ring(ring.get()), &io_uring_free_probe);
    if (!probe || !io_uring_opcode_supported(probe.get(), IORING_OP_SPLICE)) {
        io_uring_queue_exit(ring.get());
        return false;
    }

    auto submit_splice = [&](int fd_in, int fd_out, std::uintptr_t tag) -> bool {
        io_uring_sqe* sqe = io_uring_get_sqe(ring.get());
        if (!sqe) return false;
        io_uring_prep_splice(sqe, fd_in, -1, fd_out, -1, 64 * 1024, SPLICE_F_MOVE | SPLICE_F_MORE);
        io_uring_sqe_set_data64(sqe, tag);
        return io_uring_submit(ring.get()) >= 0;
    };

    if (!submit_splice(cfd, bfd, 1) || !submit_splice(bfd, cfd, 2)) {
        io_uring_queue_exit(ring.get());
        return false;
    }

    auto self = shared_from_this();
    std::thread([self, ring, submit_splice]() mutable {
        int active = 2;
        while (active > 0 && !self->closed_.load()) {
            io_uring_cqe* cqe = nullptr;
            int rc = io_uring_wait_cqe(ring.get(), &cqe);
            if (rc < 0 || !cqe) break;
            int res = cqe->res;
            auto tag = io_uring_cqe_get_data64(cqe);
            io_uring_cqe_seen(ring.get(), cqe);
            if (res == 0) {
                --active;
                continue;
            }
            if (res < 0) {
                if (res == -EAGAIN) {
                    // resubmit the same direction
                } else {
                    std::cerr << "[session] io_uring splice error: " << strerror(-res) << "\n";
                    break;
                }
            }
            // res > 0 or EAGAIN: resubmit splice for this direction
            if (!submit_splice(tag == 1 ? self->client_socket_.native_handle() : self->backend_socket_.native_handle(),
                               tag == 1 ? self->backend_socket_.native_handle() : self->client_socket_.native_handle(),
                               tag)) {
                break;
            }
        }
        io_uring_queue_exit(ring.get());
        self->close_sockets(boost::system::error_code{});
    }).detach();
    std::cout << "[session] io_uring splice engaged for " << remote_label_ << "\n";
    return true;
#else
    return false;
#endif
}
#endif

} // namespace port_sharer
