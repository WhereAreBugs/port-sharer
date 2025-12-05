#include "kernel_bypass.hpp"

#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>

#ifdef __linux__
#include <linux/bpf.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <optional>

#ifndef BPF_MOV64_REG
#define BPF_MOV64_REG(DST, SRC) BPF_ALU64_REG(BPF_MOV, DST, SRC)
#endif
#ifndef BPF_MOV64_IMM
#define BPF_MOV64_IMM(DST, IMM) BPF_ALU64_IMM(BPF_MOV, DST, IMM)
#endif
#ifndef BPF_ALU64_IMM
#define BPF_ALU64_IMM(OP, DST, IMM) \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K, .dst_reg = (DST), .src_reg = 0, .off = 0, .imm = (IMM)})
#endif
#ifndef BPF_STX_MEM
#define BPF_STX_MEM(SIZE, DST, SRC, OFF) \
    ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = (DST), .src_reg = (SRC), .off = (OFF), .imm = 0})
#endif
#ifndef BPF_LD_MAP_FD
#define BPF_LD_MAP_FD(DST, MAP) \
    ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = (DST), .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = (MAP)})
#endif
#ifndef BPF_JMP_IMM
#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
    ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K, .dst_reg = (DST), .src_reg = 0, .off = (OFF), .imm = (IMM)})
#endif
#ifndef BPF_EXIT_INSN
#define BPF_EXIT_INSN() ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0})
#endif
#ifndef BPF_EMIT_CALL
#define BPF_EMIT_CALL(FUNC) \
    ((struct bpf_insn){.code = BPF_JMP | BPF_CALL, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = (FUNC)})
#endif
#ifndef BPF_F_INGRESS
#define BPF_F_INGRESS (1U << 4)
#endif
#ifndef SK_PASS
#define SK_PASS 1
#endif

namespace port_sharer {

namespace {

constexpr int kMaxSockmapEntries = 4096;
constexpr std::size_t kBpfLogSize = 8192;

inline long bpf_syscall(enum bpf_cmd cmd, union bpf_attr* attr) {
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

struct BpfContext {
    int sock_map_fd = -1;
    int peer_map_fd = -1;
    int prog_fd = -1;
    std::atomic<bool> attached{false};
    bool ready = false;

    ~BpfContext() {
        if (prog_fd >= 0) close(prog_fd);
        if (sock_map_fd >= 0) close(sock_map_fd);
        if (peer_map_fd >= 0) close(peer_map_fd);
    }
};

BpfContext& context() {
    static BpfContext ctx;
    return ctx;
}

bool create_maps() {
    auto& ctx = context();
    union bpf_attr attr{};
    attr.map_type = BPF_MAP_TYPE_SOCKHASH;
    attr.key_size = sizeof(std::uint64_t);
    attr.value_size = sizeof(int);
    attr.max_entries = kMaxSockmapEntries;
    attr.map_flags = 0;
    ctx.sock_map_fd = static_cast<int>(bpf_syscall(BPF_MAP_CREATE, &attr));
    if (ctx.sock_map_fd < 0) {
        std::cerr << "[bpf] failed to create sockhash map: " << strerror(errno) << "\n";
        return false;
    }

    attr = {};
    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.key_size = sizeof(std::uint64_t);
    attr.value_size = sizeof(std::uint64_t);
    attr.max_entries = kMaxSockmapEntries;
    attr.map_flags = BPF_F_NO_PREALLOC;
    ctx.peer_map_fd = static_cast<int>(bpf_syscall(BPF_MAP_CREATE, &attr));
    if (ctx.peer_map_fd < 0) {
        std::cerr << "[bpf] failed to create peer map: " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

bool load_program() {
    auto& ctx = context();

    // Program: lookup peer cookie in peer_map, redirect to sock_map.
    // r0 holds return of helper (SK_PASS on success) or SK_PASS when no peer found.
    std::array<struct bpf_insn, 16> prog = {
        // 0: r6 = r1 (save ctx)
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        // 1: r0 = bpf_get_socket_cookie(ctx)
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
        BPF_EMIT_CALL(BPF_FUNC_get_socket_cookie),
        // 3: *(u64 *)(fp-8) = r0
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
        // 4: r1 = &peer_map
        BPF_LD_MAP_FD(BPF_REG_1, ctx.peer_map_fd),
        // 6: r2 = fp-8
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
        // 8: r0 = map_lookup_elem(peer_map, &cookie)
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
        // 9: if r0 == 0 goto 14
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 5),
        // 10: r2 = r0 (peer cookie ptr)
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),
        // 11: r1 = &sock_map
        BPF_LD_MAP_FD(BPF_REG_1, ctx.sock_map_fd),
        // 13: r3 = BPF_F_INGRESS
        BPF_MOV64_IMM(BPF_REG_3, BPF_F_INGRESS),
        // 14: call bpf_msg_redirect_hash
        BPF_EMIT_CALL(BPF_FUNC_msg_redirect_hash),
        // 15: exit (return helper result)
        BPF_EXIT_INSN(),
        // 16: r0 = SK_PASS
        BPF_MOV64_IMM(BPF_REG_0, SK_PASS),
        // 17: exit
        BPF_EXIT_INSN()
    };

    union bpf_attr attr{};
    attr.prog_type = BPF_PROG_TYPE_SK_MSG;
    attr.insns = reinterpret_cast<__u64>(prog.data());
    attr.insn_cnt = prog.size();
    attr.license = reinterpret_cast<__u64>("GPL");
    attr.log_buf = reinterpret_cast<__u64>(new char[kBpfLogSize]);
    attr.log_size = kBpfLogSize;
    attr.log_level = 1;

    ctx.prog_fd = static_cast<int>(bpf_syscall(BPF_PROG_LOAD, &attr));
    if (ctx.prog_fd < 0) {
        std::cerr << "[bpf] program load failed: " << strerror(errno) << "\n";
        if (attr.log_buf) {
            std::cerr << "[bpf] verifier log: " << reinterpret_cast<char*>(attr.log_buf) << "\n";
        }
        delete[] reinterpret_cast<char*>(attr.log_buf);
        return false;
    }
    delete[] reinterpret_cast<char*>(attr.log_buf);
    return true;
}

bool attach_program() {
    auto& ctx = context();
    if (ctx.attached.load(std::memory_order_acquire)) return true;
    union bpf_attr attr{};
    attr.target_fd = ctx.sock_map_fd;
    attr.attach_bpf_fd = ctx.prog_fd;
    attr.attach_type = BPF_SK_MSG_VERDICT;
    if (bpf_syscall(BPF_PROG_ATTACH, &attr) < 0) {
        std::cerr << "[bpf] program attach failed: " << strerror(errno) << "\n";
        return false;
    }
    ctx.attached.store(true, std::memory_order_release);
    return true;
}

bool ensure_ready() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, []() {
        if (!create_maps()) return;
        if (!load_program()) return;
        if (!attach_program()) return;
        context().ready = true;
    });
    return ok = context().ready;
}

std::optional<std::uint64_t> get_cookie(int fd) {
    std::uint64_t cookie = 0;
    socklen_t len = sizeof(cookie);
    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &len) != 0) {
        return std::nullopt;
    }
    return cookie;
}

bool update_map(int map_fd, const void* key, const void* value, std::uint64_t flags = BPF_ANY) {
    union bpf_attr attr{};
    attr.map_fd = map_fd;
    attr.key = reinterpret_cast<__u64>(key);
    attr.value = reinterpret_cast<__u64>(value);
    attr.flags = flags;
    return bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr) == 0;
}

void delete_map_entry(int map_fd, const void* key) {
    if (map_fd < 0) return;
    union bpf_attr attr{};
    attr.map_fd = map_fd;
    attr.key = reinterpret_cast<__u64>(key);
    bpf_syscall(BPF_MAP_DELETE_ELEM, &attr);
}

} // namespace

KernelBypassResult KernelBypass::attempt_dnat(boost::asio::ip::tcp::socket& client_socket,
                                              boost::asio::ip::tcp::socket& backend_socket,
                                              const Backend& backend,
                                              const std::string& session_label) {
    KernelBypassResult res;
    (void)backend;
    if (!ensure_ready()) {
        return res;
    }

    auto client_cookie = get_cookie(client_socket.native_handle());
    auto backend_cookie = get_cookie(backend_socket.native_handle());
    if (!client_cookie || !backend_cookie) {
        std::cerr << "[bpf] SO_COOKIE unavailable, skip kernel bypass for " << session_label << "\n";
        return res;
    }

    int sock_map = context().sock_map_fd;
    int peer_map = context().peer_map_fd;

    const int client_fd = client_socket.native_handle();
    const int backend_fd = backend_socket.native_handle();

    if (!update_map(sock_map, &client_cookie.value(), &client_fd)) {
        std::cerr << "[bpf] failed to add client socket to sockmap: " << strerror(errno) << "\n";
        return res;
    }
    if (!update_map(sock_map, &backend_cookie.value(), &backend_fd)) {
        std::cerr << "[bpf] failed to add backend socket to sockmap: " << strerror(errno) << "\n";
        delete_map_entry(sock_map, &client_cookie.value());
        return res;
    }
    if (!update_map(peer_map, &client_cookie.value(), &backend_cookie.value()) ||
        !update_map(peer_map, &backend_cookie.value(), &client_cookie.value())) {
        std::cerr << "[bpf] failed to program peer map\n";
        delete_map_entry(sock_map, &client_cookie.value());
        delete_map_entry(sock_map, &backend_cookie.value());
        return res;
    }

    res.engaged = true;
    res.client_cookie = client_cookie.value();
    res.backend_cookie = backend_cookie.value();

    std::cout << "[bpf] kernel sockmap redirect enabled for " << session_label << "\n";
    return res;
}

void KernelBypass::teardown(std::uint64_t client_cookie, std::uint64_t backend_cookie) {
    if (!context().ready) return;
    delete_map_entry(context().peer_map_fd, &client_cookie);
    delete_map_entry(context().peer_map_fd, &backend_cookie);
    delete_map_entry(context().sock_map_fd, &client_cookie);
    delete_map_entry(context().sock_map_fd, &backend_cookie);
}

} // namespace port_sharer

#else

namespace port_sharer {

KernelBypassResult KernelBypass::attempt_dnat(boost::asio::ip::tcp::socket&,
                                              boost::asio::ip::tcp::socket&,
                                              const Backend&,
                                              const std::string&) {
    return {};
}

void KernelBypass::teardown(std::uint64_t, std::uint64_t) {}

} // namespace port_sharer

#endif
