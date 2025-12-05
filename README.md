### Port Share
#### 这是什么？
一个很早期的项目。原始需求是需要在openwrt中同一个端口同时运行一个http服务和一个其他的二进制协议的服务，且都不允许修改默认端口。<br>
原理很简单，本程序作为反代，根据协议类型提取出http流量，转发到一个反代的端口。否则转发到另一个端口。将服务区分开。适用于极致的端口复用。
> 早期开发阶段，功能还十分简单。后续会添加更多协议的支持。

> 由于功能逐渐增加，现正在计划修改项目名
#### TODO
- [x] 实现基础的反代功能
- [x] 提取http/TLS流量，进行分流
- [x] 反向代理http/https时支持proxy_protocol_v2
- [x] 代码结构优化，增强可复用性
- [ ] 支持TLS SNI提取，根据SNI进一步分流
- [x] 新增自定义协议规则支持，自定义协议头检测（`prefix` 检测器）
- [x] 支持IP黑/白名单，进行强制分流或禁止分流
- [x] 支持按照访问频率(TCP SYN包)对特定IP进行封禁
- [ ] 添加CI/CD自动化构建和发布release
- [x] 新增支持存在多个混合端口，每个端口独立配置（OpenWrt/UCI 多实例）
- [x] 支持ssh用户名分流（目前仅支持SSH Banner检测/分流）
- [ ] 支持更多的协议 (rtsp etc...)
- [x] 支持使用uci配置文件统一配置（`OPENWRT` 构建）
- [x] 开发luci界面，便于配置（`luci/` 已提供基础界面）
- [ ] 开发插件系统，允许自定义协议匹配规则
- [x] Prometheus 指标收集
- [x] HTTP 源 IP 透传头注入
- [x] 零拷贝/内核旁路转发（Linux：splice/io_uring + eBPF sockmap）

#### 编译教程
在你的openwrt仓库根，运行以下代码:
```shell
git clone {本仓库地址} package/httpPortReuse
```
之后在Network -> Routing and Redirection下即可配置加入编译
#### 后记
> 欢迎Pr和Issue。

### 架构与配置
- **核心流程**：`server` 监听混合端口 -> `session` 读取首包 -> `router` 按检测器(`http`/`tls`/`ssh`/`ssh_username`/`prefix`/`always`)选择后端 -> 可选注入 PROXY v2 头/HTTP 真实源 IP 头 -> 雙向透传。
- **实例与配置**：OpenWrt/UCI 下支持多个 instance（每个监听端口独立路由与回退配置）；JSON 配置路径当前为单实例模式。LuCI 界面已包含实例/路由/回退配置页。
- **性能选项现状**：`prefer_zero_copy` 现支持 Linux 的 `splice`/`io_uring` 零拷贝转发（回落到常规路径）；`prefer_kernel_dnat` 会尝试使用 eBPF sockmap 旁路（需内核支持 `SO_COOKIE`/`BPF_PROG_TYPE_SK_MSG`，失败则回退）。
  - macOS 暂无 socket->socket 的零拷贝 API（没有 `splice`/`MSG_ZEROCOPY` 等等），因此会自动回退为常规缓冲转发。
- **默认配置**：
  - 监听 `0.0.0.0:8888`
  - `http_or_tls` -> `127.0.0.1:443`（开启 HTTP 源 IP 头注入）
  - `ssh` -> `127.0.0.1:22`
  - 其他 -> `127.0.0.1:22`
- **访问控制**：通过 `access` 段配置白/黑名单（支持 CIDR），可选按照 TCP SYN 频率封禁 IP。白名单优先，其次黑名单，最后执行频率封禁，所有检查均在 `accept` 阶段完成以减少 IO 开销。
- **自定义配置示例 (`config.json`，同 `example.json`)**：
```json
{
  "listen": { "address": "0.0.0.0", "port": 8888 },
  "peek_size": 512,
  "performance": { "prefer_zero_copy": true, "prefer_kernel_dnat": true },
  "metrics": { "enable": true, "port": 9100 },
  "access": {
    "whitelist": ["0.0.0.0/0"],
    "blacklist": ["203.0.113.1"],
    "syn_limit": { "enable": true, "max_attempts": 120, "interval_ms": 1000, "ban_seconds": 30 }
  },
  "routes": [
    {
      "name": "web",
      "detector": "http_or_tls",
      "http_forward": {
        "enable": true,
        "x_real_ip": true,
        "x_forwarded_for": true,
        "x_forwarded_proto": true,
        "x_forwarded_port": true,
        "forwarded": false,
        "headers": [{ "name": "X-Forwarded-Host", "value": "example.org" }]
      },
      "backend": { "host": "127.0.0.1", "port": 443, "proxy_protocol": false }
    },
    {
      "name": "ssh-admin",
      "detector": "ssh_username",
      "ssh_usernames": ["admin", "root"],
      "backend": { "host": "127.0.0.1", "port": 2222, "proxy_protocol": true }
    },
    {
      "name": "ssh",
      "detector": "ssh",
      "backend": { "host": "127.0.0.1", "port": 22, "proxy_protocol": true }
    }
  ],
  "fallback": { "host": "127.0.0.1", "port": 22, "proxy_protocol": false }
}
```
