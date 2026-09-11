# nft-egress-daemon

High performance, atomic nftables egress whitelist gateway daemon written in Rust.

## 模块职责与架构

守护进程常驻后台运行，负责协调内核防火墙状态与磁盘配置文件的一致性，并支持为被保护业务容器自动重定向默认路由。

- **`main.rs`**：程序入口、CLI 参数解析、子命令分流与进程生命周期管理。
- **`router.rs`**：通过 Docker Engine Unix Socket 查询业务容器 PID，直接调用原生 `libc::setns` 系统调用在子进程中切换网络命名空间并执行 `ip route`，将默认路由透明注入到目标容器（无需 `nsenter` 或 `util-linux` 依赖），并具备后台巡检与容器重启自愈能力。
- **`parser.rs`**：白名单配置解析器，支持单 IP 与 CIDR 网段解析、非标准主机位 CIDR 自动掩码截断规范化（Canonicalization）、条目排序去重与严格 Lint 模式。
- **`nft.rs`**：构造 nftables 原生批量脚本（Batch Script），通过 `nft -f -` 管道执行内核原子事务替换，避免逐条更新导致的连接中断或时序窗口。
- **`watcher.rs`**：基于 Linux inotify 监听白名单文件及父目录变动，结合非阻塞 poll 与消抖机制（Debounce）处理各类编辑器的原子写与重命名。
- **`signals.rs`**：POSIX 信号抽象处理（`SIGTERM`/`SIGINT` 优雅退出，`SIGHUP` 强制全量重新同步）。

## 子命令与用法

```bash
# 启动网关守护模式 (默认)
nft-egress-daemon run \
  --rules /path/to/nftables.conf \
  --whitelist /etc/nftables/whitelist.txt \
  --auto-route business_app \
  --gateway-v4 172.20.0.2 \
  --gateway-v6 fd00:dead:beef::2

# 校验白名单格式 (宽容模式，忽略非法行并输出警告)
nft-egress-daemon check whitelist.txt

# 严格模式校验 (遇到任何警告或主机位未置零 CIDR 均直接报错退出，适合 CI/CD Lint)
nft-egress-daemon check --strict whitelist.txt

# 单独向目标容器注入双栈默认路由
nft-egress-daemon inject-route business_app --gateway-v4 172.20.0.2 --gateway-v6 fd00:dead:beef::2
```
