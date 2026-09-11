# nix-nft-egress: 基于 nftables 的原子化双栈出口白名单网关

本项目是一个基于 Nix 构建、Rust 实现的高性能双栈（IPv4/IPv6）出口防火墙网关方案。主要用于容器化与虚拟化环境中，在保障业务容器具备正常公网访问能力的同时，默认严密阻断发往内网私有地址空间（防止 SSRF 与局域网横向渗透），并通过 inotify 监听机制实现局域网目标白名单的热重载与原子化生效。

---

## 目录

- [核心特性](#核心特性)
- [如何使用](#如何使用)
  - [1. 镜像地址与版本标签](#1-镜像地址与版本标签)
  - [2. 部署模式与编排示例（动态模式 vs 静态模式）](#2-部署模式与编排示例动态模式-vs-静态模式)
  - [3. 详细使用指南](#3-详细使用指南)
- [安全模型与流量拓扑](#安全模型与流量拓扑)
  - [1. 整体流量控制拓扑](#1-整体流量控制拓扑)
  - [2. 内核级透明 DNS 劫持与防内网探测机制](#2-内核级透明-dns-劫持与防内网探测机制)
- [项目代码库结构](#项目代码库结构)
- [核心模块深入解析](#核心模块深入解析)
  - [1. nft-egress-daemon (Rust 守护进程)](#1-nft-egress-daemon-rust-守护进程)
  - [2. default.nix (Nix 构建与镜像打包)](#2-defaultnix-nix-构建与镜像打包)
  - [3. 白名单配置规范 (whitelist.txt)](#3-白名单配置规范-whitelisttxt)
- [离线沙盒自动化测试 (test_runner.sh)](#离线沙盒自动化测试-test_runnersh)
- [构建、运行与维护指南](#构建运行与维护指南)

---

## 核心特性

- **Sidecar 共享网络栈架构**：基于标准容器网络命名空间共享（Docker `network_mode: "service:gateway"` / K8s Pod），业务容器与网关原生共享同一网络命名空间，业务容器零侵入、零特权。
- **双栈安全防护**：统一接管 IPv4 与 IPv6 流量，原生支持 IPv6 ULA（唯一本地地址）与 Link-Local 链路本地地址防护。
- **默认内网阻断（Anti-SSRF）**：默认封禁 RFC 1918、RFC 3927（IPv4 链路本地/云元数据 IMDS 地址 `169.254.0.0/16`）、RFC 6598（CGNAT 共享网段 `100.64.0.0/10`）以及 RFC 4193（IPv6 ULA），内置限速审计日志，杜绝云元数据泄漏与内网资产探测。
- **内核级透明 DNS 劫持（业务零侵入、防内网 DNS 泄露与 DNS-Rebinding SSRF）**：利用内核 nftables `nat_output` 链 NAT 能力，对业务容器发往任何目标（包括内网网关、路由器或恶意伪造的内网地址）的 53 端口 UDP 与 TCP 查询执行透明 DNAT 劫持，无感重定向至网关受信任的安全上游 DNS。
- **天然网络保持与崩溃自愈**：由容器运行时从内核层保证网络栈共享，业务容器发生崩溃、OOM 重建或正常重启，均天然处于受保护网络栈中，无需路由重新注入。
- **动态原子重载**：Rust 守护进程利用 Linux 内核 inotify 监听白名单文件，采用 nftables 原生批量脚本（Batch Script）原子替换集合（Set），零连接中断，无需重启容器。
- **CIDR 规范化与容错去重**：语法解析器自动对主机位未置零的 CIDR 网段执行掩码截断规范化（Canonicalization），杜绝因格式瑕疵导致内核事务报错回滚；自动完成条目排序去重；严格模式下可作为 CI/CD Lint 守门工具。
- **Pod 本地回环通信放行**：放行 Pod 内部本地回环接口 `lo`（`127.0.0.1` 与 `::1`），保障 Pod 内部业务容器与各类伴生进程的高性能 IPC / localhost 通信。
- **消抖与容错处理**：内置事件消抖队列（Debounce），兼容 Vim/Nano 临时文件重命名覆盖等原子写入机制，非严格模式下自动忽略脏数据并输出日志。
- **最小化纯净镜像**：由 Nix (`dockerTools.buildLayeredImage`) 分层构建，仅包含守护进程可执行文件、nftables 及必要系统依赖，极致轻量且无冗余攻击面。
- **完整离线自动化测试**：内置由隔离网络构建的容器化 Mock 靶场测试套件（12 项高标准测试），全面覆盖公网放行、私网与云元数据拦截、动态加载、权限回收、容器重启自愈、非规范 CIDR 容错、Pod 本地回环通信、双栈 TCP/UDP 透明 DNS 劫持以及白名单主机 DNS 防泄露。

---

## 如何使用

本项目已实现自动化多架构（`linux/amd64` 与 `linux/arm64`）镜像构建与发布，预编译镜像已托管在 GitHub Container Registry (GHCR)。项目主页：[github.com/shaogme/nix-nft-egress](https://github.com/shaogme/nix-nft-egress)。

### 1. 镜像地址与版本标签

- **镜像地址**：
  `ghcr.io/shaogme/nix-nft-egress:latest`
- **版本标签规范**：
  - `latest`：始终指向最新的稳定主分支多架构镜像构建。
  - `YYYYMMDD`（如 `ghcr.io/shaogme/nix-nft-egress:20260911`）：年月日格式的快照版本，便于在生产环境中锁定版本。若当日存在多次构建发布，该标签会自动更新为最新的构建产物。

---

### 2. 部署模式与编排示例（动态模式 vs 静态模式）

本项目支持两种部署模式。针对**同一宿主机上并存 $n$ 个使用出口网关的独立业务**的场景，**强烈推荐使用动态自适应模式**：

| 模式 | 适用场景 | IP 与网段规划 | 多服务并存体验 |
| :--- | :--- | :--- | :--- |
| **动态自适应模式 (推荐)** | 微服务、多独立服务、开发测试、CI/CD 靶场 | **零规划**：由 Docker 动态分配随机可用网段，业务容器通过 `network_mode: "service:gateway"` 直接共享网关网络 | **极佳**：每新增一个服务直接启动，永无网段冲突报错 |
| **静态固定模式** | 传统机房、企业合规审计、要求严格绑定固定 IP 资产 | **需显式规划**：需手动配置 `ipam.subnet` 与网关静态 IP，业务容器自动共享网关固定出口 IP | **需人工分配**：新增服务需确保子网与之前服务不重叠 |

---

#### 模式一：动态自适应模式（Dynamic Mode，推荐）

网关自动从 Docker 动态分配的子网中获取 IP，业务容器声明 `network_mode: "service:gateway"` 即可：
- **无需显式声明 `ipam` 子网**：Docker 引擎会自动为每个 `docker compose` 项目分配互不冲突的私有网段。
- **无需为容器绑定静态 IP**：网关容器动态获取 IP，业务容器原生共享网关网络栈。
- **业务容器纯净零特权**：业务容器无需配置任何特权与参数，与网关共享内核 nftables 出口防护。

示例编排配置（位于 [docker/docker-compose.yml](docker/docker-compose.yml)）：

```yaml
version: '3.8'

# Sidecar / Pod 共享网络栈模式（最高安全等级，零侵入无特权）：
# 业务容器通过 network_mode: "service:gateway" 直接共享网关网络栈。
# 网关仅需 NET_ADMIN 配置自身 nftables 规则。

networks:
  # 纯粹的外部网络，无需受保护的内部网桥
  public_net:
    driver: bridge
    enable_ipv6: true

services:
  # 1. 出口防火墙安全网关
  gateway:
    image: ghcr.io/shaogme/nix-nft-egress:latest
    container_name: egress_gateway
    cap_add:
      - NET_ADMIN
    volumes:
      - ../whitelist.txt:/etc/nftables/whitelist.txt:ro
    networks:
      - public_net
    restart: unless-stopped

  # 2. 纯净无特权业务应用
  business-app:
    image: alpine:latest
    container_name: business_app
    # 核心声明：直接共享网关网络，无需任何网络配置，零特权
    network_mode: "service:gateway"
    depends_on:
      - gateway
    command: ["sleep", "infinity"]
```

> **多服务并行部署提示**：
> 如果您在同台机器上有多个独立项目需要接入 `nix-nft-egress`，只需将上述配置文件和白名单放入各个项目的独立目录中，使用 `docker compose -p project_a up -d`、`docker compose -p project_b up -d` 即可无感启动，无需修改任何 IP 或网段参数！

---

#### 模式二：静态固定 IP 模式（Static Mode）

适用于生产环境中安全策略严格、要求锁定已知 IP 范围进行资产审计或配合外部防火墙白名单的场景。

示例编排配置（位于 [docker/docker-compose.static.yml](docker/docker-compose.static.yml)）：

```yaml
version: '3.8'

# 静态固定 IP 模式示例 (Sidecar 架构)：
# 业务容器通过 network_mode: "service:gateway" 共享网关网络栈。
# 仅需在网关容器声明外部网络的固定 IPv4 / IPv6 地址，业务容器即可自动共享该固定出口 IP。

networks:
  # 外部双栈出口网桥（固定子网）
  public_net:
    driver: bridge
    enable_ipv6: true
    ipam:
      config:
        - subnet: 172.21.0.0/24
        - subnet: fd00:cafe:babe::/64

services:
  # 1. 出口防火墙安全网关 (Sidecar)
  gateway:
    image: ghcr.io/shaogme/nix-nft-egress:latest
    container_name: egress_gateway
    cap_add:
      - NET_ADMIN
    volumes:
      - ../whitelist.txt:/etc/nftables/whitelist.txt:ro
    networks:
      public_net:
        ipv4_address: 172.21.0.2
        ipv6_address: fd00:cafe:babe::2
    restart: unless-stopped

  # 2. 纯净受保护业务容器：零网络特权，共享网关固定 IP
  business-app:
    image: alpine:latest
    container_name: business_app
    network_mode: "service:gateway"
    depends_on:
      - gateway
    command: ["sleep", "infinity"]
```

> **静态模式冲突规避**：
> 若在同一宿主机上运行多个静态模式服务栈，必须为每个栈分配互不重叠的 `subnet`（如 Service B 需分配 `172.22.0.0/24`），以避免 Docker 报 `Pool overlaps` 错误。如果不需要严格的 IPAM 控制，推荐使用前述动态模式。

---

### 3. 详细使用指南

#### 第一步：准备白名单文件 `whitelist.txt`

在 `docker-compose.yml` 同级目录下创建 `whitelist.txt`，声明允许访问的内网私有地址或网段：

```text
# ==========================================
# 局域网/私网出向白名单配置 (按需放行)
# 默认情况下所有发往 RFC 1918 / ULA 的流量均会被丢弃
# ==========================================

# 放行特定局域网主机 (IPv4 / IPv6)
192.168.1.100
fc00:1234::1

# 放行特定网段/子网 (CIDR 格式)
10.0.1.0/24
fd12:3456:789a::/48

# 支持行尾注释与空行
# 172.16.10.0/24
```

> **配置提示**：
> 1. 公网合法地址（如 `1.1.1.1`、`8.8.8.8` 或外部 Web 服务）**无需在白名单中添加**，防火墙网关默认自动放行公网流量。
> 2. 只有落在内网保留地址范围（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `127.0.0.0/8`, `fc00::/7`, `fe80::/10`）的目标才需要在此显式声明。

#### 第二步：启动服务

在包含 `docker-compose.yml` 和 `whitelist.txt` 的目录中运行：

```bash
docker compose up -d
```

查看容器运行状态：
```bash
docker compose ps
```

#### 第三步：验证隔离与放行机制

通过在业务容器 `business_app` 中发起网络请求验证效果：

1. **测试公网连通性**（直接放行）：
   ```bash
   docker exec -it business_app wget -q -T 3 -O- http://1.1.1.1
   ```
2. **测试未放行的私网地址拦截（Anti-SSRF）**（请求超时失败被 DROP）：
   ```bash
   docker exec -it business_app wget -q -T 3 -O- http://192.168.1.100
   # 终端将在 3 秒后超时退出，证明发往内网私有网段的未授权访问已被成功拦截
   ```
3. **验证白名单动态生效**：
   将目标地址（如 `192.168.1.100`）追加写入宿主机的 `whitelist.txt`，无需重启任何容器：
   ```bash
   echo "192.168.1.100" >> whitelist.txt
   # 等待 150ms 消抖与原子应用后，再次测试连通性
   docker exec -it business_app wget -q -T 3 -O- http://192.168.1.100
   ```

#### 第四步：常用运维与调试指令

- **查看内核实际生效的完整 ruleset**：
  ```bash
  docker exec -it egress_gateway nft list ruleset
  ```
- **查看当前动态加载的 IPv4 白名单集合**：
  ```bash
  docker exec -it egress_gateway nft list set inet filter lan_whitelist_v4
  ```
- **查看当前动态加载的 IPv6 白名单集合**：
  ```bash
  docker exec -it egress_gateway nft list set inet filter lan_whitelist_v6
  ```
- **查看网关守护进程实时日志**：
  ```bash
  docker logs -f egress_gateway
  ```
- **手动强制全量重新同步白名单（发送 SIGHUP 信号）**：
  ```bash
  docker kill -s HUP egress_gateway
  ```

---

## 安全模型与流量拓扑

### 1. 整体流量控制拓扑

```mermaid
flowchart TD
    subgraph PodNet ["受保护的 Pod / 共享网络空间 (Shared Netns)"]
        Client["业务应用 (business-app / tester)\n(零特权，共享网络栈)"]
        
        subgraph NetnsTraffic ["共享内核 nftables 出口流量引擎"]
            direction TB
            subgraph NatOutputEngine ["nftables NAT 引擎 (nat_output dstnat)"]
                DNSCheck{"目标端口是否为 53 (UDP/TCP)?"}
                DNATAction["内核级透明 DNAT 重定向\n(dnat to @dns_upstream_v4 / v6:53)"]
            end

            subgraph OutputFilterEngine ["nftables 过滤引擎 (output priority 0)"]
                Conntrack["连接跟踪 (established, related)"]
                Loopback["本地回环 lo 报文放行"]
                ICMPv6["ICMPv6 报文放行 (RFC 4890)"]
                UpstreamDNSCheck{"目标是否为受信任上游 DNS?\n(@dns_upstream_v4 / v6 th dport 53)"}
                WhiteCheck{"目标是否在动态白名单中?\n(@lan_whitelist_v4 / v6)"}
                PrivateCheck{"目标是否属于内网私网/保留网段?\n(@private_v4 / v6)"}
                PassAction["放行通过 (accept)"]
                DropAction["丢弃阻断 (drop) + 限速日志审计"]
            end

            subgraph NatPostEngine ["nftables 出口伪装 (nat_postrouting)"]
                NAT["MASQUERADE 出口伪装"]
            end
        end

        subgraph DaemonEngine ["Rust 守护进程 (nft-egress-daemon)"]
            ConfigFile["白名单配置文件 (whitelist.txt)"]
            InotifyWatcher["inotify 监听器 + 150ms 消抖"]
            ResolvConf["系统 resolv.conf (自动探测系统 DNS)"]
            Parser["语法解析与自省引擎 (parser.rs)"]
            BatchApplier["nft 原生原子批处理应用 (nft.rs)"]
        end
    end

    subgraph OutboundTargets ["目标网络"]
        PublicDNS["受信任上游安全 DNS 服务器"]
        PublicWAN["互联网公网服务 (Internet)"]
        AllowedLAN["放行的局域网白名单目标"]
        BlockedLAN["未放行的局域网内网服务 (被拦截)"]
    end

    Client -->|本地发起出向流量| DNSCheck
    DNSCheck -->|是 (port 53)| DNATAction
    DNSCheck -->|否| Conntrack
    DNATAction --> Conntrack

    Conntrack --> Loopback
    Loopback --> ICMPv6
    ICMPv6 --> UpstreamDNSCheck
    UpstreamDNSCheck -->|命中安全 DNS 规则| PassAction
    UpstreamDNSCheck -->|否| WhiteCheck

    WhiteCheck -->|命中白名单| PassAction
    WhiteCheck -->|未命中| PrivateCheck
    PrivateCheck -->|是私网地址| DropAction
    PrivateCheck -->|公网目标| PassAction
    PassAction --> NAT
    NAT --> PublicDNS
    NAT --> PublicWAN
    NAT --> AllowedLAN
    DropAction -.-> BlockedLAN

    ConfigFile -->|文件变动事件| InotifyWatcher
    InotifyWatcher --> Parser
    ResolvConf -->|启动时自动探测| Parser
    Parser --> BatchApplier
    BatchApplier -->|原子化更新 DNAT 规则| NatOutputEngine
    BatchApplier -->|原子化更新 Set 元素| OutputFilterEngine
```

---

### 2. 内核级透明 DNS 劫持与防内网探测机制

在容器出口管控中，DNS 查询通道常常是安全防御的盲区。若业务容器可以直接向局域网 DNS 查询，存在两大严重安全风险：
1. **内网域名资产探测与拓扑泄露**：黑客可在业务容器内针对内网 DNS（如路由器 `192.168.1.1` 或内网 AD 域控）发起域名枚举爆破，刺探局域网私有资产拓扑。
2. **DNS-Rebinding 与 SSRF 穿透**：通过动态解析恶意域名将 IP 指向内网，若内网 DNS 缺乏可信过滤或直接被业务容器利用，将直接威胁内网私密服务。

为了在**严禁业务容器访问内网 DNS** 的前提下，保障业务容器正常的域名解析能力，本项目采用**内核级透明 DNAT 劫持架构**：

#### 核心实现原理
- **内核级零侵入重定向**：在 Linux 内核 nftables 的 `nat_output` 链（优先级 `dstnat`）中挂载规则。业务容器无需任何侵入式配置或修改 `/etc/resolv.conf`，无论其向何处（例如系统自带的 `127.0.0.11`、路由器 `192.168.1.1` 或是任意不存在的内网 IP）发起的 53 端口 UDP 或 TCP 查询，均在内核层被透明重写目标地址（DNAT）至网关上游安全 DNS。
- **默认自省网关自身 DNS**：守护进程启动时默认自省网关自身的 `/etc/resolv.conf`，动态提取当前网络环境配置的合法 nameserver，并原子注入至 `@dns_upstream_v4` 和 `@dns_upstream_v6` 集合中。绝不在代码中硬编码外部公网 DNS（如 `1.1.1.1` 或 `8.8.8.8`），以适配专网、内网合规 DNS 或局域网定制环境。
- **灵活的配置覆盖**：
  - 支持通过环境变量 `DNS_UPSTREAM_V4`、`DNS_UPSTREAM_V6` 或命令行参数 `--dns-upstream-v4`、`--dns-upstream-v6` 显式指定特定上游 DNS（例如指定企业递归 DNS 或安全 Do53 服务器）。
  - 若显式设置为 `off` / `none` / `disabled`，可关闭对应协议栈的透明劫持功能。
  - 支持通过环境变量 `RESOLV_CONF_PATH` 或 `--resolv-conf` 指定 resolv.conf 的检测路径。
- **白名单规则冲突免疫**：
  - 在 `output` 链中，`ip daddr @dns_upstream_v4 th dport 53 accept` 和 `ip6 daddr @dns_upstream_v6 th dport 53 accept` 规则优先于私网拦截规则生效。
  - **DNS 强制隔离保证**：即使管理员在 `whitelist.txt` 中放行了某个内网 IP（例如放行 `192.168.100.10` 的 Web 服务），当业务容器试图向 `192.168.100.10:53` 发起 DNS 请求时，仍然会在内核层被强行劫持到上游受信任 DNS，局域网靶机绝不会收到来自业务容器的 53 端口查询请求，从源头杜绝内网 DNS 资产泄露。

---

## 项目代码库结构

```
.
├── AGENTS.md                          # AI 代理工作规范及依赖管理指引
├── default.nix                        # Nix 表达式：规则定义、Daemon 编译及 Docker 镜像打包
├── docker-compose.yml                 # 根目录开发环境配置 (devbox/npins-rust 基础容器)
├── test_runner.sh                     # 离线集成自动化测试脚本
├── test_whitelist.txt                 # 测试专用白名单挂载文件
├── whitelist.txt                      # 生产推荐白名单模板文件
├── docker/
│   ├── docker-compose.yml             # Sidecar 动态模式部署示例
│   ├── docker-compose.static.yml      # Sidecar 静态固定 IP 模式部署示例
│   └── docker-compose.test.yml        # 自动化测试沙盒靶场拓扑配置
├── docs/                              # npins 及工作流文档
│   └── npins/
│       ├── cli.md
│       ├── testing.md
│       └── usage.md
├── nft-egress-daemon/                 # Rust 守护进程源码目录
│   ├── Cargo.lock                     # 依赖版本锁定文件
│   ├── Cargo.toml                     # Cargo 配置与代码检查规则
│   ├── README.md                      # Rust 模块简述
│   └── src/
│       ├── main.rs                    # 守护进程主入口与命令行参数解析
│       ├── nft.rs                     # nft 批处理生成与管道执行交互
│       ├── parser.rs                  # IP 与 CIDR 语法解析、规范化及单元测试
│       ├── router.rs                  # 本地网络接口自省工具
│       ├── signals.rs                 # POSIX 信号处理 (SIGTERM, SIGINT, SIGHUP)
│       └── watcher.rs                 # inotify 监听循环、事件排空与消抖同步
└── npins/                             # npins 依赖锁定机制
    ├── default.nix
    └── sources.json                   # 固化的 nixpkgs 等源描述
```

---

## 核心模块深入解析

### 1. nft-egress-daemon (Rust 守护进程)

守护进程常驻后台运行，负责协调内核防火墙状态与磁盘配置文件的一致性。

#### [main.rs](nft-egress-daemon/src/main.rs) - 程序入口与模式分流
- **信号初始化**：在程序启动最前置阶段调用 [`register_signals`](nft-egress-daemon/src/signals.rs#L18)，捕获进程生命周期信号。
- **子命令支持**：
  - `run`（默认）：启动网关守护模式。支持通过 `--rules <PATH>`、`--whitelist <PATH>`、`--family <FAMILY>`、`--table <TABLE>`、`--v4-set <SET>`、`--v6-set <SET>`、`--debounce-ms <MS>`、`--dns-upstream-v4 <IP|auto|off>`、`--dns-upstream-v6 <IP|auto|off>` 以及 `--resolv-conf <PATH>` 自定义参数。
  - `check <FILE>`：静态校验白名单文件语法（通过 [`handle_check`](nft-egress-daemon/src/main.rs#L43) 实现），支持 `--strict` 标志，遇到警告即以非零码退出，可作为 CI/CD 流程中的 Lint 工具。
- **环境变量支持**：支持用于 DNS 透明劫持控制的 `DNS_UPSTREAM_V4`、`DNS_UPSTREAM_V6`、`RESOLV_CONF_PATH` 等。
- **DNS 自省与原子初始化**：调用 [`resolve_dns_upstreams`](nft-egress-daemon/src/main.rs)，当配置为 `auto`（默认）时自省 `/etc/resolv.conf` 动态提取 nameserver；通过 [`initialize_rules_and_dns`](nft-egress-daemon/src/main.rs) 在进程启动时原子下发基础 ruleset 与 DNAT 劫持规则。
- **透传执行模式（Direct Exec）**：如果传入 `-- <CMD> [ARGS...]` 或非选项参数，程序会优先从环境变量 `NFT_RULES_PATH` 或命令行加载防火墙规则，随后直接通过 Unix `exec()` 将进程替换为子命令，实现无缝作为其他应用 Entrypoint 的能力。

#### [router.rs](nft-egress-daemon/src/router.rs) - 本地网络接口自省工具
- 提供纯净的本地网络接口 IP 解析（[`get_gateway_ips`](nft-egress-daemon/src/router.rs)）与默认路由解析工具（[`get_default_routes`](nft-egress-daemon/src/router.rs)）。

#### [signals.rs](nft-egress-daemon/src/signals.rs) - POSIX 信号抽象
- 利用 `libc::signal` 注册底层信号处理函数 [`sig_handler`](nft-egress-daemon/src/signals.rs#L6)。
- `SIGTERM` 与 `SIGINT`：更新原子布尔标记 `SHUTDOWN_REQUESTED`，通知主循环优雅终止。
- `SIGHUP`：更新原子布尔标记 `RELOAD_REQUESTED`，用于运维人员手动触发规则强制全量重新同步。

#### [parser.rs](nft-egress-daemon/src/parser.rs) - 白名单与系统 DNS 解析器
- **数据结构**：[`WhitelistEntries`](nft-egress-daemon/src/parser.rs) 存储分离的 `v4: Vec<String>` 与 `v6: Vec<String>`；[`DetectedDns`](nft-egress-daemon/src/parser.rs) 存储提取到的 `v4: Option<Ipv4Addr>` 与 `v6: Option<Ipv6Addr>`。
- **系统 DNS 自省解析机制 [`parse_resolv_conf`](nft-egress-daemon/src/parser.rs) / [`detect_auto_dns`](nft-egress-daemon/src/main.rs)**：
  - 自动解析系统 `/etc/resolv.conf` 文件，过滤注释行与空行。
  - 精准提取外部接口合法 IPv4 与 IPv6 `nameserver` 字段作为安全上游 DNS，杜绝硬编码。
- **白名单单行解析机制 [`parse_line`](nft-egress-daemon/src/parser.rs)**：
  - 自动剥离 `#` 注释符及首尾空白字符。
  - 准确识别单 IP（`std::net::Ipv4Addr` / `std::net::Ipv6Addr`）与 CIDR 网段格式。
  - 严格校验掩码合法性：IPv4 掩码必须 `<= 32`，IPv6 掩码必须 `<= 128`。
  - **CIDR 规范化（Canonicalization）**：自动将主机位未置零的 CIDR（如 `192.168.1.100/24`）通过位运算掩码截断为规范网络地址（`192.168.1.0/24`），杜绝因格式瑕疵导致内核 `nftables` 报错回滚。
- **条目自动去重**：内部基于 `BTreeSet` 自动完成白名单条目的字典序去重，保证集合规则轻量与幂等。
- **模式差异 [`parse_whitelist`](nft-egress-daemon/src/parser.rs)**：
  - 守护进程运行时采用宽容模式（`strict = false`）：忽略非法行并打印标准错误警告，非规范 CIDR 自动纠正并输出 Notice，保障服务可用性。
  - `check --strict` 采用严格模式（`strict = true`）：遇到非零主机位 CIDR 或任何语法错误立即返回非零退出码。

#### [nft.rs](nft-egress-daemon/src/nft.rs) - nftables 原子脚本交互
- **白名单脚本构造 [`generate_batch_script`](nft-egress-daemon/src/nft.rs)**：针对 IPv4 与 IPv6 集合分别生成 `flush set` 与 `add element` 语句。
- **DNS 透明重定向脚本构造 [`generate_dns_redirect_script`](nft-egress-daemon/src/nft.rs)**：
  - 针对指定或探测到的上游 DNS，动态构建 `nat_output` 链 DNAT 规则及 `@dns_upstream_v4` / `@dns_upstream_v6` 集合填充语句。
  - 支持分别对 IPv4 和 IPv6 独立配置生效或关闭。
- **原子事务提交流程 [`apply_batch`](nft-egress-daemon/src/nft.rs) 与 [`apply_dns_redirect`](nft-egress-daemon/src/nft.rs)**：
  - 启动 `nft -f -` 进程，将构造好的批处理脚本通过标准输入（stdin）一次性喂入。
  - 内核在单次事务中执行规则与集合的更新，避免了传统防火墙逐条追加导致的短暂阻断或时序漏洞。
- **规则集初始化与动态重构 [`generate_base_ruleset`](nft-egress-daemon/src/nft.rs) 与 [`load_ruleset`](nft-egress-daemon/src/nft.rs)**：容器启动时加载基线配置，若缺少 `NET_ADMIN` 能力或内核模块未就绪，输出详细诊断错误。

#### [watcher.rs](nft-egress-daemon/src/watcher.rs) - inotify 高性能事件循环
- **配置结构体扩展 [`DaemonConfig`](nft-egress-daemon/src/watcher.rs)**：统一封装 rules 路径、白名单路径、集合名称、消抖间隔以及 DNS 上游配置（`resolv_conf_path`, `dns_upstream_v4`, `dns_upstream_v6`）。
- **监控策略**：同时监听白名单文件所在父目录（`parent_dir`）和白名单文件本身。使用掩码 `CLOSE_WRITE | MOVED_TO | CREATE | MODIFY | DELETE`。即便文本编辑器使用先写临时文件后 `rename` 的原子覆盖策略，亦不会丢失事件。
- **非阻塞 I/O 与 Poll**：将 inotify 文件描述符配置为 `O_NONBLOCK`，使用 `libc::poll` 设置 500ms 超时轮询，兼顾信号响应度与极低的 CPU 占用率。
- **消抖与事件排空**：
  - 检测到目标文件变动后，休眠 `debounce_ms`（默认 150ms），等待写入彻底完成。
  - 循环调用 [`drain_inotify_events`](nft-egress-daemon/src/watcher.rs#L73) 排空缓冲区内堆积的重复修改通知。
  - 如果文件句柄被删除重建，自动重新挂载 watch 句柄，随后执行 [`sync_whitelist`](nft-egress-daemon/src/watcher.rs#L38)。

---

### 2. default.nix (Nix 构建与镜像打包)

[default.nix](default.nix) 是整个网关镜像的声明式构建规范，主要包含三大部分：

#### 防火墙基线规则 (nftRules)
```nix
flush ruleset

table inet filter {
  # 1. 动态白名单集合 (支持区间匹配)
  set lan_whitelist_v4 { type ipv4_addr; flags interval; }
  set lan_whitelist_v6 { type ipv6_addr; flags interval; }

  # 2. 受信任上游 DNS 集合 (由守护进程自省 resolv.conf 或环境变量动态维护)
  set dns_upstream_v4 { type ipv4_addr; flags interval; }
  set dns_upstream_v6 { type ipv6_addr; flags interval; }

  # 3. 内网私有保留网段与云元数据
  set private_v4 {
    type ipv4_addr; flags interval;
    elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 127.0.0.0/8 }
  }
  set private_v6 {
    type ipv6_addr; flags interval;
    elements = { ::1/128, fc00::/7, fe80::/10 }
  }

  # 4. PREROUTING 链：内核级透明 DNS 劫持 (DNAT)
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    # 动态由 nft-egress-daemon 启动时自省网关容器 /etc/resolv.conf 注入，例如：
    # meta l4proto { udp, tcp } th dport 53 dnat ip to 192.168.1.1:53
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    # 1. 状态跟踪：放行已建立连接
    ct state established,related accept

    # 2. 放行 ICMPv6 邻居发现与必要控制报文 (RFC 4890)
    meta l4proto ipv6-icmp accept

    # 3. 放行被重定向后的受信任上游安全 DNS (优先于私网拦截规则)
    ip daddr @dns_upstream_v4 th dport 53 accept
    ip6 daddr @dns_upstream_v6 th dport 53 accept

    # 4. 白名单优先放行
    ip daddr @lan_whitelist_v4 accept
    ip6 daddr @lan_whitelist_v6 accept

    # 5. 审计与拦截：丢弃发往内网私有地址及云元数据的报文 (防止 SSRF)
    ip daddr @private_v4 limit rate 10/minute log prefix "[ANTI-SSRF DROP-V4]: "
    ip daddr @private_v4 drop
    ip6 daddr @private_v6 limit rate 10/minute log prefix "[ANTI-SSRF DROP-V6]: "
    ip6 daddr @private_v6 drop

    # 6. 放行公网出向流量
    accept
  }

  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    # 出口地址自适应伪装 (MASQUERADE，自适应动态与静态网络)
    masquerade
  }
}
```

> **构建参数说明**：
> `default.nix` 接受 `dnsUpstreamV4 ? null` 与 `dnsUpstreamV6 ? null` 构造参数。默认值设为 `null`；运行阶段由守护进程通过自省容器环境或读取环境变量完成安全注入。

#### 守护进程编译 (nftDaemon)
使用 `pkgs.rustPlatform.buildRustPackage` 构建，依赖项由 [Cargo.lock](nft-egress-daemon/Cargo.lock) 严密固化，保证构建的一致性与离线可重现性。

#### Docker 镜像生成 (buildLayeredImage)
打包产物为 `nix-nft-gateway:latest`：
- 仅打包 `nftDaemon`、`pkgs.nftables`、`pkgs.iana-etc`（协议/端口服务名称数据库）与 `pkgs.iproute2`。
- 不引入冗余的 Shell 或系统组件，体积小，启动毫秒级。
- 预先配置 Entrypoint 和启动参数，自动载入 Nix 生成的规则集路径。

---

### 3. 白名单配置规范 (whitelist.txt)

[whitelist.txt](whitelist.txt) 文件采用逐行声明格式：
- 支持单主机 IPv4 地址（例如：`192.168.1.100`）
- 支持 IPv4 CIDR 网段（例如：`10.0.1.0/24`）
- 支持单主机 IPv6 地址（例如：`fc00:1234::1`）
- 支持 IPv6 CIDR 网段（例如：`fd12:3456:789a::/48`）
- 支持使用 `#` 标识单行注释或行尾注释
- 支持空行与多余空格缩进，解析器会自动修剪

示例：
```text
# 运维专用机器单点放行
192.168.1.100

# 内部特定服务集群网段
10.0.1.0/24

# IPv6 ULA 放行目标
fc00:1234::1
fd12:3456:789a::/48 # 数据库同步子网
```

---

## 离线沙盒自动化测试 (test_runner.sh)

测试套件 [test_runner.sh](test_runner.sh) 与编排配置 [docker/docker-compose.test.yml](docker/docker-compose.test.yml) 配合，在完全无外网依赖的纯本地环境中构建了隔离网桥：

1. `lan_mock_net` (192.168.100.0/24, fd00:1111::/64)：模拟局域网内网靶机。
2. `wan_mock_net` (1.1.1.0/24, 2606:4700:4700::/64)：直接使用公网 IP 网段模拟外部互联网靶机。

发包测试容器 `tester` 通过 `network_mode: "service:gateway"` 接入网关，原生共享网关网络栈。

### 测试执行阶段
1. **环境归零**：将挂载的 [test_whitelist.txt](test_whitelist.txt) 清空，拉起靶场环境。
2. **测试用例 1: 模拟公网连通性 (IPv4 / IPv6)**
   - 发包容器访问 `http://1.1.1.1` 与 `http://[2606:4700:4700::1111]`。
   - 预期结果：正常通过并接收到 `Internet-OK`。
3. **测试用例 2: 局域网私网与云元数据默认阻断 (Anti-SSRF)**
   - 发包容器尝试连接未放行的局域网靶机 `192.168.100.10`、RFC 3927 云元数据地址 `169.254.169.254`、RFC 6598 共享网段 `100.64.0.1` 与 IPv6 ULA `[fd00:1111::10]`。
   - 预期结果：HTTP 请求在 2 秒内超时失败，验证默认 DROP 策略与审计日志生效。
4. **测试用例 3: 动态白名单热加载**
   - 脚本动态向 `test_whitelist.txt` 写入上述两个靶机地址并等待 2 秒。
   - 预期结果：无需重启容器或守护进程，发包机即可成功读取靶机响应 `LAN-OK`。
5. **测试用例 4: 动态白名单清空撤销**
   - 重新清空 `test_whitelist.txt`。
   - 预期结果：原本放行的局域网流量立即被再次阻断，验证权限回收完整性。
6. **测试用例 5: Sidecar 共享网络栈隔离与业务容器零特权验证**：
   - 验证发包机与网关共享网络命名空间与 IP 地址；业务容器执行路由修改命令报权限拒绝（`Operation not permitted`，无 `NET_ADMIN` 特权）；网关无 `pid: host`、无 `docker.sock` 挂载、无 `SYS_ADMIN` 特权。
7. **测试用例 6: 业务容器重启自愈与天然网络保持验证**：
   - 触发测试容器 `docker restart tester` 模拟异常崩溃或更新重启。
   - 预期结果：业务容器天然恢复公网连通且私网阻断持续有效，无需重新注入路由。
8. **测试用例 7: 非标准主机位 CIDR 容错规范化与去重生效**：
   - 写入包含非零主机位 CIDR（如 `192.168.100.55/24`）与重复条目的白名单。
   - 预期结果：解析器自动掩码截断规范化为标准网段并去重，`nftables` 规则集原子应用成功且局域网靶机放行正常。
9. **测试用例 8: Sidecar 模式 Pod 内本地回环 (lo) 通信正常验证**：
   - 在业务容器内通过 `nc` 分别测试 `127.0.0.1` 与 `::1` 本地回环通信。
   - 预期结果：Pod 内部本地回环通信放行正常。
10. **测试用例 9: 内核级透明 DNS 劫持验证 (IPv4 TCP & UDP)**：
    - 发包容器向任意内网靶机或未分配私网 IP（如 `10.254.1.1:53`）发起 TCP 与 UDP 53 端口 DNS 查询。
    - 预期结果：报文在内核层被透明 DNAT 劫持至上游安全 DNS（`1.1.1.1:53`），成功接收到 `SAFE-DNS-OK` 响应。
11. **测试用例 10: 内核级透明 DNS 劫持验证 (IPv6 TCP & UDP)**：
    - 发包容器向任意内网 IPv6 目标发起 TCP 与 UDP 53 端口 DNS 查询。
    - 预期结果：报文被透明劫持至上游安全 DNS `[2606:4700:4700::1111]:53`，成功接收到 `SAFE-DNS-OK` 响应。
12. **测试用例 11: 白名单局域网主机的 DNS-Rebinding / 内部 DNS 泄露阻断验证**：
    - 将局域网靶机 `192.168.100.10` 加入白名单放行其 HTTP 80 服务，随后发包容器向该内网靶机 53 端口发起 DNS 查询。
    - 预期结果：HTTP 80 端口通信正常（响应 `LAN-OK`），但发往该靶机 53 端口的 DNS 请求仍然被内核强制重定向至安全 DNS（响应 `SAFE-DNS-OK`），彻底杜绝内网 DNS 泄露与 DNS-Rebinding 攻击。
13. **测试用例 12: 默认自省网关自身 resolv.conf 与参数解析验证**：
    - 验证守护进程在默认自省模式下能够准确提取 `/etc/resolv.conf` 中的合法 nameserver，并验证 `--resolv-conf` 参数解析健全。
14. **规则树健全性审计**：
    - 执行 `nft list ruleset`，确保集合刷新、DNAT 规则与限速审计未破坏内核规则树结构。

---

## 构建、运行与维护指南

### 1. 编译镜像
在包含 Nix 环境的主机上，使用 `npins` 固化依赖直接进行构建：
```bash
# 构建 Docker 镜像 Tarball
nix-build default.nix

# 将生成的镜像载入 Docker 引擎
docker load < result
```

### 2. 本地校验白名单格式
在修改白名单后，可在主机上运行 daemon 的校验工具避免错误配置传入生产环境：
```bash
# 检查白名单文件合法性
cargo run --manifest-path nft-egress-daemon/Cargo.toml -- check whitelist.txt

# 严格模式检查 (任何警告均按错误处理)
cargo run --manifest-path nft-egress-daemon/Cargo.toml -- check --strict whitelist.txt
```

### 3. 启动生产服务
```bash
cd docker
docker-compose up -d
```

### 4. 运行全量自动化测试
运行沙盒自动化回归测试脚本：
```bash
chmod +x test_runner.sh
./test_runner.sh
```

### 5. 运维诊断常用命令
进入网关容器排查网络与规则状态：
```bash
# 查看当前加载的完整规则集
docker exec -it egress_gateway nft list ruleset

# 仅查看当前的 IPv4 白名单集合内容
docker exec -it egress_gateway nft list set inet filter lan_whitelist_v4

# 仅查看当前的 IPv6 白名单集合内容
docker exec -it egress_gateway nft list set inet filter lan_whitelist_v6

# 手动触发白名单强制重新同步 (发送 SIGHUP 信号)
docker kill -s HUP egress_gateway

# 查看守护进程实时日志
docker logs -f egress_gateway
```
