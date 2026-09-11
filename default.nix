{ sources ? import ./npins
, pkgs ? import sources.nixpkgs {}
, dnsUpstreamV4 ? null
, dnsUpstreamV6 ? null
}:

let
  v4DnatRule = if dnsUpstreamV4 != null
    then "meta l4proto { udp, tcp } th dport 53 dnat ip to ${dnsUpstreamV4}:53"
    else "";
  v6DnatRule = if dnsUpstreamV6 != null
    then "meta l4proto { udp, tcp } th dport 53 dnat ip6 to [${dnsUpstreamV6}]:53"
    else "";
  v4Element = if dnsUpstreamV4 != null
    then "elements = { ${dnsUpstreamV4} }"
    else "";
  v6Element = if dnsUpstreamV6 != null
    then "elements = { ${dnsUpstreamV6} }"
    else "";

  nftRules = pkgs.writeText "nftables.conf" ''
    flush ruleset

    table inet filter {
      # 1. 动态白名单集合 (IPv4 与 IPv6)
      set lan_whitelist_v4 {
        type ipv4_addr
        flags interval
      }
      set lan_whitelist_v6 {
        type ipv6_addr
        flags interval
      }

      # 2. 受信任上游 DNS 集合 (由守护进程自省 resolv.conf 或环境变量动态维护)
      set dns_upstream_v4 {
        type ipv4_addr
        flags interval
        ${v4Element}
      }
      set dns_upstream_v6 {
        type ipv6_addr
        flags interval
        ${v6Element}
      }

      # 3. 内网私有/保留网段定义
      set private_v4 {
        type ipv4_addr
        flags interval
        elements = { 
          10.0.0.0/8, 
          172.16.0.0/12, 
          192.168.0.0/16, 
          169.254.0.0/16,   # RFC 3927 IPv4 链路本地与云元数据服务 (IMDS)
          100.64.0.0/10,    # RFC 6598 共享地址空间 (CGNAT)
          127.0.0.0/8 
        }
      }
      set private_v6 {
        type ipv6_addr
        flags interval
        elements = { 
          ::1/128,          # 回环
          fc00::/7,         # 唯一本地地址 ULA (相当于 IPv4 私网)
          fe80::/10         # 链路本地地址 Link-Local
        }
      }

      # 4. PREROUTING 链：内核级透明 DNS 劫持 (DNAT)
      # 默认由守护进程启动时自省网关容器自身 DNS (/etc/resolv.conf) 并原子注入
      chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ${v4DnatRule}
        ${v6DnatRule}
      }

      chain forward {
        type filter hook forward priority 0; policy drop;

        # 状态跟踪：放行已建立连接
        ct state established,related accept

        # 放行 ICMPv6 邻居发现与必要控制报文 (RFC 4890)
        meta l4proto ipv6-icmp accept

        # 放行被重定向后的受信任上游安全 DNS (优先于私网拦截规则)
        ip daddr @dns_upstream_v4 th dport 53 accept
        ip6 daddr @dns_upstream_v6 th dport 53 accept

        # 白名单优先放行
        ip daddr @lan_whitelist_v4 accept
        ip6 daddr @lan_whitelist_v6 accept

        # 审计日志与拦截：丢弃其余发往内网私有地址的报文 (防止 SSRF)
        ip daddr @private_v4 limit rate 10/minute log prefix "[ANTI-SSRF DROP-V4]: "
        ip daddr @private_v4 drop
        ip6 daddr @private_v6 limit rate 10/minute log prefix "[ANTI-SSRF DROP-V6]: "
        ip6 daddr @private_v6 drop

        # 放行其余合法公网流量
        accept
      }

      chain postrouting {
        type nat hook postrouting priority 100; policy accept;

        # 出口双栈地址伪装 (MASQUERADE)，自适应动态与静态网络
        masquerade
      }
    }
  '';

  nftDaemon = pkgs.rustPlatform.buildRustPackage {
    pname = "nft-egress-daemon";
    version = "0.1.0";
    src = ./nft-egress-daemon;
    cargoLock = {
      lockFile = ./nft-egress-daemon/Cargo.lock;
    };
  };

in
pkgs.dockerTools.buildLayeredImage {
  name = "nix-nft-gateway";
  tag = "latest";
  contents = [
    nftDaemon
    pkgs.nftables
    pkgs.iana-etc
    pkgs.iproute2
  ];
  extraCommands = ''
    mkdir -p etc/nftables
    touch etc/nftables/whitelist.txt
  '';
  config = {
    Entrypoint = [ "${nftDaemon}/bin/nft-egress-daemon" ];
    Cmd = [
      "run"
      "--rules"
      "${nftRules}"
      "--whitelist"
      "/etc/nftables/whitelist.txt"
    ];
    Env = [
      "NFT_RULES_PATH=${nftRules}"
      "PATH=/bin:/usr/bin"
    ];
  };
}
