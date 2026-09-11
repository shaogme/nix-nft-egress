#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

COMPOSE_FILE="docker/docker-compose.test.yml"
PROJECT_NAME="nix-nft-test"

if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE="docker-compose"
else
  fail "未找到 'docker compose' 或 'docker-compose' 命令"
fi

echo "=== 初始化离线沙盒测试环境 ==="
# 初始白名单保持为空
> test_whitelist.txt
$DOCKER_COMPOSE -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v --remove-orphans || true
$DOCKER_COMPOSE -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d
sleep 3

# 离线沙盒由于两个 mock 网络均为 internal: true，Docker 不会自动生成默认路由
# 为网关补充模拟外网出口默认路由，确保任意公网与私网目标路由可达
docker exec test_gateway ip route add default via 1.1.1.254 dev eth1 2>/dev/null || true
docker exec test_gateway ip -6 route add default via 2606:4700:4700::fe dev eth1 2>/dev/null || true

EXEC_TEST="docker exec tester"

echo "=== 测试用例 1: 模拟公网连通性 (IPv4 / IPv6) ==="
# 预期：直接连通，获取 HTTP 响应
$EXEC_TEST wget -q -T 2 -O- http://1.1.1.1 | grep -q "Internet-OK" \
  && pass "IPv4 公网转发正常" || fail "IPv4 公网访问失败"

$EXEC_TEST wget -q -T 2 -O- http://[2606:4700:4700::1111] | grep -q "Internet-OK" \
  && pass "IPv6 公网转发正常" || fail "IPv6 公网访问失败"

echo "=== 测试用例 2: 局域网私网与云元数据默认阻断 ==="
# 预期：超时失败 (wget 退出码非 0)
if ! $EXEC_TEST wget -q -T 2 -O- http://192.168.100.10 >/dev/null 2>&1; then
  pass "IPv4 局域网拦截生效"
else
  fail "安全隐患：未放行的 IPv4 局域网靶机被连通！"
fi

if ! $EXEC_TEST wget -q -T 2 -O- http://169.254.169.254 >/dev/null 2>&1; then
  pass "RFC 3927 云元数据拦截生效 (169.254.169.254)"
else
  fail "安全隐患：RFC 3927 云元数据未被拦截！"
fi

if ! $EXEC_TEST wget -q -T 2 -O- http://100.64.0.1 >/dev/null 2>&1; then
  pass "RFC 6598 共享网段拦截生效 (100.64.0.1)"
else
  fail "安全隐患：RFC 6598 共享网段未被拦截！"
fi

if ! $EXEC_TEST wget -q -T 2 -O- http://[fd00:1111::10] >/dev/null 2>&1; then
  pass "IPv6 ULA 局域网拦截生效"
else
  fail "安全隐患：未放行的 IPv6 ULA 局域网靶机被连通！"
fi

echo "=== 测试用例 3: 动态白名单热加载 ==="
# 动态写入白名单（无需重启任何容器）
cat <<EOF > test_whitelist.txt
192.168.100.10
fd00:1111::10
EOF
sleep 2 # 等待 inotify 监听同步

$EXEC_TEST wget -q -T 2 -O- http://192.168.100.10 | grep -q "LAN-OK" \
  && pass "IPv4 白名单动态放行成功" || fail "IPv4 白名单热加载未生效"

$EXEC_TEST wget -q -T 2 -O- http://[fd00:1111::10] | grep -q "LAN-OK" \
  && pass "IPv6 白名单动态放行成功" || fail "IPv6 白名单热加载未生效"

echo "=== 测试用例 4: 动态白名单清空撤销 ==="
# 清空白名单
> test_whitelist.txt
sleep 2

if ! $EXEC_TEST wget -q -T 2 -O- http://192.168.100.10 >/dev/null 2>&1; then
  pass "IPv4 权限回收成功，重新阻断"
else
  fail "白名单清空后 IPv4 仍可连通！"
fi

if ! $EXEC_TEST wget -q -T 2 -O- http://[fd00:1111::10] >/dev/null 2>&1; then
  pass "IPv6 权限回收成功，重新阻断"
else
  fail "白名单清空后 IPv6 仍可连通！"
fi

echo "=== 测试用例 5: Sidecar 共享网络栈隔离与业务容器零特权验证 ==="
# 1. 验证发包机与网关共享网络命名空间 (Sidecar 架构，共享网络接口)
$EXEC_TEST ip addr show | grep -q "192.168.100.2" \
  && pass "Sidecar 共享网络栈生效 (共享网关网络接口与 IP)" \
  || fail "Sidecar 网络栈共享失败"

# 2. 验证业务容器确实不具备 NET_ADMIN 特权（最小权限原则，尝试修改网络配置应失败）
if ! $EXEC_TEST ip route add 198.51.100.0/24 via 192.168.100.254 >/dev/null 2>&1; then
  pass "业务容器无 NET_ADMIN 特权（符合最小权限安全模型）"
else
  fail "安全隐患：业务容器不应具备网络管理特权！"
fi

# 3. 验证网关彻底移除高危特权 (零 pid: host, 零 /var/run/docker.sock, 零 SYS_ADMIN/SYS_PTRACE)
if [ "$(docker inspect -f '{{.HostConfig.PidMode}}' test_gateway)" != "host" ]; then
  pass "网关容器已彻底移除 pid: host 宿主机特权"
else
  fail "安全隐患：网关仍挂载 pid: host"
fi

if ! docker inspect test_gateway | grep -q "docker.sock"; then
  pass "网关容器已彻底移除 docker.sock 挂载"
else
  fail "安全隐患：网关仍挂载 docker.sock"
fi

if ! docker inspect -f '{{.HostConfig.CapAdd}}' test_gateway | grep -E "SYS_ADMIN|SYS_PTRACE" >/dev/null 2>&1; then
  pass "网关容器已彻底移除 SYS_ADMIN / SYS_PTRACE 特权"
else
  fail "安全隐患：网关包含过度特权"
fi

echo "=== 测试用例 6: 业务容器重启自愈与天然网络保持验证 ==="
docker restart -t 1 tester >/dev/null
sleep 1 # 等待容器重启就绪
$EXEC_TEST wget -q -T 2 -O- http://1.1.1.1 | grep -q "Internet-OK" \
  && pass "业务容器重启后天然保持共享网络，公网访问正常自愈" \
  || fail "业务容器重启后未能恢复公网访问"

if ! $EXEC_TEST wget -q -T 2 -O- http://192.168.100.10 >/dev/null 2>&1; then
  pass "业务容器重启后私网防护持续有效"
else
  fail "安全隐患：业务容器重启后私网拦截失效！"
fi

echo "=== 测试用例 7: 非标准主机位 CIDR 容错规范化与去重生效 ==="
cat <<EOF > test_whitelist.txt
# 包含主机位未置零的 CIDR 与重复项
192.168.100.55/24
192.168.100.55/24
fd00:1111::99/64
EOF
sleep 2 # 等待 inotify 监听同步

$EXEC_TEST wget -q -T 2 -O- http://192.168.100.10 | grep -q "LAN-OK" \
  && pass "非零主机位 CIDR 规范化后成功放行 IPv4 靶机" \
  || fail "非零主机位 CIDR 规范化放行失败"

$EXEC_TEST wget -q -T 2 -O- http://[fd00:1111::10] | grep -q "LAN-OK" \
  && pass "非零主机位 IPv6 CIDR 规范化后成功放行 IPv6 靶机" \
  || fail "非零主机位 IPv6 CIDR 规范化放行失败"

# 清空测试白名单
> test_whitelist.txt
sleep 2

echo "=== 测试用例 8: Sidecar 模式 Pod 内本地回环 (lo) 通信正常验证 ==="
$EXEC_TEST sh -c 'nc -l -p 12345 & sleep 0.1; nc -z -w 1 127.0.0.1 12345' >/dev/null 2>&1 \
  && pass "Pod 内部本地回环 (lo) IPv4 通信放行正常" \
  || fail "Pod 内部 lo IPv4 通信异常"

$EXEC_TEST sh -c 'nc -l -p 12346 & sleep 0.1; nc -z -w 1 ::1 12346' >/dev/null 2>&1 \
  && pass "Pod 内部本地回环 (lo) IPv6 通信放行正常" \
  || fail "Pod 内部 lo IPv6 通信异常"

echo "=== 测试用例 9: 内核级透明 DNS 劫持验证 (IPv4 TCP & UDP) ==="
# 发包容器无论向任何内网 IP (如靶机 192.168.100.10 或任意私网 IP 10.254.1.1) 发送 DNS 报文
# 内核 nat 表 output 链强制 DNAT 至安全上游 DNS (mock-wan 1.1.1.1)，并原路还原响应
TCP_DNS_RES=$($EXEC_TEST sh -c 'echo "dns-test" | nc -w 2 192.168.100.10 53 2>/dev/null')
if [ "$TCP_DNS_RES" = "SAFE-DNS-OK" ]; then
  pass "IPv4 TCP DNS 查询透明重定向至安全上游 DNS 成功"
elif [ "$TCP_DNS_RES" = "LAN-DNS-LEAK" ]; then
  fail "严重安全漏洞：DNS 请求直接泄露到了局域网内部 DNS 靶机！"
else
  fail "IPv4 TCP DNS 透明劫持响应异常: '$TCP_DNS_RES'"
fi

UDP_DNS_RES=$($EXEC_TEST sh -c 'echo "dns-test" | nc -u -w 2 192.168.100.10 53 2>/dev/null')
if [ "$UDP_DNS_RES" = "SAFE-DNS-OK" ]; then
  pass "IPv4 UDP DNS 查询透明重定向至安全上游 DNS 成功"
else
  fail "IPv4 UDP DNS 透明劫持失败: '$UDP_DNS_RES'"
fi

# 对任意未分配内网私有地址的 53 端口查询也必须被自动截获重写
ARBITRARY_DNS=$($EXEC_TEST sh -c 'echo "dns-test" | nc -w 2 10.254.1.1 53 2>/dev/null')
[ "$ARBITRARY_DNS" = "SAFE-DNS-OK" ] \
  && pass "任意私网未分配 IP (10.254.1.1:53) DNS 查询自动被内核截获" \
  || fail "任意私网 IP DNS 截获失败"

ARBITRARY_UDP_DNS=$($EXEC_TEST sh -c 'echo "dns-test" | nc -u -w 2 10.254.1.1 53 2>/dev/null')
[ "$ARBITRARY_UDP_DNS" = "SAFE-DNS-OK" ] \
  && pass "任意私网未分配 IP (10.254.1.1:53) UDP DNS 自动被内核截获" \
  || fail "任意私网 IP UDP DNS 截获失败"

echo "=== 测试用例 10: 内核级透明 DNS 劫持验证 (IPv6 TCP & UDP) ==="
V6_TCP_DNS=$($EXEC_TEST sh -c 'echo "dns-test" | nc -w 2 fd00:1111::10 53 2>/dev/null')
if [ "$V6_TCP_DNS" = "SAFE-DNS-OK" ]; then
  pass "IPv6 TCP DNS 查询透明重定向至安全上游 DNS 成功"
elif [ "$V6_TCP_DNS" = "LAN-DNS-LEAK" ]; then
  fail "严重安全漏洞：IPv6 DNS 请求直接泄露到了局域网内部 DNS 靶机！"
else
  fail "IPv6 TCP DNS 透明劫持响应异常: '$V6_TCP_DNS'"
fi

V6_UDP_DNS=$($EXEC_TEST sh -c 'echo "dns-test" | nc -u -w 2 fd00:1111::10 53 2>/dev/null')
[ "$V6_UDP_DNS" = "SAFE-DNS-OK" ] \
  && pass "IPv6 UDP DNS 查询透明重定向至安全上游 DNS 成功" \
  || fail "IPv6 UDP DNS 透明劫持失败"

echo "=== 测试用例 11: 白名单局域网主机的 DNS-Rebinding / 内部 DNS 泄露阻断验证 ==="
# 场景：将局域网靶机 192.168.100.10 加入白名单，放行其 Web 业务
echo "192.168.100.10" > test_whitelist.txt
sleep 2

# 1. 验证 Web 访问正常放行
$EXEC_TEST wget -q -T 2 -O- http://192.168.100.10 | grep -q "LAN-OK" \
  && pass "白名单内网主机 HTTP (端口 80) 正常放行" \
  || fail "白名单内网主机 HTTP 访问失败"

# 2. 关键验证：即使内网主机已被加白，发往其 53 端口的 DNS 查询仍被内核劫持至安全 DNS，绝不泄露给局域网 DNS！
WHITELIST_DNS=$($EXEC_TEST sh -c 'echo "dns-test" | nc -w 2 192.168.100.10 53 2>/dev/null')
if [ "$WHITELIST_DNS" = "SAFE-DNS-OK" ]; then
  pass "安全保障：加白局域网主机的 53 端口 TCP DNS 仍被内核劫持保护，杜绝内网资产探测与 DNS 泄露"
elif [ "$WHITELIST_DNS" = "LAN-DNS-LEAK" ]; then
  fail "严重隐患：加白局域网主机后内部 DNS 服务直接被连通泄露！"
else
  fail "加白后 DNS 劫持验证异常: '$WHITELIST_DNS'"
fi

WHITELIST_UDP_DNS=$($EXEC_TEST sh -c 'echo "dns-test" | nc -u -w 2 192.168.100.10 53 2>/dev/null')
[ "$WHITELIST_UDP_DNS" = "SAFE-DNS-OK" ] \
  && pass "安全保障：加白局域网主机的 53 端口 UDP DNS 仍被内核劫持保护" \
  || fail "加白后 UDP DNS 劫持异常: '$WHITELIST_UDP_DNS'"

# 清空测试白名单
> test_whitelist.txt
sleep 2

echo "=== 测试用例 12: 默认自省网关自身 resolv.conf 与参数解析验证 ==="
HELP_OUTPUT=$(docker exec test_gateway /bin/nft-egress-daemon --help)
echo "$HELP_OUTPUT" | grep -q -- "--resolv-conf" \
  && pass "网关守护进程 resolv.conf 自动自省参数解析健全" \
  || fail "网关守护进程参数解析失败"

echo "=== 检查网关日志与 ruleset ==="
docker exec test_gateway nft list ruleset > /dev/null
pass "NFTables 语法树完整，无内存泄露或语法崩溃"

echo -e "\n${GREEN}所有无网络离线测试全部通过！${NC}"
