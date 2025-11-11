#!/usr/bin/env bash
# ===========================================================
# IP采集与屏蔽管理脚本 (Debian12 纯 nftables 持久化版)
# ===========================================================

LOGFILE="/var/log/tcpping_ips.log"
NFT_CONF="/etc/nftables.conf"
PORT=12345
SAVE_INTERVAL=10

# ------------------- 环境准备：切换为纯 nftables -------------------
prepare_nft_env() {
    echo "[CHECK] 检查系统 nftables 环境..."

    # 检测是否在使用 iptables-nft
    if update-alternatives --query iptables 2>/dev/null | grep -q "iptables-nft"; then
        echo "[FIX] 检测到系统使用 iptables-nft (兼容层)，正在切换到纯 nftables..."

        update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null 2>&1 || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy >/dev/null 2>&1 || true

        apt remove -y iptables-nft >/dev/null 2>&1 || true

        echo "[CLEAN] 清空旧 iptables/nftables 规则..."
        nft flush ruleset || true

        echo "[ENABLE] 启用并启动 nftables 服务..."
        apt install -y nftables >/dev/null 2>&1
        systemctl enable --now nftables >/dev/null 2>&1

        echo "[OK] 系统已切换为纯 nftables 模式。"
        echo
    else
        echo "[OK] 系统已在纯 nftables 模式，无需调整。"
    fi
}

# ------------------- 初始化 nftables -------------------
init_nft() {
    prepare_nft_env

    if ! systemctl is-active --quiet nftables; then
        echo "[INIT] 启动 nftables 服务..."
        systemctl enable --now nftables >/dev/null 2>&1
    fi

    if ! nft list tables 2>/dev/null | grep -q "inet filter"; then
        echo "[INIT] 创建 nftables 基础结构..."
        cat >"$NFT_CONF" <<'EOF'
#!/usr/sbin/nft -f
table inet filter {
    chain input {
        type filter hook input priority 0;
        policy accept;
    }
}
EOF
        systemctl restart nftables
        echo "[OK] 已初始化 nftables 配置。"
    fi
}

# ------------------- 实时采集服务 -------------------
start_collector_foreground() {
    init_nft
    echo "[INFO] 启动实时 IP 采集服务 (TCP $PORT)"
    echo "[INFO] 日志文件: $LOGFILE"
    echo "按 Ctrl+C 停止采集。"
    echo "----------------------------------------"

    python3 - <<PYCODE
import socket, time, os

PORT = $PORT
LOGFILE = "$LOGFILE"
SAVE_INTERVAL = $SAVE_INTERVAL

os.makedirs(os.path.dirname(LOGFILE), exist_ok=True)
ip_stats = {}

if os.path.exists(LOGFILE):
    with open(LOGFILE) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 3:
                ts = f"{parts[0]} {parts[1]}"
                ip = parts[2]
                count = int(parts[3]) if len(parts) >= 4 else 1
                ip_stats[ip] = {"time": ts, "count": count}

print(f"[INFO] 已加载 {len(ip_stats)} 条旧 IP 记录。")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", PORT))
s.listen(5)
print(f"[INFO] 正在监听 TCP {PORT}，等待连接...\n")

counter = 0
try:
    while True:
        conn, addr = s.accept()
        ip = addr[0]
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        if ip in ip_stats:
            ip_stats[ip]["count"] += 1
            ip_stats[ip]["time"] = ts
            print(f"[HIT] {ts} - {ip} (第 {ip_stats[ip]['count']} 次)")
        else:
            ip_stats[ip] = {"time": ts, "count": 1}
            print(f"[NEW-IP] {ts} - 新发现 {ip}")

        counter += 1
        if counter % SAVE_INTERVAL == 0:
            with open(LOGFILE, "w") as f:
                for ip, info in sorted(ip_stats.items()):
                    f.write(f"{info['time']} {ip} {info['count']}\n")
            print(f"[SAVE] 已保存 {len(ip_stats)} 条记录。")

        try:
            conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        conn.close()

except KeyboardInterrupt:
    print("\n[STOP] 已停止采集。")
    with open(LOGFILE, "w") as f:
        for ip, info in sorted(ip_stats.items()):
            f.write(f"{info['time']} {ip} {info['count']}\n")
    print(f"[EXIT] 已保存 {len(ip_stats)} 条最终记录。")
PYCODE
}

# ------------------- 屏蔽日志中 IP -------------------
block_ips() {
    init_nft
    if [ ! -f "$LOGFILE" ]; then
        echo "[ERROR] 未找到日志文件 $LOGFILE"
        return
    fi
    TMPFILE="/tmp/block_ips.txt"
    awk '{print $3}' "$LOGFILE" | sort -u > "$TMPFILE"
    COUNT=$(wc -l < "$TMPFILE")
    echo "[INFO] 找到 $COUNT 个唯一 IP，将添加 DROP 规则..."

    while read -r ip; do
        [ -z "$ip" ] && continue
        nft add rule inet filter input ip saddr $ip drop 2>/dev/null
        echo "[BLOCK] 已屏蔽 $ip"
    done < "$TMPFILE"

    echo "[SAVE] 保存配置到 $NFT_CONF ..."
    nft list ruleset > "$NFT_CONF"
    systemctl restart nftables
    echo "[OK] 屏蔽完成并持久化保存。"
}

# ------------------- 清空规则 -------------------
clear_blocks() {
    init_nft
    echo "[WARN] 确定要清空所有 DROP 规则？(y/n)"
    read -r ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        nft flush chain inet filter input
        nft list ruleset > "$NFT_CONF"
        systemctl restart nftables
        echo "[OK] 所有屏蔽规则已清空并保存。"
    else
        echo "[CANCEL] 已取消操作。"
    fi
}

# ------------------- 查看当前屏蔽列表 -------------------
show_blocked() {
    init_nft
    echo "[INFO] 当前屏蔽 IP 列表："
    nft list chain inet filter input | grep drop || echo "(无屏蔽规则)"
    echo "----------------------------------------"
    echo "[INFO] 已屏蔽 IP 总数: $(nft list chain inet filter input | grep -c drop)"
}

# ------------------- 菜单 -------------------
show_menu() {
    clear
    echo "=============================="
    echo " [IP采集与屏蔽管理脚本 - Debian12 纯 nftables版]"
    echo "=============================="
    echo " 1) 实时采集 IP (前台显示)"
    echo " 2) 屏蔽日志中记录的 IP"
    echo " 3) 清空所有屏蔽规则"
    echo " 4) 查看当前屏蔽 IP 列表"
    echo " 5) 退出"
    echo "=============================="
    echo -n "请输入选项 [1-5]: "
}

# ------------------- 主循环 -------------------
while true; do
    show_menu
    read -r choice
    case "$choice" in
        1) start_collector_foreground ;;
        2) block_ips ;;
        3) clear_blocks ;;
        4) show_blocked ;;
        5) echo "[EXIT] 再见！"; exit 0 ;;
        *) echo "[ERROR] 无效选项，请重试。" ;;
    esac
    echo
    read -n 1 -s -r -p "按任意键返回菜单..."
    echo
done
