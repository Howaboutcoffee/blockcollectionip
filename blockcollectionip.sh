#!/usr/bin/env bash
# ===========================================================
# IP采集与屏蔽管理脚本 (tcpdump 版 - 捕获所有 TCP 连接尝试)
# ===========================================================

LOGFILE="/var/log/tcpping_ips.log"
NFT_CONF="/etc/nftables.conf"
PORT=12345
SAVE_INTERVAL=10

# ------------------- 环境准备：切换为纯 nftables -------------------
prepare_nft_env() {
    echo "[CHECK] 检查系统 nftables 环境..."

    # 检查 nftables 是否存在
    if ! command -v nft >/dev/null 2>&1; then
        echo "[INSTALL] 未检测到 nftables，正在安装..."
        apt update -y >/dev/null 2>&1
        apt install -y nftables >/dev/null 2>&1
    fi

    # 检查 tcpdump 是否存在
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "[INSTALL] 未检测到 tcpdump，正在安装..."
        apt install -y tcpdump >/dev/null 2>&1
    fi

    # 检查是否已在纯 nftables 模式
    if update-alternatives --query iptables 2>/dev/null | grep -q "iptables-nft"; then
        echo "[FIX] 检测到系统使用 iptables-nft (兼容层)，正在切换为纯 nftables..."
        update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null 2>&1 || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy >/dev/null 2>&1 || true
        apt remove -y iptables-nft >/dev/null 2>&1 || true
        echo "[OK] 已切换为纯 nftables 模式。"
    else
        echo "[OK] 系统已在纯 nftables 模式。"
    fi

    # 确保服务启动
    systemctl enable --now nftables >/dev/null 2>&1
}

# ------------------- 初始化 nftables（仅首次） -------------------
init_nft() {
    prepare_nft_env

    # 如果 table 不存在则创建
    if ! nft list tables 2>/dev/null | grep -q "inet filter"; then
        echo "[INIT] 创建 nftables 基础结构..."
        cat >"$NFT_CONF" <<'EOF'
#!/usr/sbin/nft -f
# nftables initialized by ip-block script
table inet filter {
    chain input {
        type filter hook input priority 0;
        policy accept;
    }
}
EOF
        systemctl restart nftables
        echo "[OK] 已初始化 nftables 配置。"
    else
        echo "[OK] nftables 已存在，无需初始化。"
    fi
}

# ------------------- 实时采集服务（tcpdump 版本） -------------------
start_collector_foreground() {
    init_nft
    
    # 禁用任务控制消息，让输出更干净
    set +m
    
    echo "========================================"
    echo " [实时 IP 采集服务 - tcpdump 增强版]"
    echo "========================================"
    echo "[INFO] 监听端口: TCP $PORT"
    echo "[INFO] 日志文件: $LOGFILE"
    echo "[INFO] 捕获模式: 所有 TCP 连接尝试（包括 SYN 扫描）"
    echo "----------------------------------------"
    echo "按 Ctrl+C 停止采集。"
    echo "========================================"
    echo

    # 使用 awk 处理统计（更稳定）
    if [ -f "$LOGFILE" ]; then
        OLD_COUNT=$(wc -l < "$LOGFILE")
        echo "[INFO] 已加载 $OLD_COUNT 条旧 IP 记录。"
        echo
    fi

    # 临时文件用于进程间通信
    TMPLOG="/tmp/tcpdump_collector_$$.log"
    : > "$TMPLOG"

    # 捕获信号以保存数据并返回菜单
    STOP_FLAG=0
    trap 'STOP_FLAG=1' INT TERM

    cleanup_and_return() {
        # 重定向后续所有输出到 /dev/null（包括 stderr）
        exec 3>&1 4>&2  # 备份标准输出和错误输出
        exec 2>/dev/null  # 重定向 stderr 到 /dev/null
        
        echo
        echo "========================================"
        echo "[STOP] 正在停止采集并保存数据..."
        
        # 强制停止所有子进程
        kill -9 $LISTEN_PID 2>/dev/null
        kill -9 $TCPDUMP_PID 2>/dev/null
        pkill -9 -P $$ 2>/dev/null
        pkill -9 tcpdump 2>/dev/null
        
        # 等待进程完全终止
        sleep 0.5
        
        # 清理临时文件
        rm -f "$TMPLOG"
        
        # 恢复输出
        exec 1>&3 2>&4
        exec 3>&- 4>&-
        
        # 统计最终结果
        if [ -f "$LOGFILE" ]; then
            total_ips=$(wc -l < "$LOGFILE")
            echo "[EXIT] 已保存 $total_ips 条最终记录。"
        fi
        echo "========================================"
    }

    # 启动 Python TCP 监听服务（让 tcping 显示端口开放）
    echo "[INFO] 启动 TCP 监听服务..."
    python3 -c "
import socket, threading
def listen():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', $PORT))
    s.listen(100)
    while True:
        try:
            conn, addr = s.accept()
            conn.close()
        except:
            break
threading.Thread(target=listen, daemon=True).start()
import time
time.sleep(999999)
" >/dev/null 2>&1 &
    LISTEN_PID=$!
    disown $LISTEN_PID  # 脱离任务控制
    sleep 1  # 等待监听启动
    
    # 启动 tcpdump 捕获 SYN 包（后台）
    tcpdump -i any -n -l "tcp dst port $PORT and tcp[tcpflags] & tcp-syn != 0" 2>/dev/null | \
    while read -r line; do
        # 提取源 IP (格式: IP.port > IP.port)
        src_ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+(?=\.\d+ >)' | head -1)
        
        if [ -n "$src_ip" ]; then
            echo "$src_ip" >> "$TMPLOG"
        fi
    done &

    TCPDUMP_PID=$!
    disown $TCPDUMP_PID  # 脱离任务控制
    
    # 主循环：读取并统计
    counter=0
    heartbeat=0
    echo "[INFO] 监听已启动，等待连接... (每30秒显示一次心跳)"
    echo
    
    while [ $STOP_FLAG -eq 0 ]; do
        # 心跳提示（每30秒）
        heartbeat=$((heartbeat + 1))
        if [ $((heartbeat % 60)) -eq 0 ]; then
            echo "[心跳] 监听正常运行中... (已运行 $((heartbeat / 2)) 秒)"
        fi
        
        if [ -s "$TMPLOG" ]; then
            # 每次最多处理 100 条记录，然后检查停止标志
            processed=0
            while read -r ip && [ $processed -lt 100 ] && [ $STOP_FLAG -eq 0 ]; do
                [ -z "$ip" ] && continue
                processed=$((processed + 1))
                
                ts=$(date "+%Y-%m-%d %H:%M:%S")
                
                # 检查 IP 是否已存在
                if grep -q "^.* $ip " "$LOGFILE" 2>/dev/null; then
                    # 已存在，更新计数
                    old_count=$(grep "^.* $ip " "$LOGFILE" | tail -1 | awk '{print $4}')
                    [ -z "$old_count" ] && old_count=0
                    new_count=$((old_count + 1))
                    
                    # 删除旧记录，添加新记录
                    sed -i "/^.* $ip /d" "$LOGFILE"
                    echo "$ts $ip $new_count" >> "$LOGFILE"
                    
                    echo "[HIT] $ts - $ip (第 $new_count 次)"
                else
                    # 新 IP
                    echo "$ts $ip 1" >> "$LOGFILE"
                    echo "[NEW-IP] $ts - 新发现 $ip"
                fi
                
                counter=$((counter + 1))
                
                # 定期显示统计
                if [ $((counter % SAVE_INTERVAL)) -eq 0 ]; then
                    total_ips=$(wc -l < "$LOGFILE")
                    echo "[SAVE] 当前记录: $total_ips 个唯一 IP (总计 $counter 次连接)。"
                fi
                
            done < "$TMPLOG"
            
            # 清空临时日志
            : > "$TMPLOG"
        fi
        
        # 确保每次循环都能检查停止标志
        sleep 0.1
    done
    
    # 执行清理
    cleanup_and_return
    
    # 重置 trap
    trap - INT TERM
}

# ------------------- 屏蔽日志中 IP -------------------
block_ips() {
    init_nft
    if [ ! -f "$LOGFILE" ]; then
        echo "[ERROR] 未找到日志文件 $LOGFILE"
        echo "[INFO] 请先运行选项 1 进行 IP 采集。"
        return
    fi
    
    TMPFILE="/tmp/block_ips.txt"
    awk '{print $3}' "$LOGFILE" | sort -u > "$TMPFILE"
    COUNT=$(wc -l < "$TMPFILE")
    
    if [ "$COUNT" -eq 0 ]; then
        echo "[INFO] 日志中没有 IP 记录，无需屏蔽。"
        return
    fi
    
    echo "========================================"
    echo " [批量屏蔽 IP]"
    echo "========================================"
    echo "[INFO] 找到 $COUNT 个唯一 IP，将添加 DROP 规则..."
    echo

    blocked=0
    skipped=0
    
    while read -r ip; do
        [ -z "$ip" ] && continue
        
        # 检查是否已存在规则
        if nft list chain inet filter input 2>/dev/null | grep -q "ip saddr $ip drop"; then
            echo "[SKIP] $ip (已存在规则)"
            skipped=$((skipped + 1))
        else
            nft add rule inet filter input ip saddr "$ip" drop 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "[BLOCK] 已屏蔽 $ip"
                blocked=$((blocked + 1))
            else
                echo "[ERROR] 屏蔽失败 $ip"
            fi
        fi
    done < "$TMPFILE"

    echo
    echo "========================================"
    echo "[INFO] 屏蔽统计："
    echo "  - 新增屏蔽: $blocked"
    echo "  - 已存在跳过: $skipped"
    echo "  - 总计: $COUNT"
    echo "========================================"
    echo
    echo "[SAVE] 保存配置到 $NFT_CONF ..."
    nft list ruleset > "$NFT_CONF"
    systemctl restart nftables
    echo "[OK] 屏蔽完成并持久化保存。"
    
    rm -f "$TMPFILE"
}

# ------------------- 清空规则 -------------------
clear_blocks() {
    echo "========================================"
    echo " [清空屏蔽规则]"
    echo "========================================"
    
    # 统计当前规则数
    current_count=$(nft list chain inet filter input 2>/dev/null | grep -c drop)
    
    if [ "$current_count" -eq 0 ]; then
        echo "[INFO] 当前没有任何屏蔽规则。"
        return
    fi
    
    echo "[WARN] 当前共有 $current_count 条 DROP 规则"
    echo -n "[WARN] 确定要清空所有屏蔽规则？(y/n): "
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
    echo "========================================"
    echo " [当前屏蔽 IP 列表]"
    echo "========================================"
    
    blocked_ips=$(nft list chain inet filter input 2>/dev/null | grep "ip saddr" | grep "drop" | awk '{print $3}')
    
    if [ -z "$blocked_ips" ]; then
        echo "[INFO] 当前没有屏蔽任何 IP。"
    else
        echo "$blocked_ips" | nl
    fi
    
    echo "========================================"
    total=$(echo "$blocked_ips" | grep -c .)
    echo "[INFO] 已屏蔽 IP 总数: $total"
    echo "========================================"
}

# ------------------- 查看日志统计 -------------------
show_log_stats() {
    if [ ! -f "$LOGFILE" ]; then
        echo "[INFO] 暂无日志记录。"
        return
    fi
    
    echo "========================================"
    echo " [IP 采集日志统计]"
    echo "========================================"
    
    total_ips=$(wc -l < "$LOGFILE")
    total_hits=$(awk '{sum+=$4} END {print sum}' "$LOGFILE")
    
    echo "[INFO] 记录总数: $total_ips 个唯一 IP"
    echo "[INFO] 连接总数: $total_hits 次"
    echo
    echo "[TOP 10] 连接次数最多的 IP："
    echo "----------------------------------------"
    
    sort -k4 -rn "$LOGFILE" | head -10 | while read -r line; do
        ts=$(echo "$line" | awk '{print $1, $2}')
        ip=$(echo "$line" | awk '{print $3}')
        count=$(echo "$line" | awk '{print $4}')
        printf "%-15s | %5s 次 | 最后: %s\n" "$ip" "$count" "$ts"
    done
    
    echo "========================================"
}

# ------------------- 菜单 -------------------
show_menu() {
    clear
    echo "========================================"
    echo " IP采集与屏蔽管理脚本"
    echo " [tcpdump 增强版 - 零漏检]"
    echo "========================================"
    echo " 1) 实时采集 IP (前台显示)"
    echo " 2) 屏蔽日志中记录的 IP"
    echo " 3) 清空所有屏蔽规则"
    echo " 4) 查看当前屏蔽 IP 列表"
    echo " 5) 查看日志统计信息"
    echo " 6) 退出"
    echo "========================================"
    echo -n "请输入选项 [1-6]: "
}

# ------------------- 主循环 -------------------
while true; do
    show_menu
    # 清空输入缓冲区
    read -t 0.01 -n 10000 discard 2>/dev/null || true
    read -r choice
    case "$choice" in
        1) start_collector_foreground ;;
        2) block_ips ;;
        3) clear_blocks ;;
        4) show_blocked ;;
        5) show_log_stats ;;
        6) echo "[EXIT] 再见！"; exit 0 ;;
        *) echo "[ERROR] 无效选项，请重试。" ;;
    esac
    echo
    echo -n "按任意键返回菜单..."
    # 先清空缓冲，再等待按键
    read -t 0.01 -n 10000 discard 2>/dev/null || true
    read -n 1 -s -r
    echo
done
