#!/usr/bin/env bash
set -euo pipefail

# ===== 通用配置 =====
LOGFILE="/var/log/tcpping_ips.log"   # IP 日志文件
PORT=12345                           # 采集时监听的目标端口

# nftables 黑名单表配置（只在“屏蔽”时使用）
FAMILY="inet"
TABLE="ipblock"
CHAIN="input"
SET="ip_blacklist"
PRIORITY="-100"   # input 链优先级（数字越小越早执行）

# ===== 帮助信息 =====
usage() {
    cat <<EOF
用法: $0 [命令]

不带命令直接执行：进入菜单模式

可用命令:
  collect   持续采集 IP（Ctrl+C 停止，实时写入 $LOGFILE）
  apply     从 $LOGFILE 读取 IP，刷新 nft 黑名单并生效
  clear     清空黑名单集合（取消所有屏蔽）
  status    查看当前黑名单与规则状态
  disable   删除整个 $FAMILY $TABLE 表（相当于彻底停用本方案）
  help      显示本帮助

示例:
  $0 collect
  $0 apply
  $0 clear
  $0 status
  $0 disable
EOF
}

ensure_root_hint() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[WARN] 建议使用 root/sudo 运行（tcpdump 和 nft 通常需要）。" >&2
    fi
}

ensure_nft() {
    if ! command -v nft >/dev/null 2>&1; then
        echo "错误：未找到 nft 命令，请先安装 nftables (apt install -y nftables)。" >&2
        exit 1
    fi
}

# ====== 1) 持续采集 IP（Ctrl+C 停止） ======
cmd_collect() {
    ensure_root_hint

    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "错误：未找到 tcpdump，请先安装：apt install -y tcpdump" >&2
        exit 1
    fi

    echo "========================================"
    echo " [IP 采集（无限时，Ctrl+C 结束）]"
    echo "========================================"
    echo "[INFO] 监听端口: TCP $PORT"
    echo "[INFO] 输出日志: $LOGFILE"
    echo "----------------------------------------"
    echo "说明："
    echo "  - 持续抓取发往该端口的 TCP SYN 包；"
    echo "  - 每发现一个【新 IP】就立即打印并写入日志；"
    echo "  - 同一个 IP 只会打印/记录一次；"
    echo "  - 你可以随时按 Ctrl+C 结束本次采集。"
    echo "========================================"
    echo

    # -------- 启动临时 TCP 监听，方便 tcping 测试 --------
    LISTEN_PID=""
    if command -v python3 >/dev/null 2>&1; then
        echo "[INFO] 启动临时监听服务，采集期间端口 $PORT 将保持开放..."
        python3 - <<PY >/dev/null 2>&1 &
import socket

PORT = $PORT
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", PORT))
s.listen(100)
s.settimeout(1.0)

try:
    while True:
        try:
            conn, addr = s.accept()
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            break
finally:
    s.close()
PY
        LISTEN_PID=$!
    else
        echo "[WARN] 系统未安装 python3，无法自动开启临时监听。"
        echo "       你仍然可以采集 IP，但 tcping 到端口会显示不通。"
    fi

    # -------- 定义 Ctrl+C 时的清理动作（返回菜单，不退出脚本） --------
    STOPPED=0
    cleanup_collect() {
        if [ "$STOPPED" -eq 1 ]; then
            return
        fi
        STOPPED=1

        echo
        echo "[STOP] 收到中断信号，正在停止采集..."

        if [ -n "${LISTEN_PID:-}" ]; then
            kill "$LISTEN_PID" 2>/dev/null || true
        fi

        echo "[STOP] 采集已停止。已写入的 IP 都保存在日志中：$LOGFILE"

        # 取消 trap，避免后续误触发
        trap - INT TERM

        # 直接从函数返回（菜单模式下会回到菜单）
        return
    }
    trap cleanup_collect INT TERM

    # -------- 开始采集：实时输出 + 实时写日志 --------
    touch "$LOGFILE"

    echo "[INFO] 开始采集，按 Ctrl+C 随时停止。"
    echo

    # bash 关联数组做去重
    declare -A seen=()

    # 用 process substitution 把 tcpdump 输出喂给 while，不会丢环境变量/数组
    while IFS= read -r line; do
        src_ip=""

        # 从这一行里找第一个形如 a.b.c.d.e 的字段（IP+端口）
        for tok in $line; do
            # 只用最基础的 ERE：^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$
            if echo "$tok" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                # 去掉最后一个 .端口，得到纯 IP
                src_ip="${tok%.*}"
                break
            fi
        done

        [ -z "$src_ip" ] && continue

        if [[ -z "${seen[$src_ip]:-}" ]]; then
            seen["$src_ip"]=1
            ts=$(date '+%Y-%m-%d %H:%M:%S')
            printf "[NEW-IP] %s - %s\n" "$ts" "$src_ip"
            echo "$ts $src_ip 1" >> "$LOGFILE"
        fi
    done < <(
        tcpdump -i any -n -l \
            "tcp dst port $PORT and tcp[tcpflags] & tcp-syn != 0" \
            2>/dev/null
    )

    # 如果是 tcpdump 自然结束（不是 Ctrl+C），会走到这里
    trap - INT TERM
    if [ -n "${LISTEN_PID:-}" ]; then
        kill "$LISTEN_PID" 2>/dev/null || true
    fi
    echo "[INFO] 采集结束。日志保存在: $LOGFILE"
}

# ====== 2) 初始化 nft 结构（只用于黑名单） ======
init_nft_struct() {
    ensure_nft
    ensure_root_hint

    # 表
    if ! nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1; then
        echo "[INIT] 创建表 $FAMILY $TABLE ..."
        nft add table "$FAMILY" "$TABLE"
    fi

    # 集合：黑名单
    if ! nft list set "$FAMILY" "$TABLE" "$SET" >/dev/null 2>&1; then
        echo "[INIT] 创建集合 $FAMILY $TABLE $SET ..."
        nft add set "$FAMILY" "$TABLE" "$SET" '{ type ipv4_addr; flags interval; }'
    fi

    # 链：挂在 input hook
    if ! nft list chain "$FAMILY" "$TABLE" "$CHAIN" >/dev/null 2>&1; then
        echo "[INIT] 创建链 $FAMILY $TABLE $CHAIN ..."
        nft add chain "$FAMILY" "$TABLE" "$CHAIN" "{ type filter hook input priority $PRIORITY; policy accept; }"
    fi

    # 黑名单规则
    if ! nft list chain "$FAMILY" "$TABLE" "$CHAIN" | grep -q "@$SET"; then
        echo "[INIT] 添加规则: ip saddr @$SET drop"
        nft add rule "$FAMILY" "$TABLE" "$CHAIN" ip saddr @"$SET" drop
    fi
}

# ====== 3) 从日志应用黑名单 ======
cmd_apply() {
    if [ ! -f "$LOGFILE" ]; then
        echo "错误：找不到日志文件 $LOGFILE，先运行 collect 采集。" >&2
        exit 1
    fi

    init_nft_struct

    TMP_IPS=$(mktemp)
    TMP_NFT=$(mktemp)
    trap 'rm -f "$TMP_IPS" "$TMP_NFT"' EXIT

    # 第3个字段是 IP，提取并去重（只用 grep -E，不用 -P）
    awk '{print $3}' "$LOGFILE" \
      | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
      | sort -u > "$TMP_IPS"

    COUNT=$(grep -c . "$TMP_IPS" || true)
    echo "[INFO] 在日志中找到 $COUNT 个唯一 IP，将写入黑名单集合。"

    {
        echo "flush set $FAMILY $TABLE $SET"
        while read -r ip; do
            [ -z "$ip" ] && continue
            echo "add element $FAMILY $TABLE $SET { $ip }"
        done < "$TMP_IPS"
    } > "$TMP_NFT"

    nft -f "$TMP_NFT"

    echo "[OK] 黑名单已刷新，当前 IP 数量：$COUNT"
}

# ====== 4) 清空黑名单集合 ======
cmd_clear() {
    ensure_nft
    if nft list set "$FAMILY" "$TABLE" "$SET" >/dev/null 2>&1; then
        nft flush set "$FAMILY" "$TABLE" "$SET"
        echo "[OK] 已清空集合 $FAMILY $TABLE $SET（不再屏蔽任何 IP）。"
    else
        echo "[INFO] 集合 $FAMILY $TABLE $SET 不存在，无需清空。"
    fi
}

# ====== 5) 查看状态 ======
cmd_status() {
    ensure_nft
    echo "===== 表状态: $FAMILY $TABLE ====="
    if nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1; then
        nft list table "$FAMILY" "$TABLE"
    else
        echo "[INFO] 表不存在（当前没有启用本黑名单方案）。"
    fi

    echo
    echo "===== 黑名单 IP 数量 ====="
    if nft list set "$FAMILY" "$TABLE" "$SET" >/dev/null 2>&1; then
        COUNT=$(nft list set "$FAMILY" "$TABLE" "$SET" \
            | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | wc -l || true)
        echo "[INFO] 集合 $SET 中 IP 数量：$COUNT"
    else
        echo "[INFO] 集合 $SET 不存在。"
    fi
}

# ====== 6) 完全停用（删除整张表） ======
cmd_disable() {
    ensure_nft
    if nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1; then
        nft delete table "$FAMILY" "$TABLE"
        echo "[OK] 已删除表 $FAMILY $TABLE —— 等于彻底停用本黑名单方案。"
    else
        echo "[INFO] 表 $FAMILY $TABLE 不存在，无需删除。"
    fi
}

# ====== 菜单模式 ======
menu() {
    while true; do
        clear
        echo "========================================"
        echo " IP 采集 + 屏蔽 管理脚本 (安全精简版)"
        echo " 日志文件: $LOGFILE"
        echo "========================================"
        echo " 1) 持续采集 IP (collect)"
        echo " 2) 应用黑名单      (apply)"
        echo " 3) 清空黑名单      (clear)"
        echo " 4) 查看状态        (status)"
        echo " 5) 停用整套方案    (disable)"
        echo " 6) 退出"
        echo "========================================"
        read -rp "请选择 [1-6]: " ans

        case "$ans" in
            1) cmd_collect ;;
            2) cmd_apply ;;
            3) cmd_clear ;;
            4) cmd_status ;;
            5) cmd_disable ;;
            6) echo "再见~"; break ;;
            *) echo "无效选项，请重试。";;
        esac

        echo
        read -rp "按回车键返回菜单..." _dummy
    done
}

# ====== 主入口 ======
CMD="${1:-}"

case "$CMD" in
    "")       menu ;;
    collect)  cmd_collect; exit $? ;;  # 直接 ./test.sh collect 时，采完就退出
    apply)    cmd_apply ;;
    clear)    cmd_clear ;;
    status)   cmd_status ;;
    disable)  cmd_disable ;;
    help|-h|--help) usage ;;
    *)
        echo "未知命令：$CMD" >&2
        usage
        exit 1
        ;;
esac
