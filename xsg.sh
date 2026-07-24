#!/bin/bash
# xsg.sh — X Server Guard — 通用 Linux VPS 前置安全部署
# 单文件、零依赖、bash only
#
# 用法:
#   scp xsg.sh root@<VPS_IP>:/tmp/
#   ssh root@<VPS_IP> bash /tmp/xsg.sh
#
# Phase 0: OS/网络检测
# Phase 1: 运维用户 + SSH 密钥 + sudo + GitHub 密钥
# Phase 2: 安全基线（UFW + SSH硬化 + Fail2ban + 禁服务 + 安全挂载 + core dump + 内核模块）
# Phase 3: 纵深防御（密码策略 + auditd + SUID + hidepid + rkhunter + cron限制）
# Phase 4: 系统优化（BBR + sysctl + limits + swap + DNS chattr）
# Phase 5: 运维设施（logrotate + AIDE + unattended-upgrades）

set -euo pipefail

# ══════════════════════════════════════
# 颜色 & 工具函数
# ══════════════════════════════════════
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[*]${NC} $*"; }
die()  { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }
step_ok() { echo -e "  ${GREEN}✓${NC} $1"; }
step_fail() { echo -e "  ${RED}✗${NC} $1"; }
section() { echo ""; echo -e "  ${CYAN}═══ $1 ═══${NC}"; echo ""; }

# 配置备份（修改系统文件前调用）
bak() {
    local f="$1"
    if [[ -f "$f" ]]; then
        cp "$f" "$f.bak.$(date +%s)" 2>/dev/null || true
    fi
}

# 还原配置（失败时调用）
restore_bak() {
    local f="$1"
    local latest
    # shellcheck disable=SC2012
    latest=$(ls -t "$f.bak."* 2>/dev/null | head -1)
    if [[ -n "$latest" ]]; then
        cp "$latest" "$f" && return 0
    fi
    return 1
}

[[ "$(id -u)" -eq 0 ]] || die "需要 root 权限"

# ══════════════════════════════════════
# Phase 0: OS / 网络检测
# ══════════════════════════════════════
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     XSG — X Server Guard                 ║"
echo "  ║     Linux VPS 前置安全部署                ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

if [[ ! -f /etc/os-release ]]; then
    die "无法检测操作系统（缺少 /etc/os-release）"
fi
# shellcheck source=/dev/null
source /etc/os-release
case "$ID" in
    debian|ubuntu) log "检测到 $PRETTY_NAME ✓" ;;
    *) die "不支持的操作系统: $PRETTY_NAME。仅支持 Debian/Ubuntu。" ;;
esac

NET_OK=true
for host in github.com archive.ubuntu.com; do
    if curl -s --connect-timeout 5 --max-time 10 "https://$host" > /dev/null 2>&1; then
        echo "  网络连通: $host ✓"
    else
        warn "无法连接 $host"
        NET_OK=false
    fi
done
if ! $NET_OK; then
    echo -n "  继续? [y/N]: "
    read -r yn
    [[ "$yn" =~ ^[Yy] ]] || die "已取消"
fi

# ══════════════════════════════════════
# Phase 1: 运维用户 + 密钥部署
# ══════════════════════════════════════

# ── 用户名校验 ──
RESERVED_NAMES="root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|_apt|systemd|messagebus|sshd"
validate_username() {
    local name="$1"
    [[ ${#name} -ge 2 && ${#name} -le 32 ]] || { echo "用户名长度必须为 2-32 个字符"; return 1; }
    [[ "$name" =~ ^[a-z][a-z0-9_-]+$ ]] || { echo "用户名必须以小写字母开头，只能包含小写字母、数字、- 或 _"; return 1; }
    [[ "$name" =~ ^($RESERVED_NAMES)$ ]] && { echo "'$name' 是系统保留用户名"; return 1; }
    return 0
}

# ── 密码校验（≥12位 or 4词passphrase）──
validate_password() {
    local pass="$1"
    if [[ "$pass" =~ [[:space:]] ]]; then
        local words
        read -ra words <<< "$pass"
        [[ ${#words[@]} -ge 4 ]] || { echo "passphrase 需要至少 4 个词（空格分隔）"; return 1; }
        return 0
    fi
    [[ ${#pass} -ge 12 ]] || { echo "密码长度不能少于 12 个字符（或使用 4 词 passphrase）"; return 1; }
    [[ "$pass" =~ ^[a-zA-Z]+$ ]] || [[ "$pass" =~ ^[0-9]+$ ]] && { echo "密码不能是纯字母或纯数字"; return 1; }
    return 0
}

# ── 密钥部署通用入口 ──
# 用法: deploy_key <类型: ssh|github> <目标文件路径>
deploy_key() {
    local type="$1"   # "ssh" or "github"
    local dest="$2"
    local key_type label prompt_text

    if [[ "$type" == "ssh" ]]; then
        key_type="公钥"
        label="SSH 管理员密钥"
        prompt_text="粘贴 SSH 公钥（ssh-ed25519/rsa/ecdsa 开头，空行结束）"
    else
        key_type="私钥"
        label="GitHub Deploy Key"
        prompt_text="粘贴 GitHub 私钥（-----BEGIN OPENSSH PRIVATE KEY----- 开头，空行结束）"
    fi

    echo ""
    echo -n "  是否部署 ${label}？[Y/n]: "
    read -r enabled
    if [[ -n "$enabled" && ! "$enabled" =~ ^[Yy] ]]; then
        echo "  跳过 ${label}"
        return
    fi

    echo "    [1] 粘贴已有${key_type}"
    echo "    [2] 生成新密钥对"
    echo -n "  请选择 [1/2]: "
    read -r choice

    case "$choice" in
        1)
            echo "  ${prompt_text}:"
            true > "$dest"
            local count=0
            while IFS= read -r line; do
                [[ -z "$line" ]] && break
                if [[ "$type" == "ssh" ]]; then
                    if [[ "$line" =~ ^ssh-(ed25519|rsa|ecdsa|ed448) ]]; then
                        printf '%s\n' "$line" >> "$dest"
                        ((count++))
                    else
                        echo "    [跳过] 格式不识别: ${line:0:40}..."
                    fi
                else
                    if [[ "$line" =~ ^-----BEGIN ]] || [[ "$line" =~ ^[a-zA-Z0-9+/=]+$ ]] || [[ "$line" =~ ^-----END ]]; then
                        printf '%s\n' "$line" >> "$dest"
                        ((count++))
                    fi
                fi
            done

            if [[ $count -eq 0 ]]; then
                echo -e "  ${RED}错误: 未接收到有效${key_type}${NC}"
                rm -f "$dest"
                die "部署终止"
            fi

            chmod 600 "$dest"

            # 验证
            if [[ "$type" == "ssh" ]]; then
                log "SSH 公钥已写入（${count} 行）"
            else
                if ssh-keygen -y -f "$dest" > /dev/null 2>&1; then
                    log "GitHub 私钥验证通过 ✓"
                else
                    echo -e "  ${RED}私钥格式无效${NC}"
                    rm -f "$dest"
                    die "部署终止"
                fi
            fi
            ;;

        2)
            if [[ "$type" == "ssh" ]]; then
                local tmpkey
                tmpkey=$(mktemp)
                ssh-keygen -t ed25519 -f "$tmpkey" -N "" -C "admin@vps" -q || die "密钥生成失败"

                # 公钥写入 authorized_keys
                cp "${tmpkey}.pub" "$dest"
                chmod 600 "$dest"

                echo ""
                echo -e "  ${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
                echo -e "  ${YELLOW}║  ⚠️  以下私钥仅显示一次，请立即保存到本地！         ║${NC}"
                echo -e "  ${YELLOW}║     请确保当前屏幕无旁人可见                          ║${NC}"
                echo -e "  ${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
                echo ""
                cat "$tmpkey"
                echo ""
                echo -e "  ${GREEN}保存位置建议: ~/.ssh/vps_ed25519${NC}"

                # 30秒后清除（给用户时间保存）
                echo -n "  （30 秒后自动清除屏幕，请尽快保存...）"
                sleep 30
                clear
                rm -f "$tmpkey" "${tmpkey}.pub"
                log "私钥已从服务器删除，公钥已部署到 authorized_keys"
            else
                ssh-keygen -t ed25519 -f "$dest" -N "" -C "deploy@vps" -q || die "密钥生成失败"
                chmod 600 "$dest"

                echo ""
                echo -e "  ${GREEN}公钥（复制到 GitHub Deploy Keys 页面）:${NC}"
                echo ""
                cat "${dest}.pub"
                echo ""
                echo -e "  ${CYAN}GitHub → Settings → Deploy Keys → Add deploy key${NC}"
                echo -e "  ${CYAN}勾选 ✅ Allow write access${NC}"
                echo ""
                echo -n "  （添加完成后按回车继续）"
                read -r _
                log "GitHub deploy key 已部署"
            fi
            ;;
        *)
            die "无效选择"
            ;;
    esac
}

# ── 收集参数 ──
section "Phase 1: 运维用户创建"

while true; do
    echo -n "  创建管理员用户名 (默认: admin): "
    read -r input
    ADMIN_USER="${input:-admin}"
    if err=$(validate_username "$ADMIN_USER" 2>&1); then break
    else echo -e "  ${RED}$err${NC}"; fi
done

IS_NEW_USER=false
if id "$ADMIN_USER" &>/dev/null; then
    echo -e "  ${CYAN}用户 '$ADMIN_USER' 已存在，将复用${NC}"
else
    IS_NEW_USER=true
    echo -e "  ${GREEN}将创建用户 '$ADMIN_USER'${NC}"
fi

ADMIN_SSH="/home/$ADMIN_USER/.ssh"
mkdir -p "$ADMIN_SSH"

# SSH 管理员密钥
deploy_key "ssh" "$ADMIN_SSH/authorized_keys"

# 密码
if $IS_NEW_USER; then
    echo ""
    while true; do
        echo -n "  为用户 '$ADMIN_USER' 设置密码 (≥12位 或 4词passphrase): "
        read -rs password1
        echo ""
        if err=$(validate_password "$password1" 2>&1); then
            echo -e "  ${RED}$err${NC}"
            continue
        fi
        echo -n "  请再次输入密码确认: "
        read -rs password2
        echo ""
        if [[ "$password1" != "$password2" ]]; then
            echo -e "  ${RED}两次输入的密码不一致，请重新设置${NC}"
            continue
        fi
        USER_PASSWORD="$password1"
        break
    done
fi

# sudo
echo ""
echo -n "  是否授予 '$ADMIN_USER' sudo 权限？[Y/n]: "
read -r sudo_choice
if [[ -n "$sudo_choice" && ! "$sudo_choice" =~ ^[Yy] ]]; then
    GRANT_SUDO=false
else
    GRANT_SUDO=true
fi

# GitHub Deploy Key
deploy_key "github" "$ADMIN_SSH/github_deploy"

# ── 确认 ──
section "确认配置"
echo -e "  用户名:  ${GREEN}$ADMIN_USER${NC}"
echo -e "  SSH 密钥:  ${GREEN}$([[ -f $ADMIN_SSH/authorized_keys ]] && echo '已配置' || echo '未配置')${NC}"
echo -e "  sudo:    ${GREEN}$($GRANT_SUDO && echo '是（需要密码）' || echo '否')${NC}"
echo -e "  GitHub:  ${GREEN}$([[ -f $ADMIN_SSH/github_deploy ]] && echo '已配置' || echo '未配置')${NC}"
echo ""
echo -n "  确认以上配置？[Y/n]: "
read -r confirm
[[ -z "$confirm" || "$confirm" =~ ^[Yy] ]] || die "已取消"

# ── 执行用户创建 ──
section "执行部署"

if $IS_NEW_USER; then
    log "创建用户: $ADMIN_USER"
    useradd -m -s /bin/bash "$ADMIN_USER" || die "创建用户失败"
    printf '%s:%s' "$ADMIN_USER" "$USER_PASSWORD" | chpasswd || die "设置密码失败"
    log "用户已创建"
else
    log "用户 $ADMIN_USER 已存在"
fi

# sudo
SUDOERS_FILE="/etc/sudoers.d/$ADMIN_USER"
if $GRANT_SUDO; then
    {
        echo "$ADMIN_USER ALL=(ALL) ALL"
        echo "Defaults:$ADMIN_USER  logfile=/var/log/sudo.log"
    } > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    log "sudo 已授予（需要密码，审计日志: /var/log/sudo.log）"
else
    rm -f "$SUDOERS_FILE"
fi

# SSH 权限
chown -R "$ADMIN_USER:$ADMIN_USER" "$ADMIN_SSH"
chmod 700 "$ADMIN_SSH"

# SSH 端口
SSH_PORT=$(ss -tlnp 2>/dev/null | grep -i sshd | awk '{print $4}' | grep -oP ':\d+' | head -1 | tr -d ':' || echo "22")

log "Phase 1 完成"

# ══════════════════════════════════════
# Phase 2: 安全基线
# ══════════════════════════════════════
section "Phase 2: 安全基线"

# ── 系统更新 ──
log "系统软件包更新..."
apt-get update -qq || true
	apt-get full-upgrade -y -qq || warn "apt upgrade 有部分失败"

# ── 安装安全包 ──
log "安装安全软件包..."
apt-get install -y -qq ufw fail2ban unattended-upgrades vnstat aide aide-common \
    libpam-pwquality auditd audispd-plugins rkhunter 2>&1 | tail -1 || warn "部分包安装失败"

# ── 禁用不必要服务 ──
log "禁用不必要服务..."
for svc in cups.service cups.socket cups.path \
           avahi-daemon.service avahi-daemon.socket \
           rpcbind.service rpcbind.socket \
           ModemManager.service \
           whoopsie.service whoopsie.path; do
    systemctl mask "$svc" 2>/dev/null || true
    systemctl stop "$svc" 2>/dev/null || true
done
step_ok "已禁用不必要服务"

# ── /tmp /dev/shm 安全挂载 ──
log "安全挂载选项..."
for mp in /tmp /dev/shm; do
    if findmnt -n "$mp" &>/dev/null; then
        mount -o "remount,nodev,nosuid,noexec" "$mp" 2>/dev/null || warn "remount $mp 失败"
    fi
    # 持久化 fstab
    bak /etc/fstab
    if grep -q "^[^#].*$mp" /etc/fstab 2>/dev/null; then
        sed -i "\|$mp|s|defaults|defaults,nodev,nosuid,noexec|" /etc/fstab
    fi
done
step_ok "/tmp /dev/shm 已加固"

# ── 禁用 Core Dumps ──
log "禁用 Core Dumps..."
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/99-xsg-core.conf <<'EOF'
[Manager]
DumpCore=no
EOF
cat > /etc/sysctl.d/99-xsg-core.conf <<'EOF'
fs.suid_dumpable=0
kernel.core_pattern=|/bin/false
EOF
sysctl -p /etc/sysctl.d/99-xsg-core.conf > /dev/null 2>&1 || true
mkdir -p /etc/security/limits.d
cat > /etc/security/limits.d/99-xsg-core.conf <<'EOF'
* hard core 0
* soft core 0
EOF
step_ok "Core Dumps 已禁用"

# ── 禁用不安全内核模块 ──
log "禁用不安全内核模块..."
cat > /etc/modprobe.d/blacklist-fs-xsg.conf <<'EOF'
install cramfs /bin/false
blacklist cramfs
install freevxfs /bin/false
blacklist freevxfs
install jffs2 /bin/false
blacklist jffs2
install hfs /bin/false
blacklist hfs
install hfsplus /bin/false
blacklist hfsplus
install squashfs /bin/false
blacklist squashfs
install udf /bin/false
blacklist udf
install vfat /bin/false
blacklist vfat
EOF
step_ok "FS 模块已黑名单"

# ── 禁用不安全网络协议 ──
log "禁用不安全网络协议..."
cat > /etc/modprobe.d/blacklist-net-xsg.conf <<'EOF'
install dccp /bin/false
blacklist dccp
install sctp /bin/false
blacklist sctp
install rds /bin/false
blacklist rds
install tipc /bin/false
blacklist tipc
EOF
step_ok "网络协议模块已黑名单"

# ── UFW 防火墙 ──
log "配置 UFW 防火墙..."
ufw --force disable 2>/dev/null || true
ufw default deny incoming
ufw default allow outgoing
ufw limit "$SSH_PORT/tcp" comment 'SSH rate-limit'
ufw allow http
ufw allow https
ufw allow out 53/udp comment 'DNS'
# conntrack 修复（Ubuntu 26.04 nftables bug）
if iptables -S ufw-before-input 2>/dev/null | grep -q 'RELATED,ESTABLISHED'; then
    step_ok "conntrack 已就绪"
else
    iptables -I ufw-before-input 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    warn "conntrack 规则已插入（Ubuntu nftables 兼容修复）"
fi
echo "y" | ufw enable 2>/dev/null || true
# 持久化 1: iptables-save（重启后恢复）
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
# 持久化 2: 写入 UFW before.rules（ufw reload 后恢复）
bak /etc/ufw/before.rules
if ! grep -q "RELATED,ESTABLISHED" /etc/ufw/before.rules 2>/dev/null; then
    sed -i "/^COMMIT$/i -A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" /etc/ufw/before.rules 2>/dev/null || true
fi
echo "y" | ufw enable 2>/dev/null || true
step_ok "UFW 已配置（conntrack 双持久化）"

# ── SSH 硬化 ──
log "SSH 硬化配置..."
bak /etc/ssh/sshd_config.d/99-xsg.conf
# 死锁检测：如果用户没配 SSH key + 要禁用密码 + 要禁用 root → 拒绝
if [[ ! -f "$ADMIN_SSH/authorized_keys" ]] && [[ ! -f /root/.ssh/authorized_keys ]]; then
    die "死锁风险: 未配置任何 SSH 密钥，但即将禁用密码登录。请先配置 SSH 密钥后重试。"
fi

cat > /etc/ssh/sshd_config.d/99-xsg.conf <<'SSHEOF'
# XSG-managed: SSH 安全硬化
MaxAuthTries 3
LoginGraceTime 30
PermitEmptyPasswords no
StrictModes yes
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding yes
GatewayPorts no
PermitTunnel no
PrintMotd no
UseDNS no
TCPKeepAlive yes

KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
SSHEOF

# 禁用密码登录
cat > /etc/ssh/sshd_config.d/99-xsg-auth.conf <<'EOF'
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
EOF

# SSH 自动回滚
if sshd -t 2>&1; then
    systemctl reload sshd 2>/dev/null || systemctl restart sshd
    step_ok "SSH 硬化已应用"
else
    restore_bak /etc/ssh/sshd_config.d/99-xsg.conf
    rm -f /etc/ssh/sshd_config.d/99-xsg.conf /etc/ssh/sshd_config.d/99-xsg-auth.conf
    die "SSH 配置验证失败，已自动回滚"
fi

# ── Fail2ban ──
log "部署 Fail2ban..."
cat > /etc/fail2ban/jail.d/xsg.local <<'FBEOF'
[DEFAULT]
bantime  = 86400
findtime = 600
maxretry = 5
banaction = ufw
banaction_allports = ufw

[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 5
findtime = 600
bantime  = 86400
FBEOF

systemctl enable --now fail2ban 2>/dev/null || warn "fail2ban 启动失败"
step_ok "Fail2ban 已部署"

# ── OOM 保护 ──
log "OOM 保护..."
SSH_UNIT=$(systemctl list-units --type=service --all 2>/dev/null | grep -oP 'ssh[a-z0-9.-]*\.service' | head -1 || echo "ssh.service")
mkdir -p "/etc/systemd/system/${SSH_UNIT}.d"
cat > "/etc/systemd/system/${SSH_UNIT}.d/99-xsg-oom.conf" <<'EOF'
[Service]
OOMScoreAdjust=-1000
EOF
systemctl daemon-reload 2>/dev/null || true
step_ok "sshd OOMScoreAdjust=-1000"

log "Phase 2 完成"

# ══════════════════════════════════════
# Phase 3: 纵深防御
# ══════════════════════════════════════
section "Phase 3: 纵深防御"

# ── 密码强度策略 ──
log "密码强度策略..."
cat > /etc/security/pwquality.conf <<'EOF'
# XSG-managed
minlen = 12
minclass = 2
maxrepeat = 3
dictcheck = 1
enforcing = 1
EOF
step_ok "密码策略 (minlen=12, minclass=2)"

# ── auditd 审计 ──
log "auditd 审计框架..."
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/xsg.rules <<'EOF'
# XSG-managed: 关键文件审计
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
-w /etc/fail2ban/ -p wa -k fail2ban_config
-w /etc/ufw/ -p wa -k ufw_config
-w /etc/sudoers.d/ -p wa -k sudo_config
-w /etc/systemd/system/ -p wa -k systemd_units
-w /etc/cron.d/ -p wa -k cron_config
-w /etc/sysctl.d/ -p wa -k sysctl_config
EOF
systemctl enable --now auditd 2>/dev/null || warn "auditd 启动失败"
step_ok "auditd 已配置 (7 条规则)"

# ── SUID/SGID 清理 ──
log "SUID/SGID 清理..."
cleaned=0
for path in /usr/bin/chage /usr/bin/gpasswd /usr/bin/newgrp \
            /usr/bin/expiry /usr/bin/wall /usr/bin/write \
            /usr/bin/chfn /usr/bin/chsh; do
    if [[ -f "$path" ]]; then
        if chmod u-s,g-s "$path" 2>/dev/null; then ((cleaned++)); fi
    fi
done
step_ok "已清理 $cleaned 个 SUID/SGID"

# ── /proc hidepid=2 ──
log "/proc hidepid=2..."
bak /etc/fstab
if ! grep -q 'hidepid=2' /etc/fstab 2>/dev/null; then
    sed -i 's|proc /proc proc defaults|proc /proc proc defaults,hidepid=2|' /etc/fstab
    mount -o remount,hidepid=2 /proc 2>/dev/null || true
fi
step_ok "/proc hidepid=2"

# ── rkhunter ──
log "rkhunter..."
rkhunter --propupd --quiet 2>/dev/null || true
cat > /etc/cron.d/xsg-rkhunter <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 2 * * 0 root rkhunter --check --skip-keypress --cronjob 2>&1 | grep -E 'Warning|Infected|Suspicious' >> /var/log/xsg-rkhunter.log 2>&1
EOF
step_ok "rkhunter + 周检 cron"

# ── cron/at 访问限制 ──
log "cron/at 限制..."
echo "root" > /etc/cron.allow
rm -f /etc/cron.deny
echo "root" > /etc/at.allow
rm -f /etc/at.deny
step_ok "cron/at 仅 root 可用"

log "Phase 3 完成"

# ══════════════════════════════════════
# Phase 4: 系统优化
# ══════════════════════════════════════
section "Phase 4: 系统优化"

# ── sysctl ──
log "内核参数优化..."
bak /etc/sysctl.d/99-xsg.conf
cat > /etc/sysctl.d/99-xsg.conf <<'SYSCTLEOF'
# XSG-managed: 安全 + 性能

# ── 安全基线（不被覆盖）──
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── 性能优化 ──
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 1048576
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
fs.file-max = 1048576
fs.nr_open = 1048576
vm.swappiness = 10
SYSCTLEOF
sysctl -p /etc/sysctl.d/99-xsg.conf > /dev/null 2>&1
step_ok "sysctl (安全 17 项 + 性能 20 项)"

# ── limits.conf ──
log "文件句柄限制..."
cat > /etc/security/limits.d/99-xsg.conf <<'EOF'
*       soft    nofile  1048576
*       hard    nofile  1048576
*       soft    nproc   65535
*       hard    nproc   65535
root    soft    nofile  1048576
root    hard    nofile  1048576
root    soft    nproc   unlimited
root    hard    nproc   unlimited
EOF
step_ok "limits.conf (nofile=1048576)"

# ── Swap ──
log "自动 swap 检测..."
mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
if swapon --show 2>/dev/null | grep -q .; then
    step_ok "swap 已存在，跳过"
elif [[ $mem_kb -gt 0 && $mem_kb -le 1048576 ]]; then
    SWAP_SIZE=1024
elif [[ $mem_kb -gt 1048576 && $mem_kb -le 4194304 ]]; then
    SWAP_SIZE=512
else
    SWAP_SIZE=0
fi
if [[ $SWAP_SIZE -gt 0 ]]; then
    SWAP_FILE="/swapfile"
    # btrfs 文件系统不支持 swap file
    if df -T / 2>/dev/null | grep -q btrfs; then
        warn "btrfs 文件系统不支持 swap file，跳过"
        SWAP_SIZE=0
    fi
    avail_gb=$(df --output=avail / | tail -1 | awk '{print int($1/1024/1024)}')
    if [[ $avail_gb -gt $((SWAP_SIZE / 1024 + 2)) ]]; then
        dd if=/dev/zero of="$SWAP_FILE" bs=1M count=$((SWAP_SIZE)) status=none 2>/dev/null
        chmod 600 "$SWAP_FILE"
        mkswap "$SWAP_FILE" > /dev/null 2>&1
        swapon "$SWAP_FILE" > /dev/null 2>&1
        if ! grep -q "$SWAP_FILE" /etc/fstab 2>/dev/null; then
            echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
        fi
        step_ok "swap 已创建 (${SWAP_SIZE}MB)"
    else
        warn "磁盘空间不足，跳过 swap"
    fi
else
    step_ok "内存充足，无需 swap"
fi

# ── NTP 时间同步 ──
log "NTP 时间同步..."
timedatectl set-ntp true 2>/dev/null || true
systemctl enable --now systemd-timesyncd 2>/dev/null || true
step_ok "NTP 已启用"

# ── DNS 加固 + chattr ──
log "DNS 加固..."
if [[ -f /etc/resolv.conf ]] && ! grep -q '^#.*xsg.*reliable' /etc/resolv.conf 2>/dev/null; then
    bak /etc/resolv.conf
    cp /etc/resolv.conf /etc/resolv.conf.xsg.bak
    {
        echo "# xsg: reliable DNS — original nameservers kept as fallback"
        echo "nameserver 8.8.8.8"
        echo "nameserver 1.1.1.1"
        grep '^nameserver' /etc/resolv.conf.xsg.bak 2>/dev/null || true
    } > /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || warn "chattr +i 失败（文件系统可能不支持）"
    step_ok "DNS 已加固 (8.8.8.8 + 1.1.1.1 + chattr +i)"
else
    step_ok "DNS 已加固或跳过"
fi

# systemd-resolved fallback（resolv.conf 是 symlink 时）
if [[ -L /etc/resolv.conf ]] && systemctl is-active systemd-resolved &>/dev/null; then
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/xsg.conf <<'RESEOF'
[Resolve]
DNS=8.8.8.8 1.1.1.1
FallbackDNS=
Domains=~.
RESEOF
    systemctl restart systemd-resolved 2>/dev/null || true
    step_ok "systemd-resolved 已配置"
fi

log "Phase 4 完成"

# ══════════════════════════════════════
# Phase 5: 运维设施
# ══════════════════════════════════════
section "Phase 5: 运维设施"

# ── unattended-upgrades ──
log "无人值守安全更新..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
step_ok "unattended-upgrades 已启用"

# ── AIDE 文件完整性 ──
log "AIDE 初始化..."
if [[ -f /var/lib/aide/aide.db ]]; then
    step_ok "AIDE DB 已存在"
else
    aideinit -y -q 2>/dev/null &
    step_ok "AIDE 初始化已在后台启动"
fi
# AIDE cron
cat > /etc/cron.d/xsg-aide <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 3 * * * root aide --check 2>&1 | grep -E 'Changed|Added|Removed' >> /var/log/xsg-aide-check.log 2>&1
EOF

# ── vnstat ──
log "vnstat 流量统计..."
systemctl enable --now vnstat 2>/dev/null || true
step_ok "vnstat 已启用"

# ── logrotate ──
log "logrotate 配置..."
cat > /etc/logrotate.d/xsg <<'EOF'
/var/log/xsg-*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    maxsize 20M
    copytruncate
    create 0640 root root
}
EOF
step_ok "logrotate 已配置"

# ── 内核重启检测 ──
if [[ -f /var/run/reboot-required ]]; then
    warn "有安全更新需要重启系统"
    if [[ -f /var/run/reboot-required.pkgs ]]; then
        warn "涉及包: $(cat /var/run/reboot-required.pkgs)"
    fi
else
    step_ok "内核无需重启"
fi

# ── AES-256 加密备份 ──
log "配置加密备份..."
BACKUP_SCRIPT="/usr/local/bin/xsg-backup.sh"
cat > "$BACKUP_SCRIPT" <<'BKPEOF'
#!/bin/bash
# XSG-managed: 关键配置加密备份
set -euo pipefail
BACKUP_DIR="/root/xsg-backups"
BACKUP_FILE="$BACKUP_DIR/xsg-backup-$(date +%F).enc"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
PASS_FILE=$(mktemp)
trap "rm -f $PASS_FILE /tmp/xsg-backup.tar.gz" EXIT
if [[ -f /etc/xsg/backup.key ]]; then
    cat /etc/xsg/backup.key > "$PASS_FILE"
else
    echo "XSG backup key not found" >&2
    exit 1
fi
tar czf /tmp/xsg-backup.tar.gz -C / \
    etc/ssh/sshd_config.d etc/ufw etc/fail2ban \
    etc/sysctl.d etc/security etc/modprobe.d \
    etc/audit/rules.d etc/cron.d etc/apt/apt.conf.d \
    2>/dev/null || true
openssl enc -aes-256-cbc -pbkdf2 -salt \
    -pass file:"$PASS_FILE" \
    -in /tmp/xsg-backup.tar.gz \
    -out "$BACKUP_FILE" 2>/dev/null
chmod 600 "$BACKUP_FILE"
echo "Backup saved: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
BKPEOF
chmod 700 "$BACKUP_SCRIPT"
mkdir -p /etc/xsg
if [[ ! -f /etc/xsg/backup.key ]]; then
    openssl rand -hex 32 > /etc/xsg/backup.key
    chmod 600 /etc/xsg/backup.key
fi
cat > /etc/cron.d/xsg-backup <<'BKPCRON'
SHELL=/bin/bash
0 3 1 * * root /usr/local/bin/xsg-backup.sh >> /var/log/xsg-backup.log 2>&1
BKPCRON
step_ok "AES-256 加密备份已配置 (月检, /root/xsg-backups/)"

# ── 磁盘监控 ──
log "配置磁盘监控..."
cat > /usr/local/bin/xsg-disk-monitor.sh <<'DMEOF'
#!/bin/bash
# XSG-managed: 磁盘使用率告警
set -uo pipefail
THRESHOLD=90
LOG="/var/log/xsg-disk-monitor.log"
ROOT_USE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ -n "$ROOT_USE" && "$ROOT_USE" -gt "$THRESHOLD" ]]; then
    DISK_INFO=$(df -h / /var /opt 2>/dev/null)
    printf '[%s] [ALERT] root=%s%%\n%s\n' "$(date +%F_%T)" "$ROOT_USE" "$DISK_INFO" | tee -a "$LOG" >&2
    if command -v msmtp >/dev/null 2>&1 && [[ -f /etc/xsg/alert.email ]]; then
        printf 'Subject: [XSG] Disk Alert (%s%%)\n\n%s\n' "$ROOT_USE" "$DISK_INFO" | \
            msmtp -a xsg "$(cat /etc/xsg/alert.email)" 2>/dev/null || true
    fi
fi
DMEOF
chmod 700 /usr/local/bin/xsg-disk-monitor.sh
cat > /etc/cron.d/xsg-disk-monitor <<'DMCRON'
SHELL=/bin/bash
17 * * * * root /usr/local/bin/xsg-disk-monitor.sh >> /var/log/xsg-disk-monitor.log 2>&1
DMCRON
step_ok "磁盘监控已配置 (阈值=90%, 每小时)"

# ── ipset+geoip SSH 防御框架 ──
log "配置 SSH 暴力破解防御..."
apt-get install -y -qq geoip-bin geoip-database ipset 2>/dev/null || true
if command -v ipset >/dev/null 2>&1 && command -v geoiplookup >/dev/null 2>&1; then
    ipset create xsg-blocked hash:ip -exist 2>/dev/null || true
    ipset create xsg-throttle hash:ip timeout 3600 -exist 2>/dev/null || true
    iptables -I ufw-before-input 1 -p tcp --dport "$SSH_PORT" -m set --match-set xsg-blocked src -j DROP 2>/dev/null || true
    iptables -I ufw-before-input 2 -p tcp --dport "$SSH_PORT" -m set --match-set xsg-throttle src -m limit --limit 10/hour -j RETURN 2>/dev/null || true
    iptables -I ufw-before-input 3 -p tcp --dport "$SSH_PORT" -m set --match-set xsg-throttle src -j DROP 2>/dev/null || true
    # 持久化
    cat > /etc/xsg/ipset-restore.sh <<'IPREST'
#!/bin/bash
ipset create xsg-blocked hash:ip -exist
ipset create xsg-throttle hash:ip timeout 3600 -exist
IPREST
    chmod 700 /etc/xsg/ipset-restore.sh
    cat > /etc/systemd/system/xsg-ipset.service <<'IPSVC'
[Unit]
Description=XSG ipset restore
Before=ufw.service

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/xsg/ipset-restore.sh
ExecStop=/usr/sbin/ipset save -file /etc/xsg/ipset-backup.txt
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
IPSVC
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable xsg-ipset.service 2>/dev/null || true
    cat > /usr/local/bin/xsg-ssh-guard.sh <<'GRDSH'
#!/bin/bash
# XSG-managed: SSH 暴力破解自动封禁
set -uo pipefail
journalctl -u ssh --since "10 minutes ago" 2>/dev/null | \
    grep -oP "Failed password.*from \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | \
    while read -r ip; do
        [[ "$ip" =~ ^(10\.|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168\.|127\.) ]] && continue
        if geoiplookup "$ip" 2>/dev/null | grep -qv "CN"; then
            ipset add xsg-blocked "$ip" -exist 2>/dev/null || true
        fi
    done
GRDSH
    chmod 700 /usr/local/bin/xsg-ssh-guard.sh
    cat > /etc/cron.d/xsg-ssh-guard <<'GRDCRN'
SHELL=/bin/bash
*/10 * * * * root /usr/local/bin/xsg-ssh-guard.sh >> /var/log/xsg-ssh-guard.log 2>&1
GRDCRN
    step_ok "SSH 防御框架已部署 (ipset+geoip, 每10分钟)"
else
    warn "ipset/geoip 不可用，跳过 SSH 防御框架"
fi
log "Phase 5 完成"

# ══════════════════════════════════════
# 完成
# ══════════════════════════════════════
cat <<EOF

  ╔══════════════════════════════════════════╗
  ║     XSG 部署完成                          ║
  ╚══════════════════════════════════════════╝

  用户:     ${GREEN}$ADMIN_USER${NC}
  SSH 端口:   $SSH_PORT
  SSH 密钥:   $([[ -f $ADMIN_SSH/authorized_keys ]] && echo '已配置' || echo '未配置')
  sudo:     $($GRANT_SUDO && echo '已授予（需要密码）' || echo '未授予')
  sudo 审计:  /var/log/sudo.log
  GitHub:   $([[ -f $ADMIN_SSH/github_deploy ]] && echo "已部署 ($ADMIN_SSH/github_deploy)" || echo '未配置')

  ═══ 安全提醒 ═══
  UFW 已放行端口 $SSH_PORT、80、443。
  如需修改 SSH 端口，务必先添加 UFW 规则，否则将被锁在外面。

  ═══ 登录 ═══
  ssh -i <your_key> $ADMIN_USER@<VPS_IP>

  建议立即打开第二个终端验证登录，确认成功后再关闭当前会话。

EOF
