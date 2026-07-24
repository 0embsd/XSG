# XSG (X Server Guard)

VPS 一键安全加固脚本 — 纯 Bash、零依赖、单文件 979 行。

## 快速开始

```bash
curl -O https://raw.githubusercontent.com/0embsd/XSG/main/xsg.sh
sudo bash xsg.sh
```

根据交互提示配置管理员用户、SSH 密钥、sudo 权限即可，其余 5 个 Phase 自动执行。

## 做了什么

| Phase | 内容 |
|:-----:|------|
| **0** | OS/网络检测 |
| **1** | 管理员用户创建、SSH 密钥 (粘贴/生成)、GitHub Deploy Key、sudo (强制密码) |
| **2** | UFW (含 conntrack 双持久化)、SSH 硬化 (后量子 KEX)、Fail2ban、OOM 保护、禁用不必要服务、/tmp noexec、core dump 禁用、模块/协议黑名单 |
| **3** | 密码质量策略 (minlen=12)、auditd、SUID 清理、/proc hidepid=2、rkhunter、cron/at 限制 |
| **4** | BBR + TCP 调优、sysctl (37 项)、limits.conf (nofile=1048576)、swap (btrfs 检测)、DNS 加固 (chattr +i + systemd-resolved fallback) |
| **5** | unattended-upgrades、AIDE、logrotate、AES-256 加密备份、磁盘监控 (90% 阈值)、ipset+geoip SSH 防御 |

## 为什么选 XSG

| 对比 | du_setup | linux-ssh-init-sh | hardening-ubuntu | **XSG** |
|------|:--:|:--:|:--:|:--:|
| SSH 后量子加密 | ❌ | ❌ | ❌ | ✅ |
| 死锁检测 | ✅ | ✅ | ❌ | ✅ |
| SSH 自动回滚 | ✅ | ✅ | ❌ | ✅ |
| conntrack 修复 | ❌ | ❌ | ❌ | ✅ |
| DNS chattr +i | ❌ | ❌ | ❌ | ✅ |
| AES-256 加密备份 | ❌ | ❌ | ❌ | ✅ |
| ipset+geoip 防御 | ❌ | ❌ | ❌ | ✅ |
| btrfs 检测 | ❌ | ❌ | ❌ | ✅ |
| 单文件零依赖 | ✅ | ✅ | ❌ | ✅ |
| 中文友好 | ❌ | ❌ | ❌ | ✅ |

## 要求

- Debian/Ubuntu Linux (systemd)
- root 权限
- 外网可达 (apt 需要)

## License

GNU AGPL 3.0
