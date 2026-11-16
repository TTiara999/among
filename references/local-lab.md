# 本地实验场（WSL / Linux）——五类起靶 Runbook

> 用途：练习期动态验证手段（Tier 3 证据来源）；比赛当天在授权靶场内照抄本文动作。
> 适用：Windows + WSL（推荐 Ubuntu 24.04）或原生 Linux。`<distro>` = 你的 WSL 发行版名；`<skill-dir>` = among 技能安装目录；`<workspace>` = 当前审计工作区。

## 〇、开局预置与实测巡检（不假设预装）

> **教训**：新环境常缺 cmake/openssl/curl/uuid/libevent 头与 semgrep，临时搭环境曾耗 90+ 分钟远超读码成本。**开局必须先预置 + 实测，不假设预装。**

```bash
# 一键预置（脚本随技能分发）：编译工具链 + 各赛道 dev 头 + semgrep
# WSL 路线（Git Bash 侧执行；tr -d '\r' 去 Windows 检出的 CRLF）：
MSYS_NO_PATHCONV=1 wsl -d <distro> -- bash -c "tr -d '\r' < <skill-dir>/scripts/provision-wsl.sh | bash"
# 原生 Linux 路线：
bash <skill-dir>/scripts/provision-wsl.sh
# 实测巡检（逐项验证，而非假设）：
wsl -d <distro> -- bash -lc 'for h in openssl/ssl.h curl/curl.h uuid/uuid.h event2/event.h; do echo "#include <$h>" | gcc -E -x c - >/dev/null 2>&1 && echo "$h OK" || echo "$h MISSING"; done; cmake --version | head -1; semgrep --version'
```

- 赛道依赖矩阵：邮件（OpenSMTPD）需 libevent-dev+libssl-dev+autotools；数据库（KeyDB）需 libssl-dev+libcurl4-openssl-dev+uuid-dev+libatomic1；办公（DocumentServer）需 node+npm；智能体需 python3-venv。
- C/C++ 编译注意：Windows 检出的 CRLF 会致 `mkreleasehdr.sh` 等脚本报错——**对副本** `sed -i 's/\r$//' *.sh` 去 CRLF（不改目标源码）；编译/运行放 WSL 原生 fs（如 `~/lab/`），`/mnt/*` 跨文件系统 IO 极慢。

## 0. 拓扑与隔离纪律（红线配套）

- **分析侧**（Windows 或宿主）：Node 分析工具，只读源码；**实验场**（WSL/Linux）：起靶、PoC、跑服务一律在此隔离区内，宿主侧不执行任何目标代码。
- PoC 目标地址只打 127.0.0.1 / 实验场 IP / 授权靶场地址。
- **命令约定**：复杂命令一律落脚本文件（Git Bash 内联引号经 `wsl -- bash -lc` 双层解析会被吞）——脚本放 `<workspace>/lab-scripts/`，执行时加 `MSYS_NO_PATHCONV=1`。
- 统一执行模板：`MSYS_NO_PATHCONV=1 wsl -d <distro> -- bash <workspace>/lab-scripts/<脚本>.sh`
- 主题化约定：所有靶落在实验场 `~/targets/` 下；服务日志 `/tmp/<name>.log`；数据库统一 mariadb。

## 1. 数据库类：Redis

```bash
sudo apt-get install -y redis-server        # 或源码编译（练命令分发表审计时用源码靶）
sudo systemctl enable --now redis-server    # 无 systemd 时: redis-server --daemonize yes
redis-cli ping                              # PONG 验证
```

- 审计材料 = Redis 源码（命令分发表/ACL 面），与运行实例分开存放。
- PoC 形态：`redis-cli` 协议命令（CONFIG SET dir/dbfilename、MODULE LOAD、EVAL 面）。
- 注意：别把 PoC 打到含宿主数据的实例——另起写靶专用实例：`redis-server --port 6380 --dir /tmp`。

## 2. Web 类：RuoYi

```bash
# 源码: git clone https://github.com/yangzongzhuan/RuoYi ~/targets/ruoyi（或 gitee 镜像）
cd ~/targets/ruoyi && mvn -q -DskipTests package    # 产物 ruoyi-admin/target/ruoyi-admin.jar
# 库（一次性）：建 ry 库 + 导入 sql/*.sql；mariadb root 密码与 application.yml 一致
# 起靶：后台 java -jar ruoyi-admin/target/ruoyi-admin.jar + 轮询 HTTP 200
```

- 默认账号 admin/admin123；依赖 mariadb（127.0.0.1:3306）+ redis（6379 无密码，出题默认一致）。
- **端口 = 80**（application.yml `port: 80`，非 8080）；`/` 302 → `/login` 即启动成功。
- 审计优先级：`@DataScope` 数据权限边界、Shiro 密钥硬编码、MyBatis `${}`、/druid 等通用探针。
- PoC 形态：curl HTTP 请求；浏览器级效果用浏览器自动化截图。

## 3. 邮件类：Roundcube

```bash
# Docker 路线（GitHub release 直连不稳时优先）：
docker pull roundcube/roundcubemail:1.7.6-apache
# 提取源码做白盒审计：docker create 后 docker cp 容器内 /usr/src/roundcubemail 到 ~/targets/
# 起靶：sqlite 配置 + php -S 127.0.0.1:8000（或直接用 apache 镜像 -p 8000:80）
```

- 细节：db_dsnw 指 sqlite 文件（首访自动建表，无需 installer）；`smtp_server`/`imap_host` 默认值保留（不上线外发也不影响渲染面测试）。
- 注意：渲染链 XSS 需要邮箱里有恶意邮件——练习时用 IMAP 后端 dovecot（`apt install dovecot-imapd`）或直接向 sqlite 会话/缓存表注入已渲染内容。
- 审计优先级：guard-audit 定位 `rcube_washtml::wash` 系 → 枚举漏网边角；PoC 形态 = SMTP 投递。

## 4. 智能体类：Dify

```bash
git clone https://github.com/langgenius/dify ~/targets/dify
cd ~/targets/dify/docker && cp .env.example .env && docker compose up -d
```

- 依赖镜像较多（postgres/redis/weaviate/api/web/nginx），首起 5-10 分钟。
- 备选零安装路径：`npx n8n`（sqlite 默认）练工作流引擎类。
- 审计优先级：鉴权矩阵差集 + 执行类端点（custom_component/validate/code 等）。

## 5. 办公类：OnlyOffice

```bash
docker run -d -p 8081:80 onlyoffice/documentserver:latest   # 首启 1-2 分钟
```

- 审计优先级：zip-slip/XXE/JWT 默认密钥；PoC 形态 = docx-evil.mjs 构造恶意文档后上传。
- 注意：documentserver 体积大（~2.5G），练习完 `docker rm -f` 即可，镜像保留。

## 6. 关靶与清理

```bash
sudo systemctl stop redis-server mariadb      # 或不关（练习期常驻）
pkill -f ruoyi-admin.jar && pkill -f "php -S" # 应用层
docker compose -f ~/targets/dify/docker/docker-compose.yaml down   # 大件用完即收
```

## 7. Semgrep（可选放大器）

```bash
semgrep --version    # 开局实测；缺失则按 semgrep-quickstart.md 安装（provision-wsl.sh 已含）
semgrep scan --config auto --metrics off <目标路径>
```

- 用法细节见 `references/semgrep-quickstart.md`；与 Node 工具互补不替代。

## 8. 截图与证据形态决策表（取证前先查表，不再现场纠结）

| 场景 | 证据形态 | 采集手段 |
|---|---|---|
| HTTP / socket 协议 / SMTP 投递等协议结果 | **文本证据（默认）**——请求响应全文 | `scripts/repro-runner.mjs`（采集+脱敏+Tier标注+报告引用一键） |
| 存储型 XSS 弹窗 / 越权后台渲染 / 前端效果 | **浏览器像素截图** `NN-<name>.png` | 浏览器自动化技能（首次使用先冒烟一片区域） |
| 恶意 .docx 渲染 / 邮件客户端显示效果 | **效果替代证据**（转换器崩溃日志 / SSRF canary 命中 / 响应差异 / 文件落地） | repro-runner 输出日志；无 GUI 环境像素证据用 scrot 等留到靶场补 |

**命名约定**（repro-runner 自动遵循）：`evidence/F-XX/NN-<name>.request.txt` `NN-<name>.response.txt` `NN-<name>.png`（NN=步骤序号）。
**Tier 标注约定**：`repro-runner` 打 harness=Tier2；打完整运行目标=Tier3——在 steps.json 的 `tier` 字段声明，SUMMARY.md 自动标注。

**执行侧排障约定**：
- WSL 若为 mirrored 网络模式，宿主侧可能无法跨侧打到 WSL 内靶（回环被占用、直连被 RST）——此时证据采集改在 **WSL 内执行**（WSL 内需装 Node），WSL 内用 127.0.0.1 打靶；NAT 模式则宿主可直接打 WSL IP。
- 远程靶场（公网 URL/授权靶场）→ 宿主侧 Node 直接采集，不受此限制。
- tcp 类协议（redis/mysql）是长连接——steps 里默认「首块响应 + 300ms」自动收尾（`linger` 可改），勿依赖目标主动断连。

## 9. 运维约定

- 状态巡检/关靶脚本自行落脚本文件（`lab-scripts/lab-status.sh`、`lab-scripts/lab-down.sh` 模式），统一经 WSL 执行包装器调用：路径转换 + 引号规则集中处理，**禁止内联 `wsl bash -lc` 跑复杂命令**。
- mariadb 健康检查用 TCP（`mariadb-admin -h 127.0.0.1 -uroot -p<密码> ping`；unix socket 在 root 改认证插件后可能不可用）。