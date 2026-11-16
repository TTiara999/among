# Semgrep 竞赛日速查（靶场 Linux 环境的放大器）

> 学习自 semgrep.dev + docs（2026-11）。已过滤赛事无关功能：AppSec 平台/SCA 供应链/
> CI-CD 集成/autofix/SARIF/AI 分诊/Guardian/IDE·MCP 集成——全部不用看。
> **定位**：无 Python 环境（如纯 Windows 主机）→ 用技能自带 Node 工具（零安装）；
> Linux 环境（靶场/WSL/原生）且可装包 → Semgrep 做扫描放大器，与 Node 工具**互补**而非替代。

## 一、为什么值得在靶场装（它强在哪）

| 优势 | 说明 | 对应我们的什么 |
|---|---|---|
| AST 模式匹配 | 规则长得像代码片段（`$X` 元变量），按语法结构匹配 → 无注释/字符串/格式误报 | web-sca 用正则 + 降噪规则近似 |
| **污点模式（OSS 可用）** | `pattern-sources → pattern-sinks` 连线，跨语句、跨表达式 | web-sca 的文件内一跳连线是其子集（无跨文件） |
| 规则注册表 | 官方维护 `p/` 规则包，一键全库扫 | 五类各对应包（见下表） |
| 快 | 单遍编译模式，无需构建工程（对比 CodeQL 要建数据库） | 我们同哲学：单遍 IO、跳 vendor/大文件 |
| 免构建 | 源码树直接扫 | 同 |

明确不依赖的：Pro 引擎跨文件污点（付费，单文件污点已覆盖大部分赛题场景）。

## 二、5 分钟上手（Linux 靶场）

```bash
pipx install semgrep        # 或 uv tool install semgrep（需 Python3）
# 一键自动选规则:
semgrep scan --config auto .
# 定向扫（先关指标上报）:
semgrep scan --config p/owasp-top-ten --config p/secrets --metrics off .
```

### 安装实测坑（Ubuntu 24.04 / WSL，2026-11 练习踩过的）

```bash
# 无 pipx 时用 pip；Ubuntu 24.04 有 PEP668 externally-managed，需 --break-system-packages
pip3 install --user --break-system-packages semgrep
# 关键：~/.local/bin 必须在 PATH，否则 semgrep 核心报 `execvp pysemgrep: No such file or directory`
grep -q '.local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
grep -q '.local/bin' ~/.profile || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
export PATH="$HOME/.local/bin:$PATH"
semgrep --version    # 必须能输出版本号才算装好（实测 1.185.0）
```
> 不要假设靶场已预装 semgrep——开局先 `semgrep --version` 实测；缺失则按上式装。一键预置见 `scripts/provision-wsl.sh`。

## 三、五类赛题对应的规则包

| 赛题类 | 规则包 |
|---|---|
| Web（Java/PHP） | `p/owasp-top-ten` `p/sql-injection` `p/xss` `p/php` `p/java` |
| 智能体（Python/TS） | `p/python` `p/owasp-top-ten` `p/secrets` + 自定义（下节） |
| 邮件（PHP webmail） | `p/php` `p/xss` `p/secrets` |
| 数据库（C） | `p/c` 能力有限（C 内存类）——命令/配置面仍用 `db-surface.mjs` |
| 办公（JS/TS） | `p/typescript` `p/javascript` `p/secrets` |

## 四、自定义规则（贴合埋点速查表，10 分钟写完）

```yaml
# rules.yaml —— 与 category-playbooks 埋点特征一一对应
rules:
  # ① PHP 命令执行污点（邮件/Web 类）
  - id: php-cmd-taint
    message: 用户输入流入命令执行
    severity: ERROR
    languages: [php]
    mode: taint
    pattern-sources:
      - pattern: $_GET[...]
      - pattern: $_POST[...]
      - pattern: $_REQUEST[...]
    pattern-sinks:
      - pattern: system(...)
      - pattern: exec(...)
      - pattern: shell_exec(...)
      - pattern: popen(...)
      - pattern: proc_open(...)

  # ② Python SSRF 污点（智能体类：HTTP 节点/工具 URL）
  - id: py-ssrf-taint
    message: 用户可控 URL 进入出站请求
    severity: WARNING
    languages: [python]
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.get_json(...)
      - pattern: request.form[...]
    pattern-sinks:
      - pattern: requests.get(...)
      - pattern: requests.post(...)
      - pattern: httpx.get(...)

  # ③ MyBatis ${} 拼接（Web 类，generic 模式扫 XML）
  - id: mybatis-dollar
    message: Mapper XML 中存在 ${} 拼接
    severity: WARNING
    languages: [generic]
    paths:
      include: ["*.xml"]
    pattern-regex: '\$\{[^}]+\}'
```

运行：`semgrep scan --config rules.yaml --metrics off .`

## 五、限时赛开销控制（关键参数）

```bash
semgrep scan --config p/owasp-top-ten \
  --exclude vendor --exclude node_modules --exclude '*.min.js' \
  --max-target-bytes 1000000 \   # 跳过 >1MB 大文件
  --timeout 5 \                   # 单规则单文件 5s 超时
  --timeout-threshold 3 \         # 连续超时即跳过该文件
  --jobs 4 --metrics off .
```

## 六、什么时候用谁（决策树）

```
本机赛前练习 ──────────────── Node 工具（零安装，0.2~2.5s/库）
靶场开赛 Day1 测绘 ────────── semgrep p/ 规则包全库快扫 + web-sca 污点连线
盯上某个可疑点 ────────────── 写 10 分钟自定义污点规则（④）验证可达性
确认跨文件传播链 ──────────── 人工 + AI 追（工具都不做跨文件）
```

License 提醒：OSS CLI + MIT 规则可自由用于比赛；`r/` 前缀部分规则为私有许可，比赛用 `p/` 与自写规则即可。
