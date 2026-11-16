---
name: among
description: 开源软件白盒漏洞挖掘与竞赛解题通用技能（按 NVD 真实 CVE 实证校准），覆盖五类赛题方向——智能体（Dify/n8n/LangFlow/RAGFlow 等）、Web（若依/Jeecg/ThinkPHP 等）、邮件服务器（Roundcube 等）、数据库（Redis/SQLite/MariaDB 等）、办公（LibreOffice/OnlyOffice）。赛题形态识别、框架指纹判定、鉴权矩阵、危险点搜索、0day 模式确认、flag/证据导向利用与 writeup 撰写。当用户要求解开源软件赛题、审计智能体/数据库/邮件/办公/Web 项目源码、挖 0day、复现 CVE 或写漏洞报告时使用。
---

# among —— 开源软件白盒审计与竞赛解题（通用 · 实证校准版）

> 本技能的优先级排序依据：2026-11 从 NVD 拉取的智能体平台 664 条真实 CVE + 五类方向赛前情报。
> 详见 `references/ctf-playbook.md` 与 `references/category-playbooks.md`。
> **赛制提醒**（电科"网信杯"）：五类方向各一题、授权靶场内完成发现/验证/报告、考评 0day 与 AI 方法先进性——见 ctf-playbook §〇。

## 核心方法论（按实证频率校准）

**CVE 式白盒审计（A/B/D 型题）按此优先级**：
1. **鉴权矩阵**（实证 #1，~31%）：逐路由核对鉴权——"普通用户能否做 admin 操作"、"未认证能否访问该端点"
2. **代码/命令注入**（~23%）：执行用户/LLM 生成代码的端点（组件、validate、代码节点、沙箱）
3. **SSRF**（~9%）：HTTP 节点、网页抓取、远程文件上传
4. **存储型 XSS**（~7%）：聊天渲染、文件名、DSL 节点名、图表、PDF 内容
5. **路径遍历**（~7%）：文件上传/下载/预览、插件、MCP
6. **SSTI/模板注入**：Jinja2/render_template_string（智能体重灾区）
7. **配置与认证缺陷**：默认凭证、CORS、开放重定向、弱密钥生成、无速率限制、账号枚举

**Prompt 拼接注入**：在 664 条 CVE 中仅 ~1.3%——**它是 C 型在线挑战和自研注入题的核心，但不是 CVE 审计主力**。打在线挑战时仍为首选方向（见 ctf-playbook §C）。

## 第零步：识别赛题形态（先定策略，再动手）

| 形态 | 识别特征 | 核心策略 |
|---|---|---|
| A 开源项目审计型 | 给出完整开源仓库（或压缩包） | 走完整六步流程；按上述实证优先级排序 |
| B 自研靶场型 | 几百~几千行自研项目（FastAPI/Flask + OpenAI/LangChain SDK），常有在线环境 | 逐文件精读；按"埋点特征速查"快扫（见 ctf-playbook） |
| C 在线挑战型 | 无源码，只有可交互的 Agent 网页/API | 黑盒信息收集 → 系统提示探测 → Prompt 注入 → 工具滥用 |
| D CVE 复现型 | 给 CVE 编号或指定历史版本 | 定位修复 commit → diff → checkout 父提交复现 → **检查修复是否完整**（实证高频：MaxKB/RAGFlow 均有 incomplete-fix 系列） |
| E 配置审计型 | 给 workflow/agent 配置（n8n JSON、DSL、prompt+tools 定义） | 审工具权限、数据流向、表达式注入、外发节点 |

判断依据两问：**题目给了什么**（源码/环境/编号/配置）？**要交什么**（flag / writeup / PoC / 报告）？

## 通用智能体架构（对号入座）

```
入口层    HTTP API / WebSocket / Webhook / 前端页面 / CLI
业务层    认证授权 / 会话管理 / 应用(Workflow)管理 / 工具管理
核心层    Prompt 模板拼接 / LLM 调用封装 / 工具分发器 / RAG 检索 / 记忆
执行层    代码沙箱 / 工具执行函数 / 外部 API 调用
数据层    向量库 / 关系库 / 文件存储 / 缓存
```

重点审计 **入口层、执行层、渲染输出**（实证：漏洞大量在"端点鉴权"与"执行组件"）。

## 框架指纹速判（30 秒）

| 看到什么 | 判定 | 优先看 |
|---|---|---|
| `requirements.txt` 含 langchain / llama-index / openai | LangChain 系应用 | agent executor、tools 定义、memory |
| Flask 蓝图（`Blueprint` / `@ns.route`） | Flask API 服务 | 各鉴权装饰器是否真的校验 |
| FastAPI（`@app.post` / pydantic） | FastAPI 服务 | 依赖注入鉴权、pydantic 边界 |
| `package.json` 含 express / nestjs / n8n | Node 服务 | 路由中间件、`eval`/`child_process`、**原型污染** |
| docker-compose 多服务（api/sandbox/plugin/内部代理） | 平台型项目 | 服务间信任边界、内部 API 密钥、各服务 CORS |
| n8n / workflow JSON 配置 | 工作流引擎 | 节点凭证、`{{ }}` 表达式注入 |
| Jinja2 / 模板渲染用户数据 | 模板型 | **SSTI**（`render_template_string`、`Template(用户输入)`） |
| `.java` + Spring/若依/Jeecg 脚手架 | Java Web | MyBatis `${}`、Shiro rememberMe、fastjson、SSTI |
| `.php` 入口 + `include/require` | PHP 应用（webmail/CMS） | `unserialize`、命令执行函数、上传校验 |
| 纯 C/C++（`Makefile`/`CMakeLists`、`main()`） | 数据库/邮件/办公核心 | 命令分发表权限标记、`strcpy/sprintf/memcpy`、配置默认凭证 |
| 单文件/少量文件 + 一个 LLM key | 自研赛题（B 型） | 全文精读，埋点见 ctf-playbook |

> 五类方向是**五套不同方法论，不是一套打法换目标**：Web 审路由（指纹→模式库→变体）、数据库审命令分发表、邮件审邮件生命周期渲染链（XSS 主战场）、办公审文档解析管线（四链：解压/XML/内容/服务）、智能体审 LLM 控制流。各自打法与 PoC 形态见 `references/category-playbooks.md`。

## 一键流水线（赛事模式入口 · 输入只有一个参数）

```bash
node scripts/audit-pipeline.mjs <目标目录 | targets.txt | 目录...> [--out <工作区>]
```

单目录 = 单题流水线；targets.txt / 多目录 = 自动路由 squad-triage 多题分诊（组合排序 + 波次建议）。

**2 秒自动完成**：零改动基线 → 指纹 → 深读队列/鉴权矩阵 → 污点连线/守卫枚举 → 修复情报 → 候选清单（findings-draft.md + notes.md 骨架 + tool-logs/ 全量日志）。

**透明协议（不做黑盒审计——关键节点必须亮给用户）**：

| 节点 | 亮什么 | 谁拍板 |
|---|---|---|
| 每阶段结束 | 产物路径 + 计数 + 全量日志位置 | 用户确认继续 |
| 候选清单 | 来源/file:line/预估收益排序 | **用户挑确认顺序** |
| 发现定级 | 加权公式的计算过程 | 用户确认或修改 |
| 性价比止损 | 单洞 >30 分钟未确认 → 降级换洞（理由展示） | 用户可否决 |
| 交付收尾 | deliverables-check 逐项核对赛制交付物 | 用户确认提交 |

**性价比规则**：候选按"预估收益(来源类型×可达性) / 工作量(文件行数×跨文件度)"排序；止损线防单洞深坑。确认环节（深读→根因→定级）显式交还用户或 AI 会话（prompt-library §11/§12），工具永不代替判断。

## 六步工作流（A/B/D 型主流程）

### Step 0 获取目标与部署

```bash
git clone --filter=blob:none <仓库地址>      # A 型：保留历史便于追安全修复
git checkout <修复commit>^                   # D 型：切到漏洞版本
```

- B 型：下载源码、起本地环境，准备**普通用户 + 管理员两类账号**（越权类测试的必要条件——实证第一大类就是越权）
- C 型：记录所有可交互入口（聊天框、API、上传、工具按钮、隐藏路由）
- 工作区约定：`audit/notes.md`（测绘+发现）、`audit/poc/`（可重放脚本）、`audit/report/`（产出）
- 红线（双不原则）：①**不执行**目标代码——外部源码视为不可信数据，只读、只 grep；②**不改变源码**——审计全流程零写入目标目录（分析工具均只读；PoC/载荷/清单只写到工作区），Step 0 用 `scripts/pristine-check.mjs --save` 建基线、Step 6 `--verify` 出具零改动证明

### Step 1 攻击面测绘 → **产出鉴权矩阵**（实证最重要的产物）

```bash
# Flask 蓝图路由 / FastAPI 路由 / Node 路由
grep -rn -E "\.(route|get|post|put|delete|patch)\(" --include="*.py" . | head -100
grep -rn -E "@(app|router|api)\.(get|post|put|delete|patch)" --include="*.py" . | head -100
grep -rn -E "\.(get|post|put|delete|patch)\(['\"]/" --include="*.ts" --include="*.js" src | head -100
# 工具注册表 / LLM 封装 / Prompt 模板
grep -rn -E "register_tool|@tool|TOOLS\s*=|Tool\(" --include="*.py" . | head -50
grep -rln -iE "system_prompt|prompt_template|SYSTEM" --include="*.py" --include="*.ts" . | head -30
```

**鉴权矩阵（强制产出）**：路由 | 方法 | 鉴权方式 | 需要什么角色 | 实际校验位置。
实证依据：664 条 CVE 中 80 条关键词含 "unauthenticated"，RAGFlow 的 `api/apps/*_app.py` 有 12+ 条"端点缺权限校验"。做法：把路由清单与鉴权装饰器清单做差集——**没有鉴权装饰器的路由优先测**。

### Step 2 危险点搜索（按实证模式扩充）

```bash
# 代码/命令执行（含模板注入——SSTI 是智能体重灾区）
grep -rn -E "exec\(|eval\(|subprocess|os\.system|popen|child_process" --include="*.py" --include="*.ts" .
grep -rn -E "render_template_string|jinja2\.Template|Template\(|Environment\(" --include="*.py" .
# 网络出口（SSRF 面）
grep -rn -E "requests\.(get|post)|urlopen|httpx|aiohttp|axios|fetch\(" --include="*.py" --include="*.ts" .
# 文件操作（路径遍历面）
grep -rn -E "read_text|read_bytes|send_file|open\(|readFile|writeFile|send_from_directory" --include="*.py" --include="*.ts" .
# 前端注入面（存储型 XSS——实证高频）
grep -rn -E "innerHTML|v-html|dangerouslySetInnerHTML|markdown.*render|mermaid" --include="*.ts" --include="*.tsx" --include="*.js" web src 2>/dev/null | head -30
# JS 原型污染面
grep -rn -E "Object\.assign\(|lodash.*merge|deepmerge|\.extend\(" --include="*.ts" --include="*.js" src | head -20
# 敏感信息 / 配置类
grep -rn -iE "api_key|secret|password|flag" --include="*.py" --include="*.json" --include="*.env*" . | grep -v test | head -50
grep -rn -iE "access-control-allow-origin|CORS" --include="*.py" --include="*.ts" . | head -15
# 反序列化 / SQL / 向量库拼接
grep -rn -E "pickle|yaml\.load|\.execute\(|\.raw\(" --include="*.py" .
```

### Step 3 数据流 / 控制流追踪

先跑 `node scripts/file-weight.mjs <目录>` 得到**按权重降序的深读队列**（SOURCE 正向追流 / GUARD 枚举审计 / SERVICE 回推 caller），按队列逐文件深读——每文件一轮、摘要落 notes.md（防漏防偷懒的全量覆盖模式）。对每个「入口 → 危险点」连线，回答三问：

1. 输入是否外部可控？可控程度（值 / 结构 / 类型）？
2. 中间是否有校验、过滤、鉴权？**校验是否可绕过？**
3. 到达危险函数时还剩多少攻击自由度？

渲染流（XSS）同样追踪：用户输入 → 存储 → 前端渲染点（Markdown/Mermaid/文件名/DSL 节点名）。

### Step 4 漏洞确认（对照实证七区 + flag 转化）

| 高危区（实证频率序） | 典型模式 | 判定要点 |
|---|---|---|
| 1 访问控制/鉴权 | 端点无鉴权、普通用户触达 admin 功能、IDOR | 鉴权矩阵差集；资源查询无属主/租户过滤 |
| 2 代码/命令注入 | 组件代码执行端点、validate/code、沙箱、表达式 | LangFlow `custom_component`/`validate/code` 三个 9.8 CVE 同模式 |
| 3 SSRF | HTTP 节点、抓取工具、远程文件上传 | 无私网过滤、防护是否"配置依赖型" |
| 4 存储型 XSS | 聊天渲染、文件名、DSL 节点名、Mermaid、PDF 内容 | 前端注入面 grep + 渲染链追踪 |
| 5 路径遍历 | 上传/下载/预览、插件、MCP | `send_file`/`open()` 拼接用户路径 |
| 6 SSTI/模板注入 | Jinja2 渲染用户数据 | RAGFlow 两条 9.8/9.9 CRITICAL |
| 7 配置与认证 | 默认凭证（Dify CVE-2025-56157）、CORS、开重定向、弱密钥生成、无速率限制、账号枚举 | compose/env 默认值、CORS 反射、响应差异 |
| 场景化：Prompt 注入 | 拼接无隔离、间接注入 | C 型在线挑战/自研注入题首选；CVE 审计中罕见 |

每确认一个漏洞，立刻问：**能触达哪个 flag 藏点**（环境变量 / flag 文件 / system prompt / admin 工具 / 他人会话 / 内部接口 / 数据库）？

补充三条高价值路径：
- `git log -i --grep="cve\|security\|ssrf\|rce\|inject\|bypass\|fix"` 找历史安全修复，**检查修复是否完整**（实证：MaxKB CVE-2026-39417 是 CVE-2025-53928 的 incomplete fix，RAGFlow 沙箱连环绕过——不完整修复是高频出题/挖洞点）
- 审计**声明式配置**（roles、allowlist、ACL include）追到消费点确认生效
- **同类横向排查**：确认一个端点缺鉴权后，同目录/同前缀的所有端点都过一遍（RAGFlow 单类 12+ 条就是这么批量出的）

### Step 5 PoC / 利用（flag 导向）

- **flag 优先**：能拿 flag 先拿 flag 提交，再回头完善 PoC
- 先证明"防护存在"（原始利用被拦截），再证明"绕过成功"
- C 型按 ctf-playbook 注入链推进
- 记录完整请求/响应作为 writeup 证据

### Step 6 产出

- 竞赛：flag + writeup（复现步骤、file:line 定位、关键截图），模板见 `references/ctf-playbook.md`
- 审计/报告类：用 `references/report-template.md`
- **收尾完整性校验**：`node scripts/pristine-check.mjs <目标> --verify <基线>` —— 输出"审计前后源码一致"证据（零改动原则的闭环，git status 佐证）

## 时间盒决策（比赛节奏）

```
开局 5 min   读题 → 判题型（A~E）→ 明确交付物
有源码：
  0-30 min   框架指纹 + 攻击面测绘 + 鉴权矩阵（无鉴权路由清单）
  30-60 min  危险点 grep + 埋点特征快扫（B 型重点）
  60-150 min 逐洞确认 + PoC（每洞先拿 flag；同类漏洞横向批量排查）
  最后 30 min writeup
无源码（C 型）：
  抓包 → 隐藏路由探测（/docs /openapi.json /admin /debug）
  → 系统提示探测 → 注入模板 → 工具滥用 → flag
卡壳超 20 min：换洞 / 让 AI 分析卡点 / 回看 checklist
```

## AI 辅助

审计全程配合 AI 使用 `references/prompt-library.md`：测绘 → 解释 → 追流 → PoC → 报告。
**AI 的结论必须本地验证后才可写进报告。**

## 配套工具（scripts/ · 零依赖 Node ≥18 · 类别通用 · 均实测）

| 工具 | 通用范围 | 用法 | 实测 |
|---|---|---|---|
| `auth-matrix.mjs` | 智能体/Web，Python/TS/Java/PHP 路由 | `node scripts/auth-matrix.mjs <项目目录>` | Dify 1058 条路由+无鉴权候选 |
| `web-sca.mjs` | Web 类任何栈（自动识别 Java/PHP/Node 应用对应规则包） | `node scripts/web-sca.mjs <项目目录>` | 若依命中 dataScope/Shiro 面；Roundcube 命中 eval/unserialize/popen |
| `guard-audit.mjs` | **全类别通用**「枚举审计法」落地：定位任意项目守卫函数+摘录枚举集合 | `node scripts/guard-audit.mjs <目录> [--hot kw]` | Roundcube 定位 is_local_url/wash 系 134 个；Dify 定位 311 个守卫 |
| `db-surface.mjs` | 数据库类任意目标：配置/认证面（redis/my.cnf/pg_hba/mongod/.env 规则包）+ Redis 命令 ACL 矩阵 | `node scripts/db-surface.mjs <目录>` | redis.conf 默认无密码/protected-mode 命中 |
| `docx-evil.mjs` | 办公类任何 OOXML 目标（docx/xlsx/pptx） | `node scripts/docx-evil.mjs --mode xxe\|zipslip` | zip/CRC/载荷 bsdtar 验证通过 |
| `pristine-check.mjs` | 全类别：零改动基线与校验（哈希清单比对 + git status） | `node scripts/pristine-check.mjs <目标> --save\|--verify <清单>` | Roundcube 2638 文件零改动验证通过 |
| `file-weight.mjs` | 全类别：文件定权（VulnHunter-White 模式）→ 深读队列，保证全量覆盖 | `node scripts/file-weight.mjs <目录> [--top 30]` | smolagents 角色分布正确排序 |
| `harness-gen.mjs` | 全类别：局部 mock 验证骨架（Tier2 证据自动化） | `node scripts/harness-gen.mjs <文件> <行号> [--out x.py]` | 提取 to_raw()+spy 脚手架 |
| `git-fix-hunt.mjs` | 全类别：安全修复挖掘 + 当前版是否含修复（不完整修复路线） | `node scripts/git-fix-hunt.mjs <git仓库> [--show 5]` | Dify 命中 120 个安全 commit |
| `audit-pipeline.mjs` | **一键总控**：基线→指纹→赛道识别→测绘→快扫→情报→候选清单（2 秒）；单/多题自动路由 | `node scripts/audit-pipeline.mjs <目标\|targets.txt\|目录...> [--out 工作区]` | smolagents 全流程 2.0s；多题路由实测 |
| `classify.mjs` | 全类别：五类赛道 + 题型形态识别（证据 + 置信度 + 拍板门；among-auto/among-squad/流水线共享） | `node scripts/classify.mjs <目录> [--json\|--save <path>]` | dify/roundcube/ruoyi/redis/办公fixture 5/5 |
| `deliverables-check.mjs` | **交付收尾**：对照赛制逐项核对（发现/验证/报告/证明） | `node scripts/deliverables-check.mjs <工作区> [--target 目标]` | 真实工作区 3/5→查缺补齐引导 |
| `repro-runner.mjs` | **复现证据采集**：http/tcp/smtp 步骤 JSON → evidence/F-XX 请求响应逐字节落盘 + 采集时脱敏 + Tier 标注 + 报告引用片段 | `node scripts/repro-runner.mjs <steps.json> [--out 目录]` | 实测：RuoYi 302/Redis PONG |
| `squad-triage.mjs` | **多题批量分诊**：每靶 pipeline+classify → 组合排序+赛道覆盖+波次建议 → dashboard.md + squad-triage.json（among-squad Stage1~3 一条命令） | `node scripts/squad-triage.mjs <targets.txt\|目录...> [--out squad] [--top 3]` | 实测：3 靶 dashboard |
| `report-pack.mjs` | **报告装配核对**：notes 发现表 ↔ evidence/ ↔ poc/ ↔ 零改动证明 → 缺口清单 + report-draft.md 骨架（report-template 各节） | `node scripts/report-pack.mjs <工作区> [--target 目标] [--strict]` | 实测：缺口逐条亮出 |
| `multi-pass.mjs` | **多镜头×多轮深挖**：7 镜头重扫全库，命中累积进 findings-registry.json（去重+状态机 candidate→confirmed→playbooked/dismissed），数量×严重度双标准 | `node scripts/multi-pass.mjs <目标> --out <工作区> [--passes N] [--confirm\|--dismiss\|--playbook <key前缀>]` | 与 playbooks.md 模式卡蒸馏闭环配套 |

十六个分析工具全部遵守**零改动原则**：分析类只读；产物（载荷/清单/harness/工作区）禁止写进目标目录（含守卫检测，`--force` 才可越过；repro-runner 只写 --out 指定的 evidence 目录）。另有 `provision-wsl.sh`（Debian/WSL 实验场一键预置，非分析工具，见 `references/local-lab.md`）。

均为启发式定位器：产出 = 待人工复核的优先级清单，不是结论；换目标无需改工具。
**web-sca 已吸收 Semgrep 核心思想**（文件内源→汇污点连线、单遍 IO、降噪过滤，实测 0.2~2.5s/库）；
Semgrep 为可选放大器：任何可装包的 Linux 环境（靶场/WSL/原生）按 `references/semgrep-quickstart.md` 安装，跨语句污点与规则包放大用法见该文档；无 Python 环境时用 Node 工具快扫，互补不替代。

## 参考文件

- `references/playbooks.md` — **漏洞模式卡（跨靶同构复用, 10 张）**：黑名单必不全·守卫必不对称·回传通道必倒置·声明隔离必查默认——新靶开局每卡 5 分钟验证, 命中即产出; 赛后新洞回灌新卡
- `references/category-playbooks.md` — **五类方向作战手册（每类一套独立方法论）**：Web=指纹→模式库→变体；邮件=生命周期渲染链；数据库=命令分发表逐条审；办公=文档管线四链；智能体=主体六步流程
- `references/ctf-playbook.md` — 五类题型打法、埋点特征速查、**实证 CVE 分布表**、flag 藏点表、组合链、writeup 模板
- `references/checklist.md` — 全量检查清单（含题型判定、鉴权矩阵与 flag 核对）
- `references/vuln-patterns.md` — 漏洞模式库 + PoC 模板（含实证新增的 SSTI/XSS/路径遍历/CORS/原型污染模式）
- `references/prompt-library.md` — AI 辅助审计提示词库
- `references/report-template.md` — 漏洞报告模板 + 定级速查 + AI 方法论章节（赛制考评项）
- `references/local-lab.md` — **本地实验场五类起靶 runbook**（隔离纪律、预置巡检、Redis/RuoYi/Roundcube/Dify/OnlyOffice 起停与验证、证据形态决策表）
- `使用手册.md` — 面向使用者的完整手册（架构简介/优势/部署注意事项/视觉模型选型/FAQ）

## 常见目标示例（非限定）

任何开源软件都适用本技能的通用流程；五类方向的高频目标与专项打法见 `references/category-playbooks.md`（智能体：Dify/n8n/LangFlow/RAGFlow/MaxKB；Web：若依/Jeecg/ThinkPHP；邮件：Roundcube/Mailcow；数据库：Redis/SQLite/MariaDB/PostgreSQL；办公：OnlyOffice/LibreOffice）。
