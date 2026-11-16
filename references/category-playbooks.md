# 五类方向作战手册（每类一套独立方法论）

> 赛制：办公/数据库/智能体/邮件/Web 五类各一题。
> **核心认知：五类的"审计对象"根本不同，用同一套打法套五题必然低效。**

| 类 | 审计对象 | 方法论核心 | PoC 形态 |
|---|---|---|---|
| Web | 路由（但 80% 是脚手架） | 指纹→模式库→找变体 | HTTP 请求 |
| 智能体 | LLM 控制流 | 六步流程+鉴权矩阵（见主体） | HTTP + Prompt 载荷 |
| 邮件 | 一封邮件的生命周期 | 渲染链 XSS 追踪 | SMTP 发恶意邮件 |
| 数据库 | 命令（分发表） | 命令表逐条审权限位与校验 | Socket 协议请求 |
| 办公 | 文档解析管线 | 四链：解压/XML/内容/服务 | 构造恶意 .docx |

优先级（0 基础 × 模式固化度）：**Web > 智能体 > 邮件 > 数据库 > 办公**

> **C/C++ 靶验证分级（数据库/邮件/办公常见，2026-11 练习校准）**：
> - **能编译**（KeyDB/OpenSMTPD 等，备齐 dev 头见 local-lab §〇）→ 起实例做 Tier3 环境级 + `repro-runner --repeat 5` 锁稳定性。KeyDB 7 洞、OpenSMTPD F-01 走私均如此验证。
> - **不能全量编译**（LibreOffice basic 需整个 LO）→ **Tier2 组件级**：`harness-gen.mjs <文件> <行号>` 抽取漏洞函数，链接真实 `.o`（如 OpenSMTPD `to.o`）+ stub 构造输入证明崩溃/越界（实证 F-02 `text_to_userinfo` 组件级 5/5 stack smashing）。如实标 Tier2，不伪装 Tier3。
> - **纯静态**→ Tier1，m5 稳定性封顶 3，标注"待靶场 5 连测"。
> - **CRLF 坑**：Windows 检出副本编译前 `sed -i 's/\r$//' *.sh`（不改目标）；跨平台零改动校验用 `pristine-check --normalize-crlf`。
> - **分叉靶缺失 CVE**：KeyDB←Redis 等分叉，上游已修但分叉未合入的 CVE 仍在（git-fix-hunt 缺失 CVE 提示）——这是 C/C++ 数据库靶的高产路线。

---

## 一、Web 类：指纹 → 模式库 → 变体（不是从零审计）

**经验定位**：Java/PHP 脚手架项目 80% 代码是框架模板，**不要全读**——得分来自"版本已知漏洞的变体"和"出题方二次开发的部分"。

### 打法四步
1. **指纹定版本**：`pom.xml` / `composer.json` / 框架版本常量（ThinkPHP `THINK_VERSION`）→ 锁定该版本全部已知 CVE
2. **版本对照找变体**：取已知 CVE 的修复 commit → diff 目标源码 → 三种结果：没修（直接复现，交变体报告）、修了但不完整（换路径绕过 = 0day）、同步修了（放弃）
3. **差异审计**：只精读二次开发的业务 Controller/Service——出题方自己写的 20% 才埋新洞
4. **通用探针**：`/druid /actuator /swagger /api-docs` 直接访问

### Java 专属经验（与 PHP 完全不同）
- **鉴权不在 Controller 里**，在拦截器链/注解——矩阵做法变成：列出所有 Interceptor/Filter 覆盖的路径前缀 → 找未被覆盖的 Controller
- MyBatis 只扫 XML 里的 `${}`（`#{}` 是预编译安全的）；若依 `@DataScope` 数据权限拼接是重灾区
- 反序列化三入口：Shiro `rememberMe`、fastjson `parseObject`、各种 RPC/消息端口
- 模板引擎（Thymeleaf/Freemarker/Velocity）接受用户输入 = SSTI

### 实证 + 工具校准（若依修复史与实测）
- 若依 112 条 = 越权 17 + 默认特权 12 + 路径遍历 10 + SQLi 7；样本：CVE-2022-23869（无权限重置他人密码）
- **DataScope 逻辑边界洞**（修复 commit 292ac30a）：`@DataScope` 多角色场景下所有角色都不含权限字符时 `sqlString` 为空 → 用户获得**全部数据权限**——不是 `${}` 拼接本身，是权限构造的边界条件
- 修复史同款模式：SQL 关键字**黑名单**过滤（commit 167970e5）→ 绕过思路：大小写/编码/注释/同义函数
- 工具 `scripts/web-sca.mjs（Java 规则包）` 实测命中：`params.dataScope` 拼接（SysUserMapper 等 6 处）、`ShiroConfig.java:377 setCipherKey(Base64.decode(...))` 硬编码密钥路径、`JobInvokeUtil.invokeMethod`（quartz 定时任务 RCE 面）

---

## 二、智能体类：LLM 控制流审计（已有深备，不重复）

**经验定位**：唯一有"不可预测中间组件"（LLM）的类。白盒打法 = **SKILL.md 主体六步 + 鉴权矩阵 + 实证七区**（31% 是访问控制、23% 是执行类端点）。Prompt 注入载荷只在在线挑战场景用。见主体与 ctf-playbook。

---

## 三、邮件类：邮件生命周期数据流（XSS 主战场）

**经验定位**：审计对象不是路由，是**一封邮件的完整旅程**。实证明确：Roundcube 140 条中 XSS 占 47、Zimbra 183 条中 XSS 占 83——**邮件正文就是存储型 XSS 载荷**。

### 邮件生命周期（挂在每一站打）
```
SMTP 收信 → 队列/过滤 → 存储(maildir) → webmail 读取 → HTML 清洗(wash) → 浏览器渲染 → 用户动作(点链接/取远程图片/开附件)
```

### 打法：渲染链追踪 → 升级为「枚举审计法」（实证校准）

**实证依据**：Roundcube 真实修复史（git log）显示 `is_local_url()` 被 **8 个不同绕过连续修复**（NAT64 64:ff9b::/96 → 6to4 2002::/16 → 十六进制 IPv6-mapped → trailing-dot FQDN → nip.io/sslip.io 两轮 → CGN/链路本地），FuncIRI 修复带 "again" 标记=不完整修复。**同一防护函数的边际收益极高：一个函数=一串洞。**

1. **定位防护函数**（工具 `scripts/guard-audit.mjs` 直接定位）：`rcube_washtml::wash/wash_uri/wash_attribs`、`rcube_utils::is_local_url/mod_css_styles`
2. **列出它枚举的每个集合，找漏枚举的边角**：
   - IP 形态全家桶：NAT64、6to4、IPv6-mapped 十六进制、尾点 FQDN、nip.io/sslip.io、CGN 100.64/10、fe80::/10
   - 属性全家桶：SVG SMIL 只查 `to/from` 漏 `by`/`src`
   - 转义全家桶：CSS `url()` 的所有转义形态、未闭合 url()、`@layer`/at-rule 边界
3. **检查用户动作环节**：链接点击 CSRF token、远程图片 SSRF、ImageMagick 格式链（SVG/EPS 可引用外部资源，实证 CVE-2026-114727）
4. **补充载荷面（实证）**：邮件头注入（Bounce 动作/display-name 控制字符 CVE-2026-114726/25）、附件 MIME type XSS、TNEF zero-click XSS、PHP `rcube_session::unserialize()` 对象注入、**插件生态**（twofactor_gauthenticator 三连：暴破无限速/会话不销毁/IP 头伪造）

### 与 Web 类的本质区别（经验要点）
攻击者是**发件人**，受害者是**收件的管理员**——打"渲染时"不打"请求时"。一个 XSS 拿到管理员会话 = 接管 webmail = 读所有邮件。

### PHP 专属 grep
```bash
grep -rn "unserialize\|include.*\$\|require.*\$\|move_uploaded_file\|shell_exec\|passthru" .
```

### 实证样本
Roundcube XSS 47 条 + 未授权资源 12 + CSRF 6；Zimbra XSS 83 + CSRF 12 + SSRF 8 + XXE 5（Zimbra 的 XXE 在其解析路径里，别忘了这条副线）。

---

## 四、数据库类：命令分发表驱动（跳过 C 内存层）

**经验定位**：数据库的"路由"是**命令**，审计单位 = 分发表里的一条命令。C 层溢出（整数溢出 21/堆溢出 10，Redis 实证）是 CVE 记录大头但 0 基础打不了——**你的战场在认证层和命令层**。

### 请求生命周期
```
客户端连接 → 认证握手 → 命令分发表(name→handler + 权限flags) → 命令处理函数(输入校验) → 副作用(文件/模块/复制/子进程)
```

### 打法：分发表逐条审
1. **找分发表**：
   - Redis：`server.c` 的 `redisCommandTable[]`——每条命令的 flag（admin/writing/dangerous）
   - MariaDB：`sql_parse.cc` 的命令分发与权限检查宏
   - SQLite：sqlite3 API 层与扩展加载开关
   - PostgreSQL：进程/权限模型 + `COPY PROGRAM` 系
2. **每条命令审三件事**：权限标记位是否正确（**新增命令忘打 flag 是经典 0day**）、输入校验、副作用面
3. **认证路径单独过**：握手比较逻辑（MariaDB CVE-2012-2122——memcmp 型缺陷导致知道用户名即可登录，是"认证层白盒"的教科书）
4. **副作用链**：Redis `CONFIG SET dir/dbfilename`→任意写、`MODULE LOAD`、`EVAL` Lua 沙箱黑名单完整性、复制协议

### 数据库专属经验（他类不适用）
- **修复是逐命令打补丁**：同一 helper 函数被 N 个命令共用时，修一漏九——diff 一个命令的修复，把用同一 helper 的命令全列出来横向试
- **模块生态同根因批量**（实证）：RESTORE 序列化值校验缺陷同时存在于 redis-server（CVE-2026-25243）、RedisTimeSeries（25588）、RedisBloom（25589）——核心+模块都要过一遍
- Redis：命令表新增命令常忘 ACL 分类（工具 `scripts/db-surface.mjs` 实测 Redis 8：EVAL/SCRIPT 全家族无 ADMIN 标记、BLESS 系列新命令无标记——正是该模式候选）；Lua 沙箱看黑名单是否漏 `loadlib`/字符串构造
- MariaDB：UDF/plugin 目录权限、FILE 权限与 `secure_file_priv` 边界
- PostgreSQL：`COPY TO/FROM PROGRAM` 的 superuser 校验、`pg_read_file` 系列

### PoC 形态
Socket 协议请求（redis-cli / mysql 协议报文），不是 HTTP。

---

## 五、办公类：文档管线审计（文件即攻击面）

**经验定位**：输入不是 HTTP 请求，是**文档文件本身**。`.docx/.xlsx = zip + xml`，审计单位 = 管线上的每一站。OnlyOffice（Node）优先，LibreOffice（C++）只打配置与 XXE 面。

### 文档管线（四条攻击链）
```
上传 → 转换服务(converter) → 解压(zip) → XML 解析 → 内容执行(公式/宏) → 渲染
```

| 链 | 审什么 | 实证 |
|---|---|---|
| 解压链 | zip 成员路径校验 → **zip-slip 任意写** | OnlyOffice CVE-2020-11536（unzip 重写二进制） |
| XML 链 | 实体解析配置 → **XXE/XML 注入** | OnlyOffice CVE-2020-11535；LibreOffice libraptor CVE-2012-0037 |
| 内容链 | 公式 `=DDE`/宏默认安全级别 | CSV 注入类（若依 CVE-2022-23868 同家族） |
| 服务链 | converter 的 URL 参数（SSRF）、文件名→`child_process`（命令注入）、JWT 默认密钥 | OnlyOffice JWT secret 默认值模式 |

### PoC 形态（与所有类都不同）：构造恶意文档
```bash
# 解开 docx、改内部成员、重新打包 = 你的"请求"
unzip normal.docx -d doc/ && cd doc
# ① zip-slip 载荷：把成员路径改成 ../../../../etc/cron.d/evil
# ② XXE 载荷：在 word/document.xml 注入
#    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag">]><w:t>&xxe;</w:t>
zip -r ../evil.docx . && cd ..
```

### LibreOffice（C++ 巨件）只做三件事
XXE 配置（filter 用的 XML parser 初始化）、宏安全默认值、与 Redland/raptor 类解析库的实体开关——其余（缓冲区溢出 787/119 系）战略性放弃。

---

## 收尾对照：五类 PoC 形态速记

| 类 | 你最终"发"出去的东西 |
|---|---|
| Web | 一个 HTTP 请求（curl） |
| 智能体 | 一条消息/Prompt + 一次工具调用 |
| 邮件 | 一封恶意邮件（SMTP 投递） |
| 数据库 | 一段协议报文（socket） |
| 办公 | 一个恶意文档文件（crafted zip+xml） |

赛前情报（各类真实 CVE 分布）：`practice/audit/cve-research/category-cheatsheet.md`
