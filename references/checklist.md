# 智能体审计/解题检查清单（通用）

按区域逐项检查，审计时把本表复制进 `audit/notes.md` 逐项打勾。

## 第零步 · 题型与框架判定
- [ ] 判定题型：A 开源审计 / B 自研靶场 / C 在线挑战 / D CVE 复现 / E 配置审计
- [ ] 框架指纹：LangChain 系 / Flask / FastAPI / Express·Node / 平台型（多服务 compose）/ 工作流配置 / 自研小项目
- [ ] 明确交付物：flag / writeup / PoC / 审计报告
- [ ] 有环境：确认可达；准备**普通用户 + 管理员**两类账号（越权类测试的必要条件）
- [ ] 无源码（C 型）：抓包记录请求结构；探测隐藏路由（/docs /openapi.json /admin /debug）
- [ ] **建零改动基线**：`node scripts/pristine-check.mjs <目标> --save <清单路径>`（清单放工作区，不放目标内）

## A. 入口层（鉴权矩阵 = 第一优先）
- [ ] **产出鉴权矩阵**：路由 | 方法 | 鉴权 | 所需角色 | 校验位置（实证：664 条 CVE 中 80 条含 unauthenticated）
- [ ] 做差集：无鉴权装饰器/中间件覆盖的路由 → 优先逐个测
- [ ] 同类横向：发现一个端点缺权限校验后，同目录/同前缀全部端点过一遍（RAGFlow 单类 12+ 条模式）
- [ ] 标注每个路由的鉴权方式（无鉴权 / Token / Session / API Key / 签名）
- [ ] 找出"内部专用"路由（仅 localhost / 仅内网 / debug 前缀 / inner_api）
- [ ] 文件上传接口：类型校验、大小限制、存储路径是否可控
- [ ] 未在公开文档中出现的隐藏路由（grep 路由装饰器 vs 官方文档）
- [ ] 服务 API（对外 key 鉴权）与控制台 API 的权限边界是否清晰

## B. Prompt 拼接区
- [ ] 找到所有 Prompt 模板（f-string、format、Jinja、string.Template）
- [ ] 确认用户输入是否直接进入模板
- [ ] 是否有输入转义 / 长度限制 / 特殊字符过滤
- [ ] 多轮对话历史是否可被用户注入污染（记忆投毒）
- [ ] 工具返回结果（网页、检索文档）是否直接拼进 Prompt（间接注入面）
- [ ] 能否诱导输出系统提示词 / 密钥（信息泄露）

## C. 工具分发区
- [ ] 列出工具注册表（名称、功能、参数 schema、允许角色/租户）
- [ ] 工具调用入口是否鉴权
- [ ] 权限声明是否真的被强制执行（重点找"声明了 roles/tenant 但 invoke 不校验"的模式）
- [ ] tool_name / arguments 是否客户端可控
- [ ] 参数是否有类型与取值校验（能否注入命令、路径、URL）
- [ ] 管理员工具与普通工具是否隔离
- [ ] 工具凭证（API Key）存储与注入方式是否安全

## D. 代码执行区
- [ ] 是否存在 exec/eval/子进程执行用户或 LLM 生成的代码
- [ ] 沙箱是黑名单还是白名单
- [ ] 黑名单绕过测试：`__import__`、importlib、builtins 拼接、pathlib 读写、字符串拼接
- [ ] 是否限制文件系统、网络、环境变量访问
- [ ] 资源限制（超时、内存）是否存在
- [ ] 沙箱是否独立进程/容器（与主服务同进程 = 高危）

## E. 网络请求区（SSRF）
- [ ] 列出所有可由用户控制 URL 的功能（Webhook、网页抓取、导入、头像、HTTP 节点）
- [ ] 是否过滤私网 IP / 127.0.0.1 / 169.254.169.254 / IPv6 映射地址
- [ ] 是否限制协议（file://、gopher://、dict://）
- [ ] 重定向是否跟随（可绕过 IP 校验）
- [ ] DNS rebinding 可能性（先解析后校验 vs 校验后再请求）
- [ ] 请求是否携带内部凭证（云 metadata、内部服务头）
- [ ] 校验的是域名还是解析后的 IP
- [ ] 防护是否"配置依赖型"（默认关闭/代理可选时等于无防护）

## F. 权限与会话区
- [ ] 资源 ID（会话、工作流、知识库、文件、凭证）是否校验属主
- [ ] 普通用户能否触达管理员接口
- [ ] 多租户隔离（tenant_id 是否在所有查询中强制过滤）
- [ ] API Key 的作用域（app 级 / 租户级）是否在每条查询中生效
- [ ] Token 生成强度、过期、撤销；比较是否常量时间（`hmac.compare_digest` vs `==`）
- [ ] 认证原语是否使用客户端提供的密钥/材料验签（自签通过型缺陷）
- [ ] 内部接口的"仅本机"校验能否被 SSRF 绕过
- [ ] 部署默认密钥是否硬编码在公开仓库/模板中

## G. 数据与配置区
- [ ] 密钥是否硬编码 / 提交进仓库 / 出现在 debug 接口
- [ ] 错误响应是否泄露堆栈、路径、SQL（debug=True？）
- [ ] 日志是否记录敏感内容（Prompt、密钥）
- [ ] 向量库 / RAG 文档解析（XXE、zip 解压路径遍历、超大内存）
- [ ] 反序列化点（pickle / yaml.load / 对象存储回调）
- [ ] 声明式配置（roles、allowlist、ACL include）追到消费点确认真的生效

## G2. 渲染与配置注入面（实证高频补充）
- [ ] Jinja2/SSTI：`Template(`、`render_template_string` 是否拼用户输入；是否用 SandboxedEnvironment
- [ ] 存储型 XSS：用户输入 → 存储 → 前端渲染链（`v-html`/`innerHTML`/`dangerouslySetInnerHTML`/Markdown/Mermaid/文件名/DSL 节点名）
- [ ] CORS：Origin 是否反射 + `Allow-Credentials: true`；`after_request` 全局加头
- [ ] 开放重定向：`redirect(request.args[...])`
- [ ] JS 原型污染：`merge`/`Object.assign`/deepmerge 合并用户 JSON，是否拦 `__proto__`/`constructor`
- [ ] 向量库/数据库拼接：MyScale、RunSQL 类接口是否拼接用户 SQL（Dify/RAGFlow 均有实证）
- [ ] 登录/找回密码：限速、账号枚举（响应差异）、token 熵、默认凭证（compose/env）

## H. 组合链思考（把单个发现串成高危链）
- [ ] SSRF + 内部无鉴权接口 = ？
- [ ] 任意文件读 + 配置文件中的密钥 = ？
- [ ] Prompt 注入 + 工具调用 = ？
- [ ] IDOR + 会话记录中的敏感内容 = ？
- [ ] 沙箱逃逸 + 同网络的其他服务 = ？

## I. flag 藏点核对（每确认一个漏洞就过一遍）
- [ ] 环境变量（FLAG=...）
- [ ] /flag* 文件
- [ ] system prompt 内
- [ ] admin-only 工具的返回值
- [ ] 其他用户的会话/上传文件
- [ ] 内部接口/云 metadata
- [ ] 数据库表
- [ ] 响应头/报错堆栈
- [ ] Agent 记忆
