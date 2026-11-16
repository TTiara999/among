# 漏洞模式卡（Playbook）—— 跨靶同构复用

> 蒸馏自 smolagents v1.20.0 审计（24 条发现，2026-11）。
> 用法：换新靶（智能体框架/工作流引擎/沙箱类）时，每卡 5 分钟验证一轮，命中即产出。
> 原则：**黑名单必不全 · 守卫必不对称 · 回传通道必倒置 · 声明隔离必查默认**。
> 命中后用 multi-pass `--playbook <key>` 把对应候选标记为已蒸馏。

---

## PB-01 执行器回传通道反序列化

**找什么**：任何"沙箱/远端 → 宿主"的结果/异常回传通道，宿主侧对回传字节做 `pickle.loads` / `marshal.loads` / `numpy.load` / `torch.load`。
**检测**：grep `pickle.loads|marshal.loads` → 逐个核对数据流向：值是谁产生的？沙箱内不可信代码能否控制字节？
**判定**：开关仅是异常名/类型名 = 信任倒置 = 严重（沙箱一次 raise 即宿主 RCE）。
**已知实例**：smolagents F-1（E2B/Docker/Wasm 三执行器同型, remote_executors.py:183/399/602）。
**5 分钟验证**：在沙箱 payload 侧构造 `raise FinalAnswerException(b64(pickle(__reduce__=os.system)))`，mock 回包走宿主真实代码路径。
**同构预期**：LangFlow custom_component 回调、Dify 代码节点回传、n8n Function 节点返回值。

---

## PB-02 导入授权只查模块不查名字

**找什么**：import 白名单/授权检查——看它校验的是 `expression.module` 还是也校验 `expression.names`。
**检测**：grep `check_import|authorized_imports|allowlist` → 读 ImportFrom 分支：`state[name] = getattr(module, name)` 前有没有对 `name` 的过滤。
**判定**：无名字过滤 → `from <白名单模块> import __builtins__/__loader__/__spec__` 全部可绑定 → 严重。
**已知实例**：smolagents F-2（local_python_executor.py:1215-1232）；`__loader__.get_data(path)` = 任意文件读。
**5 分钟验证**：`from re import __builtins__` 是否报错；不报 = 命中。
**同构预期**：任何自制 Python 沙箱/REPL 限制器（Dify 沙箱、AutoGPT 执行器）。

---

## PB-03 危险函数黑名单缺项

**找什么**：黑名单数组（`DANGEROUS_*` / `FORBIDDEN_*` / `BLOCKED_*`）——逐项对照 Python 全量危险内建。
**检测**：grep 黑名单定义 → 对照清单：`open`、`exec`、`eval`、`compile`、`__import__`、`breakpoint`、`input`、`globals`、`locals`、`vars`、`dir`。
**判定**：缺 `open`（文件读写）或 `breakpoint`（交互逃逸）即高危；再查黑名单匹配是否可被 `__name__` 篡改绕过。
**已知实例**：smolagents F-3（8 项缺 `open`）+ F-11（`setattr` 可改 `__name__` 使黑名单按名匹配失效）。
**5 分钟验证**：沙箱内取 `__builtins__` 后逐键试哪个不被拦。
**同构预期**：一切 blacklist 制守卫（实证：黑名单必有漏网）。

---

## PB-04 守卫读写调不对称

**找什么**：每个守卫函数——读路径有检查，写路径（setattr/set_value）和调用路径（call/方法名）有没有对称检查。
**检测**：grep `startswith("__")` / dunder 检查 → 数它的调用点：表达式属性访问拦了，赋值目标拦了吗？方法调用拦了吗？
**判定**：任一侧缺失 = 策略可绕（高）；不对称还导致类图枚举/属性篡改。
**已知实例**：smolagents F-5（evaluate_call 不拦 `__subclasses__()` 调用）+ F-11（set_value 不拦 dunder 写）。
**5 分钟验证**：`x.__class__ = y` 赋值 / `str.__subclasses__()` 调用，任一不报错 = 命中。
**同构预期**：自制解释器/AST 求值器/模板引擎的属性守卫。

---

## PB-05 内部状态可覆写

**找什么**：解释器/会话的内部计数器、输出缓冲（`_counter` / `_print_outputs` / `_operations`）——不可信代码能否直接赋值重置。
**检测**：找 state dict 的写入分支（set_value Name）→ 检查是否只保护工具名、不保护下划线内部名。
**判定**：可重置 = DoS 防线失效（MAX_OPERATIONS 类上限全部作废）= 中；同一 state 跨会话共享 = 跨用户泄露 = 中。
**已知实例**：smolagents F-7（`_operations_count` 一行清零）+ F-23（Gradio 共享 agent 实例, state 从不重置）。
**5 分钟验证**：沙箱内 `_internal_var = 0` 赋值不报错 = 命中；UI 框架看 session 是否存引用非拷贝。
**同构预期**：一切带防线的解释器 + 一切共享实例的 Web UI。

---

## PB-06 隔离声明 vs 默认配置

**找什么**：文档/SECURITY.md 声明"隔离/沙箱"的组件 → 查默认参数是否真的隔离。
**检测**：声明处 grep `sandbox|isolated|secure` → 对照默认值：Docker 有无 `network=none`/`cap_drop`？UI 默认 `share=True`？`debug=True`？CORS `allow_origin='*'`？
**判定**：声明与默认不符 = 高（用户按声明信任，实际不隔离）。
**已知实例**：smolagents F-4（Docker 默认 bridge 网络）+ F-8（GradioUI 默认 share=True + debug=True）。
**5 分钟验证**：只读默认参数值，与文档声明对照。
**同构预期**：一切带 SECURITY.md 的沙箱类项目（实证高频：配置依赖型防护）。

---

## PB-07 无守卫网络出口

**找什么**：工具/节点发起的 HTTP 请求——URL 谁控制？有无私网过滤/超时/重定向限制？
**检测**：grep `requests.get|fetch|urlopen` → 核对：URL 来自 LLM/用户？有 `timeout`？有私网 IP 拒绝？
**判定**：URL 可控 + 无过滤 = SSRF（中）；无 timeout = 挂死 DoS（低）；响应回流上下文 = 全读型。
**已知实例**：smolagents F-6（visit_webpage）+ F-13/F-14（AgentAudio/搜索无超时）。
**5 分钟验证**：传 `http://127.0.0.1:port` 或 `http://169.254.169.254/` 看是否被拦。
**同构预期**：一切网页抓取/HTTP 节点工具（实证 ~9% CVE 属此类）。

---

## PB-08 路径拼接无清洗

**找什么**：从配置/JSON/远端取的名字（tool_name / agent_name / repo 名）直接拼进文件路径。
**检测**：grep `f"{...}.py" | / f"{name}" | join(folder, name)` → 名字来源是外部可控 JSON？有无 basename/字符白名单？
**判定**：`../` 逃逸后 read_text/exec = 低到中（取决于拼接后是否执行）。
**已知实例**：smolagents F-10（from_folder tool_name 遍历 → 任意 .py exec）。
**5 分钟验证**：JSON 里塞 `"../../x"` 看路径是否逃出目录。
**同构预期**：工作流引擎的节点名、插件加载器的模块名（实证 ~7% CVE 路径遍历类）。

---

## PB-09 机密导出通道

**找什么**：对象序列化/to_dict/日志——token/api_key 有没有被过滤后仍经旁路导出。
**检测**：grep `to_dict|serialize|dumps` → 看：显式字段排除了 token，那 `**kwargs` 呢？client_kwargs 呢？异常消息呢？CLI 参数呢？
**判定**：导出到会 push_to_hub/公开的产物 = 低到中（凭据泄露）。
**已知实例**：smolagents F-16（kwargs 通道）+ F-15（CLI --api-key 进程列表）。
**5 分钟验证**：构造带 `**kwargs` 机密的对象调 to_dict，看输出。
**同构预期**：一切带"保存/分享/导出"功能的 SDK。

---

## PB-10 LLM 可控输入直达汇点

**找什么**：LLM 生成的值（工具参数/代码/查询）不经校验直达危险汇点（XPath/SQL/shell/文件路径）。
**检测**：从工具入口正向追：`forward(self, x)` → `f"...{x}..."` 拼 XPath/SQL/命令？
**判定**：拼接即注入（低到中，视汇点威力）；提示注入可驱动 = 无需用户交互。
**已知实例**：smolagents F-17（XPath 注入）+ F-9（SpaceToolWrapper 把 LLM 路径上传远端）。
**5 分钟验证**：传 `' or '1'='1` / `') or ('1'='1` 类载荷看是否拼接执行。
**同构预期**：一切把 LLM 输出当参数传给解释器的框架（智能体重灾区）。

---

## 使用规程（每张卡）

1. **新靶开局**：10 张卡过一轮（≤50 分钟），命中处记入 notes.md 并 `--playbook <key>` 标记
2. **单卡深挖**：命中后按卡内"5 分钟验证"出 PoC
3. **赛后回灌**：新靶挖出的新模式 → 增补新卡（保持每卡 ≤15 行, 只写可复用的结构, 不写个案细节）
