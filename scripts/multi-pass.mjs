#!/usr/bin/env node
// 多镜头 × 多轮反复检测框架 —— 赛制: 数量 × 严重度双重标准
// 每次运行 = 一轮(可 --passes N 连跑 N 轮), 每轮用 7 个独立镜头重扫全库,
// 命中累积进 findings-registry.json(去重键: file:line|rule), 已确认条目跨轮保留并累计命中轮次。
// 登记库三层结构（事实-意图图, 学 sapper-v2）: fact(是什么) + intent(下一步) + status(状态机)
//   status: candidate(待确认) → confirmed(已确认) → playbooked(已蒸馏模式卡) | dismissed(已排除)
// 产物: findings-registry.json + findings-draft.md(按镜头分组, 标注状态) + tool-logs/multipass-pass<N>.log
// 零改动原则: 对目标目录只读; 全部产物只写工作区。
// 用法: node multi-pass.mjs <目标目录> --out <工作区> [--passes 3] [--modes sink,guard,...]
//       node multi-pass.mjs <目标目录> --out <工作区> --confirm <key前缀>   # 标记 confirmed
//       node multi-pass.mjs <目标目录> --out <工作区> --dismiss <key前缀>   # 标记 dismissed
//       node multi-pass.mjs <目标目录> --out <工作区> --playbook <key前缀>  # 标记 playbooked
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const args = process.argv.slice(2);
const TARGET = args[0];
if (!TARGET || !existsSync(TARGET)) { console.error("用法: node multi-pass.mjs <目标目录> --out <工作区> [--passes N] [--modes ...] [--confirm|--dismiss|--playbook <key前缀>]"); process.exit(1); }
const oIdx = args.indexOf("--out");
const WS = oIdx >= 0 ? resolve(args[oIdx + 1]) : resolve(".");
const passes = Math.max(1, parseInt((args[args.indexOf("--passes") + 1] || "1"), 10) || 1);
const mIdx = args.indexOf("--modes");
const modes = mIdx >= 0 ? args[mIdx + 1].split(",") : ["sink", "guard", "trust", "config", "deserial", "redos", "pathbuild"];
mkdirSync(join(WS, "tool-logs"), { recursive: true });

// ── 状态管理命令（--confirm/--dismiss/--playbook <key前缀>） ──
const STATUS_CMDS = [
  { flag: "--confirm",  status: "confirmed",  intent: "已确认 → 待入 notes.md 报告" },
  { flag: "--dismiss",  status: "dismissed",  intent: "已排除（负结果, 防复审计）" },
  { flag: "--playbook", status: "playbooked", intent: "已蒸馏为模式卡（references/playbooks/）" },
];
const statusCmd = STATUS_CMDS.find((c) => args.includes(c.flag));
const statusKeyPrefix = statusCmd ? args[args.indexOf(statusCmd.flag) + 1] : null;

// ── 镜头定义（每条规则: 唯一 id / 严重度提示 / 正则 / 目标后缀 / 判读要点） ──
const LENSES = {
  deserial: { name: "反序列化面（pickle/yaml/json 之外）", rules: [
    { id: "D-JSON",    sev: "中",   re: /json\.loads?\s*\((?!.*strict)/,                              ext: ".py", why: "json.loads 无 strict 标志 → 接受非标准 JSON（控制字符注入）" },
    { id: "D-MARSHAL", sev: "高",   re: /marshal\.loads?\s*\(/,                                         ext: ".py", why: "marshal 反序列化（代码对象）" },
    { id: "D-SHELVE",  sev: "中",   re: /shelve\.open\s*\(/,                                            ext: ".py", why: "shelve 底层用 pickle" },
    { id: "D-NUMPY",   sev: "中",   re: /np\.load\s*\(|numpy\.load\s*\(/,                               ext: ".py", why: "numpy.load 默认 allow_pickle=True → RCE" },
    { id: "D-TORCH",   sev: "中",   re: /torch\.load\s*\(/,                                              ext: ".py", why: "torch.load 默认用 pickle" },
  ]},
  redos: { name: "正则 ReDoS 面", rules: [
    { id: "R-NEST",    sev: "低",   re: /\(\?:?[^)]*\([^)]*\)\+\)|\(\?:?[^)]*\([^)]*\)\*\)/,            ext: ".py", why: "嵌套量词（ReDoS 经典模式）" },
    { id: "R-ORSTAR",  sev: "低",   re: /\(\?:[^)]*\|[^)]*\)\*/,                                         ext: ".py", why: "交替 + 星号（指数回溯）" },
    { id: "R-PLUSSTAR",sev: "低",   re: /\([^)]*\+\)\*/,                                                  ext: ".py", why: "加号组外带星号" },
    { id: "R-DOTSTAR", sev: "信息", re: /\.\*\?[^\n]*\.\*\?/,                                             ext: ".py", why: "双重懒惰 .\\*?（可能超线回溯）" },
  ]},
  pathbuild: { name: "路径构造面", rules: [
    { id: "P-JOIN",    sev: "低",   re: /os\.path\.join\s*\([^)]*\+/                                   , ext: ".py", why: "path.join + 字符串拼接（路径注入）" },
    { id: "P-FMT",     sev: "低",   re: /["'][^"']*\/[^"']*["']\.format\(|f["'][^"']*\/\{/,              ext: ".py", why: "f-string/format 路径拼接" },
    { id: "P-REALPATH",sev: "信息", re: /os\.path\.realpath\s*\(|Path\s*\([^)]*\)\.resolve\s*\(/,        ext: ".py", why: "realpath/resolve 可被符号链接绕过" },
    { id: "P-TEMP",    sev: "低",   re: /tempfile\.(mktemp|mkdtemp)\s*\(/,                               ext: ".py", why: "mktemp 已弃用（竞态）；mkdtemp 检查权限" },
  ]},
  sink: { name: "危险汇点全扫", rules: [
    { id: "S-EXEC",    sev: "严重", re: /\b(exec|eval)\s*\(/,                                        ext: ".py", why: "动态代码执行, 追输入来源是否 LLM/网络/文件" },
    { id: "S-SUBPROC", sev: "高",   re: /subprocess\.(run|Popen|call|check_output)\s*\(/,            ext: ".py", why: "进程创建, 核对参数可控性" },
    { id: "S-PICKLE",  sev: "严重", re: /pickle\.loads?\s*\(/,                                       ext: ".py", why: "反序列化, 核对方向(宿主侧 loads 不可信字节=逃逸)" },
    { id: "S-YAML",    sev: "中",   re: /yaml\.load\s*\((?![^)]*Loader)/,                            ext: ".py", why: "非安全 Loader 的 yaml.load" },
    { id: "S-NET",     sev: "中",   re: /requests\.(get|post|put|delete|head)\s*\(/,                  ext: ".py", why: "网络出口: 核对 URL 可控性/私网过滤/超时/重定向" },
    { id: "S-NOTIME",  sev: "低",   re: /requests\.(get|post)\([^)]*\)(?![^\n]*timeout)/,            ext: ".py", why: "无 timeout 的外呼(挂死/DoS)" },
    { id: "S-FILE-W",  sev: "中",   re: /\.(write_text|write_bytes|open)\s*\([^)]*["'w]/,            ext: ".py", why: "文件写入: 核对路径拼接是否外部可控(遍历)" },
    { id: "S-PIL",     sev: "低",   re: /PIL\.Image\.open\s*\(/,                                     ext: ".py", why: "不可信图像解码(解压炸弹/解析器漏洞)" },
  ]},
  guard: { name: "守卫不对称镜头(黑名单/读写不对称)", rules: [
    { id: "G-BLK",     sev: "中",   re: /\b(DANGEROUS|FORBIDDEN|BLOCKED|BLOCKLIST|BLACKLIST)[A-Z_]*\s*=/, ext: ".py", why: "黑名单式守卫: 枚举完备性(黑名单必有漏网)" },
    { id: "G-DUNDER",  sev: "高",   re: /startswith\(["']__["']\)/,                                   ext: ".py", why: "dunder 读检查: 核对是否存在对称的写/调用侧检查" },
    { id: "G-NAMECH",  sev: "中",   re: /check_import_authorized|_authorized|allowlist|whitelist/,    ext: ".py", why: "授权检查: 只查模块还是也查导入名/属性名" },
    { id: "G-SETATTR", sev: "中",   re: /setattr\s*\(/,                                                ext: ".py", why: "setattr 调用点: 属性名是否来自不可信数据/dunder 是否过滤" },
    { id: "G-EXCEPT",  sev: "低",   re: /except\s+(Exception|BaseException)\s*:\s*\n\s*pass/,          ext: ".py", why: "吞异常, 可能掩盖安全失败" },
  ]},
  trust: { name: "信任边界镜头(LLM输出/网络/文件 → 汇点)", rules: [
    { id: "T-LLMCODE", sev: "严重", re: /parse_code_blobs|code_action|action_blob|extract_code/,     ext: ".py", why: "LLM 输出→代码执行链上的每一跳" },
    { id: "T-TOOLCALL",sev: "高",   re: /tool_call|parse_tool|function_call/,                          ext: ".py", why: "LLM 工具调用解析: 参数是否经校验直接转发" },
    { id: "T-MD",      sev: "中",   re: /markdownify|BeautifulSoup|\.text\b/,                          ext: ".py", why: "网络内容→LLM上下文(间接注入) / 渲染(XSS)" },
    { id: "T-MCP",     sev: "高",   re: /StdioServerParameters|mcp\b/,                                 ext: ".py", why: "MCP: 子进程命令/工具名是否不可信可控" },
    { id: "T-REMOTE",  sev: "高",   re: /snapshot_download|hf_hub_download|from_code|from_folder/,    ext: ".py", why: "远端→本地执行链(供应链/遍历)" },
  ]},
  config: { name: "配置/机密镜头", rules: [
    { id: "C-CORS",    sev: "中",   re: /allow_origin|Access-Control-Allow-Origin|CORS/i,             ext: ".py", why: "CORS/来源放宽" },
    { id: "C-KEYLOG",  sev: "中",   re: /api_key|token|secret/i,                                       ext: ".py", why: "机密字段: 核对是否进日志/异常消息/文件" },
    { id: "C-VERIFY",  sev: "高",   re: /verify\s*=\s*False|CERT_NONE|sslopt/,                         ext: ".py", why: "TLS 校验关闭" },
    { id: "C-DEFAULT", sev: "中",   re: /password|passwd|secret_key|admin/i,                           ext: ".toml", why: "配置默认机密" },
    { id: "C-WF",      sev: "高",   re: /pull_request_target|\$\{\{\s*(github|head_ref|title)/,       ext: ".yml", why: "CI 表达式注入/危险触发器" },
    { id: "C-EXKEY",   sev: "中",   re: /(api_key|token)\s*=\s*["'][A-Za-z0-9_\-]{16,}["']/,          ext: ".py", why: "疑似硬编码凭据(含 examples)" },
  ]},
};

// ── 文件收集（只读遍历, 跳过 .git） ──
const files = [];
const walk = (d) => {
  for (const e of readdirSync(d)) {
    if (e === ".git" || e === "__pycache__") continue;
    const p = join(d, e);
    const s = statSync(p);
    if (s.isDirectory()) walk(p); else files.push(p);
  }
};
walk(TARGET);

// ── 登记库（跨轮累积, 事实-意图图三层结构） ──
const REG_PATH = join(WS, "findings-registry.json");
let registry = { created: new Date().toISOString(), entries: {} };
if (existsSync(REG_PATH)) { try { registry = JSON.parse(readFileSync(REG_PATH, "utf8")); } catch {} }

// 状态管理命令处理（更新匹配前缀的条目）
if (statusCmd && statusKeyPrefix) {
  let updated = 0;
  for (const key of Object.keys(registry.entries)) {
    if (key.includes(statusKeyPrefix)) {
      registry.entries[key].status = statusCmd.status;
      registry.entries[key].intent = statusCmd.intent;
      registry.entries[key].statusChangedAt = new Date().toISOString();
      updated++;
    }
  }
  writeFileSync(REG_PATH, JSON.stringify(registry, null, 2));
  console.log(`[状态更新] ${statusCmd.flag} "${statusKeyPrefix}" → ${updated} 条 → ${statusCmd.status}`);
  process.exit(0);
}

for (let pass = 1; pass <= passes; pass++) {
  const hits = [];
  for (const mode of modes) {
    const lens = LENSES[mode];
    if (!lens) continue;
    for (const f of files) {
      if (!f.endsWith(lens.ext ?? ".py")) continue;
      let lines;
      try { lines = readFileSync(f, "utf8").split("\n"); } catch { continue; }
      lines.forEach((text, i) => {
        for (const r of lens.rules) {
          if (r.ext && !f.endsWith(r.ext)) continue;
          if (r.re.test(text)) {
            const rel = relative(TARGET, f).replace(/\\/g, "/");
            const key = `${rel}:${i + 1}|${r.id}`;
            const e = registry.entries[key] || {
              key, file: rel, line: i + 1, rule: r.id, mode, sev: r.sev, why: r.why,
              excerpt: text.trim().slice(0, 140),
              // 三层结构（事实-意图图）: 新条目默认 candidate + 待确认
              fact: `[${r.sev}] ${r.why}`,
              intent: "待确认 → 读上下文判根因, 可确认则 --confirm",
              status: "candidate",
              firstPass: pass, passes: [],
            };
            e.passes.push(pass);
            e.lastSeen = pass;
            registry.entries[key] = e;
            hits.push(`${r.sev}\t${r.id}\t${rel}:${i + 1}\t${text.trim().slice(0, 100)}`);
          }
        }
      });
    }
  }
  writeFileSync(join(WS, "tool-logs", `multipass-pass${pass}.log`), hits.join("\n") || "(无命中)");
}

// ── 重写 findings-draft.md（按镜头分组, 标注状态, dismissed 单列负结果区） ──
const entries = Object.values(registry.entries).sort((a, b) => (a.sev.length - b.sev.length) || a.key.localeCompare(b.key));
const active = entries.filter((e) => (e.status ?? "candidate") !== "dismissed");
const dismissed = entries.filter((e) => e.status === "dismissed");
const STATUS_ICON = { candidate: "◻", confirmed: "✔", playbooked: "🃏", dismissed: "✗" };

let md = `# 候选发现登记库（多镜头 × 反复检测 · 事实-意图图 · 累积）\n\n> 目标: ${relative(WS, TARGET) || TARGET} · 轮次: ${passes} · 镜头: ${modes.join("/")}\n> 活跃 ${active.length} 条 + 已排除 ${dismissed.length} 条（去重键 file:line|rule）\n> 状态机: ◻ candidate → ✔ confirmed（--confirm）→ 🃏 playbooked（--playbook）| ✗ dismissed（--dismiss）\n\n`;
for (const mode of modes) {
  const lens = LENSES[mode]; if (!lens) continue;
  const group = active.filter((e) => e.mode === mode);
  if (!group.length) continue;
  md += `## 镜头 ${mode} · ${lens.name}（${group.length}）\n\n`;
  for (const e of group) {
    const st = STATUS_ICON[e.status ?? "candidate"];
    md += `- ${st} [${e.sev}] \`${e.file}:${e.line}\` ${e.rule} · 轮次${[...new Set(e.passes)].join(",")}\n    - fact: ${e.fact}\n    - intent: ${e.intent}\n    > ${e.excerpt}\n`;
  }
  md += "\n";
}
if (dismissed.length) {
  md += `## 已排除（负结果, 防复审计 · ${dismissed.length}）\n\n`;
  for (const e of dismissed) md += `- ✗ \`${e.file}:${e.line}\` ${e.rule} · ${e.intent}\n`;
  md += "\n";
}
writeFileSync(join(WS, "findings-draft.md"), md);
writeFileSync(REG_PATH, JSON.stringify(registry, null, 2));

const sevCount = {};
for (const e of active) sevCount[e.sev] = (sevCount[e.sev] || 0) + 1;
const stCount = { candidate: 0, confirmed: 0, playbooked: 0 };
for (const e of entries) { const s = e.status ?? "candidate"; if (stCount[s] !== undefined) stCount[s]++; }
console.log(`══════════ 多镜头反复检测 · ${passes} 轮完成 ══════════`);
console.log(`  镜头: ${modes.join(" / ")} · 文件: ${files.length}`);
console.log(`  累积: ${entries.length} 条（活跃 ${active.length}: ${Object.entries(sevCount).map(([k, v]) => `${k}×${v}`).join(" ")} · 已排除 ${dismissed.length}）`);
console.log(`  状态机: ◻待确认 ${stCount.candidate} · ✔已确认 ${stCount.confirmed} · 🃏已蒸馏 ${stCount.playbooked}`);
console.log(`  [✔] findings-registry.json（跨轮累积+状态） · findings-draft.md（分组+状态） · tool-logs/multipass-pass*.log`);
