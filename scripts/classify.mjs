#!/usr/bin/env node
// classify.mjs — 五类赛道 + 题型形态识别器（只读 · 零依赖 · 秒级）
// 用法: node classify.mjs <目标目录> [--json] [--save <输出.json>] [--max-files 4000]
// 原则: 识别器只给证据与置信度, 判类别由用户拍板（透明协议）——低置信/证据稀疏/无源码必停人工门
// 形态: A/B/E 可从目录检出; C(无源码在线挑战)/D(给定CVE编号) 需会话上下文, 由上层流程分流
// 消费方: among-auto(单题分派) / among-squad(批量分诊) / audit-pipeline(阶段0) 三方同源
import { readdirSync, statSync, readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, basename, resolve, dirname } from "node:path";

const args = process.argv.slice(2);
const ROOT = args[0];
if (!ROOT || !existsSync(ROOT)) {
  console.error("用法: node classify.mjs <目标目录> [--json] [--save <输出.json>] [--max-files 4000]");
  process.exit(1);
}
const JSON_MODE = args.includes("--json");
const saveIdx = args.indexOf("--save");
const SAVE = saveIdx >= 0 ? resolve(args[saveIdx + 1]) : null;
const mfIdx = args.indexOf("--max-files");
const MAX_FILES = (mfIdx >= 0 ? parseInt(args[mfIdx + 1], 10) : 0) || 4000;

const ROOT_ABS = resolve(ROOT);
const rel = (p) => p.slice(ROOT_ABS.length + 1).replace(/\\/g, "/");
const rootHas = (n) => existsSync(join(ROOT_ABS, n));

// ── 1. 只读遍历（跳过重型目录; 限流: 文件数/单文件大小/总字节） ──
const SKIP = new Set([".git", "node_modules", "vendor", "target", "build", "dist", ".venv", "venv", "__pycache__", ".idea", ".vscode", "coverage", "site-packages", ".next", ".nuxt"]);
const TEXT_EXT = new Set(["py","ts","tsx","js","jsx","mjs","cjs","vue","svelte","java","php","c","h","cc","cpp","cxx","hpp","go","rb","rs","cs","swift","kt","scala","sh","bat","ps1","sql","json","yml","yaml","toml","ini","cfg","conf","xml","html","proto","pl","lua","gradle","properties","env","md","txt"]);
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_TOTAL_BYTES = 96 * 1024 * 1024;

const files = [];
const specialConf = [];
let truncated = false;
(function walk(d, depth) {
  if (depth > 8) return;
  let es; try { es = readdirSync(d); } catch { return; }
  for (const e of es) {
    if (files.length >= MAX_FILES) { truncated = true; return; }
    if (SKIP.has(e)) continue;
    const p = join(d, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) { walk(p, depth + 1); continue; }
    const ext = (e.includes(".") ? e.split(".").pop() : "").toLowerCase();
    files.push({ p, ext, size: st.size });
    if (/^(redis\.conf|sentinel\.conf|my\.cnf|pg_hba\.conf|mongod\.conf|mongod\.yaml)$/i.test(e)) specialConf.push(rel(p));
  }
})(ROOT_ABS, 0);

// ── 2. 语言画像（弱先验: 标记证据主导打分, 语言只作边际调整） ──
const langOf = { py:"py", ts:"ts", tsx:"ts", js:"ts", jsx:"ts", mjs:"ts", cjs:"ts", vue:"ts", svelte:"ts", java:"java", php:"php", c:"c", h:"c", cc:"c", cpp:"c", cxx:"c", hpp:"c", go:"go", rb:"rb", rs:"rs", cs:"cs", kt:"kt", swift:"swift" };
const LANG = {};
let srcTotal = 0;
for (const f of files) { const g = langOf[f.ext]; if (g) { LANG[g] = (LANG[g] || 0) + 1; srcTotal++; } }
const langTop = Object.entries(LANG).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => `.${k} ${Math.round((v / (srcTotal || 1)) * 100)}%`);
const ratio = (g) => (srcTotal ? LANG[g] / srcTotal : 0);

// ── 3. 赛道标记库（[regex, 权重, 标签]; 计分 = 权重 × min(命中文件数, 10)——单文件库不放大） ──
const MARKERS = {
  agent: { label: "智能体", patterns: [
    [/langchain|llama[-_]?index|openai|anthropic|dashscope|qwen|zhipu|ollama|deepseek|bailian/gi, 8, "LLM SDK 依赖"],
    [/system[_-]?prompt|prompt[_-]?template|promptTemplate/gi, 6, "Prompt 模板"],
    [/@tool\b|register[_-]?tool|TOOLS\s*=|tool[_-]?registry|agent[_-]?executor|AgentExecutor|create[_-]?agent/gi, 6, "工具注册/Agent 执行器"],
    [/embedding|vector[_-]?store|milvus|chroma|qdrant|weaviate|pgvector|knowledge[_ ]?base|\brag\b/gi, 4, "RAG/向量库"],
    [/\bmcp\b|tool[_-]?call|function[_ ]?calling|chat\.completions/gi, 3, "LLM 调用链"],
  ]},
  web: { label: "Web", patterns: [
    [/THINK_VERSION|thinkphp|ruoyi|jeecg|shiro|fastjson|log4j|struts|spring[-_]?boot|SpringApplication/gi, 6, "Java 脚手架指纹"],
    [/HandlerInterceptor|implements\s+Filter|@Controller\b|@RestController|@RequestMapping|DispatcherServlet|WebMvcConfigurer/gi, 5, "Spring MVC"],
    [/mybatis|mapper\.xml|SqlSessionFactory|@DataScope/gi, 5, "MyBatis"],
    [/laravel|symfony|Illuminate\\|Route::(get|post|any)/gi, 4, "PHP 脚手架"],
    [/\$_(GET|POST|REQUEST|SERVER)\[/gi, 3, "PHP Web 入口"],
    // Node Web 服务（含非标准框架，如 TiddlyWiki 自研 core-server）——修复纯 JS 项目误判智能体
    [/createServer|http\.Server|https\.Server|requestHandler|\bexpress\s*\(|fastify|koa|\.listen\s*\(\s*(port|\d)|app\.(get|post|put|delete|use)\s*\(\s*['"\/]/gi, 5, "Node Web 服务"],
    [/routes?\/|router\.(get|post|put|delete)|@app\.route|res\.(send|json|end|writeHead)|req\.url/gi, 3, "HTTP 路由/响应"],
  ]},
  mail: { label: "邮件", patterns: [
    // 不收 bare "postfix"(算法记号误报: redis rax.c / duallistbox.js) 与 bare "envelope"(API 响应封装/图标名)
    [/rcube_|roundcube|zimbra|mailcow|dovecot|\bsieve\b/gi, 9, "邮件服务器指纹"],
    [/\besmtp\b|\bsmtp\b|\bimap\b|\bpop3\b/gi, 7, "邮件协议"],
    // 不收 mime[_-]?type(通用文件处理惯例, dify 414 文件误报)——只收邮件语境的 MIME 词
    [/maildir|message\/rfc822|\brfc822\b|mime[-_](decode|parse)|Mail_mime|multipart\/(mixed|alternative|related)/gi, 6, "MIME/邮件解析"],
    [/mail[_-]?from|rcpt[_-]?to|\bsendmail\b|\bmailbox\b|mail[_-]?transport/gi, 4, "邮件生命周期"],
  ]},
  db: { label: "数据库", patterns: [
    [/redisCommandTable|sql_parse|sqlite3?_api|postmaster|mongod\b|commandTable\b/gi, 9, "命令分发表/主进程"],
    [/\bredis-cli\b|MODULE LOAD|CONFIG SET|secure_file_priv|pg_read_file|COPY\s+FROM\s+PROGRAM/gi, 4, "危险命令面"],
    [/\bEVAL\b.{0,30}lua|lua_[a-z]+|replicaof|ACL\s+(CAT|LOG|USERS|SETUSER)/gi, 3, "Lua/ACL/复制面"],
    [/acceptTcpHandler|aeCreateFileEvent|wire[_ ]?protocol|command[_ ]?dispatch/gi, 3, "协议监听层"],
  ]},
  office: { label: "办公", patterns: [
    [/onlyoffice|libreoffice|documentserver|doc[ss]?[-_]?converter|x2t\b/gi, 9, "办公套件指纹"],
    [/\.(docx|xlsx|pptx)|ooxml|word\/document\.xml|\[Content_Types\]\.xml|workbook\.xml|presentationml|spreadsheetml/gi, 7, "OOXML 处理"],
    [/openpyxl|xlsxwriter|apache\s+poi|\bnpoi\b|aspose|phpoffice|phpspreadsheet/gi, 5, "文档处理库"],
    [/adm-zip|\bjszip\b|libarchive|yauzl|ZipEntry|zip[_-]?entry|unzipFile|extractAll/gi, 3, "zip 解压链"],
  ]},
};

// ── 4. 指纹（manifests/README 识别已知项目名） ──
const IDENTITY = [
  [/roundcube|rcube/i, "Roundcube"], [/zimbra/i, "Zimbra"], [/redis/i, "Redis"],
  [/thinkphp/i, "ThinkPHP"], [/ruoyi/i, "若依"], [/jeecg/i, "JeecgBoot"],
  [/\bdify\b|langflow|flowise|ragflow|maxkb|\bn8n\b|langchain|smolagents/i, "智能体平台"],
  [/onlyoffice/i, "OnlyOffice"], [/libreoffice/i, "LibreOffice"],
  [/\bdovecot\b|\bpostfix\b/i, "Dovecot/Postfix"], [/mariadb|mysql|sqlite|postgres|mongodb/i, "数据库"],
];
let identity = "?";
{
  const hay = [];
  for (const m of ["package.json", "pyproject.toml", "pom.xml", "composer.json", "README.md", "README.rst"]) {
    const p = join(ROOT_ABS, m);
    if (existsSync(p)) { try { hay.push(readFileSync(p, "utf8").slice(0, 8192)); } catch {} }
  }
  const h = hay.join("\n");
  for (const [re, name] of IDENTITY) { if (re.test(h)) { identity = name; break; } }
}

// ── 5. 题型形态（A/B/E 目录可检; C/D 上下文分流） ──
const hasGit = existsSync(join(ROOT_ABS, ".git"));
let commits = 0;
if (hasGit) {
  try { const r = spawnSync("git", ["-C", ROOT_ABS, "rev-list", "--count", "HEAD"], { encoding: "utf8", timeout: 15000 }); commits = parseInt((r.stdout || "").trim()) || 0; } catch {}
}
const hasLicense = rootHas("LICENSE") || rootHas("LICENSE.md") || rootHas("LICENSE.txt") || rootHas("LICENSE.rst");
const CONFIG_EXT = new Set(["json", "yml", "yaml", "toml", "xml"]);
const configRatio = files.length ? files.filter((f) => CONFIG_EXT.has(f.ext)).length / files.length : 0;
let form = "A", formNote = "";
if (srcTotal === 0 && files.length > 0 && configRatio >= 0.8) {
  form = "E"; formNote = "仅配置文件——人工确认是否 workflow/agent DSL（n8n JSON 等）";
} else if (hasGit && (commits > 20 || hasLicense)) {
  form = "A"; formNote = `git 历史 ${commits} commits${hasLicense ? " · 有 LICENSE" : ""}`;
} else if (srcTotal > 60) {
  form = "A"; formNote = `${srcTotal} 源文件（无 .git 以规模判开源型）`;
} else if (srcTotal > 0) {
  form = "B"; formNote = `小体量自研项目（${srcTotal} 源文件）`;
} else {
  form = "?"; formNote = "无源码/空目录——只有在线环境=C 型; 给定 CVE 编号=D 型";
}
// 伞仓库识别（.gitmodules 存在 + 工作树源码极少）：实际代码在子模块，需按 pin 补拉
let submodules = [];
if (rootHas(".gitmodules")) {
  try {
    const gm = readFileSync(join(ROOT_ABS, ".gitmodules"), "utf8");
    submodules = [...gm.matchAll(/path\s*=\s*(.+)/g)].map((m) => m[1].trim());
  } catch {}
  if (srcTotal < 30 && submodules.length) {
    form = "umbrella"; formNote = `伞仓库：${submodules.length} 个子模块（${submodules.slice(0, 4).join(", ")}${submodules.length > 4 ? "…" : ""}），工作树仅 ${srcTotal} 源文件——按 pin 提交补拉子模块到工作区再审计`;
  }
}

// ── 6. 标记扫描（只读文本, 计分 + 首次命中位置作证据） ──
const hits = {};
for (const cat of Object.keys(MARKERS)) hits[cat] = {};
let scanned = 0, scannedBytes = 0;
outer:
for (const f of files) {
  if (!TEXT_EXT.has(f.ext) || f.size > MAX_FILE_BYTES) continue;
  if (scannedBytes + f.size > MAX_TOTAL_BYTES) { truncated = true; break outer; }
  let content; try { content = readFileSync(f.p, "utf8"); } catch { continue; }
  scanned++; scannedBytes += f.size;
  for (const [cat, def] of Object.entries(MARKERS)) {
    for (const [re, w, label] of def.patterns) {
      const m = content.match(re);
      if (!m) continue;
      const h = hits[cat][label] || (hits[cat][label] = { files: new Set(), where: "" });
      h.files.add(rel(f.p));
      if (!h.where) {
        const idx = content.search(re);
        h.where = `${rel(f.p)}:${idx >= 0 ? content.slice(0, idx).split("\n").length : 1}`;
      }
    }
  }
}

// ── 7. 打分（标记主导 + 特殊文件 + 弱语言先验） ──
const score = {};
for (const cat of Object.keys(MARKERS)) {
  score[cat] = 0;
  for (const [label, h] of Object.entries(hits[cat])) {
    const w = MARKERS[cat].patterns.find((p) => p[2] === label)[1];
    score[cat] += w * Math.min(h.files.size, 10);
  }
}
if (rootHas("pom.xml")) score.web += 6;
if (rootHas("composer.json")) score.web += 3;
if (rootHas("Makefile") || rootHas("CMakeLists.txt")) { score.db += 2; score.office += 2; }
if (specialConf.length) score.db += 8;
if (ratio("c") >= 0.5) { score.db += 3; score.office += 2; }
if (ratio("php") >= 0.3) { score.mail += 2; score.web += 2; }
if (ratio("java") >= 0.5) score.web += 2;
// 删除纯语言比例(py+ts>=0.6→agent+1)的弱先验：曾致 TiddlyWiki(纯JS)误判智能体。
// 智能体判定必须由 LLM SDK / 工具注册 / LLM 调用链标记证据主导（见下方拍板门）。

// ── 8. 结果组装 ──
const DISPATCH = {
  agent:  { playbook: "among/SKILL.md 六步 + references/ctf-playbook.md", tools: "audit-pipeline → auth-matrix → git-fix-hunt", poc_form: "HTTP 请求 + Prompt 载荷", warning: "白盒优先鉴权矩阵+执行端点; Prompt 注入仅 C 型在线挑战主力" },
  web:    { playbook: "among/references/category-playbooks.md §一", tools: "web-sca → auth-matrix → guard-audit", poc_form: "HTTP 请求 (curl)", warning: "80% 脚手架: 指纹→版本CVE变体→只精读二次开发 20%; Java 鉴权在拦截器链" },
  mail:   { playbook: "among/references/category-playbooks.md §三", tools: "guard-audit → web-sca", poc_form: "SMTP 恶意邮件", warning: "攻击者=发件人/受害者=收件管理员: 打渲染时不打请求时; 一个守卫函数=一串洞" },
  db:     { playbook: "among/references/category-playbooks.md §四", tools: "db-surface → guard-audit", poc_form: "Socket 协议请求", warning: "C 层战略性放弃: 战场在认证层+命令分发表; 新命令忘打 ACL flag 是经典 0day" },
  office: { playbook: "among/references/category-playbooks.md §五", tools: "docx-evil → guard-audit", poc_form: "恶意文档 (crafted zip+xml)", warning: "管线四链: 解压/XML/内容/服务; LibreOffice 巨件只做 XXE/宏/解析库" },
};

const ranked = Object.entries(score).map(([key, s]) => ({ key, label: MARKERS[key].label, score: s })).sort((a, b) => b.score - a.score);
const total = ranked.reduce((t, x) => t + x.score, 0);
const prim = ranked[0];
const confidence = total > 0 ? Math.round((prim.score / total) * 100) / 100 : 0;
const secondary = ranked.slice(1).filter((x) => x.score >= 0.5 * prim.score && x.score > 0);
const gateReason = [];
if (prim.score < 15) gateReason.push(`证据稀疏(主赛道 ${prim.score} 分 < 15)`);
if (confidence < 0.5) gateReason.push(`置信度低(${confidence} < 0.5)`);
if (srcTotal === 0 && form !== "E" && form !== "umbrella") gateReason.push("无源码");
if (form === "umbrella") gateReason.push("伞仓库：先按 pin 补拉子模块再判赛道");
// 智能体判定须有 LLM/工具硬证据，否则强制人工复核（防纯语言/弱标记误判）
if (prim.key === "agent") {
  const strong = ["LLM SDK 依赖", "工具注册/Agent 执行器", "LLM 调用链"].some((l) => hits.agent[l]);
  if (!strong) gateReason.push("智能体判定缺 LLM SDK/工具注册/调用链硬证据——请人工复核是否实为 Web");
}

const evidence = {};
for (const cat of Object.keys(MARKERS)) {
  evidence[MARKERS[cat].label] = Object.entries(hits[cat])
    .map(([label, h]) => ({ marker: label, files: h.files.size, where: h.where }))
    .sort((a, b) => b.hits - a.hits).slice(0, 3);
}

const result = {
  target: ROOT_ABS.replace(/\\/g, "/"),
  form, form_note: formNote, submodules,
  identity, language: langTop, source_files: srcTotal, files_scanned: scanned, truncated,
  primary: { key: prim.key, label: prim.label, score: prim.score },
  confidence,
  secondary: secondary.map((x) => ({ key: x.key, label: x.label, score: x.score })),
  gate: gateReason.length > 0, gate_reason: gateReason,
  scores: Object.fromEntries(ranked.map((x) => [x.label, x.score])),
  evidence,
  dispatch: DISPATCH[prim.key],
};

// ── 9. 输出 ──
if (SAVE) { mkdirSync(dirname(SAVE), { recursive: true }); writeFileSync(SAVE, JSON.stringify(result, null, 2)); }
if (JSON_MODE) { console.log(JSON.stringify(result, null, 2)); process.exit(0); }

const BAR = "═".repeat(58);
const L = [];
L.push(`\n${BAR}\n  代码类型识别器 · ${basename(ROOT_ABS)}\n${BAR}`);
L.push(`形态判定: ${form} ${formNote}`);
L.push(`指纹: ${identity} · 语言: ${langTop.join(" / ") || "?"} · 源文件 ${srcTotal} · 扫描 ${scanned}${truncated ? "（已截断）" : ""}`);
L.push("赛道评分（证据加权, 单标记按命中文件数封顶 10）:");
const maxS = prim.score || 1;
for (const r of ranked) {
  const bar = r.score > 0 ? "█".repeat(Math.max(1, Math.round((r.score / maxS) * 12))) : "·";
  const tag = r === prim ? "  ← 主赛道" : (secondary.includes(r) ? "  ← 副赛道(双镜头)" : "");
  L.push(`  ${r.label}  ${bar.padEnd(12)} ${String(r.score).padStart(4)}${tag}`);
}
L.push(`置信度: ${confidence}${secondary.length ? ` · 混合靶: 副赛道 ${secondary.map((x) => x.label).join("/")}` : ""}`);
L.push("证据（主赛道 top）:");
for (const e of evidence[prim.label] || []) L.push(`  - ${e.marker} ×${e.files} 文件: ${e.where}`);
L.push("分派建议:");
L.push(`  playbook: ${result.dispatch.playbook}`);
L.push(`  工具链: ${result.dispatch.tools}`);
L.push(`  PoC 形态: ${result.dispatch.poc_form}`);
L.push(`  ⚠ ${result.dispatch.warning}`);
L.push(BAR);
if (result.gate) {
  L.push(`📌 拍板门(必停): ${gateReason.join("; ")} —— 由你确认或改判(五类任选), 依据是证据 file:line`);
} else {
  L.push(`📌 拍板门(常规): 默认 ${prim.label} —— 确认即走; 改判直接说类别名`);
}
L.push("   C/D 形态提示: 无源码只有环境=C 型在线挑战(直走 ctf-playbook §C); 给定 CVE 编号=D 型复现(git-fix-hunt)");
console.log(L.join("\n"));
