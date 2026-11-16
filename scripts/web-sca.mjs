#!/usr/bin/env node
// Web 类多栈扫描器 + 文件内污点连线（Semgrep 思想的轻量实现）
// 用法: node web-sca.mjs <项目目录>
// 设计(吸收 Semgrep 三大优势, 保持零依赖):
//   ① 污点连线: source(request/$_GET/req.query) → 汇(exec/eval/网络/文件) 文件内一跳传播, 输出"⚡高置信"优先级
//   ② 单遍 IO: 每文件只读一次, 全部规则共享缓存
//   ③ 降噪: 跳过注释行/常量实参/大文件/压缩文件
// 只读保证（零改动原则）: 只做 readdir/readFile/stat，绝不向目标目录写入任何文件
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.argv[2];
if (!ROOT) { console.error("用法: node web-sca.mjs <项目目录>"); process.exit(1); }

// ---------- 单遍 IO 缓存 ----------
const cache = new Map();
const readLines = (f) => {
  if (!cache.has(f)) {
    let st; try { st = statSync(f); } catch { cache.set(f, null); return null; }
    if (st.size > 512 * 1024) { cache.set(f, null); return null; } // 大文件跳过(速度)
    cache.set(f, readFileSync(f, "utf8").split(/\r?\n/));
  }
  return cache.get(f);
};
const rel = (f) => f.replace(/\\/g, "/");

function* walk(dir, depth = 0) {
  if (depth > 8) return;
  let entries; try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (/node_modules|\.git|target|dist|vendor|\.min\.|locale|tests?\b|docs?\b|examples?\b|e2e/i.test(e)) continue;
    const p = join(dir, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, depth + 1);
    else yield p;
  }
}

// ---------- 栈识别 ----------
const files = [...walk(ROOT)];
const stacks = new Set();
let composer = null, pkg = null;
for (const f of files) {
  const b = f.split(/[\\/]/).pop();
  if (b === "pom.xml" || b.endsWith(".java")) stacks.add("java");
  if (b === "composer.json") { stacks.add("php"); composer = f; }
  if (b === "package.json") { stacks.add("node"); pkg = f; }
  if (b.endsWith(".php")) stacks.add("php");
  if (/\.(ts|tsx|js)$/.test(b)) stacks.add("node");
  if (b.endsWith(".py")) stacks.add("py");
  if (/\.(c|cpp|cc|cxx|h|hpp|hxx)$/.test(b)) stacks.add("c");
}
console.log(`# Web 多栈扫描(含污点连线) —— ${ROOT}`);
console.log(`# 技术栈: ${[...stacks].join(", ") || "未知"} · 文件数 ${files.length}\n`);

// ---------- 污点引擎定义 ----------
const SRC_DIRECT = /\$_(GET|POST|REQUEST|FILES|COOKIE)|request\.(args|form|json|get_json|values|files|data|query|body|params|getParameter|getHeader|getQueryString)|req\.(query|body|params|headers)|ctx\.request|request\.GET|request\.POST|\binput\s*\(|sys\.argv|args\[|event\.(body|queryStringParameters)/;
// C/C++ 输入源（网络/参数/环境/标准输入）——用于文件内污点连线
const C_SRC = /\bargv\s*\[|\bgetenv\s*\(|\brecv(from)?\s*\(|\bfgets\s*\(|\bfread\s*\(|\bscanf\s*\(|\bsscanf\s*\(|\bgetline\s*\(|->(query|body|params|headers)|\breq->|\binput\b|\bpayload\b/;
// C/C++ 额外危险信号（无调用实参的配置/标志）：XXE 外部实体、zip-slip 路径拼接
const C_EXTRA = /XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_DTDVALID|xmlSubstituteEntities|xmlLoadExtDtd|\.\.[\\/]|zipEntry|unzip|extractTo|inflate.*path/i;
const ASSIGN = /^\s*(?:\$?(\w+)|(?:const|let|var|final|String|int)\s+(\w+))\s*=\s*([^;]{1,160});?\s*$/;

const SINKS = {
  php: /\b(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|unserialize|file_put_contents|mysqli_query)\s*\(\s*([^);]{0,90})|(?:->|::)(query|execute|exec)\s*\(\s*\$?([^);]{0,90})|^\s*(include|require)(?:_once)?\s*\(?\s*(\$?\w+)/,
  py: /\b(eval|exec|compile)\s*\(\s*([^);]{0,90})|os\.(system|popen|exec\w*)\s*\(\s*([^);]{0,90})|(subprocess\.(run|call|Popen|check_output)|requests\.(get|post|put|delete)|urlopen|httpx\.(get|post))\s*\(\s*([^);,]{0,90})|\.execute\s*\(\s*([^);,]{0,90})|open\s*\(\s*([A-Za-z_$][^);,]{0,80})/,
  node: /\beval\s*\(\s*([^);]{0,90})|new Function\s*\(|\bexecSync\s*\(\s*([^);,]{0,90})|child_process|\bspawn(Sync)?\s*\(\s*([^);,]{0,90})|\bfetch\s*\(\s*([^);,]{0,90})|axios\.\w+\s*\(\s*([^);,]{0,90})/,
  java: /Runtime\.getRuntime\(\)\.exec\s*\(\s*([^);]{0,90})|new ProcessBuilder\s*\(|JSON\.parse(Object)?\s*\(\s*([^);]{0,90})|ScriptEngine|SpelExpression/,
  // C/C++: 内存破坏 / 命令执行 / XML 解析（XXE 面）/ 格式化串
  c: /\b(strcpy|strcat|strncpy|sprintf|vsprintf|snprintf|memcpy|memmove|gets|scanf|sscanf|fscanf|system|popen|execl|execlp|execle|execv|execvp|execvpe|xmlReadDoc|xmlReadMemory|xmlCtxtReadDoc|xmlCtxtReadMemory|xmlParseDoc|xmlParseMemory|xmlSAXParseDoc)\s*\(\s*([^);]{0,90})/,
};
const SINK_NAME = {
  php: (m) => m[1] || m[3] || m[5] || "?",
  py: (m) => m[1] || m[3] || m[5] || (m[7] !== undefined ? ".execute" : m[8] !== undefined ? "open" : "?"),
  node: (m) => m[1] !== undefined ? "eval" : m[2] !== undefined ? "execSync" : m[4] !== undefined ? "spawn" : m[5] !== undefined ? "fetch" : m[6] !== undefined ? "axios" : "new Function/child_process",
  java: (m) => m[1] !== undefined ? "Runtime.exec" : m[3] !== undefined ? "parseObject" : m[0].slice(0, 26).split("(")[0].trim(),
  c: (m) => m[1] || "?",
};
const SINK_ARG = {
  php: (m) => m[2] || m[4] || m[6] || "",
  py: (m) => m[2] || m[4] || m[6] || m[7] || m[8] || "",
  node: (m) => m[1] || m[2] || m[4] || m[5] || m[6] || "",
  java: (m) => m[1] || m[3] || "",
  c: (m) => m[2] || "",
};
// 动态 SQL 才算 .execute 汇（静态字符串 SQL/ORM 语句对象直接跳过）
const DYNAMIC_SQL = /f["']|\+\s*["'\w]|\.format\(|%\s*\w|%s|format_map|\$\{/;
const isComment = (l) => /^\s*(\/\/|\/\*|\*|#|<!--)/.test(l);
const clean = (s) => s.replace(/^["'\s]+|["'\s]+$/g, "");

// ---------- 扫描主循环 ----------
const wired = [];   // ⚡ 源→汇连线(高置信)
const review = [];  // 待确认
const taintStackInfo = []; // 语言级提示

for (const f of files) {
  const ext = f.split(".").pop();
  const lang = { php: "php", py: "py", java: "java", ts: "node", js: "node", tsx: "node", c: "c", cpp: "c", cc: "c", cxx: "c", h: "c", hpp: "c", hxx: "c" }[ext];
  if (!lang || !stacks.has(lang === "py" ? "py" : lang)) continue;
  if (lang === "node" && !stacks.has("node")) continue;
  const lines = readLines(f);
  if (!lines || !SINKS[lang]) continue;
  const SRC = lang === "c" ? C_SRC : SRC_DIRECT;

  // ① 第一遍: 收集本文件被污染变量(直接源 + 一跳传播)
  const tainted = new Map(); // var -> 来源行
  lines.forEach((line, i) => {
    if (isComment(line)) return;
    const m = line.match(ASSIGN);
    if (!m) return;
    const varName = m[1] || m[2];
    const rhs = m[3] || "";
    if (SRC.test(rhs)) tainted.set(varName, { line: i + 1, src: rhs.trim().slice(0, 60) });
    else { // 一跳传播: rhs 恰好是已污染变量
      const v = rhs.replace(/^\$/, "").replace(/[^#\s].*$/, "").trim() || rhs.trim();
      const rhsVar = rhs.trim().replace(/^[\$]/, "").replace(/\(.*/, "").trim();
      if (tainted.has(rhsVar) && /^[A-Za-z_\$][\w]*$/.test(rhsVar)) tainted.set(varName, { line: i + 1, src: `传播自 ${rhsVar}` });
    }
  });

  // ② 第二遍: 汇检测 + 连线判定
  lines.forEach((line, i) => {
    if (isComment(line)) return;
    const sm = line.match(SINKS[lang]);
    const extra = (lang === "c" && C_EXTRA.test(line)) ? line.match(C_EXTRA) : null;
    if (!sm && !extra) return;
    const sinkName = sm ? SINK_NAME[lang](sm) : ("XXE/zip:" + extra[0]);
    if (sinkName === ".execute" && !DYNAMIC_SQL.test(line)) return; // 静态 SQL/ORM 跳过
    const argText = sm ? SINK_ARG[lang](sm).trim() : line.trim().slice(0, 60);
    // 判定一: 汇实参含被污染变量
    let hit = null;
    for (const [v, src] of tainted) {
      const re = new RegExp(`\\$?\\b${v}\\b`);
      if (argText && re.test(argText)) { hit = { v, src }; break; }
    }
    // 判定二: 汇行直接出现源
    const direct = SRC.test(line);
    if (hit || direct) {
      wired.push({
        file: rel(f), line: i + 1, sink: `${sinkName}(${argText.slice(0, 50) || "..."})`,
        src: hit ? `L${hit.src.line} ${hit.v} ← ${hit.src.src}` : "直接源",
        raw: line.trim().slice(0, 90),
      });
    } else {
      review.push({ file: rel(f), line: i + 1, raw: line.trim().slice(0, 90), sink: sinkName });
    }
  });
}

// ---------- 输出 ----------
console.log(`## ⚡ 源→汇连线（${wired.length} 条，高置信，优先写 PoC）`);
for (const w of wired.slice(0, 40)) console.log(`- ${w.file}:${w.line}  ${w.sink}\n    来源: ${w.src}\n    原始: ${w.raw}`);
if (!wired.length) console.log("- (无文件内直接连线; 污点可能跨文件传播——此时升级为 semgrep 跨文件或人工追)");
console.log(`\n## 其余汇命中（${review.length} 条，待人工确认可达性）`);
for (const r of review.slice(0, 30)) console.log(`- ${r.file}:${r.line}  [${r.sink}] ${r.raw}`);

// ---------- 依赖指纹 + 探针(轻量部分沿用) ----------
if (composer && existsSync(composer)) {
  try {
    const j = JSON.parse(readFileSync(composer, "utf8"));
    const fw = Object.keys({ ...(j.require || {}) }).filter((k) => /think|laravel|wordpress|typecho|symfony|codeigniter/i.test(k));
    console.log(`\n## PHP 框架: ${fw.join(", ") || "自研/无框架依赖"}`);
  } catch {}
}
if (pkg) {
  try {
    const j = JSON.parse(readFileSync(pkg, "utf8"));
    const notable = Object.keys({ ...(j.dependencies || {}) }).filter((k) => /express|strapi|n8n|flowise|nestjs|fastify|ejs|lodash/i.test(k));
    if (notable.length) console.log(`## Node 依赖: ${notable.join(", ")}`);
  } catch {}
}
const HOST = process.env.TARGET || "http://127.0.0.1:8080";
console.log("\n## 探针");
for (const p of ["/druid/index.html", "/actuator/env", "/swagger-ui/index.html", "/phpinfo.php", "/.env"])
  console.log(`curl -s -o /dev/null -w "${p}:%{http_code}\\n" ${HOST}${p}`);
console.log("\n[说明] 文件内一跳污点≈Semgrep taint 的子集(无跨文件/控制流); 高置信命中仍需人工确认, 其余命中说明污点在别处起源。");
