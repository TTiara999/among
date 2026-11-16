#!/usr/bin/env node
// 文件定权器（VulnHunter-White 模式）—— 全类别通用，保证全量覆盖与审计顺序
// 用法: node file-weight.mjs <目录> [--top 30]
// 原理: 侦察阶段给每个源码文件打 0-100 权重与角色标签，产出"按权重降序"的深读队列，
//       防止（人或 LLM）只挑有趣文件看导致覆盖缺口——实测是审计 Agent 最有效的覆盖手段
// 角色与打法: SOURCE(入口,正向追流) > GUARD(过滤器,枚举审计) > SERVICE(危险操作,回推 caller)
//            > SINK-UTIL > DTO/MODEL(薄扫)
// 只读保证（零改动原则）: 只做 readdir/readFile/stat
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const ROOT = args[0];
if (!ROOT) { console.error("用法: node file-weight.mjs <目录> [--top 30]"); process.exit(1); }
const topIdx = args.indexOf("--top");
const TOP = topIdx >= 0 ? parseInt(args[topIdx + 1], 10) || 30 : 30;

const ROLES = [
  { role: "SOURCE", w: 40,
    re: /@(?:\w+)\s*\.\s*(?:route|get|post|put|delete|patch)\s*\(|@(?:Get|Post|Put|Delete|Patch)Mapping|@(?:app|router|bp|blueprint)\b|request\.(args|form|get_json|getParameter|getHeader|query|body)|\$_(GET|POST|REQUEST|FILES)|req\.(query|body|params)|Route::|app\.use\s*\(|\.listen\s*\(|gradio\.|@(?:tool|app)\b.*route/i },
  { role: "GUARD", w: 32,
    re: /sanitize|wash|filter_|is_local|login_required|permission_|interceptor|HandlerInterceptor|authenticat|whitelist|blacklist|SecurityFilter|PreAuthorize|RequiresPermissions|escape_|purify|defang|validate_|check_import|check_authorized|_sanitize/i },
  { role: "SERVICE", w: 26,
    re: /\bexec\s*\(|\beval\s*\(|\bassert\s*\(|subprocess|os\.system|popen|child_process|requests\.(get|post|put|delete)|httpx\.|urlopen|\.execute\s*\(|open\s*\(|read_text|writeFile|file_put_contents|Runtime\.getRuntime|ProcessBuilder|unserialize|pickle|JSON\.parseObject|new Function|\b(strcpy|strcat|sprintf|vsprintf|memcpy|memmove|gets|system|execl|execlp|execv|execvp)\s*\(|xmlReadDoc|xmlCtxtRead|XML_PARSE_NOENT|XML_PARSE_DTDLOAD/i },
  { role: "SINK-UTIL", w: 12, nameRe: /(util|helper|common|handler|manager|engine|executor|interpreter|core)\b/i },
  { role: "DTO", w: 6, nameRe: /(model|entity|schema|dto|types?|bean|vo)\b/i },
];
// 跳过第三方/ vendored 库噪声（ cryptopp/cximage/libmng/libpng 等曾淹没 core 仓库深读队列）；
// 注意：不 blanket 排除 deps——KeyDB deps/lua 等 bundled 代码仍是攻击面（CVE-2024-31449 即在 deps/lua）
const SKIP_DIR = /node_modules|\.git|vendor|dist|build|__pycache__|locale|tests?|docs|examples?|static\/(?!.*\.(py|php|java))|migrations|\.min\.|3d[-_]?party|third[-_]?party|cryptopp|cximage|libmng|libpng|libjpeg|libtiff|zlib|boost|externals?|contrib/i;
const CODE_EXT = /\.(py|php|java|ts|tsx|js|go|rb|c|h|cpp|kt)$/i;

function* walk(dir, depth = 0) {
  if (depth > 8) return;
  let entries; try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (SKIP_DIR.test(e)) continue;
    const p = join(dir, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, depth + 1);
    else if (CODE_EXT.test(e) && st.size < 512 * 1024) yield p;
  }
}
const rel = (f) => f.replace(/\\/g, "/");

const files = [];
for (const f of walk(ROOT)) {
  const lines = readFileSync(f, "utf8").split(/\r?\n/);
  // 只在"代码行"上做角色匹配（注释/许可证头不算——否则 Apache 头的 "permissions" 会污染 GUARD）
  const codeLines = lines.filter((l) => l.trim() && !/^\s*(#|\/\/|\/\*|\*|<!--|--|""")/.test(l));
  const matched = [];
  const hits = {};
  for (const { role, w, re, nameRe } of ROLES) {
    const nameHit = nameRe && nameRe.test(rel(f));
    let reHit = false, sample = "";
    if (re) {
      const sampleLine = codeLines.find((l) => re.test(l));
      reHit = !!sampleLine;
      if (reHit) sample = sampleLine.trim().slice(0, 46);
    }
    if (nameHit || reHit) { matched.push({ role, w }); if (sample) hits[role] = sample; }
  }
  if (!matched.length) continue;
  const primary = matched.reduce((a, b) => (b.w > a.w ? b : a));
  const weight = Math.min(100, primary.w + Math.min(12, Math.floor(lines.length / 150)));
  files.push({ file: rel(f), weight, roles: matched.map((m) => m.role).join("+"), lines: lines.length, hits });
}

files.sort((a, b) => b.weight - a.weight);
const counts = {};
for (const f of files) for (const r of f.roles.split("+")) counts[r] = (counts[r] || 0) + 1;

console.log(`# 文件定权 —— ${ROOT}`);
console.log(`# 纳入评分文件 ${files.length} 个（角色分布: ${Object.entries(counts).map(([k, v]) => `${k}:${v}`).join(", ")}）\n`);
console.log(`## 深读队列（权重降序前 ${Math.min(TOP, files.length)}）`);
for (const f of files.slice(0, TOP)) {
  const ev = Object.entries(f.hits).slice(0, 2).map(([k, v]) => `${k}~ "${v}"`).join("; ");
  console.log(`- ${String(f.weight).padStart(3)} [${f.roles.padEnd(16)}] ${f.file} (${f.lines}行)${ev ? "  " + ev : ""}`);
}
const unlisted = files.slice(TOP);
console.log(`\n## 覆盖统计（防偷懒）: 未列入队列 ${unlisted.length} 个文件`);
for (const f of unlisted.filter((x) => /SOURCE|GUARD/.test(x.roles)).slice(0, 10))
  console.log(`  - 仍需排队: ${String(f.weight).padStart(3)} [${f.roles}] ${f.file}`);
console.log(`\n[审计法] 按队列逐文件深读（每文件一轮, 摘要落 notes.md 防重复方向）：
  SOURCE 正向追流 → GUARD 枚举审计(找漏枚举) → SERVICE 回推 caller → DTO 薄扫收工`);
