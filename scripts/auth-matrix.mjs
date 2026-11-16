#!/usr/bin/env node
// 鉴权矩阵生成器 —— 智能体/Web(Python/TS) 通用
// 用法: node auth-matrix.mjs <项目目录> [--ext py,ts,js]
// 原理: 扫描路由装饰器/方法 + 鉴权装饰器/基类/中间件, 输出"路由|鉴权?"矩阵
// 启发式工具: 输出需人工复核（尤其是类继承鉴权、全局中间件场景）
// 只读保证（零改动原则）: 本工具只做 readdir/readFile/stat，绝不向目标目录写入任何文件
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.argv[2];
if (!ROOT) { console.error("用法: node auth-matrix.mjs <项目目录> [--ext py,ts,js]"); process.exit(1); }
const extArg = process.argv.find((a) => a.startsWith("--ext"));
const EXTS = extArg ? extArg.slice(6).split(",") : ["py", "ts", "js", "java", "php"];

const ROUTE_PATTERNS = [
  // Python: Flask 蓝图 / flask-restx 命名空间 / FastAPI
  { re: /@(?:\w+)\s*\.\s*route\(\s*["']([^"']+)["']/, method: "route", lang: "py" },
  { re: /@(?:app|router|api|bp)\s*\.\s*(get|post|put|delete|patch)\(\s*["']([^"']+)["']/, method: "$1", lang: "py" },
  // Node/TS: Express / Fastify / Nest
  { re: /\.(get|post|put|delete|patch)\(\s*["']\/([^"']+)["']/, method: "$1", lang: "js" },
  // Java: Spring 注解路由
  { re: /@(Get|Post|Put|Delete|Patch)Mapping\(\s*(?:value\s*=\s*)?["']([^"']*)["']/, method: "$1", lang: "java" },
  { re: /@RequestMapping\(\s*(?:value\s*=\s*)?["']([^"']+)["']/, method: "all", lang: "java" },
  // PHP: ThinkPHP Route / 框架通用
  { re: /Route::(get|post|put|delete|rule)\(\s*["'][^"']*["']\s*,\s*["'][^"']+["']/, method: "$1", lang: "php" },
];
const AUTH_HINTS = /login_required|require_|validate_|auth|permission|@Login|@SaCheck|@PreAuthorize|@RequiresPermissions|current_user|verify|token|session|@Permission/i;
const AUTH_CLASS = /class\s+\w+\s*\(\s*\w*(login|auth|api|secure|session|token)\w*\s*\)|method_decorators\s*=|extends\s+\w*(Controller|Resource)\b/i;

function* walk(dir, depth = 0) {
  if (depth > 8) return;
  let entries;
  try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (/node_modules|\.git|dist|build|__pycache__|test/i.test(e)) continue;
    const p = join(dir, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, depth + 1);
    else if (EXTS.some((x) => e.endsWith("." + x))) yield p;
  }
}

const routes = [];
const authClasses = new Set();
for (const file of walk(ROOT)) {
  const lines = readFileSync(file, "utf8").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const cls = line.match(AUTH_CLASS);
    if (cls) { authClasses.add(`${rel(file)}:${i + 1} ${line.trim().slice(0, 80)}`); continue; }
    for (const p of ROUTE_PATTERNS) {
      const m = line.match(p.re);
      if (m) {
        const path = p.lang === "js" ? "/" + m[2] : m[1];
        const method = p.method === "$1" ? m[1].toUpperCase() : p.method.toUpperCase();
        // 检查后续 6 行内 def/函数 上方的鉴权装饰器（装饰器栈在 def 之前）
        let auth = null;
        for (let j = Math.max(0, i - 6); j < Math.min(lines.length, i + 6); j++) {
          if (j === i) continue;
          if (AUTH_HINTS.test(lines[j]) && /@|middleware|use\(/.test(lines[j])) { auth = `L${j + 1}: ${lines[j].trim().slice(0, 60)}`; break; }
        }
        routes.push({ file: rel(file), line: i + 1, method, path: path.slice(0, 60), auth });
        break;
      }
    }
  }
}

function rel(f) { return f.replace(/\\/g, "/"); }

const suspicious = routes.filter((r) => !r.auth);
console.log(`# 鉴权矩阵 —— ${ROOT}`);
console.log(`# 路由总数 ${routes.length}，其中【未检出鉴权】${suspicious.length} 条（含类继承/全局中间件鉴权的误报，需人工复核）\n`);
console.log("## 疑似无鉴权路由（优先测试）");
for (const r of suspicious.slice(0, 60)) {
  console.log(`- [${r.method}] ${r.path}  @ ${r.file}:${r.line}`);
}
if (authClasses.size) {
  console.log("\n## 检出鉴权基类/中间件（路由可能经基类鉴权）");
  for (const c of [...authClasses].slice(0, 15)) console.log(`- ${c}`);
}
console.log(`\n## 全量矩阵已检 ${routes.length} 条；前 15 条示例`);
for (const r of routes.slice(0, 15)) {
  console.log(`- [${r.method}] ${r.path} @ ${r.file}:${r.line} ${r.auth ? "auth: " + r.auth : "!!无"}`);
}
