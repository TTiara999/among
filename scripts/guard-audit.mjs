#!/usr/bin/env node
// 防护函数枚举审计器（通用，跨类别跨语言）—— 「枚举审计法」的落地工具
// 用法: node guard-audit.mjs <目录> [--hot "kw1,kw2"] [--lang php,py,java,ts,js]
// 原理: 任何"守卫函数"(wash/sanitize/filter/check/verify/is_local/escape/purify/defang...)
//       的漏洞形态都是"枚举不全"(漏一种 IP 形态/属性/转义/协议)。本工具:
//       ① 定位全项目守卫函数  ② 摘录其枚举集合(正则/数组/白名单)  ③ 找漏枚举的边角
// 适用: 邮件 HTML 清洗 / 智能体输入过滤 / Web 参数校验 / 任何含 sanitizer 的项目
// 只读保证（零改动原则）: 只做 readdir/readFile/stat，绝不向目标目录写入任何文件
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.argv[2];
if (!ROOT) { console.error("用法: node guard-audit.mjs <目录> [--hot kw1,kw2] [--lang php,py,java,ts,js]"); process.exit(1); }
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : d; };
const HOT = (arg("hot", "url,scheme,header,redirect,ip,path,svg,css,entity") || "").split(",").map((s) => s.trim()).filter(Boolean);
const LANGS = (arg("lang", "php,py,java,ts,js") || "").split(",");

// 守卫函数名特征（通用，不绑定任何项目）
const GUARD_NAME = /(wash|sanitize|sanitise|clean|purify|defang|filter|check|verify|validate|is_local|is_safe|is_allowed|escape|encode|blacklist|block|restrict|guard|normaliz)/i;
// 函数定义形态（跨语言）
const DEF = {
  php: /function\s+(\w+)\s*\(/,
  py: /def\s+(\w+)\s*\(/,
  java: /(?:public|private|protected)\s+[\w<>\[\]]+\s+(\w+)\s*\(/,
  ts: /(?:function\s+(\w+)\s*\(|(\w+)\s*(?::\s*[\w<>|]+)?\s*=\s*(?:\(|async))/,
  js: /function\s+(\w+)\s*\(|(\w+)\s*=\s*\(/,
};
// 枚举集合行特征（守卫内部的判断材料）
const ENUM = /in_array|array\s*\(|preg_match|match\s*\(|\.match\(|whitelist|blacklist|allowed|blocked|replace\s*\(|split\s*\(|includes\s*\(|indexOf\s*\(|case\s+['"]/i;

function* walk(dir, depth = 0) {
  if (depth > 8) return;
  let entries; try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (/node_modules|\.git|vendor|dist|build|__pycache__|locale|tests?\b/i.test(e)) continue;
    const p = join(dir, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, depth + 1);
    else yield p;
  }
}
const rel = (f) => f.replace(/\\/g, "/");

const guards = []; // {file, line, name, lang}
for (const f of walk(ROOT)) {
  const ext = f.split(".").pop();
  const lang = { php: "php", py: "py", java: "java", ts: "ts", js: "js" }[ext];
  if (!lang || !LANGS.includes(lang)) continue;
  const lines = readFileSync(f, "utf8").split(/\r?\n/);
  lines.forEach((line, i) => {
    const m = line.match(DEF[lang]);
    const name = m ? (m[1] || m[2]) : null;
    if (name && GUARD_NAME.test(name)) guards.push({ file: rel(f), line: i + 1, name, lang, lines });
  });
}

console.log(`# 守卫函数枚举审计 —— ${ROOT}`);
console.log(`# 定位到 ${guards.length} 个守卫函数（按文件内密度排序，优先深读命中多的文件）\n`);
// 按文件聚合、按守卫数量排序
const byFile = new Map();
for (const g of guards) {
  if (!byFile.has(g.file)) byFile.set(g.file, []);
  byFile.get(g.file).push(g);
}
const sorted = [...byFile.entries()].sort((a, b) => b[1].length - a[1].length);
let n = 0;
for (const [file, gs] of sorted) {
  if (n++ >= 10) break;
  console.log(`## ${file}`);
  for (const g of gs.slice(0, 8)) console.log(`   L${g.line}  ${g.name}()`);
  // 摘录枚举集合（守卫所在文件的判断材料行）
  let shown = 0;
  for (let i = 0; i < gs[0].lines.length && shown < 8; i++) {
    const l = gs[0].lines[i];
    if (ENUM.test(l) && l.trim().length > 18 && !/^\s*(\/\/|\*|\/\*|#)/.test(l)) {
      console.log(`   枚举 L${i + 1}  ${l.trim().slice(0, 96)}`);
      shown++;
    }
  }
  console.log("");
}

// hot 关键词：用户传入项目特定线索的二次定位（默认给通用集合）
console.log("# HOT 关键词定位（--hot 可自定义；用于把已知高危面缩小到具体行）");
const HOTRE = new RegExp(HOT.map((h) => h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "i");
let hotHits = 0;
for (const [file, gs] of sorted) {
  for (let i = 0; i < gs[0].lines.length && hotHits < 20; i++) {
    const l = gs[0].lines[i];
    if (HOTRE.test(l) && ENUM.test(l)) { console.log(`- ${file}:${i + 1}  ${l.trim().slice(0, 90)}`); hotHits++; }
  }
}
if (!hotHits) console.log("- (无命中，尝试调整 --hot)");

console.log(`
[枚举审计法三问]
1. 守卫枚举的集合全了吗? 对照标准全家桶: IP 形态(NAT64/6to4/IPv6-mapped/尾点FQDN/短格式)、属性(SMIL 的 to/from/by/src)、转义(CSS url() 所有形态)、协议(data/gopher/file)
2. 修复完整吗? git log --grep="again\\|bypass\\|incomplete" 查不完整修复历史（同一函数被修 N 次=边际收益最高的审计对象）
3. 同类守卫横向: 找到一处枚举缺失后，同目录/同名前缀的其它守卫全部过一遍`);
