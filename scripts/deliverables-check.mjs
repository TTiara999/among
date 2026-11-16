#!/usr/bin/env node
// 赛事交付物核对器 —— 对照赛制逐项检查产出完整性, 缺什么给补齐路径
// 赛制依据: writeup 提交格式（references/ctf-playbook.md §五）:
//           题目信息 / 解题思路(题型判定与信息收集、漏洞定位 file:line+根因代码、
//           利用过程) / Flag / 复现脚本 / 修复建议(一句话级)
// 用法: node deliverables-check.mjs <审计工作区目录> [--target <目标源码目录>]
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const WS = args[0];
if (!WS || !existsSync(WS)) { console.error("用法: node deliverables-check.mjs <审计工作区> [--target <源码目录>]"); process.exit(1); }
const tIdx = args.indexOf("--target");
const TARGET = tIdx >= 0 ? args[tIdx + 1] : null;
const minIdx = args.indexOf("--min");
const MIN_FINDINGS = minIdx >= 0 ? parseInt(args[minIdx + 1], 10) || 1 : 1; // 数量门槛可配置，默认 1（宁缺毋滥，不硬卡 ≥5）
const repIdx = args.indexOf("--report");
const REPORT_PATH = repIdx >= 0 ? args[repIdx + 1] : null; // 可指向工作区外的实际交付报告（如 writeup-report/<赛题>/report.md）

const check = (label, ok, hint) => ({ label, ok, hint });
const items = [];
const has = (p) => existsSync(join(WS, p));
const list = (d) => { try { return readdirSync(join(WS, d)); } catch { return []; } };

// 结构化 findings.json 优先（severity 兼容中英文），notes.md 正则仅作兜底
const SEV_ZH = { "严重": "Critical", "危急": "Critical", "高": "High", "高危": "High", "中": "Medium", "中危": "Medium", "低": "Low", "低危": "Low" };
const normSev = (s) => { s = String(s || "").trim(); if (SEV_ZH[s]) return SEV_ZH[s]; const c = s.charAt(0).toUpperCase() + s.slice(1).toLowerCase(); return ["Critical", "High", "Medium", "Low"].includes(c) ? c : "Low"; };
let findingsJson = [];
try { findingsJson = JSON.parse(readFileSync(join(WS, "findings.json"), "utf8")); if (!Array.isArray(findingsJson)) findingsJson = []; } catch {}
const sevFromJson = { Critical: 0, High: 0, Medium: 0, Low: 0 };
for (const f of findingsJson) sevFromJson[normSev(f.severity)]++;

// ── ① 漏洞发现（数量） ──
const notes = has("notes.md") ? readFileSync(join(WS, "notes.md"), "utf8") : "";
const findings = (notes.match(/^\| F-\d+/gm) || []).length;
items.push(check(
  `① 漏洞发现清单（notes.md, 当前 ${findings} 条）`,
  findings > 0,
  findings > 0 ? "已有发现表" : "跑 audit-pipeline 后逐条确认填入 findings 表"
));

// ── ② 复现脚本（可重放） ──
const pocs = list("poc").filter((f) => /\.(py|mjs|js|sh|php)$/.test(f));
items.push(check(
  `② 复现脚本（poc/ ${pocs.length} 个脚本）`,
  pocs.length > 0,
  pocs.length ? "靶场内跑通后在 writeup 回填验证结果" : "harness-gen.mjs 或手写 PoC 放入 poc/"
));

// ── ③ writeup 报告（兼容 CTF 型与审计型提交格式） ──
// 报告可在 report/ 子目录或工作区根（report.md / writeup*.md）
const reports = [
  ...list("report").filter((f) => f.endsWith(".md")).map((f) => ({ label: join("report", f), path: join(WS, "report", f) })),
  ...list(".").filter((f) => /^(report|writeup).*\.md$/i.test(f)).map((f) => ({ label: f, path: join(WS, f) })),
];
if (REPORT_PATH && existsSync(REPORT_PATH)) reports.push({ label: REPORT_PATH, path: REPORT_PATH });
let repOk = false, repDetail = [];
for (const { label: rf, path: rp } of reports) {
  const c = readFileSync(rp, "utf8");
  const parts = [];
  // 关键词兼容审计型（漏洞说明/根因/数据流/复现步骤）与 CTF 型（题目信息/解题思路/Flag）
  for (const [kw, name] of [["题目信息|审计对象|报告头|漏洞说明", "题目信息"], ["解题思路|根因|数据流|漏洞详情", "解题思路"], ["file:line|:[0-9]+", "漏洞定位"], ["利用过程|复现步骤|复现", "利用过程"], ["复现脚本|PoC|poc/", "复现脚本"], ["Flag|发现清单|执行摘要|漏洞", "Flag/发现清单"], ["修复建议", "修复建议"]]) {
    if (new RegExp(kw).test(c)) parts.push(name);
  }
  if (parts.length >= 6) repOk = true;
  repDetail.push(`${rf}: ${parts.join("/") || "空"}`);
}
items.push(check(
  `③ writeup 报告（report/ ${reports.length} 份: ${repDetail[0] || "无"}）`,
  repOk,
  repOk ? "格式齐备" : "用 references/ctf-playbook.md §五 writeup 模板生成（题目信息/解题思路/漏洞定位 file:line+根因代码/利用过程/Flag/复现脚本/一句话修复建议）"
));

// ── ④ 零改动证明 ──
const pristine = has("pristine-manifest.json");
let pristineVerified = false;
if (pristine && TARGET) {
  try {
    const { spawnSync } = await import("node:child_process");
    const SCRIPTS = resolve(process.argv[1], "..");
    const r = spawnSync(process.execPath, [join(SCRIPTS, "pristine-check.mjs"), TARGET, "--verify", join(WS, "pristine-manifest.json")], { encoding: "utf8" });
    pristineVerified = (r.stdout || "").includes("完全一致");
  } catch {}
}
items.push(check(
  `④ 零改动证明（${pristine ? (pristineVerified ? "已验证一致 ✔" : "有基线未验证") : "缺基线"}）`,
  pristineVerified,
  `node scripts/pristine-check.mjs <目标> --verify ${join(WS, "pristine-manifest.json").replace(/\\/g, "/")}`
));

// ── ⑥ 质量 × 严重度标准（赛制评分: 危害程度优先，数量门槛可配置 --min，默认 1，不硬卡 ≥5） ──
// 优先用结构化 findings.json；为空时兜底解析 notes.md 中文 severity 表
let sevCount = { ...sevFromJson };
let total = findingsJson.length;
if (total === 0) {
  sevCount = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const m of notes.matchAll(/^\| F-\d+\s*\|[^|]*\|[^|]*\|\s*(严重|高|中|低)\s*\|/gm)) sevCount[normSev(m[1])]++;
  total = sevCount.Critical + sevCount.High + sevCount.Medium + sevCount.Low;
}
const qWeight = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const qualityScore = Object.entries(sevCount).reduce((t, [k, v]) => t + qWeight[k] * v, 0);
const dualOk = total >= MIN_FINDINGS && (sevCount.Critical + sevCount.High) >= 1;

// ── ⑤ 提交物打包清单 ──
items.push(check(
  "⑤ 提交物齐全（notes + poc + report + 证明 + 双重标准达标）",
  findings > 0 && pocs.length > 0 && repOk && pristine && dualOk,
  "全部 ✅ 后即可按赛事要求提交"
));
items.push(check(
  `⑥ 质量×严重度标准（共 ${total} 条: Critical×${sevCount.Critical} High×${sevCount.High} Medium×${sevCount.Medium} Low×${sevCount.Low} · 质量分 ${qualityScore} · 门槛 --min ${MIN_FINDINGS}）`,
  dualOk,
  dualOk ? "严重/高保底，质量导向达标（数量门槛可调，宁缺毋滥）" : `需 ≥${MIN_FINDINGS} 条且至少 1 条 Critical/High：用 multi-pass.mjs/git-fix-hunt 深挖高危害洞，勿以低危凑数`
));

console.log("═".repeat(58));
console.log("  赛事交付物核对（对应赛制: 发现/复现/writeup/零改动/数量×严重度）");
console.log("═".repeat(58));
let pass = 0;
for (const it of items) {
  console.log(`  ${it.ok ? "[✅]" : "[❌]"} ${it.label}`);
  if (!it.ok) console.log(`        → 补齐: ${it.hint}`);
  if (it.ok) pass++;
}
console.log(`\n  ${pass}/${items.length} 项就绪${pass === items.length ? " —— 可以提交 🏁" : " —— 按提示补齐后复核"}`);
process.exit(pass === items.length ? 0 : 1);
