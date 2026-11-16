#!/usr/bin/env node
// report-pack.mjs — 报告装配核对器 + report-draft.md 骨架生成（报告收尾闭环, 与 deliverables-check 互补）
// 用法: node report-pack.mjs <工作区> [--target <目标目录>] [--strict]
// 核对链（对照 report-template 各节）:
//   1 发现表完整性: notes.md「## 发现」表格逐行 → 编号/标题/位置(file:line)/等级/证据等级/状态
//   2 证据闭环: evidence/F-XX/** 目录取证（request/response/png 计数）; poc/ 按 F-XX 匹配
//   3 零改动证明: pristine-manifest.json 存在 + 给定 --target 时跑 pristine-check --verify
//   4 报告骨架: 按 report-template §0~§5 生成 report-draft.md, 缺口以【缺: …】标注
// 退出码: 0=齐全; 1=存在缺口（--strict 时）; 用法错误=2
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve, dirname } from "node:path";

const SCRIPTS = dirname(resolve(process.argv[1]));
const args = process.argv.slice(2);
const WS = resolve(args[0] || ".");
const strict = args.includes("--strict");
const tIdx = args.indexOf("--target");
const TARGET = tIdx >= 0 ? resolve(args[tIdx + 1]) : null;

const read = (p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } };
const exists = existsSync;

// 1. 发现表解析
const notes = read(join(WS, "notes.md"));
const findingRows = notes.split("\n").filter((l) => /^\|\s*F-\d+/i.test(l) && !/^\|\s*编号/.test(l));
const findings = findingRows.map((l) => {
  const c = l.split("|").map((x) => x.trim());
  return { id: (c[1] || "?").toUpperCase(), title: c[2] || "", location: c[3] || "", severity: c[4] || "", evidence_tier: c[5] || "", status: c[6] || "" };
});

// 2. 证据闭环
const evBase = join(WS, "evidence");
const evDirs = exists(evBase) ? readdirSync(evBase).filter((d) => { try { return statSync(join(evBase, d)).isDirectory(); } catch { return false; } }) : [];
const evSummary = (id) => {
  const d = join(evBase, id);
  if (!exists(d)) return { n: 0, kind: [] };
  const files = readdirSync(d);
  return { n: files.length, kind: files.filter((f) => f.endsWith(".png")).length ? ["png"] : [].concat(files.some((f) => f.endsWith("request.txt")) ? ["request"] : [], files.some((f) => f.endsWith("response.txt")) ? ["response"] : [], files.some((f) => f.includes("SUMMARY")) ? ["summary"] : []) };
};
const pocFiles = exists(join(WS, "poc")) ? readdirSync(join(WS, "poc")) : [];

// 3. 零改动证明
let pristine = { checked: false, ok: null, output: "" };
if (exists(join(WS, "pristine-manifest.json"))) {
  if (TARGET && exists(TARGET)) {
    const r = spawnSync(process.execPath, [join(SCRIPTS, "pristine-check.mjs"), TARGET, "--verify", join(WS, "pristine-manifest.json")], { encoding: "utf8", timeout: 60000 });
    pristine.checked = true;
    pristine.ok = r.status === 0;
    pristine.output = (r.stdout || r.stderr || "").trim().slice(0, 400);
  } else if (!TARGET) pristine.output = "（未给 --target，跳过动态校验；清单存在）";
}

// 4. 缺口清单
const gaps = [];
const checks = [];
for (const f of findings) {
  const ev = evSummary(f.id);
  const row = [];
  if (!/:\d+/.test(f.location) && !/-/.test(f.location)) row.push("位置缺 file:line");
  if (!f.evidence_tier || f.evidence_tier === "-") row.push("证据等级未标注(Tier1/2/3)");
  if (ev.n === 0) row.push("evidence/ 无该发现证据");
  else {
    if (!ev.kind.includes("request") && !ev.kind.includes("png")) row.push("缺请求证据(request.txt/png)");
    if (f.evidence_tier.startsWith("Tier 3") && ev.n < 2) row.push("Tier3 声明但证据文件<2");
  }
  const hasPoc = pocFiles.some((p) => p.toUpperCase().includes(f.id.toUpperCase()));
  if (!hasPoc) row.push("poc/ 无可重放脚本");
  if (row.length) gaps.push(`${f.id}: ${row.join("; ")}`);
  checks.push({ id: f.id, title: f.title, ok: row.length === 0, issues: row.join("; "), ev: ev.n });
}
if (!findings.length) gaps.push("notes.md 发现表为空——确认后先填 findings 再跑本工具");
if (pristine.checked && pristine.ok === false) gaps.push(`零改动证明失败: ${pristine.output}`);
if (!exists(join(WS, "pristine-manifest.json"))) gaps.push("缺 pristine-manifest.json（开审未建零改动基线）");

// 5. report-draft.md 骨架
const esc = (s) => String(s).replace(/\|/g, "\\|");
const D = [];
D.push(`# <项目名> <版本> 白盒安全审计报告（骨架——由 report-pack 自动生成）`);
D.push("");
D.push(`> 检查时间: ${new Date().toISOString().slice(0, 19)} · 工作区: ${WS.replace(/\\/g, "/")}`);
D.push("");
D.push("## 0. AI 方法论（赛制考评项）");
D.push("");
D.push("【缺: 填写 AI 辅助链路、关键提示词（prompt-library）、每洞双链验证机制、效率数据】");
D.push("");
D.push("## 1. 报告头");
D.push("");
D.push(`- 审计对象: ${TARGET ? TARGET.replace(/\\/g, "/") : "【缺: --target 未给】"}`);
D.push("- 审计人 / 日期 / 环境说明: 【缺: 补填】");
D.push("");
D.push("## 2. 执行摘要（风险矩阵）");
D.push("");
D.push("| 编号 | 标题 | 类型 | 位置 | 等级 | 状态 | 证据闭环 |");
D.push("|---|---|---|---|---|---|---|");
for (const f of findings) {
  const ev = evSummary(f.id);
  D.push(`| ${esc(f.id)} | ${esc(f.title)} | 【补 CWE】 | ${esc(f.location)} | ${esc(f.severity)} | ${esc(f.status)} | evidence ${ev.n} 文件${ev.n === 0 ? " 【缺】" : ""} |`);
}
D.push("");
D.push("## 3. 漏洞详情");
D.push("");
for (const f of findings) {
  D.push(`### ${f.id} ${f.title}（${f.evidence_tier || "【补:证据等级】"}）`);
  D.push("");
  D.push("- 类型: 【补 CWE 与名称】 · 等级: ${f.severity} · 位置: \`${f.location}\`");
  D.push("- 描述与根因: 【补: 引用关键代码 3~8 行】");
  D.push("- 可达性与前置条件: 【补】");
  const ev = evSummary(f.id);
  D.push(`- 复现步骤与证据: ${ev.n ? `见 \`evidence/${f.id}/SUMMARY.md\`（可直接粘贴）` : "【缺: 用 repro-runner.mjs 采集】"}`);
  D.push(`- PoC: ${pocFiles.some((p) => p.toUpperCase().includes(f.id)) ? `\`poc/\` 内 ${f.id} 匹配文件` : "【缺: poc/ 无可重放脚本】"}`);
  D.push("- 影响 / 修复建议: 【补】");
  D.push("");
}
D.push("## 4. 组合利用链 【缺若无】");
D.push("");
D.push("## 5. 总体修复优先级 P0/P1/P2 【补】");
D.push("");
writeFileSync(join(WS, "report-draft.md"), D.join("\n"));

// 6. 输出
const total = findings.length;
const okCount = checks.filter((c) => c.ok).length;
console.log(`[report-pack] 发现 ${total} 条 · 证据闭环 ${okCount}/${total}${total === 0 ? "（发现表为空）" : ""}`);
for (const g of gaps) console.log(`  ✗ ${g}`);
console.log(`  → report-draft.md 已生成 · pristine: ${pristine.checked ? (pristine.ok ? "✓ 一致" : "✗ 失败") : (pristine.output || "未校验")}`);
if (strict && gaps.length) process.exit(1);