#!/usr/bin/env node
// squad-triage.mjs — 多题批量分诊 + 组合排序 + 波次建议（among-squad Stage 1~3 自动化）
// 用法: node squad-triage.mjs <targets.txt | 目标目录...> [--out <squad工作区>] [--top 3]
// targets.txt 每行一个目录路径, # 开头为注释
// 每靶: audit-pipeline (2s级) + classify --json → 卡片 → 组合打分 → 赛道覆盖 → 波次
// 产物: <out>/dashboard.md + <out>/squad-triage.json + 每靶 <out>/audit-<name>/ 完整流水线产物
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, resolve, basename, dirname } from "node:path";

const SCRIPTS = dirname(resolve(process.argv[1]));
const args = process.argv.slice(2);
if (!args.length) { console.error("用法: node squad-triage.mjs <targets.txt | 目录...> [--out <squad目录>] [--top 3]"); process.exit(1); }

const rest = [...args];
const outIdx = rest.indexOf("--out");
const OUT = outIdx >= 0 ? resolve(rest[outIdx + 1]) : resolve("squad");
if (outIdx >= 0) rest.splice(outIdx, 2);
const topIdx = rest.indexOf("--top");
const TOP = topIdx >= 0 ? parseInt(rest[topIdx + 1], 10) || 3 : 3;
if (topIdx >= 0) rest.splice(topIdx, 2);

const targets = [];
for (const t of rest) {
  if (existsSync(t) && t.toLowerCase().endsWith(".txt")) {
    targets.push(...readFileSync(t, "utf8").split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#")));
  } else if (existsSync(t)) targets.push(resolve(t));
  else console.warn(`[skip] 不存在: ${t}`);
}
if (!targets.length) { console.error("没有有效目标"); process.exit(1); }
mkdirSync(OUT, { recursive: true });

const run = (bin, ...a) => (spawnSync(process.execPath, [join(SCRIPTS, bin), ...a], { encoding: "utf8", timeout: 300000, maxBuffer: 64 * 1024 * 1024 }).stdout || "");
const esc = (s) => String(s).replace(/\|/g, "\\|");

// ── Stage 1: 批量分诊 ──
const cards = [];
for (const t of targets) {
  const name = basename(resolve(t));
  const tdir = join(OUT, `audit-${name}`);
  console.log(`[triage] ${name} ...`);
  run("audit-pipeline.mjs", t, "--out", tdir);
  let cls = null;
  try { cls = JSON.parse(run("classify.mjs", t, "--json")); } catch {}
  let candidates = 0, highConf = 0;
  try {
    const rows = (readFileSync(join(tdir, "findings-draft.md"), "utf8").split("## 候选")[1] || "").split("\n").filter((l) => l.startsWith("| ") && /\|\s*\d+\s*\|/.test(l));
    candidates = rows.length;
    highConf = rows.filter((l) => l.includes("| 高 |")).length;
  } catch {}
  const effort = Math.max(1, Math.log10((cls?.source_files || 1) + 10));
  const score = Math.round(((candidates + 3 * highConf) / effort) * 10) / 10;
  cards.push({
    name, path: t.replace(/\\/g, "/"), category: cls?.primary?.label || "?", form: cls?.form || "?",
    candidates, high_conf: highConf, source_files: cls?.source_files || 0, score,
    gate: cls?.gate || false, confidence: cls?.confidence ?? 0, secondary: (cls?.secondary || []).map((x) => x.label).join("/"),
    workspace: `audit-${name}`,
  });
}

// ── Stage 2: 组合排序 + 赛道覆盖 ──
cards.sort((a, b) => b.score - a.score);
const presentCats = [...new Set(cards.map((c) => c.category).filter((x) => x !== "?"))];
const short = [];
const used = new Set();
for (const c of cards) if (short.length < TOP && !used.has(c.name)) { short.push(c); used.add(c.name); }
for (const cat of presentCats) {
  if (!short.some((x) => x.category === cat)) {
    const pick = cards.find((c) => !used.has(c.name) && c.category === cat);
    if (pick) { short.push(pick); used.add(pick.name); }
  }
}

// ── Stage 3: 波次（同类连续） ──
const waves = [];
for (const c of short) {
  const w = waves.find((x) => x.cat === c.category);
  if (w) w.items.push(c.name); else waves.push({ cat: c.category, items: [c.name] });
}

// ── dashboard.md ──
const L = [];
L.push(`# 组合看板 · ${new Date().toISOString().slice(0, 10)}（squad-triage 自动生成）`);
L.push("");
L.push(`> 目标数 ${cards.length} · 深挖配额 ${TOP} · 打分 = (候选数 + 3×高置信) ÷ log10(源文件+10)`);
L.push("");
L.push("## 组合排序（全量）");
L.push("");
L.push("| 排名 | 靶 | 类 | 形态 | 候选 | 高置信 | 源文件 | 分诊分 | 拍板门 |");
L.push("|---|---|---|---|---|---|---|---|---|");
cards.forEach((c, i) => L.push(`| ${i + 1} | ${esc(c.name)} | ${c.category}${c.secondary ? `(副:${esc(c.secondary)})` : ""} | ${c.form} | ${c.candidates} | ${c.high_conf} | ${c.source_files} | ${c.score} | ${c.gate ? "⚠必停" : "常规"} |`));
L.push("");
L.push(`## 深挖短名单（配额 ${TOP} + 赛道覆盖补位）`);
L.push("");
for (const c of short) L.push(`- [ ] **${esc(c.name)}**（${c.category} · 分 ${c.score}）→ among-auto 流程 · 工作区 \`${c.workspace}/\``);
L.push("");
L.push("## 波次建议（同类连续，波内零切换）");
L.push("");
waves.forEach((w, i) => L.push(`${i + 1}. [${w.cat}] ${w.items.map((x) => "`" + x + "`").join(" → ")}`));
L.push("");
L.push("## 候选级保留（已测绘，不深挖）");
L.push("");
for (const c of cards.filter((c) => !used.has(c.name))) L.push(`- ${esc(c.name)}（${c.category} · ${c.candidates} 候选）——分诊证据保留在 ${c.workspace}/，收尾时并进组合报告`);
writeFileSync(join(OUT, "dashboard.md"), L.join("\n"));
writeFileSync(join(OUT, "squad-triage.json"), JSON.stringify({ generated: new Date().toISOString(), top: TOP, cards, short: short.map((c) => c.name), waves }, null, 2));
console.log(`[squad-triage] ${cards.length} 靶分诊完成 → ${OUT.replace(/\\/g, "/")}/dashboard.md`);