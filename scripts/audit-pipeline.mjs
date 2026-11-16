#!/usr/bin/env node
// 一键审计流水线（赛事模式）—— 输入一个目录，自动完成: 基线→指纹→测绘→快扫→修复情报→候选清单
// 透明协议: 每阶段打印【产物】与【决策点】; 全量日志落盘 tool-logs/; 确认环节显式交还（不做黑盒）
// 用法: node audit-pipeline.mjs <目标目录 | targets.txt | 目录...> [--out <工作区>] [--top 10]
//       单目录=单题流水线; targets.txt 或多目录=自动转 squad-triage 多题分诊
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, resolve, join } from "node:path";

const SCRIPTS = dirname(resolve(process.argv[1]));
const args = process.argv.slice(2);
const ROOT = args[0];
if (!ROOT || !existsSync(ROOT)) { console.error("用法: node audit-pipeline.mjs <目标目录 | targets.txt | 目录...> [--out <工作区>] [--top 10]"); process.exit(1); }
const outIdx = args.indexOf("--out");
const OUT = outIdx >= 0 ? resolve(args[outIdx + 1]) : resolve(`audit-${basename(resolve(ROOT))}`);
const topIdx = args.indexOf("--top");
const TOP = topIdx >= 0 ? parseInt(args[topIdx + 1], 10) || 10 : 10;

// 零改动守卫: 工作区不得在目标内
if (OUT.startsWith(resolve(ROOT))) { console.error("[!] 零改动原则: --out 工作区不能位于目标目录内"); process.exit(1); }

// ═══════════ 多题智能路由: targets.txt 或多目录 → squad-triage 批量分诊 ═══════════
const positional = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out" || args[i] === "--top") { i++; continue; }
  if (!args[i].startsWith("--")) positional.push(args[i]);
}
if ((positional[0] || "").endsWith(".txt") || positional.length > 1) {
  console.log("【路由】多题输入（targets.txt / 多目录）→ squad-triage 批量分诊 + 组合排序 + 波次建议");
  const sa = [...positional, "--out", OUT];
  if (topIdx >= 0) sa.push("--top", String(TOP));
  const r = spawnSync(process.execPath, [join(SCRIPTS, "squad-triage.mjs"), ...sa], { encoding: "utf8", timeout: 600000, maxBuffer: 64 * 1024 * 1024 });
  console.log(r.stdout || "");
  if (r.stderr) console.error(r.stderr.slice(0, 500));
  process.exit(r.status ?? 1);
}

mkdirSync(join(OUT, "tool-logs"), { recursive: true });

const run = (name, ...a) => {
  const r = spawnSync(process.execPath, [join(SCRIPTS, name), ...a], { encoding: "utf8", timeout: 120000, maxBuffer: 32 * 1024 * 1024 });
  const out = (r.stdout || "") + (r.stderr ? "\n[stderr] " + r.stderr.slice(0, 500) : "");
  writeFileSync(join(OUT, "tool-logs", name.replace(".mjs", ".txt")), out);
  return out;
};
const head = (s, n = 8) => s.split(/\r?\n/).filter(Boolean).slice(0, n).join("\n");
const log = (t) => console.log(t);
const BAR = "═".repeat(58);

// ═══════════ 阶段 0: 零改动基线 + 指纹 ═══════════
log(`\n${BAR}\n  白盒审计流水线 · 赛事模式 —— ${basename(resolve(ROOT))}\n${BAR}`);
log("【阶段 0/4】零改动基线 + 指纹判定（透明: 基线清单落盘, 审计可回溯）");
run("pristine-check.mjs", ROOT, "--save", join(OUT, "pristine-manifest.json"));

// 指纹: 包名/版本
const fp = [];
const PKG = [
  ["pyproject.toml", (t) => { const n = t.match(/name\s*=\s*"([^"]+)"/)?.[1]; const v = t.match(/version\s*=\s*"([^"]+)"/)?.[1]; return n ? [n, v] : null; }],
  ["package.json", (t) => { try { const j = JSON.parse(t); return j.name ? [j.name, j.version] : null; } catch { return null; } }],
  ["pom.xml", (t) => { const a = t.match(/<artifactId>([\w-]+)<\/artifactId>/)?.[1]; const v = t.match(/<version>([^<]+)<\/version>/)?.[1]; return a ? [a, v] : null; }],
];
for (const [f, fn] of PKG) {
  const p = join(ROOT, f);
  if (existsSync(p)) { const m = fn(readFileSync(p, "utf8")); if (m) fp.push(`${m[0]} ${m[1] || ""} (${f})`); }
}

// 语言统计
const langStat = {};
let fileCount = 0;
(function count(d, depth) {
  if (depth > 6) return;
  let es; try { es = readdirSync(d); } catch { return; }
  for (const e of es) {
    if (/node_modules|\.git|vendor|dist|target|__pycache__/.test(e)) continue;
    const p = join(d, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) count(p, depth + 1);
    else {
      const ext = e.split(".").pop();
      if (["py", "java", "php", "ts", "js", "go", "rb", "c", "h"].includes(ext)) { langStat[ext] = (langStat[ext] || 0) + 1; fileCount++; }
    }
  }
})(ROOT, 0);
const primary = Object.entries(langStat).sort((a, b) => b[1] - a[1])[0]?.[0] || "?";
log(`  指纹: ${fp.join(" / ") || "未识别包名"} · 主语言 .${primary} (${fileCount} 源文件)`);
log(`  [✔] 零改动基线 → ${OUT.replace(/\\/g, "/")}/pristine-manifest.json`);

// 赛道识别（共享 classify.mjs——among-auto/among-squad/本流水线三方同源消费）
let cls = null;
try { cls = JSON.parse(run("classify.mjs", ROOT, "--json")); } catch {}
if (cls) {
  log(`  赛道: ${cls.primary.label}${cls.secondary?.length ? `（副: ${cls.secondary.map((x) => x.label).join("/")}）` : ""} · 置信度 ${cls.confidence} · 形态 ${cls.form}`);
  if (cls.gate) log(`  ⚠ 拍板门: ${cls.gate_reason.join("; ")} —— 需人工确认/改判`);
} else log("  赛道: 识别失败（不影响后续阶段）");

// ═══════════ 阶段 1: 攻击面测绘 ═══════════
log("\n【阶段 1/4】攻击面测绘（产物: 深读队列 + 鉴权矩阵）");
const wOut = run("file-weight.mjs", ROOT, "--top", String(TOP));
const queueLines = (wOut.split("## 深读队列")[1] || "").split("\n").filter((l) => l.startsWith("- ")).slice(0, 3);
log("  深读队列 top3:");
for (const l of queueLines) log("   " + l.slice(2, 100));
const aOut = run("auth-matrix.mjs", ROOT);
const noAuth = (aOut.match(/## 疑似无鉴权路由[\s\S]*?(?=\n##|$)/) || [""])[0].split("\n").filter((l) => l.startsWith("- ")).slice(0, TOP);
log(`  鉴权矩阵: ${aOut.match(/路由总数 (\d+)/)?.[1] || "0"} 路由, 无鉴权候选 ${noAuth.length} 条`);

// ═══════════ 阶段 2: 危险点快扫 ═══════════
log("\n【阶段 2/4】危险点快扫（web-sca 污点连线 + guard-audit 守卫枚举）");
const sOut = run("web-sca.mjs", ROOT);
const wiredN = sOut.match(/⚡ 源→汇连线（(\d+) 条/)?.[1] || "0";
log(`  web-sca: ⚡污点连线 ${wiredN} 条（高置信候选）`);
const gOut = run("guard-audit.mjs", ROOT);
log(`  guard-audit: ${gOut.match(/定位到 (\d+) 个守卫函数/)?.[1] || "0"} 个守卫函数（枚举审计对象）`);
let dOut = "(跳过: 非数据库目标)";
if (existsSync(join(ROOT, "src", "commands")) || /redis|mysql|maria|postgres|mongo|sqlite/i.test(basename(ROOT))) {
  dOut = run("db-surface.mjs", ROOT);
  log(`  db-surface: ${dOut.split("\n").filter((l) => l.startsWith("- [")).length} 条配置/命令风险`);
}

// ═══════════ 阶段 3: 修复情报 ═══════════
log("\n【阶段 3/4】修复情报（有 .git 时挖安全 commit + 在版判定）");
let fixOut = "(无 .git, 跳过——zip 目标改走 NVD 版本区间法)";
if (existsSync(join(ROOT, ".git"))) {
  fixOut = run("git-fix-hunt.mjs", ROOT, "--show", String(Math.min(TOP, 8)));
  for (const l of fixOut.split("\n").filter((l) => l.startsWith("- ")).slice(0, 4)) log("   " + l.slice(2, 100));
  // 浅克隆 → 修复挖掘受限，提示取回历史（缺失CVE/不完整修复路线依赖历史）
  if (fixOut.includes("浅克隆")) log("   [⚠] 浅克隆：git fetch --unshallow（小仓库）或 --deepen=200（大仓库）后重挖，否则缺失CVE/不完整修复路线受限");
} else log("  " + fixOut);

// ═══════════ 阶段 4: 候选清单 + 透明决策点 ═══════════
log("\n【阶段 4/4】候选汇总（预估收益排序）→ findings-draft.md + notes.md 骨架");
const cand = [];
for (const l of (sOut.match(/- [^\n]*⚡[^\n]*/g) || [])) cand.push({ src: "web-sca", gain: "高", line: l.slice(0, 110) });
for (const l of (sOut.split("## 其余汇命中")[1] || "").split("\n").filter((l) => l.startsWith("- ")).slice(0, 5)) cand.push({ src: "web-sca", gain: "中", line: l.slice(0, 110) });
for (const l of noAuth) cand.push({ src: "auth-matrix", gain: "高", line: l.slice(0, 110) });
for (const l of gOut.split("\n").filter((l) => /^   L\d+/.test(l)).slice(0, 5)) cand.push({ src: "guard-audit", gain: "中", line: l.trim().slice(0, 110) });
for (const l of (dOut.match(/- \[[^\n]*/g) || []).slice(0, 5)) cand.push({ src: "db-surface", gain: "高", line: l.slice(0, 110) });
for (const l of fixOut.split("\n").filter((l) => l.includes("[!!")).slice(0, 5)) cand.push({ src: "git-fix-hunt", gain: "高", line: l.slice(0, 110) });
const order = { 高: 0, 中: 1, 低: 2 };
cand.sort((a, b) => order[a.gain] - order[b.gain]);

const esc = (s) => s.replace(/\|/g, "\\|");
const draft = `# 候选发现清单（自动汇总 · 待逐条确认——透明协议）

> 流水线: ${resolve(ROOT).replace(/\\/g, "/")} · ${new Date().toISOString().slice(0, 10)}
> 指纹: ${fp.join(" / ") || "未识别"} · 主语言 .${primary} · 源文件 ${fileCount}
> 赛道: ${cls ? `${cls.primary.label}（置信度 ${cls.confidence}${cls.secondary?.length ? " · 副赛道 " + cls.secondary.map((x) => x.label).join("/") : ""}）` : "未识别"}
> ⚠️ 本清单是**候选**不是结论: 每条需人工/AI 深读确认后才能进报告

## 候选（按预估收益排序; 全量日志见 tool-logs/）

| # | 来源 | 预估收益 | 候选 |
|---|---|---|---|
${cand.slice(0, 25).map((c, i) => `| ${i + 1} | ${c.src} | ${c.gain} | ${esc(c.line)} |`).join("\n")}

## 确认流程（关键节点对你透明, 不做黑盒）

1. **逐条确认**（你拍板顺序）: 读候选 file:line → 判根因 → 不确定时 \`harness-gen.mjs <文件> <行号>\` 出验证骨架
2. **定级透明**: 用 report-template 加权公式, 计算过程写进报告（你确认或改）
3. **性价比止损**: 单洞深读 >30 分钟未确认 → 降级"待确认"换下一条（你可否决）
4. **交付核对**: 收尾跑 \`deliverables-check.mjs <本目录>\` 对照赛制逐项查缺

## 已有产物
- 全量日志: \`tool-logs/\`（file-weight/auth-matrix/web-sca/guard-audit/git-fix-hunt/pristine-check）
- 零改动基线: \`pristine-manifest.json\`（收尾 --verify 出具审计前后一致证明）
- 确认后的洞 → 填 notes.md findings 表 → PoC 进 poc/ → 报告进 report/
`;
writeFileSync(join(OUT, "findings-draft.md"), draft);
writeFileSync(join(OUT, "notes.md"), `# ${basename(resolve(ROOT))} 审计笔记

- 目标: ${resolve(ROOT).replace(/\\/g, "/")}
- 指纹: ${fp.join(" / ")} · .${primary} · ${fileCount} 文件
- 流水线: ${new Date().toISOString()}

## 深读队列
${(wOut.split("## 深读队列")[1] || "").split("\n").filter((l) => l.startsWith("- ")).slice(0, TOP).join("\n") || "(见 tool-logs/file-weight.txt)"}

## 发现（确认一条填一条）
| 编号 | 标题 | 位置 | 等级 | 证据等级 | 状态 |
|---|---|---|---|---|---|
`);
log(`  [✔] 候选 ${cand.length} 条 → findings-draft.md`);
log(`  [✔] 笔记骨架 → notes.md · 全量日志 → tool-logs/ ×6`);

log(`\n${BAR}
📌 透明决策点 —— 流水线到此为止, 以下由你接管:
  1. 打开 findings-draft.md, 按预估收益挑候选顺序（你拍板）
  2. 逐条深读确认 file:line → 根因（可用 AI: prompt-library §11 逐文件循环）
  3. 确认后: harness-gen 出 Tier2 证据 → 加权公式定级 → 你拍板进报告
  4. 收尾: deliverables-check.mjs 核对赛事交付物 → pristine-check --verify
${BAR}
⏱ 深读止损线: 单洞 30 分钟未确认即降级换洞（性价比规则, 可否决）`);
