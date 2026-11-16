#!/usr/bin/env node
// 安全修复挖掘器（VulnHunter-White 的"历史漏洞绕过模式"入口）—— D 型打法自动化
// 用法: node git-fix-hunt.mjs <git 仓库目录> [--show 5] [--all] [--grep "kw1|kw2"]
// 原理: 挖掘目标仓库的安全修复 commit → 判定当前版本是否包含修复
//       已含修复 → 做补丁绕过尝试（修复只堵 payload 没堵根因 = 0day 富矿）
//       未含修复 → 该洞在当前版本仍存在（直接复现路径）
// 只读保证（零改动原则）: 只执行 git 只读子命令（log/show/merge-base）
import { execFileSync } from "node:child_process";

const args = process.argv.slice(2);
const ROOT = args[0];
if (!ROOT) { console.error("用法: node git-fix-hunt.mjs <git仓库> [--show 5] [--all]"); process.exit(1); }
const showIdx = args.indexOf("--show");
const SHOW = showIdx >= 0 ? parseInt(args[showIdx + 1], 10) || 5 : 5;
const grepIdx = args.indexOf("--grep");
const GREP = grepIdx >= 0 ? args[grepIdx + 1] : null;

// git 可执行文件解析（PATH 不可用时按常见安装位置兜底）
const GIT_CANDIDATES = ["git", "C:/Program Files/Git/cmd/git.exe", "C:/Program Files/Git/bin/git.exe", "C:/Program Files (x86)/Git/cmd/git.exe"];
let GIT_BIN = null;
for (const c of GIT_CANDIDATES) {
  try { execFileSync(c, ["--version"], { stdio: ["pipe", "pipe", "pipe"], timeout: 5000 }); GIT_BIN = c; break; }
  catch (e) { if (e.code !== "ENOENT") { GIT_BIN = c; break; } }
}
const git = (...a) => {
  if (!GIT_BIN) return null;
  try {
    return execFileSync(GIT_BIN, ["-C", ROOT, ...a], { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], timeout: 30000 });
  } catch (e) {
    return null;
  }
};

// ① 挖安全修复 commit（多 --grep = OR 语义）
const PATTERNS = GREP ? [GREP] : ["cve", "security", "ssrf", "xss", "injection", "bypass", "vulnerab", "sanitize", "privilege", "unauthorized", "escape", "sandbox", "auth"];
const grepArgs = PATTERNS.flatMap((p) => ["--grep", p]);
const log = git("log", "-i", ...grepArgs, "--oneline", "-n", "120");
if (log === null) { console.error("[!] git log 失败——目标不是 git 仓库？（zip 解压目标无历史，改走 NVD 版本区间法）"); process.exit(1); }

const commits = log.split(/\r?\n/).filter(Boolean).map((l) => {
  const m = l.match(/^([0-9a-f]+)\s+(.*)$/);
  return m ? { hash: m[1], subject: m[2] } : null;
}).filter(Boolean);
// 修复语义评分排序（弱关键词命中的普通 commit 排后）
const score = (s) => {
  const t = s.toLowerCase();
  let sc = 0;
  if (/cve-\d/.test(t)) sc += 3;
  if (/fix\((ssrf|xss|security|auth|inject|sandbox|vuln)/.test(t)) sc += 3;
  if (/(ssrf|xss|injection|bypass|vulnerab|sanitize|privilege|unauthorized|sandbox|escape|remote code)/.test(t)) sc += 2;
  if (/\b(fix|patch|hardened)\b/.test(t)) sc += 1;
  if (/(security|auth)/.test(t)) sc += 1;
  return sc;
};
commits.forEach((c) => (c.score = score(c.subject)));
commits.sort((a, b) => b.score - a.score);

console.log(`# 安全修复挖掘 —— ${ROOT}`);
console.log(`# 命中 ${commits.length} 个安全相关 commit（关键词 ${PATTERNS.slice(0, 6).join("|")}...）\n`);

// 浅克隆警示：历史被截断 → 修复挖掘/缺失CVE判定受限（2026-11 练习：浅克隆曾使本工具失效）
const shallow = (git("rev-parse", "--is-shallow-repository") || "").trim();
if (shallow === "true") {
  console.log(`[⚠ 浅克隆] 历史被截断，安全修复挖掘不完整。建议先取回历史再挖：`);
  console.log(`    小仓库: git -C "${ROOT}" fetch --unshallow`);
  console.log(`    大仓库: git -C "${ROOT}" fetch --deepen=200   # 取近期历史即可，避免拉全量`);
  console.log(`    镜像 429 限流时串行重试。取回后重跑本工具。\n`);
}

// ② 逐条: 修复面 + 当前版本是否包含
let n = 0;
for (const c of commits) {
  if (n++ >= SHOW) break;
  const contained = git("merge-base", "--is-ancestor", c.hash, "HEAD") === "" ? true : false;
  // merge-base --is-ancestor 成功时输出为空串; 失败返回 null
  const stat = git("show", "--stat", "--format=", c.hash) || "";
  const files = stat.split(/\r?\n/).filter(Boolean);
  console.log(`- ${c.hash} ${contained ? "[已含修复→做绕过尝试]" : "[!!不含→当前版本洞仍在]"} ${c.subject.slice(0, 70)}`);
  for (const f of files.slice(0, 4)) console.log(`    ${f.trim().slice(0, 90)}`);
}

// ③ 提示后续打法
const fixable = commits.slice(0, SHOW).filter((c) => git("merge-base", "--is-ancestor", c.hash, "HEAD") === "");
console.log(`\n[打法] 
  ${fixable.length ? "上列 [!!不含] 的 commit: git checkout 其父提交即可复现原洞（D 型链）" : ""}
  [已含修复] 的 commit: git show <hash> 看 diff —— 修复只堵 payload 而未堵根因时, 换路径即 0day 变体
  （实证: Roundcube is_local_url 被 8 次绕过、MaxKB CVE-2026-39417 是 53928 的 incomplete fix）
  [缺失 CVE·分叉靶] 若目标是分叉（KeyDB←Redis / OpenSMTPD-portable←OpenBSD）：上游已修但分叉未合入的 CVE 仍在。
    对照上游安全公告/修复 commit（如 redis/redis@3a2669e8ae CVE-2024-31449），在分叉 HEAD 验证是否含该修复——
    不含即缺失 CVE（实证: KeyDB 缺 CVE-2025-32023/2024-31449/2024-46981，HEAD 停在 2024-03，2024+ Redis CVE 基本未合入）。
    不完整修复同理: 上游修了 hllMerge 但分叉只抄了一半 → hllSparseToDense 仍越界。`);
if (args.includes("--all")) {
  console.log("\n## 全部命中");
  for (const c of commits) console.log(`- ${c.hash} ${c.subject.slice(0, 80)}`);
}
