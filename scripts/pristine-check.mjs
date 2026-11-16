#!/usr/bin/env node
// 源码零改动校验器 —— 落实「不改变源码」原则，出具可验证的完整性证明
// 用法:
//   建基线:  node pristine-check.mjs <目标目录> --save <清单路径>
//   校验:    node pristine-check.mjs <目标目录> --verify <清单路径>
// 规则: 清单文件绝不写进目标目录（默认写在当前工作目录）；排除 .git 元数据
import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

// git 可执行文件解析（PATH 不可用时按常见安装位置兜底）
const GIT_CANDIDATES = ["git", "C:/Program Files/Git/cmd/git.exe", "C:/Program Files/Git/bin/git.exe"];
let GIT_BIN = null;
for (const c of GIT_CANDIDATES) {
  try { execFileSync(c, ["--version"], { stdio: ["pipe", "pipe", "pipe"], timeout: 5000 }); GIT_BIN = c; break; }
  catch (e) { if (e.code !== "ENOENT") { GIT_BIN = c; break; } }
}

const args = process.argv.slice(2);
const ROOT = args[0];
if (!ROOT || (!args.includes("--save") && !args.includes("--verify"))) {
  console.error("用法: node pristine-check.mjs <目标目录> --save|--verify <清单路径>");
  process.exit(2);
}
const mode = args.includes("--save") ? "save" : "verify";
const flagIdx = args.indexOf(`--${mode}`);
const manifest = args[flagIdx + 1] && !args[flagIdx + 1].startsWith("--") ? args[flagIdx + 1] : "pristine-manifest.json";
const NORM_CRLF = args.includes("--normalize-crlf"); // 跨平台（Windows建基线/WSL校验）时把仅CRLF差异视为一致
const rootAbs = resolve(ROOT).replace(/\\/g, "/");

function* walk(dir, depth = 0) {
  if (depth > 9) return;
  let entries; try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (e === ".git") continue; // git 元数据不属于"源码"
    const p = join(dir, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, depth + 1);
    else yield p;
  }
}
const rel = (f) => f.replace(/\\/g, "/").replace(rootAbs + "/", "");

function snapshot() {
  const files = {};
  for (const f of walk(ROOT)) {
    const data = readFileSync(f);
    const md5 = createHash("md5").update(data).digest("hex");
    // 去 CR(0x0d) 归一化哈希：用于识别跨平台 CRLF 幻影差异（文本 CRLF→LF 后一致）
    const md5_norm = createHash("md5").update(Buffer.from(data.filter((b) => b !== 13))).digest("hex");
    files[rel(f)] = { size: data.length, md5, md5_norm };
  }
  return files;
}

if (mode === "save") {
  const outPath = resolve(manifest);
  if (outPath.replace(/\\/g, "/").startsWith(rootAbs + "/")) {
    console.error("[!] 零改动原则: 清单不能写进目标目录");
    process.exit(1);
  }
  const m = { target: rootAbs, at: new Date().toISOString(), files: snapshot() };
  writeFileSync(outPath, JSON.stringify(m));
  console.log(`[+] 基线已记录: ${Object.keys(m.files).length} 个文件 -> ${outPath.replace(/\\/g, "/")}`);
} else {
  if (!existsSync(manifest)) { console.error(`[!] 找不到清单 ${manifest}`); process.exit(2); }
  const m = JSON.parse(readFileSync(manifest, "utf8"));
  const now = snapshot();
  const added = Object.keys(now).filter((k) => !(k in m.files));
  const removed = Object.keys(m.files).filter((k) => !(k in now));
  const rawModified = Object.keys(m.files).filter((k) => k in now && m.files[k].md5 !== now[k].md5);
  // --normalize-crlf：原始哈希不同但去CR哈希相同 → 仅 CRLF 幻影差异，不算真实修改
  const crlfOnly = NORM_CRLF ? rawModified.filter((k) => m.files[k].md5_norm && m.files[k].md5_norm === now[k].md5_norm) : [];
  const modified = rawModified.filter((k) => !crlfOnly.includes(k));
  const clean = !added.length && !removed.length && !modified.length;
  console.log(`# 零改动校验 —— ${m.target}（基线 ${m.at}，${Object.keys(m.files).length} 文件）${NORM_CRLF ? " · CRLF归一化" : ""}`);
  for (const f of added.slice(0, 20)) console.log(`  + 新增 ${f}`);
  for (const f of removed.slice(0, 20)) console.log(`  - 删除 ${f}`);
  for (const f of modified.slice(0, 20)) console.log(`  ~ 修改 ${f}`);
  if (crlfOnly.length) console.log(`[i] 仅 CRLF 行尾差异 ${crlfOnly.length} 个（跨平台幻影，已忽略，非真实改动）`);
  console.log(clean ? "[✔] 目标源码与基线完全一致（零改动原则达成）" : "[✘] 存在差异（见上）——若非你本人改动，需排查");
  try {
    if (!GIT_BIN) throw new Error("no git");
    const gs = execFileSync(GIT_BIN, ["-C", ROOT, "status", "--porcelain"], { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    const lines = gs.split(/\r?\n/).filter(Boolean);
    if (lines.length) { console.log("[i] git status 差异:"); lines.slice(0, 10).forEach((l) => console.log("   " + l)); }
    else if (clean) console.log("[i] git status 亦为空");
  } catch { /* 非 git 仓库则跳过 */ }
  process.exit(clean ? 0 : 1);
}
