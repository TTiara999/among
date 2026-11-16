#!/usr/bin/env node
// 局部验证 Harness 生成器（DeepAudit 的 mock 验证思想）—— 把 Tier2 证据自动化
// 用法: node harness-gen.mjs <文件> <行号> [--out <输出文件>]
// 原理: 定位行号所属函数 → 抽取函数体与 import 区 → 生成"危险调用被 spy 拦截"的
//       可运行骨架：mock 壳记录调用即证明"输入可达危险点"（成本与准确性的平衡点）
// 局限（如实标注）: 不能证明 HTTP 入口真实可达/鉴权不拦——那需要 Tier3 靶场
// 只读保证（零改动原则）: 只读目标文件，harness 写到工作区（--out 默认当前目录）
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { execFileSync } from "node:child_process";

const args = process.argv.slice(2);
const FILE = args[0];
const LINE = parseInt(args[1], 10);
if (!FILE || !LINE) { console.error("用法: node harness-gen.mjs <文件> <行号> [--out harness.py]"); process.exit(1); }
const outIdx = args.indexOf("--out");
const OUT = outIdx >= 0 ? args[outIdx + 1] : "harness.py";

const lines = readFileSync(FILE, "utf8").split(/\r?\n/);
const isPy = FILE.endsWith(".py");
const LANG = isPy ? "py" : FILE.endsWith(".php") ? "php" : "js";

// ---------- ① 定位行号所属函数 ----------
let fnStart = -1, fnEnd = lines.length, fnName = "target";
if (isPy) {
  // 向上找"最近的、缩进更小的 def"——不因中途遇到 if/for 等更小缩进行而误断跳出函数
  const targetIndent = (lines[LINE - 1].match(/^\s*/) || [""])[0].length;
  for (let i = LINE - 1; i >= 0; i--) {
    const l = lines[i];
    const m = l.match(/^\s*(?:async\s+)?def\s+(\w+)/);
    const ind = (l.match(/^\s*/) || [""])[0].length;
    if (m && ind < targetIndent) { fnStart = i; fnName = m[1]; break; }
    const cls = l.match(/^\s*class\s+\w+/);
    if (cls && ind < targetIndent && ind <= 4) break; // 走到类体仍未遇 def → 失败
  }
  if (fnStart >= 0) {
    const fnIndent = (lines[fnStart].match(/^\s*/) || [""])[0].length;
    for (let i = fnStart + 1; i < lines.length; i++) {
      const l = lines[i];
      if (l.trim() && (l.match(/^\s*/) || [""])[0].length <= fnIndent && !l.trim().startsWith("#")) { fnEnd = i; break; }
    }
  }
} else {
  // 大括号语言: 向上找函数签名行, 配平取体
  let depth = 0, seenOpen = false;
  for (let i = LINE - 1; i >= 0; i--) {
    const l = lines[i];
    for (const ch of l) {
      if (ch === "}") depth++;
      else if (ch === "{") { if (depth === 0 && seenOpen === false) { seenOpen = true; } if (seenOpen && depth === 0) { fnStart = i; fnEnd = LINE; } depth--; }
    }
    const m = l.match(/(?:function\s+(\w+)|(?:public|private|protected)\s+[\w<>\[\]]+\s+(\w+))\s*\(/);
    if (m && l.includes("{")) { fnStart = i; fnName = m[1] || m[2]; break; }
    if (fnStart >= 0) break;
  }
  if (fnStart >= 0) { // 向下配平到闭括号
    let d = 0;
    for (let i = fnStart; i < lines.length; i++) {
      for (const ch of lines[i]) { if (ch === "{") d++; else if (ch === "}") { d--; if (d === 0) { fnEnd = i + 1; break; } } }
      if (d === 0 && i > fnStart) break;
    }
  }
}
if (fnStart < 0) { console.error("[!] 未能定位所属函数（行号或语言不适用）"); process.exit(1); }

// ---------- ② 提取函数体与 import 区 ----------
const fnBody = lines.slice(fnStart, Math.min(fnEnd, fnStart + 120));
const imports = lines.slice(0, fnStart).filter((l) =>
  isPy ? /^\s*(?:import|from)\s+\S/.test(l) : /^\s*(?:import|const|let|var|require|using)\s/.test(l)
).slice(-25);

// ---------- ③ 生成 harness ----------
const targetLine = lines[LINE - 1].trim().slice(0, 90);
let harness;
if (isPy) {
  harness = `# ===== 局部验证 Harness（自动生成，Tier2 证据）=====
# 目标: ${FILE.replace(/\\\\/g, "/")}:${LINE}  函数: ${fnName}()
# 目标行: ${targetLine}
# 用法: python ${OUT} —— 危险调用被 spy 拦截并打印, 即证明"构造输入可达危险点"
# 局限: 不能证明入口真实可达/鉴权不拦（Tier3 靶场才可证）
# 只读原则: 本文件生成于工作区, 未改动目标源码

# ---- 原 import 区 ----
${imports.join("\n") || "(无)"}

# ---- 危险调用 spy（观察是否被触发）----
import sys
CALLS = []
class _Resp:
    status_code, text, content = 200, "HIT", b"HIT"
try:
    import requests
    def _fake_get(*a, **k):
        CALLS.append(("requests.get", str(a)[:120]))
        print(f"[SPY] requests.get 被调用: {str(a)[:120]}")
        return _Resp()
    requests.get = _fake_get
    def _fake_post(*a, **k):
        CALLS.append(("requests.post", str(a)[:120]))
        print(f"[SPY] requests.post 被调用: {str(a)[:120]}")
        return _Resp()
    requests.post = _fake_post
except ImportError:
    pass
try:
    import os
    def _fake_system(cmd):
        CALLS.append(("os.system", str(cmd)[:120]))
        print(f"[SPY] os.system 被调用: {cmd}")
        return 0
    os.system = _fake_system
except ImportError:
    pass

# ---- 目标函数（原文抽取）----
${fnBody.join("\n")}

# ---- 触发（TODO: 按函数签名构造参数）----
if __name__ == "__main__":
    # TODO: ${fnName} 需要的参数/实例(self) 在此构造
    #   例如: obj = SomeClass(...); obj.${fnName}(PAYLOAD)
    print("[TODO] 请按上方签名构造调用参数后运行")
    print(f"[info] 目标函数: ${fnName}, 起始行 {fnStart + 1}, 长度 ${fnEnd - fnStart} 行")
`;
} else {
  harness = `// ===== 局部验证 Harness（自动生成，Tier2 证据）=====
// 目标: ${FILE.replace(/\\\\/g, "/")}:${LINE}  函数: ${fnName}()
// 目标行: ${targetLine}
const CALLS = [];
const _orig = { exec: global.exec, eval: global.eval };
global.exec = (...a) => { CALLS.push(["exec", String(a).slice(0, 120)]); console.log("[SPY] exec:", String(a).slice(0, 120)); };
// TODO: 若函数依赖模块级上下文, 在此补 import/mock

${imports.join("\n")}

${fnBody.join("\n")}

// ---- 触发 ----
if (require.main === module) {
  // TODO: 构造参数调用 ${fnName}(PAYLOAD)
  console.log("[TODO] 按签名构造参数; CALLS 非空 = 输入可达危险点");
}
`;
}

// 零改动守卫: 不写进目标目录
const outDir = dirname(resolve(OUT));
try {
  const markers = readdirSync(outDir).filter((f) => /^(pyproject\.toml|package\.json|pom\.xml|composer\.json|setup\.py)$/.test(f) || f === "src");
  if (markers.length && !args.includes("--force")) {
    console.error(`[!] 零改动原则: 输出目录疑似目标（${markers[0]}）。--out 指到目标外或 --force。`);
    process.exit(1);
  }
} catch {}
writeFileSync(OUT, harness);
console.log(`[+] Harness 已生成: ${resolve(OUT).replace(/\\\\/g, "/")}`);
console.log(`    函数: ${fnName}()  行 ${fnStart + 1}-${Math.min(fnEnd, fnStart + 120)}  语言: ${LANG}`);
console.log(`    下一步: 填 TODO 参数并运行, SPY 打印 = Tier2 证据（可达性证明）`);
