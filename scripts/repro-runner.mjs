#!/usr/bin/env node
// repro-runner.mjs — 复现证据采集器（零依赖 Node 24 · 只写工作区 evidence/ · 采集时脱敏）
// 用法: node repro-runner.mjs <steps.json> [--out <evidence根目录, 默认 ./evidence>]
// steps.json 契约:
// {
//   "finding": "F-01", "title": "...", "tier": 3,           // tier: 2=harness级 3=完整目标级（标注进 SUMMARY）
//   "redact": ["password=[^&\\s]+"],                        // 正则表——落盘前打码，不是写报告时才处理
//   "steps": [
//     {"name":"探测","type":"http","method":"GET","url":"http://127.0.0.1/","expect":"302"},
//     {"name":"越权","type":"http","method":"POST","url":"...","headers":{},"body":"...","expect":"200"},
//     {"name":"redis写","type":"tcp","host":"127.0.0.1","port":6379,"payload_lines":["CONFIG SET dir /tmp"],"expect":"+OK","timeout":10000},
//     {"name":"投递","type":"smtp","host":"127.0.0.1","port":25,"from":"a@x.test","to":"v@t.test","body_lines":["Subject: hi","","<p>ghost</p>"]}
//   ]
// }
// 产物: <out>/<finding>/NN-<name>.request.txt | .response.txt | SUMMARY.md（可整段粘贴进报告 §3 复现步骤）
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { createHash } from "node:crypto";

const args = process.argv.slice(2);
const STEPS_FILE = args[0];
if (!STEPS_FILE || !existsSync(STEPS_FILE)) {
  console.error("用法: node repro-runner.mjs <steps.json> [--out <目录>]");
  process.exit(1);
}
const spec = JSON.parse(readFileSync(STEPS_FILE, "utf8"));
const ns = String(spec.finding || spec.namespace || "MISC").replace(/[^\w-]/g, "_");
const outIdx = args.indexOf("--out");
const OUT = resolve(outIdx >= 0 ? args[outIdx + 1] : "evidence");
const repIdx = args.indexOf("--repeat");
const REPEAT = Math.max(1, repIdx >= 0 ? parseInt(args[repIdx + 1], 10) || 1 : 1); // 稳定性连测次数（赛制 m5：连续 N 次稳定复现）
const dir = join(OUT, ns);
mkdirSync(dir, { recursive: true });

// 注意: JS RegExp 无 PCRE 内联修饰符——(?i) 前缀剥离为构造器 gi 标志; 其余按原样; 不合法则丢弃
const redactRes = (spec.redact || []).map((s) => {
  try { return new RegExp(s, "g"); } catch {}
  if (s.startsWith("(?i)")) { try { return new RegExp(s.slice(4), "gi"); } catch { return null; } }
  return null;
}).filter(Boolean);
const clean = (t) => { let s = String(t); for (const re of redactRes) s = s.replace(re, "[REDACTED]"); return s; };
const sha = (t) => createHash("sha256").update(t).digest("hex").slice(0, 16);
const fname = (n) => n.replace(/[^\w.\-]+/g, "-").replace(/-+/g, "-").slice(0, 40);

const CAP = 65536;
const cut = (s) => s.length > CAP ? s.slice(0, CAP) + `\n...(截断, 共 ${s.length} 字节)` : s;

// ── http 步骤 ──
function httpStep(step) {
  return new Promise((resolve) => {
    const u = new URL(step.url);
    const method = (step.method || "GET").toUpperCase();
    const headers = { ...(step.headers || {}) };
    if (!Object.keys(headers).some((k) => k.toLowerCase() === "user-agent")) headers["User-Agent"] = "ARTEX-repro-runner/1.0";
    const body = step.body ?? null;
    if (body && !Object.keys(headers).some((k) => k.toLowerCase() === "content-length")) headers["Content-Length"] = Buffer.byteLength(body);
    const requestText = `${method} ${u.pathname + u.search} HTTP/1.1\r\nHost: ${u.host}\r\n` +
      Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\r\n") + `\r\n\r\n${body || ""}`;
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request(u, { method, headers, timeout: step.timeout || 15000 }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const bodyText = Buffer.concat(chunks).toString("utf8");
        const responseText = `HTTP/1.1 ${res.statusCode} ${res.statusMessage}\r\n` +
          Object.entries(res.headers).map(([k, v]) => `${k}: ${v}`).join("\r\n") + `\r\n\r\n${cut(bodyText)}`;
        const expect = step.expect == null ? true : String(res.statusCode).indexOf(String(step.expect)) >= 0;
        resolve({ ok: expect, status: res.statusCode, requestText: cut(requestText), responseText, expect: String(step.expect) });
      });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => resolve({ ok: false, status: 0, requestText: cut(requestText), responseText: `ERROR: ${e.message}` }));
    if (body) req.write(body);
    req.end();
  });
}

// ── tcp 明文步骤（redis/mysql 类协议）──
function tcpStep(step) {
  return new Promise((resolve) => {
    const lines = step.payload_lines || [step.payload || ""];
    const crlf = step.crlf !== false;
    const payload = lines.map((l) => l + (crlf ? "\r\n" : "\n")).join("");
    const requestText = `[TCP -> ${step.host}:${step.port}]\r\n${payload}`;
    const sock = net.connect({ host: step.host, port: step.port, timeout: step.timeout || 10000 }, () => sock.write(payload));
    let data = "";
    let closing = false;
    const linger = step.linger !== undefined ? step.linger : 300; // 首块响应后延迟 ms 主动收尾——长连接协议(redis/mysql)不会自己关
    sock.on("data", (d) => {
      data += d.toString("utf8");
      if (!closing) { closing = true; setTimeout(() => sock.destroy(), linger); }
      if (data.length > CAP) { data = data.slice(0, CAP); sock.destroy(); }
    });
    sock.on("close", () => {
      const responseText = `[TCP <- ${step.host}:${step.port}]\r\n${data || "(无返回数据)"}`;
      const expect = step.expect == null ? data.length > 0 : data.includes(step.expect);
      resolve({ ok: expect, status: "closed", requestText, responseText, expect: String(step.expect) });
    });
    sock.on("error", (e) => resolve({ ok: false, status: 0, requestText, responseText: `ERROR: ${e.message}` }));
  });
}

// ── smtp 投递步骤（邮件类题"恶意邮件"证据）──
function smtpStep(step) {
  return new Promise((resolve) => {
    const log = [];
    const sock = net.connect({ host: step.host, port: step.port || 25, timeout: step.timeout || 15000 });
    let buf = "", waiters = [], failed = false;
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      while (true) {
        const i = buf.indexOf("\r\n");
        if (i < 0) break;
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        log.push(`S: ${line}`);
        const w = waiters.shift();
        if (w) w(line);
      }
    });
    sock.on("error", (e) => { failed = true; resolve({ ok: false, status: 0, requestText: "(连接失败)", responseText: `ERROR: ${e.message}\r\n${cut(log.join("\r\n"))}` }); });
    const cmd = (line) => new Promise((r) => { waiters.push(r); log.push(`C: ${line}`); sock.write(line + "\r\n"); });
    (async () => {
      try {
        await cmd("HELO repro.local");
        await cmd(`MAIL FROM:<${step.from || "repro@local.test"}>`);
        await cmd(`RCPT TO:<${step.to}>`);
        await cmd("DATA");
        for (const l of step.body_lines || [step.body || ""]) { log.push(`C: ${l}`); sock.write(l + "\r\n"); }
        await cmd(".");
        await cmd("QUIT");
        const responseText = cut(log.join("\r\n"));
        resolve({ ok: !log.some((l) => l.startsWith("S: 5")), status: "completed", requestText: "SMTP 会话见 response(含 C: 发送侧)", responseText });
      } catch { if (!failed) resolve({ ok: false, status: 0, responseText: cut(log.join("\r\n")) }); }
    })();
  });
}

// ── 主流程 ──
// 每步硬超时兜底（连接黑洞/keep-alive 挂起防护; 默认取步骤 timeout 上限 +5s 或全局 45s）
const withDeadline = (p, step) => {
  const hard = Math.min(45000, (step.timeout || 15000) + 5000);
  return Promise.race([
    p,
    new Promise((resolve) => setTimeout(() => resolve({ ok: false, status: "HARD-TIMEOUT", requestText: "(未记录)", responseText: `ERROR: 步骤硬超时(${hard}ms)——目标黑洞或无响应通道, 检查 host/port 与执行侧(建议 WSL 内靶用 WSL IP 直连)` }), hard)),
  ]);
};
// 执行一遍全部步骤，证据写入 targetDir，返回 {pass, fail, summary}
async function runSteps(targetDir) {
  mkdirSync(targetDir, { recursive: true });
  const summary = [];
  summary.push(`# Evidence: ${spec.finding || ns} — ${spec.title || "(无标题)"}`);
  summary.push(`- tier: ${spec.tier || 3} ${spec.tier === 2 ? "(harness 逻辑级)" : "(完整目标环境级)"}`);
  summary.push(`- collected: ${new Date().toISOString()}`);
  summary.push(`- namespace: ${ns}`);
  summary.push("");
  let pass = 0, fail = 0;
  for (let i = 0; i < (spec.steps || []).length; i++) {
    const step = spec.steps[i];
    const name = fname(step.name || `step-${i + 1}`);
    const num = String(i + 1).padStart(2, "0");
    const runner = step.type === "tcp" ? tcpStep : step.type === "smtp" ? smtpStep : httpStep;
    const r = await withDeadline(runner(step), step);
    if (r.ok) pass++; else fail++;
    writeFileSync(join(targetDir, `${num}-${name}.request.txt`), clean(r.requestText));
    writeFileSync(join(targetDir, `${num}-${name}.response.txt`), clean(r.responseText));
    summary.push(`### ${num}. ${step.name || name}${r.ok ? "" : "  ⚠ FAILED"}`);
    summary.push(`- 类型: ${step.type} · 断言: ${r.expect == null || r.expect === "" ? "有响应即可" : `expect=${r.expect}`}${r.ok ? " · ✓" : " · ✗ 实际不满足"}`);
    summary.push(`- 响应 sha256: ${sha(clean(r.responseText))}`);
    summary.push("");
    summary.push("```");
    summary.push(clean(cut(r.requestText)));
    summary.push("```");
    summary.push("```");
    summary.push(clean(r.responseText));
    summary.push("```");
    summary.push("");
  }
  writeFileSync(join(targetDir, "SUMMARY.md"), summary.join("\n"));
  return { pass, fail, summary };
}

(async () => {
  const nSteps = (spec.steps || []).length;
  if (REPEAT <= 1) {
    const { pass, fail } = await runSteps(dir);
    console.log(`[repro-runner] ${ns}: ${pass}/${nSteps} 步通过 → ${dir.replace(/\\/g, "/")}/SUMMARY.md`);
    if (fail > 0) process.exit(1);
    return;
  }
  // 稳定性连测：连续 REPEAT 次，逐次落盘 runK/，汇总 STABILITY.md（赛制 m5 证据）
  const runs = [];
  for (let k = 1; k <= REPEAT; k++) {
    const { pass, fail } = await runSteps(join(dir, `run${k}`));
    runs.push({ k, pass, fail, ok: fail === 0 && pass === nSteps });
    console.log(`[repro-runner] ${ns} run${k}/${REPEAT}: ${pass}/${nSteps} 步通过${fail ? " ⚠" : ""}`);
  }
  const okRuns = runs.filter((r) => r.ok).length;
  const stable = okRuns === REPEAT;
  const S = [];
  S.push(`# 稳定性连测: ${spec.finding || ns} — ${spec.title || "(无标题)"}`);
  S.push(`- 连续 ${REPEAT} 次 · 成功 ${okRuns}/${REPEAT} · 判定: ${stable ? "稳定复现 ✓（可锁 m5=5）" : okRuns === 0 ? "未复现 ✗" : "偶现 ⚠（m5 降档，需排查竞态/环境）"}`);
  S.push(`- collected: ${new Date().toISOString()}`);
  S.push("");
  S.push("| 轮次 | 通过步 | 结果 |");
  S.push("|---|---|---|");
  for (const r of runs) S.push(`| run${r.k} | ${r.pass}/${nSteps} | ${r.ok ? "✓" : "✗"} |`);
  S.push("");
  S.push("> 各轮完整请求/响应见 runK/SUMMARY.md。偶现漏洞是赛制大忌——稳定 PoC 才是拿分底线。");
  writeFileSync(join(dir, "STABILITY.md"), S.join("\n"));
  console.log(`[repro-runner] ${ns}: 稳定性 ${okRuns}/${REPEAT} → ${dir.replace(/\\/g, "/")}/STABILITY.md`);
  if (!stable) process.exit(1);
})();