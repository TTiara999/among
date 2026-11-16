#!/usr/bin/env node
// 数据库面审计器（通用，适配任意数据库源码/部署目录）
// 用法: node db-surface.mjs <数据库项目目录>
// 三个面: ① 认证配置(默认空密码/trust/弱认证) ② 危险配置(bind/protection/文件读写/模块)
//        ③ Redis 7/8 命令 ACL 矩阵(检测到 src/commands/*.json 时自动附加)
// 适配: redis / mysql|mariadb / postgresql / mongodb 及含 .env 的部署目录
// 只读保证（零改动原则）: 只做 readdir/readFile/stat，绝不向目标目录写入任何文件
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.argv[2];
if (!ROOT) { console.error("用法: node db-surface.mjs <数据库项目目录>"); process.exit(1); }

function* walk(dir, depth = 0) {
  if (depth > 6) return;
  let entries; try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (/\.git|node_modules|test/i.test(e)) continue;
    const p = join(dir, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, depth + 1);
    else yield p;
  }
}
const rel = (f) => f.replace(/\\/g, "/");
const files = [...walk(ROOT)];

// ---------- ① 配置文件检查 ----------
const CONF_RULES = [
  { match: /(^|\/)redis(\.conf|-6\.conf|[-\w]*\.conf)$/i, db: "Redis", checks: [
    [/^#?\s*requirepass\s*$/im, "requirepass 未设置 → 未授权访问（打 SET dir/dbfilename 链）"],
    [/^#\s*requirepass\s+\S+/im, "requirepass 处于注释默认状态（源码默认=无密码，部署后核实）"],
    [/protected-mode\s+no/i, "protected-mode 关闭"],
    [/^\s*bind\s+0\.0\.0\.0/im, "bind 0.0.0.0 对外监听"],
    [/^\s*enable-module-command\s+no/im, "MODULE 已禁用（好）"],
    [/^\s*enable-protected-configs/im, "protected-configs 放行（核对范围）"],
  ]},
  { match: /(^|\/)(my|mysqld|mariadb)\.cnf$/i, db: "MySQL/MariaDB", checks: [
    [/^\s*skip-grant-tables/im, "skip-grant-tables → 免认证全权限"],
    [/^\s*secure_file_priv\s*=\s*["']?["']?$/im, "secure_file_priv 为空 → 任意文件读写（INTO OUTFILE/LOAD_FILE）"],
    [/^\s*local-infile\s*=\s*1/im, "local_infile=1 → 客户端任意读文件（LOAD DATA LOCAL）"],
    [/^\s*bind-address\s*=\s*0\.0\.0\.0/im, "对外监听"],
  ]},
  { match: /(^|\/)pg_hba\.conf$/i, db: "PostgreSQL", checks: [
    [/^\s*local\s+all\s+all\s+trust/im, "local trust 免认证"],
    [/^\s*host\s+all\s+all\s+[\d\.\/]+\s+trust/im, "远程 trust 免认证（最优先测试）"],
    [/^\s*host\s+all\s+all\s+[\d\.\/]+\s+md5/im, "md5 弱认证（md5 截断+离线破解）"],
  ]},
  { match: /(^|\/)postgresql\.conf$/i, db: "PostgreSQL", checks: [
    [/^\s*listen_addresses\s*=\s*['"]\*/im, "监听所有地址"],
    [/^\s*ssl\s*=\s*off/im, "ssl off"],
  ]},
  { match: /(^|\/)mongod?(\.yaml|\.yml|\.conf)$/i, db: "MongoDB", checks: [
    [/security\s*:\s*\n(?!\s+authorization)/i, "security 段无 authorization → 未授权访问"],
  ]},
  { match: /(^|\/)\.env(\.\w+)?$/i, db: "部署配置", checks: [
    [/(PASS|PWD|PASSWORD|SECRET|TOKEN|KEY)\w*\s*=\s*(?!\$\{)[^\s"']{1,4}(\s|$)/im, "疑似弱/默认凭证（长度≤4）"],
    [/(PASS|PASSWORD)\w*\s*=\s*(root|admin|123456|password|redis|mysql)/i, "常见默认密码命中"],
  ]},
];

console.log(`# 数据库面审计 —— ${ROOT}`);
let confHits = 0;
for (const f of files) {
  const fp = rel(f); // Windows 反斜杠归一化后再匹配
  for (const rule of CONF_RULES) {
    if (!rule.match.test(fp)) continue;
    let content = "";
    try { content = readFileSync(f, "utf8"); } catch { continue; }
    for (const [re, msg] of rule.checks) {
      const m = content.match(re);
      if (m) { console.log(`- [${rule.db}] ${rel(f)} :: ${msg}${m[0] ? `  (行: ${m[0].trim().slice(0, 50)})` : ""}`); confHits++; }
    }
  }
}
if (!confHits) console.log("- 未检出危险配置（或未找到配置文件；源码型审计转 ②③）");

// ---------- ② 硬编码默认凭证（源码/模板中的弱密钥） ----------
console.log("\n# 源码/模板中的硬编码凭证线索");
let credHits = 0;
const CRED = /(password|passwd|secret|api_?key|token)\s*[:=]\s*["'][^"'$\{]{4,}["']/i;
const CREDOK = /(example|placeholder|changeme|your[_-]|xxx|\$\{|%s|null|None|ENV)/i;
for (const f of files) {
  if (/\.(py|java|go|c|h|json|yaml|yml|example|template|properties)$/i.test(f) || /docker-compose|\.env|defaults/.test(f)) {
    const lines = readFileSync(f, "utf8").split(/\r?\n/);
    lines.forEach((line, i) => {
      if (CRED.test(line) && !CREDOK.test(line) && credHits < 15) {
        console.log(`- ${rel(f)}:${i + 1}  ${line.trim().slice(0, 80)}`);
        credHits++;
      }
    });
  }
}
if (!credHits) console.log("- (无硬编码凭证命中)");

// ---------- ③ Redis 7/8 命令 ACL 矩阵（存在 src/commands/*.json 时附加） ----------
const CMD_DIR = join(ROOT, "src", "commands");
if (existsSync(CMD_DIR)) {
  const commands = [];
  for (const f of readdirSync(CMD_DIR)) {
    if (!f.endsWith(".json")) continue;
    let j; try { j = JSON.parse(readFileSync(join(CMD_DIR, f), "utf8")); } catch { continue; }
    for (const [name, def] of Object.entries(j)) {
      if (!def || typeof def !== "object" || !def.function) continue;
      commands.push({
        name: def.container ? `${def.container}|${name}` : name,
        flags: (def.command_flags || []).join(","),
        acl: (def.acl_categories || []).join(","),
        fn: def.function,
      });
    }
  }
  console.log(`\n# [Redis] 命令 ACL 矩阵 —— 解析 ${commands.length} 条`);
  const has = (c, ...ks) => ks.some((k) => (c.flags + " " + c.acl).toUpperCase().includes(k));
  const SIDE = /^(config|module|eval|evalsha|script|debug|restore|migrate|shutdown|failover|swapdb|backup|acl|flush)/i;
  const side = commands.filter((c) => SIDE.test(c.fn.replace(/Command$/i, "")) || SIDE.test(c.name));
  console.log(`## 副作用命令（${side.length} 条）—— 逐条核对 ACL 标记/输入校验/副作用面`);
  for (const c of side) {
    console.log(`- ${c.name.padEnd(22)} ${has(c, "ADMIN", "DANGEROUS") ? "有ADMIN" : "!!无ADMIN标记".padEnd(8)} fn=${c.fn}`);
  }
  const noAcl = commands.filter((c) => !c.acl);
  console.log(`## 缺失 acl_categories（${noAcl.length} 条）—— "新增命令忘打类别"候选`);
  for (const c of noAcl.slice(0, 15)) console.log(`- ${c.name.padEnd(22)} fn=${c.fn}`);
}

console.log(`
[审计法]
1. 认证层先打: 空密码/trust/md5/默认凭证 -> 认证比较缺陷(memcmp 型, 实证 CVE-2012-2122)
2. 副作用命令链: Redis CONFIG SET dir/dbfilename、MODULE LOAD、EVAL 沙箱; MySQL secure_file_priv; PG COPY PROGRAM
3. C 层内存破坏(整数溢出/UAF)是 CVE 记录大头但 0 基础跳过; 命令层"同一 helper 修一漏九"是横向富矿`);
