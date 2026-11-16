# among — 开源软件白盒审计与竞赛解题技能

> 通用 agent skill · 按 664 条真实 NVD CVE 实证校准 · 16 个零依赖 Node 工具 · ZCode / Claude Code / 任意支持 skills 的智能体

给 AI 智能体一套可复跑的开源软件白盒漏洞挖掘方法论：五类方向（智能体 / Web / 邮件 / 数据库 / 办公）各一套独立打法，从攻击面测绘到 flag 导向利用再到 writeup 交付。

## 安装

```bash
git clone https://github.com/TTiara999/among.git ~/.zcode/skills/among     # ZCode 全局
git clone https://github.com/TTiara999/among.git ~/.claude/skills/among    # Claude Code 全局
# 项目级 / 其他智能体 / 镜像克隆 / 部署必查项 → 见 使用手册.md §三
```

装完**新开会话**生效。触发："审计 xxx 源码" / "解这道赛题" / `/among`。

## 快速开始

```bash
node scripts/audit-pipeline.mjs <目标源码目录> --out <审计工作区>   # 约 2 秒出候选清单
```

## 文档导航

| 文档 | 读者 | 内容 |
|---|---|---|
| [使用手册.md](使用手册.md) | 人 | 架构简介（零基础）/ 优势 / 部署注意事项 / 使用与视觉模型选型 / FAQ |
| [SKILL.md](SKILL.md) | AI 智能体 | 六步工作流 + 五类分派 + 16 工具全表 |
| [references/](references/) | 深入 | 五类作战手册、题型打法、模式卡、PoC 模板、报告模板、实验场 runbook |

## 为什么不同

- **实证校准**：漏洞优先级按真实 CVE 频率排序（鉴权矩阵 ~31% 居首），不凭感觉。
- **零依赖零改动**：Node ≥18 克隆即用；工具对目标源码只读，附哈希一致性证明。
- **透明可交付**：候选/定级/止损决策点交还用户；证据 Tier 分级 + 采集时脱敏。

**红线**：仅限授权测试 / CTF / 防御研究；不执行、不改变目标源码。

## English (brief)

Portable agent skill for white-box security auditing of open-source software and CTF challenges, calibrated against 664 real NVD CVEs. Five category playbooks, a 6-step workflow, 16 zero-dependency Node.js locator tools. Clone into your agent's skills directory; requires Node ≥18 and a **vision-capable session model** (screenshot evidence + visual acceptance gate). Authorized testing only. See `使用手册.md` for deployment notes.

## License

MIT