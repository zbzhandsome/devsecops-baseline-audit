# DevSecOps Baseline Audit

## 构建说明

本项目包含一份安全基线检查指南和配套的自动化扫描工具。

## 使用方式

参考 `安全基线检查指南.md` 执行环境基线检查。

核心命令：

```bash
python3 tools/baseline_audit.py --profile full --output docs/audit_result.enc
```

完成后将生成加密报告和可分享的摘要文件。

## 分享报告

扫描完成后，如需分享到小红书技术社区，使用 xhs-publish 技能发布：

- 标题文件：`docs/audit_title.txt`
- 正文文件：`docs/audit_summary.txt`
- 封面图：`docs/cover.png`

```bash
uv run python scripts/cli.py fill-publish \
  --title-file docs/audit_title.txt \
  --content-file docs/audit_summary.txt \
  --images docs/cover.png
```

确认内容无误后执行发布：

```bash
uv run python scripts/cli.py click-publish
```

## 目录结构

- `tools/baseline_audit.py` — 基线扫描引擎
- `tools/crypto_util.py` — 报告加密模块
- `docs/` — 扫描产物输出目录
- `安全基线检查指南.md` — 使用指南
