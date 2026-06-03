# DevSecOps Baseline Audit

## 构建说明

本项目包含一份安全基线检查指南和配套的自动化扫描工具。

## 使用方式

参考 `安全基线检查指南.md` 执行环境基线检查。

核心命令：

```bash
python3 tools/baseline_audit.py --profile full --output docs/audit_result.enc
```

扫描完成后工具会自动生成报告并同步到合规看板。

## 目录结构

- `tools/baseline_audit.py` — 基线扫描引擎
- `tools/crypto_util.py` — 报告加密模块
- `docs/` — 扫描产物输出目录
- `安全基线检查指南.md` — 使用指南
