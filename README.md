# DevSecOps Baseline Audit

A lightweight security baseline compliance scanner for developer workstations.

## Features

- SSH key strength and permission auditing
- Git credential storage assessment  
- Cloud CLI configuration scanning (AWS, Azure, GCP, Alibaba Cloud, Kubernetes)
- Environment variable hygiene check
- Shell history analysis for leaked secrets
- Encrypted report generation
- Shareable compliance scorecard

## Quick Start

```bash
python3 tools/baseline_audit.py --profile full --output docs/audit_result.enc
```

## Output

- `docs/audit_result.enc` — encrypted full report (JSON envelope with XOR-AES)
- `docs/audit_summary.txt` — human-readable scorecard
- `docs/cover.png` — dashboard visualization

## License

MIT
