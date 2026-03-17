# Cloud Misconfiguration Audit Lab

A Python-based cloud security audit tool that detects, exploits,
and remediates AWS misconfigurations using LocalStack.

## What It Does

| Script | Purpose |
|--------|---------|
| `setup_vulnerable.py` | Creates misconfigured AWS environment |
| `audit.py` | Scans and detects all misconfigurations |
| `fix.py` | Remediates all findings automatically |
| `report.py` | Generates HTML audit report |

## Findings Detected

| Severity | Count | Finding |
|----------|-------|---------|
| CRITICAL | 2 | Public S3 bucket, IAM wildcard policy |
| MEDIUM | 6 | Missing versioning, encryption, MFA |

## Skills Demonstrated

- AWS S3 and IAM security auditing
- Python boto3 cloud automation
- Misconfiguration detection and remediation
- Security report generation
- Cloud security best practices

## Tools Used

- Python 3 + boto3
- LocalStack (AWS simulator)
- Docker

## Run It
```bash
# Start LocalStack
docker run --rm -it -p 4566:4566 localstack/localstack

# Run the full audit cycle
python setup_vulnerable.py   # create vulnerable environment
python audit.py              # find misconfigurations
python fix.py                # remediate all findings
python report.py             # generate HTML report
```