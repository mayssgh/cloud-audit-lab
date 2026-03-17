import json
from datetime import datetime


def generate_report(filepath="audit_report.html"):
    """
    Generates a professional HTML audit report
    from the findings.json file produced by audit.py
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Load findings
    try:
        with open("findings.json", "r") as f:
            findings = json.load(f)
    except FileNotFoundError:
        print("[!] findings.json not found — run audit.py first")
        return

    # Count by severity
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high     = [f for f in findings if f["severity"] == "HIGH"]
    medium   = [f for f in findings if f["severity"] == "MEDIUM"]
    low      = [f for f in findings if f["severity"] == "LOW"]

    # Build findings rows
    rows = ""
    for i, f in enumerate(findings, 1):
        severity = f["severity"]

        if severity == "CRITICAL":
            badge = '<span style="background:#ff4444;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">CRITICAL</span>'
        elif severity == "HIGH":
            badge = '<span style="background:#ff6600;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">HIGH</span>'
        elif severity == "MEDIUM":
            badge = '<span style="background:#ff9900;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">MEDIUM</span>'
        else:
            badge = '<span style="background:#2196F3;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">LOW</span>'

        rows += f"""
        <tr>
            <td>{i}</td>
            <td>{f['resource']}</td>
            <td>{f['issue']}</td>
            <td style="color:#94a3b8;font-size:13px;">{f['detail']}</td>
            <td style="color:#10b981;font-size:13px;">{f['remediation']}</td>
            <td>{badge}</td>
        </tr>
        """

    # Build executive summary rows
    summary_rows = ""
    for f in critical:
        summary_rows += f"""
        <tr>
            <td><code>{f['resource']}</code></td>
            <td>{f['issue']}</td>
            <td><span style="background:#ff4444;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">CRITICAL</span></td>
            <td style="color:#10b981;font-size:13px;">{f['remediation']}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Misconfiguration Audit Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0a0d14;
            color: #e2e8f0;
            padding: 40px 20px;
        }}

        .container {{ max-width: 1100px; margin: 0 auto; }}

        /* Header */
        .header {{
            background: #111520;
            border: 1px solid #1e2535;
            border-top: 3px solid #f59e0b;
            border-radius: 8px;
            padding: 32px;
            margin-bottom: 24px;
        }}

        .header h1 {{
            font-size: 26px;
            color: #f59e0b;
            margin-bottom: 8px;
        }}

        .header p {{
            color: #64748b;
            font-size: 14px;
            line-height: 1.8;
        }}

        /* Cards */
        .cards {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }}

        .card {{
            background: #111520;
            border: 1px solid #1e2535;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .card .number {{
            font-size: 2rem;
            font-weight: bold;
        }}

        .card .label {{
            font-size: 11px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-top: 4px;
        }}

        .total   {{ color: #00e5ff; }}
        .crit    {{ color: #ff4444; }}
        .high    {{ color: #ff6600; }}
        .med     {{ color: #ff9900; }}
        .low     {{ color: #2196F3; }}

        /* Status banner */
        .banner {{
            background: #ff444422;
            border: 1px solid #ff4444;
            border-radius: 8px;
            padding: 16px 24px;
            margin-bottom: 24px;
            color: #ff4444;
            font-weight: bold;
            font-size: 15px;
        }}

        /* Section */
        .section {{
            background: #111520;
            border: 1px solid #1e2535;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 24px;
        }}

        .section-header {{
            padding: 18px 24px;
            border-bottom: 1px solid #1e2535;
            font-size: 13px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }}

        .section-header.gold   {{ color: #f59e0b; }}
        .section-header.cyan   {{ color: #00e5ff; }}
        .section-header.green  {{ color: #10b981; }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th {{
            background: #161b28;
            padding: 12px 16px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #64748b;
        }}

        td {{
            padding: 14px 16px;
            border-bottom: 1px solid #1e2535;
            font-size: 13px;
            vertical-align: top;
        }}

        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #161b28; }}

        code {{
            background: #1e2535;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: monospace;
            color: #f59e0b;
            font-size: 12px;
        }}

        /* Timeline */
        .timeline {{
            padding: 24px;
        }}

        .timeline-item {{
            display: flex;
            gap: 16px;
            margin-bottom: 20px;
            align-items: flex-start;
        }}

        .timeline-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-top: 4px;
            flex-shrink: 0;
        }}

        .dot-red    {{ background: #ff4444; }}
        .dot-yellow {{ background: #f59e0b; }}
        .dot-green  {{ background: #10b981; }}

        .timeline-content strong {{
            display: block;
            font-size: 14px;
            margin-bottom: 4px;
        }}

        .timeline-content span {{
            font-size: 13px;
            color: #64748b;
        }}

        .footer {{
            text-align: center;
            margin-top: 24px;
            color: #64748b;
            font-size: 12px;
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <h1>☁️ Cloud Misconfiguration Audit Report</h1>
        <p>
            Generated: {now} &nbsp;|&nbsp;
            Target: LocalStack (AWS Simulator) &nbsp;|&nbsp;
            Auditor: Mayssa Ghabarou &nbsp;|&nbsp;
            Status: <span style="color:#10b981;font-weight:bold;">REMEDIATED</span>
        </p>
    </div>

    <!-- Summary Cards -->
    <div class="cards">
        <div class="card">
            <div class="number total">{len(findings)}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="card">
            <div class="number crit">{len(critical)}</div>
            <div class="label">Critical</div>
        </div>
        <div class="card">
            <div class="number high">{len(high)}</div>
            <div class="label">High</div>
        </div>
        <div class="card">
            <div class="number med">{len(medium)}</div>
            <div class="label">Medium</div>
        </div>
        <div class="card">
            <div class="number low">{len(low)}</div>
            <div class="label">Low</div>
        </div>
    </div>

    <!-- Status Banner -->
    <div class="banner">
        ⚠️ &nbsp; {len(critical)} Critical finding(s) detected and remediated —
        public S3 bucket exposure and IAM privilege escalation path
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <div class="section-header gold">// Executive Summary — Critical Findings</div>
        <table>
            <thead>
                <tr>
                    <th>Resource</th>
                    <th>Issue</th>
                    <th>Severity</th>
                    <th>Remediation Applied</th>
                </tr>
            </thead>
            <tbody>
                {summary_rows}
            </tbody>
        </table>
    </div>

    <!-- Full Findings -->
    <div class="section">
        <div class="section-header cyan">// All Findings</div>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Resource</th>
                    <th>Issue</th>
                    <th>Detail</th>
                    <th>Remediation</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>

    <!-- Audit Timeline -->
    <div class="section">
        <div class="section-header green">// Audit Timeline</div>
        <div class="timeline">
            <div class="timeline-item">
                <div class="timeline-dot dot-red"></div>
                <div class="timeline-content">
                    <strong>Environment Setup</strong>
                    <span>Deployed deliberately misconfigured AWS environment
                    with 3 S3 buckets and 3 IAM users containing known vulnerabilities</span>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-dot dot-red"></div>
                <div class="timeline-content">
                    <strong>Critical Finding — Public S3 Bucket</strong>
                    <span>Bucket 'company-public-data' found publicly accessible.
                    Exposed files: employees.csv (salary data), config.json (credentials)</span>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-dot dot-red"></div>
                <div class="timeline-content">
                    <strong>Critical Finding — IAM Privilege Escalation</strong>
                    <span>User 'dev-user' found with Action:* Resource:* policy —
                    full unrestricted access to all AWS services</span>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-dot dot-yellow"></div>
                <div class="timeline-content">
                    <strong>Medium Findings — Hardening Issues</strong>
                    <span>6 medium findings identified: missing versioning on all buckets,
                    missing encryption, and no MFA on all IAM users</span>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-dot dot-green"></div>
                <div class="timeline-content">
                    <strong>Remediation Applied</strong>
                    <span>All 8 findings remediated: public access removed,
                    AES-256 encryption enabled, versioning enabled,
                    least privilege IAM policies applied</span>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-dot dot-green"></div>
                <div class="timeline-content">
                    <strong>Verification Passed</strong>
                    <span>8/8 fixes verified successfully — zero remaining findings</span>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        Cloud Misconfiguration Audit &nbsp;|&nbsp;
        Built with Python + boto3 &nbsp;|&nbsp;
        github.com/mayssgh/cloud-audit-lab
    </div>

</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[*] Audit report saved to {filepath}")


def main():
    print("\n[*] Generating Cloud Audit Report...")
    print("[*] " + "─" * 50)
    generate_report()
    print("[*] Done — open audit_report.html in your browser\n")


if __name__ == "__main__":
    main()