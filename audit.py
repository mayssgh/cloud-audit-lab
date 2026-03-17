import boto3
import json

# ─── CONNECT TO LOCALSTACK ────────────────────────────────
s3  = boto3.client("s3",  endpoint_url="http://localhost:4566",
                   aws_access_key_id="test",
                   aws_secret_access_key="test",
                   region_name="us-east-1")

iam = boto3.client("iam", endpoint_url="http://localhost:4566",
                   aws_access_key_id="test",
                   aws_secret_access_key="test",
                   region_name="us-east-1")
# ──────────────────────────────────────────────────────────


def audit_s3():
    """
    Scans all S3 buckets for misconfigurations.
    Checks: public access, versioning, encryption.
    Returns a list of findings.
    """
    print("\n[*] Auditing S3 buckets...")
    findings = []

    # Get all buckets
    buckets = s3.list_buckets()["Buckets"]
    print(f"[*] Found {len(buckets)} bucket(s)")

    for bucket in buckets:
        name = bucket["Name"]
        print(f"\n[*] Checking bucket: {name}")

        # ── Check 1: Public Access ─────────────────────
        try:
            acl      = s3.get_bucket_acl(Bucket=name)
            grants   = acl["Grants"]
            is_public = any(
                grant["Grantee"].get("URI", "") ==
                "http://acs.amazonaws.com/groups/global/AllUsers"
                for grant in grants
            )

            if is_public:
                # List what files are exposed
                objects  = s3.list_objects_v2(Bucket=name)
                files    = [o["Key"] for o in objects.get("Contents", [])]
                findings.append({
                    "resource":    f"S3 Bucket: {name}",
                    "issue":       "Bucket is publicly accessible",
                    "severity":    "CRITICAL",
                    "detail":      f"Exposed files: {', '.join(files)}",
                    "remediation": "Enable S3 Block Public Access settings"
                })
                print(f"    [!] CRITICAL — Public bucket detected")
                print(f"    [!] Exposed files: {', '.join(files)}")
            else:
                print(f"    [✓] Access control OK")

        except Exception as e:
            print(f"    [~] Could not check ACL: {e}")

        # ── Check 2: Versioning ────────────────────────
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            status     = versioning.get("Status", "Disabled")

            if status != "Enabled":
                findings.append({
                    "resource":    f"S3 Bucket: {name}",
                    "issue":       "Versioning is not enabled",
                    "severity":    "MEDIUM",
                    "detail":      "Deleted or overwritten files cannot be recovered",
                    "remediation": "Enable bucket versioning for data recovery"
                })
                print(f"    [!] MEDIUM  — Versioning disabled")
            else:
                print(f"    [✓] Versioning enabled")

        except Exception as e:
            print(f"    [~] Could not check versioning: {e}")

        # ── Check 3: Encryption ────────────────────────
        try:
            s3.get_bucket_encryption(Bucket=name)
            print(f"    [✓] Encryption enabled")

        except Exception:
            findings.append({
                "resource":    f"S3 Bucket: {name}",
                "issue":       "Server-side encryption is not enabled",
                "severity":    "MEDIUM",
                "detail":      "Data stored in plaintext — exposed if bucket is accessed",
                "remediation": "Enable AES-256 or AWS KMS encryption"
            })
            print(f"    [!] MEDIUM  — Encryption not enabled")

    return findings


def audit_iam():
    """
    Scans all IAM users for dangerous permissions.
    Checks: admin access, MFA, wildcard policies.
    Returns a list of findings.
    """
    print("\n[*] Auditing IAM users...")
    findings = []

    # Get all users
    users = iam.list_users()["Users"]
    print(f"[*] Found {len(users)} user(s)")

    for user in users:
        username = user["UserName"]
        print(f"\n[*] Checking user: {username}")

        # ── Check 1: Overprivileged Policies ──────────
        try:
            policies = iam.list_user_policies(UserName=username)

            for policy_name in policies["PolicyNames"]:
                policy_doc = iam.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )["PolicyDocument"]

                # Check for wildcard actions
                for statement in policy_doc.get("Statement", []):
                    action   = statement.get("Action", [])
                    resource = statement.get("Resource", [])

                    # Action: * means full admin access
                    if action == "*" or action == ["*"]:
                        findings.append({
                            "resource":    f"IAM User: {username}",
                            "issue":       "User has full admin privileges (Action: *)",
                            "severity":    "CRITICAL",
                            "detail":      f"Policy '{policy_name}' grants unrestricted access to all AWS services",
                            "remediation": "Apply least privilege — grant only required permissions"
                        })
                        print(f"    [!] CRITICAL — Full admin access detected")

                    # Resource: * with broad actions is dangerous
                    elif resource == "*" and isinstance(action, list) and len(action) > 5:
                        findings.append({
                            "resource":    f"IAM User: {username}",
                            "issue":       "Overly broad permissions on all resources",
                            "severity":    "HIGH",
                            "detail":      f"Policy grants {len(action)} actions on all resources",
                            "remediation": "Restrict Resource to specific ARNs"
                        })
                        print(f"    [!] HIGH    — Broad permissions on all resources")
                    else:
                        print(f"    [✓] Policy scope acceptable")

        except Exception as e:
            print(f"    [~] Could not check policies: {e}")

        # ── Check 2: MFA ───────────────────────────────
        try:
            mfa_devices = iam.list_mfa_devices(UserName=username)

            if not mfa_devices["MFADevices"]:
                findings.append({
                    "resource":    f"IAM User: {username}",
                    "issue":       "MFA is not enabled",
                    "severity":    "MEDIUM",
                    "detail":      "Account can be accessed with password alone",
                    "remediation": "Enforce MFA for all IAM users"
                })
                print(f"    [!] MEDIUM  — No MFA device found")
            else:
                print(f"    [✓] MFA enabled")

        except Exception as e:
            print(f"    [~] Could not check MFA: {e}")

    return findings


def print_summary(all_findings):
    """
    Prints a clean summary of all findings
    grouped by severity.
    """
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high     = [f for f in all_findings if f["severity"] == "HIGH"]
    medium   = [f for f in all_findings if f["severity"] == "MEDIUM"]
    low      = [f for f in all_findings if f["severity"] == "LOW"]

    print("\n" + "═" * 55)
    print("          CLOUD MISCONFIGURATION AUDIT SUMMARY")
    print("═" * 55)
    print(f"  Total Findings  : {len(all_findings)}")
    print(f"  Critical        : {len(critical)}")
    print(f"  High            : {len(high)}")
    print(f"  Medium          : {len(medium)}")
    print(f"  Low             : {len(low)}")
    print("═" * 55)

    if critical:
        print("\n  CRITICAL FINDINGS:")
        for f in critical:
            print(f"  → {f['resource']}: {f['issue']}")

    if high:
        print("\n  HIGH FINDINGS:")
        for f in high:
            print(f"  → {f['resource']}: {f['issue']}")

    if medium:
        print("\n  MEDIUM FINDINGS:")
        for f in medium:
            print(f"  → {f['resource']}: {f['issue']}")

    print("═" * 55)
    print("  Run fix.py to remediate all findings.")
    print("  Run report.py to generate full HTML report.\n")


def main():
    print("\n[*] Cloud Misconfiguration Audit Tool")
    print("[*] " + "─" * 50)
    print("[*] Target: LocalStack (AWS Simulator)")

    # Run both audits
    s3_findings  = audit_s3()
    iam_findings = audit_iam()

    # Combine all findings
    all_findings = s3_findings + iam_findings

    # Save findings to JSON for report.py to use
    with open("findings.json", "w") as f:
        json.dump(all_findings, f, indent=4)
    print(f"\n[*] Findings saved to findings.json")

    # Print summary
    print_summary(all_findings)

    return all_findings


if __name__ == "__main__":
    main()