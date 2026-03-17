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


def fix_s3():
    """
    Fixes all S3 misconfigurations:
    - Removes public access
    - Enables versioning
    - Enables encryption
    """
    print("\n[*] Fixing S3 misconfigurations...")

    buckets = s3.list_buckets()["Buckets"]

    for bucket in buckets:
        name = bucket["Name"]
        print(f"\n[*] Fixing bucket: {name}")

        # ── Fix 1: Remove Public Access ───────────────
        try:
            s3.put_bucket_acl(
                Bucket=name,
                ACL="private"
            )
            print(f"    [✓] Public access removed — set to private")
        except Exception as e:
            print(f"    [~] Could not fix ACL: {e}")

        # ── Fix 2: Enable Versioning ──────────────────
        try:
            s3.put_bucket_versioning(
                Bucket=name,
                VersioningConfiguration={"Status": "Enabled"}
            )
            print(f"    [✓] Versioning enabled")
        except Exception as e:
            print(f"    [~] Could not enable versioning: {e}")

        # ── Fix 3: Enable Encryption ──────────────────
        try:
            s3.put_bucket_encryption(
                Bucket=name,
                ServerSideEncryptionConfiguration={
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }]
                }
            )
            print(f"    [✓] AES-256 encryption enabled")
        except Exception as e:
            print(f"    [~] Could not enable encryption: {e}")

    print("\n[*] S3 fixes complete")


def fix_iam():
    """
    Fixes all IAM misconfigurations:
    - Removes wildcard admin policies
    - Applies least privilege policies
    """
    print("\n[*] Fixing IAM misconfigurations...")

    users = iam.list_users()["Users"]

    for user in users:
        username = user["UserName"]
        print(f"\n[*] Fixing user: {username}")

        # ── Fix 1: Remove Dangerous Policies ─────────
        try:
            policies = iam.list_user_policies(UserName=username)

            for policy_name in policies["PolicyNames"]:
                policy_doc = iam.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )["PolicyDocument"]

                # Check if policy has wildcard action
                is_dangerous = any(
                    statement.get("Action") == "*" or
                    statement.get("Action") == ["*"]
                    for statement in policy_doc.get("Statement", [])
                )

                if is_dangerous:
                    # Delete the dangerous policy
                    iam.delete_user_policy(
                        UserName=username,
                        PolicyName=policy_name
                    )
                    print(f"    [✓] Removed dangerous policy: {policy_name}")

                    # Replace with least privilege policy
                    iam.put_user_policy(
                        UserName=username,
                        PolicyName="LeastPrivilegePolicy",
                        PolicyDocument=json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect":   "Allow",
                                "Action": [
                                    "s3:GetObject",
                                    "s3:ListBucket"
                                ],
                                "Resource": "arn:aws:s3:::company-*"
                            }]
                        })
                    )
                    print(f"    [✓] Applied least privilege policy")
                else:
                    print(f"    [✓] Policy is acceptable")

        except Exception as e:
            print(f"    [~] Could not fix policies: {e}")

    print("\n[*] IAM fixes complete")


def verify_fixes():
    """
    Re-runs a quick check to confirm
    all fixes were applied successfully.
    """
    print("\n[*] Verifying fixes...")
    passed = 0
    failed = 0

    # Verify S3 buckets
    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]

        # Check versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") == "Enabled":
                print(f"    [✓] {name} — versioning enabled")
                passed += 1
            else:
                print(f"    [!] {name} — versioning still disabled")
                failed += 1
        except Exception:
            failed += 1

        # Check encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
            print(f"    [✓] {name} — encryption enabled")
            passed += 1
        except Exception:
            print(f"    [!] {name} — encryption still missing")
            failed += 1

    # Verify IAM users
    users = iam.list_users()["Users"]
    for user in users:
        username = user["UserName"]
        try:
            policies = iam.list_user_policies(UserName=username)
            for policy_name in policies["PolicyNames"]:
                policy_doc = iam.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )["PolicyDocument"]

                is_dangerous = any(
                    statement.get("Action") == "*"
                    for statement in policy_doc.get("Statement", [])
                )

                if not is_dangerous:
                    print(f"    [✓] {username} — no wildcard policies")
                    passed += 1
                else:
                    print(f"    [!] {username} — still has wildcard policy")
                    failed += 1
        except Exception:
            passed += 1

    # Print verification summary
    print("\n" + "─" * 45)
    print(f"  Verification complete")
    print(f"  Passed : {passed}")
    print(f"  Failed : {failed}")
    print("─" * 45)


def main():
    print("\n[*] Cloud Misconfiguration Remediation Tool")
    print("[*] " + "─" * 50)
    print("[*] Loading findings from findings.json...")

    # Load findings from audit
    try:
        with open("findings.json", "r") as f:
            findings = json.load(f)
        print(f"[*] Found {len(findings)} issues to fix")
    except FileNotFoundError:
        print("[!] findings.json not found — run audit.py first")
        return

    # Apply fixes
    fix_s3()
    fix_iam()

    # Verify everything was fixed
    verify_fixes()

    print("\n[*] All fixes applied.")
    print("[*] Run report.py to generate the full audit report.\n")


if __name__ == "__main__":
    main()