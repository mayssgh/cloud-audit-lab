import boto3
import json

# ─── CONNECT TO LOCALSTACK ────────────────────────────────
# endpoint_url points to LocalStack instead of real AWS
s3  = boto3.client("s3",  endpoint_url="http://localhost:4566",
                   aws_access_key_id="test",
                   aws_secret_access_key="test",
                   region_name="us-east-1")

iam = boto3.client("iam", endpoint_url="http://localhost:4566",
                   aws_access_key_id="test",
                   aws_secret_access_key="test",
                   region_name="us-east-1")
# ──────────────────────────────────────────────────────────


def create_misconfigured_s3():
    """
    Creates 3 S3 buckets with different
    misconfiguration levels.
    """
    print("\n[*] Creating S3 buckets...")

    # Bucket 1 — PUBLIC (critical misconfiguration)
    # Anyone on the internet can read this
    s3.create_bucket(Bucket="company-public-data")
    s3.put_bucket_acl(
        Bucket="company-public-data",
        ACL="public-read"
    )

    # Add sensitive files to the public bucket
    s3.put_object(
        Bucket="company-public-data",
        Key="employees.csv",
        Body="name,email,salary\nJohn,john@company.com,85000\nMayssa,mayssa@company.com,90000"
    )
    s3.put_object(
        Bucket="company-public-data",
        Key="config.json",
        Body='{"db_password": "supersecret123", "api_key": "sk-abc123xyz"}'
    )
    print("[!] CRITICAL — Bucket 'company-public-data' is PUBLIC")
    print("    Contains: employees.csv, config.json")

    # Bucket 2 — NO VERSIONING (medium misconfiguration)
    # If files are deleted or overwritten, no recovery possible
    s3.create_bucket(Bucket="company-backups")
    s3.put_object(
        Bucket="company-backups",
        Key="backup-2026.zip",
        Body="fake backup data"
    )
    print("[!] MEDIUM  — Bucket 'company-backups' has no versioning")

    # Bucket 3 — NO ENCRYPTION (medium misconfiguration)
    # Data stored in plain text
    s3.create_bucket(Bucket="company-logs")
    s3.put_object(
        Bucket="company-logs",
        Key="app.log",
        Body="2026-03-10 user=admin action=login ip=192.168.1.1"
    )
    print("[!] MEDIUM  — Bucket 'company-logs' has no encryption")

    print("[*] S3 setup complete — 3 buckets created\n")


def create_misconfigured_iam():
    """
    Creates IAM users with dangerous permission levels.
    """
    print("[*] Creating IAM users...")

    # User 1 — ADMIN EVERYWHERE (critical misconfiguration)
    # This user has full access to everything
    iam.create_user(UserName="dev-user")
    iam.put_user_policy(
        UserName="dev-user",
        PolicyName="DangerousAdminPolicy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect":   "Allow",
                "Action":   "*",          # allows EVERYTHING
                "Resource": "*"           # on ALL resources
            }]
        })
    )
    print("[!] CRITICAL — 'dev-user' has full admin access (Action: *)")

    # User 2 — NO MFA (medium misconfiguration)
    # Account has no multi-factor authentication
    iam.create_user(UserName="analyst-user")
    iam.put_user_policy(
        UserName="analyst-user",
        PolicyName="S3ReadPolicy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect":   "Allow",
                "Action":   ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*"
            }]
        })
    )
    print("[!] MEDIUM  — 'analyst-user' has no MFA enabled")

    # User 3 — NO ACCESS KEYS ROTATION (low misconfiguration)
    iam.create_user(UserName="service-account")
    print("[!] LOW     — 'service-account' has no key rotation policy")

    print("[*] IAM setup complete — 3 users created\n")


def main():
    print("\n[*] Setting up vulnerable AWS environment in LocalStack")
    print("[*] " + "─" * 50)
    create_misconfigured_s3()
    create_misconfigured_iam()
    print("[*] Vulnerable environment ready.")
    print("[*] Run audit.py to find all misconfigurations.\n")


if __name__ == "__main__":
    main()