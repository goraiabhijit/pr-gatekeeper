import os
import json
import datetime
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load variables from .env into memory
load_dotenv()

BUCKET_NAME = "pr-gatekeeper-audits"


def get_s3_client():
    """Create an S3 client that can reach LocalStack from a Lambda container."""
    return boto3.client(
        "s3",
        endpoint_url=os.getenv(
            "LOCALSTACK_ENDPOINT",
            "http://host.docker.internal:4566",
        ),
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
        config=Config(
            connect_timeout=3,
            read_timeout=5,
            retries={"max_attempts": 1, "mode": "standard"},
        ),
    )


def ensure_bucket_exists(s3_client):
    """Ensure the audit bucket exists before writing an audit record."""
    try:
        s3_client.head_bucket(Bucket=BUCKET_NAME)
    except ClientError:
        try:
            s3_client.create_bucket(Bucket=BUCKET_NAME)
            print(f"[Logger] Created LocalStack S3 bucket: '{BUCKET_NAME}'")
        except Exception as error:
            print(f"[Logger] Failed to create bucket '{BUCKET_NAME}': {error}")


def save_audit_log(decision: str, scan_results: dict, pr_metadata: dict = None) -> str:
    """Format and upload a Cedar decision and scan result to S3."""

    try:
        s3 = get_s3_client()
        ensure_bucket_exists(s3)

        timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        object_key = f"audit_logs/audit_{timestamp_str}_{decision}.json"

        audit_payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "decision": decision,
            "has_leaked_secret": scan_results.get("has_leaked_secret", False),
            "vulnerability_count": scan_results.get("vulnerability_count", 0),
            "detected_issues": scan_results.get("detected_issues", []),
            "pr_metadata": pr_metadata or {}
        }

        try:
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=object_key,
                Body=json.dumps(audit_payload, indent=2),
                ContentType="application/json",
            )
        except Exception as error:
            print(f"[WARNING] Failed to upload audit log to S3: {error}")
            return None

        print(f"[Logger] Successfully saved audit log to s3://{BUCKET_NAME}/{object_key}")
        return object_key
    except Exception as error:
        print(f"[WARNING] LocalStack audit log unavailable: {error}")
        return None