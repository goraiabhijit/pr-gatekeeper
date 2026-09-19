import json
import boto3

LOCALSTACK_ENDPOINT = "http://localhost:4566"
BUCKET_NAME = "pr-gatekeeper-audits"

# Initialize Boto3 S3 Client pointing to LocalStack
s3_client = boto3.client(
    "s3",
    endpoint_url=LOCALSTACK_ENDPOINT,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name="us-east-1",
)

def read_all_audit_logs():
    # 1. Fetch all objects stored under the 'audit_logs/' prefix
    response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix="audit_logs/")
    objects = response.get("Contents", [])

    if not objects:
        print(f"[INFO] No audit logs found in bucket '{BUCKET_NAME}'.")
        return

    print(f"Found {len(objects)} log file(s) in S3:\n")

    # 2. Iterate through each object key and read its body
    for obj in objects:
        key = obj["Key"]
        print(f"=== READING: {key} ===")
        
        # Download stream from S3
        s3_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=key)
        
        # Read byte body and decode to utf-8 text
        raw_data = s3_obj["Body"].read().decode("utf-8")
        
        # Format as pretty JSON output
        parsed_json = json.loads(raw_data)
        print(json.dumps(parsed_json, indent=2))
        print("-" * 50 + "\n")

if __name__ == "__main__":
    read_all_audit_logs()