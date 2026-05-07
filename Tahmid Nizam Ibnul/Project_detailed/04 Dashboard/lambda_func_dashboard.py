import json
import gzip
import base64
import boto3
from datetime import datetime, timezone
import uuid

s3 = boto3.client("s3")

BUCKET_NAME = "logbert-dashboard-alerts-914115115831"
S3_PREFIX = "logbert-alerts/"


def lambda_handler(event, context):
    print("CloudWatch to S3 Lambda triggered")

    compressed_payload = base64.b64decode(event["awslogs"]["data"])
    uncompressed_payload = gzip.decompress(compressed_payload)
    cloudwatch_data = json.loads(uncompressed_payload)

    saved_count = 0

    for log_event in cloudwatch_data.get("logEvents", []):
        message = log_event.get("message", "").strip()

        try:
            alert = json.loads(message)

            now = datetime.now(timezone.utc)
            s3_key = (
                f"{S3_PREFIX}"
                f"year={now.year}/"
                f"month={now.month:02d}/"
                f"day={now.day:02d}/"
                f"alert-{now.strftime('%H%M%S')}-{uuid.uuid4().hex[:8]}.json"
            )

            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=s3_key,
                Body=json.dumps(alert, indent=2),
                ContentType="application/json"
            )

            print(f"Saved alert to s3://{BUCKET_NAME}/{s3_key}")
            saved_count += 1

        except json.JSONDecodeError:
            print("Skipping non-JSON log message")
            print(message)

        except Exception as e:
            print("Error saving log to S3")
            print(str(e))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "saved_to_s3": saved_count
        })
    }