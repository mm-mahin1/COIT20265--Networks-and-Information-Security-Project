
import boto3
import json
import sys

AWS_REGION      = "us-east-1" 
SNS_TOPIC_NAME  = "coit20265-security-alerts"
ALERT_EMAIL     = "12282912@cqumail.com"

AWS_ACCESS_KEY  = "" 
AWS_SECRET_KEY  = "" 
# ─────────────────────────────────────────────


def get_sns_client():
    kwargs = dict(region_name=AWS_REGION)
    if AWS_ACCESS_KEY and AWS_SECRET_KEY:
        kwargs["aws_access_key_id"]     = AWS_ACCESS_KEY
        kwargs["aws_secret_access_key"] = AWS_SECRET_KEY
    return boto3.client("sns", **kwargs)


def create_topic(client) -> str:
    print(f"Creating SNS topic: {SNS_TOPIC_NAME}...")
    response = client.create_topic(Name=SNS_TOPIC_NAME)
    topic_arn = response["TopicArn"]
    print(f"  ✅ Topic ARN: {topic_arn}")
    return topic_arn


def subscribe_email(client, topic_arn: str):
    print(f"\nSubscribing {ALERT_EMAIL} to topic...")
    response = client.subscribe(
        TopicArn=topic_arn,
        Protocol="email",
        Endpoint=ALERT_EMAIL,
        ReturnSubscriptionArn=True
    )
    print(f"  ✅ Subscription ARN: {response['SubscriptionArn']}")
    print(f"\n  📧 CHECK YOUR EMAIL — {ALERT_EMAIL}")
    print("     You must click the confirmation link before alerts will be delivered.")


def send_test_alert(client, topic_arn: str):
    print("\nSending test alert...")
    test_message = """
🚨 TEST ALERT — COIT20265 NLP Anomaly Detection System
======================================================
This is a test notification from the NLP Log Anomaly Detection Dashboard.

If you received this, your AWS SNS setup is working correctly!

Timestamp   : 2025-04-14 08:00:00
Threat Score: 20 / 100
Severity    : MEDIUM
Source      : test_script

Log Message:
  failed password for root from 192.168.1.9 port 55221 ssh2
======================================================
COIT20265 · CQUniversity Australia · Dr Fariza Sabrina
"""
    response = client.publish(
        TopicArn=topic_arn,
        Subject="[TEST] COIT20265 Security Alert System — Verification",
        Message=test_message
    )
    print(f"  ✅ Test alert sent! MessageId: {response['MessageId']}")


def print_dashboard_config(topic_arn: str):
    print("\n" + "="*60)
    print("  COPY THESE VALUES INTO THE STREAMLIT DASHBOARD SIDEBAR")
    print("="*60)
    print(f"  SNS Topic ARN : {topic_arn}")
    print(f"  AWS Region    : {AWS_REGION}")
    print("="*60)
    print("\nIn the dashboard sidebar:")
    print("  ✅ Enable 'Enable AWS SNS Alerts'")
    print(f"  ✅ Paste Topic ARN: {topic_arn}")
    print(f"  ✅ Enter Region:    {AWS_REGION}")
    print("  ✅ Enter Access Key + Secret Key (or leave blank if IAM role is attached to EC2)")


def main():
    print("="*60)
    print("  COIT20265 — AWS SNS Alert Setup")
    print("="*60)

    if ALERT_EMAIL == "12282912@cqumail.com":
        print("\n❌ ERROR: Please edit setup_sns_alerts.py and set ALERT_EMAIL to your real email.")
        sys.exit(1)

    try:
        client = get_sns_client()
        topic_arn = create_topic(client)
        subscribe_email(client, topic_arn)
        send_test_alert(client, topic_arn)
        print_dashboard_config(topic_arn)
        print("\n✅ SNS setup complete!")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting:")
        print("  1. Run 'aws configure' to set up credentials")
        print("  2. Or set environment variables:")
        print("     export AWS_ACCESS_KEY_ID=your_key")
        print("     export AWS_SECRET_ACCESS_KEY=your_secret")
        print("  3. Make sure your IAM user has sns:CreateTopic, sns:Subscribe, sns:Publish permissions")


if __name__ == "__main__":
    main()
