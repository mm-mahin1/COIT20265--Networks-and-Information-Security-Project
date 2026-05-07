import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    try:
        # Handle browser CORS preflight request
        if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
            return response(200, {"message": "CORS OK"})

        body = event.get("body", "{}")

        if isinstance(body, str):
            body = json.loads(body)

        log_message = body.get("message", "No message received")

        # This is the actual website log going into CloudWatch
        logger.info("WEBSITE_LOG: %s", log_message)

        return response(200, {
            "status": "success",
            "message": "Log received",
            "logged": log_message
        })

    except Exception as e:
        logger.error("ERROR_PROCESSING_LOG: %s", str(e))
        return response(500, {
            "status": "error",
            "message": str(e)
        })


def response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST,OPTIONS"
        },
        "body": json.dumps(body)
    }