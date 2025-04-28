# BurrowRepCheck 🦞🕳️
BurrowRepCheck is a Python script integrated with AWS Lambda that automatically monitors domain reputation using the VirusTotal API and sends alerts to Slack. The goal of this tool is to ensure that your domains are not falsely flagged as malicious, helping to protect your brand image and maintain trust with vendors, partners, and customers.

## Features
- Automated domain reputation monitoring.
- VirusTotal integration for reputation analysis.
- Slack notifications for immediate visibility.
- Secure storage of API keys and credentials via AWS Secrets Manager.
- Built to run serverlessly on AWS Lambda for scalability and low overhead.

## How It Works
1. Submits each URL to VirusTotal for scanning to refresh the domain's reputation.
2. Waits for the scan results.
3. Fetches the domain reputation data from VirusTotal and 
4. Formats the results into a Slack-friendly message.
5. Sends a beautified report to the configured Slack channel.

## Requirements
- Python 3.x
- boto3 (AWS SDK for Python)
- An AWS account with access to Lambda and Secrets Manager
- VirusTotal API Key
- Slack Webhook URL

## Setup Instructions
1. Deploy to AWS Lambda
- Create a new AWS Lambda function (Python 3.x runtime).
- Upload the script or paste it into the inline editor.
- Attach a suitable IAM role that grants permission to retrieve secrets from AWS Secrets Manager.

2. Configure AWS Secrets Manager
- Create a new secret in Secrets Manager with the following JSON structure:
```json
{
  "VT_API_KEY": "your_virustotal_api_key",
  "SLACK_WEBHOOK_URL": "your_slack_webhook_url"
}
```
Save the secret under the name:
```
burrowrepcheck-secrets
```

3. Edit the Domain List
- Modify the `domain_list` list in the script to include your domains:
```python
domain_list = [
    "lobster-den.pages.dev",
    "warlocksmurf.github.io",
    "app.hackthebox.com"
]
```

4. Adjust Scan Settings (Optional)
- You can configure how long the script waits between API requests to avoid rate limiting by adjusting:
```python
SCAN_INTERVAL_SECONDS = 30
```

5. Set Up a Scheduled Trigger
- (Optional) Use AWS EventBridge to automatically trigger the Lambda function at regular intervals.
