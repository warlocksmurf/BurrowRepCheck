import json
import time
import urllib.request
import urllib.parse
import urllib.error
import boto3
import os

# --- Configuration ---
SCAN_INTERVAL_SECONDS = 30
SECRET_NAME = "burrowrepcheck-secrets"
AWS_REGION = "us-east-1"

domain_list = [
    "lobster-den.pages.dev",
    "warlocksmurf.github.io",
    "app.hackthebox.com"
]

# --- Load secrets from AWS Secrets Manager ---
def get_secrets():
    client = boto3.client("secretsmanager", region_name=AWS_REGION)
    response = client.get_secret_value(SecretId=SECRET_NAME)
    secret_dict = json.loads(response["SecretString"])
    return secret_dict["VT_API_KEY"], secret_dict["SLACK_WEBHOOK_URL"]

# --- Helper: HTTP request using urllib ---
def http_request(url, method="GET", headers=None, data=None):
    req = urllib.request.Request(url, headers=headers or {}, data=data.encode("utf-8") if data else None, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        error_message = e.read().decode()
        raise Exception(f"HTTPError: {e.code} - {error_message}")

# --- Step 1: Submit URL for scanning ---
def scan_url(domain, api_key):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = f"url=https://{domain}"
    response = http_request(url, method="POST", headers=headers, data=data)
    return True

# --- Step 2: Get domain reputation from VirusTotal ---
def get_domain_reputation(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }
    response = http_request(url, headers=headers)
    return response["data"]

# --- Step 3: Beautify the results for Slack ---
def format_for_slack_attachments(data):
    attributes = data['attributes']
    reputation = attributes.get('reputation', 'N/A')
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    domain = data['id']

    vt_link = f"https://www.virustotal.com/gui/domain/{domain}/detection"
    vt_report = f"<{vt_link}|Link>"

    return {
        "color": "#36a64f" if reputation >= 0 else "#e01e5a",
        "fields": [
            {"title": "Domain", "value": f"`{domain}`", "short": True},
            {"title": "Reputation Score", "value": reputation, "short": True},
            {"title": "Harmless", "value": last_analysis_stats.get('harmless', 0), "short": True},
            {"title": "Malicious", "value": last_analysis_stats.get('malicious', 0), "short": True},
            {"title": "Suspicious", "value": last_analysis_stats.get('suspicious', 0), "short": True},
            {"title": "Undetected", "value": last_analysis_stats.get('undetected', 0), "short": True},
            {"title": "VirusTotal Report", "value": vt_report, "short": False}
        ]
    }

# --- Step 4: Send message to Slack ---
def post_to_slack(payload, webhook_url):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            if response.status != 200:
                raise Exception(f"Slack webhook failed: {response.status} - {response.read().decode()}")
    except urllib.error.HTTPError as e:
        raise Exception(f"Slack webhook error: {e.code} - {e.read().decode()}")

# --- Lambda Handler ---
def lambda_handler(event, context):
    VT_API_KEY, SLACK_WEBHOOK_URL = get_secrets()
    slack_attachments = []

    for domain in domain_list:
        try:
            print(f"Submitting scan for {domain}")
            scan_url(domain, VT_API_KEY)
            print(f"Waiting {SCAN_INTERVAL_SECONDS} seconds before fetching report")
            time.sleep(SCAN_INTERVAL_SECONDS)

            print(f"Fetching reputation for {domain}")
            reputation_data = get_domain_reputation(domain, VT_API_KEY)
            attachment = format_for_slack_attachments(reputation_data)
            slack_attachments.append(attachment)

            print(f"Waiting {SCAN_INTERVAL_SECONDS} seconds before next domain")
            time.sleep(SCAN_INTERVAL_SECONDS)

        except Exception as e:
            print(f"Error processing {domain}: {e}")

    if slack_attachments:
        slack_payload = {
            "text": f"*Domain Reputation Scan - {time.strftime('%Y-%m-%d')}*",
            "attachments": slack_attachments
        }
        post_to_slack(slack_payload, SLACK_WEBHOOK_URL)
        print("Data posted to Slack")

    return {
        'statusCode': 200,
        'body': json.dumps('Domain reputation report sent.')
    }

