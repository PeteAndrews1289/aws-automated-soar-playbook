import json
import boto3
import uuid
import datetime
import urllib.request
import os

iam_client = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')
incident_table = dynamodb.Table('aegis_soar_incidents')

OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

def generate_ai_threat_narrative(search_name, attacker_ip, target_pod, role):
    if not OPENAI_API_KEY or OPENAI_API_KEY == "sk-YOUR_API_KEY_HERE":
        return f"Mock AI Narrative: Detected {search_name} from IP {attacker_ip} targeting {target_pod}. Pending human approval for containment."

    prompt = f"Act as an expert SOC Analyst. Write a 2-sentence professional threat summary for an incident called '{search_name}'. The attacker IP is {attacker_ip}. The compromised Kubernetes pod is {target_pod}. State that the system has paused the automated quarantine of IAM role {role} pending human approval."
    
    data = json.dumps({
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.5
    }).encode("utf-8")
    
    req = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=data, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    })
    
    try:
        response = urllib.request.urlopen(req)
        result = json.loads(response.read())
        return result["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[-] AI Generation Failed: {str(e)}")
        return "AI Summary unavailable at this time."

def log_incident_to_db(incident_id, search_name, attacker_ip, target_pod, ai_narrative):
    timestamp = datetime.datetime.utcnow().isoformat()
    try:
        incident_table.put_item(
            Item={
                'incident_id': incident_id,
                'timestamp': timestamp,
                'alert_name': search_name,
                'attacker_ip': attacker_ip,
                'affected_asset': target_pod,
                'ai_summary': ai_narrative,
                'status': 'PENDING_APPROVAL' # Changed state to pending!
            }
        )
        return True
    except Exception as e:
        return False

def send_slack_alert(incident_id, search_name, attacker_ip, target_pod, ai_narrative):
    """
    Sends an interactive Block Kit message to your Slack SOC channel.
    """
    if not SLACK_WEBHOOK_URL:
        print("[-] No Slack Webhook configured. Skipping Slack alert.")
        return
        
    slack_payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 SOAR Alert: {search_name}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Incident ID:* `{incident_id}`\n*Attacker IP:* `{attacker_ip}`\n*Target Asset:* `{target_pod}`\n\n*🤖 AI SOC Narrative:*\n_{ai_narrative}_"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🟢 Approve Quarantine",
                            "emoji": True
                        },
                        "style": "primary",
                        "value": f"approve_{incident_id}",
                        "action_id": "approve_quarantine_action"
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🔴 Mark False Positive",
                            "emoji": True
                        },
                        "style": "danger",
                        "value": f"reject_{incident_id}",
                        "action_id": "false_positive_action"
                    }
                ]
            }
        ]
    }
    
    req = urllib.request.Request(SLACK_WEBHOOK_URL, data=json.dumps(slack_payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req)
        print("[+] Slack Interactive Alert Sent!")
    except Exception as e:
        print(f"[-] Failed to send Slack Alert: {str(e)}")

def lambda_handler(event, context):
    current_incident_id = str(uuid.uuid4())
    
    try:
        payload = json.loads(event.get('body', '{}'))
        result = payload.get('result', {})
        
        search_name = payload.get('search_name', 'Manual Incident Test')
        compromised_pod = result.get('host', 'web-app-pod')
        associated_iam_role = result.get('iam_role', 'vulnerable-app-execution-role')
        attacker_ip = result.get('clientip', 'Unknown Source IP')
        
        # 1. Generate the AI SOC Narrative (Notice we aren't quarantining immediately anymore!)
        narrative = generate_ai_threat_narrative(search_name, attacker_ip, compromised_pod, associated_iam_role)
        
        # 2. Log incident to DynamoDB as PENDING_APPROVAL
        log_incident_to_db(current_incident_id, search_name, attacker_ip, compromised_pod, narrative)
        
        # 3. Fire the Interactive Slack Webhook
        send_slack_alert(current_incident_id, search_name, attacker_ip, compromised_pod, narrative)
        
        return {
            'statusCode': 200,
            'body': json.dumps({'incident_id': current_incident_id, 'status': 'Pending Human Approval in Slack'})
        }
        
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps('Execution failed.')}