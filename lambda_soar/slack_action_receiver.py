import json
import boto3
import urllib.parse
import urllib.request
import base64

dynamodb = boto3.resource('dynamodb')
incident_table = dynamodb.Table('aegis_soar_incidents')
iam_client = boto3.client('iam')

def lambda_handler(event, context):
    print("🚨 Slack Interactivity Triggered!")
    
    try:
        body = event.get('body', '')
        if event.get('isBase64Encoded'):
            body = base64.b64decode(body).decode('utf-8')
            
        parsed_body = urllib.parse.parse_qs(body)
        payload = json.loads(parsed_body['payload'][0])
        
        response_url = payload.get('response_url')
        action_id = payload['actions'][0]['action_id']
        value = payload['actions'][0]['value'] 
        incident_id = value.split('_', 1)[1]
        user = payload['user']['username']
        
        # Extract the original message so we can keep the AI Narrative on the screen!
        original_blocks = payload.get('message', {}).get('blocks', [])
        
        if action_id == 'approve_quarantine_action':
            try:
                iam_client.attach_role_policy(RoleName="vulnerable-app-execution-role", PolicyArn="arn:aws:iam::aws:policy/AWSDenyAll")
            except Exception:
                pass
            
            incident_table.update_item(
                Key={'incident_id': incident_id},
                UpdateExpression="SET #s = :s",
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'CONTAINED_BY_HUMAN'}
            )
            result_text = f"🟢 *Quarantine Approved & Executed by @{user}*"
            
        elif action_id == 'false_positive_action':
            incident_table.update_item(
                Key={'incident_id': incident_id},
                UpdateExpression="SET #s = :s",
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'FALSE_POSITIVE'}
            )
            result_text = f"🔴 *Marked as False Positive by @{user}. No action taken.*"

        # Rebuild the UI: Keep the Header and AI Narrative, but swap the buttons for the final result text!
        new_blocks = original_blocks[:3] if len(original_blocks) >= 3 else []
        new_blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": result_text
            }
        })

        update_payload = {
            "replace_original": True,
            "text": result_text,
            "blocks": new_blocks
        }
        
        # 1. Fire the update directly to the webhook (with User-Agent to prevent Slack blocking it)
        if response_url:
            req = urllib.request.Request(
                response_url, 
                data=json.dumps(update_payload).encode("utf-8"), 
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
            )
            try:
                urllib.request.urlopen(req, timeout=3)
            except Exception as e:
                print(f"Response URL failed: {e}")

        # 2. ALSO return it immediately via API Gateway to beat the 3-second clock
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(update_payload)
        }
        
    except Exception as e:
        print(f"[!] Error processing Slack action: {str(e)}")
        return {'statusCode': 500, 'body': 'Error'}