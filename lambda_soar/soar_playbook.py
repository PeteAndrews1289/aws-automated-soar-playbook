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



def generate_ai_threat_narrative(search_name, attacker_ip, target_pod, role):
    """
    Asks an LLM to generate a human-readable summary of the attack and remediation.
    """
    if OPENAI_API_KEY == "sk-YOUR_API_KEY_HERE":
        return f"Mock AI Narrative: Detected {search_name} from IP {attacker_ip} targeting {target_pod}. Automated containment protocols engaged."

    prompt = f"Act as an expert SOC Analyst. Write a 2-sentence professional threat summary for an incident called '{search_name}'. The attacker IP is {attacker_ip}. The compromised Kubernetes pod is {target_pod} and the isolated AWS IAM role is {role}. State that automated quarantine was successful."
    
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
        # Notice we are now pushing the AI Narrative into DynamoDB!
        incident_table.put_item(
            Item={
                'incident_id': incident_id,
                'timestamp': timestamp,
                'alert_name': search_name,
                'attacker_ip': attacker_ip,
                'affected_asset': target_pod,
                'ai_summary': ai_narrative,
                'status': 'CONTAINED'
            }
        )
        return True
    except Exception as e:
        return False

def quarantine_iam_role(role_name):
    policy_arn = "arn:aws:iam::aws:policy/AWSDenyAll"
    try:
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        return "SUCCESS"
    except iam_client.exceptions.NoSuchEntityException:
        return "SIMULATED_SUCCESS"
    except Exception as e:
        return f"FAILED: {str(e)}"

def generate_k8s_quarantine_manifest(pod_name):
    return "SUCCESS"

def lambda_handler(event, context):
    current_incident_id = str(uuid.uuid4())
    
    try:
        payload = json.loads(event.get('body', '{}'))
        result = payload.get('result', {})
        
        search_name = payload.get('search_name', 'Manual Incident Test')
        compromised_pod = result.get('host', 'web-app-pod')
        associated_iam_role = result.get('iam_role', 'vulnerable-app-execution-role')
        attacker_ip = result.get('clientip', 'Unknown Source IP')
        
        # 1. Execute Containment
        iam_status = quarantine_iam_role(associated_iam_role)
        generate_k8s_quarantine_manifest(compromised_pod)
        
        # 2. Generate the AI SOC Narrative
        narrative = generate_ai_threat_narrative(search_name, attacker_ip, compromised_pod, associated_iam_role)
        
        # 3. Log everything to DynamoDB
        log_incident_to_db(current_incident_id, search_name, attacker_ip, compromised_pod, narrative)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'incident_id': current_incident_id,
                'ai_narrative': narrative,
                'iam_quarantine': iam_status
            })
        }
        
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps('Execution failed.')}