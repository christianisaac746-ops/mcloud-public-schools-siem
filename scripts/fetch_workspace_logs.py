import json
import requests
from datetime import datetime, timezone, timedelta
from google.oauth2 import service_account
from googleapiclient.discovery import build

CREDENTIALS_FILE = '/etc/graylog/workspace/credentials.json'
ADMIN_EMAIL = 'crooks@mcloudschools.us'
GRAYLOG_HOST = '127.0.0.1'
GRAYLOG_PORT = 12201
APPLICATIONS = ['login', 'admin', 'drive', 'token']

def get_service():
    scopes = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']
    credentials = service_account.Credentials.from_service_account_file(
        CREDENTIALS_FILE, scopes=scopes)
    credentials = credentials.with_subject(ADMIN_EMAIL)
    return build('admin', 'reports_v1', credentials=credentials)

def send_to_graylog(message):
    payload = json.dumps(message)
    requests.post(
        f'http://{GRAYLOG_HOST}:{GRAYLOG_PORT}/gelf',
        data=payload,
        headers={'Content-Type': 'application/json'},
        timeout=5
    )

def fetch_logs(service, application):
    start_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
    try:
        results = service.activities().list(
            userKey='all',
            applicationName=application,
            startTime=start_time
        ).execute()
        activities = results.get('items', [])
        for activity in activities:
            actor = activity.get('actor', {})
            events = activity.get('events', [{}])
            message = {
                'version': '1.1',
                'host': 'google-workspace',
                'short_message': events[0].get('name', 'workspace_event'),
                'timestamp': datetime.now(timezone.utc).timestamp(),
                'level': 6,
                '_application': application,
                '_actor_email': actor.get('email', 'unknown'),
                '_actor_ip': activity.get('ipAddress', 'unknown'),
                '_event_name': events[0].get('name', 'unknown'),
                '_source': 'google_workspace'
            }
            send_to_graylog(message)
            print(f"Sent: {application} - {message['_actor_email']} - {message['_event_name']}")
    except Exception as e:
        print(f"Error fetching {application} logs: {e}")

if __name__ == '__main__':
    service = get_service()
    for app in APPLICATIONS:
        fetch_logs(service, app)

