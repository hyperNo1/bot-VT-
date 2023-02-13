import requests
import json

# Your Telegram bot API token
token = "YOUR_TELEGRAM_BOT_API_TOKEN"

# Your Telegram chat ID
chat_id = "YOUR_TELEGRAM_CHAT_ID"

# VirusTotal API key
vt_api_key = "YOUR_VIRUSTOTAL_API_KEY"

# Function to send a message to Telegram
def send_message(text):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {"chat_id": chat_id, "text": text}
    requests.post(url, data=data)

# Function to query VirusTotal for incidents and threats
def query_virustotal():
    url = "https://www.virustotal.com/api/v3/intelligence/search"
    headers = {"x-apikey": vt_api_key}
    response = requests.get(url, headers=headers)
    data = json.loads(response.text)
    return data

# Function to format and send the results of the VirusTotal query to Telegram
def send_virustotal_results():
    data = query_virustotal()
    message = "VirusTotal Intelligence Report:\n"
    for result in data['data']:
        message += f"\nIncident ID: {result['id']}\n"
        message += f"Threat Name: {result['attributes']['threat_name']}\n"
        message += f"Threat Type: {result['attributes']['threat_type']}\n"
    send_message(message)

# Call the send_virustotal_results function
send_virustotal_results()
