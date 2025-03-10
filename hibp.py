import requests
import time
import os
import json
import psutil
import sys

# Configuration
CONFIG_FILE = 'hibp-config.json'
CONFIG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONFIG_FILE)
CONFIG_DEFAULTS = {
    'hibp_api_key': "XXXXXX",
    "webhook_url": "https://webhook-collector.XXXXX.prod.alienvault.cloud/api/1.0/webhook/push",
    "webhook_api_key": "XXXXXX"
}


# Load or create configuration file
def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
            if not all(key in config for key in CONFIG_DEFAULTS):
                print("Config is malformed. Please delete it and restart the script to create blank config.")
                sys.exit(1)
            return config
        except json.JSONDecodeError:
            print("Error: Malformed JSON in config file. Please fix or delete the file.")
            sys.exit(1)
    else:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(CONFIG_DEFAULTS, f, indent=4, sort_keys=True)
        print("Config file created. Please update it with valid API keys and URL.")
        sys.exit(1)


CONFIG_DATA = load_config()
HIBP_HEADERS = {"hibp-api-key": CONFIG_DATA['hibp_api_key']}
BASE_URL = "https://haveibeenpwned.com/api/v3"
DELAY = 30
RETRIES = 3


# Prevent multiple script instances
def check_if_already_running():
    current_pid = os.getpid()
    current_name = psutil.Process(current_pid).name()
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == current_name and proc.info['pid'] != current_pid:
            print("Another instance of the script is already running.")
            print(f"{proc.info['name']} and {proc.info['pid']}")
            sys.exit(1)


# Send webhook message
def webhook_send_message(event):
    for attempt in range(RETRIES):
        try:
            response = requests.post(
                CONFIG_DATA['webhook_url'], json=event,
                headers={'API_KEY': CONFIG_DATA['webhook_api_key']}
            )
            if response.status_code == 200:
                print(f"Successfully sent event {event} to webhook.")
                return
            response_check(response)
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Unable to send webhook message. {e}")
            return


# Get breach details
def get_breached_domain_info(breach):
    url = f"{BASE_URL}/breach/{breach}"
    return make_request(url)


# Check if domain is breached
def check_breached_domain(domain):
    url = f"{BASE_URL}/breacheddomain/{domain}"
    return make_request(url)


# Make API request with retries
def make_request(url):
    for attempt in range(RETRIES):
        try:
            response = requests.get(url, headers=HIBP_HEADERS, verify=False)
            if response.status_code == 200:
                return response.json()
            response_check(response)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
    return None


# Handle API responses
def response_check(response):
    if response.status_code == 429:
        retry_after = int(response.headers.get('Retry-After', DELAY))
        print(f"Rate limit exceeded. Retrying in {retry_after} seconds...")
        time.sleep(retry_after)
    elif response.status_code == 503:
        print(f"Service unavailable. Retrying in {DELAY} seconds...")
        time.sleep(DELAY)
    elif response.status_code == 404:
        print("No breaches found for this domain.")
        return None
    else:
        print(f"Error {response.status_code}: {response.text}")


# Process breach data
def process_domain_list(domain):
    breach_data = check_breached_domain(domain)
    if not breach_data:
        return [], []

    all_breaches = {item for breaches in breach_data.values() for item in breaches}
    print(f'Found {len(breach_data)} users affected by breaches: {all_breaches}')

    breaches = [get_breached_domain_info(breach) for breach in all_breaches]
    # API rate limit handling. HIBP API has no stated API limit just limiting it to 6 queries a minute
    time.sleep(6) 

    return breach_data, breaches


# Main function
def main(domain):
    user_breach_data, breach_data = process_domain_list(domain)

    for user, breaches in user_breach_data.items():
        if isinstance(breaches, list):
            for breach in breaches:
                for event in breach_data:
                    # getting data of this breach for this user.
                    if event['Name'] == breach:
                        event['User'] = user
                        # sending event for each breach for this user
                        webhook_send_message(event)


if __name__ == "__main__":
    # checking if python already running
    check_if_already_running()
    # searching for a domain
    main("test.com")
