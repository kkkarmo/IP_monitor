import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import json
import logging
import traceback
from ratelimit import limits, sleep_and_retry
import pickle
from datetime import datetime, timedelta

logging.basicConfig(level=logging.DEBUG, filename='debug.log', filemode='w',
                    format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')

CHECK_INTERVAL = timedelta(hours=24)  # Recheck IPs every 24 hours
CHECKED_IPS_FILE = 'checked_ips.pkl'

class IPFileHandler(FileSystemEventHandler):
    def __init__(self, api_key):
        self.api_key = api_key
        self.vt_url = 'https://www.virustotal.com/api/v3/ip_addresses/'
        self.checked_ips = self.load_checked_ips()
        logging.debug(f"Initialized with API key: {api_key[:5]}...{api_key[-5:]}")

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('Public_IPs.txt'):
            logging.debug(f"File changed: {event.src_path}")
            logging.debug("Processing Public_IPs.txt")
            self.process_ip_file(event.src_path)
        else:
            logging.debug(f"Ignoring file change: {event.src_path}")

    def process_ip_file(self, file_path):
        logging.debug(f"Processing file: {file_path}")
        try:
            with open(file_path, 'r') as f:
                ips = f.read().splitlines()
            logging.debug(f"IPs found: {ips}")
            
            for ip in ips:
                if self.should_check_ip(ip):
                    result = self.check_ip(ip)
                    self.write_result(result)
                    logging.debug(result)  # Log result
                    self.checked_ips[ip] = datetime.now()
                    self.save_checked_ips()
                    time.sleep(15)  # Wait 15 seconds between checks
                else:
                    logging.debug(f"Skipping IP (recently checked): {ip}")
        except Exception as e:
            logging.error(f"Error processing file: {str(e)}")
            traceback.print_exc()

    def should_check_ip(self, ip):
        last_checked = self.checked_ips.get(ip)
        if last_checked is None:
            return True
        return datetime.now() - last_checked > CHECK_INTERVAL

    @sleep_and_retry
    @limits(calls=4, period=60)  # 4 calls per minute
    def check_ip(self, ip):
        logging.debug(f"Checking IP: {ip}")
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        try:
            response = requests.get(f"{self.vt_url}{ip}", headers=headers)
            logging.debug(f"Response status code: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return f"IP: {ip}, Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}"
            elif response.status_code == 429:
                logging.debug(f"Rate limit exceeded for IP: {ip}. Waiting before retry...")
                time.sleep(60)  # Wait for 60 seconds before retrying
                return self.check_ip(ip)  # Retry the request
            else:
                return f"IP: {ip}, Error: Unable to fetch results, status code: {response.status_code}"
        except Exception as e:
            logging.error(f"Error checking IP {ip}: {str(e)}")
            traceback.print_exc()
            return f"IP: {ip}, Error: {str(e)}"

    def write_result(self, result):
        logging.debug(f"Writing result: {result}")
        try:
            with open('vt_results.txt', 'a') as f:
                f.write(f"{result}\n")
            logging.debug("Result written successfully")
        except Exception as e:
            logging.error(f"Error writing result: {str(e)}")
            traceback.print_exc()

    def load_checked_ips(self):
        try:
            with open(CHECKED_IPS_FILE, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            return {}

    def save_checked_ips(self):
        with open(CHECKED_IPS_FILE, 'wb') as f:
            pickle.dump(self.checked_ips, f)

if __name__ == "__main__":
    try:
        with open('api_key.txt', 'r') as f:
            api_key = f.read().strip()
    except FileNotFoundError:
        logging.error("API key file not found. Please create 'api_key.txt' with your VirusTotal API key.")
        exit(1)

    path = '.'  # Current directory

    logging.debug(f"Starting script with API key: {api_key[:5]}...{api_key[-5:]}")
    event_handler = IPFileHandler(api_key)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    logging.debug("Observer started")

    logging.debug("Testing file processing...")
    try:
        event_handler.process_ip_file('Public_IPs.txt')
    except Exception as e:
        logging.error(f"Error during test processing: {str(e)}")
        traceback.print_exc()
    logging.debug("Test complete.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
