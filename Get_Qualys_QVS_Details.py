import requests
import json
import csv
import sys
import time
from datetime import datetime
from requests.exceptions import Timeout

# Get current date in YYYYMMDD format
current_date = datetime.now().strftime("%Y%m%d")

# Read CVEs from file
with open('cve_list.txt', 'r') as f:
    cve_list = f.read().strip().split('\n')

# Create CSV file and write header
csv_filename = f'qualys_cve_qvs_details_{current_date}.csv'
with open(csv_filename, 'w', newline='') as f:
    csv_writer = csv.writer(f)
    header = ['CVE', 'QVS', 'QVSLastChangedDate', 'NVDPublishedDate', 'CVSS', 'CVSSVersion']
    csv_writer.writerow(header)

# Initialize a counter for CVEs with no QVS score
no_qvs_count = 0

# Loop through the list in batches of 450. Anything more and you risk getting a "URI to long" error 
for i in range(0, len(cve_list), 450):
    batch_cve_list = cve_list[i:i + 450]
    cve_str = ','.join(batch_cve_list)

	#Change the API URL placeholder below to fit your Qualys API endpoint
    url = f"https://[YOUR API URL]/api/2.0/fo/knowledge_base/qvs/?action=list&details=All&cve={cve_str}"
    headers = {
		#Change [BASE64 USERNAME:PASSWORD] to be your formated Qualys username and password.
        "Authorization": "Basic [BASE64 USERNAME:PASSWORD]",
        "X-Requested-With": "curl",
    }

    retry_count = 0
    max_retries = 3  # Maximum number of retries in case the API endpoint doesn't respond
    
    while retry_count < max_retries:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            break  # If the request is successful, break out of the loop
        except Timeout:
            print(f"The request timed out. Retrying... {retry_count + 1}")
            retry_count += 1

    if retry_count == max_retries:
        raise Exception("Reached maximum number of retries. Aborting script.")

    data = response.json()
    
    if isinstance(data, dict):
        returned_cves = set(data.keys())
        sent_cves = set(batch_cve_list)
        cves_with_no_qvs = sent_cves - returned_cves
        no_qvs_count += len(cves_with_no_qvs)
        
        with open(csv_filename, 'a', newline='') as f:
            csv_writer = csv.writer(f)
            
            for cve, details in data.items():
                base = details.get('base', {})
                factors = details.get('contributingFactors', {})
                
                # Convert Unix timestamps to mm/dd/yyyy format
                qvs_last_changed_date = base.get('qvsLastChangedDate', 'Unknown')
                nvd_published_date = base.get('nvdPublishedDate', 'Unknown')

                if qvs_last_changed_date != 'Unknown':
                    qvs_last_changed_date = datetime.fromtimestamp(int(qvs_last_changed_date)).strftime('%m/%d/%Y')
            
                if nvd_published_date != 'Unknown':
                    nvd_published_date = datetime.fromtimestamp(int(nvd_published_date)).strftime('%m/%d/%Y')
				
                row = [
                    base.get('id', 'Unknown'),
                    base.get('qvs', 'Unknown'),
                    qvs_last_changed_date,  # Use the converted date
                    nvd_published_date,     # Use the converted date
                    factors.get('cvss', 'Unknown'),
                    factors.get('cvssVersion', 'Unknown')
                ]
                
                csv_writer.writerow(row)
                
    elif isinstance(data, list):
        cves_with_no_qvs = set(batch_cve_list)
        no_qvs_count += len(cves_with_no_qvs)
        
        with open(csv_filename, 'a', newline='') as f:
            csv_writer = csv.writer(f)
            
            for cve in cves_with_no_qvs:
                csv_writer.writerow([cve, "unscored", "", "", "", ""])
                
    print(f"Total CVEs in List: {len(cve_list)}, Remaining CVEs to Process: {len(cve_list) - (i + len(batch_cve_list))}, Total CVEs without QVS: {no_qvs_count}")

    # Sleep to respect rate limits - adjust to your needs.
	# "Standard API" rate limit is 300 calls per hour means 12 seconds between API calls so a sleep setting of 14 will help ensure we're not going over the rate limit. Processing the a full NVD CVE list will take about 1.75 hours if processing 450 CVE's per loop cycle.
	# "Enterprise API" rate limit is 750 calls per hour means 4.8 seconds between API calls so a sleep setting of 6 will help ensure we're not going over the rate limit. Processing the full NVD CVE list will take about 1 hour.
					
    sleep_duration = 14
    cooldown_message = f"Rate limit cooldown: Sleeping for {sleep_duration} seconds."
    print(cooldown_message, end='', flush=True)  # Print cooldown message without newline
    for remaining in range(sleep_duration, 0, -1):
        sys.stdout.write("\r" + cooldown_message + f" {remaining:2d} seconds remaining." + ' ' * 20)
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r" + ' ' * (len(cooldown_message) + 50) + "\r")  # Clear the countdown line

