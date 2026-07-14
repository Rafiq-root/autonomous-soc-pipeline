import requests
import sqlite3

def update_threat_database():
    # URL for an open-source, plain-text list of active malicious IP addresses
    feed_url = "http://cinsscore.com/list/ci-badguys.txt"
    
    print(f"1. Downloading active threat feed from {feed_url}...")
    try:
        response = requests.get(feed_url, timeout=10)
        response.raise_for_status() # Check for download errors
        
        # Split the downloaded text into a list of individual IP addresses
        malicious_ips = response.text.splitlines()
        print(f"Download complete. Found {len(malicious_ips)} malicious IPs.")
        
    except requests.RequestException as e:
        print(f"Error downloading threat feed: {e}")
        return

    print("2. Updating local SQLite database...")
    try:
        conn = sqlite3.connect('threat_intel.db')
        cursor = conn.cursor()
        
        # Counter for new IPs added
        added_count = 0
        
        for ip in malicious_ips:
            # Ignore empty lines or comments in the text file
            if not ip or ip.startswith('#'):
                continue
                
            # Attempt to insert the IP. 
            # The 'IGNORE' command prevents errors if the IP is already in the database.
            cursor.execute('''
                INSERT OR IGNORE INTO bad_ips (ip_address, threat_type)
                VALUES (?, ?)
            ''', (ip.strip(), 'Known Malicious Source - CINS Feed'))
            
            # Check if a new row was actually added
            if cursor.rowcount > 0:
                added_count += 1
                
        conn.commit()
        conn.close()
        
        print(f"Database update complete. Added {added_count} new threats to local storage.")
        
    except Exception as e:
        print(f"Database Error: {e}")

if __name__ == "__main__":
    update_threat_database()
