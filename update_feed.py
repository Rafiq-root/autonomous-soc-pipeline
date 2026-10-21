import ipaddress
import requests
import sqlite3

FEED_URL = "https://cinsscore.com/list/ci-badguys.txt"
FEED_TIMEOUT_SECONDS = 10

def parse_feed_lines(feed_text):
    """Return unique, canonical IP addresses from a plain-text threat feed."""
    valid_ips = []
    seen = set()
    for raw_line in feed_text.splitlines():
        candidate = raw_line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            address = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if address not in seen:
            seen.add(address)
            valid_ips.append(address)
    return valid_ips

def update_threat_database(db_path="threat_intel.db", feed_url=FEED_URL):
    # Download only over HTTPS so network intermediaries cannot silently alter indicators.
    
    print(f"1. Downloading active threat feed from {feed_url}...")
    try:
        response = requests.get(feed_url, timeout=FEED_TIMEOUT_SECONDS)
        response.raise_for_status() # Check for download errors
        malicious_ips = parse_feed_lines(response.text)
        if not malicious_ips:
            print("Feed contained no valid IP addresses; database was left unchanged.")
            return 0
        print(f"Download complete. Found {len(malicious_ips)} malicious IPs.")
        
    except requests.RequestException as e:
        print(f"Error downloading threat feed: {e}")
        return 0

    print("2. Updating local SQLite database...")
    try:
        added_count = 0
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            for ip in malicious_ips:
                cursor.execute(
                    "INSERT OR IGNORE INTO bad_ips (ip_address, threat_type) VALUES (?, ?)",
                    (ip, "Known Malicious Source - CINS Feed"),
                )
                added_count += cursor.rowcount
        print(f"Database update complete. Added {added_count} new threats to local storage.")
        return added_count
        
    except Exception as e:
        print(f"Database Error: {e}")
        return 0

if __name__ == "__main__":
    update_threat_database()
