import sqlite3

def create_database():
    # Connect to SQLite. This automatically creates a file named 'threat_intel.db'
    conn = sqlite3.connect('threat_intel.db')
    cursor = conn.cursor()

    # Create a table to hold IP addresses and their threat type
    # Think of this as creating a spreadsheet with two columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bad_ips (
            ip_address TEXT PRIMARY KEY,
            threat_type TEXT
        )
    ''')

    # Insert a known malicious IP. This IP matches the attacker in our mock logs.
    cursor.execute('''
        INSERT OR IGNORE INTO bad_ips (ip_address, threat_type)
        VALUES ('203.0.113.45', 'Known Brute Force Source')
    ''')

    # Save the changes and close the connection
    conn.commit()
    conn.close()
    print("Local threat intelligence database 'threat_intel.db' created successfully.")

if __name__ == "__main__":
    create_database()
