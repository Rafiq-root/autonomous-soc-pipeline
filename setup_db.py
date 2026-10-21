import sqlite3

def ensure_schema(conn):
    """Create or upgrade the threat table without discarding existing indicators."""
    cursor = conn.cursor()

    # Create a table to hold IP addresses and their threat type
    # Think of this as creating a spreadsheet with two columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bad_ips (
            ip_address TEXT PRIMARY KEY,
            threat_type TEXT,
            last_seen TEXT
        )
    ''')
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(bad_ips)")}
    if "last_seen" not in columns:
        cursor.execute("ALTER TABLE bad_ips ADD COLUMN last_seen TEXT")

def create_database(database_path="threat_intel.db"):
    # Connect to SQLite. This automatically creates the configured database file.
    with sqlite3.connect(database_path) as conn:
        ensure_schema(conn)

        # Insert a documentation-only sample indicator for the mock logs.
        conn.execute('''
            INSERT OR IGNORE INTO bad_ips (ip_address, threat_type)
            VALUES ('203.0.113.45', 'Known Brute Force Source')
        ''')

    print("Local threat intelligence database 'threat_intel.db' created successfully.")

if __name__ == "__main__":
    create_database()
