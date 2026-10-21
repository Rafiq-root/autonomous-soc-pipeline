import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import requests

import update_feed


class ThreatFeedTests(unittest.TestCase):
    def make_database(self, path):
        with sqlite3.connect(path) as connection:
            connection.execute(
                "CREATE TABLE bad_ips (ip_address TEXT PRIMARY KEY, threat_type TEXT)"
            )

    def read_indicators(self, path):
        with sqlite3.connect(path) as connection:
            return connection.execute(
                "SELECT ip_address, threat_type FROM bad_ips ORDER BY ip_address"
            ).fetchall()

    def test_parser_canonicalizes_deduplicates_and_rejects_invalid_lines(self):
        result = update_feed.parse_feed_lines(
            "# feed comment\n192.0.2.1\n192.0.2.1\n999.1.1.1\n2001:0db8::1\nnot-an-ip\n"
        )
        self.assertEqual(result, ["192.0.2.1", "2001:db8::1"])

    def test_update_uses_https_and_inserts_only_valid_unique_addresses(self):
        response = Mock()
        response.text = "# comment\n192.0.2.1\n192.0.2.1\n999.1.1.1\n2001:db8::1\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "threat_intel.db")
            self.make_database(db_path)
            with patch.object(update_feed.requests, "get", return_value=response) as get:
                added = update_feed.update_threat_database(db_path=db_path)
            rows = self.read_indicators(db_path)

        self.assertEqual(added, 2)
        get.assert_called_once_with(update_feed.FEED_URL, timeout=update_feed.FEED_TIMEOUT_SECONDS)
        self.assertTrue(update_feed.FEED_URL.startswith("https://"))
        self.assertTrue(response.raise_for_status.called)
        self.assertEqual(
            rows,
            [
                ("192.0.2.1", "Known Malicious Source - CINS Feed"),
                ("2001:db8::1", "Known Malicious Source - CINS Feed"),
            ],
        )

    def test_update_migrates_legacy_table_and_refreshes_last_seen(self):
        response = Mock()
        response.text = "192.0.2.1\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "threat_intel.db")
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    "CREATE TABLE bad_ips (ip_address TEXT PRIMARY KEY, threat_type TEXT)"
                )
                connection.execute(
                    "INSERT INTO bad_ips VALUES (?, ?)",
                    ("192.0.2.1", "Known Malicious Source - CINS Feed"),
                )
            with patch.object(update_feed.requests, "get", return_value=response):
                added = update_feed.update_threat_database(db_path=db_path)
            with sqlite3.connect(db_path) as connection:
                threat_type, last_seen = connection.execute(
                    "SELECT threat_type, last_seen FROM bad_ips WHERE ip_address = ?",
                    ("192.0.2.1",),
                ).fetchone()

        self.assertEqual(added, 0)
        self.assertEqual(threat_type, "Known Malicious Source - CINS Feed")
        observed_at = datetime.fromisoformat(last_seen)
        self.assertEqual(observed_at.tzinfo, timezone.utc)

    def test_invalid_or_empty_feed_does_not_change_database(self):
        response = Mock()
        response.text = "# empty feed\n999.1.1.1\nnot-an-ip\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "threat_intel.db")
            self.make_database(db_path)
            with sqlite3.connect(db_path) as connection:
                connection.execute("INSERT INTO bad_ips VALUES (?, ?)", ("198.51.100.5", "Existing"))
            with patch.object(update_feed.requests, "get", return_value=response):
                added = update_feed.update_threat_database(db_path=db_path)
            rows = self.read_indicators(db_path)

        self.assertEqual(added, 0)
        self.assertEqual(rows, [("198.51.100.5", "Existing")])

    def test_failed_download_does_not_modify_database(self):
        response = Mock()
        response.raise_for_status.side_effect = requests.HTTPError("feed unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "threat_intel.db")
            self.make_database(db_path)
            with sqlite3.connect(db_path) as connection:
                connection.execute("INSERT INTO bad_ips VALUES (?, ?)", ("198.51.100.5", "Existing"))
            with patch.object(update_feed.requests, "get", return_value=response):
                added = update_feed.update_threat_database(db_path=db_path)
            rows = self.read_indicators(db_path)

        self.assertEqual(added, 0)
        self.assertEqual(rows, [("198.51.100.5", "Existing")])


if __name__ == "__main__":
    unittest.main()
