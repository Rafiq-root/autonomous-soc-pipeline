import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

import smart_pipeline


VALID_DECISION = {
    "is_threat": True,
    "severity": "High",
    "incident_title": "Repeated SSH authentication failures",
    "mitre_tactic": "Credential Access",
    "executive_summary": "The source generated repeated failed SSH attempts.",
    "indicators_of_compromise": ["203.0.113.45"],
    "root_cause_analysis": "Repeated failed attempts indicate possible password guessing.",
    "containment_recommendation": "Review the source and consider a temporary block.",
}


class SmartPipelineTests(unittest.TestCase):
    def test_log_tail_reads_only_new_complete_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "auth.log")
            with open(path, "wb") as log_file:
                log_file.write(b"first event\n")
            tail = smart_pipeline.LogFileTail(path)
            self.assertEqual(tail.read_new_lines(), ["first event"])
            self.assertEqual(tail.read_new_lines(), [])
            with open(path, "ab") as log_file:
                log_file.write(b"second event\n")
            self.assertEqual(tail.read_new_lines(), ["second event"])

    def test_log_tail_reassembles_a_line_split_across_reads(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "auth.log")
            with open(path, "wb") as log_file:
                log_file.write(b"partial")
            tail = smart_pipeline.LogFileTail(path)
            self.assertEqual(tail.read_new_lines(), [])
            with open(path, "ab") as log_file:
                log_file.write(b" line\n")
            self.assertEqual(tail.read_new_lines(), ["partial line"])

    def test_log_tail_resets_after_file_rotation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "auth.log")
            rotated_path = os.path.join(temp_dir, "auth.log.1")
            with open(path, "wb") as log_file:
                log_file.write(b"old event\n")
            tail = smart_pipeline.LogFileTail(path)
            self.assertEqual(tail.read_new_lines(), ["old event"])
            os.replace(path, rotated_path)
            with open(path, "wb") as log_file:
                log_file.write(b"new\n")
            self.assertEqual(tail.read_new_lines(), ["new"])

    def test_log_tail_resets_after_truncation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "auth.log")
            with open(path, "wb") as log_file:
                log_file.write(b"a long previous event\n")
            tail = smart_pipeline.LogFileTail(path)
            self.assertEqual(tail.read_new_lines(), ["a long previous event"])
            with open(path, "wb") as log_file:
                log_file.write(b"new\n")
            self.assertEqual(tail.read_new_lines(), ["new"])

    def test_analyze_uses_timeout_and_returns_report_compatible_decision(self):
        response = Mock()
        response.json.return_value = {"response": json.dumps(VALID_DECISION)}
        with patch.object(smart_pipeline.requests, "post", return_value=response) as post:
            decision = smart_pipeline.analyze_behavior_with_ai(
                "203.0.113.45", ["Failed password from 203.0.113.45"], "Known brute force source"
            )

        self.assertEqual(decision, VALID_DECISION)
        post.assert_called_once()
        self.assertEqual(post.call_args.kwargs["timeout"], smart_pipeline.OLLAMA_TIMEOUT_SECONDS)
        self.assertEqual(post.call_args.args[0], smart_pipeline.OLLAMA_URL)
        self.assertTrue(response.raise_for_status.called)

    def test_invalid_json_returns_none(self):
        response = Mock()
        response.json.return_value = {"response": "not json"}
        with patch.object(smart_pipeline.requests, "post", return_value=response):
            self.assertIsNone(smart_pipeline.analyze_behavior_with_ai("192.0.2.1", [], "none"))

    def test_invalid_schema_returns_none(self):
        invalid_decision = dict(VALID_DECISION, is_threat="yes")
        response = Mock()
        response.json.return_value = {"response": json.dumps(invalid_decision)}
        with patch.object(smart_pipeline.requests, "post", return_value=response):
            self.assertIsNone(smart_pipeline.analyze_behavior_with_ai("192.0.2.1", [], "none"))

    def test_http_error_returns_none(self):
        response = Mock()
        response.raise_for_status.side_effect = requests.HTTPError("Ollama failed")
        with patch.object(smart_pipeline.requests, "post", return_value=response):
            self.assertIsNone(smart_pipeline.analyze_behavior_with_ai("192.0.2.1", [], "none"))

    def test_report_writes_fields_from_the_validated_contract(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(temp_dir, "report.txt")
            smart_pipeline.write_incident_report(
                VALID_DECISION,
                ["Failed password for admin from 203.0.113.45"],
                report_path,
            )
            with open(report_path, encoding="utf-8") as report_file:
                report = report_file.read()

        for expected in (
            "Repeated SSH authentication failures",
            "Severity      : High",
            "MITRE ATT&CK  : Credential Access",
            "The source generated repeated failed SSH attempts.",
            " - 203.0.113.45",
            "Review the source and consider a temporary block.",
            "Failed password for admin from 203.0.113.45",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_decision_validator_requires_exact_field_types(self):
        self.assertTrue(smart_pipeline.validate_ai_decision(VALID_DECISION))
        self.assertFalse(smart_pipeline.validate_ai_decision({**VALID_DECISION, "severity": "Urgent"}))
        self.assertFalse(smart_pipeline.validate_ai_decision({**VALID_DECISION, "severity": ["High"]}))
        self.assertFalse(smart_pipeline.validate_ai_decision({**VALID_DECISION, "indicators_of_compromise": [42]}))
        self.assertFalse(smart_pipeline.validate_ai_decision([VALID_DECISION]))


if __name__ == "__main__":
    unittest.main()
