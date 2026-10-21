import re
import requests
import json
import ipaddress
import sqlite3
import sys
import os
import time
import uuid
from datetime import datetime

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5"
OLLAMA_TIMEOUT_SECONDS = 60
VALID_SEVERITIES = {"Info", "Low", "Medium", "High", "Critical"}

# --- 1. DATA ORGANIZATION MODULE ---
def group_logs_by_ip(new_log_lines):
    # Extract IPv4 and IPv6 candidates, then let ipaddress reject malformed tokens.
    ip_patterns = (
        re.compile(r'(?<![0-9A-Za-z:.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])'),
        re.compile(r'(?<![0-9A-Za-z:.])[0-9A-Fa-f:.]{3,}(?![0-9A-Za-z:.])'),
    )
    ip_blocks = {}

    for line in new_log_lines:
        line = line.strip()
        ips_found = set()
        for pattern in ip_patterns:
            for candidate in pattern.findall(line):
                try:
                    ips_found.add(str(ipaddress.ip_address(candidate)))
                except ValueError:
                    continue
        for ip in ips_found:
            if ip not in ip_blocks:
                ip_blocks[ip] = []
            ip_blocks[ip].append(line)
    return ip_blocks

class LogFileTail:
    """Read appended log lines while handling rotations, truncation, and partial writes."""
    def __init__(self, path):
        self.path = path
        self.identity = None
        self.position = 0
        self.pending = b""

    def read_new_lines(self):
        try:
            with open(self.path, "rb") as log_file:
                stat = os.fstat(log_file.fileno())
                identity = (stat.st_dev, stat.st_ino)
                completed = []
                if self.identity != identity or stat.st_size < self.position:
                    if self.pending:
                        completed.append(self.pending)
                    self.position = 0
                    self.pending = b""
                    self.identity = identity

                log_file.seek(self.position)
                chunk = log_file.read()
                self.position = log_file.tell()
        except FileNotFoundError:
            return []

        lines = self.pending + chunk
        parts = lines.split(b"\n")
        self.pending = parts.pop()
        completed.extend(parts)
        return [line.rstrip(b"\r").decode("utf-8", errors="replace") for line in completed]

# --- 2. ENRICHMENT MODULE ---
def get_threat_intel(ip_address):
    try:
        conn = sqlite3.connect('threat_intel.db')
        cursor = conn.cursor()
        cursor.execute("SELECT threat_type FROM bad_ips WHERE ip_address=?", (ip_address,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else "No known threat history."
    except Exception:
        return "Database Error"

# --- 3. AUTONOMOUS AI ANALYSIS MODULE ---
def analyze_behavior_with_ai(ip, logs, intel_context):
    log_text = "\n".join(logs)
    prompt = f"""
    You are an expert SOC Analyst. Analyze the following sequence of events associated with IP Address: {ip}.
    
    THREAT INTEL CONTEXT FOR {ip}: {intel_context}
    
    EVENT SEQUENCE:
    {log_text}
    
    Determine if this IP's behavior is benign (normal) or malicious (an attack). 
    Output exactly one JSON object, with no markdown or conversational text, using this schema:
    {{
        "is_threat": true,
        "severity": "Info, Low, Medium, High, or Critical",
        "incident_title": "Short incident title",
        "mitre_tactic": "MITRE ATT&CK tactic or Unclassified",
        "executive_summary": "Short summary for the incident report",
        "indicators_of_compromise": ["indicator string"],
        "root_cause_analysis": "Evidence-based behavior analysis",
        "containment_recommendation": "Recommended action for analyst review"
    }}
    Use a boolean for is_threat, a JSON array of strings for indicators_of_compromise, and strings for every other field.
    """
    
    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json"}
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT_SECONDS)
        response.raise_for_status()
        model_output = response.json().get("response")
        if not isinstance(model_output, str):
            raise ValueError("Ollama response is missing its JSON text")
        decision = json.loads(model_output)
        if not validate_ai_decision(decision):
            raise ValueError("Ollama output does not match the incident decision schema")
        return decision
    except (requests.RequestException, ValueError, AttributeError) as e:
        print(f"AI Error for IP {ip}: {e}")
        return None

def validate_ai_decision(decision):
    """Return whether a parsed model response matches the incident report contract."""
    if not isinstance(decision, dict):
        return False
    if not isinstance(decision.get("is_threat"), bool):
        return False
    severity = decision.get("severity")
    if not isinstance(severity, str) or severity not in VALID_SEVERITIES:
        return False
    text_fields = (
        "incident_title",
        "mitre_tactic",
        "executive_summary",
        "root_cause_analysis",
        "containment_recommendation",
    )
    if any(not isinstance(decision.get(field), str) for field in text_fields):
        return False
    indicators = decision.get("indicators_of_compromise")
    return isinstance(indicators, list) and all(isinstance(item, str) for item in indicators)

def write_incident_report(ai_decision, logs, report_path="smart_soc_report.txt"):
    """Append a validated incident decision and its source log evidence to a report."""
    with open(report_path, "a", encoding="utf-8") as report_file:
        report_file.write("\n========================================================================\n")
        report_file.write("                     SOC INCIDENT REPORT TICKET\n")
        report_file.write("========================================================================\n")
        report_file.write(f"Incident ID   : INC-{str(uuid.uuid4())[:8].upper()}\n")
        report_file.write(f"Date/Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report_file.write(f"Title         : {ai_decision['incident_title']}\n")
        report_file.write(f"Severity      : {ai_decision['severity']}\n")
        report_file.write(f"MITRE ATT&CK  : {ai_decision['mitre_tactic']}\n")
        report_file.write("------------------------------------------------------------------------\n")
        report_file.write(f"[EXECUTIVE SUMMARY]\n{ai_decision['executive_summary']}\n\n")
        report_file.write("[INDICATORS OF COMPROMISE (IoCs)]\n")
        for indicator in ai_decision["indicators_of_compromise"]:
            report_file.write(f" - {indicator}\n")
        report_file.write(f"\n[ROOT CAUSE & BEHAVIORAL ANALYSIS]\n{ai_decision['root_cause_analysis']}\n\n")
        report_file.write(f"[RECOMMENDED CONTAINMENT ACTION]\n{ai_decision['containment_recommendation']}\n\n")
        report_file.write("[RAW LOG EVIDENCE]\n")
        for log in logs:
            report_file.write(f"  {log}\n")
        report_file.write("========================================================================\n")

# --- 4. CONTINUOUS MONITORING EXECUTION ---
if __name__ == "__main__":
    log_file = "mock_auth.log"
    
    if not os.path.exists(log_file):
        print(f"CRITICAL ERROR: {log_file} missing. Create the file to begin monitoring.")
        sys.exit(1)

    print(f"Initializing continuous monitoring on {log_file}...")
    print("Press Ctrl+C to stop the script.\n")
    
    log_tail = LogFileTail(log_file)
    
    try:
        while True:
            new_lines = log_tail.read_new_lines()

            if new_lines:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Detected {len(new_lines)} new events.")
                log_blocks = group_logs_by_ip(new_lines)
                
                for ip, logs in log_blocks.items():
                    print(f" -> AI analyzing behavior for IP: {ip}")
                    intel = get_threat_intel(ip)
                    ai_decision = analyze_behavior_with_ai(ip, logs, intel)
                    
                    # If a threat is found, append it to the report file
                    if ai_decision and ai_decision.get("is_threat") is True:
                        print(f"    [!] THREAT CONFIRMED: {ip}. Documenting to report.")
                        write_incident_report(ai_decision, logs)
            
            # Pause for 15 seconds before checking the file again
            time.sleep(15)
            
    except KeyboardInterrupt:
        print("\nMonitoring terminated by user.")
        sys.exit(0)
