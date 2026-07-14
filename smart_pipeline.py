import re
import requests
import json
import sqlite3
import sys
import os
import time
import uuid
from datetime import datetime

# --- 1. DATA ORGANIZATION MODULE ---
def group_logs_by_ip(new_log_lines):
    # This now accepts a list of lines directly from the continuous loop
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ip_blocks = {}

    for line in new_log_lines:
        line = line.strip()
        ips_found = ip_pattern.findall(line)
        if ips_found:
            for ip in set(ips_found):
                if ip not in ip_blocks:
                    ip_blocks[ip] = []
                ip_blocks[ip].append(line)
    return ip_blocks

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
    Output EXACTLY in JSON format. Do not add conversational text.
    {{
        "is_threat": true/false,
        "threat_level": "None, Low, Medium, High, or Critical",
        "attack_type": "Brief classification or 'Normal Activity'",
        "ai_reasoning": "Explain your behavioral analysis of the event sequence.",
        "recommended_action": "Playbook action (e.g., Block IP, Ignore)"
    }}
    """
    
    url = "http://localhost:11434/api/generate"
    payload = {"model": "qwen2.5", "prompt": prompt, "stream": False, "format": "json"}
    
    try:
        response = requests.post(url, json=payload)
        return json.loads(response.json()["response"])
    except Exception as e:
        print(f"AI Error for IP {ip}: {e}")
        return None

# --- 4. CONTINUOUS MONITORING EXECUTION ---
if __name__ == "__main__":
    log_file = "mock_auth.log"
    
    if not os.path.exists(log_file):
        print(f"CRITICAL ERROR: {log_file} missing. Create the file to begin monitoring.")
        sys.exit(1)

    print(f"Initializing continuous monitoring on {log_file}...")
    print("Press Ctrl+C to stop the script.\n")
    
    # Track the last byte read so we don't process old logs twice
    last_position = 0 
    
    try:
        while True:
            with open(log_file, 'r') as file:
                file.seek(last_position)
                new_lines = file.readlines()
                last_position = file.tell()

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
                        
                        with open("smart_soc_report.txt", "a") as report_file:
                            report_file.write(f"\n========================================================================\n")
                            report_file.write(f"                     SOC INCIDENT REPORT TICKET\n")
                            report_file.write(f"========================================================================\n")
                            report_file.write(f"Incident ID   : INC-{str(uuid.uuid4())[:8].upper()}\n")
                            report_file.write(f"Date/Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                            report_file.write(f"Title         : {ai_decision.get('incident_title', 'Unknown Threat')}\n")
                            report_file.write(f"Severity      : {ai_decision.get('severity', 'Unknown')}\n")
                            report_file.write(f"MITRE ATT&CK  : {ai_decision.get('mitre_tactic', 'Unclassified')}\n")
                            report_file.write(f"------------------------------------------------------------------------\n")
                            report_file.write(f"[EXECUTIVE SUMMARY]\n{ai_decision.get('executive_summary', 'None')}\n\n")
                            report_file.write(f"[INDICATORS OF COMPROMISE (IoCs)]\n")
                            for ioc in ai_decision.get('indicators_of_compromise', []):
                                report_file.write(f" - {ioc}\n")
                            report_file.write(f"\n[ROOT CAUSE & BEHAVIORAL ANALYSIS]\n{ai_decision.get('root_cause_analysis', 'None')}\n\n")
                            report_file.write(f"[RECOMMENDED CONTAINMENT ACTION]\n{ai_decision.get('containment_recommendation', 'None')}\n\n")
                            report_file.write(f"[RAW LOG EVIDENCE]\n")
                            for log in logs:
                                report_file.write(f"  {log}\n")
                            report_file.write(f"========================================================================\n")
            
            # Pause for 15 seconds before checking the file again
            time.sleep(15)
            
    except KeyboardInterrupt:
        print("\nMonitoring terminated by user.")
        sys.exit(0)