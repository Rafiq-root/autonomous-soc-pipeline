import re
import requests
import json
import sqlite3

# --- ENRICHMENT MODULE ---
def check_ip_in_db(ip_address):
    # Connects to the local database to verify if the IP is a known threat
    try:
        conn = sqlite3.connect('threat_intel.db')
        cursor = conn.cursor()
        cursor.execute("SELECT threat_type FROM bad_ips WHERE ip_address=?", (ip_address,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result[0] # Returns the threat type (e.g., 'Known Brute Force Source')
        return "Unknown"
    except Exception as e:
        return "Database Error"

# --- INGESTION & PRE-FILTERING MODULE ---
def filter_and_enrich(log_file):
    rule = re.compile(r"Failed password")
    # Regex to find numbers formatted as an IP address
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b') 
    
    extracted_lines = []
    enriched_data = []

    try:
        with open(log_file, 'r') as file:
            for line in file:
                if rule.search(line):
                    extracted_lines.append(line.strip())
                    
                    # Extract IPs and check them against the database
                    ips = ip_pattern.findall(line)
                    for ip in ips:
                        threat_status = check_ip_in_db(ip)
                        if threat_status != "Unknown":
                            enriched_data.append(f"CONTEXT PROVIDED: IP {ip} is flagged in database as '{threat_status}'.")
    except FileNotFoundError:
        return [], []
    
    # Remove duplicate context lines
    enriched_data = list(set(enriched_data))
    return extracted_lines, enriched_data

# --- AI ANALYSIS MODULE ---
def analyze_with_ai(logs, context):
    if not logs:
        return None

    log_text = "\n".join(logs)
    context_text = "\n".join(context) if context else "No known threat intelligence found."

    # The prompt now injects the database findings and forces JSON output
    prompt = f"""
    You are a SOC AI Analyst. Review the logs and the provided threat intel context.
    
    LOGS:
    {log_text}
    
    THREAT INTEL CONTEXT:
    {context_text}
    
    Determine if this is an attack. You MUST output ONLY valid JSON. Do not write a conversational introduction or conclusion.
    Format exactly like this:
    {{
        "threat_level": "Critical",
        "reason": "One short sentence explaining why.",
        "recommended_action": "Block IP"
    }}
    """

    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "qwen2.5",
        "prompt": prompt,
        "stream": False,
        "format": "json" # This Ollama parameter enforces strict JSON syntax
    }

    try:
        response = requests.post(url, json=payload)
        result = response.json()
        return result["response"]
    except Exception as e:
        return f'{{"error": "AI Connection Failed: {e}"}}'

# --- DOCUMENTATION MODULE ---
def generate_report(ai_json_output):
    # Converts the AI's text output into a readable file
    try:
        report_data = json.loads(ai_json_output)
        
        with open("incident_report.txt", "w") as file:
            file.write("=== AUTOMATED SOC INCIDENT REPORT ===\n")
            file.write(f"Threat Level: {report_data.get('threat_level', 'N/A')}\n")
            file.write(f"Reason: {report_data.get('reason', 'N/A')}\n")
            file.write(f"Action: {report_data.get('recommended_action', 'N/A')}\n")
            
        print("Documentation phase complete. File created: incident_report.txt")
    except json.JSONDecodeError:
        print("Failure: AI did not output valid JSON. Cannot generate report.")
        print("Raw AI Output:", ai_json_output)

# --- PIPELINE EXECUTION ---
if __name__ == "__main__":
    print("1. Filtering logs and querying local database...")
    logs, context = filter_and_enrich("mock_auth.log")
    
    if not logs:
        print("No threats detected. System idle.")
    else:
        print("2. Pushing enriched data to Qwen 2.5...")
        ai_output = analyze_with_ai(logs, context)
        
        print("3. Generating formal incident report...")
        generate_report(ai_output)
