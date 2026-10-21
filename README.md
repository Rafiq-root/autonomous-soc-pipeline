Autonomous AI SOC Analyst Pipeline

An automated, local AI-driven Security Operations Center (SOC) pipeline that emulates the triage, analysis, and reporting duties of a Tier 1 SOC Analyst.

By utilizing local Large Language Models (via Ollama) and custom Python orchestration, this tool performs continuous behavioral analysis on network/auth logs without sending sensitive telemetry to cloud providers.

🚀 Features

Autonomous Behavioral Analysis: Replaces rigid Regex rules with AI context-awareness. The AI reads event sequences to detect novel and obfuscated attacks.

Continuous Monitoring: Runs in a live loop, analyzing new log entries as they are written to the file, including after rotation or truncation.

Threat Intelligence Enrichment: Automatically queries a local SQLite database of known malicious IPs (populated by the CINS Army threat feed).

Automated SOC Reporting: Generates industry-standard Incident Response tickets, including Executive Summaries, MITRE ATT&CK mapping, IoC extraction, and containment recommendations.

100% Local & Private: All data processing and AI inference happen on-premise.

📁 Project Structure

smart_pipeline.py: The core engine. Monitors logs continuously, groups events by valid IPv4 or IPv6 address, queries the database, and feeds data to the AI for analysis.

setup_db.py: Initializes the local SQLite threat intelligence database (threat_intel.db).

update_feed.py: Fetches the CINS threat feed over HTTPS, validates and deduplicates IP indicators, and updates the local database. Designed to be run via a background scheduler for daily updates.

🛠️ Prerequisites

Python 3.x

Ollama: Installed and running locally.

LLM Model: The script defaults to qwen2.5 via Ollama.

Python dependency: `requests` (install from `requirements.txt`).

⚙️ Setup & Installation

Clone the repository:

git clone https://github.com/Rafiq-root/autonomous-soc-pipeline.git
cd autonomous-soc-pipeline

Install Python dependencies:

python3 -m pip install -r requirements.txt

Initialize the Threat Database:

python3 setup_db.py


Automate Daily Threat Intel Updates:
Threat indicators decay quickly. It is highly recommended to automate the update_feed.py script to run daily at midnight.

The updater skips comments, malformed entries, and duplicate addresses. A failed, empty, or entirely invalid feed does not change the database.

Each CINS indicator records when it was last present in the feed. Feed entries older than 30 days (including legacy entries without a timestamp) are excluded from AI threat context; manually seeded indicators are not expired by this rule. Run `update_feed.py` to refresh the CINS timestamps.

For Linux/macOS Users (Using cron):

Open your terminal and type crontab -e.

Scroll to the bottom of the file and add this line (replace /path/to/your/folder with your actual absolute path):
0 0 * * * /usr/bin/python3 /path/to/your/folder/update_feed.py

Save and exit. The system will now update your database every night at midnight.

For Windows Users (Using Task Scheduler):

Press the Windows key, type Task Scheduler, and open it.

Click Create Basic Task... on the right panel. Name it "Update SOC Threat Feed" and click Next.

Set the Trigger to Daily and set the time to midnight.

Set the Action to Start a program.

In "Program/script", type python. In "Add arguments", type the absolute path to your update_feed.py file. Click Finish.

Start the Pipeline:

python3 smart_pipeline.py

Runtime settings can be overridden without editing source code. For example:

```bash
python3 smart_pipeline.py --log-file /var/log/auth.log --report-file ./incidents.txt \
  --database ./threat_intel.db --model qwen2.5 --poll-interval 5
```

Available options include `--checkpoint-file`, `--ollama-url`, and `--ollama-timeout` as well as the paths and model shown above. Timeout and polling values must be greater than zero. Use `python3 smart_pipeline.py --help` to see all options.

`filter.py` remains as a compatibility command and forwards to the maintained `smart_pipeline.py` implementation, including its command-line options. New integrations should use `smart_pipeline.py` directly.


📝 Usage

Once smart_pipeline.py is running, it will monitor the target log file (e.g., mock_auth.log). As external systems (firewalls, SIEMs, Linux auth systems) write to this log, the pipeline will group the data, analyze the behavior, and if malicious intent is found, output a structured ticket to smart_soc_report.txt.

The Ollama response must match the incident report contract: a boolean `is_threat`, a supported `severity`, and the report fields for title, ATT&CK tactic, summary, indicators, analysis, and recommendation. Invalid JSON or fields are rejected instead of producing incomplete tickets. Requests to the local Ollama API time out after 60 seconds.

The log monitor persists its file identity, byte position, and incomplete-line buffer in `mock_auth.log.state.json`. After a restart it resumes where it left off instead of replaying old entries. It also detects rotation and truncation, and holds incomplete lines until the next newline arrives. Keep the state file alongside the log; if it is removed or unreadable, monitoring safely starts from the beginning of the current log file.

Threat reports are deduplicated in the local SQLite database by source IP and exact event batch. Repeated matches within 24 hours update the deduplication timestamp without creating another ticket; the same activity can be reported again after 24 hours. Old deduplication records are pruned after 30 days.

Log evidence is passed to the model as a JSON string array and explicitly treated as untrusted data, so text inside an event cannot override analysis instructions. The model receives at most the newest 200 lines and 12,000 characters per IP, and reports use the same bounds with a truncation notice. Model containment recommendations remain advisory for a human analyst.

Log grouping validates and canonicalizes IPv4 and IPv6 addresses before looking them up or sending their event groups to the model; malformed address-like strings are ignored.

Run the automated tests with:

```bash
python3 -m unittest discover -s tests -v
```
