# Autonomous AI SOC Analyst Pipeline

A local Python pipeline for monitoring authentication logs, grouping events by source IP, enriching them with threat intelligence, asking a locally hosted Ollama model to assess suspicious activity, and writing incident reports for analyst review.

By default, AI requests go to Ollama on `localhost`. The threat-feed updater separately downloads the CINS Army IP feed over HTTPS. If you configure a remote Ollama URL, log evidence will be sent to that endpoint.

## Features

- **Continuous log monitoring:** follows appended log entries and detects file rotation and truncation.
- **Restart recovery:** saves the log cursor and partial-line buffer so a restart can resume. An in-flight batch is replayed until processing completes.
- **IP validation:** groups events by canonical IPv4 or IPv6 address and ignores malformed address-like tokens.
- **Threat intelligence:** looks up indicators in a local SQLite database and excludes stale CINS feed entries from AI context.
- **AI-assisted triage:** validates Ollama's JSON response against the incident report schema and applies a request timeout.
- **Incident reports:** writes report tickets with a title, severity, ATT&CK tactic, summary, indicators, analysis, recommendation, and bounded log evidence.
- **Report deduplication:** suppresses the same source IP and exact event batch for 24 hours after a report is written.
- **GitHub Actions:** runs Python compilation and the unit test suite on pushes and pull requests.

## Requirements

- Python 3.9 or newer
- Ollama installed and running locally, unless you configure another compatible Ollama endpoint
- The `qwen2.5` model, or another model selected with `--model`

## Install

```bash
git clone https://github.com/Rafiq-root/autonomous-soc-pipeline.git
cd autonomous-soc-pipeline
python3 -m pip install -r requirements.txt
python3 setup_db.py
```

Make sure Ollama is running and the selected model is available. For the default model:

```bash
ollama pull qwen2.5
```

## Update threat intelligence

Run the updater to download and refresh the CINS feed in `threat_intel.db`:

```bash
python3 update_feed.py
```

The updater uses HTTPS, validates and deduplicates IP addresses, and leaves the database unchanged if the request fails or the feed contains no valid addresses. Feed indicators record when they were last present; entries older than 30 days are excluded from AI context. Manually added indicators are not expired by this rule.

To refresh the feed daily on Linux or macOS, add a cron entry and replace the paths with the locations on your system:

```cron
0 0 * * * /usr/bin/python3 /path/to/autonomous-soc-pipeline/update_feed.py
```

On Windows, schedule `update_feed.py` to run daily using Task Scheduler.

## Run the monitor

The default log path is `mock_auth.log`. Create it or provide a path to a log file your account can read:

```bash
touch mock_auth.log
python3 smart_pipeline.py
```

To use a different log and report path:

```bash
python3 smart_pipeline.py \
  --log-file /path/to/auth.log \
  --report-file ./incidents.txt \
  --database ./threat_intel.db \
  --model qwen2.5 \
  --poll-interval 5
```

The monitor groups each new batch by valid IP address, queries the local threat database, and asks Ollama to classify the event groups. It writes a ticket when the model identifies a threat. Recommendations in the report are for analyst review; the pipeline does not carry out containment actions.

Stop the monitor with `Ctrl+C`.

## Command-line options

| Option | Default | Purpose |
| --- | --- | --- |
| `--log-file` | `mock_auth.log` | Log file to monitor |
| `--checkpoint-file` | `<log-file>.state.json` | Persistent tailer state |
| `--report-file` | `smart_soc_report.txt` | Append-only incident report |
| `--database` | `threat_intel.db` | Threat intelligence and deduplication database |
| `--ollama-url` | `http://localhost:11434/api/generate` | Ollama generate API endpoint |
| `--model` | `qwen2.5` | Ollama model name |
| `--ollama-timeout` | `60` seconds | Maximum time for an Ollama request |
| `--poll-interval` | `15` seconds | Delay between log checks |

Timeout and polling values must be greater than zero. Show all options with:

```bash
python3 smart_pipeline.py --help
```

`filter.py` is retained as a compatibility command and forwards to `smart_pipeline.py`. New usage should call `smart_pipeline.py` directly.

## Processing details

- The monitor stores its cursor, file identity, and incomplete-line buffer in the checkpoint file. It advances the saved cursor after the full batch is handled. If the checkpoint is missing or unreadable, it starts from the beginning of the current log file.
- The monitor detects file replacement and truncation, and waits for a newline before processing an incomplete line.
- Incident fingerprints use the source IP and exact event batch. Matching reports are suppressed for 24 hours after the last report; old fingerprints are pruned after 30 days.
- The model receives at most the newest 200 log lines and 12,000 characters per IP. Reports use the same evidence limits and include a truncation notice when needed.
- Log entries are sent to the model as untrusted evidence with instructions not to follow commands inside them. This reduces prompt-injection risk but cannot guarantee model behavior.
- The Ollama response must contain a boolean `is_threat`, a supported severity, and the report fields. Invalid JSON or fields are rejected.

## Tests

Install dependencies, then run:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile smart_pipeline.py setup_db.py update_feed.py filter.py
```
