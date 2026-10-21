# Insider Threat Investigation Lab

An intermediate, educational DFIR project for analyzing **provided forensic exports** related to possible insider activity. Includes a Python CLI, Streamlit dashboard, sample data, SHA-256 evidence manifest, event timeline, and tests.

> **Scope and safety:** This project analyzes local CSV/JSON files that an investigator explicitly supplies. It does not collect data from endpoints, bypass access controls, monitor users, or connect to cloud accounts. Use only data you are authorized to examine. The included dataset is synthetic.

## Features

- Parse USB activity, browser history, and file/cloud activity from CSV files.
- Normalize events into a combined UTC timeline.
- Highlight rule-based investigation leads (not proof of wrongdoing).
- Hash source evidence with SHA-256 and write a manifest.
- Generate a CSV timeline and JSON findings report.
- CLI for repeatable runs and Streamlit dashboard for interactive review.
- Unit tests for parsing, hashing, and rule behavior.

## Folder structure

```text
insider-threat-investigation-lab/
├── app.py
├── dfir_lab.py
├── requirements.txt
├── README.md
├── data/
│   ├── usb_activity.csv
│   ├── browser_history.csv
│   └── file_activity.csv
├── reports/
│   └── .gitkeep
└── tests/
    └── test_dfir_lab.py
```

## Windows installation (PowerShell)

Install Python 3.11+ first, then open PowerShell in this directory:

```powershell
py -3 --version
py -3 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, either use the `Set-ExecutionPolicy` command above for the current process or call the venv interpreter directly as shown below.

## Run the CLI

Analyze the bundled synthetic dataset:

```powershell
python .\dfir_lab.py analyze --data-dir .\data --output-dir .\reports
```

Hash the supplied source files and create an evidence manifest:

```powershell
python .\dfir_lab.py hash --data-dir .\data --output .\reports\evidence_manifest.json
```

Run both commands when conducting a lab exercise. The hash manifest records the SHA-256 of each input file at the time it was read. It does **not** prove the source was authentic before collection or that it remained unchanged before hashing.

## Run the dashboard

```powershell
streamlit run app.py
```

Streamlit prints a local URL, usually `http://localhost:8501`. The dashboard processes only files in the project data folder unless the investigator uploads additional CSV files through the interface. Keep the dashboard local; do not expose it to a public network with sensitive evidence loaded.

## Run tests

```powershell
python -m pytest -q
```

## Input schemas

Timestamps must be parseable by pandas; timezone-aware timestamps are recommended. The application normalizes valid timestamps to UTC.

### `usb_activity.csv`
Required columns: `timestamp`, `device_id`, `action`, `user`, `source`

### `browser_history.csv`
Required columns: `timestamp`, `url`, `title`, `user`, `source`

### `file_activity.csv`
Required columns: `timestamp`, `action`, `path`, `bytes`, `destination`, `user`, `source`

`source` should identify the original export or evidence item. Do not put secrets or unnecessary personal information in sample files.

## Rule-based leads

The starter rules flag:
- access to cloud-storage domains,
- large file operations (default threshold: 100 MB),
- USB connection or file-copy events,
- activity clustered near cloud access and removable-media activity.

These are **triage leads only**. A cloud visit, USB connection, or large file by itself is not proof of exfiltration or malicious intent. Validate leads against original artifacts, system context, time synchronization, user authorization, and independent evidence. Avoid conclusions based solely on this score.

## Evidence integrity and privacy

1. Work from forensic images or verified exports, not the original live system when avoidable.
2. Preserve originals in a controlled evidence store; analyze working copies.
3. Record who acquired the evidence, when, from which system, with which tool/version, and the acquisition method in your case notes.
4. Hash at acquisition and after transfer; compare values and document any mismatch.
5. Keep a chain-of-custody record outside this starter application.
6. Restrict access, encrypt evidence storage, minimize personal data, and define retention/deletion procedures.
7. Do not commit real evidence, usernames, URLs, tokens, or case identifiers to Git. The sample data is synthetic.

The manifest is not digitally signed and this tool is not a validated forensic suite. For legal, regulatory, or disciplinary investigations, follow organizational policy and use validated acquisition/analysis procedures.

## Example investigation workflow

1. Create a case directory and preserve original evidence separately.
2. Export relevant artifacts using approved forensic tools.
3. Copy exports into `data/` (or select them in the dashboard).
4. Compute and preserve hashes before analysis.
5. Run analysis and review each flagged event in context.
6. Verify findings against source artifacts and document alternative explanations.
7. Export reports, hash them if required, and record the reviewer and disposition.

## License

For educational use. Add an organizationally approved license before distributing this project.
