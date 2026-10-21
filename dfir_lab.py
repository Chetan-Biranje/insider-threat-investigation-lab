"""Starter DFIR analyzer for explicitly supplied CSV exports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

import pandas as pd

REQUIRED = {
    "usb_activity.csv": {"timestamp", "device_id", "action", "user", "source"},
    "browser_history.csv": {"timestamp", "url", "title", "user", "source"},
    "file_activity.csv": {"timestamp", "action", "path", "bytes", "destination", "user", "source"},
}
CLOUD_TERMS = ("drive.google.com", "dropbox.com", "onedrive.live.com", "1drv.ms", "box.com")
LARGE_FILE_BYTES = 100 * 1024 * 1024


def sha256_file(path: Path) -> str:
    """Hash a file in streaming chunks without modifying it."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(data_dir: Path) -> dict[str, Any]:
    """Create a manifest for known input files; missing files are noted."""
    entries = []
    for name in REQUIRED:
        path = data_dir / name
        if not path.is_file():
            entries.append({"file": name, "status": "missing"})
            continue
        stat = path.stat()
        entries.append({
            "file": name,
            "status": "hashed",
            "sha256": sha256_file(path),
            "size_bytes": stat.st_size,
        })
    return {
        "manifest_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "hash_algorithm": "SHA-256",
        "scope_note": "Hashes identify file content at hashing time; they do not independently prove authenticity or prior integrity.",
        "files": entries,
    }


def load_csv(data_dir: Path, filename: str) -> pd.DataFrame:
    path = data_dir / filename
    if not path.is_file():
        return pd.DataFrame()
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    missing = REQUIRED[filename] - set(frame.columns)
    if missing:
        raise ValueError(f"{filename} missing required columns: {', '.join(sorted(missing))}")
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame[frame["timestamp"].notna()].copy()
    frame["artifact_type"] = filename.removesuffix(".csv")
    return frame


def collect_events(data_dir: Path) -> pd.DataFrame:
    """Normalize supplied CSV exports to one UTC timeline."""
    frames: list[pd.DataFrame] = []
    for filename in REQUIRED:
        frame = load_csv(data_dir, filename)
        if frame.empty:
            continue
        if filename == "usb_activity.csv":
            frame["event"] = frame["action"].astype(str) + " USB device " + frame["device_id"].astype(str)
            frame["detail"] = frame["source"].astype(str)
        elif filename == "browser_history.csv":
            frame["event"] = "Browser visit: " + frame["url"].astype(str)
            frame["detail"] = frame["title"].astype(str) + " | " + frame["source"].astype(str)
        else:
            frame["event"] = frame["action"].astype(str) + " file: " + frame["path"].astype(str)
            frame["detail"] = (
                "bytes=" + frame["bytes"].astype(str) +
                "; destination=" + frame["destination"].astype(str) +
                "; source=" + frame["source"].astype(str)
            )
            frame["bytes_numeric"] = pd.to_numeric(frame["bytes"], errors="coerce").fillna(0)
        for col in ("user", "source"):
            if col not in frame:
                frame[col] = ""
        frames.append(frame[["timestamp", "artifact_type", "event", "detail", "user", "source"] +
                            (["bytes_numeric"] if "bytes_numeric" in frame.columns else [])])
    if not frames:
        return pd.DataFrame(columns=["timestamp", "artifact_type", "event", "detail", "user", "source", "severity", "reason"])
    events = pd.concat(frames, ignore_index=True, sort=False)
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True, errors="coerce")
    events = events.sort_values("timestamp", kind="stable").reset_index(drop=True)
    events["severity"] = "info"
    events["reason"] = ""
    return events


def add_triage_flags(events: pd.DataFrame) -> pd.DataFrame:
    """Apply transparent, low-confidence triage rules; not a verdict."""
    result = events.copy()
    if result.empty:
        return result
    for idx, row in result.iterrows():
        event = str(row.get("event", "")).lower()
        detail = str(row.get("detail", "")).lower()
        reasons = []
        severity = "info"
        if row.get("artifact_type") == "browser_history" and any(term in event for term in CLOUD_TERMS):
            reasons.append("Cloud-storage domain visited; validate whether access/upload was authorized.")
            severity = "review"
        if row.get("artifact_type") == "file_activity":
            try:
                size = float(row.get("bytes_numeric", 0) or 0)
            except (TypeError, ValueError):
                size = 0
            if size >= LARGE_FILE_BYTES:
                reasons.append("File operation is at least 100 MiB; size alone does not prove exfiltration.")
                severity = "high" if severity != "review" else "high"
            if "upload" in event and any(term in detail for term in CLOUD_TERMS):
                reasons.append("Upload action references a cloud destination; corroborate with network/server logs.")
                severity = "high"
        if row.get("artifact_type") == "usb_activity" and any(term in event for term in ("connected", "file_copy")):
            reasons.append("Removable-media activity; correlate with device inventory and file events.")
            if severity == "info":
                severity = "review"
        result.at[idx, "severity"] = severity
        result.at[idx, "reason"] = " ".join(reasons)
    return result


def analyze(data_dir: Path, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    events = add_triage_flags(collect_events(data_dir))
    export = events.copy()
    if "timestamp" in export:
        export["timestamp"] = export["timestamp"].map(lambda value: value.isoformat() if pd.notna(value) else "")
    timeline_path = output_dir / "timeline.csv"
    export.to_csv(timeline_path, index=False)
    counts = events["severity"].value_counts().to_dict() if not events.empty else {}
    findings = {
        "report_version": 1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "case_label": "SYNTHETIC-TRAINING-CASE",
        "event_count": int(len(events)),
        "severity_counts": {str(k): int(v) for k, v in counts.items()},
        "events_with_triage_flags": int((events["reason"].astype(str).str.len() > 0).sum()) if not events.empty else 0,
        "interpretation": "Triage leads only; validate against original artifacts and independent sources. No finding establishes intent or misconduct.",
        "timeline_csv": str(timeline_path.name),
    }
    (output_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze supplied DFIR CSV exports.")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze_cmd = sub.add_parser("analyze", help="Build a combined timeline and triage summary.")
    analyze_cmd.add_argument("--data-dir", type=Path, default=Path("data"))
    analyze_cmd.add_argument("--output-dir", type=Path, default=Path("reports"))
    hash_cmd = sub.add_parser("hash", help="Hash expected evidence CSVs and write a manifest.")
    hash_cmd.add_argument("--data-dir", type=Path, default=Path("data"))
    hash_cmd.add_argument("--output", type=Path, default=Path("reports/evidence_manifest.json"))
    args = parser.parse_args()
    if args.command == "analyze":
        result = analyze(args.data_dir, args.output_dir)
        print(json.dumps(result, indent=2))
        print(f"Timeline written to: {args.output_dir / 'timeline.csv'}")
    elif args.command == "hash":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        manifest = build_manifest(args.data_dir)
        args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"Manifest written to: {args.output}")
        for entry in manifest["files"]:
            print(f"{entry['status']:7} {entry['file']} {entry.get('sha256', '')}")


if __name__ == "__main__":
    main()
