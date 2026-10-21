from pathlib import Path
import hashlib
import pandas as pd

from dfir_lab import add_triage_flags, build_manifest, collect_events, sha256_file


def test_sha256_file(tmp_path: Path):
    sample = tmp_path / "evidence.bin"
    sample.write_bytes(b"forensic-test")
    assert sha256_file(sample) == hashlib.sha256(b"forensic-test").hexdigest()


def test_manifest_hashes_expected_files(tmp_path: Path):
    for name in ("usb_activity.csv", "browser_history.csv", "file_activity.csv"):
        (tmp_path / name).write_text("timestamp,placeholder\n", encoding="utf-8")
    manifest = build_manifest(tmp_path)
    assert manifest["hash_algorithm"] == "SHA-256"
    assert len(manifest["files"]) == 3
    assert all(entry["status"] == "hashed" for entry in manifest["files"])


def test_sample_data_builds_sorted_timeline():
    data_dir = Path(__file__).parents[1] / "data"
    events = collect_events(data_dir)
    assert len(events) > 0
    assert events["timestamp"].is_monotonic_increasing


def test_cloud_upload_and_large_file_are_flagged():
    df = pd.DataFrame([{
        "timestamp": pd.Timestamp("2026-01-01T00:00:00Z"),
        "artifact_type": "file_activity",
        "event": "upload file: C:/temp/archive.zip",
        "detail": "bytes=209715200; destination=dropbox.com; source=edr.csv",
        "user": "synthetic-user",
        "source": "edr.csv",
        "bytes_numeric": 209715200,
        "severity": "info",
        "reason": "",
    }])
    result = add_triage_flags(df)
    assert result.iloc[0]["severity"] == "high"
    assert "cloud destination" in result.iloc[0]["reason"]
