from pathlib import Path
import tempfile

import pandas as pd
import streamlit as st

from dfir_lab import add_triage_flags, build_manifest, collect_events

ROOT = Path(__file__).parent
DATA = ROOT / "data"

st.set_page_config(page_title="Insider Threat DFIR Lab", page_icon="🔎", layout="wide")
st.title("🔎 Insider Threat Investigation Lab")
st.caption("Educational DFIR triage dashboard • analyze authorized exports only")

st.warning(
    "Triage leads are not proof of misconduct. This app does not collect endpoint data. "
    "Do not upload real evidence to a shared or publicly exposed instance."
)

with st.sidebar:
    st.header("Investigation scope")
    st.write("Default source: bundled synthetic CSV exports.")
    st.write("Timestamp display: UTC")
    st.write("Large file triage threshold: 100 MiB")
    st.subheader("Evidence integrity")
    if st.button("Hash bundled input files"):
        manifest = build_manifest(DATA)
        st.json(manifest)
        st.download_button(
            "Download SHA-256 manifest",
            data=__import__("json").dumps(manifest, indent=2),
            file_name="evidence_manifest.json",
            mime="application/json",
        )

st.subheader("Optional: analyze a supplied CSV export")
uploaded = st.file_uploader(
    "Upload one combined CSV containing normalized events (optional)",
    type=["csv"],
    help="Expected columns: timestamp, artifact_type, event, detail, user, source. Files are processed in this app session; use only authorized data.",
)
if uploaded:
    try:
        df = pd.read_csv(uploaded, dtype=str, keep_default_na=False)
        required = {"timestamp", "artifact_type", "event", "detail", "user", "source"}
        missing = required - set(df.columns)
        if missing:
            st.error("Missing columns: " + ", ".join(sorted(missing)))
        else:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
            df = df[df["timestamp"].notna()].copy()
            if "bytes_numeric" not in df.columns:
                df["bytes_numeric"] = 0
            events = add_triage_flags(df)
            st.session_state["events"] = events
    except Exception as exc:
        st.error(f"Could not parse CSV: {exc}")
else:
    st.session_state["events"] = add_triage_flags(collect_events(DATA))

events = st.session_state.get("events", pd.DataFrame())
if events.empty:
    st.info("No valid events found. Check that CSV files exist and timestamps are parseable.")
    st.stop()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events", len(events))
c2.metric("High triage", int((events["severity"] == "high").sum()))
c3.metric("Review", int((events["severity"] == "review").sum()))
c4.metric("Flagged events", int((events["reason"].astype(str).str.len() > 0).sum()))

st.subheader("Event timeline")
filtered = events.copy()
severity_options = ["info", "review", "high"]
selected = st.multiselect("Severity", severity_options, default=severity_options)
filtered = filtered[filtered["severity"].isin(selected)]
if "artifact_type" in filtered:
    types = sorted(filtered["artifact_type"].dropna().astype(str).unique())
    selected_types = st.multiselect("Artifact type", types, default=types)
    filtered = filtered[filtered["artifact_type"].isin(selected_types)]

display = filtered.copy()
display["timestamp"] = display["timestamp"].map(lambda x: x.isoformat() if pd.notna(x) else "")
st.dataframe(display, use_container_width=True, hide_index=True)

st.subheader("Investigation leads")
leads = filtered[filtered["reason"].astype(str).str.len() > 0]
if leads.empty:
    st.write("No triage rules fired for the selected filters.")
else:
    st.dataframe(leads[["timestamp", "severity", "artifact_type", "event", "reason", "source"]], use_container_width=True, hide_index=True)

st.download_button(
    "Export filtered timeline CSV",
    data=display.to_csv(index=False).encode("utf-8"),
    file_name="filtered_timeline.csv",
    mime="text/csv",
)
st.caption("Preserve original evidence separately, document acquisition and chain of custody, and corroborate every lead with independent artifacts.")
