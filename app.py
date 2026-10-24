"""The Missing Minute — Streamlit demo. Run: streamlit run app.py"""
from pathlib import Path
import pandas as pd
import streamlit as st
from src.data import generate_logs, load_or_create
from src.detector import detect_anomalies
from src.ledger import make_chain, save_chain, read_chain, verify_chain, simulate_tampering

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "synthetic_logs.csv"
LEDGER = ROOT / "data" / "ledger.json"
CHECKPOINT = ROOT / "trusted_checkpoint.json"

st.set_page_config(page_title="The Missing Minute", page_icon="🛡️", layout="wide")
st.title("🛡️ The Missing Minute")
st.caption("Detect suspicious activity. Preserve the evidence. Reveal tampering. | INSA learning project")
st.info("**Demo uses entirely synthetic security logs.** The blockchain is educational, not decentralized or production-secure.")

with st.sidebar:
    st.header("Project controls")
    contamination = st.slider("Expected anomaly fraction", min_value=0.01, max_value=0.15, value=0.05, step=0.01)
    if st.button("Reset synthetic dataset", width="stretch"):
        generate_logs().to_csv(DATA, index=False)
        st.success("Synthetic logs regenerated. Ledger (if any) was not changed.")
    st.caption("Model: Isolation Forest · Evidence: SHA-256 hash-linked blocks")

try:
    df = load_or_create(DATA)
    predictions = detect_anomalies(df, contamination)
except Exception as exc:
    st.error(f"Data/model error: {exc}")
    st.stop()

flagged = predictions[predictions["anomaly"]]
metric1, metric2, metric3 = st.columns(3)
metric1.metric("Synthetic events analyzed", len(predictions))
metric2.metric("Events flagged by ML", len(flagged))
metric3.metric("Intentionally injected attacks", int(df["injected_attack"].sum()))

tab1, tab2, tab3, tab4 = st.tabs(["🔎 Analyze logs", "🔗 Seal evidence", "🚨 Tampering demo", "ℹ️ About"])

with tab1:
    st.subheader("Which events look unusual?")
    st.write("Isolation Forest learns feature patterns without using the `injected_attack` column. Lower anomaly scores indicate more unusual behavior, not attack probabilities.")
    chart = predictions.copy()
    chart["hour"] = pd.to_datetime(chart["timestamp"]).dt.hour
    counts = chart.groupby("hour").agg(total_events=("event_id", "count"), flagged_events=("anomaly", "sum"))
    st.bar_chart(counts[["total_events", "flagged_events"]])
    display_columns = ["event_id", "timestamp", "username", "ip_address", "action", "failed_logins", "requests_per_minute", "anomaly_score", "anomaly", "injected_attack"]
    st.dataframe(predictions[display_columns].head(150), hide_index=True, width="stretch")
    st.download_button("Download analyzed logs (CSV)", predictions.to_csv(index=False).encode(), "analyzed_security_logs.csv", "text/csv")

with tab2:
    st.subheader("Register suspicious events as evidence")
    st.write("A SHA-256 fingerprint is saved for every block. Each block also references the previous hash. A separate checkpoint records the final hash and block count.")
    event_count = st.slider("How many highest-ranked anomalies to seal?", 1, min(25, len(flagged)), min(10, len(flagged)))
    if st.button("🔐 Seal flagged events into the audit ledger", type="primary"):
        selected = flagged.head(event_count)[["event_id", "timestamp", "username", "ip_address", "action", "anomaly_score"]]
        records = selected.to_dict(orient="records")
        chain = make_chain(records)
        save_chain(chain, LEDGER, CHECKPOINT)
        st.success(f"Saved {len(records)} events in {len(chain)} hash-linked blocks, including genesis.")
    if LEDGER.exists() and CHECKPOINT.exists():
        try:
            chain, checkpoint = read_chain(LEDGER, CHECKPOINT)
            ok, reason = verify_chain(chain, checkpoint)
            (st.success if ok else st.error)(reason)
            st.code(f"Trusted checkpoint final SHA-256:\n{checkpoint['last_hash']}")
            st.caption("This checkpoint is local for demonstration. Real trust requires preserving it outside an attacker's control.")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            st.error(f"Unable to verify saved ledger: {exc}")
    else:
        st.info("Click 'Seal flagged events' first.")

with tab3:
    st.subheader("What happens if someone changes the evidence?")
    if not (LEDGER.exists() and CHECKPOINT.exists()):
        st.warning("First go to 'Seal evidence' and click the seal button.")
    else:
        try:
            original, checkpoint = read_chain(LEDGER, CHECKPOINT)
            ok_before, reason_before = verify_chain(original, checkpoint)
            st.write(f"**Original evidence:** {'✅ Verified' if ok_before else '❌ Invalid'} — {reason_before}")
            choice = st.radio("Choose a simulated attack", ["Change a recorded event", "Delete a recorded event", "Rewrite all hashes"])
            if st.button("🚨 Simulate tampering"):
                altered = simulate_tampering(original, choice)
                ok_after, reason_after = verify_chain(altered, checkpoint)
                if ok_after:
                    st.error("Unexpectedly passed verification. Please investigate.")
                else:
                    st.error(f"TAMPERING DETECTED — {reason_after}")
                st.write("**Your saved original ledger was not modified.** The attack was simulated on a copy.")
                with st.expander("See original vs altered event"):
                    st.json({"original_event": original[1]["event"], "altered_first_event": altered[1]["event"] if len(altered) > 1 else None})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            st.error(f"Could not run the demonstration: {exc}")

with tab4:
    st.markdown("""### What this prototype demonstrates
    - **ML:** Isolation Forest flags unusual security events in synthetic data.
    - **Blockchain concepts:** SHA-256 fingerprints and hash links form a single-node educational ledger.
    - **Tampering test:** changing, deleting, or fully rehashing evidence fails verification against a saved checkpoint.

    ### Important limitations
    - An anomaly is **not proof of an attack**; this is not a real-time intrusion prevention system.
    - The simulated data should not be treated as evidence of real-world model accuracy.
    - The ledger is **not decentralized**. A local checkpoint can be altered by an attacker with full access; a real deployment needs an independently trusted, access-controlled or externally published checkpoint.
    - Events deleted **before they are registered** cannot be reconstructed by this application.
    - **Big Data is not claimed:** this prototype handles a small dataset with Pandas, not a distributed production workload.
    """)
