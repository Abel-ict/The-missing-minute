# 🛡️ The Missing Minute
### Intelligent Cybersecurity Anomaly Detection & Tamper-Evident Audit Logging

> **Detect suspicious activity. Protect the evidence. Reveal tampering.**

A solo, educational cybersecurity prototype made for the INSA Cyber Talent project. It combines **Machine Learning** (unsupervised anomaly detection) with **blockchain concepts** (a hash-linked evidence ledger), using fictional security logs.

## The problem

Security incidents can involve both unusual system activity and attempts to change or delete the records investigators rely on. Traditional anomaly detection doesn't itself prove that stored evidence has remained unchanged.

## The proposed solution

1. Generate **synthetic** university-style server activity logs.
2. Use **Isolation Forest** to rank unusual events based on login failures, request rate, data transferred, off-hours access, and sensitive actions.
3. Select and **seal** suspicious events into a simple SHA-256 hash-linked audit ledger.
4. **Verify** that the ledger's blocks match one another and a separately stored checkpoint (last hash + count).
5. Demonstrate detection of **event modification, deletion, and rewriting of block hashes**.

## Architecture

```text
Synthetic security logs (CSV)
           |
      Pandas features
           |
Isolation Forest (scikit-learn)
           |
      Anomaly results -------> Streamlit dashboard
           |
     Seal selected events
           |
SHA-256 hash-linked ledger ---> checkpoint (stored separately from ledger file)
           |
    Tamper simulation -------> Verification alert in dashboard
```

## Tech stack

- **Python 3.10+** — implementation language
- **Scikit-learn** — Isolation Forest ML algorithm
- **Pandas and NumPy** — sample data and processing
- **SHA-256 (`hashlib`)** — tamper-evident block hashes
- **Streamlit** — interactive dashboard

This is an **ML + blockchain-concepts** project. It does **not** claim to process genuine Big Data, use a decentralized blockchain, or run a real-world IDS.

## How to run on Ubuntu

From a terminal opened in this project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

If Ubuntu says `ensurepip is not available`, install `python3-venv` using Ubuntu's package manager, then try again. Streamlit will display a local URL such as `http://localhost:8501`.

## 2-minute demonstration

1. Open **Analyze logs**. Show anomalies and emphasize that the data is simulated.
2. Open **Seal evidence**, click **Seal flagged events into the audit ledger**, and show its verified fingerprint.
3. Open **Tampering demo** and try `Change a recorded event`; the hash integrity check must fail.
4. Try `Delete a recorded event`; an integrity or checkpoint mismatch is reported.
5. Try `Rewrite all hashes`; the block hashes now fit each other, but fail the **saved checkpoint** check.

The simulation changes a **copy** of the ledger; the authentic stored ledger is never deliberately corrupted.

## Automated tests

```bash
python -m unittest discover -s tests -v
```

## Repository structure

```text
app.py                 Streamlit UI
src/data.py            Fictional log generation
src/detector.py        Unsupervised ML detection
src/ledger.py          SHA-256 chain and checkpoint verification
tests/test_ledger.py   Five integrity tests
requirements.txt       Required dependencies
.streamlit/config.toml Dashboard theme
data/synthetic_logs.csv Sample fictional logs
README.md              This guide
```

`data/ledger.json` and `trusted_checkpoint.json` are created when you seal evidence. If a checkpoint is retained *only* on the same machine, it is not sufficiently protected against a fully privileged attacker.

## What it can and cannot prove

- **An anomaly isn't automatically an attack.** The model is trained on generated logs; its output is a ranking of unusual observations, not real intrusion detection accuracy.
- **Hash integrity is not absolute security.** A chain of hashes alone doesn't stop a malicious actor rewriting the whole chain. Verification against an independently trusted checkpoint can expose that rewrite. This prototype's checkpoint is only a separate local file; real deployment would need a secure external anchor, signatures, access controls, or append-only offsite records.
- **Not a decentralized blockchain.** There is no consensus protocol, peer-to-peer network, or smart contract here. It's a single-node simulation of blockchain-style linking for learning purposes.
- **No log recovery.** A deletion is detectable only for evidence previously registered or otherwise accounted for; evidence never received cannot be reconstructed.

## Future improvements

Collect permitted real-world logs, evaluate model precision/recall against a properly labeled dataset, move checkpoint hashes to an independently trusted service, add role-based access and signatures, and introduce Spark-based processing for genuinely larger workloads.

## Ethical use

Only generated data is included. No attacks on real systems, real user data, or live monitoring are required.
