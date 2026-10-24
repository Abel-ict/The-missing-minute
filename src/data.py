"""Create clearly marked SYNTHETIC security logs for a reproducible demo."""
from pathlib import Path
import numpy as np
import pandas as pd

FEATURES = ["failed_logins", "requests_per_minute", "bytes_transferred", "off_hours", "sensitive_action"]


def generate_logs(normal_count: int = 1200, attack_count: int = 40, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    entries = []
    base = pd.Timestamp("2026-10-20 00:00:00")

    for i in range(normal_count):
        hour = int(rng.choice(np.arange(24), p=np.array([0.006]*6 + [0.025]*2 + [0.073]*10 + [0.045]*3 + [0.02]*3) / (6*.006+2*.025+10*.073+3*.045+3*.02)))
        time = base + pd.Timedelta(days=int(rng.integers(0, 3)), hours=hour, minutes=int(rng.integers(0, 60)))
        action = str(rng.choice(["login_success", "file_view", "login_failed", "admin_action"], p=[0.58, 0.30, 0.10, 0.02]))
        entries.append({
            "timestamp": time, "username": f"user_{int(rng.integers(1, 61)):02d}",
            "ip_address": f"10.10.{int(rng.integers(0, 10))}.{int(rng.integers(2, 245))}",
            "action": action, "failed_logins": int(rng.poisson(0.4)),
            "requests_per_minute": int(max(1, rng.normal(11, 4))),
            "bytes_transferred": int(max(100, rng.lognormal(9.3, 0.65))),
            "off_hours": int(hour < 6 or hour >= 22), "sensitive_action": int(action == "admin_action"),
            "injected_attack": 0,
        })

    for i in range(attack_count):
        hour = int(rng.choice([0, 1, 2, 3, 4, 23]))
        time = base + pd.Timedelta(days=int(rng.integers(0, 3)), hours=hour, minutes=int(rng.integers(0, 60)))
        entries.append({
            "timestamp": time, "username": f"target_{int(rng.integers(1, 9)):02d}",
            "ip_address": f"172.16.{int(rng.integers(1, 9))}.{int(rng.integers(2, 245))}",
            "action": str(rng.choice(["login_failed", "admin_action", "bulk_file_read"])),
            "failed_logins": int(rng.integers(7, 32)),
            "requests_per_minute": int(rng.integers(80, 300)),
            "bytes_transferred": int(rng.integers(600000, 8000000)),
            "off_hours": 1, "sensitive_action": 1,
            "injected_attack": 1,
        })

    df = pd.DataFrame(entries).sort_values("timestamp").reset_index(drop=True)
    df.insert(0, "event_id", [f"EVT-{i:05d}" for i in range(1, len(df) + 1)])
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return df


def load_or_create(path: Path) -> pd.DataFrame:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        generate_logs().to_csv(path, index=False)
    return pd.read_csv(path)
