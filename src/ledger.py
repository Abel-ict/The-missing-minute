"""Single-node, educational hash-linked audit ledger with an external logical checkpoint.

Not a decentralized blockchain. A checkpoint stored on the same writable machine
cannot protect against an attacker who can change BOTH the ledger and checkpoint.
"""
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def _digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hash_block(block: dict) -> str:
    return _digest({key: value for key, value in block.items() if key != "hash"})


def make_chain(events: list[dict]) -> list[dict]:
    chain = []
    for i, event in enumerate([{"message": "Genesis block"}, *events]):
        block = {
            "index": i,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "event": copy.deepcopy(event),
            "previous_hash": "0" * 64 if i == 0 else chain[-1]["hash"],
        }
        block["hash"] = _hash_block(block)
        chain.append(block)
    return chain


def make_checkpoint(chain: list[dict]) -> dict:
    return {"last_hash": chain[-1]["hash"], "block_count": len(chain)}


def verify_chain(chain: list[dict], checkpoint: dict) -> tuple[bool, str]:
    if not chain:
        return False, "Ledger is empty."
    for i, block in enumerate(chain):
        if block.get("index") != i:
            return False, f"Block order changed at position {i}."
        expected_previous = "0" * 64 if i == 0 else chain[i - 1].get("hash")
        if block.get("previous_hash") != expected_previous:
            return False, f"Broken link at block {i}."
        if block.get("hash") != _hash_block(block):
            return False, f"Content of block {i} has changed."
    if len(chain) != checkpoint.get("block_count"):
        return False, "Block count differs from the trusted checkpoint (possible deletion)."
    if chain[-1]["hash"] != checkpoint.get("last_hash"):
        return False, "Ledger does not match the saved checkpoint (possible rewrite)."
    return True, "Ledger intact: hashes, links, and checkpoint match."


def save_chain(chain: list[dict], ledger_path: Path, checkpoint_path: Path) -> None:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(json.dumps(chain, indent=2), encoding="utf-8")
    checkpoint_path.write_text(json.dumps(make_checkpoint(chain), indent=2), encoding="utf-8")


def read_chain(ledger_path: Path, checkpoint_path: Path) -> tuple[list[dict], dict]:
    return (json.loads(ledger_path.read_text(encoding="utf-8")),
            json.loads(checkpoint_path.read_text(encoding="utf-8")))


def simulate_tampering(chain: list[dict], attack_type: str) -> list[dict]:
    """Manipulate an in-memory COPY, never the saved original."""
    if len(chain) < 2:
        raise ValueError("Seal one or more events first.")
    altered = copy.deepcopy(chain)
    if attack_type == "Change a recorded event":
        altered[1]["event"]["username"] = "modified_by_intruder"
    elif attack_type == "Delete a recorded event":
        altered.pop(1)
    elif attack_type == "Rewrite all hashes":
        altered[1]["event"]["username"] = "modified_by_intruder"
        for i, block in enumerate(altered):
            block["index"] = i
            block["previous_hash"] = "0" * 64 if i == 0 else altered[i-1]["hash"]
            block["hash"] = _hash_block(block)
    else:
        raise ValueError("Unknown tampering scenario")
    return altered
