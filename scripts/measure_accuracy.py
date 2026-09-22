#!/usr/bin/env python3
"""Offline detector accuracy against labelled samples.

Why this exists: **online, there is no ground truth.** Nothing tells a running
system whether a flagged anomaly was a real attack, so "model accuracy" cannot
be a live metric. What a live system can watch are proxy signals -- LLM refusal
rate, fallback rate, score distribution drift -- and those are in /api/metrics.

Real accuracy is measurable offline, here, because the sample generator seeds
known attacks. That makes these files a labelled dataset.

    python3 scripts/measure_accuracy.py

Exits non-zero if accuracy regresses, so it can run in CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "worker"))

from tests.fixtures import load_sample            # noqa: E402
from worker.detection import detect_all           # noqa: E402

# Ground truth: what scripts/generate_samples.py seeds, and the entity each
# detector should name. Keep in step with the generator.
EXPECTED_ATTACKS = {
    "volume_spike":     {"entity": "10.12.4.102",             "attack": "600 requests in 3 minutes (enumeration)"},
    "data_exfil":       {"entity": "files.dropzone-sync.ru",  "attack": "~240MB uploaded in 12 chunks"},
    "beaconing":        {"entity": "cdn-telemetry-sync.net",  "attack": "60s check-in for 5 hours (C2)"},
    "blocked_threat":   {"entity": "malware-delivery.tk",     "attack": "Emotet + O365 phish, proxy-blocked"},
    "rare_destination": {"entity": "paste-anon-share.onion.ly", "attack": "single visit, one user"},
    "off_hours":        {"entity": "d.kim",                   "attack": "CRM export at 03:00"},
}

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def analyse(path: Path):
    entries = load_sample(path)
    return entries, detect_all(entries)


IDENTIFYING_FIELDS = ("host", "client_ip", "actor", "username", "threat_name")


def entity_of(candidate) -> str:
    """The most descriptive entity to display. Host first -- a domain says more
    to a reader than an internal IP."""
    for key in IDENTIFYING_FIELDS:
        if candidate.evidence.get(key):
            return str(candidate.evidence[key])
    return candidate.title


def entities_of(candidate) -> set[str]:
    """Every identifying value in the evidence.

    Matching against all of them, not just the displayed one: a beaconing
    candidate names both the client IP and the destination host, and either is
    a correct identification of the same attack.
    """
    found = {str(candidate.evidence[k]) for k in IDENTIFYING_FIELDS
             if candidate.evidence.get(k)}
    for key in ("hosts", "users", "source_ips", "urls"):
        value = candidate.evidence.get(key)
        if isinstance(value, (list, tuple, set)):
            found.update(str(v) for v in value)
    return found


def main() -> int:
    suspicious = ROOT / "samples" / "zscaler_suspicious.log"
    benign = ROOT / "samples" / "zscaler_benign.log"

    for path in (suspicious, benign):
        if not path.exists():
            print(f"{RED}missing {path}{RESET} -- run scripts/generate_samples.py")
            return 2

    print("\n\033[1mDetector accuracy against labelled samples\033[0m")

    # --- recall: seeded attacks found -------------------------------------
    entries, candidates = analyse(suspicious)
    found = {}
    for c in candidates:
        found.setdefault(c.kind, []).append(c)

    print(f"\n{DIM}{suspicious.name}: {len(entries)} entries, "
          f"{len(candidates)} candidates{RESET}\n")

    detected = 0
    for kind, truth in EXPECTED_ATTACKS.items():
        hits = found.get(kind, [])
        if not hits:
            print(f"  {RED}MISS{RESET}  {kind:<18} {DIM}{truth['attack']}{RESET}")
            continue

        detected += 1
        best = max(hits, key=lambda c: c.score)
        entities = set().union(*(entities_of(c) for c in hits))
        # A seeded attack often surfaces as several candidates; any of them
        # naming the right entity counts as identifying it.
        named = any(truth["entity"] in e or e in truth["entity"] for e in entities)
        mark = f"{GREEN}FOUND{RESET}" if named else f"{YELLOW}FOUND{RESET}"
        print(f"  {mark} {kind:<18} conf={best.score:.2f}  {entity_of(best)}")
        if not named:
            print(f"        {YELLOW}expected to name {truth['entity']}{RESET}")

    recall = detected / len(EXPECTED_ATTACKS)

    # --- precision: false positives on clean traffic ----------------------
    benign_entries, benign_candidates = analyse(benign)
    print(f"\n{DIM}{benign.name}: {len(benign_entries)} entries{RESET}\n")
    if benign_candidates:
        for c in benign_candidates:
            print(f"  {RED}FALSE POSITIVE{RESET}  {c.kind:<18} conf={c.score:.2f}  {entity_of(c)}")
    else:
        print(f"  {GREEN}clean{RESET} -- no findings on benign traffic")

    # Attack classes are the unit: one seeded attack produces several
    # corroborating candidates, so counting candidates would understate
    # precision for doing exactly what it should.
    true_positives = detected
    false_positives = len({c.kind for c in benign_candidates})
    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) else 0.0
    )
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("\n\033[1m  Summary\033[0m")
    print(f"    recall    {recall:.0%}   ({detected}/{len(EXPECTED_ATTACKS)} attack classes)")
    print(f"    precision {precision:.0%}   ({false_positives} false-positive classes on benign)")
    print(f"    F1        {f1:.2f}")

    ok = recall == 1.0 and false_positives == 0
    print(f"\n  {GREEN}PASS{RESET}\n" if ok else f"\n  {RED}FAIL{RESET} -- accuracy regressed\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
