"""Measure replay checks against a populated gateway ledger (no network traffic)."""

import argparse
import json
import platform
import statistics
import time

from rea_aegis import __version__
from rea_aegis.gateway import RequestGuard


def measure(records=10_000, probes=2_000, repeats=5):
    guard = RequestGuard(capacity=records)
    started = time.perf_counter()
    for index in range(records):
        assert guard.claim(str(index), "nonce", 3600, 0)
    fill_seconds = time.perf_counter() - started
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        for index in range(probes):
            assert not guard.claim(str(index % records), "nonce", 3600, 1)
        samples.append(time.perf_counter() - started)
    return {
        "tool_version": __version__,
        "python": platform.python_version(),
        "platform": platform.system(),
        "records": records,
        "replay_probes_per_sample": probes,
        "fill_seconds": fill_seconds,
        "samples_seconds": samples,
        "median_probe_seconds": statistics.median(samples) / probes,
        "scope": "In-process replay rejection with live records; excludes HTTP, crypto and handler execution",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=10_000)
    parser.add_argument("--probes", type=int, default=2_000)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if min(args.records, args.probes, args.repeats) < 1:
        parser.error("All benchmark sizes must be positive")
    print(json.dumps(measure(args.records, args.probes, args.repeats), indent=2))


if __name__ == "__main__":
    main()
