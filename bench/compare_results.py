#!/usr/bin/env python3
"""Compare our cipher speeds with OpenSSL's built-in ciphers."""

import argparse
import math
from pathlib import Path

# Compare each PRINCE mode with the same AES mode, and Rabbit with ChaCha20
PAIRS = (
    ("PRINCE-ECB", "AES-128-ECB"),
    ("PRINCE-CBC", "AES-128-CBC"),
    ("PRINCE-CTR", "AES-128-CTR"),
    ("RABBIT", "ChaCha20"),
)


def read_results(path):
    expected = {name for pair in PAIRS for name in pair}
    sizes = []
    rates = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip().startswith("|"):
            continue

        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        name = cells[0]

        if name == "Cipher":
            sizes = cells[2:]
            continue
        if name not in expected:
            continue

        if not sizes or len(cells) != len(sizes) + 2:
            raise ValueError(f"Missing header or incomplete results for {name}")
        if name in rates:
            raise ValueError(f"Duplicate results for {name}")

        # Read the numbers whether or not they have "MB/s" at the end
        values = [
            float(cell.removesuffix("MB/s").strip())
            for cell in cells[2:]
        ]
        if any(not math.isfinite(value) or value <= 0 for value in values):
            raise ValueError(f"Throughput must be finite and positive for {name}")

        rates[name] = values

    # Stop if any cipher is missing, so we don't compare incomplete results
    missing = expected - rates.keys()
    if missing:
        raise ValueError("Missing results: " + ", ".join(sorted(missing)))

    return sizes, rates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results",
        type=Path,
        help="Markdown table from run_bench.sh",
    )
    args = parser.parse_args()

    try:
        sizes, rates = read_results(args.results)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")

    print("# Relative throughput\n")
    print("Custom throughput / baseline throughput x 100. Higher is faster.\n")
    print("100% = equal throughput; 50% = half; 200% = twice.\n")
    print("| Cipher | Baseline | " + " | ".join(sizes) + " |")
    print("|---|---|" + "---:|" * len(sizes))

    for custom, baseline in PAIRS:
        percentages = [
            f"{100 * own / reference:.2f}%"
            for own, reference in zip(rates[custom], rates[baseline])
        ]
        print(f"| {custom} | {baseline} | " + " | ".join(percentages) + " |")

    print("\nRatios use the rounded throughput values in the input table.")


if __name__ == "__main__":
    main()