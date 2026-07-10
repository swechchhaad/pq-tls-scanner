import argparse
import csv
from collections import Counter
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PROCESSED_FILE = DATA_DIR / "processed.csv"
STATS_FILE = DATA_DIR / "stats.txt"


def load(processed_file):
    with processed_file.open(newline="") as f:
        return list(csv.DictReader(f))


def pct(n, total):
    return f"{100 * n / total:.2f}%" if total else "0%"


def table_lines(title, counter, total):
    lines = ["", title]
    width = max((len(str(k)) for k in counter), default=0)
    for key, n in counter.most_common():
        lines.append(f"  {str(key):<{width}}  {n:>6}  ({pct(n, total)})")
    return lines


def build_report(rows):
    """build the analysis as a list of text lines"""
    total = len(rows)
    lines = [f"total certificates analyzed: {total}"]
    if not total:
        return lines

    # post-quantum adoption
    families = Counter(r["key_family"] for r in rows)
    pq = families.get("post-quantum", 0)
    classical = families.get("classical", 0)

    # signature algorithms that are post-quantum (ML-DSA / SLH-DSA / Falcon)
    pq_sig_markers = ("ml-dsa", "mldsa", "slh-dsa", "slhdsa", "dilithium", "falcon", "sphincs")
    pq_sigs = sum(
        1 for r in rows if any(m in r["signature_algorithm"].lower() for m in pq_sig_markers)
    )
    vulnerable = sum(1 for r in rows if r["quantum_vulnerable"] == "True")

    lines += [
        "",
        "post-quantum readiness",
        f"  post-quantum public keys: {pq:>6}  ({pct(pq, total)})",
        f"  classical public keys:    {classical:>6}  ({pct(classical, total)})",
        f"  post-quantum signatures:  {pq_sigs:>6}  ({pct(pq_sigs, total)})",
        "",
        f"  quantum-vulnerable certs: {vulnerable:>6}  ({pct(vulnerable, total)})",
    ]

    algs = Counter(
        f"{r['public_key_algorithm']}-{r['public_key_size']}" if r["public_key_size"]
        else r["public_key_algorithm"]
        for r in rows
    )
    lines += table_lines("public-key algorithms", algs, total)
    lines += table_lines("signature algorithms",
                         Counter(r["signature_algorithm"] for r in rows), total)
    return lines


def main():
    parser = argparse.ArgumentParser(description="summarize PQ adoption from processed cert data.")
    parser.add_argument("-i", "--input", type=Path, default=PROCESSED_FILE)
    parser.add_argument("-o", "--output", type=Path, default=STATS_FILE,
                        help=f"where to save the report (default: {STATS_FILE})")
    args = parser.parse_args()

    report = "\n".join(build_report(load(args.input))) + "\n"
    print(report, end="")
    args.output.write_text(report)
    print(f"\nsaved report to {args.output}")


if __name__ == "__main__":
    main()
