import argparse
import csv
from collections import Counter
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PROCESSED_FILE = DATA_DIR / "processed.csv"
ORG_FILE = DATA_DIR / "org.txt"
DEFAULT_TOP = 15


def load(processed_file):
    with processed_file.open(newline="") as f:
        return list(csv.DictReader(f))


def pct(n, total):
    return f"{100 * n / total:.2f}%" if total else "0%"


def normalize_org(org):
    """fold punctuation-only variants together"""
    if not org:
        return "(unknown)"
    cleaned = org.replace(",", " ").rstrip(". ").strip()
    return " ".join(cleaned.split())


def build_report(rows, top):
    """build the issuer breakdown as a list of text lines."""
    total = len(rows)
    lines = [f"total certificates analyzed: {total}"]
    if not total:
        return lines

    issuers = Counter(normalize_org(r["issuer_org"]) for r in rows)
    ranked = issuers.most_common()

    lines += ["", f"certificate authorities (by issuer organization) - {len(issuers)} distinct"]
    width = max((len(k) for k, _ in ranked[:top]), default=0)
    for org, n in ranked[:top]:
        lines.append(f"  {org:<{width}}  {n:>5}  ({pct(n, total)})")

    rest = ranked[top:]
    if rest:
        other = sum(n for _, n in rest)
        lines.append(f"  {'(other ' + str(len(rest)) + ' CAs)':<{width}}  {other:>5}  ({pct(other, total)})")

    return lines


def main():
    parser = argparse.ArgumentParser(description="summarize certificate issuers from processed cert data.")
    parser.add_argument("-i", "--input", type=Path, default=PROCESSED_FILE)
    parser.add_argument("-o", "--output", type=Path, default=ORG_FILE,
                        help=f"where to save the report (default: {ORG_FILE})")
    parser.add_argument("-n", "--top", type=int, default=DEFAULT_TOP,
                        help=f"number of CAs to list before rolling the rest into 'other' (default: {DEFAULT_TOP})")
    args = parser.parse_args()

    report = "\n".join(build_report(load(args.input), args.top)) + "\n"
    print(report, end="")
    args.output.write_text(report)
    print(f"\nsaved report to {args.output}")


if __name__ == "__main__":
    main()
