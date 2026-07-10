import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.certificate_parser import parse_b64

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RAW_FILE = DATA_DIR / "raw.csv"
PROCESSED_FILE = DATA_DIR / "processed.csv"

FIELDS = [
    "domain",
    "subject_cn",
    "issuer_cn",
    "issuer_org",
    "public_key_algorithm",
    "public_key_oid",
    "public_key_size",
    "key_family",
    "quantum_vulnerable",
    "signature_algorithm",
    "not_valid_before",
    "not_valid_after",
]


def process(raw_file, processed_file):
    """Read raw scan rows, keep the successful ones, and detect each cert's
    public-key algorithm. Returns (written, skipped, unparseable)."""
    written = skipped = unparseable = 0

    with raw_file.open(newline="") as fin, processed_file.open("w", newline="") as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=FIELDS)
        writer.writeheader()

        for row in reader:
            # cleanup: drop rows that failed to scan or have no cert
            if row.get("status") != "ok" or not row.get("cert_der_b64"):
                skipped += 1
                continue

            try:
                info = parse_b64(row["cert_der_b64"])
            except Exception as e:
                print(f"unparseable  {row['domain']}: {e}")
                unparseable += 1
                continue

            info["domain"] = row["domain"]
            writer.writerow(info)
            written += 1

    return written, skipped, unparseable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--input", type=Path, default=RAW_FILE)
    parser.add_argument("-o", "--output", type=Path, default=PROCESSED_FILE)
    args = parser.parse_args()

    written, skipped, unparseable = process(args.input, args.output)
    print(f"\nwrote {written} certs, skipped {skipped} failed scans, "
          f"{unparseable} unparseable -> {args.output}")


if __name__ == "__main__":
    main()
