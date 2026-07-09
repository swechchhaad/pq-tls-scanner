import argparse
import csv
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_SOURCE = DATA_DIR / "top-1m.csv"
DEFAULT_OUTPUT = DATA_DIR / "domains.txt"
DEFAULT_COUNT = 10_000


def extract_domains(source: Path, output: Path, count: int) -> int:
    """read the first `count` rows of a rank,domain CSV and write the domains to `output`."""
    domains = []
    with source.open(newline="") as f:
        for row in csv.reader(f):
            if not row:
                continue
            domain = row[1] if len(row) > 1 else row[0]
            domains.append(domain.strip())
            if len(domains) >= count:
                break

    with output.open("w") as f:
        f.write("\n".join(domains) + "\n")

    return len(domains)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-s", "--source", type=Path, default=DEFAULT_SOURCE,
                        help=f"source CSV (default: {DEFAULT_SOURCE})")
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT,
                        help=f"output file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("-n", "--count", type=int, default=DEFAULT_COUNT,
                        help=f"number of domains to extract (default: {DEFAULT_COUNT})")
    args = parser.parse_args()

    written = extract_domains(args.source, args.output, args.count)
    print(f"Wrote {written} domains to {args.output}")


if __name__ == "__main__":
    main()
