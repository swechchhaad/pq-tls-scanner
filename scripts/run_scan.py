import argparse
import base64
import csv
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.tls_scanner import get_certificate

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DOMAINS_FILE = DATA_DIR / "domains.txt"
OUTPUT_FILE = DATA_DIR / "raw.csv"
DEFAULT_WORKERS = 100


def read_domains(path):
    with path.open() as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def scan_one(domain):
    """fetch one certificate. returns a CSV row"""
    try:
        cert = get_certificate(domain)
        cert_b64 = base64.b64encode(cert["der"]).decode("ascii")
        return [domain, "ok", cert_b64]
    except Exception as e:
        return [domain, f"error: {e}", ""]


def scan(domains, output, workers=DEFAULT_WORKERS):
    """fetch every domain's certificate concurrently and write the rows to `output`"""
    total = len(domains)
    done = 0
    ok = 0
    write_lock = threading.Lock()

    with output.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "status", "cert_der_b64"])

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(scan_one, d): d for d in domains}
            for future in as_completed(futures):
                row = future.result()
                with write_lock:
                    writer.writerow(row)
                done += 1
                if row[1] == "ok":
                    ok += 1
                if done % 100 == 0 or done == total:
                    print(f"{done}/{total} scanned ({ok} ok)", flush=True)

    return ok, total


def main():
    parser = argparse.ArgumentParser(description="scan domains and dump raw certificates to CSV")
    parser.add_argument("-i", "--input", type=Path, default=DOMAINS_FILE,
                        help=f"domains list (default: {DOMAINS_FILE})")
    parser.add_argument("-o", "--output", type=Path, default=OUTPUT_FILE,
                        help=f"output CSV (default: {OUTPUT_FILE})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"concurrent connections (default: {DEFAULT_WORKERS})")
    args = parser.parse_args()

    domains = read_domains(args.input)
    ok, total = scan(domains, args.output, args.workers)
    print(f"\nscanned {total} domains ({ok} ok) = {args.output}")


if __name__ == "__main__":
    main()
