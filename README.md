# pq-tls-scanner

Measures post-quantum cryptography adoption in the TLS certificates served
by the most popular domains on the web. The scanner connects to each domain,
fetches its leaf certificate, and classifies the public-key and signature
algorithms as classical or post-quantum
(ML-DSA / SLH-DSA / ML-KEM, per NIST FIPS 203/204/205).

## Results — 2026-07-10

Scan of the **top 10,000 domains** from the [Tranco list](https://tranco-list.eu/list/46XZX)
generated on 08 July 2026. Certificates were fetched, parsed, and classified;
**7,811** domains returned a parseable leaf certificate.

### Post-quantum readiness

| Metric | Count | Share |
|---|---:|---:|
| Post-quantum public keys | 0 | 0.00% |
| Classical public keys | 7,811 | 100.00% |
| Post-quantum signatures | 0 | 0.00% |
| **Quantum-vulnerable certs** | **7,811** | **100.00%** |

Not a single certificate in the sample used a post-quantum public key or
signature.

### Public-key algorithms

| Algorithm | Count | Share |
|---|---:|---:|
| RSA-2048 | 4,373 | 55.99% |
| ECDSA-256 | 3,039 | 38.91% |
| RSA-4096 | 324 | 4.15% |
| ECDSA-384 | 44 | 0.56% |
| RSA-3072 | 29 | 0.37% |
| GOST2012-256 | 1 | 0.01% |
| RSA-1024 | 1 | 0.01% |

### Signature algorithms

| Algorithm | Count | Share |
|---|---:|---:|
| sha256WithRSAEncryption | 4,773 | 61.11% |
| ecdsa-with-SHA256 | 1,992 | 25.50% |
| ecdsa-with-SHA384 | 978 | 12.52% |
| sha384WithRSAEncryption | 63 | 0.81% |
| sha512WithRSAEncryption | 3 | 0.04% |
| GOST R 34.10-2012 w/ 34.11-2012 (256-bit) | 1 | 0.01% |
| sha1WithRSAEncryption | 1 | 0.01% |

## How to reproduce the numbers

The pipeline runs in four steps: get a domain list → extract the top N →
scan certificates → parse them → summarize. Generated data files
(`data/*.csv`, `data/domains.txt`) are git-ignored and rebuilt by these
scripts.

### 1. Set up

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # cryptography>=42.0
```

### 2. Get a domain list

The 2026-07-10 results use the [Tranco list](https://tranco-list.eu/list/46XZX)
generated on 08 July 2026 (list ID `46XZX`) — a `rank,domain` CSV. Download it
and save it as `data/top-1m.csv`:

```bash
# the exact list used for the results above
curl -L 'https://tranco-list.eu/download/46XZX/1000000' -o data/top-1m.csv
```

Any other `rank,domain` CSV works as well.

Then extract the top 10,000 (or more) domains:

```bash
python scripts/download_domains.py -n 10000
# data/domains.txt (10,000 domains)
```

### 3. Scan certificates

Connects to each domain on port 443 over TLS (100 workers by default) and
stores the base64-encoded DER leaf certificate:

```bash
python scripts/run_scan.py
# data/raw.csv  (one row per domain: domain, status, cert_der_b64)
```

Certificate verification is intentionally disabled during the scan so that
expired/misconfigured certs are still captured; validity is not the property
being measured. Results depend on live network conditions, so exact counts
will vary slightly from run to run.

### 4. Parse and classify

Decodes each successful certificate and detects its public-key algorithm
(from the SubjectPublicKeyInfo OID) and signature algorithm:

```bash
python scripts/process_certs.py
# data/processed.csv
```

### 5. Summarize

```bash
python scripts/analyze_results.py
# prints the report and writes data/stats.txt
```
## How PQ detection works

[scanner/algorithms.py](scanner/algorithms.py) maps public-key OIDs to
`(name, family, quantum_vulnerable)`. Classical families (RSA, ECDSA, DSA,
Ed25519/Ed448, X25519/X448) are flagged quantum-vulnerable; the NIST PQ OIDs
(ML-DSA / SLH-DSA / ML-KEM) are flagged post-quantum. Unrecognized OIDs fall
back to family `unknown`.

## License

See [LICENSE](LICENSE).
