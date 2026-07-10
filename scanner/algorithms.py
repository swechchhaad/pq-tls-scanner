OID_MAP = {
    # --- classical  ---
    "1.2.840.113549.1.1.1": ("RSA", "classical", True),
    "1.2.840.10045.2.1":    ("ECDSA", "classical", True),   # id-ecPublicKey
    "1.2.840.10040.4.1":    ("DSA", "classical", True),
    "1.3.101.112":          ("Ed25519", "classical", True),
    "1.3.101.113":          ("Ed448", "classical", True),
    "1.3.101.110":          ("X25519", "classical", True),
    "1.3.101.111":          ("X448", "classical", True),

    # --- post-quantum: ML-DSA (FIPS 204, signatures) ---
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "post-quantum", False),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "post-quantum", False),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "post-quantum", False),

    # --- post-quantum: SLH-DSA (FIPS 205, signatures) ---
    "2.16.840.1.101.3.4.3.20": ("SLH-DSA-SHA2-128s", "post-quantum", False),
    "2.16.840.1.101.3.4.3.21": ("SLH-DSA-SHA2-128f", "post-quantum", False),
    "2.16.840.1.101.3.4.3.22": ("SLH-DSA-SHA2-192s", "post-quantum", False),
    "2.16.840.1.101.3.4.3.23": ("SLH-DSA-SHA2-192f", "post-quantum", False),
    "2.16.840.1.101.3.4.3.24": ("SLH-DSA-SHA2-256s", "post-quantum", False),
    "2.16.840.1.101.3.4.3.25": ("SLH-DSA-SHA2-256f", "post-quantum", False),

    # --- post-quantum: ML-KEM (FIPS 203, key encapsulation) ---
    "2.16.840.1.101.3.4.4.1": ("ML-KEM-512", "post-quantum", False),
    "2.16.840.1.101.3.4.4.2": ("ML-KEM-768", "post-quantum", False),
    "2.16.840.1.101.3.4.4.3": ("ML-KEM-1024", "post-quantum", False),
}


def classify_oid(oid):
    """return (name, family, quantum_vulnerable) for a dotted-string OID.

    unknown OIDs fall back to the raw OID string, family "unknown"
    """
    return OID_MAP.get(oid, (oid, "unknown", None))
