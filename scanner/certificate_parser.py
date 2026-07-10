import base64

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from scanner.algorithms import classify_oid


def _public_key_size(public_key):
    """best-effort key size in bits; none if it doesn't apply / is unknown."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.curve.key_size
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return 256 if isinstance(public_key, ed25519.Ed25519PublicKey) else 448
    return None


def _name_attr(name, oid):
    """pull a single RDN value (e.g. common name) out of an x509 Name, or ''."""
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else ""


def parse_certificate(der_bytes):
    """parse DER certificate bytes into a flat dict of fields."""
    cert = x509.load_der_x509_certificate(der_bytes)

    # public-key algorithm straight from the SubjectPublicKeyInfo OID.
    # works even for PQ algorithms the library can't fully parse into a key.
    pk_oid = cert.public_key_algorithm_oid.dotted_string
    name, family, quantum_vulnerable = classify_oid(pk_oid)

    try:
        key_size = _public_key_size(cert.public_key())
    except Exception:
        key_size = None

    return {
        "subject_cn": _name_attr(cert.subject, x509.NameOID.COMMON_NAME),
        "issuer_cn": _name_attr(cert.issuer, x509.NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, x509.NameOID.ORGANIZATION_NAME),
        "public_key_algorithm": name,
        "public_key_oid": pk_oid,
        "public_key_size": key_size,
        "key_family": family,
        "quantum_vulnerable": quantum_vulnerable,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "not_valid_before": cert.not_valid_before_utc.date().isoformat(),
        "not_valid_after": cert.not_valid_after_utc.date().isoformat(),
    }


def parse_b64(b64_der):
    """Parse a base64-encoded DER certificate (the form stored in raw.csv)."""
    return parse_certificate(base64.b64decode(b64_der))
